/**
 * Peer profiles — the name, bio and picture a person publishes about
 * themselves (Stream `0x08`).
 *
 * Distinct from `trust-service`'s "profile", which is the RFC 004 §8
 * trust score and has nothing to do with anything user-visible.
 *
 * A profile is **mutable and single-writer**: only its subject may
 * change it, and a new version replaces the old rather than joining a
 * list. That is what makes it not a message. Sent as specially-tagged
 * chat it would have to be filtered out of every view forever, any
 * client not knowing the convention would render the tag as text, and
 * each new avatar would sit in message history permanently on both
 * devices.
 *
 * ### What the SDK decides, and what it leaves alone
 *
 * - **A size cap**, enforced here rather than left to the app. Without
 *   one the first person to set a 12MB photo replicates it to everyone
 *   they talk to.
 * - **Nothing before pairing.** Profiles go only to paired peers and are
 *   accepted only from paired peers. A ticket is shareable, so a
 *   stranger who dials one must not learn your name and face from it.
 * - **The display name is not authoritative.** It is what the peer calls
 *   themselves, which is not the same as what you call them. Whatever
 *   name the user typed locally wins; this layer never assumes its value
 *   is the one shown.
 */

import { SecretBox } from './storage/secret-box.js';
import type { IStorageDriver, PeerProfileRecord } from './storage/types.js';
import { StorageCollections } from './storage/types.js';

/**
 * Largest avatar accepted, in bytes.
 *
 * 256KB is generous for a picture displayed at avatar size and small
 * enough that replicating one to every contact is unremarkable. Rejected
 * on the way in as well as the way out: a peer running a modified build
 * does not get to write a 12MB row into our database.
 */
export const MAX_AVATAR_BYTES = 256 * 1024;

/** Used when no box is supplied, so reads and writes stay symmetric. */
const passThrough = new SecretBox(null);

/** Longest display name accepted, in UTF-16 code units. */
export const MAX_DISPLAY_NAME_LENGTH = 128;

/** Longest bio accepted, in UTF-16 code units. */
export const MAX_BIO_LENGTH = 1024;

/** A peer's self-published profile. */
export interface PeerProfile {
  readonly displayName?: string;
  readonly bio?: string;
  readonly avatar?: { readonly mime: string; readonly bytes: Uint8Array };
  /** Author's clock when this version was written. */
  readonly updatedAt: number;
}

/** Fields a caller may change. `null` clears one; omitted keeps it. */
export interface ProfileUpdate {
  readonly displayName?: string | null;
  readonly bio?: string | null;
  readonly avatar?: { readonly mime: string; readonly bytes: Uint8Array } | null;
}

/** Raised when a profile exceeds a limit this SDK enforces. */
export class ProfileTooLargeError extends Error {
  constructor(
    readonly field: 'avatar' | 'displayName' | 'bio',
    readonly limit: number,
    readonly actual: number,
  ) {
    super(
      `Profile ${field} is ${actual} against a limit of ${limit}. ` +
        'Resize or shorten it before setting the profile.',
    );
    this.name = 'ProfileTooLargeError';
  }
}

/** Collaborators the profile service needs. */
export interface ProfileServiceDeps {
  readonly storage: IStorageDriver;
  /** This node's did:key — the subject of the profile we author. */
  readonly selfDid: string;
  /** Send our profile to every paired, connected peer. */
  readonly broadcast: (encoded: Uint8Array) => Promise<number>;
  /**
   * Encryption at rest.
   *
   * A profile table is a contact list with faces attached: who this
   * person talks to, and what they look like. Worth as much to whoever
   * steals the database as the messages are.
   */
  readonly box?: SecretBox;
}

type ProfileListener = (did: string, profile: PeerProfile) => void;

/**
 * Stores our own profile and every peer profile we have been told about.
 */
export class ProfileService {
  private readonly cache = new Map<string, PeerProfile>();
  private readonly listeners = new Set<ProfileListener>();
  private mine: PeerProfile | undefined;

  constructor(private readonly deps: ProfileServiceDeps) {}

  /** Load persisted profiles into memory. Call once during init. */
  async load(): Promise<void> {
    const rows = await this.deps.storage.query(StorageCollections.PEER_PROFILES);

    const box = this.deps.box ?? passThrough;

    for (const row of rows) {
      const record = rowToRecord(row, box);
      const profile = recordToProfile(record);

      if (record.did === this.deps.selfDid) this.mine = profile;
      else this.cache.set(record.did, profile);
    }
  }

  /** This node's own profile, if one has been set. */
  getMyProfile(): PeerProfile | undefined {
    return this.mine;
  }

  /**
   * Replace our profile and tell every paired, connected peer.
   *
   * Fields left undefined are kept, so setting a bio does not erase a
   * picture. To clear one, pass `null`.
   *
   * @returns How many peers received it. Zero is normal — it means
   *   nobody was connected, and the profile still reaches them when they
   *   next connect.
   * @throws {ProfileTooLargeError} If a field exceeds its cap.
   */
  async setMyProfile(update: ProfileUpdate): Promise<number> {
    const merged = applyUpdate(this.mine, update);
    assertWithinLimits(merged);

    this.mine = merged;
    await this.persist(this.deps.selfDid, merged);

    return this.deps.broadcast(encodeProfile(merged));
  }

  /** A peer's profile, or undefined if they have not published one. */
  getPeerProfile(did: string): PeerProfile | undefined {
    return this.cache.get(did);
  }

  /** Every peer profile currently held. */
  listPeerProfiles(): ReadonlyMap<string, PeerProfile> {
    return new Map(this.cache);
  }

  /**
   * Subscribe to profile updates from peers.
   *
   * @returns An unsubscribe function.
   */
  onPeerProfile(listener: ProfileListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Our profile encoded for the wire, or undefined if none is set. */
  encodeMine(): Uint8Array | undefined {
    return this.mine ? encodeProfile(this.mine) : undefined;
  }

  /**
   * Accept a profile a paired peer sent us.
   *
   * Pairing is checked by the caller: `SessionManager` drops every frame
   * from an unpaired peer before routing it.
   *
   * Ignored unless strictly newer than what we hold, which is what stops
   * a replayed old frame from reverting someone's picture. `updatedAt`
   * is the author's clock, so this orders one peer's versions against
   * each other and never one peer against another — it is not used for
   * anything that requires agreement between devices.
   */
  async ingestRemote(peerDid: string, encoded: Uint8Array): Promise<void> {
    const incoming = decodeProfile(encoded);

    // A peer running a modified build does not get to write an
    // oversized row into our database.
    assertWithinLimits(incoming);

    const held = this.cache.get(peerDid);
    if (held && incoming.updatedAt <= held.updatedAt) return;

    this.cache.set(peerDid, incoming);
    await this.persist(peerDid, incoming);

    for (const listener of this.listeners) listener(peerDid, incoming);
  }

  private async persist(did: string, profile: PeerProfile): Promise<void> {
    const box = this.deps.box ?? passThrough;

    await this.deps.storage.put(StorageCollections.PEER_PROFILES, did, {
      did,
      display_name: profile.displayName ? box.seal(profile.displayName) : null,
      bio: profile.bio ? box.seal(profile.bio) : null,
      avatar_mime: profile.avatar?.mime ?? null,
      // Copied before sealing: the caller may reuse its buffer after we
      // return.
      avatar: profile.avatar
        ? box.sealBytes(new Uint8Array(profile.avatar.bytes))
        : null,
      updated_at: profile.updatedAt,
    });
  }
}

/** Merge an update over the held profile, stamping the author's clock. */
function applyUpdate(
  held: PeerProfile | undefined,
  update: ProfileUpdate,
): PeerProfile {
  return {
    displayName: pick(update.displayName, held?.displayName),
    bio: pick(update.bio, held?.bio),
    avatar: pick(update.avatar, held?.avatar),
    updatedAt: Date.now(),
  };
}

/** `null` clears, `undefined` keeps, anything else replaces. */
function pick<T>(next: T | null | undefined, current: T | undefined): T | undefined {
  if (next === null) return undefined;
  return next ?? current;
}

function assertWithinLimits(profile: PeerProfile): void {
  if (
    profile.displayName &&
    profile.displayName.length > MAX_DISPLAY_NAME_LENGTH
  ) {
    throw new ProfileTooLargeError(
      'displayName',
      MAX_DISPLAY_NAME_LENGTH,
      profile.displayName.length,
    );
  }

  if (profile.bio && profile.bio.length > MAX_BIO_LENGTH) {
    throw new ProfileTooLargeError('bio', MAX_BIO_LENGTH, profile.bio.length);
  }

  if (profile.avatar && profile.avatar.bytes.length > MAX_AVATAR_BYTES) {
    throw new ProfileTooLargeError(
      'avatar',
      MAX_AVATAR_BYTES,
      profile.avatar.bytes.length,
    );
  }
}

/**
 * Wire format: a JSON header, then the avatar bytes raw.
 *
 * The picture stays outside the JSON because base64 inside it would add
 * a third again to every profile frame, for the one field where that
 * actually costs something.
 */
export function encodeProfile(profile: PeerProfile): Uint8Array {
  const header = JSON.stringify({
    displayName: profile.displayName,
    bio: profile.bio,
    avatarMime: profile.avatar?.mime,
    updatedAt: profile.updatedAt,
  });

  const headerBytes = new TextEncoder().encode(header);
  const avatar = profile.avatar?.bytes ?? new Uint8Array(0);
  const out = new Uint8Array(4 + headerBytes.length + avatar.length);

  new DataView(out.buffer).setUint32(0, headerBytes.length, false);
  out.set(headerBytes, 4);
  out.set(avatar, 4 + headerBytes.length);

  return out;
}

/**
 * Decode a `0x08` payload.
 *
 * @throws If it is malformed.
 */
export function decodeProfile(bytes: Uint8Array): PeerProfile {
  if (bytes.length < 4) throw new Error('Profile frame is too short');

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerLength = view.getUint32(0, false);

  if (bytes.length < 4 + headerLength) {
    throw new Error('Profile frame declares a header it does not carry');
  }

  const header = JSON.parse(
    new TextDecoder().decode(bytes.subarray(4, 4 + headerLength)),
  ) as {
    displayName?: string;
    bio?: string;
    avatarMime?: string;
    updatedAt?: number;
  };

  const avatarBytes = bytes.slice(4 + headerLength);
  const avatar =
    header.avatarMime && avatarBytes.length > 0
      ? { mime: header.avatarMime, bytes: avatarBytes }
      : undefined;

  return {
    displayName: header.displayName,
    bio: header.bio,
    avatar,
    // A frame that omits its clock sorts to the bottom rather than
    // taking `Date.now()`, which would let a malformed profile outrank
    // every legitimate version that follows it.
    updatedAt: typeof header.updatedAt === 'number' ? header.updatedAt : 0,
  };
}

function rowToRecord(
  row: Record<string, unknown>,
  box: SecretBox,
): PeerProfileRecord {
  const name = row['display_name'] as string | null;
  const bio = row['bio'] as string | null;
  const avatar = row['avatar'] as Uint8Array | null;

  return {
    did: row['did'] as string,
    displayName: name ? box.open(name) : undefined,
    bio: bio ? box.open(bio) : undefined,
    avatarMime: (row['avatar_mime'] as string | null) ?? undefined,
    avatar: avatar ? box.openBytes(avatar) : undefined,
    updatedAt: row['updated_at'] as number,
  };
}

function recordToProfile(record: PeerProfileRecord): PeerProfile {
  return {
    displayName: record.displayName,
    bio: record.bio,
    avatar:
      record.avatarMime && record.avatar
        ? { mime: record.avatarMime, bytes: record.avatar }
        : undefined,
    updatedAt: record.updatedAt,
  };
}
