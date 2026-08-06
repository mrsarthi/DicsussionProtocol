/**
 * @dicsussion/sdk — GroupService
 *
 * Group/channel management: creation, joining, leaving, and invite
 * handling per RFC 004 §7.3.
 *
 * A group *is* a channel, not a parallel concept: it shares the same
 * CRDT document, the same `channel_meta` row, and the same bounded
 * membership tree as any other channel. Creating one produces a Channel
 * Creator Genesis Anchor (RFC 002 §4.1), so a joining peer can verify
 * the group's origin rather than trusting whoever invited them.
 *
 * ENCRYPTION: messages fan out pairwise — each member receives their own
 * envelope sealed with ephemeral X25519 ECDH. That costs N encryptions
 * per message, which is fine for ordinary group sizes and keeps forward
 * secrecy per recipient. Sender-key schemes trade that for O(1) sends
 * and are the natural optimisation once real group sizes are known.
 */

import { v4 as uuidv4 } from 'uuid';

import { createDeparture } from '@dicsussion/core/crdt';
import type { DocumentManager } from '@dicsussion/core/crdt';
import type { DepartureRecord } from '@dicsussion/core/crdt';
import type { BoundedMembershipTree } from '@dicsussion/core/crdt';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';
import type { GenesisAnchor } from './wot/genesis-anchor.js';
import { bootstrapFromAnchor, createGenesisAnchor } from './wot/genesis-anchor.js';
import type { IStorageDriver } from './storage/types.js';
import { StorageCollections } from './storage/types.js';
import type { GroupInfo, GroupInvite } from './types.js';

/** Collaborators the group service needs once the engine is running. */
export interface GroupServiceDeps {
  readonly storage: IStorageDriver;
  readonly documents: DocumentManager;
  /** This node's did:key. */
  readonly getLocalDid: () => string;
  /** Signing keypair, for authoring genesis anchors. */
  readonly getSigningKey: () => Ed25519KeyPair;
  /** This node's Poseidon identity commitment. */
  readonly getCommitment: () => bigint;
  /** Persist a verified genesis anchor. */
  readonly saveAnchor: (anchor: GenesisAnchor) => void;
  /** Load a channel's persisted anchor. */
  readonly loadAnchor: (channelId: string) => GenesisAnchor | undefined;
  /**
   * Announce a signed departure to peers.
   *
   * Optional so the service still works without a running sync engine;
   * without it a leave is local-only and will be undone by the next
   * reconciliation.
   */
  readonly announceDeparture?: (departure: DepartureRecord) => void;
  /**
   * Advertise our membership root for a channel so peers reconcile.
   *
   * Optional for the same reason as `announceDeparture`: without a
   * running sync engine a join is local-only.
   */
  readonly announceMembership?: (channelId: string) => void;
  /**
   * Default proof policy for channels this node creates.
   *
   * Only ever applied at creation time — an existing channel's policy
   * comes from its signed anchor.
   */
  readonly defaultRequireProofs?: () => boolean;
}

/** Options for creating a group. */
export interface CreateGroupOptions {
  /**
   * Require a Groth16 membership proof on anonymous messages.
   *
   * Signed into the genesis anchor, so every member agrees. Costs ~1s
   * per anonymous send; worth it on an open channel, wasteful in a
   * two-person chat where the recipient already knows the sender.
   */
  readonly requireProofs?: boolean;
}

/**
 * Group service for managing chat channels and group membership.
 */
export class GroupService {
  private readonly inviteCallbacks: Array<(invite: GroupInvite) => void> = [];
  /** Membership trees by group id, rebuilt from anchors on demand. */
  private readonly membership = new Map<string, BoundedMembershipTree>();
  private deps: GroupServiceDeps | null = null;

  /** Wire the service to the running engine. */
  attach(deps: GroupServiceDeps): void {
    this.deps = deps;
  }

  /**
   * Create a group and become its genesis trust anchor.
   *
   * @param name Human-readable group name.
   * @param members did:keys to record as initial members.
   * @returns The created group.
   */
  async createGroup(
    name: string,
    members: string[],
    options: CreateGroupOptions = {},
  ): Promise<GroupInfo> {
    const deps = this.requireDeps();

    const groupId = uuidv4();
    const createdAt = Math.floor(Date.now() / 1000);
    const creator = deps.getLocalDid();

    // The creator anchors the group: joining peers verify this signature
    // instead of trusting whoever forwarded them an invite.
    const { anchor, tree } = createGenesisAnchor(
      groupId,
      deps.getSigningKey(),
      creator,
      deps.getCommitment(),
      createdAt,
      options.requireProofs ?? deps.defaultRequireProofs?.() ?? false,
    );

    deps.saveAnchor(anchor);
    this.membership.set(groupId, tree);

    // The creator is always a member, even if omitted from `members`.
    const roster = unique([creator, ...members]);

    await this.persist({ groupId, name, members: roster, createdAt });
    deps.documents.createDocument(name, groupId);

    return { groupId, name, members: roster, createdAt };
  }

  /**
   * Adopt a group learned out of band, e.g. from an invite.
   *
   * Records the metadata and its genesis anchor without joining — the
   * two are separate so a peer can inspect a group before committing
   * its identity commitment to the membership tree.
   *
   * @param info Group metadata as advertised by the inviter.
   * @param anchor The creator's genesis anchor.
   * @throws If the anchor fails verification.
   */
  async importGroup(info: GroupInfo, anchor: GenesisAnchor): Promise<void> {
    const deps = this.requireDeps();

    if (anchor.channelId !== info.groupId) {
      throw new Error(
        `Anchor is for channel ${anchor.channelId}, not group ${info.groupId}`,
      );
    }

    // Throws on an unverifiable anchor, so a forged invite cannot seed a
    // group record that later looks legitimate.
    deps.saveAnchor(anchor);

    // Adopt the anchored member set without adding ourselves. Without a
    // tree an imported group can verify nobody's membership proofs, so
    // an observer would have to join before it could check whether
    // anyone else belonged.
    this.membership.set(info.groupId, bootstrapFromAnchor(anchor));

    await this.persist(info);
  }

  /**
   * Join a group, verifying its genesis anchor first.
   *
   * @param groupId The group to join.
   * @throws If the group is unknown or its anchor fails verification.
   */
  async joinGroup(groupId: string): Promise<void> {
    const deps = this.requireDeps();
    const info = await this.getGroupInfo(groupId);

    const anchor = deps.loadAnchor(groupId);
    if (!anchor) {
      throw new Error(
        `Cannot join ${groupId}: no genesis anchor, so its origin is unverifiable`,
      );
    }

    // Throws if the signature or the anchored root does not check out.
    const tree = bootstrapFromAnchor(anchor);
    tree.insert(deps.getCommitment());
    this.membership.set(groupId, tree);

    // Existing members do not learn about us by us inserting ourselves
    // locally. Advertising the new root starts reconciliation, which is
    // what actually admits us to their trees — and on a proof-required
    // channel it is the difference between our proofs verifying and
    // being silently rejected against a root that never included us.
    deps.announceMembership?.(groupId);

    const self = deps.getLocalDid();
    if (!info.members.includes(self)) {
      await this.persist({ ...info, members: [...info.members, self] });
    }

    if (!deps.documents.hasDocument(groupId)) {
      deps.documents.createDocument(info.name, groupId);
    }
  }

  /**
   * Leave a group, announcing a signed departure to peers.
   *
   * Membership syncs as a two-phase set, so simply dropping the
   * commitment locally would be undone by the next reconciliation. The
   * departure is a tombstone signed by this node's own `did:key` — only
   * you can announce that you left, which stops a peer evicting anyone
   * but itself.
   *
   * The retired commitment is permanent: rejoining means presenting a
   * fresh one, so an old departure cannot be replayed to evict a member
   * who has since rejoined.
   */
  async leaveGroup(groupId: string): Promise<void> {
    const deps = this.requireDeps();
    const info = await this.getGroupInfo(groupId);
    const self = deps.getLocalDid();

    const departure = createDeparture(
      groupId,
      self,
      deps.getCommitment(),
      deps.getSigningKey(),
    );

    deps.announceDeparture?.(departure);
    this.membership.delete(groupId);

    await this.persist({
      ...info,
      members: info.members.filter((did) => did !== self),
    });
  }

  /**
   * Look up a group.
   *
   * @throws If no such group is stored locally.
   */
  async getGroupInfo(groupId: string): Promise<GroupInfo> {
    const deps = this.requireDeps();
    const row = await deps.storage.get(StorageCollections.CHANNEL_META, groupId);

    if (!row) throw new Error(`Unknown group: ${groupId}`);

    return {
      groupId,
      name: String(row['title'] ?? groupId),
      members: parseMembers(row['peers']),
      createdAt: Number(row['created_at'] ?? 0),
    };
  }

  /** Every group this node knows about. */
  async listGroups(): Promise<GroupInfo[]> {
    const rows = await this.requireDeps().storage.query(
      StorageCollections.CHANNEL_META,
    );

    return rows.map((row) => ({
      groupId: String(row['channel_id'] ?? ''),
      name: String(row['title'] ?? ''),
      members: parseMembers(row['peers']),
      createdAt: Number(row['created_at'] ?? 0),
    }));
  }

  /**
   * Whether a channel requires Groth16 proofs on anonymous messages.
   *
   * Read from the channel's signed anchor, never from local settings —
   * every member must reach the same answer or the strict ones silently
   * drop the lax ones' messages.
   */
  requiresProofs(groupId: string): boolean {
    return this.deps?.loadAnchor(groupId)?.requireProofs ?? false;
  }

  /** The membership tree backing a group, if this node holds one. */
  getMembershipTree(groupId: string): BoundedMembershipTree | undefined {
    return this.membership.get(groupId);
  }

  /**
   * Deliver an invite to registered listeners.
   *
   * Called by the client when an invite arrives from a peer.
   */
  emitInvite(invite: GroupInvite): void {
    for (const callback of this.inviteCallbacks) callback(invite);
  }

  /**
   * Register a callback for group invite notifications.
   * @returns Unsubscribe function.
   */
  onInvite(callback: (invite: GroupInvite) => void): () => void {
    this.inviteCallbacks.push(callback);

    return () => {
      const idx = this.inviteCallbacks.indexOf(callback);
      if (idx >= 0) this.inviteCallbacks.splice(idx, 1);
    };
  }

  /** Write a group's metadata to `channel_meta`. */
  private async persist(info: GroupInfo): Promise<void> {
    await this.requireDeps().storage.put(
      StorageCollections.CHANNEL_META,
      info.groupId,
      {
        channel_id: info.groupId,
        title: info.name,
        peers: JSON.stringify(info.members),
        access_threshold: 0,
        created_at: info.createdAt,
        last_activity: Math.floor(Date.now() / 1000),
      },
    );
  }

  private requireDeps(): GroupServiceDeps {
    if (!this.deps) {
      throw new Error(
        'GroupService is not attached to a running client. Use DicsussionClient.init().',
      );
    }
    return this.deps;
  }
}

/** Parse the JSON member list stored in `channel_meta.peers`. */
function parseMembers(value: unknown): string[] {
  if (typeof value !== 'string' || value.length === 0) return [];

  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed)
      ? parsed.filter((v): v is string => typeof v === 'string')
      : [];
  } catch {
    return [];
  }
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}
