/**
 * @dicsussion/sdk — IdentityService
 *
 * Identity lifecycle: creation, loading, and export per RFC 004 §7.3.
 *
 * A node identity is two keypairs: Ed25519 for did:key addressing and
 * signing (RFC 001 §3.1), and a separate X25519 pair for E2EE key
 * agreement. They are kept distinct so no key is used across both a
 * signature scheme and a key-agreement scheme.
 */

import type { BlindKeyPair, KeyPair } from '@dicsussion/core/crypto';
import { generateBlindKeyPair, membershipCommitment } from '@dicsussion/core/crypto';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';
import { createMnemonic, deriveIdentity } from './identity-derivation.js';
import type { RevocationTombstone } from './slashing/tombstone.js';
import { createLocalRetirementTombstone } from './slashing/tombstone.js';
import { SecretBox } from './storage/secret-box.js';
import type { IStorageDriver } from './storage/types.js';
import { StorageCollections } from './storage/types.js';
import type { Identity } from './types.js';

/** A fully materialised local identity, including secret key material. */
export interface LocalIdentity {
  /** W3C did:key derived from the Ed25519 public key. */
  readonly did: string;
  /** Ed25519 keypair for signing and transport handshakes. */
  readonly signing: Ed25519KeyPair;
  /** X25519 keypair for E2EE key agreement. */
  readonly encryption: KeyPair;
  /**
   * ZekPoc RLN identity secret a_0 (RFC 003 §4.1).
   *
   * This is the value reconstructed by Lagrange interpolation if the
   * holder ever double-sends within an epoch, so it must never leave
   * the device.
   */
  readonly identitySecret: bigint;
  /** Per-identity trapdoor mixed into the membership commitment. */
  readonly trapdoor: bigint;
  /** `cm_identity = Poseidon(DS_member, a_0, trapdoor)`. */
  readonly commitment: bigint;
  /**
   * RSA blind-signing keypair, or null until first needed.
   *
   * Generated lazily: RSA-2048 keygen searches for two 1024-bit primes
   * and takes hundreds of milliseconds to seconds, which is a poor thing
   * to put on the very first `init()` when most nodes never issue an
   * endorsement at all. `ensureBlindKeypair()` materialises it.
   */
  readonly blindKeypair: BlindKeyPair | null;
  /**
   * BIP-39 recovery phrase this identity was derived from.
   *
   * Absent for identities created before phrase support existed.
   */
  readonly mnemonic?: string;
  /** Unix timestamp (seconds) of creation. */
  readonly createdAt: number;
}

/**
 * Identity service for managing local cryptographic identities.
 */
export class IdentityService {
  private identity: LocalIdentity | null = null;
  private storage: IStorageDriver | null = null;
  private publishRevocation:
    | ((tombstone: RevocationTombstone) => Promise<void>)
    | null = null;
  /** Encryption at rest for secret columns; pass-through until configured. */
  private box = new SecretBox(null);

  /**
   * Enable encryption at rest for secret key material.
   *
   * Must be called before `loadOrCreate`. The key's provenance is the
   * application's concern — an OS keychain, a user passphrase, or a
   * hardware token all satisfy RFC 004 §4.1 equally.
   */
  attachStorageKey(masterKey: Uint8Array | string): void {
    this.box = new SecretBox(masterKey);
  }

  /** Attach a storage driver so identities can be persisted. */
  attachStorage(storage: IStorageDriver): void {
    this.storage = storage;
  }

  /**
   * Create a fresh identity backed by a BIP-39 recovery phrase.
   *
   * Every key except the RSA blind-signing key is derived from the
   * phrase, so the identity can be restored on another device — see
   * `identity-derivation.ts` for why RSA is excluded.
   */
  async createIdentity(): Promise<Identity> {
    return this.materialise(createMnemonic());
  }

  /**
   * Restore an identity from its recovery phrase.
   *
   * Yields the same `did:key` and the same `cm_identity`, so channel
   * membership and reputation survive a lost device. A **new**
   * blind-signing key is generated: peers holding the old endorsement
   * key must re-pair before issuing new endorsements.
   *
   * @param mnemonic The twelve-word phrase from `exportMnemonic`.
   * @throws If the phrase fails BIP-39 checksum validation.
   */
  async recoverFromMnemonic(mnemonic: string): Promise<Identity> {
    return this.materialise(mnemonic);
  }

  /**
   * The recovery phrase for the loaded identity.
   *
   * @throws If no identity is loaded, or it predates phrase support.
   */
  async exportMnemonic(): Promise<string> {
    const identity = this.getLocalIdentity();

    if (!identity.mnemonic) {
      throw new Error(
        'This identity has no recovery phrase; it was created before BIP-39 support',
      );
    }

    return identity.mnemonic;
  }

  /**
   * Return this node's blind-signing keypair, generating it if needed.
   *
   * The first call costs an RSA-2048 keygen. Every later call, and every
   * run after the first, reads the persisted key.
   *
   * @throws If no identity has been loaded yet.
   */
  async ensureBlindKeypair(): Promise<BlindKeyPair> {
    const identity = this.identity;
    if (!identity) {
      throw new Error(
        'No identity loaded. Call loadOrCreate() before requesting the ' +
          'endorsement key.',
      );
    }

    if (identity.blindKeypair) return identity.blindKeypair;

    const blindKeypair = await generateBlindKeyPair();

    // Replace the cached identity wholesale: `LocalIdentity` is readonly,
    // and a half-updated copy is how a key gets generated twice.
    const updated: LocalIdentity = { ...identity, blindKeypair };
    this.identity = updated;
    await this.persist(updated);

    return blindKeypair;
  }

  /**
   * Load the persisted identity, creating one on first run.
   */
  async loadOrCreate(): Promise<Identity> {
    if (this.identity) return this.toPublicIdentity(this.identity);

    const restored = await this.restore();
    if (restored) {
      this.identity = restored;
      return this.toPublicIdentity(restored);
    }

    return this.createIdentity();
  }

  /**
   * The full local identity, including secret keys.
   *
   * @throws If no identity has been created or loaded yet.
   */
  getLocalIdentity(): LocalIdentity {
    if (!this.identity) {
      throw new Error('No identity loaded. Call loadOrCreate() first.');
    }
    return this.identity;
  }

  /** Whether an identity is currently loaded. */
  get hasIdentity(): boolean {
    return this.identity !== null;
  }

  /**
   * Get the current node's did:key identifier.
   */
  async getCurrentDid(): Promise<string> {
    return this.getLocalIdentity().did;
  }

  /**
   * Retire this identity and broadcast a `USER_REVOKED` tombstone.
   *
   * Targets `cm_identity` rather than the `did:key` (RFC 003 §7.1), so
   * the revocation survives transport-layer rotation. Peers that verify
   * it blacklist the commitment permanently.
   *
   * This is irreversible: the retired commitment can never be readmitted.
   * Continuing to participate means creating a new identity, or
   * recovering from the phrase with a fresh trapdoor.
   *
   * @throws If no revocation transport has been attached.
   */
  async revokeKey(): Promise<void> {
    const identity = this.getLocalIdentity();

    if (!this.publishRevocation) {
      throw new Error(
        'revokeKey requires a running client so the tombstone can be gossiped on Stream 0x03',
      );
    }

    await this.publishRevocation(
      createLocalRetirementTombstone(identity.commitment, {
        keypair: identity.signing,
        did: identity.did,
      }),
    );
  }

  /**
   * Attach the transport used to gossip revocations.
   *
   * Injected by the client so this service does not depend on the
   * session layer directly.
   */
  attachRevocationPublisher(
    publish: (tombstone: RevocationTombstone) => Promise<void>,
  ): void {
    this.publishRevocation = publish;
  }

  /** Derive, persist and cache an identity from a phrase. */
  private async materialise(mnemonic: string): Promise<Identity> {
    const derived = deriveIdentity(mnemonic);

    const identity: LocalIdentity = {
      did: derived.did,
      signing: derived.signing,
      encryption: derived.encryption,
      identitySecret: derived.identitySecret,
      trapdoor: derived.trapdoor,
      commitment: derived.commitment,
      // Not derivable from the seed and expensive to produce, so it is
      // generated on first use rather than on every init().
      blindKeypair: null,
      mnemonic,
      createdAt: Math.floor(Date.now() / 1000),
    };

    this.identity = identity;
    await this.persist(identity);

    return this.toPublicIdentity(identity);
  }

  /** Unseal a possibly-encrypted column, preserving null/undefined. */
  private unseal(value: unknown): unknown {
    return typeof value === 'string' ? this.box.open(value) : value;
  }

  private toPublicIdentity(identity: LocalIdentity): Identity {
    return {
      did: identity.did,
      publicKey: toHex(identity.signing.publicKey),
      createdAt: identity.createdAt,
    };
  }

  private async persist(identity: LocalIdentity): Promise<void> {
    if (!this.storage) return;

    await this.storage.put(StorageCollections.IDENTITY, identity.did, {
      did: identity.did,
      ed25519_public_key: toHex(identity.signing.publicKey),
      ed25519_secret_key_encrypted: this.box.seal(
        toHex(identity.signing.secretKey),
      ),
      x25519_public_key: toHex(identity.encryption.publicKey),
      x25519_secret_key_encrypted: this.box.seal(
        toHex(identity.encryption.secretKey),
      ),
      created_at: identity.createdAt,
      // Decimal strings: a 254-bit field element would be truncated by
      // SQLite's 64-bit INTEGER type.
      rln_identity_secret: this.box.seal(identity.identitySecret.toString()),
      rln_trapdoor: this.box.seal(identity.trapdoor.toString()),
      blind_modulus: identity.blindKeypair?.n.toString() ?? null,
      blind_exponent: identity.blindKeypair?.e.toString() ?? null,
      blind_private_exponent: identity.blindKeypair
        ? this.box.seal(identity.blindKeypair.d.toString())
        : null,
      mnemonic_encrypted: identity.mnemonic
        ? this.box.seal(identity.mnemonic)
        : null,
    });
  }

  private async restore(): Promise<LocalIdentity | null> {
    if (!this.storage) return null;

    const rows = await this.storage.query(
      StorageCollections.IDENTITY,
      undefined,
      1,
    );
    const row = rows[0];
    if (!row) return null;

    const did = row['did'];
    const edPub = row['ed25519_public_key'];
    const edSec = row['ed25519_secret_key_encrypted'];
    const xPub = row['x25519_public_key'];
    const xSec = row['x25519_secret_key_encrypted'];
    const createdAt = row['created_at'];

    if (
      typeof did !== 'string' ||
      typeof edPub !== 'string' ||
      typeof edSec !== 'string' ||
      typeof xPub !== 'string' ||
      typeof xSec !== 'string'
    ) {
      return null;
    }

    // A row written before migration v3 has no ZekPoc material. Treat it
    // as unusable rather than fabricating a secret, so the caller creates
    // a fresh identity instead of silently getting a zero commitment.
    //
    // `open()` is a no-op on values written before encryption was
    // enabled, and throws on a wrong key rather than yielding garbage.
    const identitySecret = bigIntOrNull(this.unseal(row['rln_identity_secret']));
    const trapdoor = bigIntOrNull(this.unseal(row['rln_trapdoor']));
    const modulus = bigIntOrNull(row['blind_modulus']);
    const exponent = bigIntOrNull(row['blind_exponent']);
    const privateExponent = bigIntOrNull(
      this.unseal(row['blind_private_exponent']),
    );

    // The RLN secret and trapdoor define the identity — without them
    // there is nothing to restore. The blind-signing key deliberately
    // does *not* belong in that test: it is generated on first use, so
    // an identity that has never issued an endorsement legitimately has
    // none. Treating its absence as a corrupt record would silently
    // discard the identity and mint a new one on every restart.
    if (identitySecret === null || trapdoor === null) {
      return null;
    }

    const blindKeypair =
      modulus !== null && exponent !== null && privateExponent !== null
        ? { n: modulus, e: exponent, d: privateExponent }
        : null;

    return {
      did,
      signing: {
        publicKey: fromHex(edPub),
        secretKey: fromHex(this.box.open(edSec)),
      },
      encryption: {
        publicKey: fromHex(xPub),
        secretKey: fromHex(this.box.open(xSec)),
      },
      identitySecret,
      trapdoor,
      commitment: membershipCommitment(identitySecret, trapdoor),
      blindKeypair,
      mnemonic:
        typeof row['mnemonic_encrypted'] === 'string'
          ? this.box.open(row['mnemonic_encrypted'])
          : undefined,
      createdAt: typeof createdAt === 'number' ? createdAt : 0,
    };
  }
}

function bigIntOrNull(value: unknown): bigint | null {
  if (typeof value !== 'string' || value.length === 0) return null;

  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
