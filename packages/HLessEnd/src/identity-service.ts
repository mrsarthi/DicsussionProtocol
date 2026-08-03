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

import { generateX25519Keypair } from '../../core/src/crypto/keys.js';
import type { KeyPair } from '../../core/src/crypto/types.js';
import { generateKeypair, publicKeyToDidKey } from '../../core/src/transport/did-key.js';
import type { Ed25519KeyPair } from '../../core/src/transport/did-key.js';
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
  /** Unix timestamp (seconds) of creation. */
  readonly createdAt: number;
}

/**
 * Identity service for managing local cryptographic identities.
 */
export class IdentityService {
  private identity: LocalIdentity | null = null;
  private storage: IStorageDriver | null = null;

  /** Attach a storage driver so identities can be persisted. */
  attachStorage(storage: IStorageDriver): void {
    this.storage = storage;
  }

  /**
   * Create a new identity: Ed25519 signing keys, X25519 encryption keys,
   * and the derived did:key.
   *
   * The identity is persisted when a storage driver is attached.
   */
  async createIdentity(): Promise<Identity> {
    const signing = generateKeypair();
    const encryption = generateX25519Keypair();
    const did = publicKeyToDidKey(signing.publicKey);
    const createdAt = Math.floor(Date.now() / 1000);

    this.identity = { did, signing, encryption, createdAt };
    await this.persist(this.identity);

    return this.toPublicIdentity(this.identity);
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
   * Export the mnemonic backup phrase for key recovery.
   *
   * Deferred: BIP-39 seed derivation is not part of Phase 1A, and
   * emitting a phrase that does not actually reconstruct the key would
   * be worse than refusing.
   */
  async exportMnemonic(): Promise<string> {
    throw new Error(
      'exportMnemonic requires BIP-39 seed derivation, which is not implemented in Phase 1A',
    );
  }

  /**
   * Recover an identity from a mnemonic backup phrase.
   *
   * Deferred alongside `exportMnemonic`.
   */
  async recoverFromMnemonic(_mnemonic: string): Promise<Identity> {
    throw new Error(
      'recoverFromMnemonic requires BIP-39 seed derivation, which is not implemented in Phase 1A',
    );
  }

  /**
   * Revoke the current signing key and broadcast a tombstone.
   *
   * Deferred: revocation tombstones travel on Stream 0x03 and are
   * specified as part of the Phase 3 slashing pipeline (RFC 003 §3.4).
   */
  async revokeKey(): Promise<void> {
    throw new Error(
      'revokeKey depends on the Stream 0x03 revocation pipeline, delivered in Phase 3',
    );
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

    // NOTE: secret keys are stored in the clear in Phase 1A. The column
    // names carry the `_encrypted` suffix because RFC 004 §4.1 requires
    // an OS-keychain-wrapped secret; wiring that keychain is deliberately
    // out of scope here and MUST land before any production use.
    await this.storage.put(StorageCollections.IDENTITY, identity.did, {
      did: identity.did,
      ed25519_public_key: toHex(identity.signing.publicKey),
      ed25519_secret_key_encrypted: toHex(identity.signing.secretKey),
      x25519_public_key: toHex(identity.encryption.publicKey),
      x25519_secret_key_encrypted: toHex(identity.encryption.secretKey),
      created_at: identity.createdAt,
    });
  }

  private async restore(): Promise<LocalIdentity | null> {
    if (!this.storage) return null;

    const rows = await this.storage.query(StorageCollections.IDENTITY, undefined, 1);
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

    return {
      did,
      signing: { publicKey: fromHex(edPub), secretKey: fromHex(edSec) },
      encryption: { publicKey: fromHex(xPub), secretKey: fromHex(xSec) },
      createdAt: typeof createdAt === 'number' ? createdAt : 0,
    };
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
