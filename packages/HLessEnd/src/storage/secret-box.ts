/**
 * @dicsussion/storage — Encryption at Rest for Secret Columns
 *
 * The `identity` table's columns have always been named
 * `*_secret_key_encrypted`. Until now that was aspirational — the values
 * were plaintext. This makes the names true.
 *
 * WHAT THIS PROTECTS AGAINST: a database file read at rest — a stolen
 * laptop, a backup, another app on the device. It does **not** protect
 * against an attacker who already has the master key, or who can read
 * this process's memory while the client is running.
 *
 * WHERE THE KEY COMES FROM is deliberately the application's problem.
 * A headless SDK cannot know whether the right source is an OS keychain,
 * a user passphrase, or a hardware token, so it takes a key and says
 * nothing about its provenance. RFC 004 §4.1's OS-keychain requirement
 * is then satisfied by the *app* handing us a keychain-held key.
 *
 * Values are stored as `v1:<base64 nonce>:<base64 ciphertext>`, so an
 * encrypted column is self-describing and a future scheme can be told
 * apart by its prefix.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { decrypt, encrypt } from '@dicsussion/core/crypto';

/** Prefix identifying the current at-rest format. */
export const SECRET_BOX_PREFIX = 'v1';

/** HKDF label separating the at-rest key from any other use of the master key. */
const STORAGE_KEY_INFO = 'dicsussion/storage-at-rest/v1';

/**
 * Seals and opens secret column values.
 *
 * Construct with a 32-byte master key, or `null` for development, in
 * which case values pass through unchanged.
 */
export class SecretBox {
  private readonly key: Uint8Array | null;

  /**
   * @param masterKey 32-byte key, a passphrase string, or null to disable.
   */
  constructor(masterKey: Uint8Array | string | null) {
    this.key = masterKey === null ? null : deriveStorageKey(masterKey);
  }

  /** Whether values are actually encrypted. */
  get isEnabled(): boolean {
    return this.key !== null;
  }

  /**
   * Encrypt a secret value for storage.
   *
   * @param plaintext The value to protect.
   * @returns A self-describing `v1:nonce:ciphertext` string, or the
   *   input unchanged when encryption is disabled.
   */
  seal(plaintext: string): string {
    if (!this.key) return plaintext;

    const { ciphertext, nonce } = encrypt(
      new TextEncoder().encode(plaintext),
      this.key,
    );

    return [
      SECRET_BOX_PREFIX,
      Buffer.from(nonce).toString('base64'),
      Buffer.from(ciphertext).toString('base64'),
    ].join(':');
  }

  /**
   * Decrypt a stored value.
   *
   * Values without the prefix are returned as-is, so a database written
   * before encryption was enabled still opens. Upgrading is therefore a
   * matter of rewriting rows, not a migration that can fail halfway.
   *
   * @throws If the value is encrypted but the key is wrong or absent.
   */
  open(stored: string): string {
    if (!stored.startsWith(`${SECRET_BOX_PREFIX}:`)) return stored;

    if (!this.key) {
      throw new Error(
        'This database holds encrypted secrets but no storage key was supplied',
      );
    }

    const [, nonceB64, ciphertextB64] = stored.split(':');
    if (!nonceB64 || !ciphertextB64) {
      throw new Error('Malformed encrypted value: expected v1:nonce:ciphertext');
    }

    // AES-GCM authenticates, so a wrong key fails here rather than
    // silently yielding garbage that looks like a key.
    const plaintext = decrypt(
      new Uint8Array(Buffer.from(ciphertextB64, 'base64')),
      new Uint8Array(Buffer.from(nonceB64, 'base64')),
      this.key,
    );

    return new TextDecoder().decode(plaintext);
  }

  /** Whether a stored value is in encrypted form. */
  static isSealed(value: string): boolean {
    return value.startsWith(`${SECRET_BOX_PREFIX}:`);
  }
}

/**
 * Derive the at-rest key from an application-supplied master key.
 *
 * Domain-separated so the same master key used elsewhere never produces
 * this key by accident.
 */
function deriveStorageKey(masterKey: Uint8Array | string): Uint8Array {
  const material =
    typeof masterKey === 'string'
      ? new TextEncoder().encode(masterKey)
      : masterKey;

  if (material.length === 0) {
    throw new Error('Storage key must not be empty');
  }

  return hkdf(
    sha256,
    material,
    undefined,
    new TextEncoder().encode(STORAGE_KEY_INFO),
    32,
  );
}
