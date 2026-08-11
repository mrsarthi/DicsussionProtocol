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

import { argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  base64ToBytes,
  bytesToBase64,
  decrypt,
  encrypt,
} from '@dicsussion/core/crypto';

/** Prefix identifying the current at-rest format. */
export const SECRET_BOX_PREFIX = 'v1';

/** HKDF label separating the at-rest key from any other use of the master key. */
const STORAGE_KEY_INFO = 'dicsussion/storage-at-rest/v1';

/** Format tag for passphrase-derived values, which carry their own salt. */
const SECRET_BOX_PREFIX_V2 = 'v2';

/** Salt length for Argon2id, in bytes. */
const SALT_BYTES = 16;

/**
 * Argon2id cost parameters: OWASP's `t=2, m=19 MiB, p=1` profile.
 *
 * Measured on this repo's reference machine with `@noble/hashes`:
 *
 *   t=3, m=64 MiB  ->  2638 ms   (OWASP baseline)
 *   t=2, m=19 MiB  ->   538 ms   (chosen)
 *
 * The baseline was rejected on evidence, not preference. `@noble/hashes`
 * is pure JavaScript and runs an order of magnitude slower than a native
 * Argon2, so the baseline costs ~2.6 s here and worse on a phone. A
 * client that stalls for three seconds on open pushes app developers to
 * abandon passphrases or cache the derived key somewhere careless —
 * trading a real weakness for a theoretical one.
 *
 * 19 MiB still buys roughly a 500,000x slowdown over the HKDF this
 * replaced, which is the change that matters. Revisit if a native Argon2
 * becomes available.
 *
 * Derivation is memoised per salt, so this is paid once per database
 * rather than once per stored value.
 */
const ARGON2_PARAMS = { t: 2, m: 19_456, p: 1, dkLen: 32 } as const;

/**
 * Seals and opens secret column values.
 *
 * Construct with a 32-byte master key, or `null` for development, in
 * which case values pass through unchanged.
 */
export class SecretBox {
  /** Warn once per process, not once per secret. */
  private static unencryptedWarned = false;

  /** Set only for raw-key mode; passphrases derive per salt instead. */
  private readonly key: Uint8Array | null;

  /** Set only for passphrase mode. */
  private readonly passphrase: string | null;

  /** Argon2id results, memoised by salt. */
  private readonly derived = new Map<string, Uint8Array>();

  /** Salt minted for values this instance writes. */
  private writeSalt: Uint8Array | undefined;

  /**
   * @param masterKey 32-byte key, a passphrase string, or null to disable.
   *
   * The two key types are handled differently on purpose. A 32-byte key
   * already carries full entropy, so HKDF is the right tool — it expands
   * and domain-separates, cheaply.
   *
   * A passphrase does not. Running one through HKDF, as this class did
   * until 2026-08-11, produces a key an attacker can guess at roughly a
   * billion candidates per second once they hold the database file, since
   * HKDF is *designed* to be fast. Passphrases are therefore stretched
   * with Argon2id against a random per-database salt.
   */
  constructor(masterKey: Uint8Array | string | null) {
    this.passphrase = typeof masterKey === 'string' ? masterKey : null;
    this.key =
      masterKey === null || typeof masterKey === 'string'
        ? null
        : deriveStorageKey(masterKey);

    if (typeof masterKey === 'string' && masterKey.length === 0) {
      throw new Error('Storage key must not be empty');
    }
  }

  /** Whether values are actually encrypted. */
  get isEnabled(): boolean {
    return this.key !== null || this.passphrase !== null;
  }

  /**
   * Warn once that secrets are being written in the clear.
   *
   * Passthrough is legitimate in development, but silence here is how an
   * application ships having simply forgotten `storageKey` — the data
   * looks fine, the API behaves identically, and identity secrets sit on
   * disk unprotected. Warning once keeps it visible without flooding.
   */
  private warnUnencrypted(): void {
    if (SecretBox.unencryptedWarned) return;
    SecretBox.unencryptedWarned = true;

    console.warn(
      '[dicsussion] Secrets are being stored UNENCRYPTED. Pass ' +
        '`storageKey` to DicsussionClient.init() to enable encryption at ' +
        'rest (RFC 004 §4.1). This is acceptable only in development.',
    );
  }

  /**
   * Encrypt a secret value for storage.
   *
   * @param plaintext The value to protect.
   * @returns A self-describing `v1:nonce:ciphertext` string, or the
   *   input unchanged when encryption is disabled.
   */
  seal(plaintext: string): string {
    if (!this.passphrase && !this.key) {
      this.warnUnencrypted();
      return plaintext;
    }

    // A passphrase writes `v2`, carrying the salt it was stretched with.
    // A 32-byte key already has full entropy and needs no stretching, so
    // it keeps the cheaper `v1` form.
    if (this.passphrase) {
      const { key, salt } = this.passphraseKey();
      const { ciphertext, nonce } = encrypt(
        new TextEncoder().encode(plaintext),
        key,
      );

      return [
        SECRET_BOX_PREFIX_V2,
        bytesToBase64(salt),
        bytesToBase64(nonce),
        bytesToBase64(ciphertext),
      ].join(':');
    }

    const { ciphertext, nonce } = encrypt(
      new TextEncoder().encode(plaintext),
      this.key!,
    );

    return [
      SECRET_BOX_PREFIX,
      bytesToBase64(nonce),
      bytesToBase64(ciphertext),
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
    if (!SecretBox.isSealed(stored)) return stored;

    if (!this.key && !this.passphrase) {
      throw new Error(
        'This database holds encrypted secrets but no storage key was supplied',
      );
    }

    const parts = stored.split(':');

    // `v2` carries its own salt, so a database written by an earlier
    // session — with a different random salt — still opens. Derivations
    // are cached per salt, so the Argon2id cost is paid once per distinct
    // salt rather than once per row.
    if (parts[0] === SECRET_BOX_PREFIX_V2) {
      const [, saltB64, nonceB64, ciphertextB64] = parts;
      if (!saltB64 || !nonceB64 || !ciphertextB64) {
        throw new Error(
          'Malformed encrypted value: expected v2:salt:nonce:ciphertext',
        );
      }
      if (!this.passphrase) {
        throw new Error(
          'This value was sealed with a passphrase, but a raw key was supplied',
        );
      }

      const salt = base64ToBytes(saltB64);
      const plaintext = decrypt(
        base64ToBytes(ciphertextB64),
        base64ToBytes(nonceB64),
        this.passphraseKey(salt).key,
      );

      return new TextDecoder().decode(plaintext);
    }

    const [, nonceB64, ciphertextB64] = parts;
    if (!nonceB64 || !ciphertextB64) {
      throw new Error('Malformed encrypted value: expected v1:nonce:ciphertext');
    }
    if (!this.key) {
      throw new Error(
        'This value was sealed with a raw key, but a passphrase was supplied',
      );
    }

    // AES-GCM authenticates, so a wrong key fails here rather than
    // silently yielding garbage that looks like a key.
    const plaintext = decrypt(
      base64ToBytes(ciphertextB64),
      base64ToBytes(nonceB64),
      this.key,
    );

    return new TextDecoder().decode(plaintext);
  }

  /**
   * Stretch the passphrase against `salt`, caching by salt.
   *
   * Argon2id costs ~100 ms by design. Paying that per stored value would
   * make opening a database with a few hundred secrets take a minute, so
   * derivations are memoised — the deterrent applies to an attacker
   * guessing passphrases, who must derive afresh for each guess.
   */
  private passphraseKey(salt?: Uint8Array): {
    key: Uint8Array;
    salt: Uint8Array;
  } {
    let useSalt = salt;

    if (!useSalt) {
      // No salt yet for this instance: mint one and reuse it for every
      // value this session writes.
      this.writeSalt ??= randomSalt();
      useSalt = this.writeSalt;
    }

    const cacheKey = bytesToBase64(useSalt);
    let key = this.derived.get(cacheKey);

    if (!key) {
      key = argon2id(
        new TextEncoder().encode(this.passphrase!),
        useSalt,
        ARGON2_PARAMS,
      );
      this.derived.set(cacheKey, key);
    }

    return { key, salt: useSalt };
  }

  /** Whether a stored value is in encrypted form. */
  static isSealed(value: string): boolean {
    return (
      value.startsWith(`${SECRET_BOX_PREFIX}:`) ||
      value.startsWith(`${SECRET_BOX_PREFIX_V2}:`)
    );
  }
}

/** Fresh random salt for a passphrase derivation. */
function randomSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_BYTES);
  globalThis.crypto.getRandomValues(salt);
  return salt;
}

/**
 * Derive the at-rest key from an application-supplied master key.
 *
 * Domain-separated so the same master key used elsewhere never produces
 * this key by accident.
 */
function deriveStorageKey(masterKey: Uint8Array): Uint8Array {
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
