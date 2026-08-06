/**
 * @dicsussion/crypto — AES-256-GCM Encryption
 *
 * Symmetric encryption/decryption and ephemeral-key E2EE
 * for message payloads per RFC 003 §6.
 *
 * Uses `@noble/ciphers` rather than `node:crypto` or Web Crypto. The
 * reason is not portability alone — it is that **Web Crypto's AES-GCM is
 * async and these functions are synchronous**. `sealMessage`,
 * `encryptForPeer`, and every caller above them are sync, so adopting
 * `crypto.subtle` would push `await` through the message path for no
 * behavioural gain. Noble is a pure-JS constant-time implementation that
 * is sync on every runtime.
 *
 * The ciphertext layout is unchanged: raw ciphertext followed by the
 * 16-byte GCM tag, byte-for-byte interoperable with the previous
 * `node:crypto` implementation, so data written by an older build still
 * decrypts.
 */

import { gcm } from '@noble/ciphers/aes.js';

import type { EncryptedPayload } from './types.js';
import { deriveSharedSecret, generateX25519Keypair } from './keys.js';

/** AES-256-GCM nonce size in bytes. */
const NONCE_SIZE = 12;

/** AES-256-GCM auth tag size in bytes. */
const TAG_SIZE = 16;

/**
 * Encrypt plaintext using AES-256-GCM with a pre-shared key.
 *
 * @param plaintext Data to encrypt.
 * @param sharedSecret 32-byte symmetric key.
 * @returns Ciphertext with appended auth tag + random nonce.
 */
export function encrypt(
  plaintext: Uint8Array,
  sharedSecret: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  // A repeated (key, nonce) pair under GCM is catastrophic — it leaks
  // the XOR of both plaintexts and the authentication subkey. The nonce
  // must come from a CSPRNG, never a counter we might reset.
  const nonce = new Uint8Array(NONCE_SIZE);
  globalThis.crypto.getRandomValues(nonce);

  // Noble returns ciphertext with the tag already appended.
  return { ciphertext: gcm(sharedSecret, nonce).encrypt(plaintext), nonce };
}

/**
 * Decrypt AES-256-GCM ciphertext with a pre-shared key.
 *
 * @param ciphertext Encrypted data with appended auth tag.
 * @param nonce 12-byte nonce used during encryption.
 * @param sharedSecret 32-byte symmetric key.
 * @returns Decrypted plaintext.
 * @throws If authentication fails.
 */
export function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  sharedSecret: Uint8Array,
): Uint8Array {
  if (ciphertext.length < TAG_SIZE) {
    throw new Error('Ciphertext too short to contain auth tag');
  }

  // Throws on a tag mismatch, which is the point: a caller must never be
  // handed plaintext that failed authentication.
  return gcm(sharedSecret, nonce).decrypt(ciphertext);
}

/**
 * Encrypt plaintext for a specific peer using ephemeral X25519 ECDH.
 *
 * Generates an ephemeral X25519 keypair, derives a shared secret with the
 * recipient's public key, and encrypts with AES-256-GCM.
 *
 * @param plaintext Data to encrypt.
 * @param recipientX25519Pub Recipient's 32-byte X25519 public key.
 * @returns Encrypted payload with ephemeral public key for key agreement.
 */
export function encryptForPeer(
  plaintext: Uint8Array,
  recipientX25519Pub: Uint8Array,
): EncryptedPayload {
  const ephemeral = generateX25519Keypair();
  const sharedSecret = deriveSharedSecret(
    ephemeral.secretKey,
    recipientX25519Pub,
  );
  const { ciphertext, nonce } = encrypt(plaintext, sharedSecret);

  return {
    ciphertext,
    nonce,
    ephemeralPubkey: ephemeral.publicKey,
  };
}

/**
 * Decrypt a payload from a peer using our X25519 private key.
 *
 * Derives the shared secret from the ephemeral public key in the payload
 * and our private key, then decrypts with AES-256-GCM.
 *
 * @param payload Encrypted payload with ephemeral key.
 * @param myX25519Priv Our 32-byte X25519 private key.
 * @returns Decrypted plaintext.
 */
export function decryptFromPeer(
  payload: EncryptedPayload,
  myX25519Priv: Uint8Array,
): Uint8Array {
  const sharedSecret = deriveSharedSecret(
    myX25519Priv,
    payload.ephemeralPubkey,
  );
  return decrypt(payload.ciphertext, payload.nonce, sharedSecret);
}
