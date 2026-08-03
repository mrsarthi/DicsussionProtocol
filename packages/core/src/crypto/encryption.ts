/**
 * @dicsussion/crypto — AES-256-GCM Encryption
 *
 * Symmetric encryption/decryption and ephemeral-key E2EE
 * for message payloads per RFC 003 §6.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import type { EncryptedPayload, KeyPair } from './types.js';
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
  const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
  const cipher = createCipheriv('aes-256-gcm', sharedSecret, nonce);

  const encrypted = cipher.update(plaintext);
  const final = cipher.final();
  const tag = cipher.getAuthTag();

  // Concatenate encrypted + final + tag
  const ciphertext = new Uint8Array(encrypted.length + final.length + TAG_SIZE);
  ciphertext.set(new Uint8Array(encrypted.buffer, encrypted.byteOffset, encrypted.length));
  ciphertext.set(
    new Uint8Array(final.buffer, final.byteOffset, final.length),
    encrypted.length,
  );
  ciphertext.set(new Uint8Array(tag.buffer, tag.byteOffset, tag.length), encrypted.length + final.length);

  return { ciphertext, nonce };
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

  const encryptedData = ciphertext.subarray(0, ciphertext.length - TAG_SIZE);
  const tag = ciphertext.subarray(ciphertext.length - TAG_SIZE);

  const decipher = createDecipheriv('aes-256-gcm', sharedSecret, nonce);
  decipher.setAuthTag(tag);

  const decrypted = decipher.update(encryptedData);
  const final = decipher.final();

  const result = new Uint8Array(decrypted.length + final.length);
  result.set(new Uint8Array(decrypted.buffer, decrypted.byteOffset, decrypted.length));
  result.set(new Uint8Array(final.buffer, final.byteOffset, final.length), decrypted.length);

  return result;
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
  const sharedSecret = deriveSharedSecret(ephemeral.secretKey, recipientX25519Pub);
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
  const sharedSecret = deriveSharedSecret(myX25519Priv, payload.ephemeralPubkey);
  return decrypt(payload.ciphertext, payload.nonce, sharedSecret);
}
