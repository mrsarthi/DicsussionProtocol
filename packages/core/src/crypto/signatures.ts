/**
 * @dicsussion/crypto — Ed25519 Signatures
 *
 * Message signing and verification for handshake authentication
 * and revocation tombstones per RFC 001 §5.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

/**
 * Sign a message with an Ed25519 secret key.
 *
 * @param message The message bytes to sign.
 * @param secretKey 32-byte Ed25519 private key (seed).
 * @returns 64-byte Ed25519 signature.
 */
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/**
 * Verify an Ed25519 signature over a message.
 *
 * @param message The original message bytes.
 * @param signature 64-byte Ed25519 signature.
 * @param publicKey 32-byte Ed25519 public key.
 * @returns True if the signature is valid.
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
