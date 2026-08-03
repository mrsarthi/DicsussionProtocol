/**
 * @dicsussion/crypto — Key Generation
 *
 * Ed25519 signing keypairs, X25519 encryption keypairs, and
 * ECDH shared secret derivation per RFC 001 §3.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';

import type { KeyPair } from './types.js';

/**
 * Generate a new Ed25519 signing keypair.
 * Used for did:key identity and message signing.
 */
export function generateEd25519Keypair(): KeyPair {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { publicKey, secretKey };
}

/**
 * Generate a new X25519 encryption keypair.
 * Used for ECDH key agreement in E2EE.
 */
export function generateX25519Keypair(): KeyPair {
  const secretKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(secretKey);
  return { publicKey, secretKey };
}

/**
 * Derive a shared secret via X25519 ECDH key agreement.
 *
 * @param myPrivateKey My 32-byte X25519 private key.
 * @param theirPublicKey Their 32-byte X25519 public key.
 * @returns 32-byte shared secret.
 */
export function deriveSharedSecret(
  myPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array,
): Uint8Array {
  return x25519.getSharedSecret(myPrivateKey, theirPublicKey);
}
