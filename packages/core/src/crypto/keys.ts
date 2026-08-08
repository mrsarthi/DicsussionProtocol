/**
 * @dicsussion/crypto — Key Generation
 *
 * Ed25519 signing keypairs, X25519 encryption keypairs, and
 * ECDH shared secret derivation per RFC 001 §3.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

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
 * Domain separation for the message-encryption key.
 *
 * Distinct labels here are what let a future key be derived from the
 * same exchange without either key revealing anything about the other.
 */
const E2EE_KEY_INFO = new TextEncoder().encode('dicsussion/e2ee-key/v1');

/**
 * Derive a message-encryption key via X25519 ECDH plus HKDF-SHA256.
 *
 * **The raw ECDH output must never be used as a cipher key directly.**
 * It is the u-coordinate of a curve point, not uniform bytes: it carries
 * algebraic structure, and a few of its bits are biased. Every serious
 * protocol — TLS 1.3, Signal, Noise, WireGuard — runs it through a KDF
 * first, for three reasons:
 *
 *   1. The output becomes indistinguishable from random.
 *   2. The `info` label gives key separation, so a second use of the
 *      same exchange cannot produce a correlated key.
 *   3. It gives somewhere to bind transcript data later, without another
 *      format change.
 *
 * @param myPrivateKey My 32-byte X25519 private key.
 * @param theirPublicKey Their 32-byte X25519 public key.
 * @returns 32-byte AES-256 key.
 */
export function deriveSharedSecret(
  myPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array,
): Uint8Array {
  const rawEcdh = x25519.getSharedSecret(myPrivateKey, theirPublicKey);

  // Salt is omitted deliberately: both peers must derive the same key
  // and there is no agreed random value to use. HKDF treats an absent
  // salt as a zero block, which is safe when the IKM is a curve point.
  return hkdf(sha256, rawEcdh, undefined, E2EE_KEY_INFO, 32);
}
