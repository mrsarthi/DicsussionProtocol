/**
 * @dicsussion/transport — did:key Identity
 *
 * Ed25519 keypair generation and W3C did:key encoding/decoding
 * per RFC 001 §3.1–3.2.
 *
 * Encoding: did:key:z6M[Base58Btc-encoded-multicodec-public-key]
 * Multicodec Prefix: 0xed01 (Ed25519 public key varint)
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { base58btc } from 'multiformats/bases/base58';

/** Ed25519 multicodec varint prefix bytes. */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/** did:key method prefix. */
const DID_KEY_PREFIX = 'did:key:';

/** Expected total length: 2-byte prefix + 32-byte public key. */
const PREFIXED_KEY_LENGTH = ED25519_MULTICODEC_PREFIX.length + 32;

export interface Ed25519KeyPair {
  /** 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** 32-byte Ed25519 private key (seed). */
  readonly secretKey: Uint8Array;
}

/**
 * Generate a new Ed25519 keypair.
 * @returns A fresh Ed25519 keypair with 32-byte public and secret keys.
 */
export function generateKeypair(): Ed25519KeyPair {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { publicKey, secretKey };
}

/**
 * Derive a W3C did:key string from a raw Ed25519 public key.
 *
 * Format: did:key:z6M[Base58Btc(0xed01 || pubkey)]
 *
 * @param publicKey Raw 32-byte Ed25519 public key.
 * @returns The did:key string.
 */
export function publicKeyToDidKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32, got ${publicKey.length}`);
  }

  const prefixed = new Uint8Array(PREFIXED_KEY_LENGTH);
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(publicKey, ED25519_MULTICODEC_PREFIX.length);

  return DID_KEY_PREFIX + base58btc.encode(prefixed);
}

/**
 * Extract the raw 32-byte Ed25519 public key from a did:key string.
 *
 * @param did The did:key string (did:key:z6M...).
 * @returns The raw 32-byte public key.
 * @throws If the did:key format is invalid.
 */
export function didKeyToPublicKey(did: string): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new Error(`Invalid did:key format: must start with "${DID_KEY_PREFIX}"`);
  }

  const multibaseEncoded = did.slice(DID_KEY_PREFIX.length);
  const decoded = base58btc.decode(multibaseEncoded);

  if (decoded.length !== PREFIXED_KEY_LENGTH) {
    throw new Error(
      `Invalid did:key decoded length: expected ${PREFIXED_KEY_LENGTH}, got ${decoded.length}`,
    );
  }

  // Validate multicodec prefix
  if (decoded[0] !== ED25519_MULTICODEC_PREFIX[0] || decoded[1] !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new Error(
      `Invalid multicodec prefix: expected 0xed01, got 0x${decoded[0]?.toString(16)}${decoded[1]?.toString(16)}`,
    );
  }

  // Zero-copy: return a view into the decoded buffer
  return decoded.subarray(ED25519_MULTICODEC_PREFIX.length);
}

/**
 * Validate whether a string is a well-formed did:key for Ed25519.
 *
 * @param did The string to validate.
 * @returns True if the did:key is valid.
 */
export function validateDidKey(did: string): boolean {
  try {
    didKeyToPublicKey(did);
    return true;
  } catch {
    return false;
  }
}
