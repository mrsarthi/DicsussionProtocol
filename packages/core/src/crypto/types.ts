/**
 * @dicsussion/crypto — Type Definitions
 *
 * Key types, encrypted payload structures, and SecurityEnvelope
 * per RFC 001 §3 and RFC 003 §6.
 */

/** Ed25519 or X25519 keypair. */
export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

/** AES-256-GCM encrypted payload with ephemeral key material. */
export interface EncryptedPayload {
  /** AES-256-GCM ciphertext. */
  readonly ciphertext: Uint8Array;
  /** 12-byte AES-256-GCM nonce. */
  readonly nonce: Uint8Array;
  /** 32-byte ephemeral X25519 public key (for key agreement). */
  readonly ephemeralPubkey: Uint8Array;
}

/**
 * Security envelope for wire transmission over Sub-Stream 0x02.
 * Per RFC 003 §6.1, `version` MUST appear at offset 0.
 */
export interface SecurityEnvelope {
  /** Protocol version (0x01). */
  readonly version: number;
  /** Epoch ID (10s window). */
  readonly epoch: number;
  /** Proven tier threshold (0, 50, 100, 200). */
  readonly tierThreshold: number;
  /** 32-byte Poseidon RLN nullifier. */
  readonly rlnNullifier: Uint8Array;
  /** Unified Groth16 proof bytes (~128 bytes). */
  readonly zkProof: Uint8Array;
  /** 32-byte ephemeral X25519 public key. */
  readonly ephemeralPubkey: Uint8Array;
  /** 12-byte AES-256-GCM nonce. */
  readonly nonce: Uint8Array;
  /** Variable-length encrypted payload. */
  readonly ciphertext: Uint8Array;
}

/** Current protocol version. */
export const PROTOCOL_VERSION = 0x01;
