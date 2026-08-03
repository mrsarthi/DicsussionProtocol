/**
 * @dicsussion/transport — Handshake Protocol
 *
 * Mutually authenticated handshake sequence with clock synchronization,
 * nonce replay protection, and timeout enforcement per RFC 001 §5.
 *
 * Sequence:
 *   A → B: HandshakeInit { timestamp, did_key, nonce_a }
 *   B → A: HandshakeChallenge { nonce_b, sig_b(nonce_a) }
 *   A → B: HandshakeAck { sig_a(nonce_b) }
 */

import { randomBytes } from 'node:crypto';

import { ed25519 } from '@noble/curves/ed25519.js';

import type { Ed25519KeyPair } from './did-key.js';
import type { HandshakeAck, HandshakeChallenge, HandshakeInit } from './types.js';
import {
  EPOCH_DURATION_S,
  MAX_CLOCK_SKEW_S,
  NONCE_EXPIRY_S,
  TransportError,
  TransportException,
} from './types.js';

/** Nonce replay tracker: maps nonce hex → timestamp of receipt. */
const nonceRegistry = new Map<string, number>();

/** Convert Uint8Array to hex string for map key. */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Prune expired nonces older than NONCE_EXPIRY_S from the registry.
 */
function pruneExpiredNonces(nowS: number): void {
  for (const [key, timestamp] of nonceRegistry) {
    if (nowS - timestamp > NONCE_EXPIRY_S) {
      nonceRegistry.delete(key);
    }
  }
}

/**
 * Create a HandshakeInit message with a fresh 32-byte nonce.
 *
 * @param keypair The initiator's Ed25519 keypair.
 * @param didKey The initiator's did:key string.
 * @param timestampS Optional unix timestamp in seconds (defaults to now).
 */
export function createHandshakeInit(
  keypair: Ed25519KeyPair,
  didKey: string,
  timestampS?: number,
): HandshakeInit {
  void keypair; // keypair used for later signing, included for API consistency
  const nonce = new Uint8Array(randomBytes(32));
  const timestamp = timestampS ?? Math.floor(Date.now() / 1000);

  return { timestamp, didKey, nonce };
}

/**
 * Process an incoming HandshakeInit and produce a HandshakeChallenge.
 *
 * Validates:
 * - Clock skew ≤ 10 seconds
 * - Nonce not replayed
 * - Nonce not expired (age ≤ 300 seconds)
 *
 * @param init The received HandshakeInit.
 * @param responderKeypair Responder's Ed25519 keypair for signing.
 * @param localTimestampS Optional local unix timestamp in seconds.
 * @returns The HandshakeChallenge and computed clock offset.
 */
export function processHandshakeInit(
  init: HandshakeInit,
  responderKeypair: Ed25519KeyPair,
  localTimestampS?: number,
): { challenge: HandshakeChallenge; clockOffset: number } {
  const localTime = localTimestampS ?? Math.floor(Date.now() / 1000);
  const clockOffset = calculateClockOffset(init.timestamp, localTime);

  // Validate clock skew
  if (Math.abs(clockOffset) > MAX_CLOCK_SKEW_S) {
    throw new TransportException(
      TransportError.ClockSkewTooHigh,
      `Clock skew ${clockOffset}s exceeds maximum ${MAX_CLOCK_SKEW_S}s`,
    );
  }

  // Check nonce age (bound to handshake timestamp, not sliding timer)
  const nonceAge = localTime - init.timestamp;
  if (nonceAge > NONCE_EXPIRY_S) {
    throw new TransportException(
      TransportError.ReplayRejected,
      `Handshake age ${nonceAge}s exceeds maximum ${NONCE_EXPIRY_S}s`,
    );
  }

  // Check nonce replay
  const nonceHex = toHex(init.nonce);
  pruneExpiredNonces(localTime);

  if (nonceRegistry.has(nonceHex)) {
    throw new TransportException(
      TransportError.ReplayRejected,
      'Nonce replay detected',
    );
  }
  nonceRegistry.set(nonceHex, localTime);

  // Sign initiator's nonce with responder's key
  const signature = ed25519.sign(init.nonce, responderKeypair.secretKey);

  // Generate responder's nonce
  const nonce = new Uint8Array(randomBytes(32));

  return {
    challenge: { nonce, signature },
    clockOffset,
  };
}

/**
 * Create a HandshakeAck by signing the responder's nonce.
 *
 * @param keypair Initiator's Ed25519 keypair.
 * @param responderNonce The responder's 32-byte nonce from the challenge.
 */
export function createHandshakeAck(
  keypair: Ed25519KeyPair,
  responderNonce: Uint8Array,
): HandshakeAck {
  const signature = ed25519.sign(responderNonce, keypair.secretKey);
  return { signature };
}

/**
 * Verify a HandshakeAck signature against a nonce and public key.
 *
 * @param ack The received HandshakeAck.
 * @param peerPublicKey The peer's 32-byte Ed25519 public key.
 * @param expectedNonce The nonce that was sent in the challenge.
 * @returns True if the signature is valid.
 */
export function verifyHandshakeAck(
  ack: HandshakeAck,
  peerPublicKey: Uint8Array,
  expectedNonce: Uint8Array,
): boolean {
  try {
    return ed25519.verify(ack.signature, expectedNonce, peerPublicKey);
  } catch {
    return false;
  }
}

/**
 * Verify a HandshakeChallenge signature (responder signed initiator's nonce).
 *
 * @param challenge The received HandshakeChallenge.
 * @param responderPublicKey Responder's 32-byte Ed25519 public key.
 * @param initiatorNonce The nonce originally sent in HandshakeInit.
 * @returns True if the signature is valid.
 */
export function verifyHandshakeChallenge(
  challenge: HandshakeChallenge,
  responderPublicKey: Uint8Array,
  initiatorNonce: Uint8Array,
): boolean {
  try {
    return ed25519.verify(challenge.signature, initiatorNonce, responderPublicKey);
  } catch {
    return false;
  }
}

/**
 * Calculate clock offset between remote and local timestamps.
 * Δ_peer = T_remote − T_local
 *
 * @param remoteTimestampS Remote peer's unix timestamp in seconds.
 * @param localTimestampS Local unix timestamp in seconds.
 * @returns The clock offset in seconds.
 */
export function calculateClockOffset(remoteTimestampS: number, localTimestampS: number): number {
  return remoteTimestampS - localTimestampS;
}

/**
 * Calculate the current epoch number.
 * E = ⌊(T_local + Δ_peer) / 10⌋
 *
 * @param localTimestampS Local unix timestamp in seconds.
 * @param peerOffsetS Clock offset from handshake (Δ_peer).
 * @returns The epoch number.
 */
export function calculateEpoch(localTimestampS: number, peerOffsetS: number): number {
  return Math.floor((localTimestampS + peerOffsetS) / EPOCH_DURATION_S);
}

/**
 * Clear the nonce replay registry. Useful for testing.
 */
export function clearNonceRegistry(): void {
  nonceRegistry.clear();
}
