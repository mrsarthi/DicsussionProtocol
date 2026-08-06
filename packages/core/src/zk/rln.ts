/**
 * @dicsussion/zk — RLN Signal Construction
 *
 * Builds the per-message rate-limiting signal defined in RFC 003 §4.1.
 *
 * A sender publishes, for every message:
 *   - `η` — the nullifier, fixed by (secret, epoch, message_index)
 *   - `x` — the message commitment, binding the transport transcript
 *   - `y` — the polynomial share at x
 *
 * Staying within quota means each η is used once, so only one point per
 * line is ever revealed and the sender stays anonymous. Exceeding quota
 * reuses an η with a different x, revealing a second point on the same
 * line — see `shamir.ts` for why that surrenders the secret.
 */

import { reduceToField } from '../crypto/field.js';
import {
  poseidonDomain,
  DomainSeparator,
  rlnNullifier,
  slopeWitness,
} from '../crypto/poseidon.js';
import { evaluateShare } from './shamir.js';
import type { PolynomialShare } from './shamir.js';

/** Epoch duration in seconds (RFC 003 §3.0). */
export const EPOCH_DURATION_S = 10;

/** Rolling window width in epochs (RFC 003 §3.0). */
export const ROLLING_WINDOW_EPOCHS = 3;

/** Everything needed to bind a message commitment (RFC 003 §4.1). */
export interface MessageContext {
  /** Protocol version byte. */
  readonly version: number;
  /** Sub-stream the message travels on. */
  readonly streamId: number;
  readonly epoch: number;
  /** Proven tier threshold (0, 50, 100, 200). */
  readonly tier: number;
  /** Hash of the ciphertext, as raw bytes. */
  readonly ciphertextHash: Uint8Array;
  /** Recipient identifier, reduced into the field. */
  readonly recipientId: bigint;
}

/** A complete RLN signal accompanying one message. */
export interface RlnSignal {
  readonly nullifier: bigint;
  readonly x: bigint;
  readonly y: bigint;
  readonly epoch: number;
  readonly messageIndex: number;
}

/** Current epoch from a unix timestamp, with optional peer clock offset. */
export function currentEpoch(
  nowMs: number = Date.now(),
  peerOffsetMs = 0,
): number {
  return Math.floor((nowMs + peerOffsetMs) / 1000 / EPOCH_DURATION_S);
}

/**
 * Compute the public message commitment `x`.
 *
 * `x = Poseidon(DS_MSG, H(version ‖ stream_id ‖ epoch ‖ tier ‖
 *                          ciphertext_hash ‖ recipient_id) mod r)`
 *
 * Binding the full transport context is what stops a captured share
 * being replayed in a different stream or epoch to forge a second point.
 */
export function messageCommitment(context: MessageContext): bigint {
  const transcript = encodeTranscript(context);
  return poseidonDomain(DomainSeparator.MSG, reduceToField(transcript));
}

/**
 * Build the RLN signal for one message.
 *
 * @param identitySecret The sender's secret a_0.
 * @param context Transport context binding the commitment.
 * @param messageIndex Index within the epoch, `0 ≤ i < quota`.
 */
export function createSignal(
  identitySecret: bigint,
  context: MessageContext,
  messageIndex: number,
): RlnSignal {
  const epoch = BigInt(context.epoch);
  const index = BigInt(messageIndex);

  const nullifier = rlnNullifier(identitySecret, epoch, index);
  const slope = slopeWitness(identitySecret, epoch, index);
  const x = messageCommitment(context);

  return {
    nullifier,
    x,
    y: evaluateShare(identitySecret, slope, x),
    epoch: context.epoch,
    messageIndex,
  };
}

/** Project a signal into the share form the slashing detector consumes. */
export function signalToShare(signal: RlnSignal): PolynomialShare {
  return { x: signal.x, y: signal.y, nullifier: signal.nullifier };
}

/**
 * Whether a proof's epoch is still acceptable.
 *
 * RFC 003 §3.2 rejects proofs older than 2 epochs (20 seconds); the
 * rolling window (§4.1) spans 3. Accepting stale proofs would let a
 * sender bank quota from quiet epochs and spend it in a burst.
 */
export function isEpochFresh(
  proofEpoch: number,
  currentEpochValue: number,
  maxAgeEpochs = 2,
): boolean {
  const age = currentEpochValue - proofEpoch;
  // Future-dated proofs are rejected too — a skewed or lying clock must
  // not buy extra quota.
  return age >= 0 && age <= maxAgeEpochs;
}

/**
 * Epoch quota for a proven tier (RFC 003 §3.2).
 *
 * @param tierThreshold The proven threshold: 0, 50, 100, or 200.
 */
export function quotaForTier(tierThreshold: number): number {
  if (tierThreshold >= 200) return 100;
  if (tierThreshold >= 100) return 10;
  if (tierThreshold >= 50) return 3;
  return 1;
}

/**
 * Whether a message index is inside the rolling-window quota.
 *
 * `0 ≤ i < Q_window(T, W)` per RFC 003 §4.1.
 */
export function isWithinQuota(
  messageIndex: number,
  tierThreshold: number,
  windowEpochs: number = ROLLING_WINDOW_EPOCHS,
): boolean {
  if (!Number.isInteger(messageIndex) || messageIndex < 0) return false;
  return messageIndex < quotaForTier(tierThreshold) * windowEpochs;
}

/** Serialise the transcript fields bound into the commitment. */
function encodeTranscript(context: MessageContext): Uint8Array {
  const header = new Uint8Array(1 + 1 + 8 + 2);
  const view = new DataView(header.buffer);

  view.setUint8(0, context.version);
  view.setUint8(1, context.streamId);
  view.setBigUint64(2, BigInt(context.epoch), false);
  view.setUint16(10, context.tier, false);

  const recipient = new Uint8Array(32);
  let value = context.recipientId;
  for (let i = 31; i >= 0; i--) {
    recipient[i] = Number(value & 0xffn);
    value >>= 8n;
  }

  const out = new Uint8Array(
    header.length + context.ciphertextHash.length + recipient.length,
  );
  out.set(header, 0);
  out.set(context.ciphertextHash, header.length);
  out.set(recipient, header.length + context.ciphertextHash.length);

  return out;
}
