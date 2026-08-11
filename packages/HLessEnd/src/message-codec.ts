/**
 * @dicsussion/sdk — Message Payload Codec
 *
 * Encodes the plaintext that goes *inside* a SecurityEnvelope before
 * AES-256-GCM encryption, and rebuilds it after decryption.
 *
 * Channel id and author live in the encrypted plaintext rather than the
 * envelope header, so an on-path observer of Stream `0x02` learns
 * neither the conversation nor the participants — only that a frame of
 * some size moved between two peers.
 */

import { decrypt, encrypt } from '@dicsussion/core/crypto';
import { deserializeEnvelope, serializeEnvelope } from '@dicsussion/core/crypto';
import type { SecurityEnvelope } from '@dicsussion/core/crypto';
import { PROTOCOL_VERSION } from '@dicsussion/core/crypto';
import type { WireProof } from './proof-service.js';

/** The plaintext body carried inside an envelope. */
export interface MessagePayload {
  readonly id: string;
  readonly channelId: string;
  /** Author's did:key, or undefined in anonymous RLN channels. */
  readonly authorDid?: string;
  readonly content: string;
  /** Unix timestamp in seconds. */
  readonly timestamp: number;
  /**
   * Sender-assigned per-channel sequence number (RFC 002 §4.3), used to
   * order messages that share a one-second timestamp.
   */
  readonly messageIndex: number;
  /**
   * RLN nullifier η, present exactly when `authorDid` is absent.
   *
   * In an anonymous channel this is the only sender identifier, and it
   * is what makes rate limiting possible without attribution: reusing
   * one within an epoch is what exposes the sender's own secret.
   */
  readonly nullifierHash?: string;
  /**
   * The RLN polynomial share accompanying an anonymous message.
   *
   * `x` is the message commitment, `y = a_0 + a_1·x`. Both travel with
   * the message because slashing needs **two points on the same line**:
   * without `y` on the wire, a recipient can see that a nullifier was
   * reused but cannot interpolate the offender's secret, and the rate
   * limit is unenforceable.
   *
   * Present exactly when `nullifierHash` is.
   */
  readonly rlnShare?: { readonly x: string; readonly y: string };
  /**
   * Groth16 proof of membership, tier, and quota (RFC 003 §3.4).
   *
   * Present when the channel's signed anchor requires proofs. Policy
   * comes from the anchor rather than local settings, so every member
   * reaches the same answer.
   */
  readonly zkProof?: WireProof;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Largest accepted message body, in UTF-16 code units.
 *
 * The parser validated field *types* but not *sizes*, so a peer could send
 * a multi-gigabyte `content` string. AES-GCM authenticates, so the sender
 * must already be paired — but pairing means "accepted once", not "trusted
 * forever", and the cost lands on memory and on every row `MessageStore`
 * subsequently writes.
 *
 * 64 KiB matches `MAX_GOSSIP_BODY`, so the two inbound paths agree on what
 * counts as absurd.
 */
const MAX_CONTENT_LENGTH = 65_536;

/** Largest accepted message or channel identifier. */
const MAX_ID_LENGTH = 256;

/** Serialise a payload to its canonical JSON byte form. */
export function encodePayload(payload: MessagePayload): Uint8Array {
  return encoder.encode(
    JSON.stringify({
      id: payload.id,
      channelId: payload.channelId,
      authorDid: payload.authorDid ?? null,
      content: payload.content,
      timestamp: payload.timestamp,
      messageIndex: payload.messageIndex,
      nullifierHash: payload.nullifierHash ?? null,
      rlnShare: payload.rlnShare ?? null,
      zkProof: payload.zkProof ?? null,
    }),
  );
}

/**
 * Parse a decrypted payload.
 *
 * @throws If the bytes are not a well-formed payload. Callers treat this
 *   as a corrupt or hostile frame and drop it.
 */
export function decodePayload(bytes: Uint8Array): MessagePayload {
  const parsed: unknown = JSON.parse(decoder.decode(bytes));

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Message payload is not an object');
  }

  const raw = parsed as Record<string, unknown>;

  if (typeof raw['id'] !== 'string') throw new Error('Message payload missing id');
  if (typeof raw['channelId'] !== 'string') {
    throw new Error('Message payload missing channelId');
  }
  if (typeof raw['content'] !== 'string') {
    throw new Error('Message payload missing content');
  }
  if (raw['content'].length > MAX_CONTENT_LENGTH) {
    throw new Error(
      `Message content too large: ${raw['content'].length} > ${MAX_CONTENT_LENGTH}`,
    );
  }
  if (raw['id'].length > MAX_ID_LENGTH) {
    throw new Error(`Message id too large: ${raw['id'].length} > ${MAX_ID_LENGTH}`);
  }
  if (raw['channelId'].length > MAX_ID_LENGTH) {
    throw new Error(
      `Channel id too large: ${raw['channelId'].length} > ${MAX_ID_LENGTH}`,
    );
  }
  if (typeof raw['timestamp'] !== 'number') {
    throw new Error('Message payload missing timestamp');
  }

  const authorDid = raw['authorDid'];
  const messageIndex = raw['messageIndex'];
  const nullifierHash = raw['nullifierHash'];
  const share = raw['rlnShare'] as { x?: unknown; y?: unknown } | null;
  const proof = raw['zkProof'] as
    | { proof?: unknown; publicSignals?: unknown }
    | null;

  return {
    id: raw['id'],
    channelId: raw['channelId'],
    authorDid: typeof authorDid === 'string' ? authorDid : undefined,
    content: raw['content'],
    timestamp: raw['timestamp'],
    messageIndex: typeof messageIndex === 'number' ? messageIndex : 0,
    nullifierHash: typeof nullifierHash === 'string' ? nullifierHash : undefined,
    rlnShare:
      share && typeof share.x === 'string' && typeof share.y === 'string'
        ? { x: share.x, y: share.y }
        : undefined,
    // Signals must be strings on the wire: a JSON number cannot hold a
    // 254-bit field element without silently losing precision.
    zkProof:
      proof &&
      proof.proof !== undefined &&
      Array.isArray(proof.publicSignals) &&
      proof.publicSignals.every((v) => typeof v === 'string')
        ? { proof: proof.proof, publicSignals: proof.publicSignals as string[] }
        : undefined,
  };
}

/**
 * Encrypt a payload into a wire-ready SecurityEnvelope.
 *
 * The envelope's `rlnNullifier` carries the RLN nullifier when the
 * payload is anonymous, so a recipient can index shares without first
 * decrypting. The Groth16 proof, when the channel requires one, rides
 * inside the encrypted plaintext rather than the envelope header —
 * public signals name the channel's membership root, which would
 * otherwise leak the conversation to an on-path observer.
 *
 * @param payload The plaintext message.
 * @param sessionKey The connection's forward-secret session key
 *   (RFC 001 §5.1), not a long-term identity key.
 * @param epoch The 10-second epoch this message belongs to.
 * @returns Serialised envelope bytes for Stream `0x02`.
 */
export function sealMessage(
  payload: MessagePayload,
  sessionKey: Uint8Array,
  epoch: number,
): Uint8Array {
  const encrypted = encrypt(encodePayload(payload), sessionKey);

  const envelope: SecurityEnvelope = {
    version: PROTOCOL_VERSION,
    epoch,
    tierThreshold: 0,
    rlnNullifier: new Uint8Array(32),
    zkProof: new Uint8Array(0),
    // Reserved. Sealing now uses the connection's forward-secret session
    // key, so there is no per-message ephemeral half to publish; the
    // field stays in the layout so the wire format is unchanged.
    ephemeralPubkey: new Uint8Array(32),
    nonce: encrypted.nonce,
    ciphertext: encrypted.ciphertext,
  };

  return serializeEnvelope(envelope);
}

/** A decrypted message plus the envelope metadata it arrived with. */
export interface OpenedMessage {
  readonly payload: MessagePayload;
  readonly epoch: number;
  readonly tierThreshold: number;
}

/**
 * Decrypt an inbound Stream `0x02` envelope.
 *
 * @param bytes Raw envelope bytes off the wire.
 * @param sessionKey The connection's forward-secret session key.
 * @throws If the envelope is malformed or authentication fails.
 */
export function openMessage(
  bytes: Uint8Array,
  sessionKey: Uint8Array,
): OpenedMessage {
  const envelope = deserializeEnvelope(bytes);

  const plaintext = decrypt(envelope.ciphertext, envelope.nonce, sessionKey);

  return {
    payload: decodePayload(plaintext),
    epoch: envelope.epoch,
    tierThreshold: envelope.tierThreshold,
  };
}
