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

import {
  decryptFromPeer,
  encryptForPeer,
} from '../../core/src/crypto/encryption.js';
import {
  deserializeEnvelope,
  serializeEnvelope,
} from '../../core/src/crypto/envelope.js';
import type { SecurityEnvelope } from '../../core/src/crypto/types.js';
import { PROTOCOL_VERSION } from '../../core/src/crypto/types.js';

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
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

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
  if (typeof raw['timestamp'] !== 'number') {
    throw new Error('Message payload missing timestamp');
  }

  const authorDid = raw['authorDid'];
  const messageIndex = raw['messageIndex'];

  return {
    id: raw['id'],
    channelId: raw['channelId'],
    authorDid: typeof authorDid === 'string' ? authorDid : undefined,
    content: raw['content'],
    timestamp: raw['timestamp'],
    messageIndex: typeof messageIndex === 'number' ? messageIndex : 0,
  };
}

/**
 * Encrypt a payload into a wire-ready SecurityEnvelope.
 *
 * Phase 1A carries no zero-knowledge proof: `zkProof` is empty and
 * `rlnNullifier` is zero-filled. The RLN fields are populated in Phase 3
 * once the proving engine exists; the envelope layout already reserves
 * them so the wire format does not change.
 *
 * @param payload The plaintext message.
 * @param recipientEncryptionKey Recipient's 32-byte X25519 public key.
 * @param epoch The 10-second epoch this message belongs to.
 * @returns Serialised envelope bytes for Stream `0x02`.
 */
export function sealMessage(
  payload: MessagePayload,
  recipientEncryptionKey: Uint8Array,
  epoch: number,
): Uint8Array {
  const encrypted = encryptForPeer(encodePayload(payload), recipientEncryptionKey);

  const envelope: SecurityEnvelope = {
    version: PROTOCOL_VERSION,
    epoch,
    tierThreshold: 0,
    rlnNullifier: new Uint8Array(32),
    zkProof: new Uint8Array(0),
    ephemeralPubkey: encrypted.ephemeralPubkey,
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
 * @param myEncryptionSecret Our 32-byte X25519 private key.
 * @throws If the envelope is malformed or authentication fails.
 */
export function openMessage(
  bytes: Uint8Array,
  myEncryptionSecret: Uint8Array,
): OpenedMessage {
  const envelope = deserializeEnvelope(bytes);

  const plaintext = decryptFromPeer(
    {
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
      ephemeralPubkey: envelope.ephemeralPubkey,
    },
    myEncryptionSecret,
  );

  return {
    payload: decodePayload(plaintext),
    epoch: envelope.epoch,
    tierThreshold: envelope.tierThreshold,
  };
}
