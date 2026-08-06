/**
 * @dicsussion/crdt — Stream 0x01 Sync Message Codec
 *
 * Binary encoding for the state reconciliation messages exchanged on
 * Sub-Stream `0x01` per RFC 002 §4.2.
 *
 * Wire format:
 *   [0]        msg_type   u8
 *   [1]        doc_id_len u8    (0 when the message is document-agnostic)
 *   [2..N]     doc_id     utf8
 *   [N..N+4]   body_len   u32 BE
 *   [N+4..]    body       variable
 *
 * Bodies are decoded per message type; all payload views are zero-copy
 * subarrays over the caller's buffer (AGENT_INSTRUCTIONS §4.2 rule 1).
 */

import { bytesToField, fieldToBytes } from '../crypto/field.js';
import type { DepartureRecord } from './membership-departure.js';

/** Sync message discriminants carried in the `msg_type` byte. */
export const SyncMessageType = {
  /** Advertise the local canonical state root (RFC 002 §4.2 step 1). */
  ROOT_SYNC: 0x01,
  /** Answer a root advertisement (step 2). */
  ROOT_MATCH: 0x02,
  /** Ask a peer for changes we are missing (step 5). */
  REQUEST_DELTA: 0x03,
  /** Deliver Automerge binary changes (step 6). */
  SEND_DELTA: 0x04,
  /** Advertise a channel's membership tree root (RFC 002 §4.1). */
  MEMBER_ROOT: 0x05,
  /** Deliver identity commitments so member sets can be unioned. */
  MEMBER_LIST: 0x06,
  /** Deliver signed departure tombstones (the 2P-set's remove half). */
  MEMBER_DEPARTURE: 0x07,
} as const;

export type SyncMessageTypeValue =
  (typeof SyncMessageType)[keyof typeof SyncMessageType];

const VALID_TYPES = new Set<number>(Object.values(SyncMessageType));

/** Maximum sync body size — mirrors the 1 MB decompression ceiling. */
export const MAX_SYNC_BODY_SIZE = 1_048_576;

/** A decoded Stream 0x01 message. */
export interface SyncFrame {
  readonly type: SyncMessageTypeValue;
  /** Target document UUID, or empty string for document-agnostic messages. */
  readonly docId: string;
  /** Message body — a zero-copy view into the source buffer. */
  readonly body: Uint8Array;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Encode a sync message for transmission on Stream 0x01.
 *
 * @throws If the doc id or body exceeds protocol bounds.
 */
export function encodeSyncFrame(
  type: SyncMessageTypeValue,
  docId: string,
  body: Uint8Array,
): Uint8Array {
  const docIdBytes = encoder.encode(docId);

  if (docIdBytes.length > 255) {
    throw new Error(`doc_id exceeds 255 bytes: ${docIdBytes.length}`);
  }
  if (body.length > MAX_SYNC_BODY_SIZE) {
    throw new Error(
      `Sync body exceeds ${MAX_SYNC_BODY_SIZE} bytes: ${body.length}`,
    );
  }

  const buffer = new Uint8Array(1 + 1 + docIdBytes.length + 4 + body.length);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;
  view.setUint8(offset, type);
  offset += 1;

  view.setUint8(offset, docIdBytes.length);
  offset += 1;

  buffer.set(docIdBytes, offset);
  offset += docIdBytes.length;

  view.setUint32(offset, body.length, false);
  offset += 4;

  buffer.set(body, offset);

  return buffer;
}

/**
 * Decode a Stream 0x01 message using zero-copy payload views.
 *
 * @throws If the buffer is truncated or the message type is unknown.
 */
export function decodeSyncFrame(buffer: Uint8Array): SyncFrame {
  if (buffer.length < 6) {
    throw new Error(`Sync frame too small: ${buffer.length} < 6`);
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;
  const type = view.getUint8(offset);
  offset += 1;

  if (!VALID_TYPES.has(type)) {
    throw new Error(`Unknown sync message type: 0x${type.toString(16)}`);
  }

  const docIdLen = view.getUint8(offset);
  offset += 1;

  if (offset + docIdLen + 4 > buffer.length) {
    throw new Error('Sync frame truncated: doc_id runs past buffer');
  }

  const docId = docIdLen === 0
    ? ''
    : decoder.decode(buffer.subarray(offset, offset + docIdLen));
  offset += docIdLen;

  const bodyLen = view.getUint32(offset, false);
  offset += 4;

  if (bodyLen > MAX_SYNC_BODY_SIZE) {
    throw new Error(`Sync body exceeds ${MAX_SYNC_BODY_SIZE} bytes: ${bodyLen}`);
  }
  if (offset + bodyLen > buffer.length) {
    throw new Error('Sync frame truncated: body runs past buffer');
  }

  // Zero-copy view into the caller's buffer.
  const body = buffer.subarray(offset, offset + bodyLen);

  return { type: type as SyncMessageTypeValue, docId, body };
}

/** Encode a boolean body (used by ROOT_MATCH). */
export function encodeBoolBody(value: boolean): Uint8Array {
  return new Uint8Array([value ? 1 : 0]);
}

/** Decode a boolean body. */
export function decodeBoolBody(body: Uint8Array): boolean {
  return body.length > 0 && body[0] === 1;
}

/**
 * Commitments carried in one MEMBER_LIST frame.
 *
 * A full depth-16 tree holds 65,536 commitments — 2 MB, over the 1 MB
 * body ceiling — so large sets are chunked across several frames.
 */
export const MAX_MEMBERS_PER_FRAME = 1024;

/** `[32 root][4 member_count]` */
export function encodeMemberRootBody(
  root: bigint,
  memberCount: number,
): Uint8Array {
  const body = new Uint8Array(36);
  body.set(fieldToBytes(root), 0);
  new DataView(body.buffer).setUint32(32, memberCount, false);

  return body;
}

/** Decode a MEMBER_ROOT body. */
export function decodeMemberRootBody(body: Uint8Array): {
  root: bigint;
  memberCount: number;
} {
  if (body.length !== 36) {
    throw new Error(`MEMBER_ROOT body must be 36 bytes, got ${body.length}`);
  }

  return {
    root: bytesToField(body.subarray(0, 32)),
    memberCount: new DataView(
      body.buffer,
      body.byteOffset,
      body.byteLength,
    ).getUint32(32, false),
  };
}

/**
 * `[1 is_final][2 count][32 commitment]*`
 *
 * `is_final` lets a receiver know whether more chunks follow, so it can
 * defer replying until it has seen the sender's whole set.
 */
export function encodeMemberListBody(
  commitments: readonly bigint[],
  isFinal: boolean,
): Uint8Array {
  if (commitments.length > MAX_MEMBERS_PER_FRAME) {
    throw new Error(
      `MEMBER_LIST holds at most ${MAX_MEMBERS_PER_FRAME} commitments, got ${commitments.length}`,
    );
  }

  const body = new Uint8Array(3 + commitments.length * 32);
  const view = new DataView(body.buffer);

  view.setUint8(0, isFinal ? 1 : 0);
  view.setUint16(1, commitments.length, false);

  commitments.forEach((commitment, i) => {
    body.set(fieldToBytes(commitment), 3 + i * 32);
  });

  return body;
}

/** Decode a MEMBER_LIST body. */
export function decodeMemberListBody(body: Uint8Array): {
  commitments: bigint[];
  isFinal: boolean;
} {
  if (body.length < 3) {
    throw new Error('MEMBER_LIST body truncated: missing header');
  }

  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const isFinal = view.getUint8(0) === 1;
  const count = view.getUint16(1, false);

  if (count > MAX_MEMBERS_PER_FRAME) {
    throw new Error(`MEMBER_LIST claims ${count} commitments, over the limit`);
  }
  if (3 + count * 32 > body.length) {
    throw new Error('MEMBER_LIST body truncated: commitments run past buffer');
  }

  const commitments: bigint[] = [];
  for (let i = 0; i < count; i++) {
    commitments.push(bytesToField(body.subarray(3 + i * 32, 3 + (i + 1) * 32)));
  }

  return { commitments, isFinal };
}

/** Departures carried in one MEMBER_DEPARTURE frame. */
export const MAX_DEPARTURES_PER_FRAME = 256;

/**
 * Encode departure tombstones as length-prefixed JSON.
 *
 * JSON rather than a packed struct: departures are rare, carry a
 * variable-length did:key, and benefit from being inspectable. Field
 * elements become decimal strings — JSON numbers cannot hold 254 bits.
 */
export function encodeDepartureBody(
  departures: readonly DepartureRecord[],
  isFinal: boolean,
): Uint8Array {
  if (departures.length > MAX_DEPARTURES_PER_FRAME) {
    throw new Error(
      `MEMBER_DEPARTURE holds at most ${MAX_DEPARTURES_PER_FRAME} records, got ${departures.length}`,
    );
  }

  const payload = {
    isFinal,
    departures: departures.map((d) => ({
      channelId: d.channelId,
      did: d.did,
      commitment: d.commitment.toString(),
      departedAt: d.departedAt,
      signature: bytesToBase64(d.signature),
    })),
  };

  return encoder.encode(JSON.stringify(payload));
}

/** Decode a MEMBER_DEPARTURE body. */
export function decodeDepartureBody(body: Uint8Array): {
  departures: DepartureRecord[];
  isFinal: boolean;
} {
  const raw = JSON.parse(decoder.decode(body)) as {
    isFinal?: boolean;
    departures?: Array<{
      channelId: string;
      did: string;
      commitment: string;
      departedAt: number;
      signature: string;
    }>;
  };

  const entries = raw.departures ?? [];
  if (entries.length > MAX_DEPARTURES_PER_FRAME) {
    throw new Error(
      `MEMBER_DEPARTURE claims ${entries.length} records, over the limit`,
    );
  }

  return {
    isFinal: raw.isFinal !== false,
    departures: entries.map((d) => ({
      channelId: d.channelId,
      did: d.did,
      commitment: BigInt(d.commitment),
      departedAt: d.departedAt,
      signature: base64ToBytes(d.signature),
    })),
  };
}

/*
 * Base64 without `Buffer`: this module is reachable from a browser
 * build, where `Buffer` does not exist.
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
