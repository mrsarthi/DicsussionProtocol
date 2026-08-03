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
