/**
 * @dicsussion/slashing — Stream 0x03 & 0x06 Wire Codecs
 *
 * `0x06` carries RLN polynomial shares between peers so any node can
 * assemble a double-spend proof. `0x03` carries the resulting revocation
 * tombstones and is the protocol's only high-priority stream — a
 * compromised identity must outrun the messages it is still sending,
 * which is why `PriorityFrameQueue` lets 0x03 preempt 0x02.
 *
 * Both use the same framing as the other sub-streams:
 *   [0] msg_type u8 · [1..4] body_len u32 BE · [5..] body
 */

import {
  base64ToBytes,
  bytesToBase64,
  bytesToField,
  fieldToBytes,
} from '@dicsussion/core/crypto';
import type { ObservedShare } from './share-collector.js';
import type {
  DoubleSpendProof,
  RevocationTombstone,
  RevocationReasonValue,
} from './tombstone.js';

/** Stream 0x06 message kinds. */
export const ShareMessageType = {
  /** A single observed RLN share. */
  SHARE: 0x01,
  /** A batch of shares, e.g. on reconnect. */
  SHARE_BATCH: 0x02,
} as const;

/** Stream 0x03 message kinds. */
export const RevocationMessageType = {
  TOMBSTONE: 0x01,
} as const;

/** Maximum gossip body, bounding memory on hostile input. */
export const MAX_GOSSIP_BODY = 64 * 1024;

/** Maximum shares in one batch frame. */
export const MAX_SHARE_BATCH = 256;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

// ─── Stream 0x06: share gossip ───────────────────────────────────────────────

/** Encode one observed share. */
export function encodeShare(share: ObservedShare): Uint8Array {
  return frame(ShareMessageType.SHARE, encodeShareBody(share));
}

/** Encode a batch of observed shares. */
export function encodeShareBatch(shares: readonly ObservedShare[]): Uint8Array {
  if (shares.length > MAX_SHARE_BATCH) {
    throw new Error(
      `Share batch of ${shares.length} exceeds the ${MAX_SHARE_BATCH} limit`,
    );
  }

  const count = new Uint8Array(2);
  new DataView(count.buffer).setUint16(0, shares.length, false);

  return frame(
    ShareMessageType.SHARE_BATCH,
    concat([count, ...shares.map(encodeShareBody)]),
  );
}

/**
 * Decode a Stream 0x06 payload into shares.
 *
 * @throws If the frame is malformed, truncated, or oversized.
 */
export function decodeShareMessage(buffer: Uint8Array): ObservedShare[] {
  const { type, body } = unframe(buffer);

  if (type === ShareMessageType.SHARE) {
    return [decodeShareBody(body, 0).share];
  }
  if (type !== ShareMessageType.SHARE_BATCH) {
    throw new Error(`Unknown share message type: 0x${type.toString(16)}`);
  }

  if (body.length < 2) throw new Error('Share batch truncated: missing count');

  const count = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint16(
    0,
    false,
  );
  if (count > MAX_SHARE_BATCH) {
    throw new Error(`Share batch claims ${count} entries, over the limit`);
  }

  const shares: ObservedShare[] = [];
  let offset = 2;

  for (let i = 0; i < count; i++) {
    const { share, next } = decodeShareBody(body, offset);
    shares.push(share);
    offset = next;
  }

  return shares;
}

/** `[32 x][32 y][32 nullifier][8 epoch]` */
function encodeShareBody(share: ObservedShare): Uint8Array {
  const epoch = new Uint8Array(8);
  new DataView(epoch.buffer).setBigUint64(0, BigInt(share.epoch), false);

  return concat([
    fieldToBytes(share.x),
    fieldToBytes(share.y),
    fieldToBytes(share.nullifier),
    epoch,
  ]);
}

function decodeShareBody(
  body: Uint8Array,
  offset: number,
): { share: ObservedShare; next: number } {
  const SHARE_BYTES = 32 * 3 + 8;
  if (offset + SHARE_BYTES > body.length) {
    throw new Error('Share body truncated');
  }

  const x = bytesToField(body.subarray(offset, offset + 32));
  const y = bytesToField(body.subarray(offset + 32, offset + 64));
  const nullifier = bytesToField(body.subarray(offset + 64, offset + 96));
  const epoch = Number(
    new DataView(body.buffer, body.byteOffset + offset + 96, 8).getBigUint64(0, false),
  );

  return { share: { x, y, nullifier, epoch }, next: offset + SHARE_BYTES };
}

// ─── Stream 0x03: revocation tombstones ──────────────────────────────────────

/**
 * Encode a tombstone as length-prefixed JSON.
 *
 * JSON rather than a packed struct because tombstones are rare,
 * variable-shaped, and benefit from being inspectable during an
 * incident. Field elements become decimal strings — JSON numbers cannot
 * hold 254-bit values.
 */
export function encodeTombstone(tombstone: RevocationTombstone): Uint8Array {
  const payload = {
    revocationId: tombstone.revocationId,
    membershipCommitment: tombstone.membershipCommitment.toString(),
    reason: tombstone.reason,
    doubleSpendProof: tombstone.doubleSpendProof
      ? {
          nullifier: tombstone.doubleSpendProof.nullifier.toString(),
          shareOne: {
            x: tombstone.doubleSpendProof.shareOne.x.toString(),
            y: tombstone.doubleSpendProof.shareOne.y.toString(),
          },
          shareTwo: {
            x: tombstone.doubleSpendProof.shareTwo.x.toString(),
            y: tombstone.doubleSpendProof.shareTwo.y.toString(),
          },
        }
      : undefined,
    reconstructedSecret: tombstone.reconstructedSecret?.toString(),
    trapdoor: tombstone.trapdoor?.toString(),
    timestamp: tombstone.timestamp,
    validatorDid: tombstone.validatorDid,
    signature: bytesToBase64(tombstone.signature),
  };

  return frame(
    RevocationMessageType.TOMBSTONE,
    encoder.encode(JSON.stringify(payload)),
  );
}

/**
 * Decode a Stream 0x03 payload.
 *
 * Structural decoding only — the caller MUST still run
 * `verifyTombstone`, since anyone can send a well-formed lie.
 *
 * @throws If the frame or JSON is malformed.
 */
export function decodeTombstone(buffer: Uint8Array): RevocationTombstone {
  const { type, body } = unframe(buffer);
  if (type !== RevocationMessageType.TOMBSTONE) {
    throw new Error(`Unknown revocation message type: 0x${type.toString(16)}`);
  }

  const raw = JSON.parse(decoder.decode(body)) as Record<string, unknown>;

  if (
    typeof raw['revocationId'] !== 'string' ||
    typeof raw['membershipCommitment'] !== 'string' ||
    typeof raw['reason'] !== 'string' ||
    typeof raw['validatorDid'] !== 'string' ||
    typeof raw['signature'] !== 'string' ||
    typeof raw['timestamp'] !== 'number'
  ) {
    throw new Error('Tombstone is missing required fields');
  }

  const proof = raw['doubleSpendProof'] as
    | {
        nullifier: string;
        shareOne: { x: string; y: string };
        shareTwo: { x: string; y: string };
      }
    | undefined;

  const doubleSpendProof: DoubleSpendProof | undefined = proof
    ? {
        nullifier: safeBigInt(proof.nullifier, 'nullifier'),
        shareOne: {
          x: safeBigInt(proof.shareOne?.x, 'shareOne.x'),
          y: safeBigInt(proof.shareOne?.y, 'shareOne.y'),
        },
        shareTwo: {
          x: safeBigInt(proof.shareTwo?.x, 'shareTwo.x'),
          y: safeBigInt(proof.shareTwo?.y, 'shareTwo.y'),
        },
      }
    : undefined;

  return {
    revocationId: raw['revocationId'],
    membershipCommitment: safeBigInt(
      raw['membershipCommitment'],
      'membershipCommitment',
    ),
    reason: raw['reason'] as RevocationReasonValue,
    doubleSpendProof,
    reconstructedSecret: optionalBigInt(
      raw['reconstructedSecret'],
      'reconstructedSecret',
    ),
    trapdoor: optionalBigInt(raw['trapdoor'], 'trapdoor'),
    timestamp: raw['timestamp'],
    validatorDid: raw['validatorDid'],
    signature: base64ToBytes(raw['signature']),
  };
}

// ─── Shared framing ──────────────────────────────────────────────────────────

function frame(type: number, body: Uint8Array): Uint8Array {
  if (body.length > MAX_GOSSIP_BODY) {
    throw new Error(`Gossip body exceeds ${MAX_GOSSIP_BODY} bytes`);
  }

  const out = new Uint8Array(5 + body.length);
  const view = new DataView(out.buffer);

  view.setUint8(0, type);
  view.setUint32(1, body.length, false);
  out.set(body, 5);

  return out;
}

function unframe(buffer: Uint8Array): { type: number; body: Uint8Array } {
  if (buffer.length < 5) {
    throw new Error(`Gossip frame too small: ${buffer.length} < 5`);
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const type = view.getUint8(0);
  const length = view.getUint32(1, false);

  if (length > MAX_GOSSIP_BODY) {
    throw new Error(`Gossip body claims ${length} bytes, over the limit`);
  }
  if (5 + length > buffer.length) {
    throw new Error('Gossip frame truncated: body runs past buffer');
  }

  return { type, body: buffer.subarray(5, 5 + length) };
}

/**
 * Longest decimal string accepted for a field element.
 *
 * A BN254 scalar is under 2^254, which is 78 decimal digits. Anything
 * longer is not a field element, and refusing it early is what stops the
 * DoS below.
 */
const MAX_FIELD_DIGITS = 78;

/**
 * Parse a field element from untrusted JSON.
 *
 * `BigInt()` accepts a string of any length and parses it in worse than
 * linear time, so a peer that sends a 10 MB run of digits freezes the
 * event loop for as long as it takes — no memory exhaustion, no error,
 * just a stalled node. The length check has to happen *before* the
 * conversion, not after.
 */
function safeBigInt(value: unknown, field: string): bigint {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Gossip field ${field} is not a numeric string`);
  }
  if (value.length > MAX_FIELD_DIGITS) {
    throw new Error(
      `Gossip field ${field} claims ${value.length} digits, over the ${MAX_FIELD_DIGITS} limit`,
    );
  }
  if (!/^\d+$/.test(value)) {
    throw new Error(`Gossip field ${field} is not a decimal integer`);
  }

  return BigInt(value);
}

function optionalBigInt(value: unknown, field: string): bigint | undefined {
  return typeof value === 'string' && value.length > 0
    ? safeBigInt(value, field)
    : undefined;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);

  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}
