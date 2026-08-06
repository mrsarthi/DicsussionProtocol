/**
 * @dicsussion/wot — Stream 0x04 Voucher Handshake Codec
 *
 * Binary encoding for the synchronous blind-voucher issuance exchange
 * described in RFC 003 §5, carried on Sub-Stream `0x04`.
 *
 *   A ← B: VOUCHER_REQUEST  { blinded }
 *   A → B: VOUCHER_RESPONSE { blindSignature, issuerPublicKey }
 *   A → B: VOUCHER_REJECT   { reason }
 *
 * Only blinded values cross the wire during issuance. The issuer never
 * observes the serial, so it cannot link the request it signed to the
 * voucher redeemed later.
 *
 * Frame layout:
 *   [0]      msg_type u8
 *   [1..4]   body_len u32 BE
 *   [5..]    body     variable
 */

/** Voucher handshake message discriminants. */
export const VoucherMessageType = {
  /** Receiver asks an issuer to blind-sign a commitment. */
  REQUEST: 0x01,
  /** Issuer returns the blind signature and its public key. */
  RESPONSE: 0x02,
  /** Issuer declines (quota exhausted, insufficient score, etc.). */
  REJECT: 0x03,
} as const;

export type VoucherMessageTypeValue =
  (typeof VoucherMessageType)[keyof typeof VoucherMessageType];

const VALID_TYPES = new Set<number>(Object.values(VoucherMessageType));

/** Maximum voucher body size — generous for RSA-2048 values. */
export const MAX_VOUCHER_BODY = 8_192;

/** Reasons an issuer may decline. */
export const VoucherRejectReason = {
  QUOTA_EXHAUSTED: 'quota_exhausted',
  INSUFFICIENT_SCORE: 'insufficient_score',
  UNKNOWN_PEER: 'unknown_peer',
  MALFORMED_REQUEST: 'malformed_request',
} as const;

export type VoucherRejectReasonValue =
  (typeof VoucherRejectReason)[keyof typeof VoucherRejectReason];

/** Receiver → issuer: please sign this blinded value. */
export interface VoucherRequest {
  readonly type: 'request';
  /** Blinded commitment `m · r^e mod n`. */
  readonly blinded: bigint;
}

/** Issuer → receiver: signed, here is my key so you can verify. */
export interface VoucherResponse {
  readonly type: 'response';
  readonly blindSignature: bigint;
  /** Issuer RSA modulus. */
  readonly modulus: bigint;
  /** Issuer RSA public exponent. */
  readonly exponent: bigint;
}

/** Issuer → receiver: declined. */
export interface VoucherReject {
  readonly type: 'reject';
  readonly reason: string;
}

export type VoucherMessage = VoucherRequest | VoucherResponse | VoucherReject;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/** Encode a voucher handshake message for Stream 0x04. */
export function encodeVoucherMessage(message: VoucherMessage): Uint8Array {
  switch (message.type) {
    case 'request':
      return frame(
        VoucherMessageType.REQUEST,
        encodeBigInts([message.blinded]),
      );
    case 'response':
      return frame(
        VoucherMessageType.RESPONSE,
        encodeBigInts([message.blindSignature, message.modulus, message.exponent]),
      );
    case 'reject':
      return frame(
        VoucherMessageType.REJECT,
        encoder.encode(message.reason),
      );
  }
}

/**
 * Decode a Stream 0x04 payload.
 *
 * @throws If the frame is truncated, oversized, or of unknown type.
 */
export function decodeVoucherMessage(buffer: Uint8Array): VoucherMessage {
  if (buffer.length < 5) {
    throw new Error(`Voucher frame too small: ${buffer.length} < 5`);
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const type = view.getUint8(0);

  if (!VALID_TYPES.has(type)) {
    throw new Error(`Unknown voucher message type: 0x${type.toString(16)}`);
  }

  const bodyLen = view.getUint32(1, false);
  if (bodyLen > MAX_VOUCHER_BODY) {
    throw new Error(`Voucher body exceeds ${MAX_VOUCHER_BODY} bytes: ${bodyLen}`);
  }
  if (5 + bodyLen > buffer.length) {
    throw new Error('Voucher frame truncated: body runs past buffer');
  }

  const body = buffer.subarray(5, 5 + bodyLen);

  switch (type) {
    case VoucherMessageType.REQUEST: {
      const [blinded] = decodeBigInts(body, 1);
      return { type: 'request', blinded: blinded! };
    }
    case VoucherMessageType.RESPONSE: {
      const [blindSignature, modulus, exponent] = decodeBigInts(body, 3);
      return {
        type: 'response',
        blindSignature: blindSignature!,
        modulus: modulus!,
        exponent: exponent!,
      };
    }
    default:
      return { type: 'reject', reason: decoder.decode(body) };
  }
}

/** Prefix a body with its type byte and big-endian length. */
function frame(type: VoucherMessageTypeValue, body: Uint8Array): Uint8Array {
  if (body.length > MAX_VOUCHER_BODY) {
    throw new Error(`Voucher body exceeds ${MAX_VOUCHER_BODY} bytes`);
  }

  const buffer = new Uint8Array(5 + body.length);
  const view = new DataView(buffer.buffer);

  view.setUint8(0, type);
  view.setUint32(1, body.length, false);
  buffer.set(body, 5);

  return buffer;
}

/** Length-prefix a sequence of big integers as `[u16 len][bytes]`. */
function encodeBigInts(values: readonly bigint[]): Uint8Array {
  const encoded = values.map(bigIntToBytes);
  const total = encoded.reduce((sum, b) => sum + 2 + b.length, 0);

  const buffer = new Uint8Array(total);
  const view = new DataView(buffer.buffer);

  let offset = 0;
  for (const bytes of encoded) {
    view.setUint16(offset, bytes.length, false);
    offset += 2;
    buffer.set(bytes, offset);
    offset += bytes.length;
  }

  return buffer;
}

/** Read exactly `count` length-prefixed big integers. */
function decodeBigInts(body: Uint8Array, count: number): bigint[] {
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const values: bigint[] = [];

  let offset = 0;
  for (let i = 0; i < count; i++) {
    if (offset + 2 > body.length) {
      throw new Error('Voucher body truncated: missing length prefix');
    }

    const length = view.getUint16(offset, false);
    offset += 2;

    if (offset + length > body.length) {
      throw new Error('Voucher body truncated: value runs past buffer');
    }

    values.push(bytesToBigInt(body.subarray(offset, offset + length)));
    offset += length;
  }

  return values;
}

function bigIntToBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error('Cannot encode a negative big integer');
  if (value === 0n) return new Uint8Array([0]);

  const hex = value.toString(16);
  const padded = hex.length % 2 === 0 ? hex : `0${hex}`;
  const bytes = new Uint8Array(padded.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}
