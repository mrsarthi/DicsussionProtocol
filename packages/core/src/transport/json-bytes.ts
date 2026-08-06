/**
 * @dicsussion/transport — Binary-safe JSON for control messages
 *
 * The RFC 001 §5 handshake carries `Uint8Array` nonces and signatures,
 * and JSON has no byte-array type. Left to itself `JSON.stringify` turns
 * a `Uint8Array` into `{"0":31,"1":139,…}`, which survives the round
 * trip as a plain object — so signature verification fails against
 * something that still looks structurally like a handshake. The failure
 * reads as "peer rejected the handshake", not "the codec is wrong".
 *
 * Every transport that serialises handshake messages must use these, or
 * two transports will disagree about the wire format of the same
 * protocol.
 *
 * Base64 is done with `atob`/`btoa` rather than `Buffer` so the same
 * code runs in a browser.
 */

/** Marker distinguishing an encoded byte array from an ordinary object. */
const BYTES_KEY = '__bytes';

/** `JSON.stringify` replacer that encodes byte arrays. */
export function bytesReplacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return { [BYTES_KEY]: bytesToBase64(value) };
  }
  return value;
}

/** `JSON.parse` reviver that restores byte arrays. */
export function bytesReviver(_key: string, value: unknown): unknown {
  if (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Record<string, unknown>)[BYTES_KEY] === 'string'
  ) {
    return base64ToBytes((value as Record<string, string>)[BYTES_KEY]!);
  }
  return value;
}

/** Serialise a control message, preserving byte arrays. */
export function encodeControlJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value, bytesReplacer));
}

/**
 * Parse a control message, restoring byte arrays.
 *
 * @throws If the bytes are not valid UTF-8 JSON. Callers treat that as a
 *   hostile or corrupt peer and drop the message.
 */
export function decodeControlJson<T>(bytes: Uint8Array): T {
  return JSON.parse(new TextDecoder().decode(bytes), bytesReviver) as T;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  // Chunked: spreading a large array into `fromCharCode` blows the
  // argument limit, and handshake payloads are small but nothing here
  // enforces that.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}
