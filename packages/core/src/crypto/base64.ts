/**
 * @dicsussion/crypto — Runtime-Neutral Base64
 *
 * `Buffer` is Node-only. Reaching for it in shared code compiles and
 * tests cleanly, then throws `ReferenceError: Buffer is not defined` the
 * first time the module runs in a browser — and an `esbuild
 * --platform=browser` check does not catch it, because `Buffer` is a
 * global reference rather than an import of a Node builtin.
 *
 * `btoa`/`atob` are present in browsers, Node 16+, and React Native, so
 * every runtime the SDK targets is covered by one implementation.
 */

/** Chunk size for the charCode fan-out, small enough to stay off the stack limit. */
const CHUNK = 0x8000;

/**
 * Encode bytes as standard base64.
 *
 * Converted in chunks rather than a single `String.fromCharCode(...bytes)`
 * spread — that form throws `RangeError: Maximum call stack size exceeded`
 * once the array grows past a few hundred kilobytes, which is exactly the
 * size a serialised document reaches in production and never in a test.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';

  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }

  return btoa(binary);
}

/**
 * Decode standard base64 into bytes.
 *
 * @throws If the input is not valid base64.
 */
export function base64ToBytes(encoded: string): Uint8Array {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/** Encode bytes as URL-safe base64, without padding. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

/**
 * Decode URL-safe base64 into bytes.
 *
 * Padding is restored first: `atob` rejects unpadded input, while the
 * base64url convention omits it.
 *
 * @throws If the input is not valid base64url.
 */
export function base64UrlToBytes(encoded: string): Uint8Array {
  const standard = encoded.replaceAll('-', '+').replaceAll('_', '/');
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, '=');

  return base64ToBytes(padded);
}

/** Encode a UTF-8 string as URL-safe base64. */
export function utf8ToBase64Url(text: string): string {
  return bytesToBase64Url(new TextEncoder().encode(text));
}

/** Decode URL-safe base64 into a UTF-8 string. */
export function base64UrlToUtf8(encoded: string): string {
  return new TextDecoder().decode(base64UrlToBytes(encoded));
}
