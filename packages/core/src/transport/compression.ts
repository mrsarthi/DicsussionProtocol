/**
 * @dicsussion/transport — LZ4 Frame Compression (RFC 001 §3.4)
 *
 * The `COMPRESSED` frame flag and the 1 MB decompression ceiling have
 * existed since Phase 1A, but nothing ever compressed anything. This
 * supplies the missing half.
 *
 * Compression is applied **only when it actually helps**. Encrypted
 * payloads are indistinguishable from random and do not compress, so
 * blindly compressing every frame would burn CPU to make ciphertext
 * slightly larger. CRDT deltas and membership lists, by contrast,
 * compress well — the Phase 1 spike measured a 3 KB repetitive payload
 * down to 42 bytes.
 *
 * The decompression bound is a security control, not an optimisation:
 * without it a 1 KB frame could claim to expand into gigabytes and
 * exhaust memory before anything else could reject it.
 */

import { compress, decompress } from 'lz4js';

import { MAX_DECOMPRESSED_SIZE } from './types.js';

/**
 * Payloads below this never compress usefully — the LZ4 block header
 * alone would outweigh any saving.
 */
export const MIN_COMPRESSION_SIZE = 256;

/**
 * Only keep a compressed payload if it saves at least this fraction.
 *
 * A marginal saving is not worth the decompression cost on a phone.
 */
export const MIN_COMPRESSION_RATIO = 0.9;

/** Outcome of an attempted compression. */
export interface CompressionResult {
  /** The payload to transmit — compressed only if worthwhile. */
  readonly payload: Uint8Array;
  /** Whether `payload` is compressed, i.e. whether to set the flag. */
  readonly compressed: boolean;
}

/**
 * Compress a payload if doing so is worthwhile.
 *
 * Never throws: a compression failure falls back to the original bytes,
 * because failing to send is worse than sending uncompressed.
 *
 * @param payload Raw frame payload.
 */
export function maybeCompress(payload: Uint8Array): CompressionResult {
  if (payload.length < MIN_COMPRESSION_SIZE) {
    return { payload, compressed: false };
  }

  try {
    const compressed = Uint8Array.from(compress(payload));

    // Encrypted payloads expand rather than shrink; keep the original.
    if (compressed.length >= payload.length * MIN_COMPRESSION_RATIO) {
      return { payload, compressed: false };
    }

    return { payload: compressed, compressed: true };
  } catch {
    return { payload, compressed: false };
  }
}

/**
 * Decompress a payload that arrived with the `COMPRESSED` flag set.
 *
 * @param payload Compressed bytes.
 * @returns The original payload.
 * @throws If the result would exceed the 1 MB ceiling, or the data is
 *   not valid LZ4 — both are rejections, never silent pass-through.
 */
export function decompressPayload(payload: Uint8Array): Uint8Array {
  let result: Uint8Array;

  try {
    result = Uint8Array.from(decompress(payload));
  } catch (error) {
    throw new Error(
      `Failed to decompress frame payload: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  // A decompression bomb is caught here rather than by the frame codec,
  // which only sees the *compressed* length.
  if (result.length > MAX_DECOMPRESSED_SIZE) {
    throw new Error(
      `Decompressed payload is ${result.length} bytes, over the ${MAX_DECOMPRESSED_SIZE} limit`,
    );
  }

  return result;
}
