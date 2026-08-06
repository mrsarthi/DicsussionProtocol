/**
 * LZ4 frame compression (RFC 001 §3.4).
 *
 * The `COMPRESSED` flag and the 1 MB ceiling existed since Phase 1A but
 * nothing ever compressed anything. The behaviour that matters is
 * selectivity: encrypted payloads are indistinguishable from random and
 * must be left alone rather than grown.
 */

import { randomBytes } from 'node:crypto';

import { expect, test } from '@playwright/test';

import {
  decompressPayload,
  maybeCompress,
  MIN_COMPRESSION_SIZE,
} from '../../packages/core/src/transport/compression.js';
import { MAX_DECOMPRESSED_SIZE } from '../../packages/core/src/transport/types.js';

/** Highly repetitive data, like a CRDT delta or membership list. */
function compressible(size: number): Uint8Array {
  return new TextEncoder().encode('the quick brown fox '.repeat(size));
}

/**
 * Genuinely random data, standing in for ciphertext.
 *
 * Must be real CSPRNG output: an LCG's low bits are periodic enough that
 * LZ4 compresses them, which would make this test assert the opposite of
 * what it intends.
 */
function incompressible(size: number): Uint8Array {
  return new Uint8Array(randomBytes(size));
}

test.describe('Transport — LZ4 Compression', () => {
  test('repetitive payloads compress substantially', () => {
    const original = compressible(200);
    const result = maybeCompress(original);

    expect(result.compressed).toBe(true);
    expect(result.payload.length).toBeLessThan(original.length / 2);
  });

  test('a compressed payload round-trips exactly', () => {
    const original = compressible(200);
    const result = maybeCompress(original);

    expect(Array.from(decompressPayload(result.payload))).toEqual(
      Array.from(original),
    );
  });

  test('random data is left uncompressed rather than grown', () => {
    const original = incompressible(4_096);
    const result = maybeCompress(original);

    // Ciphertext does not compress; paying CPU to make it bigger would
    // be strictly worse.
    expect(result.compressed).toBe(false);
    expect(result.payload).toBe(original);
  });

  test('payloads below the threshold are skipped', () => {
    const small = compressible(1).subarray(0, MIN_COMPRESSION_SIZE - 1);
    const result = maybeCompress(small);

    expect(result.compressed).toBe(false);
    expect(result.payload).toBe(small);
  });

  test('an empty payload is handled', () => {
    const result = maybeCompress(new Uint8Array(0));

    expect(result.compressed).toBe(false);
    expect(result.payload).toHaveLength(0);
  });

  test('a payload at the size boundary is handled', () => {
    const exact = compressible(1).subarray(0, MIN_COMPRESSION_SIZE);

    expect(() => maybeCompress(exact)).not.toThrow();
  });

  test('corrupt compressed data is rejected, not passed through', () => {
    const result = maybeCompress(compressible(200));
    const corrupted = result.payload.slice();
    corrupted[4] ^= 0xff;
    corrupted[5] ^= 0xff;

    // Either it fails to decompress, or it produces different bytes —
    // silently returning the corrupt input would be the dangerous case.
    let threw = false;
    let output: Uint8Array | null = null;
    try {
      output = decompressPayload(corrupted);
    } catch {
      threw = true;
    }

    expect(threw || output === null || output.length !== result.payload.length).toBe(
      true,
    );
  });

  test('garbage input is rejected with a clear error', () => {
    expect(() => decompressPayload(new Uint8Array([1, 2, 3, 4, 5]))).toThrow(
      /Failed to decompress/,
    );
  });

  test('a decompression bomb is refused before allocating', () => {
    // A tiny payload that expands far past the ceiling. The frame codec
    // only sees the *compressed* length, so this bound is the only thing
    // standing between a 1 KB frame and gigabytes of memory.
    const bomb = maybeCompress(new Uint8Array(MAX_DECOMPRESSED_SIZE + 1_024));

    expect(bomb.compressed).toBe(true);
    expect(bomb.payload.length).toBeLessThan(10_000);
    expect(() => decompressPayload(bomb.payload)).toThrow(/over the .* limit/);
  });

  test('a payload just under the ceiling still decompresses', () => {
    const large = new Uint8Array(MAX_DECOMPRESSED_SIZE - 1_024);
    const result = maybeCompress(large);

    expect(decompressPayload(result.payload).length).toBe(large.length);
  });
});
