/**
 * Frame reassembly over a byte stream.
 *
 * `LocalTransport` delivers whole frames, so none of this is exercised
 * in-process. Real QUIC streams are byte-oriented — a read can return
 * half a header, or three frames at once — which makes this the most
 * likely source of real-network bugs (transport plan §6).
 */

import { expect, test } from '@playwright/test';

import { encodeFrame } from '../../packages/core/src/transport/frame-codec.js';
import { FrameReader } from '../../packages/core/src/transport/frame-reader.js';
import { StreamType } from '../../packages/core/src/transport/types.js';

const payload = (n: number, size = 8) => new Uint8Array(size).fill(n);

/** Concatenate encoded frames into one contiguous byte stream. */
function stream(...frames: Uint8Array[]): Uint8Array {
  const total = frames.reduce((sum, f) => sum + f.length, 0);
  const out = new Uint8Array(total);

  let offset = 0;
  for (const frame of frames) {
    out.set(frame, offset);
    offset += frame.length;
  }

  return out;
}

test.describe('Transport — Frame Reader', () => {
  test('a whole frame in one chunk is emitted immediately', () => {
    const reader = new FrameReader();
    const frames = reader.push(encodeFrame(StreamType.E2EE_MESSAGE, payload(1)));

    expect(frames).toHaveLength(1);
    expect(frames[0]!.header.streamType).toBe(StreamType.E2EE_MESSAGE);
    expect(Array.from(frames[0]!.payload)).toEqual(Array.from(payload(1)));
    expect(reader.hasPartialFrame).toBe(false);
  });

  test('several frames in one chunk all emit, in order', () => {
    const reader = new FrameReader();

    const frames = reader.push(
      stream(
        encodeFrame(StreamType.CRDT_SYNC, payload(1)),
        encodeFrame(StreamType.E2EE_MESSAGE, payload(2)),
        encodeFrame(StreamType.REVOCATION_GOSSIP, payload(3)),
      ),
    );

    expect(frames.map((f) => f.header.streamType)).toEqual([
      StreamType.CRDT_SYNC,
      StreamType.E2EE_MESSAGE,
      StreamType.REVOCATION_GOSSIP,
    ]);
  });

  test('a frame split across two chunks is reassembled', () => {
    const reader = new FrameReader();
    const encoded = encodeFrame(StreamType.E2EE_MESSAGE, payload(7, 64));
    const split = 20;

    expect(reader.push(encoded.subarray(0, split))).toHaveLength(0);
    expect(reader.hasPartialFrame).toBe(true);

    const frames = reader.push(encoded.subarray(split));
    expect(frames).toHaveLength(1);
    expect(Array.from(frames[0]!.payload)).toEqual(Array.from(payload(7, 64)));
  });

  test('a split inside the header is handled', () => {
    const reader = new FrameReader();
    const encoded = encodeFrame(StreamType.CRDT_SYNC, payload(3));

    // Cut mid-header: the length field is not yet readable.
    expect(reader.push(encoded.subarray(0, 6))).toHaveLength(0);
    expect(reader.pending).toBe(6);

    expect(reader.push(encoded.subarray(6))).toHaveLength(1);
  });

  test('byte-at-a-time delivery still yields exactly one frame', () => {
    const reader = new FrameReader();
    const encoded = encodeFrame(StreamType.E2EE_MESSAGE, payload(9, 32));

    const collected = [];
    for (const byte of encoded) {
      collected.push(...reader.push(new Uint8Array([byte])));
    }

    expect(collected).toHaveLength(1);
    expect(Array.from(collected[0]!.payload)).toEqual(Array.from(payload(9, 32)));
    expect(reader.hasPartialFrame).toBe(false);
  });

  test('a chunk carrying one frame plus a partial emits only the complete one', () => {
    const reader = new FrameReader();
    const first = encodeFrame(StreamType.CRDT_SYNC, payload(1));
    const second = encodeFrame(StreamType.E2EE_MESSAGE, payload(2));

    const frames = reader.push(stream(first, second.subarray(0, 5)));

    expect(frames).toHaveLength(1);
    expect(frames[0]!.header.streamType).toBe(StreamType.CRDT_SYNC);
    expect(reader.pending).toBe(5);

    // The remainder completes the second frame.
    expect(reader.push(second.subarray(5))).toHaveLength(1);
  });

  test('a zero-length payload is a valid frame', () => {
    const reader = new FrameReader();
    const frames = reader.push(encodeFrame(StreamType.CRDT_SYNC, new Uint8Array(0)));

    expect(frames).toHaveLength(1);
    expect(frames[0]!.payload).toHaveLength(0);
  });

  test('an oversized declared length is rejected before allocating', () => {
    const reader = new FrameReader();
    const encoded = encodeFrame(StreamType.E2EE_MESSAGE, payload(1));

    // Rewrite the length field to claim far more than the ceiling.
    const hostile = encoded.slice();
    new DataView(hostile.buffer).setUint32(4, 0xffffffff, false);

    expect(() => reader.push(hostile)).toThrow(/over the .* limit/);
  });

  test('a corrupted payload fails the checksum rather than being emitted', () => {
    const reader = new FrameReader();
    const encoded = encodeFrame(StreamType.E2EE_MESSAGE, payload(1));

    const corrupted = encoded.slice();
    corrupted[corrupted.length - 1] ^= 0xff;

    expect(() => reader.push(corrupted)).toThrow();
  });

  test('reset discards a buffered partial frame', () => {
    const reader = new FrameReader();
    const encoded = encodeFrame(StreamType.E2EE_MESSAGE, payload(1));

    reader.push(encoded.subarray(0, 8));
    expect(reader.hasPartialFrame).toBe(true);

    reader.reset();
    expect(reader.pending).toBe(0);
  });

  test('a long stream of frames does not retain earlier buffers', () => {
    const reader = new FrameReader();
    let emitted = 0;

    // Interleave large and small frames, delivered in awkward slices.
    for (let i = 0; i < 50; i++) {
      const encoded = encodeFrame(StreamType.CRDT_SYNC, payload(i % 256, 1_024));
      emitted += reader.push(encoded.subarray(0, 100)).length;
      emitted += reader.push(encoded.subarray(100)).length;
    }

    expect(emitted).toBe(50);
    // Nothing left over: every frame was consumed exactly.
    expect(reader.pending).toBe(0);
  });
});
