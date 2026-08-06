/**
 * @dicsussion/transport — Buffered Frame Reader
 *
 * Reassembles protocol frames from a byte stream.
 *
 * QUIC streams are byte-oriented, not message-oriented: a single read
 * may return half a frame, three frames, or a frame boundary in the
 * middle of the header. `LocalTransport` hands over whole frames, so
 * none of that is exercised in-process — which is exactly why this is
 * the most likely source of real-network bugs (see the transport plan
 * §6).
 *
 * The frame header carries the payload length, so reassembly is
 * deterministic: buffer until the header is complete, read the declared
 * length, then emit. Anything that cannot be satisfied yet stays
 * buffered for the next read.
 */

import { decodeFrame } from './frame-codec.js';
import type { Frame } from './types.js';
import { HEADER_SIZE, MAX_DECOMPRESSED_SIZE } from './types.js';

/**
 * Accumulates stream bytes and emits complete frames.
 *
 * One instance per stream — buffers are not shared, since interleaving
 * two streams' bytes would corrupt both.
 */
export class FrameReader {
  private buffer: Uint8Array<ArrayBuffer> = new Uint8Array(0);

  /**
   * Append received bytes and extract every frame now complete.
   *
   * @param chunk Bytes as received from the stream.
   * @returns Frames completed by this chunk, in arrival order.
   * @throws If a frame declares a payload beyond the protocol ceiling —
   *   a malformed or hostile length must not be allowed to allocate.
   */
  push(chunk: Uint8Array): Frame[] {
    this.buffer = concat(this.buffer, chunk);

    const frames: Frame[] = [];

    for (;;) {
      // Not enough bytes to know how long the frame is.
      if (this.buffer.length < HEADER_SIZE) break;

      const payloadLength = readPayloadLength(this.buffer);

      // Reject before allocating, not after (RFC 001 §3.4).
      if (payloadLength > MAX_DECOMPRESSED_SIZE) {
        throw new Error(
          `Frame declares ${payloadLength} bytes, over the ${MAX_DECOMPRESSED_SIZE} limit`,
        );
      }

      const frameLength = HEADER_SIZE + payloadLength;
      if (this.buffer.length < frameLength) break;

      // decodeFrame validates the CRC, so a corrupted frame throws here
      // rather than being handed upward.
      frames.push(decodeFrame(this.buffer.subarray(0, frameLength)));

      // Copy the remainder: `subarray` would retain the whole original
      // buffer, so a long-lived stream would never release memory.
      this.buffer = this.buffer.slice(frameLength);
    }

    return frames;
  }

  /** Bytes currently held awaiting completion. */
  get pending(): number {
    return this.buffer.length;
  }

  /** Whether a partial frame is buffered. */
  get hasPartialFrame(): boolean {
    return this.buffer.length > 0;
  }

  /** Discard buffered bytes, e.g. after a stream error. */
  reset(): void {
    this.buffer = new Uint8Array(0);
  }
}

/**
 * Read the payload length from a frame header.
 *
 * Mirrors the layout written by `encodeFrame`:
 *   [0..1] magic u16 · [2] stream u8 · [3] flags u8 ·
 *   [4..7] payload_len u32 BE · [8..11] crc32c u32 BE
 */
const PAYLOAD_LENGTH_OFFSET = 4;

function readPayloadLength(buffer: Uint8Array): number {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  return view.getUint32(PAYLOAD_LENGTH_OFFSET, false);
}

function concat(
  left: Uint8Array<ArrayBuffer>,
  right: Uint8Array,
): Uint8Array<ArrayBuffer> {
  if (left.length === 0) return right.slice();
  if (right.length === 0) return left;

  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}
