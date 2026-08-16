/**
 * @dicsussion/transport — Byte-pipe reader for the bridged transport
 *
 * Turns an ordered byte stream into the two shapes the handshake needs,
 * in sequence: length-prefixed control messages while RFC 001 §5 runs,
 * then protocol frames once a session exists.
 *
 * THE PART THAT IS EASY TO GET WRONG: the last control message and the
 * first frames can arrive in the same chunk. Switching modes must
 * therefore re-drain whatever is already buffered rather than waiting for
 * the next read — otherwise the first frames of every connection are lost
 * whenever the peer is fast enough to coalesce, which is most of the time
 * on loopback and intermittent on a real network.
 */

import { FrameReader } from './frame-reader.js';
import { decodeControlJson, encodeControlJson } from './json-bytes.js';
import type { Frame } from './types.js';

/** Length prefix on control messages, matching the Iroh control stream. */
const LENGTH_PREFIX_BYTES = 4;

/**
 * Ceiling on a control message, mirroring `iroh-transport`'s reader.
 *
 * Rejected before allocating: the length is attacker-controlled until the
 * handshake completes.
 */
const MAX_CONTROL_BYTES = 64 * 1024;

/** Frame a control message for an ordered byte stream. */
export function encodeControlMessage(value: unknown): Uint8Array {
  const body = encodeControlJson(value);
  const out = new Uint8Array(LENGTH_PREFIX_BYTES + body.length);

  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, LENGTH_PREFIX_BYTES);

  return out;
}

/**
 * Reassembles control messages, then frames, from one byte pipe.
 *
 * One instance per connection — two connections' bytes share no buffer.
 */
export class PipeReader {
  private buffer: Uint8Array = new Uint8Array(0);
  private frames: FrameReader | null = null;
  private onFrames: ((frames: Frame[]) => void) | null = null;
  private waiter: { resolve: (bytes: Uint8Array) => void; reject: (error: Error) => void } | null =
    null;

  /** Append bytes from the host and dispatch whatever they complete. */
  push(chunk: Uint8Array): void {
    this.buffer = concat(this.buffer, chunk);
    this.drain();
  }

  /**
   * Await the next control message.
   *
   * @param timeoutMs How long before a stalled handshake gives up.
   * @throws If another read is already pending, if the peer declares an
   *   oversized message, or on timeout.
   */
  async readControl<T>(timeoutMs: number): Promise<T> {
    if (this.waiter) {
      throw new Error('A control read is already pending on this pipe');
    }
    if (this.frames) {
      throw new Error('Pipe has moved to frames; control reads are over');
    }

    const bytes = await new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new Error(`Handshake stalled for ${timeoutMs}ms`));
      }, timeoutMs);

      // A pending handshake must not hold a Node process open.
      (timer as unknown as { unref?: () => void }).unref?.();

      this.waiter = {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };

      // The message may already be buffered from an earlier chunk.
      this.drain();
    });

    return decodeControlJson<T>(bytes);
  }

  /**
   * Stop expecting control messages and emit frames from here on.
   *
   * Bytes already buffered are re-drained immediately — see the note at
   * the top of this file.
   *
   * @param handler Receives each batch of completed frames.
   */
  switchToFrames(handler: (frames: Frame[]) => void): void {
    this.frames = new FrameReader();
    this.onFrames = handler;
    this.drain();
  }

  /** Abandon a pending read, e.g. when the connection closes. */
  fail(reason: string): void {
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.reject(new Error(reason));
  }

  /** Release buffered bytes. */
  reset(): void {
    this.buffer = new Uint8Array(0);
    this.frames?.reset();
  }

  private drain(): void {
    if (this.frames) {
      if (this.buffer.length === 0) return;

      const chunk = this.buffer;
      this.buffer = new Uint8Array(0);

      let completed: Frame[];
      try {
        completed = this.frames.push(chunk);
      } catch {
        // An over-long or corrupt frame is dropped, never fatal
        // (RFC 001 §7). The reader is reset so one bad length does not
        // desynchronise every frame behind it.
        this.frames.reset();
        return;
      }

      if (completed.length > 0) this.onFrames?.(completed);
      return;
    }

    const waiter = this.waiter;
    if (!waiter) return;
    if (this.buffer.length < LENGTH_PREFIX_BYTES) return;

    const view = new DataView(
      this.buffer.buffer,
      this.buffer.byteOffset,
      this.buffer.byteLength,
    );
    const length = view.getUint32(0, false);

    if (length > MAX_CONTROL_BYTES) {
      this.waiter = null;
      waiter.reject(
        new Error(`Control message claims ${length} bytes, over the limit`),
      );
      return;
    }

    const total = LENGTH_PREFIX_BYTES + length;
    if (this.buffer.length < total) return;

    const body = this.buffer.slice(LENGTH_PREFIX_BYTES, total);
    this.buffer = this.buffer.slice(total);

    this.waiter = null;
    waiter.resolve(body);
  }
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length === 0) return right.slice();
  if (right.length === 0) return left;

  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}
