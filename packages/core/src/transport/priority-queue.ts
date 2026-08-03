/**
 * @dicsussion/transport — Priority Frame Queue
 *
 * Two-band send queue enforcing the preemption rule from RFC 001 §6 and
 * AGENT_INSTRUCTIONS §4.2 rule 5: revocation tombstones on Stream `0x03`
 * MUST be delivered ahead of chat traffic on Stream `0x02`, including
 * during partition recovery when both bands are backlogged.
 *
 * Ordering guarantees:
 * - The priority band drains completely before the normal band.
 * - Within a band, frames stay strictly FIFO.
 * - A priority frame enqueued after normal frames still jumps ahead.
 */

import { isPriorityFrame } from './frame-codec.js';
import type { Frame, StreamTypeValue } from './types.js';
import { FrameFlags, StreamType } from './types.js';

/** A frame awaiting transmission. */
export interface QueuedFrame {
  readonly streamType: StreamTypeValue;
  /** Fully encoded wire frame (12-byte header + payload). */
  readonly bytes: Uint8Array;
  /** Monotonic sequence number, used to keep FIFO order within a band. */
  readonly sequence: number;
}

/**
 * Whether a stream type must be treated as high priority on send.
 *
 * Stream `0x03` (revocation gossip) is unconditionally high priority;
 * any other stream may opt in via the PRIORITY frame flag.
 */
export function isPriorityStream(streamType: StreamTypeValue, flags = 0): boolean {
  return (
    streamType === StreamType.REVOCATION_GOSSIP ||
    (flags & FrameFlags.PRIORITY) !== 0
  );
}

/**
 * Priority-banded FIFO queue for outbound frames.
 */
export class PriorityFrameQueue {
  private readonly priorityBand: QueuedFrame[] = [];
  private readonly normalBand: QueuedFrame[] = [];
  private sequence = 0;

  /** Total frames awaiting transmission across both bands. */
  get size(): number {
    return this.priorityBand.length + this.normalBand.length;
  }

  /** Frames waiting in the high-priority band. */
  get priorityCount(): number {
    return this.priorityBand.length;
  }

  /** Frames waiting in the normal band. */
  get normalCount(): number {
    return this.normalBand.length;
  }

  /** True when nothing is queued. */
  get isEmpty(): boolean {
    return this.size === 0;
  }

  /**
   * Queue an encoded frame for transmission.
   *
   * @param streamType Sub-protocol stream type (0x01–0x06).
   * @param bytes The encoded wire frame.
   * @param flags Frame flags from the header, used to honour PRIORITY.
   */
  enqueue(streamType: StreamTypeValue, bytes: Uint8Array, flags = 0): void {
    const entry: QueuedFrame = { streamType, bytes, sequence: this.sequence++ };

    if (isPriorityStream(streamType, flags)) {
      this.priorityBand.push(entry);
    } else {
      this.normalBand.push(entry);
    }
  }

  /**
   * Remove the next frame to transmit: priority band first, then normal.
   *
   * @returns The next frame, or undefined when the queue is empty.
   */
  dequeue(): QueuedFrame | undefined {
    return this.priorityBand.shift() ?? this.normalBand.shift();
  }

  /**
   * Remove and return every queued frame in transmission order.
   *
   * Used on partition recovery, where all pending tombstones must be
   * handed to the peer before any Automerge state merge is attempted.
   */
  drain(): QueuedFrame[] {
    const drained = [...this.priorityBand, ...this.normalBand];
    this.priorityBand.length = 0;
    this.normalBand.length = 0;
    return drained;
  }

  /** Inspect the next frame without removing it. */
  peek(): QueuedFrame | undefined {
    return this.priorityBand[0] ?? this.normalBand[0];
  }

  /** Discard all queued frames. */
  clear(): void {
    this.priorityBand.length = 0;
    this.normalBand.length = 0;
  }
}

/**
 * Sort received frames so revocation gossip is processed first.
 *
 * RFC 001 §6 requires peers to apply all pending tombstones before
 * executing Automerge merges when recovering from a partition.
 *
 * @param frames Frames as they arrived off the wire.
 * @returns A new array in processing order; the input is not mutated.
 */
export function orderFramesByPriority(frames: readonly Frame[]): Frame[] {
  const priority: Frame[] = [];
  const normal: Frame[] = [];

  for (const frame of frames) {
    if (isPriorityFrame(frame.header)) priority.push(frame);
    else normal.push(frame);
  }

  return [...priority, ...normal];
}
