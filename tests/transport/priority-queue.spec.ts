import { expect, test } from '@playwright/test';

import { encodeFrame, decodeFrame } from '../../packages/core/src/transport/frame-codec.js';
import {
  isPriorityStream,
  orderFramesByPriority,
  PriorityFrameQueue,
} from '../../packages/core/src/transport/priority-queue.js';
import { FrameFlags, StreamType } from '../../packages/core/src/transport/types.js';

const payload = (n: number) => new Uint8Array([n]);

test.describe('Transport — Priority Frame Queue', () => {
  test('revocation gossip drains before queued chat traffic', () => {
    const queue = new PriorityFrameQueue();

    queue.enqueue(StreamType.E2EE_MESSAGE, payload(1));
    queue.enqueue(StreamType.E2EE_MESSAGE, payload(2));
    queue.enqueue(StreamType.REVOCATION_GOSSIP, payload(3));

    expect(queue.dequeue()?.streamType).toBe(StreamType.REVOCATION_GOSSIP);
    expect(queue.dequeue()?.streamType).toBe(StreamType.E2EE_MESSAGE);
    expect(queue.dequeue()?.streamType).toBe(StreamType.E2EE_MESSAGE);
    expect(queue.dequeue()).toBeUndefined();
  });

  test('FIFO order is preserved within each band', () => {
    const queue = new PriorityFrameQueue();

    queue.enqueue(StreamType.CRDT_SYNC, payload(1));
    queue.enqueue(StreamType.REVOCATION_GOSSIP, payload(10));
    queue.enqueue(StreamType.CRDT_SYNC, payload(2));
    queue.enqueue(StreamType.REVOCATION_GOSSIP, payload(11));
    queue.enqueue(StreamType.CRDT_SYNC, payload(3));

    const order = queue.drain().map((f) => f.bytes[0]);
    expect(order).toEqual([10, 11, 1, 2, 3]);
  });

  test('the PRIORITY flag promotes any stream type', () => {
    const queue = new PriorityFrameQueue();

    queue.enqueue(StreamType.E2EE_MESSAGE, payload(1));
    queue.enqueue(StreamType.CRDT_SYNC, payload(2), FrameFlags.PRIORITY);

    expect(queue.dequeue()?.bytes[0]).toBe(2);
    expect(queue.priorityCount).toBe(0);
  });

  test('band counters and emptiness track enqueued frames', () => {
    const queue = new PriorityFrameQueue();
    expect(queue.isEmpty).toBe(true);

    queue.enqueue(StreamType.E2EE_MESSAGE, payload(1));
    queue.enqueue(StreamType.REVOCATION_GOSSIP, payload(2));

    expect(queue.size).toBe(2);
    expect(queue.priorityCount).toBe(1);
    expect(queue.normalCount).toBe(1);
    expect(queue.isEmpty).toBe(false);

    queue.clear();
    expect(queue.isEmpty).toBe(true);
  });

  test('peek reveals the next frame without consuming it', () => {
    const queue = new PriorityFrameQueue();

    queue.enqueue(StreamType.E2EE_MESSAGE, payload(1));
    queue.enqueue(StreamType.REVOCATION_GOSSIP, payload(2));

    expect(queue.peek()?.bytes[0]).toBe(2);
    expect(queue.size).toBe(2);
  });

  test('isPriorityStream classifies streams and flags', () => {
    expect(isPriorityStream(StreamType.REVOCATION_GOSSIP)).toBe(true);
    expect(isPriorityStream(StreamType.E2EE_MESSAGE)).toBe(false);
    expect(isPriorityStream(StreamType.E2EE_MESSAGE, FrameFlags.PRIORITY)).toBe(true);
    expect(isPriorityStream(StreamType.E2EE_MESSAGE, FrameFlags.COMPRESSED)).toBe(false);
  });

  test('inbound frames reorder so tombstones are processed first', () => {
    const frames = [
      decodeFrame(encodeFrame(StreamType.E2EE_MESSAGE, payload(1))),
      decodeFrame(encodeFrame(StreamType.CRDT_SYNC, payload(2))),
      decodeFrame(encodeFrame(StreamType.REVOCATION_GOSSIP, payload(3))),
    ];

    const ordered = orderFramesByPriority(frames);

    expect(ordered[0]!.header.streamType).toBe(StreamType.REVOCATION_GOSSIP);
    // The input array is left untouched.
    expect(frames[0]!.header.streamType).toBe(StreamType.E2EE_MESSAGE);
  });
});
