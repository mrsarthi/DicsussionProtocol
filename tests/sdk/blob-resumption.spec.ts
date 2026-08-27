/**
 * A transfer that dies part-way resumes from where it stopped.
 *
 * Without this a 10MB send over a flaky mobile link either completes or
 * is retried from zero, and on a bad enough connection it never
 * completes at all — each attempt throwing away everything the previous
 * one achieved.
 *
 * Driven through `BlobService` directly rather than two clients, because
 * the point is to cut the link at a chosen byte, which a real connection
 * does not let a test choose.
 */

import { expect, test } from '@playwright/test';

import {
  BLOB_CHUNK_BYTES,
  BlobService,
  BlobUnavailableError,
} from '../../packages/HLessEnd/src/blob-service.js';
import { SQLiteDriver } from '../../packages/HLessEnd/src/storage/sqlite-driver.js';
import type { IStorageDriver } from '../../packages/HLessEnd/src/storage/types.js';

function pattern(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 31 + 7) % 256;
  return out;
}

async function memoryStorage(): Promise<IStorageDriver> {
  const driver = new SQLiteDriver(':memory:');
  await driver.initialize();
  return driver;
}

/**
 * Two services joined by a link the test can cut.
 *
 * `chunksBeforeCut` counts payloads the sender is allowed to deliver;
 * after that every send reports the peer as unreachable, which is what a
 * dropped connection looks like from here.
 */
function link(options: { chunksBeforeCut: number }) {
  const state = {
    sender: undefined as BlobService | undefined,
    receiver: undefined as BlobService | undefined,
    delivered: 0,
    cut: false,
  };

  const deliver = async (
    to: 'sender' | 'receiver',
    from: string,
    payload: Uint8Array,
  ): Promise<boolean> => {
    if (state.cut) return false;

    // Only chunks travelling towards the receiver are counted: the
    // request and any refusal are not what a stalled download loses.
    if (to === 'receiver') {
      if (state.delivered >= options.chunksBeforeCut) {
        state.cut = true;
        return false;
      }
      state.delivered++;
    }

    await state[to]?.handleFrame(from, payload);

    return true;
  };

  return { state, deliver };
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('Blob transfer — resumption', () => {
  test('a cut transfer resumes from where it stopped', async () => {
    const senderStorage = await memoryStorage();
    const receiverStorage = await memoryStorage();
    const original = pattern(BLOB_CHUNK_BYTES * 4 + 137);

    const wire = link({ chunksBeforeCut: 2 });

    const sender = new BlobService({
      storage: senderStorage,
      sendTo: (_did, payload) => wire.deliver('receiver', 'did:receiver', payload),
      reachablePeers: () => ['did:receiver'],
      stallTimeoutMs: 750,
    });

    const receiver = new BlobService({
      storage: receiverStorage,
      sendTo: (_did, payload) => wire.deliver('sender', 'did:sender', payload),
      reachablePeers: () => ['did:sender'],
      stallTimeoutMs: 750,
    });

    wire.state.sender = sender;
    wire.state.receiver = receiver;

    const ref = await sender.put(original, 'image/jpeg');

    // First attempt: two chunks land, then the link dies.
    await expect(receiver.get(ref)).rejects.toThrow(BlobUnavailableError);
    expect(await receiver.has(ref)).toBe(false);

    // Second attempt over a healthy link. If the offset were ignored the
    // transfer would start again, and the assembled bytes would still be
    // correct — so what proves resumption is how much crossed the wire.
    const healthy = link({ chunksBeforeCut: Number.POSITIVE_INFINITY });
    healthy.state.sender = sender;
    healthy.state.receiver = receiver;

    const resumed = new BlobService({
      storage: receiverStorage,
      sendTo: (_did, payload) => healthy.deliver('sender', 'did:sender', payload),
      reachablePeers: () => ['did:sender'],
      stallTimeoutMs: 750,
    });
    const resumedSender = new BlobService({
      storage: senderStorage,
      sendTo: (_did, payload) => healthy.deliver('receiver', 'did:receiver', payload),
      reachablePeers: () => ['did:receiver'],
      stallTimeoutMs: 750,
    });
    healthy.state.sender = resumedSender;
    healthy.state.receiver = resumed;

    const bytes = await resumed.get(ref);

    expect(Buffer.from(bytes).equals(Buffer.from(original))).toBe(true);

    // Five chunks in total; two already had. Sending all five again
    // would mean the offset was ignored.
    expect(healthy.state.delivered).toBe(3);
  });

  test('what resumed still has to match its hash', async () => {
    const senderStorage = await memoryStorage();
    const receiverStorage = await memoryStorage();
    const original = pattern(BLOB_CHUNK_BYTES * 2);

    const wire = link({ chunksBeforeCut: Number.POSITIVE_INFINITY });

    const sender = new BlobService({
      storage: senderStorage,
      sendTo: (_did, payload) => wire.deliver('receiver', 'did:receiver', payload),
      reachablePeers: () => ['did:receiver'],
      stallTimeoutMs: 750,
    });
    const receiver = new BlobService({
      storage: receiverStorage,
      sendTo: (_did, payload) => wire.deliver('sender', 'did:sender', payload),
      reachablePeers: () => ['did:sender'],
      stallTimeoutMs: 750,
    });

    wire.state.sender = sender;
    wire.state.receiver = receiver;

    const ref = await sender.put(original, 'image/png');
    const bytes = await receiver.get(ref);

    // Content addressing is only worth anything if it is checked, and
    // resumption is exactly where a mismatched byte could otherwise slip
    // in — the two halves come from two different transfers.
    expect(Buffer.from(bytes).equals(Buffer.from(original))).toBe(true);
    expect(await receiver.has(ref)).toBe(true);
  });

  test('a partial copy is never served on to someone else', async () => {
    const senderStorage = await memoryStorage();
    const middleStorage = await memoryStorage();
    const original = pattern(BLOB_CHUNK_BYTES * 3);

    const wire = link({ chunksBeforeCut: 1 });

    const sender = new BlobService({
      storage: senderStorage,
      sendTo: (_did, payload) => wire.deliver('receiver', 'did:middle', payload),
      reachablePeers: () => ['did:middle'],
      stallTimeoutMs: 750,
    });
    const middle = new BlobService({
      storage: middleStorage,
      sendTo: (_did, payload) => wire.deliver('sender', 'did:sender', payload),
      reachablePeers: () => ['did:sender'],
      stallTimeoutMs: 750,
    });

    wire.state.sender = sender;
    wire.state.receiver = middle;

    const ref = await sender.put(original, 'image/png');
    await expect(middle.get(ref)).rejects.toThrow(BlobUnavailableError);

    // The middle node holds one chunk. Passing it on would let a third
    // party believe a transfer finished when the bytes simply stop.
    const thirdStorage = await memoryStorage();
    const onward = link({ chunksBeforeCut: Number.POSITIVE_INFINITY });

    const server = new BlobService({
      storage: middleStorage,
      sendTo: (_did, payload) => onward.deliver('receiver', 'did:third', payload),
      reachablePeers: () => [],
      stallTimeoutMs: 750,
    });
    const third = new BlobService({
      storage: thirdStorage,
      sendTo: (_did, payload) => onward.deliver('sender', 'did:middle', payload),
      reachablePeers: () => ['did:middle'],
      stallTimeoutMs: 750,
    });

    onward.state.sender = server;
    onward.state.receiver = third;

    await expect(third.get(ref)).rejects.toThrow(BlobUnavailableError);
    expect(await third.has(ref)).toBe(false);
  });
});
