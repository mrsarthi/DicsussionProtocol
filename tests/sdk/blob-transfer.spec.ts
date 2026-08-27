/**
 * Media transfer — images and files, moved outside the conversation.
 *
 * The thing being avoided is base64 in a message body: a third larger
 * than the file, permanent in the CRDT, loaded whole into memory on both
 * sides, and impossible to delete afterwards.
 *
 * So the tests that matter are that the bytes travel intact, that they
 * travel only when someone asks, that a partial transfer resumes rather
 * than restarting, and that a failure says which failure it was.
 */

import { expect, test } from '@playwright/test';

import {
  BlobTooLargeError,
  BlobUnavailableError,
  MAX_BLOB_BYTES,
} from '../../packages/HLessEnd/src/blob-service.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import {
  decodePayload,
  encodePayload,
} from '../../packages/HLessEnd/src/message-codec.js';

const settle = () => new Promise((r) => setTimeout(r, 800));

/** Deterministic bytes, so a mismatch says where rather than just that. */
function pattern(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 31 + 7) % 256;
  return out;
}

async function pairedPair(): Promise<[DicsussionClient, DicsussionClient]> {
  const a = await DicsussionClient.init({ storagePath: ':memory:' });
  const b = await DicsussionClient.init({ storagePath: ':memory:' });

  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
  a.chat.createChannel('room', [b.did]);
  b.chat.createChannel('room', [a.did]);
  await a.connect(b.getTicket());

  // `connect` resolves when the dialer finishes its handshake; the
  // accepting side has not necessarily surfaced the connection yet, and
  // a fetch started before it does finds nobody to ask.
  await settle();

  return [a, b];
}

test.describe.configure({ mode: 'serial', timeout: 90_000 });

test.describe('SDK — storing blobs', () => {
  test('a handle names its content', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const ref = await alice.blobs.put(pattern(1000), 'image/png');

      expect(ref.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(ref.size).toBe(1000);
      expect(ref.mime).toBe('image/png');
    } finally {
      await alice.disconnect();
    }
  });

  test('the same bytes twice are the same blob', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Content addressing earning its keep: a picture forwarded around
      // a group is stored once however many times it arrives.
      const first = await alice.blobs.put(pattern(500), 'image/png');
      const second = await alice.blobs.put(pattern(500), 'image/png');

      expect(second.hash).toBe(first.hash);
    } finally {
      await alice.disconnect();
    }
  });

  test('bytes come back from local storage unchanged', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const original = pattern(9999);
      const ref = await alice.blobs.put(original, 'application/pdf');

      expect(Array.from(await alice.blobs.get(ref))).toEqual(
        Array.from(original),
      );
    } finally {
      await alice.disconnect();
    }
  });

  test('an oversized blob is refused with a limit the app can quote', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const error = await alice.blobs
        .put(new Uint8Array(MAX_BLOB_BYTES + 1), 'video/mp4')
        .catch((e: unknown) => e as BlobTooLargeError);

      expect(error).toBeInstanceOf(BlobTooLargeError);
      expect(error.limit).toBe(MAX_BLOB_BYTES);
      expect(error.actual).toBe(MAX_BLOB_BYTES + 1);
    } finally {
      await alice.disconnect();
    }
  });

  test('deleting forgets the bytes', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const ref = await alice.blobs.put(pattern(100), 'image/png');
      expect(await alice.blobs.has(ref)).toBe(true);

      await alice.blobs.delete(ref);
      expect(await alice.blobs.has(ref)).toBe(false);
    } finally {
      await alice.disconnect();
    }
  });
});

test.describe('SDK — fetching blobs from a peer', () => {
  test('bytes arrive intact across the wire', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const original = pattern(5000);
      const ref = await alice.blobs.put(original, 'image/png');

      expect(Array.from(await bob.blobs.get(ref))).toEqual(
        Array.from(original),
      );
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a blob larger than one chunk is reassembled in order', async () => {
    const [alice, bob] = await pairedPair();

    try {
      // Over 256KB, so this exercises the multi-chunk path rather than a
      // single frame that happens to fit.
      const original = pattern(700_000);
      const ref = await alice.blobs.put(original, 'image/jpeg');

      const fetched = await bob.blobs.get(ref);
      expect(fetched.length).toBe(original.length);
      // Compared as a whole rather than sampled: an off-by-one in
      // reassembly would pass a spot check at either end.
      expect(Buffer.from(fetched).equals(Buffer.from(original))).toBe(true);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a fetched blob is kept, so the second read is local', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const ref = await alice.blobs.put(pattern(2000), 'image/png');
      await bob.blobs.get(ref);

      expect(await bob.blobs.has(ref)).toBe(true);

      // Alice is gone; a stored blob must not need her again.
      await alice.disconnect();
      expect((await bob.blobs.get(ref)).length).toBe(2000);
    } finally {
      await bob.disconnect();
    }
  });

  test('progress is reported as chunks land', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const ref = await alice.blobs.put(pattern(600_000), 'image/jpeg');

      const seen: number[] = [];
      bob.blobs.onProgress(ref, (received, total) => {
        expect(total).toBe(600_000);
        seen.push(received);
      });

      await bob.blobs.get(ref);

      // Monotonic, and ending at the full size — a bar that goes
      // backwards is worse than no bar.
      expect(seen.length).toBeGreaterThan(1);
      expect(seen[seen.length - 1]).toBe(600_000);
      expect([...seen].sort((a, b) => a - b)).toEqual(seen);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('two callers waiting on one blob share the transfer', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const original = pattern(300_000);
      const ref = await alice.blobs.put(original, 'image/png');

      const [first, second] = await Promise.all([
        bob.blobs.get(ref),
        bob.blobs.get(ref),
      ]);

      expect(first.length).toBe(original.length);
      expect(second.length).toBe(original.length);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — when a blob cannot be had', () => {
  test('nobody connected is a named failure, not a hang', async () => {
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // The app has to phrase this for a human. "Invalid ticket" is what
      // happens when failures arrive without distinguishable causes.
      const error = await bob.blobs
        .get({ hash: 'a'.repeat(64), size: 10, mime: 'image/png' })
        .catch((e: unknown) => e as BlobUnavailableError);

      expect(error).toBeInstanceOf(BlobUnavailableError);
    } finally {
      await bob.disconnect();
    }
  });

  test('a peer who does not have it says so rather than stalling', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const error = await bob.blobs
        .get({ hash: 'b'.repeat(64), size: 10, mime: 'image/png' })
        .catch((e: unknown) => e as BlobUnavailableError);

      expect(error).toBeInstanceOf(BlobUnavailableError);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('an unpaired peer cannot pull bytes by hash', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const ref = await alice.blobs.put(pattern(1000), 'image/png');

      // A hash is a capability if anyone may redeem it. Alice never
      // accepted this peer, so she serves them nothing.
      await stranger.connect(alice.getTicket());
      await settle();

      await expect(stranger.blobs.get(ref)).rejects.toThrow(
        BlobUnavailableError,
      );
    } finally {
      await alice.disconnect();
      await stranger.disconnect();
    }
  });
});

test.describe('SDK — attachments on messages', () => {
  test('a handle travels with the message and the bytes do not', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const original = pattern(4096);
      const ref = await alice.blobs.put(original, 'image/png');

      const received = new Promise<readonly { hash: string }[] | undefined>(
        (resolve) => {
          bob.chat.onMessage('room', (message) =>
            resolve(message.attachments),
          );
        },
      );

      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'look at this',
        attachments: [ref],
      });

      const attachments = await received;
      expect(attachments?.[0]?.hash).toBe(ref.hash);

      // The handle arrived; the bytes did not follow it uninvited.
      expect(await bob.blobs.has(ref)).toBe(false);

      // And they are there when asked for.
      expect(Array.from(await bob.blobs.get(ref))).toEqual(Array.from(original));
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('attachments survive in history', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const ref = await alice.blobs.put(pattern(64), 'image/png');

      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'with a picture',
        attachments: [ref],
      });
      await settle();

      const history = await alice.chat.getHistory('room');
      const withPicture = history.find((m) => m.content === 'with a picture');

      expect(withPicture?.attachments?.[0]?.hash).toBe(ref.hash);
      expect(withPicture?.attachments?.[0]?.mime).toBe('image/png');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a message without attachments reports none', async () => {
    const [alice, bob] = await pairedPair();

    try {
      await alice.chat.sendMessage({ channelId: 'room', content: 'just text' });
      await settle();

      const history = await alice.chat.getHistory('room');
      expect(history[0]?.attachments).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('Blob wire format', () => {
  test('the envelope carries attachment handles', () => {
    // This is where they were silently dropped: `encodePayload` names
    // its fields explicitly, so a field added to `MessagePayload` and
    // not to the encoder vanishes on the wire while every local test
    // still passes, because the CRDT carries it separately.
    const ref = { hash: 'a'.repeat(64), size: 1234, mime: 'image/png' };
    const back = decodePayload(
      encodePayload({
        id: 'm1',
        channelId: 'room',
        authorDid: 'did:key:zAlice',
        content: 'look',
        attachments: [ref],
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(back.attachments?.[0]).toEqual(ref);
  });

  test('a message with no attachments decodes to none', () => {
    const back = decodePayload(
      encodePayload({
        id: 'm1',
        channelId: 'room',
        content: 'plain',
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(back.attachments).toBeUndefined();
  });

  test('a handle whose hash is not a hash is refused', () => {
    // Handles arrive from a peer and are written into the conversation
    // document, so they are checked rather than trusted.
    const forged = new TextEncoder().encode(
      JSON.stringify({
        id: 'm1',
        channelId: 'room',
        content: 'look',
        attachments: [{ hash: '../../etc/passwd', size: 1, mime: 'image/png' }],
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    // The message survives; only the bad handle is dropped.
    const back = decodePayload(forged);
    expect(back.content).toBe('look');
    expect(back.attachments).toBeUndefined();
  });

  test('an absurd number of handles is refused', () => {
    const many = Array.from({ length: 100 }, () => ({
      hash: 'a'.repeat(64),
      size: 1,
      mime: 'image/png',
    }));

    const forged = new TextEncoder().encode(
      JSON.stringify({
        id: 'm1',
        channelId: 'room',
        content: 'look',
        attachments: many,
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(decodePayload(forged).attachments).toBeUndefined();
  });
});
