/**
 * Replies — which messages a message answers.
 *
 * The alternative an application is forced into is a marker inside
 * `content`: a convention every client must know forever, rendered as
 * literal text by any that does not, and impossible to strip from a
 * quoted excerpt without also stripping text a user typed.
 *
 * Ids are carried, not resolved. A reply legitimately arrives before the
 * message it answers, and may name one this device never received — so
 * the tests that matter are that the reference survives every hop
 * intact, and that a dangling one is not an error.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import {
  decodePayload,
  encodePayload,
} from '../../packages/HLessEnd/src/message-codec.js';

const settle = () => new Promise((r) => setTimeout(r, 800));

async function pairedPair(): Promise<[DicsussionClient, DicsussionClient]> {
  const a = await DicsussionClient.init({ storagePath: ':memory:' });
  const b = await DicsussionClient.init({ storagePath: ':memory:' });

  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
  a.chat.createChannel('room', [b.did]);
  b.chat.createChannel('room', [a.did]);
  await a.connect(b.getTicket());
  await settle();

  return [a, b];
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('SDK — replies across the wire', () => {
  test('a reply reaches the peer carrying what it answers', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const first = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'what time?',
      });

      const arrived = new Promise<readonly string[] | undefined>((resolve) => {
        bob.chat.onMessage('room', (m) => {
          if (m.content === 'seven') resolve(m.replyTo);
        });
      });

      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'seven',
        replyTo: [first.id],
      });

      expect(await arrived).toEqual([first.id]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the content is left exactly as typed', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const first = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'first',
      });

      const arrived = new Promise<string>((resolve) => {
        bob.chat.onMessage('room', (m) => {
          if (m.replyTo) resolve(m.content);
        });
      });

      // The whole point: a reference must not be smuggled through the
      // body. Text that looks like a marker is just text.
      const typed = '> re: something\nactually seven';
      await alice.chat.sendMessage({
        channelId: 'room',
        content: typed,
        replyTo: [first.id],
      });

      expect(await arrived).toBe(typed);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a reply answering several messages keeps all of them', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const a = await alice.chat.sendMessage({ channelId: 'room', content: 'one' });
      const b = await alice.chat.sendMessage({ channelId: 'room', content: 'two' });

      const arrived = new Promise<readonly string[] | undefined>((resolve) => {
        bob.chat.onMessage('room', (m) => {
          if (m.content === 'both') resolve(m.replyTo);
        });
      });

      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'both',
        replyTo: [a.id, b.id],
      });

      expect(await arrived).toEqual([a.id, b.id]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a reference to a message this device never saw is kept, not dropped', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const arrived = new Promise<readonly string[] | undefined>((resolve) => {
        bob.chat.onMessage('room', (m) => resolve(m.replyTo));
      });

      // Out-of-order delivery is normal, and a peer may be answering
      // something from before this device joined. Dropping the reference
      // would silently turn a reply into an ordinary message.
      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'answering something you never got',
        replyTo: ['a-message-that-never-arrived'],
      });

      expect(await arrived).toEqual(['a-message-that-never-arrived']);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('an ordinary message reports no reply', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const arrived = new Promise<readonly string[] | undefined>((resolve) => {
        bob.chat.onMessage('room', (m) => resolve(m.replyTo));
      });

      await alice.chat.sendMessage({ channelId: 'room', content: 'plain' });

      expect(await arrived).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — replies in history', () => {
  test('a reply survives in the sender history', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const first = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'question',
      });
      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'answer',
        replyTo: [first.id],
      });
      await settle();

      const history = await alice.chat.getHistory('room');
      const answer = history.find((m) => m.content === 'answer');

      expect(answer?.replyTo).toEqual([first.id]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a reply survives in the receiver history', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const first = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'question',
      });
      await alice.chat.sendMessage({
        channelId: 'room',
        content: 'answer',
        replyTo: [first.id],
      });
      await settle();

      // Where attachments were lost: the peer's own write of the same
      // message replaced the sender's copy, so a field the envelope did
      // not carry disappeared after a sync.
      const history = await bob.chat.getHistory('room');
      const answer = history.find((m) => m.content === 'answer');

      expect(answer?.replyTo).toEqual([first.id]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a message without a reply reports none in history', async () => {
    const [alice, bob] = await pairedPair();

    try {
      await alice.chat.sendMessage({ channelId: 'room', content: 'plain' });
      await settle();

      const history = await alice.chat.getHistory('room');
      expect(history[0]?.replyTo).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('Reply wire format', () => {
  test('the envelope carries reply references', () => {
    // `encodePayload` names its fields explicitly, so a field added to
    // `MessagePayload` and not to the encoder vanishes on the wire while
    // local tests still pass — the CRDT carries it separately. That is
    // exactly how `attachments` was lost.
    const back = decodePayload(
      encodePayload({
        id: 'm2',
        channelId: 'room',
        authorDid: 'did:key:zAlice',
        content: 'seven',
        replyTo: ['m1'],
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(back.replyTo).toEqual(['m1']);
  });

  test('a message with no reply decodes to none', () => {
    const back = decodePayload(
      encodePayload({
        id: 'm1',
        channelId: 'room',
        content: 'plain',
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(back.replyTo).toBeUndefined();
  });

  test('references that are not strings are refused', () => {
    const forged = new TextEncoder().encode(
      JSON.stringify({
        id: 'm2',
        channelId: 'room',
        content: 'seven',
        replyTo: [{ evil: true }, 42],
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    // The message survives; only the bad references are dropped.
    const back = decodePayload(forged);
    expect(back.content).toBe('seven');
    expect(back.replyTo).toBeUndefined();
  });

  test('an absurd number of references is refused', () => {
    const forged = new TextEncoder().encode(
      JSON.stringify({
        id: 'm2',
        channelId: 'room',
        content: 'seven',
        replyTo: Array.from({ length: 100 }, (_, i) => `m${i}`),
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(decodePayload(forged).replyTo).toBeUndefined();
  });

  test('an over-long reference is refused', () => {
    // Ids are written into the conversation document, so their length is
    // bounded rather than trusted.
    const forged = new TextEncoder().encode(
      JSON.stringify({
        id: 'm2',
        channelId: 'room',
        content: 'seven',
        replyTo: ['x'.repeat(300)],
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(decodePayload(forged).replyTo).toBeUndefined();
  });

  test('replies and attachments coexist on one message', () => {
    const ref = { hash: 'a'.repeat(64), size: 12, mime: 'image/png' };
    const back = decodePayload(
      encodePayload({
        id: 'm2',
        channelId: 'room',
        content: 'here it is',
        replyTo: ['m1'],
        attachments: [ref],
        timestamp: 1,
        messageIndex: 0,
      }),
    );

    expect(back.replyTo).toEqual(['m1']);
    expect(back.attachments?.[0]).toEqual(ref);
  });
});
