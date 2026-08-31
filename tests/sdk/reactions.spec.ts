/**
 * Reactions — the WhatsApp gesture, not a message.
 *
 * Carried as messages, tapping and untapping would leave a permanent
 * entry each time and every client would have to know to hide them from
 * the conversation. Carried as ephemeral signals they would vanish on
 * restart and never reach anyone who was offline. They are neither: one
 * mutable slot per person per message, living in the conversation
 * document.
 *
 * So the tests that matter are that a second reaction *replaces* a
 * first, that withdrawal sticks, and that both survive a sync.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { MAX_REACTION_LENGTH } from '../../packages/HLessEnd/src/types.js';
import type { ReactionEvent } from '../../packages/HLessEnd/src/types.js';

const settle = (ms = 900) => new Promise((r) => setTimeout(r, ms));

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

test.describe('SDK — reacting', () => {
  test('a reaction is visible to the person who made it', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      alice.chat.react('room', message.id, '👍');

      const [summary] = alice.chat.getReactions('room', message.id);
      expect(summary?.emoji).toBe('👍');
      expect(summary?.count).toBe(1);
      expect(summary?.mine).toBe(true);
      expect(summary?.reactors).toEqual([alice.did]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('reacting again replaces rather than accumulates', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      // The whole reason this is not a message: a user who taps three
      // things in a row has left one mark, not three.
      alice.chat.react('room', message.id, '👍');
      alice.chat.react('room', message.id, '❤️');
      alice.chat.react('room', message.id, '😂');

      const summaries = alice.chat.getReactions('room', message.id);
      expect(summaries).toHaveLength(1);
      expect(summaries[0]?.emoji).toBe('😂');
      expect(summaries[0]?.count).toBe(1);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('withdrawing leaves nothing behind', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      alice.chat.react('room', message.id, '👍');
      alice.chat.unreact('room', message.id);

      expect(alice.chat.getReactions('room', message.id)).toEqual([]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('withdrawing when there is nothing to withdraw is harmless', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      expect(() => alice.chat.unreact('room', message.id)).not.toThrow();
      expect(alice.chat.getReactions('room', message.id)).toEqual([]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('reacting can be undone and redone', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      alice.chat.react('room', message.id, '👍');
      alice.chat.unreact('room', message.id);
      alice.chat.react('room', message.id, '👍');

      const summaries = alice.chat.getReactions('room', message.id);
      expect(summaries).toHaveLength(1);
      expect(summaries[0]?.count).toBe(1);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — reactions between people', () => {
  test('a peer sees one that was made', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      alice.chat.react('room', message.id, '👍');
      await settle();

      const [summary] = bob.chat.getReactions('room', message.id);
      expect(summary?.emoji).toBe('👍');
      expect(summary?.reactors).toEqual([alice.did]);
      // Bob did not react, so it is not his.
      expect(summary?.mine).toBe(false);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('two people on one message are counted together', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      alice.chat.react('room', message.id, '👍');
      bob.chat.react('room', message.id, '👍');
      await settle();

      const [summary] = bob.chat.getReactions('room', message.id);
      expect(summary?.count).toBe(2);
      expect(summary?.reactors).toEqual([alice.did, bob.did].sort());
      expect(summary?.mine).toBe(true);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('different reactions are grouped separately', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      alice.chat.react('room', message.id, '👍');
      bob.chat.react('room', message.id, '❤️');
      await settle();

      const summaries = bob.chat.getReactions('room', message.id);
      expect(summaries).toHaveLength(2);
      expect(summaries.map((r) => r.count)).toEqual([1, 1]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a withdrawal reaches the other side', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      alice.chat.react('room', message.id, '👍');
      await settle();
      expect(bob.chat.getReactions('room', message.id)).toHaveLength(1);

      alice.chat.unreact('room', message.id);
      await settle();

      // A withdrawal that did not travel would leave the reaction lit on
      // every device except the one that removed it.
      expect(bob.chat.getReactions('room', message.id)).toEqual([]);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a listener is told when a peer reacts', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      const events: ReactionEvent[] = [];
      bob.chat.onReaction('room', (event) => events.push(event));

      alice.chat.react('room', message.id, '👍');
      await settle();

      const seen = events.find((e) => e.authorDid === alice.did);
      expect(seen?.emoji).toBe('👍');
      expect(seen?.messageId).toBe(message.id);
      expect(seen?.removed).toBe(false);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a withdrawal is reported as one', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      alice.chat.react('room', message.id, '👍');
      await settle();

      const events: ReactionEvent[] = [];
      bob.chat.onReaction('room', (event) => events.push(event));

      alice.chat.unreact('room', message.id);
      await settle();

      // `removed` spares every caller a string comparison against ''.
      expect(events.at(-1)?.removed).toBe(true);
      expect(events.at(-1)?.emoji).toBe('');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('unsubscribing stops delivery', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      let seen = 0;
      const stop = bob.chat.onReaction('room', () => seen++);
      stop();

      alice.chat.react('room', message.id, '👍');
      await settle();

      expect(seen).toBe(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — reaction limits', () => {
  test('an over-long reaction is refused', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      // Long enough and a reaction becomes a message in disguise, in a
      // field no client renders as one.
      expect(() =>
        alice.chat.react('room', message.id, 'x'.repeat(MAX_REACTION_LENGTH + 1)),
      ).toThrow(/limit/);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('an empty reaction points at unreact', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      expect(() => alice.chat.react('room', message.id, '')).toThrow(/unreact/);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a multi-code-point emoji fits', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });

      // A ZWJ sequence with a skin tone is many code units. A cap set by
      // eye rather than by counting would reject it.
      const family = '👩🏽‍❤️‍👨🏻';
      alice.chat.react('room', message.id, family);

      expect(alice.chat.getReactions('room', message.id)[0]?.emoji).toBe(family);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('reacting in an unknown conversation is refused', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      expect(() => alice.chat.react('nowhere', 'm1', '👍')).toThrow(/Unknown/);
    } finally {
      await alice.disconnect();
    }
  });
});

test.describe('SDK — reactions are not messages', () => {
  test('reacting does not add to the conversation', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      const before = (await bob.chat.getHistory('room')).length;

      alice.chat.react('room', message.id, '👍');
      alice.chat.unreact('room', message.id);
      alice.chat.react('room', message.id, '❤️');
      await settle();

      // Three taps. If these were messages the thread would have grown
      // by three, and every client would have to hide them.
      expect((await bob.chat.getHistory('room')).length).toBe(before);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a reaction does not reach onMessage', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const message = await alice.chat.sendMessage({
        channelId: 'room',
        content: 'nice',
      });
      await settle();

      let messages = 0;
      bob.chat.onMessage('room', () => messages++);

      alice.chat.react('room', message.id, '👍');
      await settle();

      expect(messages).toBe(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});
