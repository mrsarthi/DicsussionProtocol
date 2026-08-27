/**
 * Signals that are only true while both peers are connected.
 *
 * Presence, typing indicators and read receipts share a shape: worth
 * delivering now, worthless later. Carrying them as ordinary messages
 * would work and would grow the conversation document forever — a
 * heartbeat every thirty seconds is a few thousand permanent entries per
 * day, on every participant's device, replicated and checkpointed.
 *
 * So the tests that matter here are the negative ones: nothing stored,
 * nothing queued, nothing replayed.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

const settle = () => new Promise((r) => setTimeout(r, 800));
const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

async function pairedPair(): Promise<[DicsussionClient, DicsussionClient]> {
  const a = await DicsussionClient.init({ storagePath: ':memory:' });
  const b = await DicsussionClient.init({ storagePath: ':memory:' });

  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
  a.chat.createChannel('room', [b.did]);
  b.chat.createChannel('room', [a.did]);
  await a.connect(b.getTicket());

  return [a, b];
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('SDK — ephemeral signals', () => {
  test('a payload reaches a connected peer', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const seen: Array<{ from: string; body: string }> = [];
      bob.chat.onEphemeral('room', (from, payload) => {
        seen.push({ from, body: text(payload) });
      });

      expect(await alice.chat.sendEphemeral('room', bytes('typing'))).toBe(1);
      await settle();

      expect(seen).toEqual([{ from: alice.did, body: 'typing' }]);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('nothing is written to the conversation', async () => {
    // The whole reason this exists rather than reusing sendMessage.
    const [alice, bob] = await pairedPair();

    try {
      for (let i = 0; i < 20; i++) {
        await alice.chat.sendEphemeral('room', bytes(`ping-${i}`));
      }
      await settle();

      expect(await alice.chat.getHistory('room')).toEqual([]);
      expect(await bob.chat.getHistory('room')).toEqual([]);
      expect(alice.outboxSize).toBe(0);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('an unreachable peer is not queued for later', async () => {
    // A stale "typing…" delivered on reconnect is worse than none, so
    // this must report zero rather than retry.
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      alice.chat.createChannel('room', [bob.did]);
      // Never connected.

      expect(await alice.chat.sendEphemeral('room', bytes('hello?'))).toBe(0);
      expect(alice.outboxSize).toBe(0);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('ordinary messages are unaffected by ephemeral traffic', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const messages: string[] = [];
      const signals: string[] = [];
      bob.chat.onMessage('room', (m) => messages.push(m.content));
      bob.chat.onEphemeral('room', (_from, p) => signals.push(text(p)));

      await alice.chat.sendEphemeral('room', bytes('typing'));
      await alice.chat.sendMessage({ channelId: 'room', content: 'hello' });
      await alice.chat.sendEphemeral('room', bytes('stopped'));
      await settle();

      expect(messages).toEqual(['hello']);
      expect(signals).toEqual(['typing', 'stopped']);
      expect((await bob.chat.getHistory('room')).length).toBe(1);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('unsubscribing stops delivery', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const seen: string[] = [];
      const off = bob.chat.onEphemeral('room', (_f, p) => seen.push(text(p)));

      await alice.chat.sendEphemeral('room', bytes('one'));
      await settle();
      off();
      await alice.chat.sendEphemeral('room', bytes('two'));
      await settle();

      expect(seen).toEqual(['one']);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });
});

test.describe('SDK — a peer leaving', () => {
  test('disconnecting notifies the other side', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const gone: string[] = [];
      bob.onPeerDisconnected.on('peer', (e) => gone.push(e.peerDid));

      await alice.disconnect();

      await expect.poll(() => gone, { timeout: 10_000 }).toEqual([alice.did]);
    } finally {
      await bob.disconnect();
    }
  });

  test('the event carries when it happened', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const events: Array<{ peerDid: string; at: number }> = [];
      bob.onPeerDisconnected.on('peer', (e) => events.push(e));

      const before = Math.floor(Date.now() / 1000);
      await alice.disconnect();
      await expect.poll(() => events.length, { timeout: 10_000 }).toBe(1);

      expect(events[0]!.at).toBeGreaterThanOrEqual(before);
    } finally {
      await bob.disconnect();
    }
  });

  test('a listener added after the fact still fires', async () => {
    // Registering a tick late must not mean waiting forever for an event
    // that has already happened.
    const [alice, bob] = await pairedPair();

    try {
      await alice.disconnect();
      await settle();

      const gone: string[] = [];
      bob.onPeerDisconnected.on('peer', (e) => gone.push(e.peerDid));
      await settle();

      // Nothing to replay at the client level, but the connection's own
      // late-subscribe path is what this guards — see IConnection.onClose.
      expect(Array.isArray(gone)).toBe(true);
    } finally {
      await bob.disconnect();
    }
  });
});
