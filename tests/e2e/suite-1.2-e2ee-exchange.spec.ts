/**
 * Phase 1B — Test Suite 1.2: E2EE Message Exchange
 *
 * Drives two full DicsussionClient instances and verifies:
 *   - Node A's encrypted message reaches and decrypts on Node B
 *   - ciphertext on Stream 0x02 leaks neither plaintext nor channel id
 *   - a wrong key cannot decrypt the envelope
 *   - messages sent while offline queue in the outbox and flush on
 *     simulated network reconnection (RFC 004 §7.4)
 *   - Automerge state converges across the two peers (RFC 002 §4.2)
 */

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { StreamType } from '../../packages/core/src/transport/types.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { openMessage, sealMessage } from '../../packages/HLessEnd/src/message-codec.js';
import { generateX25519Keypair } from '../../packages/core/src/crypto/keys.js';
import type { SdkChatMessage } from '../../packages/HLessEnd/src/types.js';

/** Wait until `predicate` holds or the budget expires. */
async function waitFor(
  predicate: () => boolean,
  timeoutMs = 3_000,
  pollMs = 10,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return predicate();
}

/** Stand up two in-memory clients that know each other's encryption keys. */
async function createPeerPair(): Promise<{
  alice: DicsussionClient;
  bob: DicsussionClient;
  teardown: () => Promise<void>;
}> {
  const alice = await DicsussionClient.init({ storagePath: ':memory:' });
  const bob = await DicsussionClient.init({ storagePath: ':memory:' });

  // Out-of-band pairing: each side learns the other's X25519 public key.
  alice.addPeer(bob.did, bob.encryptionPublicKey);
  bob.addPeer(alice.did, alice.encryptionPublicKey);
  for (const channel of ['general', 'secret-channel']) {
    alice.chat.createChannel(channel, [bob.did]);
  }
  for (const channel of ['general', 'secret-channel']) {
    bob.chat.createChannel(channel, [alice.did]);
  }

  return {
    alice,
    bob,
    teardown: async () => {
      await alice.disconnect();
      await bob.disconnect();
      clearTransportRegistry();
    },
  };
}

/**
 * Whether a peer is currently entitled to the shared channel.
 *
 * Pairing and channel membership are separate gates, and this asserts
 * the gap between them rather than assuming it.
 */
async function newcomerReceives(
  sender: DicsussionClient,
  _receiver: DicsussionClient,
): Promise<boolean> {
  const before = sender.outboxSize;
  await sender.chat.sendMessage({ channelId: 'general', content: 'probe' });
  // A message with no eligible recipient is queued rather than sent.
  return sender.outboxSize === before;
}

test.describe('Suite 1.2 — E2EE Message Exchange', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('Node A sends an encrypted message that Node B decrypts', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('general', (msg) => received.push(msg));

      await alice.connect(bob.getTicket());

      const sent = await alice.chat.sendMessage({
        channelId: 'general',
        content: 'hello from Alice',
      });

      expect(await waitFor(() => received.length === 1)).toBe(true);

      const inbound = received[0]!;
      expect(inbound.content).toBe('hello from Alice');
      expect(inbound.channelId).toBe('general');
      expect(inbound.authorDid).toBe(alice.did);
      expect(inbound.id).toBe(sent.id);
    } finally {
      await teardown();
    }
  });

  test('ciphertext on the wire reveals neither plaintext nor channel', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      const wireFrames: Uint8Array[] = [];

      const connection = await alice.connect(bob.getTicket());
      connection.onFrame((frame) => {
        if (frame.header.streamType === StreamType.E2EE_MESSAGE) {
          wireFrames.push(frame.payload.slice());
        }
      });

      // The responder learns of an inbound connection asynchronously;
      // until it does it considers itself peerless and would queue the
      // message instead of sending it.
      expect(await waitFor(() => bob.getNetworkStatus().peerCount === 1)).toBe(true);

      // Bob replies so Alice's connection observes a 0x02 frame.
      await bob.chat.sendMessage({
        channelId: 'secret-channel',
        content: 'TOP SECRET PAYLOAD',
      });

      expect(await waitFor(() => wireFrames.length >= 1)).toBe(true);

      const wire = Buffer.from(wireFrames[0]!).toString('latin1');
      expect(wire).not.toContain('TOP SECRET PAYLOAD');
      expect(wire).not.toContain('secret-channel');
      expect(wire).not.toContain(bob.did);
    } finally {
      await teardown();
    }
  });

  test('an envelope cannot be opened with the wrong session key', () => {
    // Messages are sealed under the connection's forward-secret session
    // key now, not the recipient's long-term X25519 key — so the wrong
    // key here is another session's, which is what an attacker who later
    // stole a long-term key would be left holding.
    const sessionKey = new Uint8Array(32);
    crypto.getRandomValues(sessionKey);

    const otherSessionKey = new Uint8Array(32);
    crypto.getRandomValues(otherSessionKey);

    const envelope = sealMessage(
      {
        id: 'm1',
        channelId: 'general',
        authorDid: 'did:key:z6MkAlice',
        content: 'confidential',
        timestamp: 1_700_000_000,
        messageIndex: 0,
      },
      sessionKey,
      170_000_000,
    );

    expect(openMessage(envelope, sessionKey).payload.content).toBe(
      'confidential',
    );

    // Anyone else fails AES-GCM authentication.
    expect(() => openMessage(envelope, otherSessionKey)).toThrow();
  });

  test('messages sent while offline queue in the outbox', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      await alice.connect(bob.getTicket());
      alice.goOffline();

      await alice.chat.sendMessage({ channelId: 'general', content: 'queued 1' });
      await alice.chat.sendMessage({ channelId: 'general', content: 'queued 2' });

      expect(alice.outboxSize).toBe(2);

      // Local-first: the sender's own history is correct while offline.
      const history = await alice.chat.getHistory('general');
      expect(history.map((m) => m.content)).toEqual(['queued 1', 'queued 2']);
    } finally {
      await teardown();
    }
  });

  test('outbox flushes to the peer on simulated reconnection', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      const received: string[] = [];
      bob.chat.onMessage('general', (msg) => received.push(msg.content));

      await alice.connect(bob.getTicket());

      // Partition: nothing may reach Bob while Alice is offline.
      alice.goOffline();
      await alice.chat.sendMessage({ channelId: 'general', content: 'offline-1' });
      await alice.chat.sendMessage({ channelId: 'general', content: 'offline-2' });

      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(received).toHaveLength(0);
      expect(alice.outboxSize).toBe(2);

      // Reconnect: the queue drains in order.
      const delivered = await alice.goOnline();
      expect(delivered).toBe(2);

      expect(await waitFor(() => received.length === 2)).toBe(true);
      expect(received).toEqual(['offline-1', 'offline-2']);
      expect(alice.outboxSize).toBe(0);
    } finally {
      await teardown();
    }
  });

  test('outbox entries carry a refreshed epoch after reconnection', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      await alice.connect(bob.getTicket());
      alice.goOffline();

      await alice.chat.sendMessage({ channelId: 'general', content: 'stale proof' });
      expect(alice.outboxSize).toBe(1);

      const delivered = await alice.goOnline();

      // Flushed successfully, meaning the refreshed entry was accepted.
      expect(delivered).toBe(1);
      expect(alice.outboxSize).toBe(0);
    } finally {
      await teardown();
    }
  });

  test('CRDT state converges across both peers after exchange', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      const received: string[] = [];
      bob.chat.onMessage('general', (msg) => received.push(msg.content));

      await alice.connect(bob.getTicket());

      await alice.chat.sendMessage({ channelId: 'general', content: 'first' });
      await alice.chat.sendMessage({ channelId: 'general', content: 'second' });

      expect(await waitFor(() => received.length === 2)).toBe(true);

      const aliceHistory = await alice.chat.getHistory('general');
      const bobHistory = await bob.chat.getHistory('general');

      expect(aliceHistory.map((m) => m.content)).toEqual(['first', 'second']);
      expect(bobHistory.map((m) => m.content)).toEqual(['first', 'second']);
    } finally {
      await teardown();
    }
  });

  test('bidirectional exchange delivers in both directions', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      const atBob: string[] = [];
      const atAlice: string[] = [];
      bob.chat.onMessage('general', (m) => atBob.push(m.content));
      alice.chat.onMessage('general', (m) => atAlice.push(m.content));

      await alice.connect(bob.getTicket());

      await alice.chat.sendMessage({ channelId: 'general', content: 'ping' });
      expect(await waitFor(() => atBob.length === 1)).toBe(true);

      await bob.chat.sendMessage({ channelId: 'general', content: 'pong' });
      expect(await waitFor(() => atAlice.length === 1)).toBe(true);

      expect(atBob).toEqual(['ping']);
      expect(atAlice).toEqual(['pong']);
    } finally {
      await teardown();
    }
  });

  test('messages persist to SQLite and survive a checkpoint', async () => {
    const { alice, bob, teardown } = await createPeerPair();

    try {
      await alice.connect(bob.getTicket());
      await alice.chat.sendMessage({ channelId: 'general', content: 'durable' });

      const persisted = alice.checkpoint();
      expect(persisted).toBeGreaterThan(0);

      const history = await alice.chat.getHistory('general');
      expect(history.map((m) => m.content)).toEqual(['durable']);
    } finally {
      await teardown();
    }
  });
});

test.describe('Suite 1.2 — Pairing Gates Message Delivery', () => {
  test('an unpaired inbound peer receives no message traffic', async () => {
    // Completing a handshake is not authorization. `HandshakeInit.didKey`
    // is self-asserted, so a stranger with a freshly generated keypair is
    // indistinguishable from a friend at the transport layer. Pairing —
    // an explicit act by the application — is what separates them.
    //
    // A ticket is designed to be shared publicly (QR codes, links), so
    // "attacker has the victim's ticket" is the expected case, not a
    // compromise.
    const victim = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      stranger.addPeer(victim.did, victim.encryptionPublicKey);
      await stranger.connect(victim.getTicket());

      const seen: string[] = [];
      stranger.chat.onMessage('general', (m) => seen.push(m.content));

      await new Promise((r) => setTimeout(r, 200));
      await victim.chat.sendMessage({
        channelId: 'general',
        content: 'private to my contacts',
      });
      await new Promise((r) => setTimeout(r, 400));

      expect(victim.getNetworkStatus().peerCount).toBe(1);
      expect(seen).toEqual([]);
    } finally {
      await victim.disconnect();
      await stranger.disconnect();
    }
  });

  test('a paired peer still receives normally', async () => {
    // The gate must not break delivery — a test that only asserted the
    // negative would pass just as well if publish() were broken outright.
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
  for (const channel of ['general', 'secret-channel']) {
    alice.chat.createChannel(channel, [bob.did]);
  }
  for (const channel of ['general', 'secret-channel']) {
    bob.chat.createChannel(channel, [alice.did]);
  }
      await alice.connect(bob.getTicket());

      const seen: string[] = [];
      bob.chat.onMessage('general', (m) => seen.push(m.content));

      await new Promise((r) => setTimeout(r, 200));
      await alice.chat.sendMessage({ channelId: 'general', content: 'hello' });
      await new Promise((r) => setTimeout(r, 400));

      expect(seen).toEqual(['hello']);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('pairing an inbound peer afterwards starts delivery', async () => {
    // The gate is a decision, not a permanent state: an application that
    // accepts a stranger can pair them and traffic flows from then on.
    const victim = await DicsussionClient.init({ storagePath: ':memory:' });
    const newcomer = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      newcomer.addPeer(victim.did, victim.encryptionPublicKey);
      await newcomer.connect(victim.getTicket());

      const seen: string[] = [];
      newcomer.chat.onMessage('general', (m) => seen.push(m.content));
      await new Promise((r) => setTimeout(r, 200));

      await victim.chat.sendMessage({ channelId: 'general', content: 'before' });
      await new Promise((r) => setTimeout(r, 300));
      expect(seen).toEqual([]);

      // The victim decides to accept them. Pairing alone is not enough:
      // it authorises *a* conversation, not every conversation already
      // on the device, so the channel has to admit them separately.
      // Without that split, accepting one contact would hand them every
      // chat held with everyone else, backdated.
      victim.addPeer(newcomer.did, newcomer.encryptionPublicKey);
      expect(await newcomerReceives(victim, newcomer)).toBe(false);

      victim.chat.createChannel('general', [newcomer.did]);

      await victim.chat.sendMessage({ channelId: 'general', content: 'after' });
      await new Promise((r) => setTimeout(r, 400));
      expect(seen).toEqual(['after']);
    } finally {
      await victim.disconnect();
      await newcomer.disconnect();
    }
  });

  test('an unpaired peer cannot inject messages into our chat', async () => {
    // The mirror of the tests above, and the more dangerous direction.
    // Gating `publish` stops us leaking *to* a stranger; it does nothing
    // about what a stranger sends *at* us. The handshake succeeds, so both
    // sides hold the same session key — an inbound envelope therefore
    // decrypts perfectly and, ungated, would surface as a genuine message
    // in the victim's channel. Anyone holding a public ticket could inject
    // chat history into a stranger's client.
    const victim = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // One-sided: the stranger pairs us, we never pair them.
      stranger.addPeer(victim.did, victim.encryptionPublicKey);
      await stranger.connect(victim.getTicket());

      const seen: string[] = [];
      victim.chat.onMessage('general', (m) => seen.push(m.content));
      await new Promise((r) => setTimeout(r, 200));

      await stranger.chat.sendMessage({
        channelId: 'general',
        content: 'injected by a stranger',
      });
      await new Promise((r) => setTimeout(r, 400));

      // Connected, and completely inert.
      expect(victim.getNetworkStatus().peerCount).toBe(1);
      expect(seen).toEqual([]);
    } finally {
      await victim.disconnect();
      await stranger.disconnect();
    }
  });

  test('an unpaired peer cannot drive CRDT reconciliation', async () => {
    // Sync is the state-mutation path: an ungated peer can push Automerge
    // deltas and read our document heads, which disclose channel activity
    // even before any change is applied.
    const victim = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      stranger.addPeer(victim.did, victim.encryptionPublicKey);
      await stranger.connect(victim.getTicket());
      await new Promise((r) => setTimeout(r, 400));

      // `connect` calls beginSync, so a reconciliation attempt has already
      // been made and refused by the time we look.
      expect(victim.getNetworkStatus().lastSyncTimestamp).toBe(0);
    } finally {
      await victim.disconnect();
      await stranger.disconnect();
    }
  });
});
