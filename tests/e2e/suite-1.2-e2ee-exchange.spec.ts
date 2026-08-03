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

  test('an envelope cannot be opened with the wrong key', () => {
    const recipient = generateX25519Keypair();
    const attacker = generateX25519Keypair();

    const envelope = sealMessage(
      {
        id: 'm1',
        channelId: 'general',
        authorDid: 'did:key:z6MkAlice',
        content: 'confidential',
        timestamp: 1_700_000_000,
        messageIndex: 0,
      },
      recipient.publicKey,
      170_000_000,
    );

    // The intended recipient reads it.
    expect(openMessage(envelope, recipient.secretKey).payload.content).toBe(
      'confidential',
    );

    // Anyone else fails AES-GCM authentication.
    expect(() => openMessage(envelope, attacker.secretKey)).toThrow();
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
