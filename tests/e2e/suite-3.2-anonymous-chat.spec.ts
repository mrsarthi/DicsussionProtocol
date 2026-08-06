/**
 * Phase 3B — Test Suite 3.2: End-to-End Anonymous Chat
 *
 * Three headless peers exchange anonymous messages. Verifies that a
 * message carries an RLN `nullifierHash` in place of an `authorDid`, is
 * ingested by every peer, and that nothing on the wire or in local
 * storage attributes it to its sender.
 */

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { StreamType } from '../../packages/core/src/transport/types.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import type { SdkChatMessage } from '../../packages/HLessEnd/src/types.js';

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 5_000,
  pollMs = 10,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return predicate();
}

/** Three fully-meshed peers, each knowing the others' encryption keys. */
async function createMesh(): Promise<{
  nodes: DicsussionClient[];
  teardown: () => Promise<void>;
}> {
  const nodes = await Promise.all([
    DicsussionClient.init({ storagePath: ':memory:' }),
    DicsussionClient.init({ storagePath: ':memory:' }),
    DicsussionClient.init({ storagePath: ':memory:' }),
  ]);

  // Out-of-band pairing across the full mesh.
  for (const self of nodes) {
    for (const other of nodes) {
      if (self !== other) self.addPeer(other.did, other.encryptionPublicKey);
    }
  }

  // Dial A→B, A→C, B→C so every pair has one connection.
  await nodes[0]!.connect(nodes[1]!.getTicket());
  await nodes[0]!.connect(nodes[2]!.getTicket());
  await nodes[1]!.connect(nodes[2]!.getTicket());

  await waitFor(() => nodes.every((n) => n.getNetworkStatus().peerCount === 2));

  return {
    nodes,
    teardown: async () => {
      await Promise.all(nodes.map((n) => n.disconnect()));
      clearTransportRegistry();
    },
  };
}

test.describe('Suite 3.2 — End-to-End Anonymous Chat', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('an anonymous message carries a nullifier instead of an author', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const message = await client.chat.sendMessage({
        channelId: 'anon',
        content: 'who said that',
        anonymous: true,
      });

      // RFC 003 §4.1: author_did NULL, nullifier_hash present.
      expect(message.authorDid).toBeUndefined();
      expect(message.nullifierHash).toBeDefined();
      expect(message.nullifierHash).toMatch(/^0x[0-9a-f]{64}$/);
    } finally {
      await client.disconnect();
    }
  });

  test('an attributed message carries an author and no nullifier', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const message = await client.chat.sendMessage({
        channelId: 'general',
        content: 'attributed',
      });

      // The two identifiers are mutually exclusive — carrying both would
      // defeat the anonymity the nullifier exists to provide.
      expect(message.authorDid).toBe(client.did);
      expect(message.nullifierHash).toBeUndefined();
    } finally {
      await client.disconnect();
    }
  });

  test('three peers all ingest an anonymous message', async () => {
    const { nodes, teardown } = await createMesh();

    try {
      const [alice, bob, carol] = nodes as [
        DicsussionClient,
        DicsussionClient,
        DicsussionClient,
      ];

      const atBob: SdkChatMessage[] = [];
      const atCarol: SdkChatMessage[] = [];
      bob.chat.onMessage('anon', (m) => atBob.push(m));
      carol.chat.onMessage('anon', (m) => atCarol.push(m));

      const sent = await alice.chat.sendMessage({
        channelId: 'anon',
        content: 'anonymous broadcast',
        anonymous: true,
      });

      expect(await waitFor(() => atBob.length === 1 && atCarol.length === 1)).toBe(
        true,
      );

      for (const received of [atBob[0]!, atCarol[0]!]) {
        expect(received.content).toBe('anonymous broadcast');
        expect(received.nullifierHash).toBe(sent.nullifierHash);
        // Neither recipient can tell who sent it.
        expect(received.authorDid).toBeUndefined();
      }
    } finally {
      await teardown();
    }
  });

  test('recipients cannot attribute an anonymous message to any peer', async () => {
    const { nodes, teardown } = await createMesh();

    try {
      const [alice, bob] = nodes as [DicsussionClient, DicsussionClient, DicsussionClient];

      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('anon', (m) => received.push(m));

      await alice.chat.sendMessage({
        channelId: 'anon',
        content: 'untraceable',
        anonymous: true,
      });

      expect(await waitFor(() => received.length === 1)).toBe(true);

      const serialised = JSON.stringify(received[0]);
      for (const node of nodes) {
        expect(serialised).not.toContain(node.did);
      }
    } finally {
      await teardown();
    }
  });

  test('the wire ciphertext leaks neither the sender nor the nullifier', async () => {
    // A dedicated pair, so the observed connection is the same one the
    // sender publishes over.
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);

      const frames: Uint8Array[] = [];
      const connection = await bob.connect(alice.getTicket());
      connection.onFrame((frame) => {
        if (frame.header.streamType === StreamType.E2EE_MESSAGE) {
          frames.push(frame.payload.slice());
        }
      });

      // The responder learns of the inbound connection asynchronously.
      expect(await waitFor(() => alice.getNetworkStatus().peerCount === 1)).toBe(true);

      const sent = await alice.chat.sendMessage({
        channelId: 'anon',
        content: 'SECRET ANON PAYLOAD',
        anonymous: true,
      });

      expect(await waitFor(() => frames.length >= 1)).toBe(true);

      const wire = Buffer.from(frames[0]!).toString('latin1');
      expect(wire).not.toContain('SECRET ANON PAYLOAD');
      expect(wire).not.toContain(alice.did);
      // The nullifier travels inside the AES-GCM ciphertext, not the header.
      expect(wire).not.toContain(sent.nullifierHash!.slice(2, 32));
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      clearTransportRegistry();
    }
  });

  test('anonymous and attributed messages coexist in one channel', async () => {
    const { nodes, teardown } = await createMesh();

    try {
      const [alice, bob] = nodes as [DicsussionClient, DicsussionClient, DicsussionClient];

      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('mixed', (m) => received.push(m));

      await alice.chat.sendMessage({ channelId: 'mixed', content: 'signed' });
      await alice.chat.sendMessage({
        channelId: 'mixed',
        content: 'unsigned',
        anonymous: true,
      });

      expect(await waitFor(() => received.length === 2)).toBe(true);

      const signed = received.find((m) => m.content === 'signed')!;
      const unsigned = received.find((m) => m.content === 'unsigned')!;

      expect(signed.authorDid).toBe(alice.did);
      expect(signed.nullifierHash).toBeUndefined();
      expect(unsigned.authorDid).toBeUndefined();
      expect(unsigned.nullifierHash).toBeDefined();
    } finally {
      await teardown();
    }
  });

  test('successive anonymous messages use distinct nullifiers', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const first = await client.chat.sendMessage({
        channelId: 'anon',
        content: 'one',
        anonymous: true,
      });
      const second = await client.chat.sendMessage({
        channelId: 'anon',
        content: 'two',
        anonymous: true,
      });

      // Reusing a nullifier within an epoch is exactly what surrenders
      // the sender's secret, so honest sends must never collide.
      expect(first.nullifierHash).not.toBe(second.nullifierHash);
    } finally {
      await client.disconnect();
    }
  });

  test('anonymous history survives and stays unattributed locally', async () => {
    const { nodes, teardown } = await createMesh();

    try {
      const [alice, bob] = nodes as [DicsussionClient, DicsussionClient, DicsussionClient];

      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('anon', (m) => received.push(m));

      await alice.chat.sendMessage({
        channelId: 'anon',
        content: 'persisted anonymously',
        anonymous: true,
      });

      expect(await waitFor(() => received.length === 1)).toBe(true);

      const history = await bob.chat.getHistory('anon');
      expect(history).toHaveLength(1);
      expect(history[0]!.content).toBe('persisted anonymously');
      expect(history[0]!.authorDid).toBeUndefined();
      expect(history[0]!.nullifierHash).toBeDefined();
    } finally {
      await teardown();
    }
  });

  test('CRDT state converges across all three peers', async () => {
    const { nodes, teardown } = await createMesh();

    try {
      const [alice, bob, carol] = nodes as [
        DicsussionClient,
        DicsussionClient,
        DicsussionClient,
      ];

      const seen = [0, 0, 0];
      bob.chat.onMessage('anon', () => seen[1]!++);
      carol.chat.onMessage('anon', () => seen[2]!++);

      await alice.chat.sendMessage({ channelId: 'anon', content: 'a', anonymous: true });
      await alice.chat.sendMessage({ channelId: 'anon', content: 'b', anonymous: true });

      expect(await waitFor(() => seen[1] === 2 && seen[2] === 2)).toBe(true);

      const histories = await Promise.all(
        nodes.map((n) => n.chat.getHistory('anon')),
      );

      for (const history of histories) {
        expect(history.map((m) => m.content)).toEqual(['a', 'b']);
      }
    } finally {
      await teardown();
    }
  });
});
