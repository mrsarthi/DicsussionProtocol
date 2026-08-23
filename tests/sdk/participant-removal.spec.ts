/**
 * Removing someone from a conversation.
 *
 * Blocking in an application is a local decision; on its own it does not
 * reach the protocol, so a blocked peer keeps receiving new messages and
 * keeps being able to write into shared documents — CRDT changes are not
 * individually authenticated.
 *
 * Removal closes both directions. What it deliberately does *not* do is
 * undo the past: whatever the peer already received is on their device,
 * and these tests assert that honestly rather than pretending otherwise.
 */

import { expect, test } from '@playwright/test';

import type {
  BridgePipe,
  BridgeTarget,
} from '../../packages/core/src/transport/bridge-pipe.js';
import { createBridgedTransport } from '../../packages/core/src/transport/bridged-transport.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

class Hub {
  private readonly data = new Map<string, Set<(id: string, b: Uint8Array) => void>>();
  private readonly inbound = new Map<string, Set<(id: string, i: unknown) => void>>();
  private readonly endpointOf = new Map<string, string>();
  private readonly link = new Map<string, [string, string]>();
  private counter = 0;

  pipe(name: string): BridgePipe {
    this.data.set(name, new Set());
    this.inbound.set(name, new Set());

    return {
      addresses: async () => ({ directAddresses: ['127.0.0.1:1'] }),
      connect: async (target: BridgeTarget) => {
        const peer = this.endpointOf.get(
          Buffer.from(target.transportKey).toString('hex'),
        )!;
        const id = `c${++this.counter}`;
        this.link.set(id, [name, peer]);
        queueMicrotask(() => {
          for (const h of this.inbound.get(peer)!) h(id, {});
        });
        return id;
      },
      send: async (id, bytes) => {
        const pair = this.link.get(id);
        if (!pair) return;
        const other = pair[0] === name ? pair[1] : pair[0];
        queueMicrotask(() => {
          for (const h of this.data.get(other)!) h(id, bytes);
        });
      },
      onData: (h) => {
        this.data.get(name)!.add(h);
        return () => this.data.get(name)!.delete(h);
      },
      onInbound: (h) => {
        this.inbound.get(name)!.add(h);
        return () => this.inbound.get(name)!.delete(h);
      },
      onClosed: () => () => {},
      disconnect: async () => {},
      close: async () => {},
    };
  }

  register(name: string, key: Uint8Array): void {
    this.endpointOf.set(Buffer.from(key).toString('hex'), name);
  }
}

async function spawn(hub: Hub, name: string): Promise<DicsussionClient> {
  const client = await DicsussionClient.init(
    { storagePath: ':memory:' },
    { transport: (identity) => createBridgedTransport(hub.pipe(name), { identity }) },
  );
  hub.register(name, client.getTicket().transportKey!);
  return client;
}

const settle = () => new Promise((r) => setTimeout(r, 1200));
const history = async (c: DicsussionClient): Promise<string[]> =>
  (await c.chat.getHistory('room')).map((m) => m.content);

test.describe.configure({ mode: 'serial', timeout: 90_000 });

test.describe('SDK — removing a participant', () => {
  test('they stop receiving new messages', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
      alice.chat.createChannel('room', [bob.did]);
      bob.chat.createChannel('room', [alice.did]);
      await alice.connect(bob.getTicket());

      await alice.chat.sendMessage({ channelId: 'room', content: 'before' });
      await expect.poll(() => history(bob), { timeout: 15_000 }).toEqual(['before']);

      expect(alice.chat.removeParticipant('room', bob.did)).toBe(true);

      await alice.chat.sendMessage({ channelId: 'room', content: 'after' });
      await settle();

      // "before" remains — it was already delivered and cannot be recalled.
      expect(await history(bob)).toEqual(['before']);
      expect(await history(alice)).toEqual(['before', 'after']);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('their writes are no longer accepted', async () => {
    // The half a local block cannot achieve. CRDT changes are not
    // individually authenticated, so a peer still on the list can write
    // into the shared document however the application feels about them.
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
      alice.chat.createChannel('room', [bob.did]);
      bob.chat.createChannel('room', [alice.did]);
      await alice.connect(bob.getTicket());
      await settle();

      alice.chat.removeParticipant('room', bob.did);

      await bob.chat.sendMessage({ channelId: 'room', content: 'let me in' });
      await settle();

      expect(await history(alice)).toEqual([]);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('removal reports whether they were there, and is idempotent', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');

    try {
      alice.chat.createChannel('room', [bob.did]);

      expect(alice.chat.removeParticipant('room', bob.did)).toBe(true);
      expect(alice.chat.removeParticipant('room', bob.did)).toBe(false);
      expect(alice.chat.removeParticipant('room', 'did:key:z6MkNobody')).toBe(false);

      // Re-admitting works, so a block can be reversed.
      alice.chat.createChannel('room', [bob.did]);
      expect(alice.chat.removeParticipant('room', bob.did)).toBe(true);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });
});
