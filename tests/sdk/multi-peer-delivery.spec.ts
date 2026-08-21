/**
 * Three participants, which is the smallest number that finds this.
 *
 * Every earlier suite used one contact, where "is anyone connected" and
 * "can I reach my contact" are the same question. They stop being the
 * same the moment a second peer exists, or a stranger knocks — and the
 * send path asked the first while delivering on the second.
 */

import { expect, test } from '@playwright/test';

import type {
  BridgePipe,
  BridgeTarget,
} from '../../packages/core/src/transport/bridge-pipe.js';
import { createBridgedTransport } from '../../packages/core/src/transport/bridged-transport.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

/** An N-party bus; endpoints are found by their transport key. */
class Hub {
  private readonly data = new Map<string, Set<(id: string, b: Uint8Array) => void>>();
  private readonly inbound = new Map<string, Set<(id: string, i: unknown) => void>>();
  private readonly closed = new Map<string, Set<(id: string) => void>>();
  private readonly endpointOf = new Map<string, string>();
  private readonly link = new Map<string, [string, string]>();
  private counter = 0;

  pipe(name: string): BridgePipe {
    this.data.set(name, new Set());
    this.inbound.set(name, new Set());
    this.closed.set(name, new Set());

    return {
      addresses: async () => ({ directAddresses: ['127.0.0.1:1'] }),
      connect: async (target: BridgeTarget) => {
        const peer = this.endpointOf.get(Buffer.from(target.transportKey).toString('hex'));
        if (!peer) throw new Error('no such endpoint');

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
      onClosed: (h) => {
        this.closed.get(name)!.add(h);
        return () => this.closed.get(name)!.delete(h);
      },
      disconnect: async () => {},
      close: async () => {},
    };
  }

  register(name: string, transportKey: Uint8Array): void {
    this.endpointOf.set(Buffer.from(transportKey).toString('hex'), name);
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

/** Pair two clients in both directions, as any real application must. */
function pair(a: DicsussionClient, b: DicsussionClient): void {
  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
}

test.describe('SDK — delivery with more than one peer', () => {
  test('a stranger connecting does not make the node look reachable', async () => {
    // The sharp case. Mallory pairs with nobody and simply dials. That
    // alone used to flip `connected` to true, so a message meant for an
    // offline contact was published to zero peers, resolved as success,
    // and never queued.
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');
    const mallory = await spawn(hub, 'mallory');

    try {
      pair(alice, bob); // Bob is a contact, but never connects.

      await mallory.connect(alice.getTicket());
      await expect
        .poll(() => alice.getNetworkStatus().peerCount, { timeout: 10_000 })
        .toBeGreaterThan(0);

      // A socket exists, but not one this node may send on.
      expect(alice.getNetworkStatus().connected).toBe(false);

      await alice.chat.sendMessage({ channelId: 'general', content: 'for bob' });
      expect(alice.outboxSize).toBe(1);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), mallory.disconnect()]);
    }
  });

  test('a message reaching one contact still queues for the absent one', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');
    const carol = await spawn(hub, 'carol');

    try {
      pair(alice, bob);
      pair(alice, carol);
      await alice.connect(carol.getTicket()); // Carol on, Bob off.

      const carolSaw: string[] = [];
      carol.chat.onMessage('general', (m) => carolSaw.push(m.content));

      await alice.chat.sendMessage({ channelId: 'general', content: 'party at 8' });
      await expect.poll(() => carolSaw, { timeout: 10_000 }).toEqual(['party at 8']);

      // Bob is absent. He converges when he returns — see below — so the
      // message is not lost, but nothing has reached him yet.
      expect(await bob.chat.getHistory('general')).toEqual([]);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });

  test('a message delivered by sync reaches onMessage, once', async () => {
    // The bug behind the report. Sync merges into the document and used
    // to notify nobody, so an application appending on the event saw
    // nothing — indistinguishable from loss, though the data was there.
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');

    try {
      pair(alice, bob);

      // Sent while Bob is away, so it can only arrive by sync.
      await alice.chat.sendMessage({ channelId: 'general', content: 'while you were out' });

      const bobSaw: string[] = [];
      bob.chat.onMessage('general', (m) => bobSaw.push(m.content));

      await bob.connect(alice.getTicket());
      await expect
        .poll(() => bobSaw, { timeout: 20_000 })
        .toEqual(['while you were out']);

      // A later sync re-applies the same document. De-duplication is by
      // message id, so the listener must not fire again.
      await alice.chat.sendMessage({ channelId: 'general', content: 'second' });
      await expect
        .poll(() => bobSaw, { timeout: 20_000 })
        .toEqual(['while you were out', 'second']);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });
});
