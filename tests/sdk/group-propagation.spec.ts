/**
 * A message must reach everyone in a conversation, not only the people
 * the sender happens to be connected to.
 *
 * Reconciliation used to run once, when a connection opened. That is
 * enough for two people and quietly wrong for three: with Bob in the
 * middle of a star, Alice and Carol never exchanged anything, so each
 * saw half the conversation while Bob saw all of it — permanently, with
 * nothing on any screen to indicate a split.
 *
 * The fix is to relay every local change onward, including changes that
 * merely arrived. That is the part a direct fan-out cannot do, because
 * the sender has no connection to the far side.
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
        const peer = this.endpointOf.get(
          Buffer.from(target.transportKey).toString('hex'),
        );
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

const GROUP = 'the-group';

/** Everyone knows everyone, and all three belong to the conversation. */
function admitAll(clients: DicsussionClient[]): void {
  for (const self of clients) {
    const others = clients.filter((c) => c !== self);
    for (const other of others) {
      self.addPeer(other.did, other.encryptionPublicKey);
    }
    self.chat.createChannel(
      GROUP,
      others.map((o) => o.did),
    );
  }
}

const contents = async (c: DicsussionClient): Promise<string[]> =>
  (await c.chat.getHistory(GROUP)).map((m) => m.content).sort();

test.describe.configure({ mode: 'serial', timeout: 90_000 });

test.describe('SDK — a message reaches the whole conversation', () => {
  test('it travels through a peer in the middle', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');
    const carol = await spawn(hub, 'carol');

    try {
      admitAll([alice, bob, carol]);

      // A star, not a mesh. Alice and Carol never connect to each other,
      // so anything between them has to pass through Bob.
      await alice.connect(bob.getTicket());
      await carol.connect(bob.getTicket());

      await alice.chat.sendMessage({ channelId: GROUP, content: 'from-alice' });

      await expect
        .poll(() => contents(carol), { timeout: 20_000 })
        .toEqual(['from-alice']);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });

  test('everyone writing at once loses nobody', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');
    const carol = await spawn(hub, 'carol');

    try {
      admitAll([alice, bob, carol]);
      await alice.connect(bob.getTicket());
      await carol.connect(bob.getTicket());

      // Simultaneous writes from every participant — the case a CRDT is
      // chosen for, and the one that silently dropped a message before
      // documents shared a genesis.
      await Promise.all([
        alice.chat.sendMessage({ channelId: GROUP, content: 'A' }),
        bob.chat.sendMessage({ channelId: GROUP, content: 'B' }),
        carol.chat.sendMessage({ channelId: GROUP, content: 'C' }),
      ]);

      for (const client of [alice, bob, carol]) {
        await expect
          .poll(() => contents(client), { timeout: 20_000 })
          .toEqual(['A', 'B', 'C']);
      }
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });

  test('everyone agrees on the order', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');
    const carol = await spawn(hub, 'carol');

    try {
      admitAll([alice, bob, carol]);
      await alice.connect(bob.getTicket());
      await carol.connect(bob.getTicket());

      await Promise.all([
        alice.chat.sendMessage({ channelId: GROUP, content: 'A' }),
        bob.chat.sendMessage({ channelId: GROUP, content: 'B' }),
        carol.chat.sendMessage({ channelId: GROUP, content: 'C' }),
      ]);

      await expect.poll(() => contents(alice), { timeout: 20_000 }).toHaveLength(3);
      await expect.poll(() => contents(carol), { timeout: 20_000 }).toHaveLength(3);

      // Convergence is not enough on its own: every replica must also
      // present the same conversation, or two people reading the same
      // group see different threads.
      const order = async (c: DicsussionClient): Promise<string[]> =>
        (await c.chat.getHistory(GROUP)).map((m) => m.content);

      expect(await order(carol)).toEqual(await order(alice));
      expect(await order(bob)).toEqual(await order(alice));
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });
});
