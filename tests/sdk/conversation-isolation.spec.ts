/**
 * A contact must not receive conversations they are not part of.
 *
 * Synchronisation used to offer every document a node held to any paired
 * peer. Pairing means "we agreed to talk", not "you may read everything
 * I have — including from before we met", so adding a second contact
 * handed them the first one's history, in readable text, with nothing on
 * either screen to say so.
 *
 * Strangers were never affected, which is what made it easy to miss: the
 * boundary that failed was the one between people you trust.
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

function pair(a: DicsussionClient, b: DicsussionClient): void {
  // Deliberately pairing only. Granting channel access here would
  // erase the distinction these tests exist to prove: being a contact
  // is not the same as belonging to a conversation.
  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
}

const settle = () => new Promise((r) => setTimeout(r, 1500));

test.describe.configure({ mode: 'serial', timeout: 90_000 });

test.describe('SDK — conversations stay with their participants', () => {
  test('an uninvolved contact never receives the conversation', async () => {
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');
    const carol = await spawn(hub, 'carol');

    try {
      // Alice pairs with Bob only, and talks to him.
      pair(alice, bob);
      await alice.connect(bob.getTicket());
      await settle();
      await alice.chat.sendMessage({
        channelId: 'alice+bob',
        content: 'SECRET-FOR-BOB',
        participants: [bob.did],
      });
      await settle();

      // Carol is added afterwards — a later, unrelated contact.
      pair(alice, carol);
      await alice.connect(carol.getTicket());
      await settle();

      expect(await bob.chat.getHistory('alice+bob')).toHaveLength(1);

      // The whole point. Carol was never in this conversation, and the
      // message predates her being added at all.
      expect(await carol.chat.getHistory('alice+bob')).toEqual([]);
      expect(carol.listDocuments?.() ?? []).not.toContain('alice+bob');
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });

  test('the intended participant still receives it', async () => {
    // The guard must not be so tight that nothing syncs — the failure
    // mode on the other side of this fix.
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');

    try {
      pair(alice, bob);
      await alice.chat.sendMessage({
        channelId: 'alice+bob',
        content: 'hello',
        participants: [bob.did],
      });

      await bob.connect(alice.getTicket());
      await settle();

      const history = await bob.chat.getHistory('alice+bob');
      expect(history.map((m) => m.content)).toEqual(['hello']);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('a peer cannot push a conversation we have no part in', async () => {
    // The mirror of the outbound filter. Adopting an uninvited document
    // both stores someone else's conversation and lets a peer mint
    // documents on this node.
    const hub = new Hub();
    const alice = await spawn(hub, 'alice');
    const bob = await spawn(hub, 'bob');

    try {
      pair(alice, bob);
      // Bob writes a conversation Alice is not part of.
      await bob.chat.sendMessage({
        channelId: 'bob+dave',
        content: 'not for alice',
        participants: ['did:key:z6MkDaveNotAlice'],
      });

      await bob.connect(alice.getTicket());
      await settle();

      expect(await alice.chat.getHistory('bob+dave')).toEqual([]);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });
});
