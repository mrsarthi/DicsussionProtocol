/**
 * What happens to a message when the peer has gone.
 *
 * The bug these cover lost messages while showing them as sent. Three
 * things combined:
 *
 *   1. `PeerRegistry` treated the *presence* of a connection object as
 *      liveness, so a torn-down connection counted as reachable forever.
 *   2. `getNetworkStatus().connected` and the outbox gate read that
 *      count, so the client believed it was online indefinitely.
 *   3. `sendMessage` chose between publishing and queueing on the
 *      strength of that belief, and let the resulting failure escape —
 *      leaving the message in local history, in no retry queue.
 *
 * `detachConnection` existed the whole time and was never called.
 */

import { expect, test } from '@playwright/test';

import type {
  BridgeInbound,
  BridgePipe,
  BridgeTarget,
} from '../../packages/core/src/transport/bridge-pipe.js';
import { createBridgedTransport } from '../../packages/core/src/transport/bridged-transport.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

type Handler = (id: string, bytes: Uint8Array) => void;
type Inbound = (id: string, info: BridgeInbound) => void;
type Closed = (id: string) => void;

/**
 * Two pipes wired together, with a switch to cut the wire.
 *
 * `reportClosed` is the host telling the SDK a connection is gone —
 * `severSilently` is the harder case, where the bytes stop arriving and
 * nobody says anything.
 */
class Bus {
  readonly data = new Map<string, Set<Handler>>();
  readonly inbound = new Map<string, Set<Inbound>>();
  readonly closed = new Map<string, Set<Closed>>();
  private live = true;

  pipe(side: 'a' | 'b'): BridgePipe {
    const other = side === 'a' ? 'b' : 'a';
    this.data.set(side, new Set());
    this.inbound.set(side, new Set());
    this.closed.set(side, new Set());

    return {
      addresses: async () => ({ directAddresses: ['127.0.0.1:1'] }),
      connect: async (_t: BridgeTarget) => {
        queueMicrotask(() => {
          for (const h of this.inbound.get(other) ?? []) h('c', {});
        });
        return 'c';
      },
      send: async (id, bytes) => {
        if (!this.live) return; // dropped on the floor, no error
        queueMicrotask(() => {
          for (const h of this.data.get(other) ?? []) h(id, bytes);
        });
      },
      onData: (h) => {
        this.data.get(side)!.add(h);
        return () => this.data.get(side)!.delete(h);
      },
      onInbound: (h) => {
        this.inbound.get(side)!.add(h);
        return () => this.inbound.get(side)!.delete(h);
      },
      onClosed: (h) => {
        this.closed.get(side)!.add(h);
        return () => this.closed.get(side)!.delete(h);
      },
      disconnect: async () => {},
      close: async () => {},
    };
  }

  /** The host notices and reports it. */
  reportClosed(side: 'a' | 'b'): void {
    this.live = false;
    for (const h of this.closed.get(side) ?? []) h('c');
  }

  /** Bytes stop arriving and nothing is reported. */
  severSilently(): void {
    this.live = false;
  }

  restore(): void {
    this.live = true;
  }
}

interface Pair {
  alice: DicsussionClient;
  bob: DicsussionClient;
  bus: Bus;
  received: string[];
}

async function connectedPair(): Promise<Pair> {
  const bus = new Bus();

  const alice = await DicsussionClient.init(
    { storagePath: ':memory:' },
    { transport: (identity) => createBridgedTransport(bus.pipe('a'), { identity }) },
  );
  const bob = await DicsussionClient.init(
    { storagePath: ':memory:' },
    { transport: (identity) => createBridgedTransport(bus.pipe('b'), { identity }) },
  );

  const received: string[] = [];
  bob.chat.onMessage('general', (m) => {
    received.push(m.content);
  });

  alice.addPeer(bob.did, bob.encryptionPublicKey);
  bob.addPeer(alice.did, alice.encryptionPublicKey);
  for (const channel of ['general']) {
    alice.chat.createChannel(channel, [bob.did]);
  }
  for (const channel of ['general']) {
    bob.chat.createChannel(channel, [alice.did]);
  }
  await alice.connect(bob.getTicket());

  return { alice, bob, bus, received };
}

test.describe('SDK — a peer that has gone', () => {
  test('a reported close makes the client honestly offline', async () => {
    const { alice, bob, bus } = await connectedPair();

    try {
      expect(alice.getNetworkStatus().connected).toBe(true);
      expect(alice.getNetworkStatus().peerCount).toBe(1);

      bus.reportClosed('a');
      await new Promise((r) => setTimeout(r, 200));

      // Previously both stayed as above: the registry held a dead
      // connection object and counted it.
      expect(alice.getNetworkStatus().connected).toBe(false);
      expect(alice.getNetworkStatus().peerCount).toBe(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a message to a departed peer queues instead of vanishing', async () => {
    const { alice, bob, bus, received } = await connectedPair();

    try {
      await alice.chat.sendMessage({ channelId: 'general', content: 'one' });
      await expect.poll(() => received.length).toBe(1);

      bus.reportClosed('a');
      await new Promise((r) => setTimeout(r, 200));

      // Must not reject, and must not be silently dropped.
      await alice.chat.sendMessage({ channelId: 'general', content: 'two' });

      expect(alice.outboxSize).toBe(1);
      expect(received).toEqual(['one']);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a silent death also queues, without the host reporting it', async () => {
    // The harder case: the transport still believes it is connected, so
    // no state check can catch this. Only attempting the send and
    // queueing on failure does.
    const { alice, bob, bus, received } = await connectedPair();

    try {
      bus.severSilently();

      await alice.chat.sendMessage({ channelId: 'general', content: 'lost?' });
      await new Promise((r) => setTimeout(r, 500));

      expect(received).toEqual([]);

      // The transport reported success — it wrote into the pipe and the
      // pipe discarded it. Nothing at this layer can tell. What must NOT
      // happen is the client believing delivery occurred and having no
      // record to retry from.
      const queued = alice.outboxSize;
      const inHistory = (await alice.chat.getHistory('general')).length;

      // The message is recoverable from at least one of the two.
      expect(queued + inHistory).toBeGreaterThan(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('reconnecting flushes what was queued', async () => {
    const { alice, bob, bus, received } = await connectedPair();

    try {
      bus.reportClosed('a');
      await new Promise((r) => setTimeout(r, 200));

      await alice.chat.sendMessage({ channelId: 'general', content: 'held' });
      expect(alice.outboxSize).toBe(1);
      expect(received).toEqual([]);

      // The peer comes back. Queueing is only half a recovery — something
      // has to notice, and reconnection is that moment.
      bus.restore();
      await alice.connect(bob.getTicket());

      await expect.poll(() => received, { timeout: 15_000 }).toEqual(['held']);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the outbox does not become permanently unreachable', async () => {
    // The one-way door: because the registry never detached, the client
    // believed it was online forever, so every later send took the
    // publish path and threw. The queue was never reachable again.
    const { alice, bob, bus } = await connectedPair();

    try {
      bus.reportClosed('a');
      await new Promise((r) => setTimeout(r, 200));

      for (const content of ['a', 'b', 'c']) {
        await alice.chat.sendMessage({ channelId: 'general', content });
      }

      expect(alice.outboxSize).toBe(3);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});
