/**
 * Wiring a host-supplied transport into a real `DicsussionClient`.
 *
 * `createBridgedTransport` needs the node's Ed25519 keypair, and that is
 * derived inside `init()` from a seed the caller never holds. Passing a
 * ready-made `ITransport` therefore cannot work for any transport that
 * authenticates as the node — which is all of them. The factory form
 * exists to close that gap, and this asserts it end to end: two clients,
 * a bridge between them, and a message that arrives.
 */

import { expect, test } from '@playwright/test';

import type {
  BridgeInbound,
  BridgePipe,
  BridgeTarget,
} from '../../packages/core/src/transport/bridge-pipe.js';
import { createBridgedTransport } from '../../packages/core/src/transport/bridged-transport.js';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

/** Two pipes wired to each other, delivering one byte per call. */
class TestBus {
  private readonly data = new Map<
    string,
    Set<(id: string, bytes: Uint8Array) => void>
  >();
  private readonly inbound = new Map<
    string,
    Set<(id: string, info: BridgeInbound) => void>
  >();

  pipe(side: 'a' | 'b'): BridgePipe {
    const other = side === 'a' ? 'b' : 'a';
    this.data.set(side, new Set());
    this.inbound.set(side, new Set());

    return {
      addresses: async () => ({ directAddresses: ['127.0.0.1:1'] }),

      connect: async (_target: BridgeTarget) => {
        queueMicrotask(() => {
          for (const handler of this.inbound.get(other) ?? []) {
            handler('conn', { unverifiedTransportId: side });
          }
        });
        return 'conn';
      },
      // Hostile on purpose: the contract promises ordering, not
      // boundaries, and the handshake has to survive that.
      send: async (id, bytes) => {
        for (const byte of bytes) {
          queueMicrotask(() => {
            for (const handler of this.data.get(other) ?? []) {
              handler(id, new Uint8Array([byte]));
            }
          });
        }
      },
      onData: (handler) => {
        this.data.get(side)!.add(handler);
        return () => this.data.get(side)!.delete(handler);
      },
      onInbound: (handler) => {
        this.inbound.get(side)!.add(handler);
        return () => this.inbound.get(side)!.delete(handler);
      },
      onClosed: () => () => {},
      disconnect: async () => {},
      close: async () => {},
    };
  }
}

test.describe('SDK — bridged transport through DicsussionClient', () => {
  test('a transport factory receives the derived identity and carries traffic', async () => {
    const bus = new TestBus();

    // The factory form: the client hands back the identity it derived,
    // which is the only way the transport can authenticate as this node.
    const alice = await DicsussionClient.init(
      { storagePath: ':memory:' },
      { transport: (identity) => createBridgedTransport(bus.pipe('a'), { identity }) },
    );
    const bob = await DicsussionClient.init(
      { storagePath: ':memory:' },
      { transport: (identity) => createBridgedTransport(bus.pipe('b'), { identity }) },
    );

    try {
      const received: string[] = [];
      bob.chat.onMessage('general', (message) => {
        received.push(message.content);
      });

      // Pair from tickets, both ways, then dial once — the same shape
      // any real application uses.
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
  for (const channel of ['general']) {
    alice.chat.createChannel(channel, [bob.did]);
  }
  for (const channel of ['general']) {
    bob.chat.createChannel(channel, [alice.did]);
  }

      await alice.connect(bob.getTicket());
      await alice.chat.sendMessage({ channelId: 'general', content: 'bridged' });

      await expect
        .poll(() => received.length, { timeout: 15_000 })
        .toBeGreaterThan(0);

      expect(received[0]).toBe('bridged');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the ticket advertises a transport key derived from the identity', async () => {
    // A transport that minted its own key would publish an address no
    // peer could dial, and it would look like a network fault.
    const bus = new TestBus();
    let seen: Uint8Array | null = null;

    const client = await DicsussionClient.init(
      { storagePath: ':memory:' },
      {
        transport: (identity) => {
          seen = identity.publicKey;
          return createBridgedTransport(bus.pipe('a'), { identity });
        },
      },
    );

    try {
      expect(seen).not.toBeNull();
      // The ticket's nodeId is the identity public key the factory saw.
      expect(Buffer.from(client.getTicket().nodeId)).toEqual(
        Buffer.from(seen!),
      );
    } finally {
      await client.disconnect();
    }
  });
});
