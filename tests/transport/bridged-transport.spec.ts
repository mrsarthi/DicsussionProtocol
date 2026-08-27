/**
 * Bridged transport over a host-supplied byte pipe.
 *
 * The point of interest is chunking. `BridgePipe` promises ordered bytes
 * and nothing else, so every test here runs three times: bytes delivered
 * whole, split to one byte per call, and coalesced into as few calls as
 * possible. A transport that only works under one of those is broken —
 * and would look fine on loopback while failing on a real network.
 */

import { expect, test } from '@playwright/test';

import type {
  BridgeInbound,
  BridgePipe,
  BridgeTarget,
} from '../../packages/core/src/transport/bridge-pipe.js';
import { createBridgedTransport } from '../../packages/core/src/transport/bridged-transport.js';
import { generateKeypair } from '../../packages/core/src/transport/did-key.js';
import { publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import type { Ed25519KeyPair } from '../../packages/core/src/transport/did-key.js';
import type {
  IConnection,
  ITransport,
} from '../../packages/core/src/transport/transport-interface.js';
import type { PeerTicket } from '../../packages/core/src/transport/types.js';
import { StreamType } from '../../packages/core/src/transport/types.js';

/** How a bus hands bytes to the far side. */
type Chunking = 'whole' | 'split' | 'coalesced';

const CHUNKINGS: Chunking[] = ['whole', 'split', 'coalesced'];

/**
 * Two `BridgePipe`s wired to each other, with controllable chunking.
 *
 * Deliberately does not preserve message boundaries in any mode — that
 * is the contract the SDK must not depend on.
 */
class TestBus {
  private readonly dataHandlers = new Map<
    string,
    Set<(id: string, bytes: Uint8Array) => void>
  >();
  private readonly inboundHandlers = new Map<
    string,
    Set<(id: string, info: BridgeInbound) => void>
  >();
  private readonly closedHandlers = new Map<string, Set<(id: string) => void>>();
  private readonly pending = new Map<string, Uint8Array[]>();
  private counter = 0;

  constructor(private readonly chunking: Chunking) {}

  pipe(side: 'a' | 'b'): BridgePipe {
    const other = side === 'a' ? 'b' : 'a';
    this.dataHandlers.set(side, new Set());
    this.inboundHandlers.set(side, new Set());
    this.closedHandlers.set(side, new Set());

    return {
      addresses: async () => ({ directAddresses: ['127.0.0.1:1'] }),

      connect: async (_target: BridgeTarget) => {
        const id = `c${++this.counter}`;
        // The far side learns of the channel before any bytes arrive,
        // exactly as a host would report an accepted QUIC connection.
        queueMicrotask(() => {
          for (const handler of this.inboundHandlers.get(other) ?? []) {
            handler(id, { unverifiedTransportId: `transport-${side}` });
          }
        });
        return id;
      },

      send: async (id: string, bytes: Uint8Array) => {
        this.deliver(other, id, bytes);
      },

      onData: (handler) => {
        this.dataHandlers.get(side)!.add(handler);
        return () => this.dataHandlers.get(side)!.delete(handler);
      },

      onInbound: (handler) => {
        this.inboundHandlers.get(side)!.add(handler);
        return () => this.inboundHandlers.get(side)!.delete(handler);
      },

      onClosed: (handler) => {
        this.closedHandlers.get(side)!.add(handler);
        return () => this.closedHandlers.get(side)!.delete(handler);
      },

      disconnect: async (id: string) => {
        for (const handler of this.closedHandlers.get(other) ?? []) handler(id);
      },

      close: async () => {},
    };
  }

  private deliver(target: 'a' | 'b', id: string, bytes: Uint8Array): void {
    const handlers = this.dataHandlers.get(target)!;

    if (this.chunking === 'split') {
      // One byte at a time: every header, every length prefix, and every
      // frame boundary lands mid-call.
      for (const byte of bytes) {
        queueMicrotask(() => {
          for (const handler of handlers) handler(id, new Uint8Array([byte]));
        });
      }
      return;
    }

    if (this.chunking === 'coalesced') {
      // Hold everything written in this tick and deliver it as one blob,
      // so the last handshake message and the first frames arrive fused.
      const key = `${target}:${id}`;
      const queued = this.pending.get(key);

      if (queued) {
        queued.push(bytes);
        return;
      }

      this.pending.set(key, [bytes]);
      queueMicrotask(() => {
        const all = this.pending.get(key) ?? [];
        this.pending.delete(key);

        const total = all.reduce((n, part) => n + part.length, 0);
        const merged = new Uint8Array(total);
        let offset = 0;
        for (const part of all) {
          merged.set(part, offset);
          offset += part.length;
        }

        for (const handler of handlers) handler(id, merged);
      });
      return;
    }

    queueMicrotask(() => {
      for (const handler of handlers) handler(id, bytes);
    });
  }
}

function ticketFor(identity: Ed25519KeyPair): PeerTicket {
  return {
    didKey: publicKeyToDidKey(identity.publicKey),
    nodeId: identity.publicKey,
    directAddresses: ['127.0.0.1:1'],
    transportKey: new Uint8Array(32).fill(7),
  };
}

interface Pair {
  alice: ITransport;
  bob: ITransport;
  dialed: IConnection;
  accepted: IConnection;
}

async function connectedPair(chunking: Chunking): Promise<Pair> {
  const bus = new TestBus(chunking);
  const aliceKeys = generateKeypair();
  const bobKeys = generateKeypair();

  const alice = createBridgedTransport(bus.pipe('a'), { identity: aliceKeys });
  const bob = createBridgedTransport(bus.pipe('b'), { identity: bobKeys });

  const inbound = new Promise<IConnection>((resolve) => bob.onConnection(resolve));
  const dialed = await alice.connect(ticketFor(bobKeys));
  const accepted = await inbound;

  return { alice, bob, dialed, accepted };
}

/** Resolve with the next frame payload seen on a connection. */
function nextPayload(connection: IConnection): Promise<string> {
  return new Promise((resolve) => {
    const off = connection.onFrame((frame) => {
      off();
      resolve(new TextDecoder().decode(frame.payload));
    });
  });
}

for (const chunking of CHUNKINGS) {
  test.describe(`Bridged transport — bytes delivered ${chunking}`, () => {
    test('two peers complete the RFC 001 §5 handshake', async () => {
      const { alice, bob, dialed, accepted } = await connectedPair(chunking);

      // Each side ended up with the other's did:key, which only the
      // handshake could have established — the pipe never carried one.
      expect(dialed.peerDid).not.toBe(accepted.peerDid);
      expect(dialed.sessionKey.length).toBe(32);

      // Both derived the same session key from their ephemeral halves.
      expect(Buffer.from(dialed.sessionKey)).toEqual(
        Buffer.from(accepted.sessionKey),
      );

      await alice.close();
      await bob.close();
    });

    test('a message crosses the pipe', async () => {
      const { alice, bob, dialed, accepted } = await connectedPair(chunking);

      const arrived = nextPayload(accepted);
      await dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('hello'));

      expect(await arrived).toBe('hello');

      await alice.close();
      await bob.close();
    });

    test('traffic flows in both directions', async () => {
      const { alice, bob, dialed, accepted } = await connectedPair(chunking);

      const atBob = nextPayload(accepted);
      await dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('ping'));
      expect(await atBob).toBe('ping');

      const atAlice = nextPayload(dialed);
      await accepted.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('pong'));
      expect(await atAlice).toBe('pong');

      await alice.close();
      await bob.close();
    });

    test('frames sent immediately after the handshake are not lost', async () => {
      // The regression this file exists for: under coalescing, the ack
      // and the first frames arrive in one chunk, so a reader that waits
      // for the *next* chunk after switching modes drops them.
      const bus = new TestBus(chunking);
      const aliceKeys = generateKeypair();
      const bobKeys = generateKeypair();

      const alice = createBridgedTransport(bus.pipe('a'), { identity: aliceKeys });
      const bob = createBridgedTransport(bus.pipe('b'), { identity: bobKeys });

      const inbound = new Promise<IConnection>((resolve) => bob.onConnection(resolve));
      const dialed = await alice.connect(ticketFor(bobKeys));

      // Send without awaiting the accepter — the frame chases the ack.
      void dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('first'));

      const accepted = await inbound;
      expect(await nextPayload(accepted)).toBe('first');

      await alice.close();
      await bob.close();
    });

    test('every sub-stream multiplexes over one pipe', async () => {
      const { alice, bob, dialed, accepted } = await connectedPair(chunking);

      // Counted from StreamType, not listed: a hand-kept list silently
      // stops covering a stream type the day one is added.
      const streams = Object.values(StreamType);
      const seen = new Map<number, string>();
      const done = new Promise<void>((resolve) => {
        accepted.onFrame((frame) => {
          seen.set(frame.header.streamType, new TextDecoder().decode(frame.payload));
          if (seen.size === streams.length) resolve();
        });
      });

      for (const streamType of streams) {
        await dialed.send(streamType, new TextEncoder().encode(`s${streamType}`));
      }

      await done;
      expect(seen.get(StreamType.CRDT_SYNC)).toBe(`s${StreamType.CRDT_SYNC}`);
      expect(seen.get(StreamType.RLN_SHARE_EXCHANGE)).toBe(
        `s${StreamType.RLN_SHARE_EXCHANGE}`,
      );

      await alice.close();
      await bob.close();
    });

    test('a large payload is reassembled across reads', async () => {
      const { alice, bob, dialed, accepted } = await connectedPair(chunking);

      // Comfortably past any single-read boundary.
      const big = 'x'.repeat(chunking === 'split' ? 2_000 : 64_000);

      const arrived = nextPayload(accepted);
      await dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode(big));

      expect(await arrived).toBe(big);

      await alice.close();
      await bob.close();
    });

    test('many frames all arrive, in order', async () => {
      const { alice, bob, dialed, accepted } = await connectedPair(chunking);

      const count = chunking === 'split' ? 20 : 200;
      const received: string[] = [];

      const done = new Promise<void>((resolve) => {
        accepted.onFrame((frame) => {
          received.push(new TextDecoder().decode(frame.payload));
          if (received.length === count) resolve();
        });
      });

      for (let i = 0; i < count; i++) {
        await dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode(`m${i}`));
      }

      await done;
      expect(received).toEqual(Array.from({ length: count }, (_, i) => `m${i}`));

      await alice.close();
      await bob.close();
    });
  });
}

test.describe('Bridged transport — failure handling', () => {
  test('a ticket without a transport key is refused', async () => {
    const bus = new TestBus('whole');
    const alice = createBridgedTransport(bus.pipe('a'), {
      identity: generateKeypair(),
    });

    const ticket = ticketFor(generateKeypair());
    const { transportKey: _omitted, ...withoutKey } = ticket;

    await expect(alice.connect(withoutKey as PeerTicket)).rejects.toThrow(
      /no transport key/,
    );

    await alice.close();
  });

  test('a peer that answers with the wrong identity fails verification', async () => {
    const bus = new TestBus('whole');
    const bobKeys = generateKeypair();

    const alice = createBridgedTransport(bus.pipe('a'), {
      identity: generateKeypair(),
    });
    const bob = createBridgedTransport(bus.pipe('b'), { identity: bobKeys });

    // Dial with a ticket naming a different key than Bob actually holds.
    const impostor = { ...ticketFor(bobKeys), nodeId: generateKeypair().publicKey };

    await expect(alice.connect(impostor)).rejects.toThrow(/challenge verification/);

    await alice.close();
    await bob.close();
  });

  test('sending after close is refused', async () => {
    const { alice, bob, dialed } = await connectedPair('whole');

    await dialed.close();
    await expect(
      dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('nope')),
    ).rejects.toThrow(/Cannot send/);

    await alice.close();
    await bob.close();
  });

  test('a stalled handshake times out rather than hanging', async () => {
    // A pipe that accepts a dial and then says nothing.
    const silent: BridgePipe = {
      addresses: async () => ({ directAddresses: [] }),
      connect: async () => 'c1',
      send: async () => {},
      onData: () => () => {},
      onInbound: () => () => {},
      onClosed: () => () => {},
      disconnect: async () => {},
      close: async () => {},
    };

    const alice = createBridgedTransport(silent, {
      identity: generateKeypair(),
      timeoutMs: 200,
    });

    await expect(alice.connect(ticketFor(generateKeypair()))).rejects.toThrow(
      /stalled/,
    );

    await alice.close();
  });
});
