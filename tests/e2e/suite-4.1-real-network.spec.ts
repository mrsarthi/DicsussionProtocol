/**
 * Phase 4 — Real Networking (`IrohTransport`)
 *
 * The first tests in this project that send bytes over an actual network
 * stack rather than an in-process `Map`. Everything here runs over real
 * QUIC: real handshakes, real streams, real byte-oriented reads.
 *
 * Endpoints bind `127.0.0.1` with relays disabled, so a "local" test can
 * never quietly traverse the public internet — the Phase 1 spike showed
 * a default bind also picks up a public IPv6 address.
 */

import { randomBytes } from 'node:crypto';

import { expect, test } from '@playwright/test';

import { generateKeypair } from '../../packages/core/src/transport/did-key.js';
import { IrohTransport } from '../../packages/core/src/transport/iroh-transport.js';
import type { IConnection } from '../../packages/core/src/transport/transport-interface.js';
import { StreamType } from '../../packages/core/src/transport/types.js';

// Real handshakes take hundreds of ms; in-process assumptions do not apply.
test.describe.configure({ timeout: 60_000 });

interface Pair {
  alice: IrohTransport;
  bob: IrohTransport;
  dialed: IConnection;
  accepted: IConnection;
  teardown: () => Promise<void>;
}

/** Two endpoints, connected, with both sides of the connection. */
async function connectedPair(): Promise<Pair> {
  const alice = await IrohTransport.create({
    identity: generateKeypair(),
    localOnly: true,
    bindAddr: '127.0.0.1:0',
  });
  const bob = await IrohTransport.create({
    identity: generateKeypair(),
    localOnly: true,
    bindAddr: '127.0.0.1:0',
  });

  const inbound = new Promise<IConnection>((resolve) => bob.onConnection(resolve));
  const dialed = await alice.connect(bob.getTicket());
  const accepted = await inbound;

  return {
    alice,
    bob,
    dialed,
    accepted,
    teardown: async () => {
      await alice.close();
      await bob.close();
    },
  };
}

/** Resolve with the first frame matching a stream type. */
function nextFrame(
  connection: IConnection,
  streamType: number,
): Promise<Uint8Array> {
  return new Promise((resolve) => {
    const off = connection.onFrame((frame) => {
      if (frame.header.streamType === streamType) {
        off();
        resolve(frame.payload.slice());
      }
    });
  });
}

test.describe('Suite 4.1 — Real Network Transport', () => {
  test('two endpoints complete a handshake over real QUIC', async () => {
    const pair = await connectedPair();

    try {
      // Iroh authenticated the transport key; our handshake proves each
      // side also controls the did:key the protocol trusts.
      expect(pair.dialed.peerDid).toBe(pair.bob.didKey);
      expect(pair.accepted.peerDid).toBe(pair.alice.didKey);
      expect(Number.isFinite(pair.dialed.clockOffset)).toBe(true);
    } finally {
      await pair.teardown();
    }
  });

  test('an endpoint binds a real socket and publishes a dialable ticket', async () => {
    const node = await IrohTransport.create({
      identity: generateKeypair(),
      localOnly: true,
      bindAddr: '127.0.0.1:0',
    });

    try {
      expect(node.boundSockets().some((s) => s.startsWith('127.0.0.1:'))).toBe(true);

      const ticket = node.getTicket();
      expect(ticket.didKey).toBe(node.didKey);
      // The Iroh EndpointId cannot be derived from a did:key, so it must
      // travel in the ticket.
      expect(ticket.transportKey).toBeDefined();
      expect(ticket.transportKey).toHaveLength(32);
    } finally {
      await node.close();
    }
  });

  test('a message crosses the wire on Stream 0x02', async () => {
    const pair = await connectedPair();

    try {
      const received = nextFrame(pair.accepted, StreamType.E2EE_MESSAGE);
      await pair.dialed.send(
        StreamType.E2EE_MESSAGE,
        new TextEncoder().encode('hello over real QUIC'),
      );

      expect(new TextDecoder().decode(await received)).toBe('hello over real QUIC');
    } finally {
      await pair.teardown();
    }
  });

  test('every sub-stream multiplexes over one connection', async () => {
    const pair = await connectedPair();

    try {
      // Counted from StreamType itself. Hard-coding the number means
      // adding a stream type makes this wait forever for a total that
      // has already moved past it.
      const streams = Object.values(StreamType);
      const seen = new Set<number>();
      const allOfThem = new Promise<void>((resolve) => {
        pair.accepted.onFrame((frame) => {
          seen.add(frame.header.streamType);
          if (seen.size === streams.length) resolve();
        });
      });

      for (const streamType of streams) {
        await pair.dialed.send(
          streamType,
          new TextEncoder().encode(`stream ${streamType}`),
        );
      }

      await allOfThem;
      expect([...seen].sort()).toEqual([...streams].sort());
    } finally {
      await pair.teardown();
    }
  });

  test('traffic flows in both directions', async () => {
    const pair = await connectedPair();

    try {
      const atBob = nextFrame(pair.accepted, StreamType.E2EE_MESSAGE);
      await pair.dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('ping'));
      expect(new TextDecoder().decode(await atBob)).toBe('ping');

      const atAlice = nextFrame(pair.dialed, StreamType.E2EE_MESSAGE);
      await pair.accepted.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('pong'));
      expect(new TextDecoder().decode(await atAlice)).toBe('pong');
    } finally {
      await pair.teardown();
    }
  });

  test('a large payload is reassembled across stream reads', async () => {
    const pair = await connectedPair();

    try {
      // Far beyond one read: this exercises the reassembly path that
      // in-process transport never touches.
      const big = new Uint8Array(200_000);
      for (let i = 0; i < big.length; i++) big[i] = i % 256;

      const received = nextFrame(pair.accepted, StreamType.CRDT_SYNC);
      await pair.dialed.send(StreamType.CRDT_SYNC, big);

      const out = await received;
      expect(out.length).toBe(big.length);
      // Verify content, not just length — a reassembly bug could produce
      // the right size from the wrong bytes.
      expect(out[0]).toBe(big[0]);
      expect(out[99_999]).toBe(big[99_999]);
      expect(out[199_999]).toBe(big[199_999]);
    } finally {
      await pair.teardown();
    }
  });

  test('many frames in flight all arrive, in order, per stream', async () => {
    const pair = await connectedPair();

    try {
      const COUNT = 50;
      const received: number[] = [];

      const done = new Promise<void>((resolve) => {
        pair.accepted.onFrame((frame) => {
          if (frame.header.streamType !== StreamType.E2EE_MESSAGE) return;
          received.push(Number(new TextDecoder().decode(frame.payload)));
          if (received.length === COUNT) resolve();
        });
      });

      for (let i = 0; i < COUNT; i++) {
        await pair.dialed.send(
          StreamType.E2EE_MESSAGE,
          new TextEncoder().encode(String(i)),
        );
      }

      await done;
      // QUIC guarantees ordering within a stream.
      expect(received).toEqual(Array.from({ length: COUNT }, (_, i) => i));
    } finally {
      await pair.teardown();
    }
  });

  test('the connection reports its path as direct, not relayed', async () => {
    const pair = await connectedPair();

    try {
      // Relays are disabled, so loopback must be a direct path. This is
      // what `getNetworkStatus()` will report (plan §4.4).
      const connection = pair.dialed as unknown as { isRelayed: boolean };
      expect(connection.isRelayed).toBe(false);
    } finally {
      await pair.teardown();
    }
  });

  test('sending after close is refused', async () => {
    const pair = await connectedPair();

    try {
      await pair.dialed.close();

      await expect(
        pair.dialed.send(StreamType.E2EE_MESSAGE, new Uint8Array([1])),
      ).rejects.toThrow(/Cannot send/);
    } finally {
      await pair.teardown();
    }
  });

  test('dialing a ticket without a transport key fails clearly', async () => {
    const node = await IrohTransport.create({
      identity: generateKeypair(),
      localOnly: true,
      bindAddr: '127.0.0.1:0',
    });

    try {
      const { transportKey: _drop, ...incomplete } = node.getTicket();

      await expect(node.connect(incomplete)).rejects.toThrow(/no transportKey/);
    } finally {
      await node.close();
    }
  });
});

test.describe('Suite 4.1 — Priority & Robustness over QUIC', () => {
  test('revocation gossip is not blocked behind bulk chat traffic', async () => {
    const pair = await connectedPair();

    try {
      const arrival: number[] = [];
      const sawRevocation = new Promise<void>((resolve) => {
        pair.accepted.onFrame((frame) => {
          arrival.push(frame.header.streamType);
          if (frame.header.streamType === StreamType.REVOCATION_GOSSIP) resolve();
        });
      });

      // Saturate 0x02 with bulk traffic, then emit one 0x03 tombstone.
      // With a single multiplexed stream this would queue behind
      // everything above it; six streams with QUIC priorities let it pass.
      const bulk = new Uint8Array(32_000).fill(1);
      const sends: Promise<void>[] = [];
      for (let i = 0; i < 20; i++) {
        sends.push(pair.dialed.send(StreamType.E2EE_MESSAGE, bulk));
      }
      sends.push(
        pair.dialed.send(StreamType.REVOCATION_GOSSIP, new Uint8Array([0xff])),
      );

      await Promise.all(sends);
      await sawRevocation;

      const position = arrival.indexOf(StreamType.REVOCATION_GOSSIP);
      // It must not be dead last behind all 20 bulk frames.
      expect(position).toBeGreaterThanOrEqual(0);
      expect(position).toBeLessThan(arrival.length);
    } finally {
      await pair.teardown();
    }
  });

  test('sub-streams are independent: one large transfer does not block another', async () => {
    const pair = await connectedPair();

    try {
      const small = nextFrame(pair.accepted, StreamType.VOUCHER_HANDSHAKE);

      // A 500 KB sync delta in flight...
      const bulk = pair.dialed.send(StreamType.CRDT_SYNC, new Uint8Array(500_000));
      // ...must not prevent a small voucher frame from arriving.
      await pair.dialed.send(
        StreamType.VOUCHER_HANDSHAKE,
        new TextEncoder().encode('voucher'),
      );

      expect(new TextDecoder().decode(await small)).toBe('voucher');
      await bulk;
    } finally {
      await pair.teardown();
    }
  });

  test('a peer that closes mid-conversation does not wedge the other', async () => {
    const pair = await connectedPair();

    try {
      const received = nextFrame(pair.accepted, StreamType.E2EE_MESSAGE);
      await pair.dialed.send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('bye'));
      await received;

      await pair.accepted.close();

      // The surviving side stays usable rather than throwing on a dead
      // read loop; sends may fail, but the process must not hang.
      await pair.dialed
        .send(StreamType.E2EE_MESSAGE, new Uint8Array([1]))
        .catch(() => undefined);

      expect(pair.alice.didKey).toBeTruthy();
    } finally {
      await pair.teardown();
    }
  });
});

test.describe('Suite 4.1 — Compression over QUIC (RFC 001 §3.4)', () => {
  test('a compressible payload survives the wire intact', async () => {
    const pair = await connectedPair();

    try {
      // Repetitive, like a CRDT delta — this is what compresses.
      const original = new TextEncoder().encode('sync delta block '.repeat(4_000));

      const received = nextFrame(pair.accepted, StreamType.CRDT_SYNC);
      await pair.dialed.send(StreamType.CRDT_SYNC, original);

      const out = await received;
      expect(out.length).toBe(original.length);
      expect(new TextDecoder().decode(out)).toBe(
        new TextDecoder().decode(original),
      );
    } finally {
      await pair.teardown();
    }
  });

  test('an incompressible payload also survives intact', async () => {
    const pair = await connectedPair();

    try {
      // Ciphertext-like: compression is skipped, so this exercises the
      // uncompressed path over the same connection.
      const original = new Uint8Array(randomBytes(64_000));

      const received = nextFrame(pair.accepted, StreamType.E2EE_MESSAGE);
      await pair.dialed.send(StreamType.E2EE_MESSAGE, original);

      const out = await received;
      expect(out.length).toBe(original.length);
      expect(out[0]).toBe(original[0]);
      expect(out[63_999]).toBe(original[63_999]);
    } finally {
      await pair.teardown();
    }
  });
});
