/**
 * Phase 1B — Test Suite 1.1: Peer Discovery & Transport
 *
 * Orchestrates two headless peer instances and verifies:
 *   - local mDNS discovery over `_p2p-sync._udp.local` (RFC 001 §4.1)
 *   - the mutually authenticated QUIC-stream handshake (RFC 001 §5)
 *   - sub-stream multiplexing across every stream type (RFC 001 §6)
 *   - DERP relay failover when hole-punching times out (RFC 001 §4.2)
 *
 * Discovery runs over an in-process datagram bus rather than real
 * multicast so the suite is deterministic and needs no LAN.
 */

import { expect, test } from '@playwright/test';

import {
  clearDatagramBuses,
  InMemoryDatagramSocket,
} from '../../packages/core/src/transport/datagram-socket.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import {
  clearTransportRegistry,
  LocalTransport,
} from '../../packages/core/src/transport/local-transport.js';
import { MdnsDiscovery } from '../../packages/core/src/transport/mdns-discovery.js';
import { RelayFailoverManager } from '../../packages/core/src/transport/relay-failover.js';
import type { Frame } from '../../packages/core/src/transport/types.js';
import {
  ConnectionState,
  StreamType,
  TransportError,
} from '../../packages/core/src/transport/types.js';

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

test.describe('Suite 1.1 — Peer Discovery & Transport', () => {
  test.afterEach(() => {
    clearTransportRegistry();
    clearDatagramBuses();
  });

  test('two headless peers discover each other over local mDNS', async () => {
    const group = `discovery-${Date.now()}`;

    const nodeA = new MdnsDiscovery({
      didKey: 'did:key:z6MkNodeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      port: 4242,
      socket: new InMemoryDatagramSocket(group, '10.0.0.1'),
      beaconIntervalMs: 100,
    });

    const nodeB = new MdnsDiscovery({
      didKey: 'did:key:z6MkNodeBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      port: 4343,
      socket: new InMemoryDatagramSocket(group, '10.0.0.2'),
      beaconIntervalMs: 100,
    });

    const discoveredByA: string[] = [];
    nodeA.onPeerDiscovered((peer) => discoveredByA.push(peer.did));

    await nodeA.start();
    await nodeB.start();

    try {
      // Each node must learn about the other, and neither about itself.
      expect(await waitFor(() => nodeA.getPeers().length === 1)).toBe(true);
      expect(await waitFor(() => nodeB.getPeers().length === 1)).toBe(true);

      const peerOfA = nodeA.getPeers()[0]!;
      expect(peerOfA.did).toBe('did:key:z6MkNodeBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
      expect(peerOfA.port).toBe(4343);
      expect(peerOfA.address).toBe('10.0.0.2');

      // Discovery fires exactly once per peer, not once per beacon.
      await new Promise((resolve) => setTimeout(resolve, 250));
      expect(discoveredByA).toHaveLength(1);
    } finally {
      await nodeA.stop();
      await nodeB.stop();
    }
  });

  test('a peer that stops beaconing is evicted as stale', async () => {
    const group = `expiry-${Date.now()}`;

    const nodeA = new MdnsDiscovery({
      didKey: 'did:key:z6MkStayAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      port: 4242,
      socket: new InMemoryDatagramSocket(group, '10.0.0.1'),
      beaconIntervalMs: 50,
      peerTtlMs: 120,
    });

    const nodeB = new MdnsDiscovery({
      didKey: 'did:key:z6MkLeaveBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      port: 4343,
      socket: new InMemoryDatagramSocket(group, '10.0.0.2'),
      beaconIntervalMs: 50,
    });

    const expired: string[] = [];
    nodeA.onPeerExpired((peer) => expired.push(peer.did));

    await nodeA.start();
    await nodeB.start();

    try {
      expect(await waitFor(() => nodeA.getPeers().length === 1)).toBe(true);

      // B goes away; A must notice within the TTL window.
      await nodeB.stop();

      expect(await waitFor(() => nodeA.getPeers().length === 0)).toBe(true);
      expect(expired).toContain('did:key:z6MkLeaveBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
    } finally {
      await nodeA.stop();
    }
  });

  test('discovery ignores foreign and malformed datagrams', async () => {
    const group = `noise-${Date.now()}`;

    const listener = new MdnsDiscovery({
      didKey: 'did:key:z6MkListenerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      port: 4242,
      socket: new InMemoryDatagramSocket(group, '10.0.0.1'),
      beaconIntervalMs: 1_000,
    });

    const noiseSocket = new InMemoryDatagramSocket(group, '10.0.0.9');

    await listener.start();
    await noiseSocket.bind();

    try {
      // Random bytes, and a well-formed TXT record for another service.
      await noiseSocket.send(new Uint8Array([0xff, 0x00, 0x13, 0x37]));
      await noiseSocket.send(
        new TextEncoder().encode('svc=_other._udp'),
      );

      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(listener.getPeers()).toHaveLength(0);
    } finally {
      await listener.stop();
      await noiseSocket.close();
    }
  });

  test('two peers complete the QUIC handshake and open a session', async () => {
    const keypairA = generateKeypair();
    const keypairB = generateKeypair();

    const transportA = new LocalTransport(keypairA);
    const transportB = new LocalTransport(keypairB);

    try {
      const didB = publicKeyToDidKey(keypairB.publicKey);

      let inboundPeerDid: string | null = null;
      transportB.onConnection((connection) => {
        inboundPeerDid = connection.peerDid;
      });

      const connection = await transportA.connect({
        didKey: didB,
        nodeId: keypairB.publicKey,
        directAddresses: [],
      });

      // Handshake succeeded ⇒ session is active and clock-synced.
      expect(connection.state).toBe(ConnectionState.Active);
      expect(connection.peerDid).toBe(didB);
      expect(Math.abs(connection.clockOffset)).toBeLessThanOrEqual(10);

      // The responder observed the inbound connection.
      expect(await waitFor(() => inboundPeerDid !== null)).toBe(true);
      expect(inboundPeerDid).toBe(publicKeyToDidKey(keypairA.publicKey));
    } finally {
      await transportA.close();
      await transportB.close();
    }
  });

  test('every sub-stream multiplexes over one connection', async () => {
    const keypairA = generateKeypair();
    const keypairB = generateKeypair();

    const transportA = new LocalTransport(keypairA);
    const transportB = new LocalTransport(keypairB);

    try {
      const received: Frame[] = [];
      transportB.onConnection((connection) => {
        connection.onFrame((frame) => received.push(frame));
      });

      const connection = await transportA.connect({
        didKey: publicKeyToDidKey(keypairB.publicKey),
        nodeId: keypairB.publicKey,
        directAddresses: [],
      });

      // Every declared type, not a hand-kept list — a list drifts out of
      // date silently the moment a stream type is added.
      const streams = Object.values(StreamType);

      for (const streamType of streams) {
        await connection.send(streamType, new Uint8Array([streamType, 0xaa]));
      }

      expect(await waitFor(() => received.length === streams.length)).toBe(true);

      const seen = received.map((f) => f.header.streamType).sort();
      expect(seen).toEqual([...streams].sort());

      // Payloads survive the round trip intact.
      for (const frame of received) {
        expect(Array.from(frame.payload)).toEqual([frame.header.streamType, 0xaa]);
      }
    } finally {
      await transportA.close();
      await transportB.close();
    }
  });

  test('revocation gossip (0x03) preempts chat traffic (0x02)', async () => {
    const keypairA = generateKeypair();
    const keypairB = generateKeypair();

    const transportA = new LocalTransport(keypairA);
    const transportB = new LocalTransport(keypairB);

    try {
      const order: number[] = [];
      transportB.onConnection((connection) => {
        connection.onFrame((frame) => order.push(frame.header.streamType));
      });

      const connection = await transportA.connect({
        didKey: publicKeyToDidKey(keypairB.publicKey),
        nodeId: keypairB.publicKey,
        directAddresses: [],
      });

      // Queue chat first, then a tombstone, within the same tick.
      await connection.send(StreamType.E2EE_MESSAGE, new Uint8Array([1]));
      await connection.send(StreamType.E2EE_MESSAGE, new Uint8Array([2]));
      await connection.send(StreamType.REVOCATION_GOSSIP, new Uint8Array([3]));

      expect(await waitFor(() => order.length === 3)).toBe(true);

      // RFC 001 §6: the tombstone must arrive ahead of the chat frames.
      expect(order[0]).toBe(StreamType.REVOCATION_GOSSIP);
      expect(order.slice(1)).toEqual([
        StreamType.E2EE_MESSAGE,
        StreamType.E2EE_MESSAGE,
      ]);
    } finally {
      await transportA.close();
      await transportB.close();
    }
  });

  test('direct hole-punch is preferred when it succeeds', async () => {
    const manager = new RelayFailoverManager({
      relayEndpoints: ['derp-1.example:443'],
      holePunchTimeoutMs: 500,
      sleep: async () => undefined,
    });

    let relayAttempts = 0;

    const route = await manager.establish(
      async () => undefined,
      async () => {
        relayAttempts++;
      },
    );

    expect(route.kind).toBe('direct');
    expect(route.endpoint).toBeNull();
    expect(relayAttempts).toBe(0);
  });

  test('failover moves to the DERP relay when hole-punching times out', async () => {
    const manager = new RelayFailoverManager({
      relayEndpoints: ['derp-1.example:443', 'derp-2.example:443'],
      holePunchTimeoutMs: 100,
      sleep: async () => undefined,
    });

    const attempted: string[] = [];

    const route = await manager.establish(
      // Never resolves — simulates symmetric NAT blocking UDP.
      () => new Promise<void>(() => undefined),
      async (endpoint) => {
        attempted.push(endpoint);
        if (endpoint === 'derp-1.example:443') {
          throw new Error('relay sleeping');
        }
      },
    );

    expect(route.kind).toBe('relay');
    expect(route.endpoint).toBe('derp-2.example:443');
    expect(route.relayIndex).toBe(1);

    // The primary relay was retried before moving on to the backup.
    expect(attempted.filter((e) => e === 'derp-1.example:443').length).toBeGreaterThan(1);
  });

  test('exhausting every relay reports IrohDerpRelayUnavailable', async () => {
    const manager = new RelayFailoverManager({
      relayEndpoints: ['derp-1.example:443'],
      holePunchTimeoutMs: 50,
      maxRetriesPerRelay: 1,
      sleep: async () => undefined,
    });

    await expect(
      manager.establish(
        async () => {
          throw new Error('hole punch refused');
        },
        async () => {
          throw new Error('relay unreachable');
        },
      ),
    ).rejects.toThrow(TransportError.DerpRelayUnavailable);
  });

  test('hole-punch failure with no relays configured is reported as such', async () => {
    const manager = new RelayFailoverManager({
      holePunchTimeoutMs: 50,
      sleep: async () => undefined,
    });

    await expect(
      manager.establish(
        async () => {
          throw new Error('hole punch refused');
        },
        async () => undefined,
      ),
    ).rejects.toThrow(TransportError.HolePunchTimeout);
  });
});
