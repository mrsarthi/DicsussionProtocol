/**
 * @dicsussion/transport — Local Network Discovery (mDNS)
 *
 * Broadcasts a beacon on `_p2p-sync._udp.local` every 5000ms and
 * maintains a table of live LAN peers per RFC 001 §4.1.
 *
 * Peers are considered stale after `peerTtlMs` (3 missed beacons by
 * default) and are evicted with an `expired` notification so the
 * transport layer can tear down dead routes.
 */

import { EventEmitter } from 'node:events';

import type { IDatagramSocket } from './datagram-socket.js';
import { UdpMulticastSocket } from './datagram-socket.js';
import type { MdnsBeacon } from './mdns-record.js';
import { decodeBeacon, encodeBeacon, MDNS_PROTOCOL_VERSION } from './mdns-record.js';
import { MDNS_BEACON_INTERVAL_MS, MDNS_SERVICE_ID } from './types.js';

/** A peer observed on the local network. */
export interface DiscoveredPeer {
  /** Peer's did:key identifier. */
  readonly did: string;
  /** Source IP address the beacon arrived from. */
  readonly address: string;
  /** UDP port the peer is listening on. */
  readonly port: number;
  /** Epoch milliseconds of the most recent beacon. */
  readonly lastSeen: number;
}

export type PeerHandler = (peer: DiscoveredPeer) => void;

export interface MdnsDiscoveryOptions {
  /** This node's did:key identifier. */
  readonly didKey: string;
  /** This node's listening UDP port, advertised in the beacon. */
  readonly port: number;
  /** Datagram backend. Defaults to real IPv4 multicast. */
  readonly socket?: IDatagramSocket;
  /** Beacon broadcast interval (default 5000ms per RFC 001 §4.1). */
  readonly beaconIntervalMs?: number;
  /** Peer staleness window (default: 3 beacon intervals). */
  readonly peerTtlMs?: number;
}

/**
 * mDNS beacon discovery service for local-network peer detection.
 */
export class MdnsDiscovery {
  private readonly emitter = new EventEmitter();
  private readonly peers = new Map<string, DiscoveredPeer>();
  private readonly socket: IDatagramSocket;
  private readonly didKey: string;
  private readonly port: number;
  private readonly beaconIntervalMs: number;
  private readonly peerTtlMs: number;

  private beaconTimer: NodeJS.Timeout | null = null;
  private reaperTimer: NodeJS.Timeout | null = null;
  private unsubscribe: (() => void) | null = null;
  private running = false;

  constructor(options: MdnsDiscoveryOptions) {
    this.didKey = options.didKey;
    this.port = options.port;
    this.socket = options.socket ?? new UdpMulticastSocket();
    this.beaconIntervalMs = options.beaconIntervalMs ?? MDNS_BEACON_INTERVAL_MS;
    this.peerTtlMs = options.peerTtlMs ?? this.beaconIntervalMs * 3;

    // Discovery is best-effort background chatter; never let a listener
    // count warning or a late beacon crash the node.
    this.emitter.setMaxListeners(0);
  }

  /** Whether the service is currently broadcasting. */
  get isRunning(): boolean {
    return this.running;
  }

  /**
   * Bind the socket, announce immediately, and start the beacon
   * and staleness-reaper timers.
   */
  async start(): Promise<void> {
    if (this.running) return;

    await this.socket.bind();
    this.unsubscribe = this.socket.onMessage((msg, rinfo) => {
      this.handleDatagram(msg, rinfo.address);
    });
    this.running = true;

    // Announce straight away so peers do not wait a full interval.
    await this.announce();

    this.beaconTimer = setInterval(() => {
      void this.announce().catch(() => {
        // A dropped beacon is non-fatal; the next interval retries.
      });
    }, this.beaconIntervalMs);
    this.beaconTimer.unref?.();

    this.reaperTimer = setInterval(() => {
      this.reapStalePeers();
    }, this.beaconIntervalMs);
    this.reaperTimer.unref?.();
  }

  /** Stop broadcasting and release the socket. */
  async stop(): Promise<void> {
    this.running = false;

    if (this.beaconTimer) {
      clearInterval(this.beaconTimer);
      this.beaconTimer = null;
    }
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }

    await this.socket.close();
    this.peers.clear();
    this.emitter.removeAllListeners();
  }

  /** Broadcast a single beacon immediately. */
  async announce(): Promise<void> {
    if (!this.running) return;

    const beacon: MdnsBeacon = {
      service: MDNS_SERVICE_ID,
      did: this.didKey,
      port: this.port,
      version: MDNS_PROTOCOL_VERSION,
    };

    await this.socket.send(encodeBeacon(beacon));
  }

  /** Snapshot of all currently live peers. */
  getPeers(): DiscoveredPeer[] {
    return Array.from(this.peers.values());
  }

  /** Look up a single peer by did:key. */
  getPeer(did: string): DiscoveredPeer | undefined {
    return this.peers.get(did);
  }

  /** Subscribe to first-sighting of a peer. Returns an unsubscribe function. */
  onPeerDiscovered(handler: PeerHandler): () => void {
    this.emitter.on('discovered', handler);
    return () => {
      this.emitter.off('discovered', handler);
    };
  }

  /** Subscribe to peer staleness eviction. Returns an unsubscribe function. */
  onPeerExpired(handler: PeerHandler): () => void {
    this.emitter.on('expired', handler);
    return () => {
      this.emitter.off('expired', handler);
    };
  }

  /** Evict peers whose most recent beacon is older than the TTL. */
  private reapStalePeers(now: number = Date.now()): void {
    for (const [did, peer] of this.peers) {
      if (now - peer.lastSeen > this.peerTtlMs) {
        this.peers.delete(did);
        this.emitter.emit('expired', peer);
      }
    }
  }

  private handleDatagram(msg: Uint8Array, address: string): void {
    const beacon = decodeBeacon(msg);

    // Not one of ours, or malformed — ignore silently (RFC 001 §7).
    if (!beacon) return;

    // Never treat our own loopback beacon as a peer.
    if (beacon.did === this.didKey) return;

    const existing = this.peers.get(beacon.did);
    const peer: DiscoveredPeer = {
      did: beacon.did,
      address,
      port: beacon.port,
      lastSeen: Date.now(),
    };
    this.peers.set(beacon.did, peer);

    if (!existing) {
      this.emitter.emit('discovered', peer);
    }
  }
}
