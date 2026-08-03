/**
 * @dicsussion/transport — Datagram Socket Abstraction
 *
 * Pluggable UDP backend for mDNS beacon discovery (RFC 001 §4.1).
 * Production uses IPv4 multicast via `node:dgram`; tests use an
 * in-process bus so discovery can be exercised without touching
 * the host network stack.
 */

import { createSocket, type Socket } from 'node:dgram';

/** IPv4 multicast group used by mDNS. */
export const MDNS_MULTICAST_ADDRESS = '224.0.0.251';

/** Standard mDNS UDP port. */
export const MDNS_PORT = 5353;

/** Source address/port of a received datagram. */
export interface DatagramInfo {
  readonly address: string;
  readonly port: number;
}

export type DatagramHandler = (msg: Uint8Array, rinfo: DatagramInfo) => void;

/**
 * Minimal datagram transport contract required by beacon discovery.
 */
export interface IDatagramSocket {
  /** Join the group and begin receiving datagrams. */
  bind(): Promise<void>;
  /** Broadcast a datagram to the whole group. */
  send(msg: Uint8Array): Promise<void>;
  /** Subscribe to inbound datagrams. Returns an unsubscribe function. */
  onMessage(handler: DatagramHandler): () => void;
  /** Leave the group and release the socket. */
  close(): Promise<void>;
}

/**
 * Real IPv4 multicast socket bound to the mDNS group.
 *
 * `reuseAddr` lets several nodes on one host share port 5353, and
 * multicast loopback is enabled so co-located peers see each other.
 */
export class UdpMulticastSocket implements IDatagramSocket {
  private socket: Socket | null = null;
  private readonly handlers = new Set<DatagramHandler>();

  constructor(
    private readonly group: string = MDNS_MULTICAST_ADDRESS,
    private readonly port: number = MDNS_PORT,
  ) {}

  async bind(): Promise<void> {
    if (this.socket) return;

    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    this.socket = socket;

    socket.on('message', (msg, rinfo) => {
      const view = new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength);
      for (const handler of this.handlers) {
        handler(view, { address: rinfo.address, port: rinfo.port });
      }
    });

    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(this.port, () => {
        socket.off('error', reject);
        try {
          socket.addMembership(this.group);
          socket.setMulticastLoopback(true);
          resolve();
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    });

    // Do not keep the event loop alive purely for discovery.
    socket.unref();
  }

  async send(msg: Uint8Array): Promise<void> {
    const socket = this.socket;
    if (!socket) throw new Error('Datagram socket is not bound');

    await new Promise<void>((resolve, reject) => {
      socket.send(msg, this.port, this.group, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  onMessage(handler: DatagramHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  async close(): Promise<void> {
    const socket = this.socket;
    this.handlers.clear();
    if (!socket) return;
    this.socket = null;

    await new Promise<void>((resolve) => {
      socket.close(() => resolve());
    });
  }
}

/** Registry of in-process buses keyed by group name. */
const busRegistry = new Map<string, Set<InMemoryDatagramSocket>>();

/**
 * In-process datagram bus for deterministic multi-node tests.
 *
 * Sockets sharing a group name deliver to one another asynchronously,
 * mirroring real multicast semantics (the sender does not receive its
 * own datagram synchronously).
 */
export class InMemoryDatagramSocket implements IDatagramSocket {
  private readonly handlers = new Set<DatagramHandler>();
  private bound = false;

  constructor(
    private readonly group: string = 'default',
    private readonly address: string = '127.0.0.1',
    private readonly port: number = MDNS_PORT,
  ) {}

  async bind(): Promise<void> {
    if (this.bound) return;
    this.bound = true;

    let members = busRegistry.get(this.group);
    if (!members) {
      members = new Set();
      busRegistry.set(this.group, members);
    }
    members.add(this);
  }

  async send(msg: Uint8Array): Promise<void> {
    if (!this.bound) throw new Error('Datagram socket is not bound');

    const members = busRegistry.get(this.group);
    if (!members) return;

    // Copy so a caller reusing its buffer cannot mutate in-flight data.
    const frozen = msg.slice();
    const rinfo: DatagramInfo = { address: this.address, port: this.port };
    const peers = Array.from(members).filter((m) => m !== this);

    setImmediate(() => {
      for (const peer of peers) {
        peer.deliver(frozen, rinfo);
      }
    });
  }

  onMessage(handler: DatagramHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  async close(): Promise<void> {
    this.bound = false;
    this.handlers.clear();

    const members = busRegistry.get(this.group);
    if (members) {
      members.delete(this);
      if (members.size === 0) busRegistry.delete(this.group);
    }
  }

  private deliver(msg: Uint8Array, rinfo: DatagramInfo): void {
    if (!this.bound) return;
    for (const handler of this.handlers) {
      handler(msg, rinfo);
    }
  }
}

/** Tear down every in-process bus. Test cleanup helper. */
export function clearDatagramBuses(): void {
  busRegistry.clear();
}
