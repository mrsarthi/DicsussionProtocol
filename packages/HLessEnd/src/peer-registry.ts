/**
 * @dicsussion/sdk — Peer Registry
 *
 * Directory of known peers: their E2EE public key (learned during
 * out-of-band pairing, RFC 001 §3.3) and their live connection, if any.
 *
 * Encryption keys are deliberately separate from the Ed25519 identity
 * key. Reusing one keypair across signing and key agreement is a known
 * cross-protocol hazard, so each node carries a distinct X25519 key.
 */

import { ConnectionState } from '@dicsussion/core/transport';
import type { IConnection } from '@dicsussion/core/transport';

/** A known peer and its current connection state. */
export interface PeerRecord {
  /** Peer's did:key identifier. */
  readonly did: string;
  /** Peer's 32-byte X25519 public key for E2EE key agreement. */
  readonly encryptionKey: Uint8Array;
  /**
   * Whether this peer was paired out of band (RFC 001 §3.3).
   *
   * **This is an authorization boundary, not a cache flag.** Only paired
   * peers receive message traffic. An inbound dialer is recorded here so
   * its connection can be tracked, but anyone can complete a handshake —
   * the did:key in a `HandshakeInit` is self-asserted, so a stranger with
   * a freshly generated keypair looks exactly like a friend. Pairing is
   * what distinguishes them.
   */
  readonly paired: boolean;
  /** Live connection, or undefined when not connected. */
  readonly connection?: IConnection;
}

/**
 * Tracks paired peers and their active connections.
 */
export class PeerRegistry {
  private readonly peers = new Map<string, PeerRecord>();

  /** Number of known peers, connected or not. */
  get size(): number {
    return this.peers.size;
  }

  /** Number of peers with a live connection. */
  get connectedCount(): number {
    let count = 0;
    for (const peer of this.peers.values()) {
      if (isLive(peer)) count++;
    }
    return count;
  }

  /**
   * Record a peer's encryption key, learned out of band during pairing.
   *
   * @throws If the key is not a 32-byte X25519 public key.
   */
  addPeer(did: string, encryptionKey: Uint8Array): void {
    if (encryptionKey.length !== 32) {
      throw new Error(
        `X25519 public key must be 32 bytes, got ${encryptionKey.length}`,
      );
    }

    const existing = this.peers.get(did);
    this.peers.set(did, {
      did,
      encryptionKey: encryptionKey.slice(),
      // Reaching this method *is* the pairing act — the key came from a
      // ticket or an explicit application call, not from the wire.
      paired: true,
      connection: existing?.connection,
    });
  }

  /**
   * Record an inbound peer that has not been paired.
   *
   * Needed so the connection can be tracked and CRDT sync can proceed,
   * but the peer receives no message traffic until `addPeer` runs.
   */
  addUnpairedPeer(did: string): void {
    if (this.peers.has(did)) return;

    this.peers.set(did, {
      did,
      encryptionKey: new Uint8Array(32),
      paired: false,
    });
  }

  /** Peers that were paired out of band and are currently connected. */
  listPairedConnected(): PeerRecord[] {
    return this.listConnected().filter((peer) => peer.paired);
  }

  /** Bind a live connection to a known peer. */
  attachConnection(did: string, connection: IConnection): void {
    const existing = this.peers.get(did);

    if (!existing) {
      throw new Error(`Cannot attach connection to unknown peer: ${did}`);
    }

    this.peers.set(did, { ...existing, connection });
  }

  /** Drop a peer's connection while keeping its key material. */
  detachConnection(did: string): void {
    const existing = this.peers.get(did);
    if (!existing) return;

    // Pairing survives disconnection — it is a decision the application
    // made, not a property of the transport.
    this.peers.set(did, {
      did: existing.did,
      encryptionKey: existing.encryptionKey,
      paired: existing.paired,
    });
  }

  /** Look up a peer record. */
  getPeer(did: string): PeerRecord | undefined {
    return this.peers.get(did);
  }

  /** Look up a peer's X25519 public key. */
  getEncryptionKey(did: string): Uint8Array | undefined {
    return this.peers.get(did)?.encryptionKey;
  }

  /** Whether the peer currently has a live connection. */
  isConnected(did: string): boolean {
    const peer = this.peers.get(did);
    return peer !== undefined && isLive(peer);
  }

  /** All known peers. */
  list(): PeerRecord[] {
    return Array.from(this.peers.values());
  }

  /** Only peers with a live connection. */
  listConnected(): PeerRecord[] {
    return this.list().filter(isLive);
  }

  /**
   * Forget connections that are no longer active, keeping key material.
   *
   * Liveness is read from `ConnectionState` on every query, so a dead
   * connection stops counting the moment the transport marks it closed —
   * this only releases the object itself.
   *
   * @returns How many were dropped.
   */
  pruneDisconnected(): number {
    let dropped = 0;
    for (const peer of this.peers.values()) {
      if (peer.connection && !isLive(peer)) {
        this.detachConnection(peer.did);
        dropped++;
      }
    }
    return dropped;
  }

  /** Forget a peer entirely. */
  removePeer(did: string): boolean {
    return this.peers.delete(did);
  }

  /** Drop every peer and connection. */
  clear(): void {
    this.peers.clear();
  }
}

/**
 * Whether a peer's connection can actually carry traffic.
 *
 * Presence of a connection object is not liveness. When a transport
 * tears a connection down it sets `ConnectionState.Disconnected` and
 * wipes the session key, but the object stays referenced here — so a
 * check for existence alone reports a peer as reachable indefinitely
 * after it has gone. Every send would then be attempted instead of
 * queued, and the outbox built for exactly this case never engages.
 */
function isLive(peer: PeerRecord): boolean {
  return peer.connection?.state === ConnectionState.Active;
}
