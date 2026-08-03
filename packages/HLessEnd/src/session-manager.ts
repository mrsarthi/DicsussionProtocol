/**
 * @dicsussion/sdk — Peer Session Manager
 *
 * Owns everything that happens on a live connection: registering peers,
 * routing inbound frames to the right sub-protocol handler, and fanning
 * outbound messages to connected peers.
 *
 * Keeping this out of `DicsussionClient` leaves the client as a thin
 * facade over composed services rather than a single state manager
 * (AGENT_INSTRUCTIONS §4.1 rule 3).
 */

import type { CrdtSyncEngine } from '../../core/src/crdt/sync-engine.js';
import type { IConnection } from '../../core/src/transport/transport-interface.js';
import type { Frame } from '../../core/src/transport/types.js';
import { StreamType } from '../../core/src/transport/types.js';
import type { MessagePayload } from './message-codec.js';
import { openMessage, sealMessage } from './message-codec.js';
import { currentEpoch } from './outbox.js';
import type { PeerRegistry } from './peer-registry.js';

/** Collaborators the session manager needs. */
export interface SessionManagerDeps {
  readonly peers: PeerRegistry;
  readonly syncEngine: CrdtSyncEngine;
  /** Our X25519 private key, for opening inbound envelopes. */
  readonly getEncryptionSecret: () => Uint8Array;
  /** Hand a decrypted message to the chat layer. */
  readonly onMessage: (payload: MessagePayload) => Promise<void>;
}

/**
 * Manages live peer connections and sub-stream frame routing.
 */
export class SessionManager {
  private lastSyncTimestamp = 0;

  constructor(private readonly deps: SessionManagerDeps) {}

  /** Epoch milliseconds of the most recent CRDT sync exchange. */
  get lastSync(): number {
    return this.lastSyncTimestamp;
  }

  /** Peers with a live connection. */
  get connectedCount(): number {
    return this.deps.peers.connectedCount;
  }

  /**
   * Attach frame handling and sync state to a new connection.
   *
   * An inbound peer may not have been paired yet, so it is recorded with
   * a placeholder key. Messages are never encrypted to that placeholder
   * — see `publish`.
   */
  registerConnection(connection: IConnection): void {
    const { peers, syncEngine } = this.deps;
    const peerDid = connection.peerDid;

    if (!peers.getPeer(peerDid)) {
      peers.addPeer(peerDid, new Uint8Array(32));
    }
    peers.attachConnection(peerDid, connection);
    syncEngine.registerPeer(peerDid);

    connection.onFrame((frame) => {
      void this.handleFrame(frame, connection);
    });
  }

  /** Open the RFC 002 §4.2 reconciliation conversation with a peer. */
  async beginSync(connection: IConnection): Promise<void> {
    await connection.send(
      StreamType.CRDT_SYNC,
      this.deps.syncEngine.beginSync(connection.peerDid),
    );
  }

  /**
   * Encrypt a payload for every connected peer and send it on Stream 0x02.
   *
   * Each peer gets its own envelope: encryption is per-recipient via
   * ephemeral X25519 ECDH, so there is no shared group key in Phase 1A.
   */
  async publish(payload: MessagePayload): Promise<void> {
    const epoch = currentEpoch();
    const sends: Promise<void>[] = [];

    for (const peer of this.deps.peers.listConnected()) {
      // Peers that connected inbound before pairing carry a placeholder
      // key; skip them rather than encrypting to an all-zero key.
      if (isZeroKey(peer.encryptionKey)) continue;

      const envelope = sealMessage(payload, peer.encryptionKey, epoch);
      sends.push(peer.connection!.send(StreamType.E2EE_MESSAGE, envelope));
    }

    await Promise.all(sends);
  }

  /** Route an inbound frame by sub-stream. */
  private async handleFrame(frame: Frame, connection: IConnection): Promise<void> {
    try {
      switch (frame.header.streamType) {
        case StreamType.CRDT_SYNC:
          await this.handleSyncFrame(frame, connection);
          break;
        case StreamType.E2EE_MESSAGE:
          await this.handleMessageFrame(frame);
          break;
        default:
          // Streams 0x03–0x06 belong to Phases 2–3; ignore for now.
          break;
      }
    } catch {
      // A malformed or undecryptable frame is dropped, never fatal
      // (RFC 001 §7). The connection stays up.
    }
  }

  private async handleSyncFrame(frame: Frame, connection: IConnection): Promise<void> {
    const replies = this.deps.syncEngine.handleMessage(
      connection.peerDid,
      frame.payload,
    );

    for (const reply of replies) {
      await connection.send(StreamType.CRDT_SYNC, reply);
    }

    this.lastSyncTimestamp = Date.now();
  }

  private async handleMessageFrame(frame: Frame): Promise<void> {
    const opened = openMessage(frame.payload, this.deps.getEncryptionSecret());
    await this.deps.onMessage(opened.payload);
  }
}

function isZeroKey(key: Uint8Array): boolean {
  return key.every((b) => b === 0);
}
