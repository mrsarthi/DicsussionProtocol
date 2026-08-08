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

import { decodeSyncFrame, SyncMessageType } from '@dicsussion/core/crdt';
import type { CrdtSyncEngine } from '@dicsussion/core/crdt';
import type { MembershipSyncEngine } from '@dicsussion/core/crdt';
import type { SyncFrame } from '@dicsussion/core/crdt';
import { StreamType } from '@dicsussion/core/transport';
import type { Frame } from '@dicsussion/core/transport';
import type { IConnection } from '@dicsussion/core/transport';
import type { MessagePayload } from './message-codec.js';
import { openMessage, sealMessage } from './message-codec.js';
import { currentEpoch } from './outbox.js';
import type { PeerRegistry } from './peer-registry.js';

/** Collaborators the session manager needs. */
export interface SessionManagerDeps {
  readonly peers: PeerRegistry;
  readonly syncEngine: CrdtSyncEngine;
  /** Hand a decrypted message to the chat layer. */
  readonly onMessage: (payload: MessagePayload) => Promise<void>;
  /**
   * Membership reconciliation engine.
   *
   * Optional so the session manager works before groups are wired.
   */
  readonly membershipSync?: MembershipSyncEngine;
  /**
   * Handle a Stream 0x04 voucher frame.
   *
   * Optional so the session manager still works before the Web-of-Trust
   * stack is attached.
   */
  readonly onVoucherFrame?: (
    payload: Uint8Array,
    connection: IConnection,
  ) => Promise<void>;
  /** Handle a Stream 0x06 RLN share frame. */
  readonly onShareFrame?: (payload: Uint8Array) => Promise<void>;
  /** Handle a Stream 0x03 revocation tombstone. */
  readonly onRevocationFrame?: (payload: Uint8Array) => Promise<void>;
  /** Handle a Stream 0x05 RLN signal broadcast. */
  readonly onSignalFrame?: (payload: Uint8Array) => Promise<void>;
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
   * An inbound peer may not have been paired yet. It is recorded so its
   * connection can be tracked and CRDT sync can proceed, but it receives
   * no message traffic until the application pairs it — see `publish`.
   */
  registerConnection(connection: IConnection): void {
    const { peers, syncEngine } = this.deps;
    const peerDid = connection.peerDid;

    // Recorded, but explicitly NOT paired. Anyone can complete a
    // handshake — `HandshakeInit.didKey` is self-asserted, so a stranger
    // with a fresh keypair is indistinguishable from a friend. Pairing
    // happens out of band, and until it does this peer gets no messages.
    peers.addUnpairedPeer(peerDid);

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
    const sends: Array<Promise<void>> = [];

    // Paired peers only. A live connection is not authorization: the
    // handshake authenticates *a* key, not that its holder is someone
    // this node chose to talk to. Publishing to every connected peer
    // would hand plaintext to any stranger who dialled us.
    for (const peer of this.deps.peers.listPairedConnected()) {
      const connection = peer.connection;
      if (!connection) continue;

      // Sealed under the connection's session key, not the peer's
      // long-term X25519 key. That is what makes the traffic forward
      // secret: the session key exists only while both ephemeral halves
      // did, and those are wiped at handshake completion.
      const envelope = sealMessage(payload, connection.sessionKey, epoch);
      sends.push(connection.send(StreamType.E2EE_MESSAGE, envelope));
    }

    await Promise.all(sends);
  }

  /** Route an inbound frame by sub-stream. */
  private async handleFrame(
    frame: Frame,
    connection: IConnection,
  ): Promise<void> {
    try {
      switch (frame.header.streamType) {
        case StreamType.CRDT_SYNC:
          await this.handleSyncFrame(frame, connection);
          break;
        case StreamType.E2EE_MESSAGE:
          await this.handleMessageFrame(frame, connection);
          break;
        case StreamType.VOUCHER_HANDSHAKE:
          await this.deps.onVoucherFrame?.(frame.payload, connection);
          break;
        case StreamType.REVOCATION_GOSSIP:
          await this.deps.onRevocationFrame?.(frame.payload);
          break;
        case StreamType.RLN_SHARE_EXCHANGE:
          await this.deps.onShareFrame?.(frame.payload);
          break;
        case StreamType.RLN_SIGNAL:
          await this.deps.onSignalFrame?.(frame.payload);
          break;
        default:
          // Unknown stream types are ignored, never fatal — a future
          // protocol version may add one (RFC 001 §7).
          break;
      }
    } catch {
      // A malformed or undecryptable frame is dropped, never fatal
      // (RFC 001 §7). The connection stays up.
    }
  }

  private async handleSyncFrame(
    frame: Frame,
    connection: IConnection,
  ): Promise<void> {
    // Membership messages ride the same sub-stream as document sync but
    // are handled by a different engine, so they are split out first.
    if (await this.routeMembershipFrame(frame, connection)) return;

    const replies = this.deps.syncEngine.handleMessage(
      connection.peerDid,
      frame.payload,
    );

    for (const reply of replies) {
      await connection.send(StreamType.CRDT_SYNC, reply);
    }

    this.lastSyncTimestamp = Date.now();
  }

  /**
   * Dispatch a membership message, if this frame is one.
   *
   * @returns True when the frame was membership traffic and is handled.
   */
  private async routeMembershipFrame(
    frame: Frame,
    connection: IConnection,
  ): Promise<boolean> {
    const membership = this.deps.membershipSync;
    if (!membership) return false;

    let decoded: SyncFrame;
    try {
      decoded = decodeSyncFrame(frame.payload);
    } catch {
      return false;
    }

    const peer = connection.peerDid;
    let replies: Uint8Array[];

    switch (decoded.type) {
      case SyncMessageType.MEMBER_ROOT:
        replies = membership.handleMemberRoot(peer, decoded.docId, decoded.body);
        break;
      case SyncMessageType.MEMBER_LIST:
        replies = membership.handleMemberList(peer, decoded.docId, decoded.body);
        break;
      case SyncMessageType.MEMBER_DEPARTURE:
        replies = membership.handleDeparture(peer, decoded.docId, decoded.body);
        break;
      default:
        return false;
    }

    for (const reply of replies) {
      await connection.send(StreamType.CRDT_SYNC, reply);
    }

    return true;
  }

  private async handleMessageFrame(
    frame: Frame,
    connection: IConnection,
  ): Promise<void> {
    const opened = openMessage(frame.payload, connection.sessionKey);
    await this.deps.onMessage(opened.payload);
  }
}
