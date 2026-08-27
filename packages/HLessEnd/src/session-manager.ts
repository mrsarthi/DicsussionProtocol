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
import {
  openMessage,
  openOpaque,
  sealMessage,
  sealOpaque,
} from './message-codec.js';
import { currentEpoch } from './outbox.js';
import type { PeerRegistry } from './peer-registry.js';

/** Collaborators the session manager needs. */
export interface SessionManagerDeps {
  readonly peers: PeerRegistry;
  /**
   * Whether a peer belongs to a channel.
   *
   * Pairing authorises *a* conversation, not every conversation. Without
   * this, publishing fanned a message out to every paired peer whatever
   * channel it belonged to, so a contact received chats they were never
   * part of — over the envelope path, quite apart from synchronisation.
   *
   * Defaults to refusing, so a caller that omits it sends nothing rather
   * than sending everything to everyone.
   */
  readonly mayReceive?: (peerDid: string, channelId: string) => boolean;
  /**
   * Whether this node already holds the conversation.
   *
   * Distinguishes "not a participant" from "never heard of it", which
   * decide opposite things on the inbound path.
   */
  readonly knowsChannel?: (channelId: string) => boolean;
  /**
   * An ephemeral payload arrived on Stream `0x07`.
   *
   * Never persisted and never acknowledged: if nothing is listening, it
   * is gone.
   */
  readonly onEphemeral?: (
    peerDid: string,
    channelId: string,
    payload: Uint8Array,
  ) => void;
  /**
   * A peer sent us their profile on Stream `0x08`.
   *
   * Only ever called for a paired peer: `handleFrame` drops everything
   * from an unpaired one before routing.
   */
  readonly onProfile?: (peerDid: string, encoded: Uint8Array) => Promise<void>;
  /**
   * A paired peer sent a blob request, chunk, or refusal on `0x09`.
   */
  readonly onBlobFrame?: (peerDid: string, payload: Uint8Array) => Promise<void>;
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
   * connection can be tracked, but until the application pairs it the
   * peer gets no protocol surface at all — see `handleFrame`.
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

  /**
   * Open the RFC 002 §4.2 reconciliation conversation with a peer.
   *
   * Refuses unpaired peers: beginning sync would disclose our document
   * heads, which leak channel membership and activity even before any
   * change is exchanged.
   */
  async beginSync(connection: IConnection): Promise<void> {
    if (!this.isPaired(connection.peerDid)) return;

    await connection.send(
      StreamType.CRDT_SYNC,
      this.deps.syncEngine.beginSync(connection.peerDid),
    );
  }

  /**
   * Whether a peer was paired out of band, and may therefore be spoken to.
   *
   * A completed handshake is **not** authorization. `HandshakeInit.didKey`
   * is self-asserted, so a stranger who generates a fresh keypair produces
   * a handshake indistinguishable from a friend's. Pairing (RFC 001 §3.3)
   * happens off the wire and is the only thing that separates them.
   */
  private isPaired(peerDid: string): boolean {
    return this.deps.peers.getPeer(peerDid)?.paired === true;
  }

  /**
   * Encrypt a payload for every connected peer and send it on Stream 0x02.
   *
   * Each peer gets its own envelope: encryption is per-recipient via
   * ephemeral X25519 ECDH, so there is no shared group key in Phase 1A.
   */
  async publish(payload: MessagePayload): Promise<number> {
    const epoch = currentEpoch();
    const sends: Array<Promise<void>> = [];

    // Paired peers only. A live connection is not authorization: the
    // handshake authenticates *a* key, not that its holder is someone
    // this node chose to talk to. Publishing to every connected peer
    // would hand plaintext to any stranger who dialled us.
    for (const peer of this.deps.peers.listPairedConnected()) {
      const connection = peer.connection;
      if (!connection) continue;

      // Paired is not the same as "in this conversation".
      if (!this.deps.mayReceive?.(peer.did, payload.channelId)) continue;

      // Sealed under the connection's session key, not the peer's
      // long-term X25519 key. That is what makes the traffic forward
      // secret: the session key exists only while both ephemeral halves
      // did, and those are wiped at handshake completion.
      const envelope = sealMessage(payload, connection.sessionKey, epoch);
      sends.push(connection.send(StreamType.E2EE_MESSAGE, envelope));
    }

    await Promise.all(sends);

    // Reporting the count is what lets the caller tell "delivered to
    // nobody" from "delivered". Fanning out to an empty set resolves
    // exactly like a successful send, so a node whose only connection is
    // an unpaired stranger would otherwise mark the message sent and
    // never queue it.
    return sends.length;
  }

  /**
   * Send an ephemeral payload to everyone currently reachable.
   *
   * Deliberately unlike `publish`: nothing is written locally, nothing
   * is queued, and a peer that is not connected right now simply does
   * not get it. That is the point — presence, typing and read receipts
   * are only true while both ends are connected, so retrying one later
   * would deliver a claim that has since become false.
   *
   * @returns How many peers it reached.
   */
  async publishEphemeral(channelId: string, payload: Uint8Array): Promise<number> {
    const epoch = currentEpoch();
    const sends: Array<Promise<void>> = [];

    for (const peer of this.deps.peers.listPairedConnected()) {
      const connection = peer.connection;
      if (!connection) continue;
      if (!this.deps.mayReceive?.(peer.did, channelId)) continue;

      // Channel id travels with the payload rather than in a header:
      // the frame carries only a stream type, and a receiver has to know
      // which conversation a signal belongs to.
      const framed = encodeEphemeral(channelId, payload);
      sends.push(
        connection.send(
          StreamType.EPHEMERAL,
          sealOpaque(framed, connection.sessionKey, epoch),
        ),
      );
    }

    await Promise.all(sends);

    return sends.length;
  }

  /**
   * Send our profile to every paired, connected peer.
   *
   * Not gated by channel membership, unlike everything else here: a
   * profile belongs to a person rather than a conversation, and pairing
   * is the whole of its access control. Unpaired peers are excluded
   * because `listPairedConnected` excludes them.
   *
   * @returns How many peers received it.
   */
  async publishProfile(encoded: Uint8Array): Promise<number> {
    const epoch = currentEpoch();
    const sends: Array<Promise<void>> = [];

    for (const peer of this.deps.peers.listPairedConnected()) {
      const connection = peer.connection;
      if (!connection) continue;

      sends.push(
        connection.send(
          StreamType.PROFILE,
          sealOpaque(encoded, connection.sessionKey, epoch),
        ),
      );
    }

    await Promise.all(sends);

    return sends.length;
  }

  /**
   * Send a blob payload to one peer.
   *
   * @returns Whether the peer was reachable. A caller moves on to
   *   another source rather than waiting for a timeout it can predict.
   */
  async sendBlobTo(peerDid: string, payload: Uint8Array): Promise<boolean> {
    const peer = this.deps.peers.getPeer(peerDid);

    // Paired as well as connected. Blobs are requested by hash, so an
    // unpaired peer that learned one could otherwise pull the bytes
    // behind a picture it was never sent.
    if (!peer?.paired || !peer.connection) return false;

    const connection = peer.connection;

    await connection.send(
      StreamType.BLOB,
      sealOpaque(payload, connection.sessionKey, currentEpoch()),
    );

    return true;
  }

  /** Send our profile to one peer, on connecting or on being paired. */
  async sendProfileTo(
    connection: IConnection,
    encoded: Uint8Array,
  ): Promise<void> {
    await connection.send(
      StreamType.PROFILE,
      sealOpaque(encoded, connection.sessionKey, currentEpoch()),
    );
  }

  /**
   * Push a document's latest changes to everyone entitled to it.
   *
   * Reconciliation used to happen once, when a connection opened. That
   * makes a two-party chat work and quietly breaks a group: a message
   * reaching one member never travels onward, so with three people in a
   * star the middle node holds everything and the outer two each see
   * half a conversation, permanently and with nothing to indicate it.
   *
   * Calling this whenever a document changes locally is what makes
   * changes propagate — including onward from a node that merely
   * received them, which is the part a direct fan-out cannot do.
   *
   * Convergent and therefore self-limiting: once a peer is up to date
   * `syncDocument` yields nothing, so relaying does not loop.
   */
  async pushDocument(docId: string): Promise<void> {
    const sends: Array<Promise<void>> = [];

    for (const peer of this.deps.peers.listPairedConnected()) {
      const connection = peer.connection;
      if (!connection) continue;
      if (!this.deps.mayReceive?.(peer.did, docId)) continue;

      for (const frame of this.deps.syncEngine.syncDocument(peer.did, docId)) {
        sends.push(connection.send(StreamType.CRDT_SYNC, frame));
      }
    }

    await Promise.all(sends);
  }

  /** Route an inbound frame by sub-stream. */
  private async handleFrame(
    frame: Frame,
    connection: IConnection,
  ): Promise<void> {
    // Authorization gate for everything inbound.
    //
    // Completing a handshake proves only that the dialer holds the key it
    // presented — never that we chose to talk to them. Without this check
    // a stranger can push Automerge deltas into our documents, submit
    // membership frames, spend our voucher issuance quota, and inject
    // revocation gossip and RLN shares, purely by dialling us.
    //
    // Nothing legitimate is lost: pairing is out of band (RFC 001 §3.3),
    // so no wire traffic is needed to become paired. Peers that dial us
    // stay connected and silent until the application pairs them, at
    // which point every stream below opens at once.
    if (!this.isPaired(connection.peerDid)) return;

    try {
      switch (frame.header.streamType) {
        case StreamType.CRDT_SYNC:
          await this.handleSyncFrame(frame, connection);
          break;
        case StreamType.E2EE_MESSAGE:
          await this.handleMessageFrame(frame, connection);
          break;
        case StreamType.EPHEMERAL:
          this.handleEphemeralFrame(frame, connection);
          break;
        case StreamType.BLOB:
          await this.deps.onBlobFrame?.(
            connection.peerDid,
            openOpaque(frame.payload, connection.sessionKey),
          );
          break;
        case StreamType.PROFILE:
          await this.deps.onProfile?.(
            connection.peerDid,
            openOpaque(frame.payload, connection.sessionKey),
          );
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

  private handleEphemeralFrame(frame: Frame, connection: IConnection): void {
    const opened = openOpaque(frame.payload, connection.sessionKey);
    const { channelId, payload } = decodeEphemeral(opened);

    // Same membership rule as `0x02`. A signal is still a disclosure —
    // that someone is present, or typing — so it is gated identically.
    if (
      this.deps.knowsChannel?.(channelId) &&
      !this.deps.mayReceive?.(connection.peerDid, channelId)
    ) {
      return;
    }

    this.deps.onEphemeral?.(connection.peerDid, channelId, payload);
  }

  private async handleMessageFrame(
    frame: Frame,
    connection: IConnection,
  ): Promise<void> {
    const opened = openMessage(frame.payload, connection.sessionKey);

    // Membership gates inbound traffic too, but only for conversations
    // this node already has an opinion about.
    //
    // Checking only on the way out would leave a peer removed from a
    // conversation still able to write into it. Checking unconditionally
    // is worse: a channel that does not exist here yet has no
    // participants, so every *new* conversation a paired peer starts
    // would be refused — the first message of any chat, dropped.
    //
    // So: unknown channel means a new conversation from someone already
    // paired, and `recordLocally` records them as a participant. A known
    // channel means the list is authoritative.
    const { channelId } = opened.payload;
    if (
      this.deps.knowsChannel?.(channelId) &&
      !this.deps.mayReceive?.(connection.peerDid, channelId)
    ) {
      return;
    }

    await this.deps.onMessage(opened.payload);
  }
}

/** Length-prefixed channel id, then the opaque payload. */
function encodeEphemeral(channelId: string, payload: Uint8Array): Uint8Array {
  const id = new TextEncoder().encode(channelId);
  const out = new Uint8Array(2 + id.length + payload.length);

  new DataView(out.buffer).setUint16(0, id.length, false);
  out.set(id, 2);
  out.set(payload, 2 + id.length);

  return out;
}

function decodeEphemeral(bytes: Uint8Array): {
  channelId: string;
  payload: Uint8Array;
} {
  if (bytes.length < 2) throw new Error('Ephemeral frame is too short');

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const idLength = view.getUint16(0, false);

  if (bytes.length < 2 + idLength) {
    throw new Error('Ephemeral frame declares a channel id it does not carry');
  }

  return {
    channelId: new TextDecoder().decode(bytes.subarray(2, 2 + idLength)),
    payload: bytes.slice(2 + idLength),
  };
}
