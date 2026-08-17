/**
 * @dicsussion/transport — Bridged transport over a host-owned byte pipe
 *
 * The third `ITransport`, and the one that makes a native app possible.
 * `IrohTransport` needs `@number0/iroh`, a Node NAPI module that cannot
 * load in a webview; `WebSocketTransport` needs a relay to carry every
 * byte. A Tauri or React Native app has neither problem and the opposite
 * need: it already owns a real QUIC socket in its native layer, and only
 * lacks a way to hand those bytes to the protocol.
 *
 * This closes that gap. The host supplies {@link BridgePipe} — dial,
 * write, and three events — and the RFC 001 §5 handshake, session-key
 * derivation, framing, and priority all stay here, where they are tested.
 *
 * **What this costs, stated plainly.** A host pipe is one byte channel
 * per peer, so all six RFC 001 §6 sub-streams share it. Over Iroh's six
 * QUIC streams a large `0x01` CRDT delta cannot delay `0x03` revocation
 * gossip; over one pipe that guarantee weakens to send-queue ordering —
 * urgent frames jump the queue, but a frame already handed to the host
 * still finishes first. With frames capped at `MAX_DECOMPRESSED_SIZE`
 * that is a bounded delay rather than a stall.
 *
 * `IrohTransport` keeps the stronger guarantee and is preferred wherever
 * it runs. This transport exists because a webview cannot open a QUIC
 * socket at all.
 */

import type {
  BridgeAddresses,
  BridgeInbound,
  BridgePipe,
} from './bridge-pipe.js';
import type { Ed25519KeyPair } from './did-key.js';
import { didKeyToPublicKey, publicKeyToDidKey } from './did-key.js';
import { encodeFrame } from './frame-codec.js';
import { deriveTransportKey } from './transport-key.js';
import {
  calculateClockOffset,
  createHandshakeAck,
  createHandshakeInit,
  deriveSessionKey,
  HandshakeTag,
  NonceRegistry,
  processHandshakeInit,
  transcriptFor,
  verifyHandshakeAck,
  verifyHandshakeChallenge,
} from './handshake.js';
import { Emitter } from './emitter.js';
import { encodeControlMessage, PipeReader } from './pipe-reader.js';
import { PriorityFrameQueue } from './priority-queue.js';
import type {
  ConnectionHandler,
  FrameHandler,
  IConnection,
  ITransport,
} from './transport-interface.js';
import type {
  Frame,
  HandshakeAck,
  HandshakeChallenge,
  HandshakeInit,
  PeerTicket,
  StreamTypeValue,
} from './types.js';
import { ConnectionState } from './types.js';

/**
 * Challenge plus the responder's clock.
 *
 * `HandshakeChallenge` carries no timestamp, but the dialer needs one to
 * compute Δ_peer — so it rides alongside, exactly as on the Iroh path.
 */
interface ChallengeMessage {
  readonly challenge: HandshakeChallenge;
  readonly timestamp: number;
}

/** How long to wait for a handshake step before giving up. */
export const BRIDGE_HANDSHAKE_TIMEOUT_MS = 10_000;

export interface BridgedTransportOptions {
  /** This node's Ed25519 identity, for the RFC 001 §5 handshake. */
  readonly identity: Ed25519KeyPair;
  /** Handshake timeout override. */
  readonly timeoutMs?: number;
}

/** A live session over one host-owned byte channel. */
class BridgedConnection implements IConnection {
  private readonly frameEmitter = new Emitter<{ frame: [Frame, IConnection] }>();
  private readonly sendQueue = new PriorityFrameQueue();
  private _state: ConnectionState = ConnectionState.Handshaking;
  private flushScheduled = false;

  constructor(
    public readonly peerDid: string,
    public readonly clockOffset: number,
    public readonly sessionKey: Uint8Array,
    private readonly deliver: (bytes: Uint8Array) => void,
    private readonly onClose: (peerDid: string) => void,
  ) {}

  get state(): ConnectionState {
    return this._state;
  }

  /** Frames still awaiting transmission. */
  get pendingFrames(): number {
    return this.sendQueue.size;
  }

  /** Mark the session live once the handshake completes. */
  activate(): void {
    this._state = ConnectionState.Active;
  }

  async send(
    streamType: StreamTypeValue,
    payload: Uint8Array,
    flags = 0,
  ): Promise<void> {
    if (this._state !== ConnectionState.Active) {
      throw new Error(`Cannot send on ${this._state} connection`);
    }

    // Queued rather than written inline: one flat pipe has no priority of
    // its own, so this is the only place RFC 001 §6 banding can happen.
    this.sendQueue.enqueue(streamType, encodeFrame(streamType, payload, flags), flags);
    this.scheduleFlush();
  }

  onFrame(handler: FrameHandler): () => void {
    this.frameEmitter.on('frame', handler);
    return () => this.frameEmitter.off('frame', handler);
  }

  /** Hand reassembled frames to this session's subscribers. */
  ingest(frames: Frame[]): void {
    for (const frame of frames) this.frameEmitter.emit('frame', frame, this);
  }

  async close(): Promise<void> {
    if (this._state === ConnectionState.Disconnected) return;

    this._state = ConnectionState.Disconnected;
    this.frameEmitter.removeAllListeners();

    // Best-effort wipe — see LocalConnection.close() for why this is not
    // a guarantee of erasure.
    this.sessionKey.fill(0);
    this.onClose(this.peerDid);
  }

  /** Close without asking the host to tear down — it already has. */
  markClosed(): void {
    if (this._state === ConnectionState.Disconnected) return;

    this._state = ConnectionState.Disconnected;
    this.frameEmitter.removeAllListeners();
    this.sessionKey.fill(0);
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;

    queueMicrotask(() => {
      this.flushScheduled = false;

      for (;;) {
        const next = this.sendQueue.dequeue();
        if (!next) break;
        this.deliver(next.bytes);
      }
    });
  }
}

/** Per-connection state held while, and after, the handshake runs. */
interface Channel {
  readonly reader: PipeReader;
  connection: BridgedConnection | null;
}

class BridgedTransport implements ITransport {
  private readonly nonces = new NonceRegistry();
  private readonly channels = new Map<string, Channel>();
  private readonly byPeer = new Map<string, string>();
  private readonly connectionHandlers = new Set<ConnectionHandler>();
  private readonly unsubscribes: Array<() => void> = [];
  private readonly timeoutMs: number;
  private readonly didKey: string;
  private closed = false;

  /** Last reachability snapshot from the host; see `getTicket`. */
  private addresses: BridgeAddresses = { directAddresses: [] };

  constructor(
    private readonly pipe: BridgePipe,
    private readonly options: BridgedTransportOptions,
  ) {
    this.didKey = publicKeyToDidKey(options.identity.publicKey);
    this.timeoutMs = options.timeoutMs ?? BRIDGE_HANDSHAKE_TIMEOUT_MS;

    this.unsubscribes.push(
      this.pipe.onData((id, bytes) => this.channelFor(id).reader.push(bytes)),
      this.pipe.onInbound((id, info) => void this.accept(id, info)),
      this.pipe.onClosed((id) => this.teardown(id)),
    );

    // Warm the cache immediately, so `getTicket()` is not silently
    // address-less until someone thinks to refresh. Fire-and-forget
    // because construction is synchronous: a host that is not ready to
    // answer yet simply leaves the snapshot empty, and callers that need
    // a dialable ticket still await `refreshAddresses()` first.
    void this.refreshAddresses().catch(() => {
      // A host with no addresses to report yet is not an error.
    });
  }

  async connect(ticket: PeerTicket): Promise<IConnection> {
    if (this.closed) throw new Error('Transport is closed');

    const existing = this.byPeer.get(ticket.didKey);
    const live = existing ? this.channels.get(existing)?.connection : null;
    if (live && live.state === ConnectionState.Active) return live;

    if (!ticket.transportKey) {
      throw new Error(
        `Ticket for ${ticket.didKey} carries no transport key; nothing to dial`,
      );
    }

    const connectionId = await this.pipe.connect({
      transportKey: ticket.transportKey,
      directAddresses: ticket.directAddresses,
      ...(ticket.derpRelay ? { relayUrl: ticket.derpRelay } : {}),
    });

    const channel = this.channelFor(connectionId);

    // Dialer side of the three-message handshake. The challenge is what
    // proves the far side holds the Ed25519 secret behind its did:key —
    // the host authenticated a transport key, which says nothing about
    // who owns the identity.
    const { init, ephemeralSecret } = createHandshakeInit(
      this.options.identity,
      this.didKey,
    );

    // `finally`, not a wipe at each exit: `readControl` rejects on
    // timeout or a dropped pipe, and neither is rare on a real network.
    // The X25519 secret would otherwise stay live in the heap until GC,
    // which is the one place forward secrecy assumes it is not.
    try {
      await this.write(connectionId, encodeControlMessage(init));

      const { challenge, timestamp } =
        await channel.reader.readControl<ChallengeMessage>(this.timeoutMs);

      const context = {
        initiatorDid: this.didKey,
        responderDid: ticket.didKey,
        initiatorNonce: init.nonce,
        responderNonce: challenge.nonce,
        initiatorEphemeral: init.ephemeralKey,
        responderEphemeral: challenge.ephemeralKey,
      };

      // The ticket's nodeId is the did:key public half, so verifying
      // against it binds this pipe to the identity the rest of the
      // protocol trusts — not to whatever the host handed us.
      if (!verifyHandshakeChallenge(challenge, ticket.nodeId, context)) {
        await this.drop(connectionId);
        throw new Error(
          `Handshake with ${ticket.didKey} failed challenge verification`,
        );
      }

      await this.write(
        connectionId,
        encodeControlMessage(createHandshakeAck(this.options.identity, context)),
      );

      const sessionKey = deriveSessionKey(
        ephemeralSecret,
        challenge.ephemeralKey,
        transcriptFor(HandshakeTag.ACK, context),
      );

      return this.establish(
        connectionId,
        ticket.didKey,
        calculateClockOffset(timestamp, init.timestamp),
        sessionKey,
      );
    } finally {
      ephemeralSecret.fill(0);
    }
  }

  onConnection(handler: ConnectionHandler): () => void {
    this.connectionHandlers.add(handler);
    return () => this.connectionHandlers.delete(handler);
  }

  /**
   * A ticket peers can dial, assembled from both halves.
   *
   * The transport key is derived from the identity by one-way HKDF, so
   * only this side can compute it; the addresses behind it are known
   * only to the host. Neither half alone is dialable.
   *
   * Synchronous, and therefore served from the last snapshot the host
   * gave us — matching `IrohTransport.getTicket`, which likewise reads
   * cached endpoint state. Call {@link refreshAddresses} first when the
   * ticket is about to be published, because address discovery is not
   * instant: a public address arrives from STUN some time after the
   * socket binds, and a ticket taken before that carries LAN addresses
   * only and is undialable from any other network.
   */
  getTicket(): PeerTicket {
    return {
      didKey: this.didKey,
      nodeId: this.options.identity.publicKey,
      directAddresses: this.addresses.directAddresses,
      transportKey: deriveTransportKey(this.options.identity).publicKey,
      ...(this.addresses.relayUrl ? { derpRelay: this.addresses.relayUrl } : {}),
    };
  }

  /**
   * Re-read how the host says this node is reachable.
   *
   * @returns The refreshed snapshot, also cached for {@link getTicket}.
   */
  async refreshAddresses(): Promise<BridgeAddresses> {
    this.addresses = await this.pipe.addresses();
    return this.addresses;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    for (const unsubscribe of this.unsubscribes) unsubscribe();

    for (const channel of this.channels.values()) {
      channel.reader.fail('Transport closed');
      channel.connection?.markClosed();
    }

    this.channels.clear();
    this.byPeer.clear();
    this.connectionHandlers.clear();

    await this.pipe.close();
  }

  get connectionCount(): number {
    let count = 0;
    for (const channel of this.channels.values()) {
      if (channel.connection?.state === ConnectionState.Active) count++;
    }
    return count;
  }

  /** Accepter side of the handshake. */
  private async accept(connectionId: string, _info: BridgeInbound): Promise<void> {
    // An inbound notification announces a *new* connection, so start from
    // a clean reader even if this id has been seen before. Hosts are free
    // to recycle ids, and a carried-over reader would already be in frame
    // mode — sending the new handshake to the frame parser, where it
    // simply never arrives. The failure surfaces as a handshake timeout
    // on a connection that looks otherwise healthy.
    this.teardown(connectionId);
    const channel = this.channelFor(connectionId);

    try {
      const init = await channel.reader.readControl<HandshakeInit>(this.timeoutMs);

      const localTimestamp = Math.floor(Date.now() / 1000);
      const { challenge, clockOffset, sessionKey } = processHandshakeInit(
        init,
        this.options.identity,
        localTimestamp,
        this.nonces,
      );

      await this.write(
        connectionId,
        encodeControlMessage({ challenge, timestamp: localTimestamp }),
      );

      const ack = await channel.reader.readControl<HandshakeAck>(this.timeoutMs);
      const context = {
        initiatorDid: init.didKey,
        responderDid: this.didKey,
        initiatorNonce: init.nonce,
        responderNonce: challenge.nonce,
        initiatorEphemeral: init.ephemeralKey,
        responderEphemeral: challenge.ephemeralKey,
      };

      if (!verifyHandshakeAck(ack, didKeyToPublicKey(init.didKey), context)) {
        await this.drop(connectionId);
        return;
      }

      const connection = this.establish(
        connectionId,
        init.didKey,
        clockOffset,
        sessionKey,
      );

      for (const handler of this.connectionHandlers) handler(connection);
    } catch {
      // A peer that fails or abandons the handshake simply gets no
      // session; it must not take the transport down with it.
      await this.drop(connectionId);
    }
  }

  private establish(
    connectionId: string,
    peerDid: string,
    clockOffset: number,
    sessionKey: Uint8Array,
  ): BridgedConnection {
    const channel = this.channelFor(connectionId);

    const connection = new BridgedConnection(
      peerDid,
      clockOffset,
      sessionKey,
      (bytes) => void this.write(connectionId, bytes),
      () => void this.drop(connectionId),
    );

    channel.connection = connection;
    this.byPeer.set(peerDid, connectionId);

    // Must precede `activate()`: bytes already buffered behind the ack
    // are dispatched synchronously from here.
    channel.reader.switchToFrames((frames) => connection.ingest(frames));
    connection.activate();

    return connection;
  }

  private channelFor(connectionId: string): Channel {
    let channel = this.channels.get(connectionId);
    if (!channel) {
      channel = { reader: new PipeReader(), connection: null };
      this.channels.set(connectionId, channel);
    }
    return channel;
  }

  private async write(connectionId: string, bytes: Uint8Array): Promise<void> {
    if (this.closed) return;
    await this.pipe.send(connectionId, bytes);
  }

  /** Tear a connection down and tell the host. */
  private async drop(connectionId: string): Promise<void> {
    this.teardown(connectionId);
    try {
      await this.pipe.disconnect(connectionId);
    } catch {
      // The host may already have discarded it; nothing left to do.
    }
  }

  /** Forget a connection the host has closed. */
  private teardown(connectionId: string): void {
    const channel = this.channels.get(connectionId);
    if (!channel) return;

    this.channels.delete(connectionId);
    channel.reader.fail('Connection closed');
    channel.reader.reset();

    const peerDid = channel.connection?.peerDid;
    if (peerDid && this.byPeer.get(peerDid) === connectionId) {
      this.byPeer.delete(peerDid);
    }

    channel.connection?.markClosed();
  }
}

/**
 * Build an `ITransport` over a host-supplied byte pipe.
 *
 * @param pipe The host's byte channel. See {@link BridgePipe} for the
 *   contract — ordered bytes, boundaries not preserved.
 * @param options This node's identity, and an optional handshake timeout.
 */
export function createBridgedTransport(
  pipe: BridgePipe,
  options: BridgedTransportOptions,
): ITransport {
  return new BridgedTransport(pipe, options);
}
