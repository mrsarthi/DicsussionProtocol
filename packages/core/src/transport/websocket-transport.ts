/**
 * @dicsussion/transport — Browser transport over a WebSocket relay
 *
 * The second `ITransport`, and the one that makes a browser build
 * possible. Iroh is a native module with no WASM target, and a browser
 * cannot open a QUIC socket or accept an inbound connection at all — so
 * a browser peer is unreachable by any direct means.
 *
 * Both peers therefore hold a WebSocket to a relay, which forwards bytes
 * between them by `did:key` (see `relay-protocol.ts`).
 *
 * **What this costs, stated plainly.** Every byte goes through a third
 * party. The relay cannot read messages — payloads are sealed and the
 * RFC 001 §5 handshake runs end-to-end through it, so it cannot
 * impersonate a peer either. What it *does* learn is who talks to whom
 * and when, which is precisely the metadata a direct Iroh connection
 * hides. `IrohTransport` remains the better choice wherever it runs.
 */

import { Emitter } from './emitter.js';

import type { Ed25519KeyPair } from './did-key.js';
import { didKeyToPublicKey, publicKeyToDidKey } from './did-key.js';
import { decodeFrame, encodeFrame } from './frame-codec.js';
import { decodeControlJson, encodeControlJson } from './json-bytes.js';
import {
  calculateClockOffset,
  createHandshakeAck,
  createHandshakeInit,
  deriveSessionKey,
  HandshakeTag,
  transcriptFor,
  processHandshakeInit,
  verifyHandshakeAck,
  verifyHandshakeChallenge,
} from './handshake.js';
import type {
  HandshakeAck,
  HandshakeChallenge,
  HandshakeInit,
} from './types.js';

import { PriorityFrameQueue } from './priority-queue.js';
import {
  decodeRelayMessage,
  encodeRelayMessage,
  RelayMessageType,
} from './relay-protocol.js';
import type {
  ConnectionHandler,
  FrameHandler,
  IConnection,
  ITransport,
} from './transport-interface.js';
import type { Frame, PeerTicket, StreamTypeValue } from './types.js';
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

/** How long to wait for a dial or handshake step before giving up. */
export const RELAY_HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * The subset of `WebSocket` this transport uses.
 *
 * Structural rather than the DOM type, for the same reason as the
 * IndexedDB driver: a Node package must not pull `lib: ["DOM"]` into
 * scope, and re-declaring the global name would collide with consumers
 * who do compile with DOM. It also makes the transport testable without
 * a browser or a live relay.
 */
export interface WebSocketLike {
  binaryType: string;
  send(data: ArrayBufferView | ArrayBuffer): void;
  close(): void;
  onopen: (() => void) | null;
  onclose: (() => void) | null;
  onerror: ((error: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
}

export interface WebSocketTransportOptions {
  /** Relay endpoint, e.g. `wss://relay.example`. */
  readonly relayUrl: string;
  /** This node's Ed25519 identity, for the RFC 001 §5 handshake. */
  readonly identity: Ed25519KeyPair;
  /**
   * Socket factory. Defaults to `globalThis.WebSocket`, which exists in
   * browsers and in Node 22+.
   */
  readonly createSocket?: (url: string) => WebSocketLike;
  /** Handshake/dial timeout override. */
  readonly timeoutMs?: number;
}

/** A peer session multiplexed over the relay socket. */
class RelayConnection implements IConnection {
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

    // Queued rather than sent inline, so revocation gossip on 0x03
    // queued in the same tick still preempts 0x02 chat traffic — a
    // WebSocket gives no priority of its own (RFC 001 §6).
    this.sendQueue.enqueue(streamType, encodeFrame(streamType, payload, flags), flags);
    this.scheduleFlush();
  }

  onFrame(handler: FrameHandler): () => void {
    this.frameEmitter.on('frame', handler);
    return () => this.frameEmitter.off('frame', handler);
  }

  /** Feed inbound relay bytes to this session's subscribers. */
  ingest(bytes: Uint8Array): void {
    let frame: Frame;
    try {
      frame = decodeFrame(bytes);
    } catch {
      // A corrupt or hostile frame is dropped, never fatal (RFC 001 §7).
      return;
    }

    this.frameEmitter.emit('frame', frame, this);
  }

  async close(): Promise<void> {
    if (this._state === ConnectionState.Disconnected) return;

    this._state = ConnectionState.Disconnected;
    this.frameEmitter.removeAllListeners();
    this.onClose(this.peerDid);
  }

  /** Close without notifying the relay — used when the socket is gone. */
  markClosed(): void {
    this._state = ConnectionState.Disconnected;
    this.frameEmitter.removeAllListeners();
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

/**
 * `ITransport` over a WebSocket relay, for browsers and webviews.
 */
export class WebSocketTransport implements ITransport {
  private readonly connections = new Map<string, RelayConnection>();
  private readonly connectionHandlers = new Set<ConnectionHandler>();
  /** Dials awaiting their `OPENED`, keyed by peer did. */
  private readonly pendingDials = new Map<
    string,
    { resolve: () => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }
  >();
  /** Handshake messages awaiting a reader, keyed by peer did. */
  private readonly inboundControl = new Map<string, Uint8Array[]>();
  private readonly controlWaiters = new Map<string, (bytes: Uint8Array) => void>();

  private readonly timeoutMs: number;
  private socket: WebSocketLike | null = null;
  private ready: Promise<void> | null = null;
  private closed = false;

  readonly didKey: string;

  constructor(private readonly options: WebSocketTransportOptions) {
    this.didKey = publicKeyToDidKey(options.identity.publicKey);
    this.timeoutMs = options.timeoutMs ?? RELAY_HANDSHAKE_TIMEOUT_MS;
  }

  /**
   * Open the relay socket and register this node's did:key.
   *
   * Idempotent — every entry point awaits it, so callers never have to
   * sequence connect against transport startup.
   */
  async start(): Promise<void> {
    if (this.ready) return this.ready;

    this.ready = new Promise<void>((resolve, reject) => {
      const factory =
        this.options.createSocket ??
        ((url: string) =>
          new (globalThis as unknown as {
            WebSocket: new (url: string) => WebSocketLike;
          }).WebSocket(url));

      let socket: WebSocketLike;
      try {
        socket = factory(this.options.relayUrl);
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
        return;
      }

      socket.binaryType = 'arraybuffer';
      this.socket = socket;

      const timer = setTimeout(() => {
        reject(
          new Error(
            `Relay ${this.options.relayUrl} did not accept a connection within ${this.timeoutMs}ms`,
          ),
        );
      }, this.timeoutMs);
      unref(timer);

      socket.onopen = () => {
        clearTimeout(timer);
        this.sendEnvelope(RelayMessageType.REGISTER, this.didKey, EMPTY);
        resolve();
      };

      socket.onerror = (error) => {
        clearTimeout(timer);
        reject(
          error instanceof Error
            ? error
            : new Error(`Relay socket error: ${String(error)}`),
        );
      };

      socket.onclose = () => {
        clearTimeout(timer);
        this.handleSocketClosed();
      };

      socket.onmessage = (event) => this.handleMessage(event.data);
    });

    return this.ready;
  }

  /**
   * Dial a peer through the relay and run the RFC 001 §5 handshake.
   *
   * The ticket's `derpRelay` is ignored: both peers must already share
   * *this* relay to be reachable at all. Cross-relay routing would need
   * relays that federate, which this protocol does not define.
   */
  async connect(ticket: PeerTicket): Promise<IConnection> {
    await this.start();

    const existing = this.connections.get(ticket.didKey);
    if (existing && existing.state === ConnectionState.Active) return existing;

    await this.dial(ticket.didKey);

    // Dialer side of the three-message handshake. The challenge is what
    // proves the far side holds the Ed25519 secret behind its did:key —
    // without it the relay could answer for any peer it likes.
    const { init, ephemeralSecret } = createHandshakeInit(
      this.options.identity,
      this.didKey,
    );
    this.sendControl(ticket.didKey, init);

    const { challenge, timestamp } = await this.readControl<ChallengeMessage>(
      ticket.didKey,
    );

    // The ticket's nodeId is the did:key public half, so verifying the
    // challenge against it binds this relay session to the identity the
    // rest of the protocol trusts — not to whatever the relay claims.
    const context = {
      initiatorDid: this.didKey,
      responderDid: ticket.didKey,
      initiatorNonce: init.nonce,
      responderNonce: challenge.nonce,
      initiatorEphemeral: init.ephemeralKey,
      responderEphemeral: challenge.ephemeralKey,
    };

    if (!verifyHandshakeChallenge(challenge, ticket.nodeId, context)) {
      this.sendEnvelope(RelayMessageType.CLOSED, ticket.didKey, EMPTY);
      ephemeralSecret.fill(0);
      throw new Error(
        `Handshake with ${ticket.didKey} failed challenge verification`,
      );
    }

    this.sendControl(
      ticket.didKey,
      createHandshakeAck(this.options.identity, context),
    );

    const sessionKey = deriveSessionKey(
      ephemeralSecret,
      challenge.ephemeralKey,
      transcriptFor(HandshakeTag.ACK, context),
    );
    ephemeralSecret.fill(0);

    return this.establish(
      ticket.didKey,
      calculateClockOffset(timestamp, init.timestamp),
      sessionKey,
    );
  }

  onConnection(handler: ConnectionHandler): () => void {
    this.connectionHandlers.add(handler);
    return () => this.connectionHandlers.delete(handler);
  }

  async close(): Promise<void> {
    this.closed = true;

    for (const connection of this.connections.values()) {
      connection.markClosed();
    }
    this.connections.clear();

    for (const pending of this.pendingDials.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Transport closed'));
    }
    this.pendingDials.clear();
    this.controlWaiters.clear();
    this.inboundControl.clear();

    this.socket?.close();
    this.socket = null;
    this.ready = null;
  }

  /** Live sessions, for diagnostics. */
  get connectionCount(): number {
    return this.connections.size;
  }

  // ─── Relay plumbing ──────────────────────────────────────────────────

  private async dial(peerDid: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingDials.delete(peerDid);
        reject(
          new Error(`Relay did not open a session with ${peerDid} within ${this.timeoutMs}ms`),
        );
      }, this.timeoutMs);
      unref(timer);

      this.pendingDials.set(peerDid, { resolve, reject, timer });
      this.sendEnvelope(RelayMessageType.DIAL, peerDid, EMPTY);
    });
  }

  private handleMessage(data: unknown): void {
    const bytes = toBytes(data);
    if (!bytes) return;

    let message;
    try {
      message = decodeRelayMessage(bytes);
    } catch {
      // The relay is untrusted; a malformed envelope is dropped.
      return;
    }

    switch (message.type) {
      case RelayMessageType.OPENED: {
        const pending = this.pendingDials.get(message.did);
        if (pending) {
          clearTimeout(pending.timer);
          this.pendingDials.delete(message.did);
          pending.resolve();
        } else {
          // Inbound: a peer dialled us. Answer the handshake.
          void this.accept(message.did);
        }
        break;
      }

      case RelayMessageType.DATA:
        this.route(message.did, message.payload);
        break;

      case RelayMessageType.CLOSED: {
        const connection = this.connections.get(message.did);
        connection?.markClosed();
        this.connections.delete(message.did);

        const pending = this.pendingDials.get(message.did);
        if (pending) {
          clearTimeout(pending.timer);
          this.pendingDials.delete(message.did);
          pending.reject(new Error(`Relay refused a session with ${message.did}`));
        }
        break;
      }

      default:
        // REGISTER and DIAL are client→relay only.
        break;
    }
  }

  /** Accepter side of the handshake. */
  private async accept(peerDid: string): Promise<void> {
    try {
      const init = await this.readControl<HandshakeInit>(peerDid);

      // The relay chose the label on this session, so it could route a
      // handshake from one peer while naming another. Binding the two
      // together is what stops a relay attributing A's traffic to B.
      if (init.didKey !== peerDid) {
        this.sendEnvelope(RelayMessageType.CLOSED, peerDid, EMPTY);
        return;
      }

      const localTimestamp = Math.floor(Date.now() / 1000);
      const { challenge, clockOffset, sessionKey } = processHandshakeInit(
        init,
        this.options.identity,
        localTimestamp,
      );
      this.sendControl(peerDid, { challenge, timestamp: localTimestamp });

      const ack = await this.readControl<HandshakeAck>(peerDid);
      const context = {
        initiatorDid: init.didKey,
        responderDid: this.didKey,
        initiatorNonce: init.nonce,
        responderNonce: challenge.nonce,
        initiatorEphemeral: init.ephemeralKey,
        responderEphemeral: challenge.ephemeralKey,
      };

      if (!verifyHandshakeAck(ack, didKeyToPublicKey(init.didKey), context)) {
        this.sendEnvelope(RelayMessageType.CLOSED, peerDid, EMPTY);
        return;
      }

      const connection = this.establish(init.didKey, clockOffset, sessionKey);

      for (const handler of this.connectionHandlers) handler(connection);
    } catch {
      // A peer that fails or abandons the handshake simply gets no
      // session; it must not take the transport down with it.
      this.sendEnvelope(RelayMessageType.CLOSED, peerDid, EMPTY);
    }
  }

  private establish(
    peerDid: string,
    clockOffset: number,
    sessionKey: Uint8Array,
  ): RelayConnection {
    const connection = new RelayConnection(
      peerDid,
      clockOffset,
      sessionKey,
      (bytes) => this.sendEnvelope(RelayMessageType.DATA, peerDid, bytes),
      (did) => {
        this.connections.delete(did);
        this.sendEnvelope(RelayMessageType.CLOSED, did, EMPTY);
      },
    );

    connection.activate();
    this.connections.set(peerDid, connection);

    return connection;
  }

  /**
   * Deliver inbound bytes to a session, or hold them for the handshake.
   *
   * Handshake JSON and protocol frames share one relay stream, so a
   * session that does not exist yet means the bytes belong to the
   * handshake still in progress.
   */
  private route(peerDid: string, payload: Uint8Array): void {
    const connection = this.connections.get(peerDid);
    if (connection && connection.state === ConnectionState.Active) {
      connection.ingest(payload);
      return;
    }

    const waiter = this.controlWaiters.get(peerDid);
    if (waiter) {
      this.controlWaiters.delete(peerDid);
      waiter(payload);
      return;
    }

    // Arrived before anyone was reading; queue it rather than drop it —
    // the accepter registers its reader a tick after `OPENED`.
    const queued = this.inboundControl.get(peerDid) ?? [];
    queued.push(payload);
    this.inboundControl.set(peerDid, queued);
  }

  private sendControl(peerDid: string, message: unknown): void {
    // Must go through the shared codec: handshake nonces and signatures
    // are Uint8Arrays, and plain JSON silently turns them into objects.
    this.sendEnvelope(RelayMessageType.DATA, peerDid, encodeControlJson(message));
  }

  private async readControl<T>(peerDid: string): Promise<T> {
    const queued = this.inboundControl.get(peerDid);
    const bytes =
      queued && queued.length > 0
        ? queued.shift()!
        : await new Promise<Uint8Array>((resolve, reject) => {
            const timer = setTimeout(() => {
              this.controlWaiters.delete(peerDid);
              reject(
                new Error(`Handshake with ${peerDid} stalled for ${this.timeoutMs}ms`),
              );
            }, this.timeoutMs);
            unref(timer);

            this.controlWaiters.set(peerDid, (value) => {
              clearTimeout(timer);
              resolve(value);
            });
          });

    return decodeControlJson<T>(bytes);
  }

  private sendEnvelope(
    type: (typeof RelayMessageType)[keyof typeof RelayMessageType],
    did: string,
    payload: Uint8Array,
  ): void {
    if (this.closed || !this.socket) return;

    try {
      this.socket.send(encodeRelayMessage({ type, did, payload }));
    } catch {
      // A dead socket surfaces through `onclose`; a throw here must not
      // escape into a caller's send path.
    }
  }

  private handleSocketClosed(): void {
    for (const connection of this.connections.values()) {
      connection.markClosed();
    }
    this.connections.clear();

    for (const pending of this.pendingDials.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Relay socket closed'));
    }
    this.pendingDials.clear();

    this.ready = null;
    this.socket = null;
  }
}

const EMPTY = new Uint8Array(0);

/** Normalise whatever the socket hands us into bytes. */
function toBytes(data: unknown): Uint8Array | null {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  // Text frames are not part of this protocol.
  return null;
}

/** Keep timers from holding a Node process open; a no-op in browsers. */
function unref(timer: ReturnType<typeof setTimeout>): void {
  (timer as { unref?: () => void }).unref?.();
}
