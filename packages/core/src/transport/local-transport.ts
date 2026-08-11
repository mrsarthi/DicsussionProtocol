/**
 * @dicsussion/transport — Local In-Process Transport
 *
 * EventEmitter-based transport implementing ITransport for Phase 1A testing.
 * Simulates QUIC stream multiplexing with asynchronous frame delivery
 * across all 6 sub-streams (0x01–0x06).
 *
 * Design constraints (from user review):
 * - Asynchronous delivery: frames are delivered via setImmediate, never
 *   synchronously in the same tick as send().
 * - Full sub-stream multiplexing support for all 6 stream types.
 */

import { Emitter } from './emitter.js';

import type { Ed25519KeyPair } from './did-key.js';
import { publicKeyToDidKey } from './did-key.js';
import { decodeFrame, encodeFrame } from './frame-codec.js';
import {
  calculateClockOffset,
  clearNonceRegistry,
  createHandshakeAck,
  createHandshakeInit,
  NonceRegistry,
  deriveSessionKey,
  HandshakeTag,
  transcriptFor,
  processHandshakeInit,
  verifyHandshakeAck,
  verifyHandshakeChallenge,
} from './handshake.js';
import { PriorityFrameQueue } from './priority-queue.js';
import type { ConnectionHandler, FrameHandler, IConnection, ITransport } from './transport-interface.js';
import type { Frame, PeerTicket, StreamTypeValue } from './types.js';
import { ConnectionState } from './types.js';

/**
 * Global registry of local transport instances for in-process peer discovery.
 * Maps did:key → LocalTransport instance.
 */
const localTransportRegistry = new Map<string, LocalTransport>();

/**
 * In-process connection between two local peers.
 */
class LocalConnection implements IConnection {
  private readonly frameEmitter = new Emitter<{ frame: [Frame] }>();
  private readonly sendQueue = new PriorityFrameQueue();
  private _state: ConnectionState = ConnectionState.Handshaking;
  private flushScheduled = false;

  constructor(
    public readonly peerDid: string,
    public readonly clockOffset: number,
    public readonly sessionKey: Uint8Array,
    private readonly remoteSend: (frame: Uint8Array) => void,
  ) {
    this._state = ConnectionState.Active;
  }

  get state(): ConnectionState {
    return this._state;
  }

  /** Frames still awaiting transmission on this connection. */
  get pendingFrames(): number {
    return this.sendQueue.size;
  }

  async send(
    streamType: StreamTypeValue,
    payload: Uint8Array,
    flags = 0,
  ): Promise<void> {
    if (this._state !== ConnectionState.Active) {
      throw new Error(`Cannot send on ${this._state} connection`);
    }

    const frameBytes = encodeFrame(streamType, payload, flags);

    // Frames buffer into a priority-banded queue rather than going out
    // immediately, so Stream 0x03 revocation gossip queued in the same
    // tick preempts Stream 0x02 chat traffic (RFC 001 §6).
    this.sendQueue.enqueue(streamType, frameBytes, flags);
    this.scheduleFlush();
  }

  /**
   * Drain the send queue on the next tick, in priority order.
   *
   * Delivery stays asynchronous — a frame is never handed to the remote
   * in the same tick as the `send()` that produced it.
   */
  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;

    setImmediate(() => {
      this.flushScheduled = false;
      if (this._state !== ConnectionState.Active) {
        this.sendQueue.clear();
        return;
      }

      for (const queued of this.sendQueue.drain()) {
        this.remoteSend(queued.bytes);
      }
    });
  }

  onFrame(handler: FrameHandler): () => void {
    const wrappedHandler = (frame: Frame) => handler(frame, this);
    this.frameEmitter.on('frame', wrappedHandler);
    return () => {
      this.frameEmitter.off('frame', wrappedHandler);
    };
  }

  /** Deliver a raw frame buffer to this connection's listeners. */
  _deliverFrame(frameBytes: Uint8Array): void {
    const frame = decodeFrame(frameBytes);
    this.frameEmitter.emit('frame', frame);
  }

  async close(): Promise<void> {
    if (this._state === ConnectionState.Disconnected) return;

    this._state = ConnectionState.Disconnected;
    this.sendQueue.clear();
    this.frameEmitter.removeAllListeners();

    // Wipe the session key rather than leaving it referenced for as long
    // as anything holds the connection.
    //
    // Best-effort, and deliberately not claimed as more: the runtime may
    // already have copied this buffer during HKDF, and those copies are
    // unreachable from here. What it does remove is the long-lived
    // reference that outlives the session — the one that ends up in heap
    // dumps and core files. Treat it as reducing exposure, not as
    // guaranteeing erasure.
    this.sessionKey.fill(0);
  }
}

/**
 * Local in-process transport for testing and development.
 *
 * Two LocalTransport instances in the same process can connect
 * to each other via the global registry, simulating P2P networking
 * with full frame codec, handshake, and multiplexing support.
 */
export class LocalTransport implements ITransport {
  private readonly connectionEmitter = new Emitter<{
    connection: [IConnection];
  }>();
  private readonly connections = new Map<string, LocalConnection>();
  /** Replay tracker scoped to this transport, not shared across instances. */
  private readonly nonces = new NonceRegistry();

  private readonly didKey: string;
  private closed = false;

  constructor(
    private readonly keypair: Ed25519KeyPair,
    private readonly clockOffsetS: number = 0,
  ) {
    this.didKey = publicKeyToDidKey(keypair.publicKey);
    localTransportRegistry.set(this.didKey, this);
  }

  /**
   * Get the did:key for this transport's node.
   */
  getDidKey(): string {
    return this.didKey;
  }

  async connect(ticket: PeerTicket): Promise<IConnection> {
    if (this.closed) {
      throw new Error('Transport is closed');
    }

    const remote = localTransportRegistry.get(ticket.didKey);
    if (!remote) {
      throw new Error(`No local transport found for ${ticket.didKey}`);
    }

    // Perform handshake
    const localTime = Math.floor(Date.now() / 1000) + this.clockOffsetS;
    const { init, ephemeralSecret } = createHandshakeInit(
      this.keypair,
      this.didKey,
      localTime,
    );

    const remoteTime = Math.floor(Date.now() / 1000) + remote.clockOffsetS;
    const { challenge, clockOffset, sessionKey } = processHandshakeInit(
      init,
      remote.keypair,
      remoteTime,
      remote.nonces,
    );

    // The transcript binds both identities, both nonces and both
    // ephemerals, so a signature can only ever validate for the pair it
    // was made for.
    const context = {
      initiatorDid: this.didKey,
      responderDid: ticket.didKey,
      initiatorNonce: init.nonce,
      responderNonce: challenge.nonce,
      initiatorEphemeral: init.ephemeralKey,
      responderEphemeral: challenge.ephemeralKey,
    };

    const remotePublicKey = remote.keypair.publicKey;
    if (!verifyHandshakeChallenge(challenge, remotePublicKey, context)) {
      throw new Error('Handshake challenge verification failed');
    }

    const ack = createHandshakeAck(this.keypair, context);

    if (!verifyHandshakeAck(ack, this.keypair.publicKey, context)) {
      throw new Error('Handshake ack verification failed');
    }

    // Both sides now hold the same session key. The initiator's
    // ephemeral secret has done its work and is wiped.
    const initiatorSessionKey = deriveSessionKey(
      ephemeralSecret,
      challenge.ephemeralKey,
      transcriptFor(HandshakeTag.ACK, context),
    );
    ephemeralSecret.fill(0);

    // Create bidirectional connection pair
    let remoteConnection: LocalConnection;

    const localConnection = new LocalConnection(
      ticket.didKey,
      clockOffset,
      initiatorSessionKey,
      (frameBytes: Uint8Array) => {
        // Asynchronous delivery to remote
        setImmediate(() => {
          remoteConnection._deliverFrame(frameBytes);
        });
      },
    );

    remoteConnection = new LocalConnection(
      this.didKey,
      -clockOffset,
      sessionKey,
      (frameBytes: Uint8Array) => {
        // Asynchronous delivery to local
        setImmediate(() => {
          localConnection._deliverFrame(frameBytes);
        });
      },
    );

    this.connections.set(ticket.didKey, localConnection);
    remote.connections.set(this.didKey, remoteConnection);

    // Notify remote transport of incoming connection (async)
    setImmediate(() => {
      remote.connectionEmitter.emit('connection', remoteConnection);
    });

    return localConnection;
  }

  onConnection(handler: ConnectionHandler): () => void {
    this.connectionEmitter.on('connection', handler);
    return () => {
      this.connectionEmitter.off('connection', handler);
    };
  }

  async close(): Promise<void> {
    this.closed = true;
    localTransportRegistry.delete(this.didKey);

    const closePromises = Array.from(this.connections.values()).map((c) => c.close());
    await Promise.all(closePromises);
    this.connections.clear();
    this.connectionEmitter.removeAllListeners();
  }
}

/**
 * Clear the global transport registry. Useful for test cleanup.
 */
export function clearTransportRegistry(): void {
  localTransportRegistry.clear();
  clearNonceRegistry();
}
