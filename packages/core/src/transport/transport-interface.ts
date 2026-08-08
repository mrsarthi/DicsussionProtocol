/**
 * @dicsussion/transport — Transport Interface
 *
 * Abstract ITransport and IConnection interfaces for pluggable
 * transport backends. Phase 1A uses a local in-process transport;
 * Iroh QUIC native bindings will implement this interface later.
 */

import type { Frame, PeerTicket, StreamTypeValue } from './types.js';
import { ConnectionState } from './types.js';

/** Callback for receiving incoming frames. */
export type FrameHandler = (frame: Frame, connection: IConnection) => void;

/** Callback for new incoming connections. */
export type ConnectionHandler = (connection: IConnection) => void;

/**
 * Represents a single peer-to-peer connection with multiplexed streams.
 */
export interface IConnection {
  /** The remote peer's did:key identifier. */
  readonly peerDid: string;

  /** Negotiated clock offset (Δ_peer) in seconds. */
  readonly clockOffset: number;

  /** Current connection state. */
  readonly state: ConnectionState;

  /**
   * Forward-secret key for this session (RFC 001 §5.1).
   *
   * Derived from both peers' ephemeral X25519 halves during the
   * handshake, and valid only for this connection. Both secrets are
   * wiped once it exists, so traffic sealed under it stays unreadable
   * even if both long-term identity keys are later compromised.
   */
  readonly sessionKey: Uint8Array;

  /**
   * Send a payload on a specific sub-stream.
   *
   * Frames are queued with priority banding: Stream `0x03` and any frame
   * carrying the PRIORITY flag preempt lower-priority traffic (RFC 001 §6).
   *
   * @param streamType Sub-protocol stream type (0x01–0x06).
   * @param payload Raw payload bytes to send.
   * @param flags Optional frame flags (compressed, priority).
   */
  send(streamType: StreamTypeValue, payload: Uint8Array, flags?: number): Promise<void>;

  /**
   * Register a handler for incoming frames on this connection.
   * @param handler Callback invoked for each received frame.
   * @returns Unsubscribe function.
   */
  onFrame(handler: FrameHandler): () => void;

  /**
   * Close the connection gracefully.
   */
  close(): Promise<void>;
}

/**
 * Transport layer abstraction for P2P networking.
 *
 * Implementations:
 * - `LocalTransport`: In-process EventEmitter (Phase 1A testing)
 * - Future: `IrohTransport`: Native Iroh QUIC via NAPI bindings
 */
export interface ITransport {
  /**
   * Connect to a remote peer using their ticket.
   * Performs handshake, clock sync, and stream setup.
   *
   * @param ticket The remote peer's connection ticket.
   * @returns An active connection to the peer.
   */
  connect(ticket: PeerTicket): Promise<IConnection>;

  /**
   * Register a handler for incoming connection requests.
   * @param handler Callback invoked when a new peer connects.
   * @returns Unsubscribe function.
   */
  onConnection(handler: ConnectionHandler): () => void;

  /**
   * Close the transport and all active connections.
   */
  close(): Promise<void>;
}

export { ConnectionState };
