/**
 * @dicsussion/transport
 *
 * Public API surface for the transport module.
 * Re-exports all types, codecs, identity, handshake, and transport abstractions.
 */
// Types & constants
export {
  ConnectionState,
  EPOCH_DURATION_S,
  FrameFlags,
  HANDSHAKE_TIMEOUT_MS,
  HEADER_SIZE,
  HOLE_PUNCH_TIMEOUT_MS,
  MAX_CLOCK_SKEW_S,
  MAX_DECOMPRESSED_SIZE,
  MDNS_BEACON_INTERVAL_MS,
  MDNS_SERVICE_ID,
  NONCE_EXPIRY_S,
  PROTOCOL_MAGIC,
  StreamType,
  TransportError,
  TransportException,
  VALID_STREAM_TYPES,
} from './types.js';

export type {
  Frame,
  FrameHeader,
  HandshakeAck,
  HandshakeChallenge,
  HandshakeInit,
  PeerTicket,
  StreamTypeValue,
} from './types.js';
// Identity (did:key)
export {
  didKeyToPublicKey,
  generateKeypair,
  publicKeyToDidKey,
  validateDidKey,
} from './did-key.js';

export type { Ed25519KeyPair } from './did-key.js';
// Frame codec
export {
  decodeFrame,
  decodeFrameHeader,
  encodeFrame,
  isPriorityFrame,
  validateChecksum,
} from './frame-codec.js';
// Handshake
export {
  calculateClockOffset,
  calculateEpoch,
  clearNonceRegistry,
  NonceRegistry,
  createHandshakeAck,
  createHandshakeInit,
  processHandshakeInit,
  verifyHandshakeAck,
  verifyHandshakeChallenge,
} from './handshake.js';
// Local transport implementation
export { clearTransportRegistry, LocalTransport } from './local-transport.js';
// Datagram backends (mDNS substrate)
export {
  clearDatagramBuses,
  InMemoryDatagramSocket,
  MDNS_MULTICAST_ADDRESS,
  MDNS_PORT,
  UdpMulticastSocket,
} from './datagram-socket.js';

export type {
  DatagramHandler,
  DatagramInfo,
  IDatagramSocket,
} from './datagram-socket.js';
// mDNS beacon record codec
export {
  decodeBeacon,
  encodeBeacon,
  MAX_BEACON_SIZE,
  MDNS_PROTOCOL_VERSION,
} from './mdns-record.js';

export type { MdnsBeacon } from './mdns-record.js';
// mDNS local network discovery (RFC 001 §4.1)
export { MdnsDiscovery } from './mdns-discovery.js';

export type {
  DiscoveredPeer,
  MdnsDiscoveryOptions,
  PeerHandler,
} from './mdns-discovery.js';
// NAT traversal & DERP relay failover (RFC 001 §4.2)
export { RelayFailoverManager } from './relay-failover.js';

export type {
  DirectAttempt,
  RelayAttempt,
  RelayFailoverOptions,
  RouteKind,
  TransportRoute,
} from './relay-failover.js';
// Priority preemption (RFC 001 §6)
export {
  isPriorityStream,
  orderFramesByPriority,
  PriorityFrameQueue,
} from './priority-queue.js';

export type { QueuedFrame } from './priority-queue.js';
// Real QUIC transport (Iroh) — the native module loads lazily, so
// importing this barrel does not require @number0/iroh to be present.
export { DICSUSSION_ALPN, IrohTransport } from './iroh-transport.js';

export type { IrohTransportOptions } from './iroh-transport.js';
export {
  CONTROL_STREAM_TAG,
  IrohConnection,
  STREAM_PRIORITY,
} from './iroh-connection.js';
export { FrameReader } from './frame-reader.js';
export {
  deriveTransportKey,
  TRANSPORT_KEY_INFO,
  transportPublicKey,
} from './transport-key.js';

export type { TransportKeyPair } from './transport-key.js';
// LZ4 frame compression (RFC 001 §3.4)
export {
  decompressPayload,
  maybeCompress,
  MIN_COMPRESSION_RATIO,
  MIN_COMPRESSION_SIZE,
} from './compression.js';

export type { CompressionResult } from './compression.js';
// Ticket serialization (RFC 001 §3.3)
export { decodeTicket, encodeTicket, TICKET_PREFIX } from './ticket-codec.js';
// Browser transport over a WebSocket relay (RFC 001 §4)
export {
  RELAY_HANDSHAKE_TIMEOUT_MS,
  WebSocketTransport,
} from './websocket-transport.js';

export type {
  WebSocketLike,
  WebSocketTransportOptions,
} from './websocket-transport.js';
export {
  decodeRelayMessage,
  encodeRelayMessage,
  MAX_RELAY_PAYLOAD,
  RelayMessageType,
} from './relay-protocol.js';

export type { RelayMessage, RelayMessageTypeValue } from './relay-protocol.js';
// Dependency-free event emitter (replaces node:events)
export { Emitter } from './emitter.js';

export type {
  ConnectionHandler,
  FrameHandler,
  IConnection,
  ITransport,
} from './transport-interface.js';
