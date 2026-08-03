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
  createHandshakeAck,
  createHandshakeInit,
  processHandshakeInit,
  verifyHandshakeAck,
  verifyHandshakeChallenge,
} from './handshake.js';

// Transport interface
export type {
  ConnectionHandler,
  FrameHandler,
  IConnection,
  ITransport,
} from './transport-interface.js';

// Local transport implementation
export {
  clearTransportRegistry,
  LocalTransport,
} from './local-transport.js';

// Datagram backends (mDNS substrate)
export {
  clearDatagramBuses,
  InMemoryDatagramSocket,
  MDNS_MULTICAST_ADDRESS,
  MDNS_PORT,
  UdpMulticastSocket,
} from './datagram-socket.js';

export type { DatagramHandler, DatagramInfo, IDatagramSocket } from './datagram-socket.js';

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
