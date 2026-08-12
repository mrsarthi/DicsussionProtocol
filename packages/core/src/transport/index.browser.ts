/**
 * @dicsussion/transport — browser barrel
 *
 * Same export surface as `index.ts`, minus the four modules that reach for
 * `node:dgram` and `node:events`: `iroh-transport`, `iroh-connection`,
 * `mdns-discovery`, and `datagram-socket`.
 *
 * See `../zk/index.browser.ts` for why real stub modules are required here
 * rather than a `browser: false` mapping, and for the rule the stubs obey.
 *
 * A browser cannot open a QUIC socket, join a multicast group, or accept an
 * inbound connection, so none of what is stubbed below could work regardless
 * of packaging. Use `WebSocketTransport`, which is exported unchanged.
 */

// ─── Unchanged: no Node dependency ───────────────────────────────────────
import { StreamType } from './types.js';

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

export {
  didKeyToPublicKey,
  generateKeypair,
  publicKeyToDidKey,
  validateDidKey,
} from './did-key.js';

export type { Ed25519KeyPair } from './did-key.js';

export {
  decodeFrame,
  decodeFrameHeader,
  encodeFrame,
  isPriorityFrame,
  validateChecksum,
} from './frame-codec.js';

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

export { clearTransportRegistry, LocalTransport } from './local-transport.js';

export {
  decodeBeacon,
  encodeBeacon,
  MAX_BEACON_SIZE,
  MDNS_PROTOCOL_VERSION,
} from './mdns-record.js';

export type { MdnsBeacon } from './mdns-record.js';

export { RelayFailoverManager } from './relay-failover.js';

export type {
  DirectAttempt,
  RelayAttempt,
  RelayFailoverOptions,
  RouteKind,
  TransportRoute,
} from './relay-failover.js';

export {
  isPriorityStream,
  orderFramesByPriority,
  PriorityFrameQueue,
} from './priority-queue.js';

export type { QueuedFrame } from './priority-queue.js';

export { FrameReader } from './frame-reader.js';

export {
  deriveTransportKey,
  TRANSPORT_KEY_INFO,
  transportPublicKey,
} from './transport-key.js';

export type { TransportKeyPair } from './transport-key.js';

export {
  decompressPayload,
  maybeCompress,
  MIN_COMPRESSION_RATIO,
  MIN_COMPRESSION_SIZE,
} from './compression.js';

export type { CompressionResult } from './compression.js';

export { decodeTicket, encodeTicket, TICKET_PREFIX } from './ticket-codec.js';

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

export { Emitter } from './emitter.js';

export type {
  ConnectionHandler,
  FrameHandler,
  IConnection,
  ITransport,
} from './transport-interface.js';

// Types erase at build time, so these are safe even though their
// implementations are not.
export type { IrohTransportOptions } from './iroh-transport.js';
export type {
  DatagramHandler,
  DatagramInfo,
  IDatagramSocket,
} from './datagram-socket.js';
export type {
  DiscoveredPeer,
  MdnsDiscoveryOptions,
  PeerHandler,
} from './mdns-discovery.js';

// ─── Mirrored constants ──────────────────────────────────────────────────
// Pure data living inside Node-only modules. Duplicated rather than
// imported, because importing would pull `node:dgram` back in.
//
// `tests/transport/browser-barrel-parity.spec.ts` asserts these stay equal
// to the Node barrel's values — duplication without a guard is how the two
// silently diverge.

/** @see datagram-socket.ts */
export const MDNS_MULTICAST_ADDRESS = '224.0.0.251';

/** @see datagram-socket.ts */
export const MDNS_PORT = 5353;

/** @see iroh-transport.ts */
export const DICSUSSION_ALPN = 'dicsussion/1';

/** @see iroh-connection.ts */
export const CONTROL_STREAM_TAG = 0x00;

/** @see iroh-connection.ts */
export const STREAM_PRIORITY: Record<number, number> = {
  [StreamType.REVOCATION_GOSSIP]: 100,
  [StreamType.RLN_SHARE_EXCHANGE]: 60,
  [StreamType.VOUCHER_HANDSHAKE]: 50,
  [StreamType.CRDT_SYNC]: 40,
  [StreamType.RLN_SIGNAL]: 30,
  [StreamType.E2EE_MESSAGE]: 20,
};

// ─── Stubs ───────────────────────────────────────────────────────────────

const NO_QUIC =
  'IrohTransport requires QUIC and a native module, neither of which a ' +
  'browser provides. Use WebSocketTransport instead — note it does not ' +
  'yet encrypt CRDT traffic from the relay operator.';

const NO_MULTICAST =
  'mDNS discovery requires UDP multicast, which browsers cannot open. ' +
  'Pair by ticket instead (encodeTicket / decodeTicket).';

/** Throws: no QUIC in a browser. */
export class IrohTransport {
  constructor() {
    throw new Error(NO_QUIC);
  }
}

/** Throws: no QUIC in a browser. */
export class IrohConnection {
  constructor() {
    throw new Error(NO_QUIC);
  }
}

/** Throws: no UDP multicast in a browser. */
export class MdnsDiscovery {
  constructor() {
    throw new Error(NO_MULTICAST);
  }
}

/** Throws: no UDP socket in a browser. */
export class UdpMulticastSocket {
  constructor() {
    throw new Error(NO_MULTICAST);
  }
}

/** Throws: lives beside the UDP backend, and is test-only regardless. */
export class InMemoryDatagramSocket {
  constructor() {
    throw new Error(NO_MULTICAST);
  }
}

/** No-op: there are no datagram buses to clear. */
export function clearDatagramBuses(): void {
  // Intentionally empty. Test cleanup helpers should be safe to call
  // anywhere, and there is no state here to reset.
}
