/**
 * @dicsussion/transport — Type Definitions
 *
 * Wire protocol types, frame headers, peer addressing, handshake messages,
 * and error types per RFC 001.
 */

// ─── Sub-Protocol Stream Types (RFC 001 §6) ──────────────────────────────────

/** QUIC sub-stream protocol identifiers. */
export const StreamType = {
  /** Channel Membership & Automerge CRDT State Sync */
  CRDT_SYNC: 0x01,
  /** E2EE Encrypted Message Envelopes */
  E2EE_MESSAGE: 0x02,
  /** Key, Identity, & Slashing Revocation Gossip (HIGH PRIORITY) */
  REVOCATION_GOSSIP: 0x03,
  /** Synchronous Voucher Issuance Handshakes */
  VOUCHER_HANDSHAKE: 0x04,
  /** RLN Signal Broadcast */
  RLN_SIGNAL: 0x05,
  /** RLN Polynomial Share Exchange */
  RLN_SHARE_EXCHANGE: 0x06,
} as const;

export type StreamTypeValue = (typeof StreamType)[keyof typeof StreamType];

/** Set of all valid stream type values for validation. */
export const VALID_STREAM_TYPES = new Set<number>(Object.values(StreamType));

// ─── Frame Flags (RFC 001 §3.4) ──────────────────────────────────────────────

export const FrameFlags = {
  /** Payload is LZ4 compressed */
  COMPRESSED: 0x01,
  /** High priority frame */
  PRIORITY: 0x02,
} as const;

// ─── Wire Protocol Constants ─────────────────────────────────────────────────

/** Fixed protocol magic identifier (2 bytes). */
export const PROTOCOL_MAGIC = 0x5032;

/** Wire frame header size in bytes. */
export const HEADER_SIZE = 12;

/** Maximum LZ4 decompressed payload size (1 MB). */
export const MAX_DECOMPRESSED_SIZE = 1_048_576;

/** Handshake timeout in milliseconds. */
export const HANDSHAKE_TIMEOUT_MS = 5_000;

/** Maximum clock skew tolerance in seconds. */
export const MAX_CLOCK_SKEW_S = 10;

/** Nonce expiry window in seconds. */
export const NONCE_EXPIRY_S = 300;

/** Epoch duration in seconds. */
export const EPOCH_DURATION_S = 10;

/** DERP relay hole-punch timeout in milliseconds. */
export const HOLE_PUNCH_TIMEOUT_MS = 3_000;

/** mDNS beacon interval in milliseconds. */
export const MDNS_BEACON_INTERVAL_MS = 5_000;

/** mDNS service identifier. */
export const MDNS_SERVICE_ID = '_p2p-sync._udp.local';

// ─── Wire Frame Header (RFC 001 §3.4) ───────────────────────────────────────

/** Parsed 12-byte wire frame header. */
export interface FrameHeader {
  /** Fixed protocol identifier (0x5032). */
  readonly magic: number;
  /** Sub-protocol stream type (0x01–0x06). */
  readonly streamType: StreamTypeValue;
  /** Bit flags (compressed, priority). */
  readonly flags: number;
  /** Big-endian payload length in bytes. */
  readonly payloadLen: number;
  /** CRC32-C checksum of the payload bytes. */
  readonly checksum: number;
}

/** A complete wire frame: header + payload. */
export interface Frame {
  readonly header: FrameHeader;
  /** Raw payload bytes (zero-copy view into original buffer). */
  readonly payload: Uint8Array;
}

// ─── Peer Identity & Addressing (RFC 001 §3.2–3.3) ──────────────────────────

/**
 * Connection ticket for out-of-band peer pairing.
 * Serialized as Base64-encoded string.
 */
export interface PeerTicket {
  /** W3C did:key string (did:key:z6M...). */
  readonly didKey: string;
  /** Raw 32-byte Ed25519 public key. */
  readonly nodeId: Uint8Array;
  /** Direct endpoint addresses (e.g., "192.168.1.104:4242"). */
  readonly directAddresses: readonly string[];
  /** Optional Iroh DERP relay endpoint for fallback. */
  readonly derpRelay?: string;
  /**
   * Raw 32-byte transport public key — the peer's Iroh `EndpointId`.
   *
   * Derived from the identity key via domain-separated HKDF, so it
   * cannot be computed from `didKey` alone (derivation needs the
   * secret). It is therefore published here. Absent for transports that
   * do not use a separate key, such as `LocalTransport`.
   */
  readonly transportKey?: Uint8Array;
  /**
   * Raw 32-byte X25519 public key for E2EE.
   *
   * RFC 001 §3.3 calls a ticket an out-of-band *pairing* artifact, so it
   * carries everything needed to start an encrypted conversation. Without
   * this the recipient could dial the peer but not encrypt to them.
   */
  readonly encryptionKey?: Uint8Array;
}

// ─── Handshake Messages (RFC 001 §5) ─────────────────────────────────────────

export interface HandshakeInit {
  /** Unix timestamp (seconds) of the initiator. */
  readonly timestamp: number;
  /** Initiator's did:key string. */
  readonly didKey: string;
  /** 32-byte cryptographically secure random nonce. */
  readonly nonce: Uint8Array;
}

export interface HandshakeChallenge {
  /** Responder's 32-byte nonce. */
  readonly nonce: Uint8Array;
  /** Responder's Ed25519 signature over the initiator's nonce. */
  readonly signature: Uint8Array;
}

export interface HandshakeAck {
  /** Initiator's Ed25519 signature over the responder's nonce. */
  readonly signature: Uint8Array;
}

// ─── Connection State ────────────────────────────────────────────────────────

export enum ConnectionState {
  Connecting = 'connecting',
  Handshaking = 'handshaking',
  Active = 'active',
  Disconnected = 'disconnected',
}

// ─── Transport Errors (RFC 001 §7) ───────────────────────────────────────────

export enum TransportError {
  ClockSkewTooHigh = 'ClockSkewTooHigh',
  HolePunchTimeout = 'HolePunchTimeout',
  DerpRelayUnavailable = 'IrohDerpRelayUnavailable',
  ChecksumMismatch = 'ChecksumMismatch',
  DecompressionBomb = 'DecompressionBomb',
  BufferOverrun = 'BufferOverrun',
  UnknownStreamType = 'UnknownStreamType',
  HandshakeTimeout = 'HandshakeTimeout',
  ReplayRejected = 'ReplayRejected',
}

/** Typed transport error with code and message. */
export class TransportException extends Error {
  constructor(
    public readonly code: TransportError,
    message: string,
  ) {
    super(`[${code}] ${message}`);
    this.name = 'TransportException';
  }
}
