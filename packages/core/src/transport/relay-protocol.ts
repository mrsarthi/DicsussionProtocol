/**
 * @dicsussion/transport — Browser relay envelope
 *
 * The framing spoken between a browser peer and a relay server.
 *
 * A browser cannot open a QUIC socket or accept an inbound connection,
 * so it cannot run Iroh and cannot be dialled directly. A relay stands
 * in: both peers hold a WebSocket to it, and it forwards bytes between
 * them by `did:key`.
 *
 * **The relay is deliberately dumb, and that is the security argument.**
 * It sees only sealed frames, and the RFC 001 §5 handshake still runs
 * end-to-end through it — so a hostile relay can drop or delay traffic
 * but cannot read it, and cannot impersonate a peer whose Ed25519 key it
 * does not hold. It does learn who talks to whom, which is a real
 * metadata cost that direct Iroh connections avoid.
 *
 * This envelope is *not* the Dicsussion frame format. It wraps frames
 * for the relay hop only; the payload of a `DATA` envelope is exactly
 * the bytes `encodeFrame` produced.
 */

/** Envelope message types. */
export const RelayMessageType = {
  /** Client → relay: claim a did:key on this socket. */
  REGISTER: 0x01,
  /** Client → relay: open a session with the named peer. */
  DIAL: 0x02,
  /** Relay → client: a session with the named peer is open. */
  OPENED: 0x03,
  /** Either direction: frame bytes for/from the named peer. */
  DATA: 0x04,
  /** Either direction: the session with the named peer has ended. */
  CLOSED: 0x05,
} as const;

export type RelayMessageTypeValue =
  (typeof RelayMessageType)[keyof typeof RelayMessageType];

/** A decoded relay envelope. */
export interface RelayMessage {
  readonly type: RelayMessageTypeValue;
  /** Counterparty did:key — the target outbound, the source inbound. */
  readonly did: string;
  /** Frame bytes; empty for control messages. */
  readonly payload: Uint8Array;
}

/** Largest did:key we will encode or accept. */
const MAX_DID_BYTES = 1024;

/**
 * Largest relay payload, matching the frame codec's own ceiling.
 *
 * Bounded on decode as well as encode: a relay is untrusted, so a
 * length field it supplies must never be used to size an allocation
 * without a limit.
 */
export const MAX_RELAY_PAYLOAD = 16 * 1024 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Encode a relay envelope.
 *
 * Layout: type (1) ‖ didLen (2, big-endian) ‖ did ‖ payload.
 */
export function encodeRelayMessage(message: RelayMessage): Uint8Array {
  const did = encoder.encode(message.did);

  if (did.length > MAX_DID_BYTES) {
    throw new Error(`did:key too long for a relay envelope: ${did.length} bytes`);
  }
  if (message.payload.length > MAX_RELAY_PAYLOAD) {
    throw new Error(
      `Relay payload of ${message.payload.length} bytes exceeds the ${MAX_RELAY_PAYLOAD}-byte limit`,
    );
  }

  const out = new Uint8Array(3 + did.length + message.payload.length);
  out[0] = message.type;
  out[1] = (did.length >>> 8) & 0xff;
  out[2] = did.length & 0xff;
  out.set(did, 3);
  out.set(message.payload, 3 + did.length);

  return out;
}

/**
 * Decode a relay envelope.
 *
 * @throws If the bytes are truncated, over-long, or carry an unknown
 *   type. Callers drop the message rather than treating this as fatal —
 *   the peer on the far side of a relay is not trusted.
 */
export function decodeRelayMessage(bytes: Uint8Array): RelayMessage {
  if (bytes.length < 3) {
    throw new Error('Relay envelope shorter than its 3-byte header');
  }

  const type = bytes[0]!;
  if (!isRelayMessageType(type)) {
    throw new Error(`Unknown relay message type: 0x${type.toString(16)}`);
  }

  const didLen = (bytes[1]! << 8) | bytes[2]!;
  if (didLen > MAX_DID_BYTES) {
    throw new Error(`Relay envelope claims a ${didLen}-byte did:key`);
  }
  if (bytes.length < 3 + didLen) {
    throw new Error('Relay envelope truncated inside its did:key');
  }

  const payload = bytes.subarray(3 + didLen);
  if (payload.length > MAX_RELAY_PAYLOAD) {
    throw new Error(`Relay payload of ${payload.length} bytes exceeds the limit`);
  }

  let did: string;
  try {
    did = decoder.decode(bytes.subarray(3, 3 + didLen));
  } catch {
    throw new Error('Relay envelope did:key is not valid UTF-8');
  }

  // Copied, not a view: the caller keeps this past the lifetime of the
  // socket buffer it arrived in.
  return { type, did, payload: new Uint8Array(payload) };
}

function isRelayMessageType(value: number): value is RelayMessageTypeValue {
  return (
    value === RelayMessageType.REGISTER ||
    value === RelayMessageType.DIAL ||
    value === RelayMessageType.OPENED ||
    value === RelayMessageType.DATA ||
    value === RelayMessageType.CLOSED
  );
}
