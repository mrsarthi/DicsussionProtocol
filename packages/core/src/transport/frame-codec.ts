/**
 * @dicsussion/transport — Wire Frame Codec
 *
 * 12-byte binary frame header encoder/decoder with CRC32-C checksums
 * and zero-copy payload extraction per RFC 001 §3.4.
 *
 * Header layout (12 bytes):
 *   [0..1]  magic       u16  Protocol identifier (0x5032)
 *   [2]     stream_type u8   Sub-protocol ID (0x01–0x06)
 *   [3]     flags       u8   Bit flags (compressed, priority)
 *   [4..7]  payload_len u32  Big-endian payload length
 *   [8..11] checksum    u32  CRC32-C of payload bytes
 */

import CRC32C from 'crc-32';

import {
  type Frame,
  type FrameHeader,
  type StreamTypeValue,
  FrameFlags,
  HEADER_SIZE,
  MAX_FRAME_PAYLOAD,
  PROTOCOL_MAGIC,
  TransportError,
  TransportException,
  VALID_STREAM_TYPES,
} from './types.js';

/**
 * Encode a payload into a complete wire frame with header.
 *
 * @param streamType Sub-protocol stream type (0x01–0x06).
 * @param payload Raw payload bytes.
 * @param flags Optional frame flags (compressed, priority).
 * @returns Complete frame buffer: 12-byte header + payload.
 */
export function encodeFrame(
  streamType: StreamTypeValue,
  payload: Uint8Array,
  flags: number = 0,
): Uint8Array {
  if (!VALID_STREAM_TYPES.has(streamType)) {
    throw new TransportException(
      TransportError.UnknownStreamType,
      `Invalid stream type: 0x${streamType.toString(16).padStart(2, '0')}`,
    );
  }

  const frame = new Uint8Array(HEADER_SIZE + payload.length);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

  // Magic (u16 BE)
  view.setUint16(0, PROTOCOL_MAGIC, false);

  // Stream type (u8)
  view.setUint8(2, streamType);

  // Flags (u8)
  view.setUint8(3, flags);

  // Payload length (u32 BE)
  view.setUint32(4, payload.length, false);

  // CRC32-C checksum of payload (u32 BE, stored as unsigned)
  const checksum = CRC32C.buf(payload) >>> 0;
  view.setUint32(8, checksum, false);

  // Copy payload after header
  frame.set(payload, HEADER_SIZE);

  return frame;
}

/**
 * Decode a frame header from a buffer using zero-copy views.
 *
 * @param buffer Buffer containing at least 12 bytes.
 * @returns Parsed FrameHeader.
 * @throws TransportException on invalid magic, unknown stream type, or buffer overrun.
 */
export function decodeFrameHeader(buffer: Uint8Array): FrameHeader {
  if (buffer.length < HEADER_SIZE) {
    throw new TransportException(
      TransportError.BufferOverrun,
      `Buffer too small for header: ${buffer.length} < ${HEADER_SIZE}`,
    );
  }

  // Zero-copy: create DataView over the existing buffer
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  const magic = view.getUint16(0, false);
  if (magic !== PROTOCOL_MAGIC) {
    throw new TransportException(
      TransportError.ChecksumMismatch,
      `Invalid magic: 0x${magic.toString(16).padStart(4, '0')}, expected 0x${PROTOCOL_MAGIC.toString(16).padStart(4, '0')}`,
    );
  }

  const streamType = view.getUint8(2) as StreamTypeValue;
  if (!VALID_STREAM_TYPES.has(streamType)) {
    throw new TransportException(
      TransportError.UnknownStreamType,
      `Unknown stream type: 0x${streamType.toString(16).padStart(2, '0')}`,
    );
  }

  const flags = view.getUint8(3);
  const payloadLen = view.getUint32(4, false);
  const checksum = view.getUint32(8, false);

  return { magic, streamType, flags, payloadLen, checksum };
}

/**
 * Decode a complete frame (header + payload) from a buffer using zero-copy views.
 *
 * @param buffer Buffer containing header + payload.
 * @returns Parsed Frame with zero-copy payload view.
 * @throws TransportException on validation failures.
 */
export function decodeFrame(buffer: Uint8Array): Frame {
  const header = decodeFrameHeader(buffer);

  // `payloadLen` is a u32 the sender chooses, so it is bounded before it
  // is used to size anything. Without this a peer can claim a 4 GB frame
  // and make a reassembling reader buffer toward it.
  if (header.payloadLen > MAX_FRAME_PAYLOAD) {
    throw new TransportException(
      TransportError.BufferOverrun,
      `Frame claims ${header.payloadLen} bytes, over the ${MAX_FRAME_PAYLOAD}-byte limit`,
    );
  }

  const totalRequired = HEADER_SIZE + header.payloadLen;
  if (buffer.length < totalRequired) {
    throw new TransportException(
      TransportError.BufferOverrun,
      `Buffer too small for payload: ${buffer.length} < ${totalRequired}`,
    );
  }

  // Zero-copy: extract payload as a subarray view (RFC 001 §3.4 requirement)
  const payload = buffer.subarray(HEADER_SIZE, HEADER_SIZE + header.payloadLen);

  // Validate CRC32-C checksum
  const computed = CRC32C.buf(payload) >>> 0;
  if (computed !== header.checksum) {
    throw new TransportException(
      TransportError.ChecksumMismatch,
      `CRC32-C mismatch: computed 0x${computed.toString(16)}, expected 0x${header.checksum.toString(16)}`,
    );
  }

  // NOTE: there is deliberately no decompression-bomb check here.
  //
  // The obvious one — comparing `payloadLen` against the *decompressed*
  // ceiling — measures the wrong quantity: a 100 KB compressed payload
  // that expands to 100 MB passes it. It read as protection while
  // providing none, which is worse than nothing.
  //
  // The real check is in `decompressPayload`, against the actual output
  // length, and `MAX_FRAME_PAYLOAD` above bounds the compressed side.
  return { header, payload };
}

/**
 * Validate a CRC32-C checksum against a payload.
 *
 * @param expectedChecksum The expected CRC32-C value.
 * @param payload The payload bytes to verify.
 * @returns True if the checksum matches.
 */
export function validateChecksum(expectedChecksum: number, payload: Uint8Array): boolean {
  const computed = CRC32C.buf(payload) >>> 0;
  return computed === expectedChecksum;
}

/**
 * Check if a frame has the priority flag set.
 * Stream 0x03 (Revocation Gossip) MUST be processed with higher priority (RFC 001 §6).
 */
export function isPriorityFrame(header: FrameHeader): boolean {
  return (
    (header.flags & FrameFlags.PRIORITY) !== 0 || header.streamType === 0x03
  );
}
