/**
 * @dicsussion/crypto — SecurityEnvelope Serialization
 *
 * Binary serialization/deserialization for the encrypted wire envelope
 * transmitted over Sub-Stream 0x02 per RFC 003 §6.1.
 *
 * Layout:
 *   [0]       version          u8   (0x01)
 *   [1..8]    epoch            u64  BE
 *   [9..10]   tier_threshold   u16  BE
 *   [11..42]  rln_nullifier    32 bytes
 *   [43..44]  zk_proof_len     u16  BE
 *   [45..N]   zk_proof         variable
 *   [N..N+32] ephemeral_pubkey 32 bytes
 *   [N+32..N+44] nonce         12 bytes
 *   [N+44..] ciphertext        remaining bytes
 */

import type { SecurityEnvelope } from './types.js';
import { PROTOCOL_VERSION } from './types.js';

/** Minimum envelope size: 1+8+2+32+2+0+32+12+0 = 89 bytes (empty proof+ciphertext). */
const MIN_ENVELOPE_SIZE = 89;

/**
 * Serialize a SecurityEnvelope to binary format.
 * Version field appears at offset 0 per RFC 003 §6.1.
 *
 * @param envelope The envelope to serialize.
 * @returns Binary representation as Uint8Array.
 */
export function serializeEnvelope(envelope: SecurityEnvelope): Uint8Array {
  const proofLen = envelope.zkProof.length;
  const totalLen =
    1 + 8 + 2 + 32 + 2 + proofLen + 32 + 12 + envelope.ciphertext.length;

  const buffer = new Uint8Array(totalLen);
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;

  // version (u8)
  view.setUint8(offset, envelope.version);
  offset += 1;

  // epoch (u64 BE) — split into high and low 32-bit words
  const epochHigh = Math.floor(envelope.epoch / 0x100000000);
  const epochLow = envelope.epoch >>> 0;
  view.setUint32(offset, epochHigh, false);
  view.setUint32(offset + 4, epochLow, false);
  offset += 8;

  // tier_threshold (u16 BE)
  view.setUint16(offset, envelope.tierThreshold, false);
  offset += 2;

  // rln_nullifier (32 bytes)
  buffer.set(envelope.rlnNullifier, offset);
  offset += 32;

  // zk_proof_len (u16 BE)
  view.setUint16(offset, proofLen, false);
  offset += 2;

  // zk_proof (variable)
  buffer.set(envelope.zkProof, offset);
  offset += proofLen;

  // ephemeral_pubkey (32 bytes)
  buffer.set(envelope.ephemeralPubkey, offset);
  offset += 32;

  // nonce (12 bytes)
  buffer.set(envelope.nonce, offset);
  offset += 12;

  // ciphertext (remaining)
  buffer.set(envelope.ciphertext, offset);

  return buffer;
}

/**
 * Deserialize a SecurityEnvelope from binary format using zero-copy views.
 *
 * @param buffer Binary envelope data.
 * @returns Parsed SecurityEnvelope.
 * @throws If the buffer is too small or version is unsupported.
 */
export function deserializeEnvelope(buffer: Uint8Array): SecurityEnvelope {
  if (buffer.length < MIN_ENVELOPE_SIZE) {
    throw new Error(
      `Envelope too small: ${buffer.length} < ${MIN_ENVELOPE_SIZE} bytes`,
    );
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let offset = 0;

  // version (u8)
  const version = view.getUint8(offset);
  offset += 1;

  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported envelope version: 0x${version.toString(16)}`);
  }

  // epoch (u64 BE)
  const epochHigh = view.getUint32(offset, false);
  const epochLow = view.getUint32(offset + 4, false);
  const epoch = epochHigh * 0x100000000 + epochLow;
  offset += 8;

  // tier_threshold (u16 BE)
  const tierThreshold = view.getUint16(offset, false);
  offset += 2;

  // Every field below is COPIED, not a view.
  //
  // `subarray` aliases the caller's buffer. A transport that pools or
  // reuses its receive buffer — the obvious optimisation, and one no
  // caller is stopped from making — would then mutate these fields under
  // any code still holding the envelope. For `nonce` that is
  // catastrophic: AES-GCM with a repeated (key, nonce) pair leaks the
  // XOR of both plaintexts and the authentication subkey.
  //
  // The copies cost one allocation per message and remove the whole
  // class of bug.
  const rlnNullifier = buffer.slice(offset, offset + 32);
  offset += 32;

  // zk_proof_len (u16 BE)
  const proofLen = view.getUint16(offset, false);
  offset += 2;

  if (offset + proofLen + 32 + 12 > buffer.length) {
    throw new Error('Envelope truncated: insufficient bytes for proof + key + nonce');
  }

  const zkProof = buffer.slice(offset, offset + proofLen);
  offset += proofLen;

  const ephemeralPubkey = buffer.slice(offset, offset + 32);
  offset += 32;

  const nonce = buffer.slice(offset, offset + 12);
  offset += 12;

  const ciphertext = buffer.slice(offset);

  return {
    version,
    epoch,
    tierThreshold,
    rlnNullifier,
    zkProof,
    ephemeralPubkey,
    nonce,
    ciphertext,
  };
}
