/**
 * @dicsussion/transport — Handshake Protocol
 *
 * Mutually authenticated handshake sequence with clock synchronization,
 * nonce replay protection, and timeout enforcement per RFC 001 §5.
 *
 * Sequence:
 *   A → B: HandshakeInit { timestamp, did_key, nonce_a }
 *   B → A: HandshakeChallenge { nonce_b, sig_b(nonce_a) }
 *   A → B: HandshakeAck { sig_a(nonce_b) }
 */


import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import type { Ed25519KeyPair } from './did-key.js';
import { publicKeyToDidKey } from './did-key.js';
import type { HandshakeAck, HandshakeChallenge, HandshakeInit } from './types.js';
import {
  EPOCH_DURATION_S,
  MAX_CLOCK_SKEW_S,
  NONCE_EXPIRY_S,
  TransportError,
  TransportException,
} from './types.js';

/**
 * Hard ceiling on tracked nonces.
 *
 * Entries live for `NONCE_EXPIRY_S` (5 minutes) and are pruned only when
 * a handshake arrives, so an attacker sending inits at line rate could
 * otherwise grow this without bound for the whole window. At 20k entries
 * (~1.5 MB of keys) the oldest are evicted instead.
 *
 * Evicting early slightly weakens replay protection for the dropped
 * nonces — but a peer that can flood 20k handshakes in five minutes can
 * simply replay in real time anyway, and unbounded memory is the worse
 * failure.
 */
const MAX_TRACKED_NONCES = 20_000;

/**
 * Per-node replay tracker: nonce hex → timestamp of receipt.
 *
 * **Instance-scoped, deliberately.** This was module-level state, which
 * meant every `DicsussionClient` in a process shared one registry. Nothing
 * was exploitable — 32-byte random nonces do not collide across peers, so
 * no legitimate handshake was ever rejected because of a neighbour — but
 * it coupled instances that should be independent: a multi-tenant host,
 * an app embedding several nodes, and the test suite all shared one map.
 * `clearNonceRegistry()` existed solely so tests could work around it,
 * which is the tell.
 *
 * Each transport now owns one. Dropping the transport drops its nonces
 * with it, rather than leaving them attached to the module for the life
 * of the process.
 */
export class NonceRegistry {
  private readonly seen = new Map<string, number>();

  /** Tracked entries, after any pruning that has occurred. */
  get size(): number {
    return this.seen.size;
  }

  /**
   * Record a nonce, rejecting it if already seen.
   *
   * @param nonceHex Hex encoding of the 32-byte nonce.
   * @param nowS Current unix time in seconds.
   * @throws {TransportException} If this nonce was already recorded.
   */
  admit(nonceHex: string, nowS: number): void {
    this.prune(nowS);

    // Check and insert stay adjacent and synchronous — see the note in
    // `processHandshakeInit` on why an `await` between them would open a
    // real TOCTOU window.
    if (this.seen.has(nonceHex)) {
      throw new TransportException(
        TransportError.ReplayRejected,
        'Nonce replay detected',
      );
    }

    this.seen.set(nonceHex, nowS);
  }

  /** Drop expired entries, then evict oldest-first if still over the cap. */
  prune(nowS: number): void {
    for (const [key, timestamp] of this.seen) {
      if (nowS - timestamp > NONCE_EXPIRY_S) {
        this.seen.delete(key);
      }
    }

    // Map iterates in insertion order, so the front is the oldest.
    if (this.seen.size > MAX_TRACKED_NONCES) {
      const excess = this.seen.size - MAX_TRACKED_NONCES;
      let dropped = 0;

      for (const key of this.seen.keys()) {
        this.seen.delete(key);
        if (++dropped >= excess) break;
      }
    }
  }

  /** Forget every tracked nonce. */
  clear(): void {
    this.seen.clear();
  }
}

/**
 * Registry used when a caller supplies none.
 *
 * Kept so `processHandshakeInit` stays callable with three arguments —
 * transports pass their own, and only ad-hoc callers land here.
 */
const defaultNonceRegistry = new NonceRegistry();

const encoder = new TextEncoder();

/** Domain separation for the per-session message key. */
const SESSION_KEY_LABEL = encoder.encode('dicsussion/session-key/v1');

/** Distinguishes the two signatures so neither can be replayed as the other. */
const TRANSCRIPT_TAG = { CHALLENGE: 0x01, ACK: 0x02 } as const;

/**
 * The bytes both sides sign, and the value the session key is bound to.
 *
 * Everything that identifies this exchange goes in: **both did:keys,
 * both nonces, both ephemeral keys**, under a domain label and a
 * per-message tag.
 *
 * Signing only the nonce would leave the ephemerals unauthenticated —
 * an on-path attacker could swap in its own and read the session. But
 * signing the ephemerals alone is not enough either: without the
 * identities, the agreed key is not bound to *who* agreed it, which
 * permits an unknown-key-share. An attacker M who is a known peer of V
 * can relay V's ephemeral to T under V's name, forward V's ack, and
 * leave T sharing a key with V while V believes it is talking to M.
 * Neither signature would have covered the discrepancy.
 *
 * Length-prefixing each field keeps the encoding unambiguous — without
 * it, adjacent variable-length values could be re-split to produce the
 * same bytes from different inputs.
 */
function transcript(
  tag: number,
  initiatorDid: string,
  responderDid: string,
  initiatorNonce: Uint8Array,
  responderNonce: Uint8Array,
  initiatorEphemeral: Uint8Array,
  responderEphemeral: Uint8Array,
): Uint8Array {
  const parts: Uint8Array[] = [
    encoder.encode('dicsussion/handshake/v1'),
    new Uint8Array([tag]),
    encoder.encode(initiatorDid),
    encoder.encode(responderDid),
    initiatorNonce,
    responderNonce,
    initiatorEphemeral,
    responderEphemeral,
  ];

  const total = parts.reduce((sum, part) => sum + 4 + part.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);

  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}

/**
 * Everything that identifies one handshake.
 *
 * Passed as a unit so no caller can accidentally bind a signature to a
 * subset of it — omitting a field is exactly how the unknown-key-share
 * above became possible.
 */
export interface HandshakeContext {
  readonly initiatorDid: string;
  readonly responderDid: string;
  readonly initiatorNonce: Uint8Array;
  readonly responderNonce: Uint8Array;
  readonly initiatorEphemeral: Uint8Array;
  readonly responderEphemeral: Uint8Array;
}

/** Build the transcript for one message type from a context. */
export function transcriptFor(
  tag: number,
  context: HandshakeContext,
): Uint8Array {
  return transcript(
    tag,
    context.initiatorDid,
    context.responderDid,
    context.initiatorNonce,
    context.responderNonce,
    context.initiatorEphemeral,
    context.responderEphemeral,
  );
}

/** Tag values, exported so transports can build the ACK-bound key. */
export const HandshakeTag = TRANSCRIPT_TAG;

/**
 * Derive the session message key from the two ephemeral halves.
 *
 * This is the whole forward-secrecy story: the key exists only while
 * both secrets do. Discard them at close and the session's traffic is
 * unrecoverable, even to someone who later steals both long-term keys.
 */
export function deriveSessionKey(
  myEphemeralSecret: Uint8Array,
  theirEphemeralPublic: Uint8Array,
  boundTranscript: Uint8Array,
): Uint8Array {
  const shared = x25519.getSharedSecret(myEphemeralSecret, theirEphemeralPublic);

  // The transcript goes into `info`, so the key itself — not merely the
  // signatures over it — is bound to the identity pair. Two peers who
  // disagree about who they are talking to derive different keys and
  // simply fail to communicate, rather than sharing a key under a
  // mistaken belief about the counterparty.
  const info = new Uint8Array(SESSION_KEY_LABEL.length + boundTranscript.length);
  info.set(SESSION_KEY_LABEL, 0);
  info.set(boundTranscript, SESSION_KEY_LABEL.length);

  return hkdf(sha256, shared, undefined, info, 32);
}

/** Convert Uint8Array to hex string for map key. */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create a HandshakeInit message with a fresh 32-byte nonce.
 *
 * @param keypair The initiator's Ed25519 keypair.
 * @param didKey The initiator's did:key string.
 * @param timestampS Optional unix timestamp in seconds (defaults to now).
 */
export function createHandshakeInit(
  keypair: Ed25519KeyPair,
  didKey: string,
  timestampS?: number,
): { init: HandshakeInit; ephemeralSecret: Uint8Array } {
  void keypair; // keypair used for later signing, included for API consistency
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  const timestamp = timestampS ?? Math.floor(Date.now() / 1000);

  // The secret half is returned to the caller, never sent. It lives as
  // long as the connection and no longer.
  const ephemeralSecret = x25519.utils.randomSecretKey();
  const ephemeralKey = x25519.getPublicKey(ephemeralSecret);

  return {
    init: { timestamp, didKey, nonce, ephemeralKey },
    ephemeralSecret,
  };
}

/**
 * Process an incoming HandshakeInit and produce a HandshakeChallenge.
 *
 * Validates:
 * - Clock skew ≤ 10 seconds
 * - Nonce not replayed
 * - Nonce not expired (age ≤ 300 seconds)
 *
 * @param init The received HandshakeInit.
 * @param responderKeypair Responder's Ed25519 keypair for signing.
 * @param localTimestampS Optional local unix timestamp in seconds.
 * @returns The HandshakeChallenge and computed clock offset.
 */
export function processHandshakeInit(
  init: HandshakeInit,
  responderKeypair: Ed25519KeyPair,
  localTimestampS?: number,
  nonces?: NonceRegistry,
): { challenge: HandshakeChallenge; clockOffset: number; sessionKey: Uint8Array } {
  const localTime = localTimestampS ?? Math.floor(Date.now() / 1000);
  const clockOffset = calculateClockOffset(init.timestamp, localTime);

  // Validate clock skew
  if (Math.abs(clockOffset) > MAX_CLOCK_SKEW_S) {
    throw new TransportException(
      TransportError.ClockSkewTooHigh,
      `Clock skew ${clockOffset}s exceeds maximum ${MAX_CLOCK_SKEW_S}s`,
    );
  }

  // Check nonce age (bound to handshake timestamp, not sliding timer)
  const nonceAge = localTime - init.timestamp;
  if (nonceAge > NONCE_EXPIRY_S) {
    throw new TransportException(
      TransportError.ReplayRejected,
      `Handshake age ${nonceAge}s exceeds maximum ${NONCE_EXPIRY_S}s`,
    );
  }

  // Check nonce replay.
  //
  // The check and the insert are deliberately adjacent and synchronous.
  // An `await` between them would open a genuine TOCTOU window: two
  // copies of the same init could both pass `has()` before either
  // reached `set()`. In a single-threaded runtime this sequence cannot
  // interleave, so no lock is needed — but the property is easy to lose
  // by making this function async later.
  //
  // A residual, accepted weakness: an on-path attacker who replays a
  // captured init before the genuine one arrives burns that nonce, and
  // the real handshake is then rejected as a replay. They cannot
  // complete the handshake (the ack needs the initiator's key), and the
  // initiator succeeds on retry with a fresh nonce. It is no escalation
  // — an on-path attacker can already drop the packet outright.
  (nonces ?? defaultNonceRegistry).admit(toHex(init.nonce), localTime);

  // Responder's ephemeral half. The secret is used once, here, to derive
  // the session key and is then dropped — it is never stored.
  const ephemeralSecret = x25519.utils.randomSecretKey();
  const ephemeralKey = x25519.getPublicKey(ephemeralSecret);

  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);

  const responderDid = publicKeyToDidKey(responderKeypair.publicKey);
  const bound = (tag: number): Uint8Array =>
    transcript(
      tag,
      init.didKey,
      responderDid,
      init.nonce,
      nonce,
      init.ephemeralKey,
      ephemeralKey,
    );

  const signature = ed25519.sign(
    bound(TRANSCRIPT_TAG.CHALLENGE),
    responderKeypair.secretKey,
  );

  try {
    const sessionKey = deriveSessionKey(
      ephemeralSecret,
      init.ephemeralKey,
      bound(TRANSCRIPT_TAG.ACK),
    );

    return {
      challenge: { nonce, ephemeralKey, signature },
      clockOffset,
      sessionKey,
    };
  } finally {
    // Wiped on every path, including a low-order peer key that makes
    // the exchange throw.
    ephemeralSecret.fill(0);
  }
}

/**
 * Create a HandshakeAck by signing the responder's nonce.
 *
 * @param keypair Initiator's Ed25519 keypair.
 * @param responderNonce The responder's 32-byte nonce from the challenge.
 */
export function createHandshakeAck(
  keypair: Ed25519KeyPair,
  context: HandshakeContext,
): HandshakeAck {
  return {
    signature: ed25519.sign(
      transcriptFor(TRANSCRIPT_TAG.ACK, context),
      keypair.secretKey,
    ),
  };
}

/**
 * Verify a HandshakeAck signature against a nonce and public key.
 *
 * @param ack The received HandshakeAck.
 * @param peerPublicKey The peer's 32-byte Ed25519 public key.
 * @param expectedNonce The nonce that was sent in the challenge.
 * @returns True if the signature is valid.
 */
export function verifyHandshakeAck(
  ack: HandshakeAck,
  peerPublicKey: Uint8Array,
  context: HandshakeContext,
): boolean {
  try {
    return ed25519.verify(
      ack.signature,
      transcriptFor(TRANSCRIPT_TAG.ACK, context),
      peerPublicKey,
    );
  } catch {
    return false;
  }
}

/**
 * Verify a HandshakeChallenge signature (responder signed initiator's nonce).
 *
 * @param challenge The received HandshakeChallenge.
 * @param responderPublicKey Responder's 32-byte Ed25519 public key.
 * @param initiatorNonce The nonce originally sent in HandshakeInit.
 * @returns True if the signature is valid.
 */
export function verifyHandshakeChallenge(
  challenge: HandshakeChallenge,
  responderPublicKey: Uint8Array,
  context: HandshakeContext,
): boolean {
  try {
    return ed25519.verify(
      challenge.signature,
      transcriptFor(TRANSCRIPT_TAG.CHALLENGE, context),
      responderPublicKey,
    );
  } catch {
    return false;
  }
}

/**
 * Calculate clock offset between remote and local timestamps.
 * Δ_peer = T_remote − T_local
 *
 * @param remoteTimestampS Remote peer's unix timestamp in seconds.
 * @param localTimestampS Local unix timestamp in seconds.
 * @returns The clock offset in seconds.
 */
export function calculateClockOffset(remoteTimestampS: number, localTimestampS: number): number {
  return remoteTimestampS - localTimestampS;
}

/**
 * Calculate the current epoch number.
 * E = ⌊(T_local + Δ_peer) / 10⌋
 *
 * @param localTimestampS Local unix timestamp in seconds.
 * @param peerOffsetS Clock offset from handshake (Δ_peer).
 * @returns The epoch number.
 */
export function calculateEpoch(localTimestampS: number, peerOffsetS: number): number {
  return Math.floor((localTimestampS + peerOffsetS) / EPOCH_DURATION_S);
}

/**
 * Clear the nonce replay registry. Useful for testing.
 */
export function clearNonceRegistry(): void {
  defaultNonceRegistry.clear();
}
