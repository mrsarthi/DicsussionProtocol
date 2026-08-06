/**
 * @dicsussion/crdt — Signed Membership Departures
 *
 * Makes leaving a channel propagate.
 *
 * Membership is a grow-only set, so dropping a commitment locally is
 * undone by the next reconciliation — a departed member simply
 * reappears. Departures therefore need their own grow-only set of
 * *tombstones*, and the active membership becomes
 * `joins − departures`: a two-phase set, which still converges under
 * any message ordering.
 *
 * A departure is permanent for that commitment. Rejoining means
 * presenting a **fresh** commitment (new trapdoor), which is desirable
 * anyway — it stops an old departure record from being replayed to evict
 * someone who has since rejoined.
 *
 * WHO MAY REMOVE WHOM: a departure is signed by the departing member's
 * own `did:key`. Only you can announce that you left. Without that,
 * anyone could evict anyone by gossiping a tombstone — the same reason
 * revocation tombstones carry their own evidence (RFC 003 §7).
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import { fieldToBytes } from '../crypto/field.js';
import type { Ed25519KeyPair } from '../transport/did-key.js';
import { didKeyToPublicKey } from '../transport/did-key.js';

/** A member's signed statement that they have left a channel. */
export interface DepartureRecord {
  readonly channelId: string;
  /** The departing member's did:key. */
  readonly did: string;
  /** The identity commitment being retired. */
  readonly commitment: bigint;
  /** Unix seconds — informational; ordering is not needed for a 2P-set. */
  readonly departedAt: number;
  /** Ed25519 signature over the canonical bytes below. */
  readonly signature: Uint8Array;
}

const encoder = new TextEncoder();

/**
 * Canonical bytes covered by a departure signature.
 *
 * Length-prefixed so no two distinct departures serialise identically —
 * a channel id containing a delimiter must not be able to impersonate a
 * different field layout.
 */
export function encodeDepartureForSigning(
  departure: Omit<DepartureRecord, 'signature'>,
): Uint8Array {
  const parts: Uint8Array[] = [
    encoder.encode('dicsussion/membership-departure/v1'),
    lengthPrefixed(encoder.encode(departure.channelId)),
    lengthPrefixed(encoder.encode(departure.did)),
    fieldToBytes(departure.commitment),
    encodeUint64(departure.departedAt),
  ];

  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);

  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}

/**
 * Sign a departure from a channel.
 *
 * @param channelId The channel being left.
 * @param did The departing member's did:key.
 * @param commitment The identity commitment to retire.
 * @param keypair The departing member's signing keypair.
 */
export function createDeparture(
  channelId: string,
  did: string,
  commitment: bigint,
  keypair: Ed25519KeyPair,
  departedAt: number = Math.floor(Date.now() / 1000),
): DepartureRecord {
  const unsigned = { channelId, did, commitment, departedAt };

  return {
    ...unsigned,
    signature: ed25519.sign(encodeDepartureForSigning(unsigned), keypair.secretKey),
  };
}

/**
 * Verify a departure is genuinely signed by the member it names.
 *
 * The public key is recovered from `did`, so a forged record cannot
 * supply a key of its own choosing.
 *
 * @param departure The record to check.
 * @param expectedChannelId Optional channel to bind against, so a valid
 *   departure from one channel cannot evict a member from another.
 */
export function verifyDeparture(
  departure: DepartureRecord,
  expectedChannelId?: string,
): boolean {
  if (expectedChannelId !== undefined && departure.channelId !== expectedChannelId) {
    return false;
  }

  try {
    const { signature, ...unsigned } = departure;

    return ed25519.verify(
      signature,
      encodeDepartureForSigning(unsigned),
      didKeyToPublicKey(departure.did),
    );
  } catch {
    return false;
  }
}

/**
 * Tracks verified departures for one channel.
 *
 * A grow-only set of tombstones: adding is idempotent, and nothing is
 * ever removed, which is what keeps the two-phase set convergent.
 */
export class DepartureSet {
  private readonly records = new Map<bigint, DepartureRecord>();

  constructor(private readonly channelId: string) {}

  /** Departed commitments. */
  get size(): number {
    return this.records.size;
  }

  /**
   * Record a departure, if it verifies.
   *
   * @returns True if this was a new, valid departure.
   */
  add(departure: DepartureRecord): boolean {
    if (!verifyDeparture(departure, this.channelId)) return false;
    if (this.records.has(departure.commitment)) return false;

    this.records.set(departure.commitment, departure);
    return true;
  }

  /** Whether a commitment has departed. */
  has(commitment: bigint): boolean {
    return this.records.has(commitment);
  }

  /** Every departure record, for gossiping to peers. */
  list(): DepartureRecord[] {
    return Array.from(this.records.values());
  }

  /** Retired commitments. */
  commitments(): bigint[] {
    return Array.from(this.records.keys());
  }
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function encodeUint64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}
