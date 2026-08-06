/**
 * @dicsussion/wot — Trust Counter Persistence
 *
 * Reads and writes the `wot_peers` collection (RFC 004 §4.1), keeping
 * the stored `subjective_score` in sync with the counters it derives
 * from.
 *
 * Scores are recomputed from counters on every mutation rather than
 * incremented in place: the counters are the source of truth, so a
 * corrupted or hand-edited score cannot drift permanently.
 */

import type { IStorageDriver, WotPeerRecord } from '../storage/types.js';
import { StorageCollections } from '../storage/types.js';
import { calculateScore } from './score-calculator.js';

/** Counters that make up a peer's trust record. */
export interface TrustCounters {
  readonly verifiedSessions: number;
  readonly vouchersRedeemed: number;
  readonly vouchersIssued: number;
  readonly isBlacklisted: boolean;
  readonly lastInteraction: number;
}

const ZERO_COUNTERS: TrustCounters = {
  verifiedSessions: 0,
  vouchersRedeemed: 0,
  vouchersIssued: 0,
  isBlacklisted: false,
  lastInteraction: 0,
};

/**
 * SQLite-backed store for per-peer Web-of-Trust counters.
 */
export class TrustStore {
  constructor(private readonly storage: IStorageDriver) {}

  /**
   * Load a peer's record.
   *
   * @returns Zeroed counters for an unknown peer — RFC 004 §8 requires
   *   unverified contacts to default to S_base = 0, not to be absent.
   */
  async get(did: string): Promise<WotPeerRecord> {
    const row = await this.storage.get(StorageCollections.WOT_PEERS, did);
    if (!row) return this.toRecord(did, ZERO_COUNTERS);

    return this.toRecord(did, {
      verifiedSessions: numberOr(row['verified_sessions'], 0),
      vouchersRedeemed: numberOr(row['vouchers_redeemed'], 0),
      vouchersIssued: numberOr(row['vouchers_issued'], 0),
      isBlacklisted: numberOr(row['is_blacklisted'], 0) !== 0,
      lastInteraction: numberOr(row['last_interaction'], 0),
    });
  }

  /** Write a full record, recomputing its score from the counters. */
  async put(did: string, counters: TrustCounters): Promise<WotPeerRecord> {
    const record = this.toRecord(did, counters);

    await this.storage.put(StorageCollections.WOT_PEERS, did, {
      did: record.did,
      verified_sessions: record.verifiedSessions,
      vouchers_redeemed: record.vouchersRedeemed,
      vouchers_issued: record.vouchersIssued,
      subjective_score: Number.isFinite(record.subjectiveScore)
        ? record.subjectiveScore
        : 0,
      is_blacklisted: record.isBlacklisted ? 1 : 0,
      last_interaction: record.lastInteraction,
    });

    return record;
  }

  /** Credit a verified bidirectional chat session (+10 POC). */
  async creditVerifiedSession(did: string, now: number): Promise<WotPeerRecord> {
    return this.mutate(did, (current) => ({
      ...current,
      verifiedSessions: current.verifiedSessions + 1,
      lastInteraction: now,
    }));
  }

  /** Credit a redeemed endorsement voucher (+5 POC). */
  async creditVoucherRedeemed(did: string, now: number): Promise<WotPeerRecord> {
    return this.mutate(did, (current) => ({
      ...current,
      vouchersRedeemed: current.vouchersRedeemed + 1,
      lastInteraction: now,
    }));
  }

  /**
   * Record that a peer issued a voucher (−2 POC).
   *
   * The deduction is what prevents voucher farming: minting endorsements
   * costs the issuer more than a single redemption is worth to them.
   */
  async debitVoucherIssued(did: string, now: number): Promise<WotPeerRecord> {
    return this.mutate(did, (current) => ({
      ...current,
      vouchersIssued: current.vouchersIssued + 1,
      lastInteraction: now,
    }));
  }

  /**
   * Blacklist a peer, driving its score to −∞ (RFC 004 §6.1).
   *
   * Used when a peer's RLN nullifier reveals double-spending.
   */
  async blacklist(did: string, now: number): Promise<WotPeerRecord> {
    return this.mutate(did, (current) => ({
      ...current,
      isBlacklisted: true,
      lastInteraction: now,
    }));
  }

  /** Lift a blacklist, restoring the counter-derived score. */
  async unblacklist(did: string, now: number): Promise<WotPeerRecord> {
    return this.mutate(did, (current) => ({
      ...current,
      isBlacklisted: false,
      lastInteraction: now,
    }));
  }

  /** All known peer records. */
  async list(): Promise<WotPeerRecord[]> {
    const rows = await this.storage.query(StorageCollections.WOT_PEERS);

    return rows.map((row) =>
      this.toRecord(String(row['did'] ?? ''), {
        verifiedSessions: numberOr(row['verified_sessions'], 0),
        vouchersRedeemed: numberOr(row['vouchers_redeemed'], 0),
        vouchersIssued: numberOr(row['vouchers_issued'], 0),
        isBlacklisted: numberOr(row['is_blacklisted'], 0) !== 0,
        lastInteraction: numberOr(row['last_interaction'], 0),
      }),
    );
  }

  /** Read-modify-write a peer's counters. */
  private async mutate(
    did: string,
    update: (current: TrustCounters) => TrustCounters,
  ): Promise<WotPeerRecord> {
    const current = await this.get(did);

    return this.put(
      did,
      update({
        verifiedSessions: current.verifiedSessions,
        vouchersRedeemed: current.vouchersRedeemed,
        vouchersIssued: current.vouchersIssued,
        isBlacklisted: current.isBlacklisted,
        lastInteraction: current.lastInteraction,
      }),
    );
  }

  private toRecord(did: string, counters: TrustCounters): WotPeerRecord {
    const subjectiveScore = counters.isBlacklisted
      ? Number.NEGATIVE_INFINITY
      : calculateScore(
          counters.verifiedSessions,
          counters.vouchersRedeemed,
          counters.vouchersIssued,
        );

    return {
      did,
      verifiedSessions: counters.verifiedSessions,
      vouchersRedeemed: counters.vouchersRedeemed,
      vouchersIssued: counters.vouchersIssued,
      subjectiveScore,
      isBlacklisted: counters.isBlacklisted,
      lastInteraction: counters.lastInteraction,
    };
  }
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}
