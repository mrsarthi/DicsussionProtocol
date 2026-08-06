/**
 * @dicsussion/wot — Voucher Nullifier & Genesis Anchor Persistence
 *
 * Redemption nullifiers MUST survive a restart. `VoucherService` holds
 * them in memory, so without this store a node that restarts forgets
 * every voucher it has already paid out — and RFC 003 §8
 * `ReplayedVoucher` stops being enforced. An attacker who kept a single
 * voucher could redeem it repeatedly across restarts and inflate their
 * reputation without bound.
 *
 * Nullifiers are stored as decimal strings: they are 254-bit field
 * elements and SQLite's INTEGER is 64-bit.
 *
 * Backed by `IStorageDriver`, so the same store works on IndexedDB in a
 * browser. Both record sets are small and bounded — one anchor per
 * channel, one nullifier per voucher ever redeemed — so they are held in
 * memory and written through. That keeps the reads synchronous, which
 * they must be: `getGenesisAnchor()` and `requiresProofs()` are called
 * on the message path and from synchronous public API.
 */

import { deserializeValue } from '../storage/driver-shared.js';
import { StorageCollections } from '../storage/types.js';
import type { IStorageDriver } from '../storage/types.js';
import { WriteQueue } from '../storage/write-queue.js';
import type { GenesisAnchor } from './genesis-anchor.js';

/** A spent redemption nullifier. */
export interface SpentNullifier {
  readonly nullifier: bigint;
  readonly scope: bigint;
  readonly redeemedAt: number;
}

/**
 * Persistence for voucher nullifiers and channel genesis anchors.
 */
export class VoucherStore {
  private readonly writes = new WriteQueue();
  private readonly nullifiers = new Map<string, SpentNullifier>();
  private readonly anchors = new Map<string, GenesisAnchor>();
  private hydrated = false;

  constructor(private readonly storage: IStorageDriver) {}

  /**
   * Load persisted state into memory.
   *
   * Must complete before any redemption is attempted — that is the
   * whole point of the store. Callers that skip it get a node which
   * silently accepts every previously spent voucher again.
   */
  async hydrate(): Promise<void> {
    if (this.hydrated) return;

    for (const row of await this.storage.query(
      StorageCollections.VOUCHER_NULLIFIERS,
    )) {
      const nullifier = String(row['nullifier']);
      this.nullifiers.set(nullifier, {
        nullifier: BigInt(nullifier),
        scope: BigInt(String(row['scope'] ?? '0')),
        redeemedAt: Number(row['redeemed_at'] ?? 0),
      });
    }

    for (const row of await this.storage.query(
      StorageCollections.GENESIS_ANCHORS,
    )) {
      const anchor = toAnchor(row);
      this.anchors.set(anchor.channelId, anchor);
    }

    this.hydrated = true;
  }

  // ─── Redemption nullifiers ────────────────────────────────────────────

  /**
   * Record a spent redemption nullifier.
   *
   * Idempotent: replaying a redemption overwrites rather than
   * conflicting, since the caller has already rejected it.
   */
  recordSpent(nullifier: bigint, scope: bigint, redeemedAt: number): void {
    const key = nullifier.toString();
    this.nullifiers.set(key, { nullifier, scope, redeemedAt });

    this.writes.enqueue(() =>
      this.storage.put(StorageCollections.VOUCHER_NULLIFIERS, key, {
        nullifier: key,
        scope: scope.toString(),
        redeemed_at: redeemedAt,
      }),
    );
  }

  /** Whether a nullifier has already been spent. */
  isSpent(nullifier: bigint): boolean {
    return this.nullifiers.has(nullifier.toString());
  }

  /** Every spent nullifier, for rehydrating a VoucherService at boot. */
  loadAllNullifiers(): SpentNullifier[] {
    return [...this.nullifiers.values()].sort(
      (a, b) => a.redeemedAt - b.redeemedAt,
    );
  }

  /** Count of spent nullifiers. */
  countNullifiers(): number {
    return this.nullifiers.size;
  }

  // ─── Genesis anchors ──────────────────────────────────────────────────

  /** Persist a channel's signed genesis anchor. */
  saveAnchor(anchor: GenesisAnchor): void {
    this.anchors.set(anchor.channelId, anchor);

    this.writes.enqueue(() =>
      this.storage.put(
        StorageCollections.GENESIS_ANCHORS,
        anchor.channelId,
        {
          channel_id: anchor.channelId,
          creator_did: anchor.creatorDid,
          creator_commitment: anchor.creatorCommitment.toString(),
          initial_root: anchor.initialRoot.toString(),
          created_at: anchor.createdAt,
          require_proofs: anchor.requireProofs ? 1 : 0,
          signature: new Uint8Array(anchor.signature),
        },
      ),
    );
  }

  /** Load one channel's anchor. */
  loadAnchor(channelId: string): GenesisAnchor | undefined {
    return this.anchors.get(channelId);
  }

  /** Load every persisted anchor, oldest first. */
  loadAllAnchors(): GenesisAnchor[] {
    return [...this.anchors.values()].sort((a, b) => a.createdAt - b.createdAt);
  }

  /** Remove a channel's anchor. */
  deleteAnchor(channelId: string): boolean {
    if (!this.anchors.delete(channelId)) return false;

    this.writes.enqueue(async () => {
      await this.storage.delete(StorageCollections.GENESIS_ANCHORS, channelId);
    });

    return true;
  }

  /** Wait for queued writes to land. */
  async flush(): Promise<void> {
    await this.writes.flush();
  }
}

function toAnchor(row: Record<string, unknown>): GenesisAnchor {
  return {
    channelId: String(row['channel_id']),
    creatorDid: String(row['creator_did']),
    creatorCommitment: BigInt(String(row['creator_commitment'] ?? '0')),
    initialRoot: BigInt(String(row['initial_root'] ?? '0')),
    createdAt: Number(row['created_at'] ?? 0),
    requireProofs: Number(row['require_proofs'] ?? 0) === 1,
    signature: deserializeValue(row['signature']) as Uint8Array,
  };
}
