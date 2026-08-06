/**
 * @dicsussion/slashing — RLN Share Collector
 *
 * Watches the shares peers publish and detects quota violations
 * (RFC 003 §8 `DoubleShareDetected`).
 *
 * Every node runs this against traffic it already receives, so detection
 * is a side effect of ordinary participation rather than a privileged
 * role. The first honest node to observe both halves of a double-send
 * can slash — there is no committee to bribe and no single observer to
 * take offline.
 *
 * Shares are retained only for the rolling window plus a grace margin.
 * Keeping them forever would turn every node into a permanent archive of
 * who spoke when, which is exactly the metadata this protocol exists to
 * avoid.
 */

import type { PolynomialShare } from '@dicsussion/core/zk';
import { recoverSecret, verifyRecovery } from '@dicsussion/core/zk';
import { ROLLING_WINDOW_EPOCHS } from '@dicsussion/core/zk';

/** A share as observed on the wire, tagged with its epoch. */
export interface ObservedShare extends PolynomialShare {
  readonly epoch: number;
}

/** A detected quota violation, ready to be turned into a tombstone. */
export interface SlashingEvidence {
  readonly identitySecret: bigint;
  readonly slope: bigint;
  readonly nullifier: bigint;
  readonly shares: readonly [PolynomialShare, PolynomialShare];
  readonly epoch: number;
}

export interface ShareCollectorOptions {
  /**
   * Epochs to retain shares for. Defaults to the rolling window plus one
   * epoch of slack for clock skew between peers.
   */
  readonly retentionEpochs?: number;
}

/**
 * Collects RLN shares and surfaces double-spend evidence.
 */
export class ShareCollector {
  /** Shares grouped by nullifier — the only grouping that can conflict. */
  private readonly byNullifier = new Map<bigint, ObservedShare[]>();

  /** Nullifiers already reported, so evidence is emitted once. */
  private readonly reported = new Set<bigint>();

  private readonly retentionEpochs: number;

  constructor(options: ShareCollectorOptions = {}) {
    this.retentionEpochs = options.retentionEpochs ?? ROLLING_WINDOW_EPOCHS + 1;
  }

  /** Distinct nullifiers currently retained. */
  get trackedNullifiers(): number {
    return this.byNullifier.size;
  }

  /** Total retained shares. */
  get size(): number {
    let total = 0;
    for (const group of this.byNullifier.values()) total += group.length;
    return total;
  }

  /**
   * Record an observed share and report any violation it completes.
   *
   * @param share The share, with the epoch it was published in.
   * @returns Evidence if this share revealed a secret, else undefined.
   */
  observe(share: ObservedShare): SlashingEvidence | undefined {
    if (this.reported.has(share.nullifier)) return undefined;

    const group = this.byNullifier.get(share.nullifier) ?? [];

    // An identical (x, y) is the same message arriving twice — normal in
    // a gossip mesh. Storing it would let a duplicate delivery masquerade
    // as a double-send.
    if (group.some((held) => held.x === share.x)) return undefined;

    group.push(share);
    this.byNullifier.set(share.nullifier, group);

    if (group.length < 2) return undefined;

    return this.extractEvidence(group, share.epoch);
  }

  /** Observe many shares, returning every violation found. */
  observeAll(shares: Iterable<ObservedShare>): SlashingEvidence[] {
    const found: SlashingEvidence[] = [];

    for (const share of shares) {
      const evidence = this.observe(share);
      if (evidence) found.push(evidence);
    }

    return found;
  }

  /** Whether a nullifier has already produced evidence. */
  hasReported(nullifier: bigint): boolean {
    return this.reported.has(nullifier);
  }

  /**
   * Drop shares older than the retention window.
   *
   * @param currentEpoch The current epoch.
   * @returns Number of shares evicted.
   */
  prune(currentEpoch: number): number {
    const cutoff = currentEpoch - this.retentionEpochs;
    let evicted = 0;

    for (const [nullifier, group] of this.byNullifier) {
      const kept = group.filter((share) => share.epoch > cutoff);
      evicted += group.length - kept.length;

      if (kept.length === 0) {
        this.byNullifier.delete(nullifier);
      } else {
        this.byNullifier.set(nullifier, kept);
      }
    }

    return evicted;
  }

  /** Forget everything, including the reported set. */
  clear(): void {
    this.byNullifier.clear();
    this.reported.clear();
  }

  /**
   * Try every pair in a conflicting group until one verifies.
   *
   * Verification is not redundant: recovery is algebraic and yields an
   * answer for any two points, so the result is checked against both
   * shares before it can become a revocation.
   */
  private extractEvidence(
    group: readonly ObservedShare[],
    epoch: number,
  ): SlashingEvidence | undefined {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const first = group[i]!;
        const second = group[j]!;

        const recovery = recoverSecret(first, second);
        if (!recovery.recovered) continue;

        if (
          !verifyRecovery(recovery.identitySecret, recovery.slope, [first, second])
        ) {
          continue;
        }

        this.reported.add(first.nullifier);

        return {
          identitySecret: recovery.identitySecret,
          slope: recovery.slope,
          nullifier: first.nullifier,
          shares: [first, second],
          epoch,
        };
      }
    }

    return undefined;
  }
}
