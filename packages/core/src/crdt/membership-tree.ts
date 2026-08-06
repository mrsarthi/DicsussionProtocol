/**
 * @dicsussion/crdt — Bounded Identity Membership Set
 *
 * Manages the active identity commitment set backing the depth-16
 * Merkle tree, per RFC 002 §4.1.
 *
 * Two properties do the real work here:
 *
 * 1. **Deterministic ordering.** A commitment's leaf index is its rank
 *    in the lexicographic byte ordering of the whole active set, not its
 *    insertion order. Two peers that have seen the same commitments in
 *    different orders therefore derive byte-identical trees — which is
 *    the point: it removes concurrent-insertion ambiguity entirely.
 *    The cost is that inserting shifts every higher-ranked index, so the
 *    root is recomputed rather than patched.
 *
 * 2. **Canonical eviction at capacity.** The lowest-indexed commitment is
 *    dropped and its slot becomes `cm_empty = 0`. Eviction must be a pure
 *    function of committed state — an LRU keyed on local activity would
 *    let two peers evict different members and fork the root.
 *
 * 3. **Version-bound roots.** `root()` binds the algorithm version, depth
 *    and capacity to the raw tree root, so changing how roots are
 *    computed is detectable rather than silently invalidating every
 *    proof and anchor in the network.
 */

import { compareFieldBytes, assertCanonicalField } from '../crypto/field.js';
import { membershipRoot } from '../crypto/poseidon.js';
import type { MerkleProof, TreeLevels } from './sparse-merkle-tree.js';
import {
  buildLevels,
  MAX_LEAVES,
  proofFromLevels,
  rootFromLevels,
  TREE_DEPTH,
  verifyProof,
} from './sparse-merkle-tree.js';

/**
 * Membership root algorithm version (RFC 002 §4.1).
 *
 * Bound into every root. Increment when the root computation changes, so
 * peers can tell "computed differently" from "different members".
 */
export const MEMBERSHIP_ROOT_VERSION = 1;

/**
 * Default active-member cap.
 *
 * Root computation is O(N) Poseidon hashes because a commitment's leaf
 * index is its *rank* in the sorted set — inserting re-ranks everything
 * above it. At the depth-16 ceiling of 65,536 members that is ~14 s per
 * rebuild, which is unusable on a phone.
 *
 * 4,096 keeps a rebuild near a second while preserving the two properties
 * that matter: order-independent roots, and a 16-hash Merkle path so
 * circuit cost stays fixed. Larger channels should shard rather than
 * raise this. Revisit only alongside a change of indexing scheme, which
 * `MEMBERSHIP_ROOT_VERSION` exists to make survivable.
 */
export const DEFAULT_MAX_MEMBERS = 4_096;

/** A tracked member and its liveness metadata. */
export interface MemberRecord {
  /** Poseidon identity commitment. */
  readonly commitment: bigint;
  /**
   * Epoch milliseconds of the most recent activity.
   *
   * Local bookkeeping only — deliberately NOT an input to eviction or the
   * root, since a local clock is not committed state and peers would
   * disagree.
   */
  readonly lastActive: number;
  /** Epoch milliseconds when first admitted. */
  readonly joinedAt: number;
}

/** Result of admitting a commitment. */
export interface InsertResult {
  /** Leaf index after re-ranking. */
  readonly index: number;
  /** Commitment displaced by eviction, if capacity was reached. */
  readonly evicted?: bigint;
  /** False when the commitment was already present (activity refreshed). */
  readonly inserted: boolean;
}

/**
 * The active identity set for one channel, bounded at N_max.
 */
export class BoundedMembershipTree {
  private readonly members = new Map<bigint, MemberRecord>();

  /** Sorted commitment cache, invalidated on any mutation. */
  private sortedCache: bigint[] | null = null;
  /** Materialised tree levels, so N proofs cost O(N·D) rather than O(N²·D). */
  private levelsCache: TreeLevels | null = null;

  constructor(private readonly capacity: number = DEFAULT_MAX_MEMBERS) {
    if (capacity < 1 || capacity > MAX_LEAVES) {
      throw new Error(
        `Capacity must be in [1, ${MAX_LEAVES}], got ${capacity}`,
      );
    }
  }

  /** Active commitment count. */
  get size(): number {
    return this.members.size;
  }

  /** Maximum active commitments before eviction kicks in. */
  get maxSize(): number {
    return this.capacity;
  }

  /** Whether the set is at capacity. */
  get isFull(): boolean {
    return this.members.size >= this.capacity;
  }

  /**
   * Admit a commitment, evicting the lowest-indexed member if the set is
   * already at capacity.
   *
   * Re-inserting an existing commitment refreshes its activity instead of
   * duplicating it.
   *
   * @param commitment Canonical Poseidon identity commitment.
   * @param now Epoch milliseconds, injectable for deterministic tests.
   */
  insert(commitment: bigint, now: number = Date.now()): InsertResult {
    assertCanonicalField(commitment);

    if (commitment === 0n) {
      throw new Error('Cannot insert the empty-leaf tombstone (0) as a member');
    }

    const existing = this.members.get(commitment);
    if (existing) {
      this.members.set(commitment, { ...existing, lastActive: now });
      // Ordering is by commitment bytes, so a touch cannot change indices.
      return { index: this.indexOf(commitment), inserted: false };
    }

    let evicted: bigint | undefined;
    if (this.isFull) {
      evicted = this.evictCanonical();
    }

    this.members.set(commitment, {
      commitment,
      lastActive: now,
      joinedAt: now,
    });
    this.invalidate();

    return { index: this.indexOf(commitment), evicted, inserted: true };
  }

  /**
   * Refresh a member's activity timestamp.
   *
   * @returns False if the commitment is not a member.
   */
  touch(commitment: bigint, now: number = Date.now()): boolean {
    const existing = this.members.get(commitment);
    if (!existing) return false;

    this.members.set(commitment, { ...existing, lastActive: now });
    return true;
  }

  /** Remove a commitment, freeing its slot. */
  remove(commitment: bigint): boolean {
    const removed = this.members.delete(commitment);
    if (removed) this.invalidate();
    return removed;
  }

  /** Whether a commitment is currently active. */
  has(commitment: bigint): boolean {
    return this.members.has(commitment);
  }

  /** Look up a member's liveness record. */
  getRecord(commitment: bigint): MemberRecord | undefined {
    return this.members.get(commitment);
  }

  /**
   * Active commitments in canonical leaf order.
   *
   * Sorted lexicographically over the 32-byte big-endian encoding
   * (RFC 002 §4.1).
   */
  sortedCommitments(): bigint[] {
    if (this.sortedCache) return this.sortedCache;

    this.sortedCache = Array.from(this.members.keys()).sort(compareFieldBytes);
    return this.sortedCache;
  }

  /**
   * Leaf index of a commitment — its rank in the sorted set.
   *
   * @returns -1 if not a member.
   */
  indexOf(commitment: bigint): number {
    const sorted = this.sortedCommitments();

    // Binary search: the array is sorted by the same comparator.
    let low = 0;
    let high = sorted.length - 1;

    while (low <= high) {
      const mid = (low + high) >>> 1;
      const cmp = compareFieldBytes(sorted[mid]!, commitment);

      if (cmp === 0) return mid;
      if (cmp < 0) low = mid + 1;
      else high = mid - 1;
    }

    return -1;
  }

  /**
   * The canonical, version-bound membership root.
   *
   * Binds the algorithm version, depth and capacity to the raw tree root
   * (RFC 002 §4.1), so a future change to how roots are computed is
   * *detectable* rather than silently invalidating every root, proof and
   * genesis anchor in the network.
   */
  root(): bigint {
    return membershipRoot(
      MEMBERSHIP_ROOT_VERSION,
      TREE_DEPTH,
      this.capacity,
      this.rawRoot(),
    );
  }

  /**
   * The unversioned Merkle root over the active set.
   *
   * This is what inclusion proofs verify against — the version binding
   * wraps it rather than being part of the tree itself.
   */
  rawRoot(): bigint {
    return rootFromLevels(this.levels());
  }

  /**
   * Build an inclusion proof for a member.
   *
   * @throws If the commitment is not currently a member.
   */
  proveMembership(commitment: bigint): MerkleProof {
    const index = this.indexOf(commitment);
    if (index < 0) {
      throw new Error(
        `Commitment is not an active member: ${commitment.toString()}`,
      );
    }

    return proofFromLevels(this.levels(), index);
  }

  /** Materialise (and cache) the tree levels for the current member set. */
  private levels(): TreeLevels {
    if (this.levelsCache) return this.levelsCache;

    this.levelsCache = buildLevels(this.sortedCommitments());
    return this.levelsCache;
  }

  /** Verify a proof against this tree's current raw root. */
  verify(proof: MerkleProof): boolean {
    return verifyProof(proof, this.rawRoot());
  }

  /** All member records, most recently active first. */
  listMembers(): MemberRecord[] {
    return Array.from(this.members.values()).sort(
      (a, b) => b.lastActive - a.lastActive,
    );
  }

  /** Drop every member. */
  clear(): void {
    this.members.clear();
    this.invalidate();
  }

  /**
   * Evict the lowest-indexed member — index 0 in the sorted set.
   *
   * WHY NOT LRU: the root must be a pure function of committed state, and
   * `lastActive` is a *local* observation that is never committed. Two
   * peers with different views of activity would evict different members
   * and fork the root — which is strictly worse than any suboptimality in
   * the eviction policy itself.
   *
   * Lowest-index is arbitrary but *canonical*: index is rank in the
   * lexicographic byte ordering, so every peer computes the same victim
   * from the same member set, with no shared clock or gossip required.
   *
   * Recording `lastActive` in the leaf was the alternative, and is worse:
   * the root would change on every message, and RLN proofs are bound to a
   * root, so honest proofs would go stale almost immediately.
   */
  private evictCanonical(): bigint | undefined {
    const sorted = this.sortedCommitments();
    const victim = sorted[0];

    if (victim === undefined) return undefined;

    this.members.delete(victim);
    this.invalidate();
    return victim;
  }

  private invalidate(): void {
    this.sortedCache = null;
    this.levelsCache = null;
  }
}
