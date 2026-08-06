/**
 * Phase 2B — Test Suite 2.1: Merkle Tree & Bounded Membership
 *
 * Generates 100 mock identities and verifies:
 *   - deterministic root regardless of insertion order (RFC 002 §4.1)
 *   - lexicographic byte ordering drives leaf indices
 *   - every member proves inclusion in exactly 16 hashes
 *   - canonical (lowest-index) eviction at the boundary cap
 *   - version-bound roots, so an algorithm change is detectable
 *   - canonical field validation rejects out-of-range scalars
 */

import { expect, test } from '@playwright/test';

import {
  BoundedMembershipTree,
  DEFAULT_MAX_MEMBERS,
  MEMBERSHIP_ROOT_VERSION,
} from '../../packages/core/src/crdt/membership-tree.js';
import {
  emptyRoot,
  MAX_LEAVES,
  TREE_DEPTH,
  verifyProof,
} from '../../packages/core/src/crdt/sparse-merkle-tree.js';
import {
  BN254_SCALAR_FIELD,
  compareFieldBytes,
} from '../../packages/core/src/crypto/field.js';
import {
  membershipCommitment,
  membershipRoot,
} from '../../packages/core/src/crypto/poseidon.js';

/** Deterministic mock identity commitments. */
function mockIdentities(count: number): bigint[] {
  return Array.from({ length: count }, (_, i) =>
    membershipCommitment(BigInt(i + 1) * 1_000_003n, BigInt(i + 7) * 99_991n),
  );
}

/** Fisher-Yates with a fixed seed, so shuffles are reproducible. */
function seededShuffle<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;

  for (let i = out.length - 1; i > 0; i--) {
    state = (state * 1_103_515_245 + 12_345) & 0x7fffffff;
    const j = state % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }

  return out;
}

test.describe('Suite 2.1 — Merkle Tree & Bounded Membership', () => {
  test('100 identities produce a deterministic root regardless of insert order', () => {
    const identities = mockIdentities(100);

    const inOrder = new BoundedMembershipTree();
    identities.forEach((cm, i) => inOrder.insert(cm, 1_000 + i));

    const reversed = new BoundedMembershipTree();
    [...identities].reverse().forEach((cm, i) => reversed.insert(cm, 1_000 + i));

    const shuffled = new BoundedMembershipTree();
    seededShuffle(identities, 42).forEach((cm, i) => shuffled.insert(cm, 1_000 + i));

    expect(inOrder.size).toBe(100);
    expect(reversed.root()).toBe(inOrder.root());
    expect(shuffled.root()).toBe(inOrder.root());
  });

  test('leaf indices follow lexicographic byte ordering', () => {
    const identities = mockIdentities(100);
    const tree = new BoundedMembershipTree();
    identities.forEach((cm, i) => tree.insert(cm, 1_000 + i));

    const sorted = tree.sortedCommitments();
    expect(sorted).toHaveLength(100);

    // Strictly ascending under the canonical byte comparator.
    for (let i = 1; i < sorted.length; i++) {
      expect(compareFieldBytes(sorted[i - 1]!, sorted[i]!)).toBeLessThan(0);
    }

    // A commitment's index is its rank in that ordering.
    for (const [rank, commitment] of sorted.entries()) {
      expect(tree.indexOf(commitment)).toBe(rank);
    }
  });

  test('every one of 100 members proves inclusion in exactly 16 hashes', () => {
    const identities = mockIdentities(100);
    const tree = new BoundedMembershipTree();
    identities.forEach((cm, i) => tree.insert(cm, 1_000 + i));

    const root = tree.rawRoot();

    for (const commitment of identities) {
      const proof = tree.proveMembership(commitment);

      expect(proof.siblings).toHaveLength(TREE_DEPTH);
      expect(proof.leaf).toBe(commitment);
      expect(verifyProof(proof, root)).toBe(true);
    }
  });

  test('a proof for one tree does not verify against a mutated tree', () => {
    const identities = mockIdentities(100);
    const tree = new BoundedMembershipTree();
    identities.forEach((cm, i) => tree.insert(cm, 1_000 + i));

    const proof = tree.proveMembership(identities[0]!);
    const originalRoot = tree.rawRoot();
    expect(verifyProof(proof, originalRoot)).toBe(true);

    // Admitting another identity re-ranks the set and moves the root.
    tree.insert(membershipCommitment(999_999n, 12_345n), 2_000);

    expect(tree.rawRoot()).not.toBe(originalRoot);
    expect(verifyProof(proof, tree.rawRoot())).toBe(false);
  });

  test('tampering with a proof leaf or sibling is rejected', () => {
    const tree = new BoundedMembershipTree();
    mockIdentities(20).forEach((cm, i) => tree.insert(cm, 1_000 + i));

    const proof = tree.proveMembership(tree.sortedCommitments()[5]!);
    const root = tree.rawRoot();

    expect(verifyProof({ ...proof, leaf: proof.leaf + 1n }, root)).toBe(false);
    expect(verifyProof({ ...proof, index: proof.index + 1 }, root)).toBe(false);

    const bentSiblings = [...proof.siblings];
    bentSiblings[0] = bentSiblings[0]! + 1n;
    expect(verifyProof({ ...proof, siblings: bentSiblings }, root)).toBe(false);
  });

  test('a proof with the wrong number of siblings is rejected', () => {
    const tree = new BoundedMembershipTree();
    mockIdentities(10).forEach((cm, i) => tree.insert(cm, 1_000 + i));

    const proof = tree.proveMembership(tree.sortedCommitments()[0]!);
    const truncated = { ...proof, siblings: proof.siblings.slice(0, 15) };

    expect(verifyProof(truncated, tree.rawRoot())).toBe(false);
  });

  test('eviction at the cap drops the lowest-indexed member', () => {
    const capacity = 100;
    const tree = new BoundedMembershipTree(capacity);
    const identities = mockIdentities(capacity);

    identities.forEach((cm, i) => tree.insert(cm, 1_000 + i));
    expect(tree.isFull).toBe(true);

    // Index 0 is the smallest commitment by byte order — a value every
    // peer computes identically, unlike a local activity clock.
    const expectedVictim = tree.sortedCommitments()[0]!;

    const newcomer = membershipCommitment(777_777n, 555_555n);
    const result = tree.insert(newcomer, 5_000);

    expect(result.evicted).toBe(expectedVictim);
    expect(tree.size).toBe(capacity);
    expect(tree.has(expectedVictim)).toBe(false);
    expect(tree.has(newcomer)).toBe(true);
  });

  test('eviction is independent of insertion order and local clocks', () => {
    // The whole point: two peers that saw the same members in different
    // orders, with different activity timestamps, must evict identically
    // — otherwise they fork the root at capacity.
    const left = new BoundedMembershipTree(3);
    const right = new BoundedMembershipTree(3);
    const identities = mockIdentities(3);

    identities.forEach((cm, i) => left.insert(cm, 1_000 + i));
    [...identities].reverse().forEach((cm, i) => right.insert(cm, 9_000 - i));

    const newcomer = membershipCommitment(13n, 17n);
    expect(left.insert(newcomer, 2_000).evicted).toBe(
      right.insert(newcomer, 7_777).evicted,
    );
    expect(left.root()).toBe(right.root());
  });

  test('touching a member does not change who gets evicted', () => {
    // `lastActive` is local bookkeeping and must not influence the root.
    const withTouch = new BoundedMembershipTree(3);
    const without = new BoundedMembershipTree(3);
    const identities = mockIdentities(3);

    identities.forEach((cm, i) => {
      withTouch.insert(cm, 1_000 + i);
      without.insert(cm, 1_000 + i);
    });

    expect(withTouch.touch(identities[0]!, 9_999)).toBe(true);

    const newcomer = membershipCommitment(31n, 41n);
    expect(withTouch.insert(newcomer, 5_000).evicted).toBe(
      without.insert(newcomer, 5_000).evicted,
    );
  });

  test('re-inserting an existing member refreshes rather than duplicates', () => {
    const tree = new BoundedMembershipTree();
    const [a] = mockIdentities(1) as [bigint];

    const first = tree.insert(a, 1_000);
    const second = tree.insert(a, 2_000);

    expect(first.inserted).toBe(true);
    expect(second.inserted).toBe(false);
    expect(tree.size).toBe(1);
    expect(tree.getRecord(a)?.lastActive).toBe(2_000);
  });

  test('removing a member returns the root to its earlier value', () => {
    const tree = new BoundedMembershipTree();
    const identities = mockIdentities(10);

    identities.slice(0, 9).forEach((cm, i) => tree.insert(cm, 1_000 + i));
    const before = tree.root();

    tree.insert(identities[9]!, 2_000);
    expect(tree.root()).not.toBe(before);

    expect(tree.remove(identities[9]!)).toBe(true);
    expect(tree.root()).toBe(before);
  });

  test('an empty tree has the canonical all-zero raw root', () => {
    const tree = new BoundedMembershipTree();

    expect(tree.rawRoot()).toBe(emptyRoot());
    expect(tree.size).toBe(0);
    // The published root is version-bound, so it is deliberately not the
    // bare tree root.
    expect(tree.root()).not.toBe(emptyRoot());
  });

  test('the root binds version, depth and capacity', () => {
    const identities = mockIdentities(5);

    const small = new BoundedMembershipTree(10);
    const large = new BoundedMembershipTree(20);
    identities.forEach((cm, i) => {
      small.insert(cm, 1_000 + i);
      large.insert(cm, 1_000 + i);
    });

    // Same members, same raw tree — but different capacity means a
    // different membership set once eviction applies, so the published
    // roots must differ.
    expect(small.rawRoot()).toBe(large.rawRoot());
    expect(small.root()).not.toBe(large.root());

    expect(small.root()).toBe(
      membershipRoot(MEMBERSHIP_ROOT_VERSION, TREE_DEPTH, 10, small.rawRoot()),
    );
  });

  test('capacity defaults below N_max to keep root computation tractable', () => {
    expect(MAX_LEAVES).toBe(65_536);
    // Root cost is O(N); 65,536 members is ~14 s per rebuild.
    expect(DEFAULT_MAX_MEMBERS).toBe(4_096);
    expect(new BoundedMembershipTree().maxSize).toBe(DEFAULT_MAX_MEMBERS);

    expect(() => new BoundedMembershipTree(MAX_LEAVES + 1)).toThrow(/Capacity/);
    expect(() => new BoundedMembershipTree(0)).toThrow(/Capacity/);
  });

  test('non-canonical and tombstone commitments are rejected', () => {
    const tree = new BoundedMembershipTree();

    expect(() => tree.insert(BN254_SCALAR_FIELD)).toThrow(/NonCanonicalField/);
    expect(() => tree.insert(-1n)).toThrow(/NonCanonicalField/);
    expect(() => tree.insert(0n)).toThrow(/tombstone/);
  });

  test('proving a non-member fails loudly', () => {
    const tree = new BoundedMembershipTree();
    tree.insert(mockIdentities(1)[0]!, 1_000);

    expect(() => tree.proveMembership(12_345n)).toThrow(/not an active member/);
  });
});
