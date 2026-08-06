/**
 * @dicsussion/crdt — Bounded Sparse Merkle Tree (D=16)
 *
 * Fixed-depth Poseidon Merkle tree over 2^16 = 65,536 leaf slots, per
 * RFC 002 §4.1 and the frozen parameters in RFC 003 §3.0.
 *
 * Depth is fixed so every membership proof is exactly 16 hashes
 * (~160 circuit constraints), keeping Phase 3 proving cost constant
 * regardless of how full the tree is.
 *
 * Empty slots hold `cm_empty = 0`. Because most of the tree is empty,
 * roots are computed with precomputed per-level zero subtree hashes and
 * only the populated prefix is walked — O(N·D) rather than O(2^D).
 */

import { poseidonPair } from '../crypto/poseidon.js';
import { assertCanonicalField } from '../crypto/field.js';

/** Frozen tree depth (RFC 003 §3.0). */
export const TREE_DEPTH = 16;

/** Maximum active commitments, N_max = 2^16. */
export const MAX_LEAVES = 1 << TREE_DEPTH;

/** Tombstone value for an unoccupied leaf. */
export const EMPTY_LEAF = 0n;

/** A Merkle inclusion proof — always exactly TREE_DEPTH siblings. */
export interface MerkleProof {
  /** The leaf being proven. */
  readonly leaf: bigint;
  /** Leaf index within the tree. */
  readonly index: number;
  /** Sibling hashes, level 0 (leaf level) upward. */
  readonly siblings: readonly bigint[];
}

/**
 * Zero-subtree hash for each level, cached across all tree instances.
 *
 * `zeros[0] = 0`, `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`.
 */
let zeroCache: bigint[] | null = null;

/** Per-level hashes of an entirely empty subtree. */
export function zeroHashes(): readonly bigint[] {
  if (zeroCache) return zeroCache;

  const zeros: bigint[] = [EMPTY_LEAF];
  for (let level = 1; level <= TREE_DEPTH; level++) {
    const below = zeros[level - 1]!;
    zeros.push(poseidonPair(below, below));
  }

  zeroCache = zeros;
  return zeros;
}

/** The root of a completely empty tree. */
export function emptyRoot(): bigint {
  return zeroHashes()[TREE_DEPTH]!;
}

/**
 * Materialised tree levels: `levels[0]` is the populated leaf prefix,
 * `levels[TREE_DEPTH]` is the single-element root level.
 *
 * Building this once and reading many proofs out of it turns bulk proof
 * generation from O(N²·D) into O(N·D).
 */
export type TreeLevels = readonly (readonly bigint[])[];

/**
 * Build every tree level from a dense, ordered leaf array.
 *
 * Slots beyond `leaves.length` are implicitly empty, so only the
 * populated prefix costs any hashing.
 *
 * @param leaves Leaves in index order, length ≤ MAX_LEAVES.
 */
export function buildLevels(leaves: readonly bigint[]): TreeLevels {
  if (leaves.length > MAX_LEAVES) {
    throw new Error(
      `Leaf count ${leaves.length} exceeds capacity ${MAX_LEAVES}`,
    );
  }

  const zeros = zeroHashes();
  const levels: bigint[][] = [[...leaves]];

  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    const current = levels[depth]!;
    const zeroAtLevel = zeros[depth]!;
    const next: bigint[] = [];

    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]!;
      // A missing right sibling means that whole subtree is empty.
      const right = i + 1 < current.length ? current[i + 1]! : zeroAtLevel;
      next.push(poseidonPair(left, right));
    }

    levels.push(next);
  }

  return levels;
}

/** Read the root out of prebuilt levels. */
export function rootFromLevels(levels: TreeLevels): bigint {
  return levels[TREE_DEPTH]?.[0] ?? emptyRoot();
}

/**
 * Compute the root over a dense, ordered leaf array.
 *
 * @param leaves Leaves in index order, length ≤ MAX_LEAVES.
 */
export function computeRoot(leaves: readonly bigint[]): bigint {
  if (leaves.length === 0) return emptyRoot();
  return rootFromLevels(buildLevels(leaves));
}

/**
 * Extract an inclusion proof from prebuilt levels.
 *
 * @param levels Output of `buildLevels`.
 * @param index Leaf index to prove.
 */
export function proofFromLevels(levels: TreeLevels, index: number): MerkleProof {
  if (index < 0 || index >= MAX_LEAVES) {
    throw new Error(`Leaf index ${index} out of range [0, ${MAX_LEAVES})`);
  }

  const zeros = zeroHashes();
  const siblings: bigint[] = [];
  let cursor = index;

  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    const level = levels[depth] ?? [];
    const siblingIndex = cursor % 2 === 0 ? cursor + 1 : cursor - 1;

    siblings.push(
      siblingIndex < level.length ? level[siblingIndex]! : zeros[depth]!,
    );

    cursor = Math.floor(cursor / 2);
  }

  const leafLevel = levels[0] ?? [];

  return {
    leaf: index < leafLevel.length ? leafLevel[index]! : EMPTY_LEAF,
    index,
    siblings,
  };
}

/**
 * Build an inclusion proof for a leaf index.
 *
 * Convenience wrapper over `buildLevels` + `proofFromLevels`. Prefer the
 * two-step form when proving more than one leaf of the same tree.
 *
 * @param leaves Leaves in index order.
 * @param index Index to prove.
 */
export function generateProof(
  leaves: readonly bigint[],
  index: number,
): MerkleProof {
  return proofFromLevels(buildLevels(leaves), index);
}

/**
 * Recompute a root from a proof and check it against the expected value.
 *
 * This is the host-side mirror of the in-circuit Merkle gadget: the
 * verification path here must hash in exactly the same order the circuit
 * will, or Phase 3 proofs will not validate against host-computed roots.
 *
 * @returns True if the proof reconstructs `expectedRoot`.
 */
export function verifyProof(proof: MerkleProof, expectedRoot: bigint): boolean {
  if (proof.siblings.length !== TREE_DEPTH) return false;
  if (proof.index < 0 || proof.index >= MAX_LEAVES) return false;

  try {
    assertCanonicalField(proof.leaf);
    for (const sibling of proof.siblings) {
      assertCanonicalField(sibling);
    }
  } catch {
    return false;
  }

  let node = proof.leaf;
  let cursor = proof.index;

  for (const sibling of proof.siblings) {
    node = cursor % 2 === 0
      ? poseidonPair(node, sibling)
      : poseidonPair(sibling, node);
    cursor = Math.floor(cursor / 2);
  }

  return node === expectedRoot;
}
