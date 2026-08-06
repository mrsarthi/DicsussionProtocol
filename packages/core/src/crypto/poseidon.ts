/**
 * @dicsussion/crypto — Domain-Separated Poseidon
 *
 * Poseidon hashing over the BN254 scalar field with the domain
 * separation tags frozen in RFC 003 §3.1.
 *
 * Every protocol hash is prefixed with its tag so a digest produced for
 * one purpose can never be replayed as another (a nullifier can't be
 * passed off as a membership commitment).
 *
 * HASH PRIMITIVE (RFC 003 §3.0, §3.0.1): circomlib-compatible Poseidon
 * via `poseidon-lite`. This is the single swap point for the protocol's
 * hash — every commitment and nullifier in the system flows through
 * `poseidonHash` below.
 *
 * Poseidon2 is deferred, not rejected: no production Circom gadget
 * exists (the circomlib PR has been unmerged since April 2023) and the
 * available attempts are t=3 only, while the domain-separated
 * constructions here need t=5. Matching circomlib is what keeps these
 * digests identical to what the Phase 3 Circom circuits compute.
 *
 * Changing the backend rehashes every identity commitment, nullifier,
 * and Merkle root in existence — a hard fork of the identity set.
 * `tests/crypto/poseidon-vectors.spec.ts` pins the digests so such a
 * change fails loudly rather than silently forking peers apart.
 */

import {
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
} from 'poseidon-lite';

import { assertCanonicalField } from './field.js';

/**
 * Domain separation tags (RFC 003 §3.1).
 *
 * NOTE: RFC 003 §7.1 writes `cm_identity = Poseidon(4, a_0, trapdoor)`,
 * which contradicts §3.1's `DS_member = 6`. §3.1 is the frozen-parameter
 * table and is treated as authoritative here.
 */
export const DomainSeparator = {
  /** Rate-limiting nullifier derivation. */
  NULLIFIER: 1n,
  /** Private witness slope a_1. */
  SLOPE: 2n,
  /** Transport transcript message commitment. */
  MSG: 3n,
  /** Blind endorsement voucher redemption nullifier. */
  VOUCHER: 4n,
  /** Issuer allocation nullifier. */
  ISSUE: 5n,
  /** Membership commitment derivation. */
  MEMBER: 6n,
  /** Versioned membership root binding (RFC 002 §4.1). */
  ROOT: 7n,
  /** Identity trapdoor derivation (RFC 003 §7.1). */
  TRAPDOOR: 8n,
} as const;

export type DomainSeparatorValue =
  (typeof DomainSeparator)[keyof typeof DomainSeparator];

/**
 * Hash 1–5 field elements with Poseidon.
 *
 * All inputs are validated as canonical before hashing (RFC 003 §3.3),
 * so a non-canonical scalar can never reach the permutation.
 *
 * @throws If the arity is unsupported or any input is out of field.
 */
export function poseidonHash(inputs: readonly bigint[]): bigint {
  for (const input of inputs) {
    assertCanonicalField(input);
  }

  switch (inputs.length) {
    case 1:
      return poseidon1(inputs as bigint[]);
    case 2:
      return poseidon2(inputs as bigint[]);
    case 3:
      return poseidon3(inputs as bigint[]);
    case 4:
      return poseidon4(inputs as bigint[]);
    case 5:
      return poseidon5(inputs as bigint[]);
    default:
      throw new Error(
        `Poseidon supports 1–5 inputs, got ${inputs.length}`,
      );
  }
}

/**
 * Hash inputs under an explicit domain separation tag.
 *
 * The tag occupies the first slot: `Poseidon(DS, ...inputs)`.
 *
 * @param domain The RFC 003 §3.1 tag.
 * @param inputs Up to four further field elements.
 */
export function poseidonDomain(
  domain: DomainSeparatorValue,
  ...inputs: bigint[]
): bigint {
  return poseidonHash([domain, ...inputs]);
}

/**
 * Two-input Poseidon used for Merkle path elements.
 *
 * Tree internal nodes are deliberately *not* domain separated: the
 * circuit's Merkle gadget hashes raw (left, right) pairs, and adding a
 * tag here would make host-computed roots disagree with in-circuit ones.
 */
export function poseidonPair(left: bigint, right: bigint): bigint {
  return poseidonHash([left, right]);
}

// ─── Protocol commitments (RFC 003 §4.1, §5, §7.1) ──────────────────────────

/**
 * Derive an identity's trapdoor from its secret.
 *
 * `trapdoor = Poseidon(DS_trapdoor, a_0)`
 *
 * WHY DERIVED RATHER THAN INDEPENDENT: `cm_identity` mixes `a_0` with a
 * trapdoor, and a slashing tombstone must name `cm_identity`. An observer
 * who recovers `a_0` from two shares therefore needs the trapdoor to
 * compute the commitment — and could never know an independently random
 * one. With independent randomness, slashing can only ever fire against
 * yourself, which makes the whole rate limit unenforceable.
 *
 * Deriving it deterministically costs nothing: `a_0` is a uniform 254-bit
 * secret, so the trapdoor is equally unpredictable to anyone without it,
 * and the commitment remains one-way.
 */
export function deriveTrapdoor(identitySecret: bigint): bigint {
  return poseidonDomain(DomainSeparator.TRAPDOOR, identitySecret);
}

/**
 * RLN membership commitment — the identity a revocation tombstone targets.
 *
 * `cm_identity = Poseidon(DS_member, a_0, trapdoor)`
 *
 * @param identitySecret The user's private secret a_0.
 * @param trapdoor Per-identity trapdoor; see {@link deriveTrapdoor}.
 */
export function membershipCommitment(
  identitySecret: bigint,
  trapdoor: bigint,
): bigint {
  return poseidonDomain(DomainSeparator.MEMBER, identitySecret, trapdoor);
}

/**
 * RLN rate-limiting nullifier.
 *
 * `η = Poseidon(DS_nullifier, a_0, epoch, message_index)`
 */
export function rlnNullifier(
  identitySecret: bigint,
  epoch: bigint,
  messageIndex: bigint,
): bigint {
  return poseidonDomain(
    DomainSeparator.NULLIFIER,
    identitySecret,
    epoch,
    messageIndex,
  );
}

/**
 * Private Shamir slope witness a_1.
 *
 * `a_1 = Poseidon(DS_slope, a_0, epoch, message_index)`
 */
export function slopeWitness(
  identitySecret: bigint,
  epoch: bigint,
  messageIndex: bigint,
): bigint {
  return poseidonDomain(
    DomainSeparator.SLOPE,
    identitySecret,
    epoch,
    messageIndex,
  );
}

/**
 * Voucher redemption nullifier.
 *
 * `ν = Poseidon(DS_voucher, serial, scope, cm_redeemer)`
 *
 * Redeeming twice yields the same ν, which is what makes double
 * redemption detectable without learning who redeemed (RFC 003 §5.5).
 */
export function voucherNullifier(
  serial: bigint,
  scope: bigint,
  redeemerCommitment: bigint,
): bigint {
  return poseidonDomain(
    DomainSeparator.VOUCHER,
    serial,
    scope,
    redeemerCommitment,
  );
}

/**
 * Issuer allocation nullifier, enforcing issuance quota without
 * recording who received the voucher.
 *
 * `nullifier_issue = Poseidon(DS_issue, a_0^A, epoch, k)`
 *
 * @param issuerSecret The issuer's identity secret.
 * @param epoch Issuance epoch.
 * @param counter Per-epoch issuance counter k.
 */
export function issuanceNullifier(
  issuerSecret: bigint,
  epoch: bigint,
  counter: bigint,
): bigint {
  return poseidonDomain(
    DomainSeparator.ISSUE,
    issuerSecret,
    epoch,
    counter,
  );
}

/**
 * Bind a raw Merkle root to the algorithm that produced it.
 *
 * `root = Poseidon(DS_root, version, depth, capacity, tree_root)`
 *
 * WHY VERSION THE ROOT: the root algorithm is a one-way door. Once real
 * identity sets exist, changing how the root is computed silently
 * invalidates every root, proof and genesis anchor in the network, with
 * no way for a peer to tell "computed differently" from "different
 * members". Binding the version and parameters makes an algorithm change
 * detectable rather than catastrophic, and lets a future scheme migrate
 * under the RFC 003 §9.4 dual-support window.
 *
 * `depth` and `capacity` are included because both change the meaning of
 * the same tree: the same members under a different capacity are a
 * different membership set once eviction applies.
 */
export function membershipRoot(
  version: number,
  depth: number,
  capacity: number,
  treeRoot: bigint,
): bigint {
  return poseidonHash([
    DomainSeparator.ROOT,
    BigInt(version),
    BigInt(depth),
    BigInt(capacity),
    treeRoot,
  ]);
}
