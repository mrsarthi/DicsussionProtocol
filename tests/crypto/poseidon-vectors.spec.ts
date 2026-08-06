/**
 * Pinned Poseidon digest vectors.
 *
 * Every identity commitment, nullifier, and Merkle root in the protocol
 * is a Poseidon digest. Changing the hash backend, a domain separation
 * tag, or an input ordering silently rehashes all of them — peers would
 * still agree with themselves and quietly fork away from everyone else.
 *
 * These vectors freeze the current values so such a change fails loudly.
 *
 * A failure here is NOT a flaky test. It means either:
 *   - the hash backend changed (see RFC 003 §3.0.1 migration trigger), or
 *   - a domain separation tag or argument order changed.
 * Both are hard forks of the identity set. Do not "fix" this file by
 * pasting in new numbers without understanding which change caused it.
 */

import { expect, test } from '@playwright/test';

import {
  BoundedMembershipTree,
  DEFAULT_MAX_MEMBERS,
  MEMBERSHIP_ROOT_VERSION,
} from '../../packages/core/src/crdt/membership-tree.js';
import {
  emptyRoot,
  TREE_DEPTH,
  zeroHashes,
} from '../../packages/core/src/crdt/sparse-merkle-tree.js';
import {
  issuanceNullifier,
  membershipCommitment,
  membershipRoot,
  poseidonHash,
  rlnNullifier,
  slopeWitness,
  voucherNullifier,
} from '../../packages/core/src/crypto/poseidon.js';

test.describe('Crypto — Pinned Poseidon Vectors', () => {
  test('raw Poseidon matches circomlib for arity 1 through 5', () => {
    // Arity 2 and 3 are the published circomlib test vectors; the rest
    // are pinned from this implementation to catch backend drift.
    expect(poseidonHash([1n])).toBe(
      18586133768512220936620570745912940619677854269274689475585506675881198879027n,
    );
    expect(poseidonHash([1n, 2n])).toBe(
      7853200120776062878684798364095072458815029376092732009249414926327459813530n,
    );
    expect(poseidonHash([1n, 2n, 3n])).toBe(
      6542985608222806190361240322586112750744169038454362455181422643027100751666n,
    );
    expect(poseidonHash([1n, 2n, 3n, 4n])).toBe(
      18821383157269793795438455681495246036402687001665670618754263018637548127333n,
    );
    expect(poseidonHash([1n, 2n, 3n, 4n, 5n])).toBe(
      6183221330272524995739186171720101788151706631170188140075976616310159254464n,
    );
  });

  test('protocol commitments are pinned (RFC 003 §3.1, §4.1, §5, §7.1)', () => {
    expect(membershipCommitment(12_345n, 67_890n)).toBe(
      18370413424925250233123063401295719033677941627915038714404507929135309024631n,
    );
    expect(rlnNullifier(12_345n, 100n, 3n)).toBe(
      13460831855955614826659429247671845734143518247379578300446808572910860781592n,
    );
    expect(slopeWitness(12_345n, 100n, 3n)).toBe(
      17539524353299644863142940035250329514892991912924568717471090494197875526075n,
    );
    expect(voucherNullifier(11n, 22n, 33n)).toBe(
      17316590273572532794903372698207028477915338992402891243903651059074647886991n,
    );
    expect(issuanceNullifier(12_345n, 100n, 2n)).toBe(
      3734841780248093935537540861773332492875350873310631979935931810116866711759n,
    );
  });

  test('membership commitment uses DS_member = 6, not the §7.1 erratum value 4', () => {
    // RFC 003 §7.1 originally wrote Poseidon(4, a_0, trapdoor), which is
    // DS_voucher's tag. Tag 4 must produce a different digest, or
    // membership commitments would collide with voucher nullifiers.
    const correct = membershipCommitment(12_345n, 67_890n);
    const errataneous = poseidonHash([4n, 12_345n, 67_890n]);

    expect(correct).toBe(poseidonHash([6n, 12_345n, 67_890n]));
    expect(correct).not.toBe(errataneous);
  });

  test('sparse tree zero hashes and empty root are pinned', () => {
    const zeros = zeroHashes();

    expect(zeros).toHaveLength(TREE_DEPTH + 1);
    expect(zeros[0]).toBe(0n);
    expect(zeros[1]).toBe(
      14744269619966411208579211824598458697587494354926760081771325075741142829156n,
    );
    expect(emptyRoot()).toBe(
      19217088683336594659449020493828377907203207941212636669271704950158751593251n,
    );
    expect(zeros[TREE_DEPTH]).toBe(emptyRoot());
  });

  test('a populated membership root is pinned', () => {
    const tree = new BoundedMembershipTree();

    for (let i = 1; i <= 5; i++) {
      tree.insert(membershipCommitment(BigInt(i), BigInt(i * 7)), 1_000 + i);
    }

    // The raw tree root — what inclusion proofs and the circuit verify
    // against. Unchanged by the version wrapper introduced above it.
    expect(tree.rawRoot()).toBe(
      8338691658242661325720325054197416076790865122025087901534250909521329078178n,
    );

    // The published, version-bound root (RFC 002 §4.1). Changing the
    // version, depth or capacity changes this — which is the point.
    expect(tree.root()).toBe(
      7088393757832016170287368163230999807342066123420631296527994401503284872964n,
    );
  });

  test('the version binding is pinned', () => {
    // Guards the parameters themselves: bumping the version or the
    // default capacity is a network-wide migration, never incidental.
    expect(MEMBERSHIP_ROOT_VERSION).toBe(1);
    expect(TREE_DEPTH).toBe(16);
    expect(DEFAULT_MAX_MEMBERS).toBe(4_096);

    expect(membershipRoot(1, 16, 4_096, 0n)).toBe(
      poseidonHash([7n, 1n, 16n, 4_096n, 0n]),
    );
  });
});
