/**
 * Phase 3A — RLN slashing primitives (RFC 003 §4.1, §7, §8).
 *
 * The security claim under test: staying within quota keeps a sender
 * anonymous, exceeding it surrenders their identity secret, and neither
 * property can be subverted by a hostile observer replaying traffic.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { expect, test } from '@playwright/test';

import { BN254_SCALAR_FIELD } from '../../packages/core/src/crypto/field.js';
import {
  deriveTrapdoor,
  membershipCommitment,
} from '../../packages/core/src/crypto/poseidon.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import {
  createSignal,
  isEpochFresh,
  isWithinQuota,
  quotaForTier,
  signalToShare,
} from '../../packages/core/src/zk/rln.js';
import {
  evaluateShare,
  findSlashablePair,
  recoverSecret,
  verifyRecovery,
} from '../../packages/core/src/zk/shamir.js';
import {
  decodeShareMessage,
  decodeTombstone,
  encodeShare,
  encodeShareBatch,
  encodeTombstone,
  MAX_SHARE_BATCH,
} from '../../packages/HLessEnd/src/slashing/gossip-protocol.js';
import { ShareCollector } from '../../packages/HLessEnd/src/slashing/share-collector.js';
import {
  createSlashingTombstone,
  createUserRevocation,
  encodeTombstoneForSigning,
  RevocationReason,
  verifyTombstone,
} from '../../packages/HLessEnd/src/slashing/tombstone.js';

const SECRET = 555_666_777n;
const TRAPDOOR = 111_222_333n;

/** Distinct message contexts, differing only in ciphertext. */
function context(seed: number, epoch = 100) {
  return {
    version: 1,
    streamId: 2,
    epoch,
    tier: 50,
    ciphertextHash: new Uint8Array(32).fill(seed),
    recipientId: 42n,
  };
}

function validator() {
  const keypair = generateKeypair();
  return { keypair, did: publicKeyToDidKey(keypair.publicKey) };
}

test.describe('ZK — Slashing Polynomial', () => {
  test('a single share reveals nothing about the secret', () => {
    const signal = createSignal(SECRET, context(1), 0);

    // One point lies on infinitely many lines; recovery needs a second.
    expect(findSlashablePair([signalToShare(signal)])).toBeUndefined();
    expect(signal.y).not.toBe(SECRET);
  });

  test('two shares under one nullifier recover the secret exactly', () => {
    const honest = createSignal(SECRET, context(1), 0);
    const overspend = createSignal(SECRET, context(9), 0);

    expect(overspend.nullifier).toBe(honest.nullifier);
    expect(overspend.x).not.toBe(honest.x);

    const found = findSlashablePair([honest, overspend].map(signalToShare));
    expect(found).toBeDefined();
    expect(found!.identitySecret).toBe(SECRET);
    expect(verifyRecovery(found!.identitySecret, found!.slope, found!.shares)).toBe(
      true,
    );
  });

  test('staying within quota never produces a slashable pair', () => {
    const signals = Array.from({ length: 3 }, (_, i) =>
      signalToShare(createSignal(SECRET, context(i + 1), i)),
    );

    expect(findSlashablePair(signals)).toBeUndefined();
  });

  test('replaying one message cannot frame an honest sender', () => {
    const signal = signalToShare(createSignal(SECRET, context(1), 0));

    // Same nullifier AND same x — a duplicate delivery, not overspending.
    const result = recoverSecret(signal, signal);
    expect(result.recovered).toBe(false);
    expect(result).toMatchObject({ reason: 'duplicate-commitment' });
    expect(findSlashablePair([signal, signal])).toBeUndefined();
  });

  test('shares from different nullifiers do not combine', () => {
    const a = signalToShare(createSignal(SECRET, context(1), 0));
    const b = signalToShare(createSignal(SECRET, context(2), 1));

    expect(recoverSecret(a, b)).toMatchObject({
      recovered: false,
      reason: 'nullifier-mismatch',
    });
  });

  test('polynomial evaluation stays inside the scalar field', () => {
    const y = evaluateShare(BN254_SCALAR_FIELD - 1n, BN254_SCALAR_FIELD - 2n, 12_345n);

    expect(y).toBeGreaterThanOrEqual(0n);
    expect(y).toBeLessThan(BN254_SCALAR_FIELD);
  });

  test('different senders sharing an epoch and index stay separate', () => {
    const other = 999_888_777n;
    const a = signalToShare(createSignal(SECRET, context(1), 0));
    const b = signalToShare(createSignal(other, context(1), 0));

    // Nullifiers are bound to the secret, so two senders never collide.
    expect(a.nullifier).not.toBe(b.nullifier);
    expect(findSlashablePair([a, b])).toBeUndefined();
  });
});

test.describe('ZK — Quota & Epoch Rules', () => {
  test('tier quotas match RFC 003 §3.2', () => {
    expect(quotaForTier(0)).toBe(1);
    expect(quotaForTier(50)).toBe(3);
    expect(quotaForTier(100)).toBe(10);
    expect(quotaForTier(200)).toBe(100);
  });

  test('quota is enforced across the rolling window', () => {
    // Tier 1 = 3 msgs/epoch over a 3-epoch window = 9.
    expect(isWithinQuota(8, 50)).toBe(true);
    expect(isWithinQuota(9, 50)).toBe(false);
    expect(isWithinQuota(-1, 50)).toBe(false);
    expect(isWithinQuota(1.5, 50)).toBe(false);
  });

  test('stale and future-dated proofs are both rejected', () => {
    expect(isEpochFresh(100, 100)).toBe(true);
    expect(isEpochFresh(98, 100)).toBe(true);
    expect(isEpochFresh(97, 100)).toBe(false);
    // A lying clock must not buy extra quota.
    expect(isEpochFresh(101, 100)).toBe(false);
  });
});

test.describe('ZK — Share Collector', () => {
  test('detects a quota violation and recovers the secret', () => {
    const collector = new ShareCollector();

    expect(
      collector.observe({ ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 }),
    ).toBeUndefined();
    expect(
      collector.observe({ ...signalToShare(createSignal(SECRET, context(2), 1)), epoch: 100 }),
    ).toBeUndefined();

    const evidence = collector.observe({
      ...signalToShare(createSignal(SECRET, context(9), 0)),
      epoch: 100,
    });

    expect(evidence).toBeDefined();
    expect(evidence!.identitySecret).toBe(SECRET);
    expect(evidence!.shares).toHaveLength(2);
  });

  test('duplicate deliveries of one message are ignored', () => {
    const collector = new ShareCollector();
    const share = { ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 };

    expect(collector.observe(share)).toBeUndefined();
    expect(collector.observe(share)).toBeUndefined();
    expect(collector.observe(share)).toBeUndefined();
    expect(collector.size).toBe(1);
  });

  test('evidence is reported only once per nullifier', () => {
    const collector = new ShareCollector();
    collector.observe({ ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 });

    expect(
      collector.observe({ ...signalToShare(createSignal(SECRET, context(2), 0)), epoch: 100 }),
    ).toBeDefined();
    expect(collector.hasReported(createSignal(SECRET, context(1), 0).nullifier)).toBe(true);

    // A third conflicting share must not re-report.
    expect(
      collector.observe({ ...signalToShare(createSignal(SECRET, context(3), 0)), epoch: 100 }),
    ).toBeUndefined();
  });

  test('pruning drops shares beyond the retention window', () => {
    const collector = new ShareCollector({ retentionEpochs: 2 });

    collector.observe({ ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 });
    collector.observe({ ...signalToShare(createSignal(SECRET, context(2), 1)), epoch: 105 });

    expect(collector.size).toBe(2);

    // Cutoff is 106 - 2 = 104, so epoch 100 is evicted and 105 survives.
    expect(collector.prune(106)).toBe(1);
    expect(collector.size).toBe(1);

    // Advancing far enough clears the rest.
    expect(collector.prune(120)).toBe(1);
    expect(collector.size).toBe(0);
  });

  test('observeAll surfaces every violation in a batch', () => {
    const collector = new ShareCollector();

    const found = collector.observeAll([
      { ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 },
      { ...signalToShare(createSignal(SECRET, context(2), 0)), epoch: 100 },
    ]);

    expect(found).toHaveLength(1);
    expect(found[0]!.identitySecret).toBe(SECRET);
  });
});

test.describe('ZK — Revocation Tombstones', () => {
  /** Produce genuine slashing evidence for the shared test secret. */
  function evidence() {
    const collector = new ShareCollector();
    collector.observe({ ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 });
    return collector.observe({
      ...signalToShare(createSignal(SECRET, context(9), 0)),
      epoch: 100,
    })!;
  }

  test('a tombstone targets the offender and verifies', () => {
    const tombstone = createSlashingTombstone(evidence().shares, TRAPDOOR, validator());

    expect(tombstone.reason).toBe(RevocationReason.SLASHED_DOUBLE_SHARE);
    expect(tombstone.membershipCommitment).toBe(
      membershipCommitment(SECRET, TRAPDOOR),
    );
    expect(verifyTombstone(tombstone).valid).toBe(true);
  });

  test('it targets the identity commitment, not the offender did:key', () => {
    const offender = validator();
    const tombstone = createSlashingTombstone(evidence().shares, TRAPDOOR, validator());

    // RFC 003 §7.1: revocation operates on cm_identity, so it survives
    // transport-layer identity rotation and never names the offender.
    expect(tombstone.membershipCommitment).toBe(
      membershipCommitment(SECRET, TRAPDOOR),
    );

    const fields = Object.keys(tombstone);
    expect(fields).toContain('membershipCommitment');
    expect(fields).not.toContain('offenderDid');
    expect(fields).not.toContain('targetDid');

    // The only did present is the *validator's* — who observed it, not
    // who is being revoked.
    expect(tombstone.validatorDid).not.toBe(offender.did);
  });

  test('refuses to build from non-conflicting shares', () => {
    const a = signalToShare(createSignal(SECRET, context(1), 0));
    const b = signalToShare(createSignal(SECRET, context(2), 1));

    expect(() => createSlashingTombstone([a, b], TRAPDOOR, validator())).toThrow(
      /do not prove a double-spend/,
    );
  });

  test('a forged commitment or secret is rejected', () => {
    const tombstone = createSlashingTombstone(evidence().shares, TRAPDOOR, validator());

    expect(
      verifyTombstone({
        ...tombstone,
        membershipCommitment: tombstone.membershipCommitment + 1n,
      }),
    ).toMatchObject({ valid: false });

    expect(
      verifyTombstone({ ...tombstone, reconstructedSecret: SECRET + 1n }),
    ).toMatchObject({ valid: false });
  });

  test('any tampering breaks the validator signature', () => {
    const tombstone = createSlashingTombstone(evidence().shares, TRAPDOOR, validator());

    expect(
      verifyTombstone({ ...tombstone, timestamp: tombstone.timestamp + 1 }),
    ).toMatchObject({ valid: false, reason: 'bad-signature' });

    expect(
      verifyTombstone({ ...tombstone, revocationId: 'rev-forged' }),
    ).toMatchObject({ valid: false, reason: 'bad-signature' });
  });

  test('a signature from one node cannot be reattributed to another', () => {
    const tombstone = createSlashingTombstone(evidence().shares, TRAPDOOR, validator());

    expect(
      verifyTombstone({ ...tombstone, validatorDid: validator().did }),
    ).toMatchObject({ valid: false, reason: 'bad-signature' });
  });

  test('a correctly signed tombstone with fabricated shares is still rejected', () => {
    const v = validator();
    const real = createSlashingTombstone(evidence().shares, TRAPDOOR, v);

    // Re-sign a doctored payload so the signature itself is valid.
    const doctored = {
      ...real,
      doubleSpendProof: {
        nullifier: real.doubleSpendProof!.nullifier,
        shareOne: { x: 1n, y: 2n },
        shareTwo: { x: 3n, y: 4n },
      },
    };
    const resigned = createResigned(doctored, v);

    // Evidence beats authority: the maths does not check out.
    expect(verifyTombstone(resigned).valid).toBe(false);
  });
});

test.describe('ZK — Gossip Codecs (0x03 / 0x06)', () => {
  test('a single share round-trips', () => {
    const share = { ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 };
    const [decoded] = decodeShareMessage(encodeShare(share));

    expect(decoded).toEqual(share);
  });

  test('a share batch round-trips in order', () => {
    const shares = [1, 2, 3].map((n) => ({
      ...signalToShare(createSignal(SECRET, context(n), n)),
      epoch: 100,
    }));

    expect(decodeShareMessage(encodeShareBatch(shares))).toEqual(shares);
  });

  test('oversized batches are refused', () => {
    const share = { ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 };
    const tooMany = Array.from({ length: MAX_SHARE_BATCH + 1 }, () => share);

    expect(() => encodeShareBatch(tooMany)).toThrow(/exceeds/);
  });

  test('malformed share frames are rejected', () => {
    const encoded = encodeShare({
      ...signalToShare(createSignal(SECRET, context(1), 0)),
      epoch: 100,
    });

    expect(() => decodeShareMessage(encoded.subarray(0, 4))).toThrow(/too small/);
    expect(() => decodeShareMessage(encoded.subarray(0, encoded.length - 4))).toThrow(
      /truncated/,
    );

    const wrongType = encoded.slice();
    wrongType[0] = 0x7f;
    expect(() => decodeShareMessage(wrongType)).toThrow(/Unknown share message type/);
  });

  test('a tombstone survives the wire and still verifies', () => {
    const collector = new ShareCollector();
    collector.observe({ ...signalToShare(createSignal(SECRET, context(1), 0)), epoch: 100 });
    const ev = collector.observe({
      ...signalToShare(createSignal(SECRET, context(9), 0)),
      epoch: 100,
    })!;

    const tombstone = createSlashingTombstone(ev.shares, TRAPDOOR, validator());
    const decoded = decodeTombstone(encodeTombstone(tombstone));

    expect(decoded.membershipCommitment).toBe(tombstone.membershipCommitment);
    expect(decoded.reconstructedSecret).toBe(tombstone.reconstructedSecret);
    expect(verifyTombstone(decoded).valid).toBe(true);
  });

  test('malformed tombstone frames are rejected', () => {
    expect(() => decodeTombstone(new Uint8Array(3))).toThrow(/too small/);
  });
});

/** Re-sign an arbitrary tombstone body, simulating a malicious validator. */
function createResigned(
  tombstone: ReturnType<typeof createSlashingTombstone>,
  v: ReturnType<typeof validator>,
): ReturnType<typeof createSlashingTombstone> {
  const { signature: _drop, ...unsigned } = tombstone;

  return {
    ...tombstone,
    signature: ed25519.sign(encodeTombstoneForSigning(unsigned), v.keypair.secretKey),
  };
}

test.describe('ZK — Voluntary Revocation Cannot Be Forged', () => {
  test('a USER_REVOKED tombstone naming someone else is rejected', () => {
    // The attack: commitments are public — MEMBER_LIST frames gossip them
    // so peers can union their member sets. If a signature alone were
    // enough, anyone who had seen a commitment could permanently revoke
    // it, and revocation is irreversible by design.
    const victimSecret = 424242n;
    const victimCommitment = membershipCommitment(
      victimSecret,
      deriveTrapdoor(victimSecret),
    );

    const attacker = generateKeypair();
    const forged = createUserRevocation(victimCommitment, {
      keypair: attacker,
      did: publicKeyToDidKey(attacker.publicKey),
    });

    // The signature itself is perfectly valid — that is the point.
    const verdict = verifyTombstone(forged);

    expect(verdict.valid).toBe(false);
    expect(verdict.valid === false && verdict.reason).toBe(
      'unprovable-ownership',
    );
  });

  test('even a self-authored voluntary revocation is unverifiable from the wire', () => {
    // Not a bug: nothing on the wire distinguishes this from the forgery
    // above, so a receiver cannot treat them differently. Voluntary
    // retirement is a local action; channel departure is the verifiable
    // way to tell peers you have left.
    const secret = 7n;
    const owner = generateKeypair();

    const own = createUserRevocation(
      membershipCommitment(secret, deriveTrapdoor(secret)),
      { keypair: owner, did: publicKeyToDidKey(owner.publicKey) },
    );

    expect(verifyTombstone(own).valid).toBe(false);
  });

  test('slashing tombstones are still accepted — the fix is narrow', () => {
    // A slashing tombstone binds the commitment to recovered key
    // material, so it verifies. Rejecting those too would have disabled
    // the anti-spam guarantee entirely, which is the failure mode this
    // test exists to catch.
    const collector = new ShareCollector();
    collector.observe({
      ...signalToShare(createSignal(SECRET, context(1), 0)),
      epoch: 100,
    });
    const detected = collector.observe({
      ...signalToShare(createSignal(SECRET, context(9), 0)),
      epoch: 100,
    })!;

    const signer = generateKeypair();
    const tombstone = createSlashingTombstone(detected.shares, TRAPDOOR, {
      keypair: signer,
      did: publicKeyToDidKey(signer.publicKey),
    });

    expect(verifyTombstone(tombstone).valid).toBe(true);
  });
});
