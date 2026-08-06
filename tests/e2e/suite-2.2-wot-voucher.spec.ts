/**
 * Phase 2B — Test Suite 2.2: WoT & Voucher Exchange
 *
 * Runs two live nodes through the synchronous Stream 0x04 blind-voucher
 * handshake and verifies:
 *   - the +5 POC local score update on redemption (RFC 004 §6.1)
 *   - the issuer's −2 POC issuance burn (RFC 003 §5.2)
 *   - unlinkability: the issuer never sees the serial it signed
 *   - replayed vouchers are rejected (RFC 003 §8 `ReplayedVoucher`)
 *   - verified bidirectional sessions credit +10 POC only when all five
 *     RFC 004 §6.2 conditions hold
 *   - the Channel Creator Genesis Anchor bootstraps membership
 */

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import { membershipCommitment } from '../../packages/core/src/crypto/poseidon.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { currentEpoch } from '../../packages/HLessEnd/src/outbox.js';
import {
  bootstrapFromAnchor,
  createGenesisAnchor,
  verifyGenesisAnchor,
} from '../../packages/HLessEnd/src/wot/genesis-anchor.js';
import { SessionTracker } from '../../packages/HLessEnd/src/wot/session-tracker.js';
import { TrustTier } from '../../packages/HLessEnd/src/wot/types.js';

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 3_000,
  pollMs = 10,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return predicate();
}

/** Two connected clients that know each other's encryption and endorsement keys. */
async function createTrustPair(): Promise<{
  alice: DicsussionClient;
  bob: DicsussionClient;
  teardown: () => Promise<void>;
}> {
  const alice = await DicsussionClient.init({ storagePath: ':memory:' });
  const bob = await DicsussionClient.init({ storagePath: ':memory:' });

  alice.addPeer(bob.did, bob.encryptionPublicKey);
  bob.addPeer(alice.did, alice.encryptionPublicKey);

  await alice.connect(bob.getTicket());
  await waitFor(() => bob.getNetworkStatus().peerCount === 1);

  return {
    alice,
    bob,
    teardown: async () => {
      await alice.disconnect();
      await bob.disconnect();
      clearTransportRegistry();
    },
  };
}

test.describe('Suite 2.2 — WoT & Voucher Exchange', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('a peer starts at the untrusted baseline of 0 POC', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const profile = await client.trust.getProfile('did:key:z6MkStranger');

      expect(profile.subjectiveScore).toBe(0);
      expect(profile.tier).toBe(TrustTier.Untrusted);
      expect(profile.isBlacklisted).toBe(false);
    } finally {
      await client.disconnect();
    }
  });

  test('synchronous voucher handshake raises the issuer to +5 POC', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      const before = await alice.trust.getProfile(bob.did);
      expect(before.subjectiveScore).toBe(0);

      // Bob gifts Alice a +5 POC endorsement over Stream 0x04.
      const redeemed = await alice.requestEndorsement(
        bob.did,
        await bob.getEndorsementKey(),
      );
      expect(redeemed).toBe(true);

      const after = await alice.trust.getProfile(bob.did);
      expect(after.subjectiveScore).toBe(5);

      const counters = await alice.trust.getCounters(bob.did);
      expect(counters?.vouchersRedeemed).toBe(1);
    } finally {
      await teardown();
    }
  });

  test('the issuer burns 2 POC for each voucher it mints', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      await alice.requestEndorsement(bob.did, await bob.getEndorsementKey());

      // RFC 003 §5.2: S(A) ← S(A) − 2 on the issuer's own books.
      const selfCounters = await bob.trust.getCounters(bob.did);
      expect(selfCounters?.vouchersIssued).toBe(1);
      expect(selfCounters?.subjectiveScore).toBe(-2);
    } finally {
      await teardown();
    }
  });

  test('the issuer never learns the serial it blind-signed', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      await alice.requestEndorsement(bob.did, await bob.getEndorsementKey());

      // The issuer records only (nullifier_issue, epoch, counter) — no
      // recipient DID and no recipient commitment (RFC 003 §5.2).
      const records = bob.getIssuanceRecords();
      expect(records).toHaveLength(1);

      const serialised = JSON.stringify(
        records.map((r) => ({ ...r, nullifier: r.nullifier.toString() })),
      );
      expect(serialised).not.toContain(alice.did);
      expect(serialised).not.toContain(alice.identityCommitment.toString());
    } finally {
      await teardown();
    }
  });

  test('two endorsements from the same peer accumulate to +10 POC', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      // Distinct scopes yield distinct redemption nullifiers.
      await alice.requestEndorsement(bob.did, await bob.getEndorsementKey(), 1n);
      await alice.requestEndorsement(bob.did, await bob.getEndorsementKey(), 2n);

      const profile = await alice.trust.getProfile(bob.did);
      expect(profile.subjectiveScore).toBe(10);
    } finally {
      await teardown();
    }
  });

  test('a replayed voucher is rejected and does not move the score', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      const pending = alice.trust.beginVoucherRequest(
        await bob.getEndorsementKey(),
        7n,
      );
      const blindSignature = await bob.trust.issueEndorsement(
        pending.blinded,
        0,
        bob.did,
      );
      const token = alice.trust.completeVoucher(pending, blindSignature);

      expect(await alice.trust.redeemVoucher(token, bob.did)).toBe(true);
      expect((await alice.trust.getProfile(bob.did)).subjectiveScore).toBe(5);

      // Same serial + scope + redeemer ⇒ same ν ⇒ rejected.
      expect(await alice.trust.redeemVoucher(token, bob.did)).toBe(false);
      expect((await alice.trust.getProfile(bob.did)).subjectiveScore).toBe(5);
    } finally {
      await teardown();
    }
  });

  test('a corrupted blind signature is rejected at unblinding', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      const pending = alice.trust.beginVoucherRequest(
        await bob.getEndorsementKey(),
        3n,
      );
      const blindSignature = await bob.trust.issueEndorsement(
        pending.blinded,
        0,
        bob.did,
      );

      // A response that was tampered with in transit must fail here,
      // not silently produce a voucher that fails later at redemption.
      expect(() =>
        alice.trust.completeVoucher(pending, blindSignature + 1n),
      ).toThrow(/does not verify/);
    } finally {
      await teardown();
    }
  });

  test('a voucher attributed to the wrong issuer is rejected at redemption', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      const pending = alice.trust.beginVoucherRequest(
        await bob.getEndorsementKey(),
        4n,
      );
      const blindSignature = await bob.trust.issueEndorsement(
        pending.blinded,
        0,
        bob.did,
      );
      const token = alice.trust.completeVoucher(pending, blindSignature);

      // Re-attribute Bob's signature to Alice's own issuing key.
      const forged = { ...token, issuerPublicKey: await alice.getEndorsementKey() };

      expect(await alice.trust.redeemVoucher(forged, alice.did)).toBe(false);
      expect((await alice.trust.getProfile(alice.did)).subjectiveScore).toBe(0);
    } finally {
      await teardown();
    }
  });

  test('issuance quota is enforced per epoch', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      // The default quota is 4 vouchers per 10-second epoch. The loop
      // normally completes well inside one epoch, but it can straddle a
      // boundary — at which point the quota legitimately resets. The
      // epoch is therefore recorded so a rollover is distinguished from
      // a quota failure rather than showing up as a flaky test.
      const startEpoch = currentEpoch();

      let issued = 0;
      let rejection: Error | null = null;

      for (let scope = 0; scope < 6; scope++) {
        try {
          await alice.requestEndorsement(
            bob.did,
            await bob.getEndorsementKey(),
            BigInt(scope),
          );
          issued++;
        } catch (err) {
          rejection = err as Error;
          break;
        }
      }

      if (currentEpoch() === startEpoch) {
        // Wholly within one epoch: the fifth request must be refused.
        expect(issued).toBe(4);
        expect(rejection?.message).toMatch(/quota_exhausted/);
      } else {
        // A rollover granted a fresh allowance; the invariant is only
        // that no single epoch exceeded its quota.
        expect(issued).toBeLessThanOrEqual(8);
      }
    } finally {
      await teardown();
    }
  });

  test('endorsement lifts a peer across the Standard tier threshold', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      // 10 vouchers = 50 POC, the Tier 1 (Standard) boundary. Issuance is
      // quota-limited per epoch, so these are spread across epochs — a
      // peer genuinely cannot mint 50 POC of endorsements in one window.
      for (let i = 0; i < 10; i++) {
        const pending = alice.trust.beginVoucherRequest(
          await bob.getEndorsementKey(),
          BigInt(i),
        );
        const blindSignature = await bob.trust.issueEndorsement(
          pending.blinded,
          Math.floor(i / 4),
          bob.did,
        );
        const token = alice.trust.completeVoucher(pending, blindSignature);

        expect(await alice.trust.redeemVoucher(token, bob.did)).toBe(true);
      }

      const profile = await alice.trust.getProfile(bob.did);
      expect(profile.subjectiveScore).toBe(50);
      expect(profile.tier).toBe(TrustTier.Standard);
    } finally {
      await teardown();
    }
  });

  test('blacklisting drives a peer to -Infinity regardless of vouchers', async () => {
    const { alice, bob, teardown } = await createTrustPair();

    try {
      await alice.requestEndorsement(bob.did, await bob.getEndorsementKey());
      expect((await alice.trust.getProfile(bob.did)).subjectiveScore).toBe(5);

      await alice.trust.blacklist(bob.did);

      const profile = await alice.trust.getProfile(bob.did);
      expect(profile.subjectiveScore).toBe(Number.NEGATIVE_INFINITY);
      expect(profile.isBlacklisted).toBe(true);
      expect(profile.tier).toBe(TrustTier.Untrusted);
    } finally {
      await teardown();
    }
  });
});

test.describe('Suite 2.2 — Verified Bidirectional Sessions (RFC 004 §6.2)', () => {
  const LOCAL = 'did:key:z6MkLocalNode';
  const PEER = 'did:key:z6MkRemotePeer';

  /**
   * Feed a conversation satisfying every condition except those omitted.
   *
   * Credit lands on whichever message first completes the conditions —
   * not necessarily the last one — so this accumulates across the whole
   * exchange rather than returning only the final evaluation.
   */
  function converse(
    tracker: SessionTracker,
    opts: {
      epochs?: number;
      proofValid?: boolean;
      bothSides?: boolean;
      baseTimestamp?: number;
      baseEpoch?: number;
    } = {},
  ): { credited: boolean; blockers: readonly string[] } {
    const epochs = opts.epochs ?? 3;
    const proofValid = opts.proofValid ?? true;
    const bothSides = opts.bothSides ?? true;
    const baseTimestamp = opts.baseTimestamp ?? 1_000;
    const baseEpoch = opts.baseEpoch ?? 100;

    let credited = false;
    let blockers: readonly string[] = [];

    for (let i = 0; i < epochs; i++) {
      const timestamp = baseTimestamp + i * 15;
      const epoch = baseEpoch + i;

      const local = tracker.record({
        peerDid: PEER,
        fromLocal: true,
        epoch,
        timestamp,
        proofValid,
      });
      credited ||= local.credited;
      blockers = local.blockers;

      if (bothSides) {
        const remote = tracker.record({
          peerDid: PEER,
          fromLocal: false,
          epoch,
          timestamp,
          proofValid,
        });
        credited ||= remote.credited;
        if (!credited) blockers = remote.blockers;
      }
    }

    return { credited, blockers };
  }

  test('a full bidirectional session over 3 epochs is credited', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });
    expect(converse(tracker).credited).toBe(true);
  });

  test('a one-sided conversation is never credited', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });
    const result = converse(tracker, { bothSides: false });

    expect(result.credited).toBe(false);
    expect(result.blockers).toContain('no-remote-message');
  });

  test('messages without valid proofs are not credited', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });
    const result = converse(tracker, { proofValid: false });

    expect(result.credited).toBe(false);
    expect(result.blockers).toContain('local-proof-missing');
    expect(result.blockers).toContain('remote-proof-missing');
  });

  test('a burst inside a single epoch fails the 3-epoch minimum', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });

    for (let i = 0; i < 20; i++) {
      tracker.record({
        peerDid: PEER,
        fromLocal: i % 2 === 0,
        epoch: 100,
        timestamp: 1_000,
        proofValid: true,
      });
    }

    const result = tracker.evaluate(PEER, 1_000);
    expect(result.credited).toBe(false);
    expect(result.blockers).toContain('insufficient-epochs');
    expect(result.blockers).toContain('insufficient-duration');
  });

  test('a conversation shorter than 30 seconds is not credited', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });

    for (let i = 0; i < 3; i++) {
      // Three distinct epochs but only 4 seconds of wall clock.
      tracker.record({
        peerDid: PEER,
        fromLocal: true,
        epoch: 100 + i,
        timestamp: 1_000 + i * 2,
        proofValid: true,
      });
      tracker.record({
        peerDid: PEER,
        fromLocal: false,
        epoch: 100 + i,
        timestamp: 1_000 + i * 2,
        proofValid: true,
      });
    }

    const result = tracker.evaluate(PEER, 1_004);
    expect(result.credited).toBe(false);
    expect(result.blockers).toContain('insufficient-duration');
  });

  test('self-chats never count', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });

    const result = tracker.record({
      peerDid: LOCAL,
      fromLocal: true,
      epoch: 100,
      timestamp: 1_000,
      proofValid: true,
    });

    expect(result.credited).toBe(false);
    expect(result.blockers).toContain('self-chat');
  });

  test('a second session within 24 hours is blocked by cooldown', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });

    expect(converse(tracker).credited).toBe(true);
    expect(tracker.isInCooldown(PEER, 1_100)).toBe(true);

    // Another fully qualifying conversation immediately afterwards.
    const second = converse(tracker, { baseTimestamp: 2_000, baseEpoch: 200 });

    expect(second.credited).toBe(false);
    expect(second.blockers).toContain('cooldown-active');
  });

  test('a session qualifies again once the cooldown lapses', () => {
    const tracker = new SessionTracker({ localDid: LOCAL });
    expect(converse(tracker).credited).toBe(true);

    // 24 hours and change later.
    const second = converse(tracker, {
      baseTimestamp: 1_000 + 86_400 + 60,
      baseEpoch: 900,
    });

    expect(second.credited).toBe(true);
  });
});

test.describe('Suite 2.2 — Channel Creator Genesis Anchor', () => {
  test('a creator bootstraps a channel and the anchor verifies', () => {
    const keypair = generateKeypair();
    const did = publicKeyToDidKey(keypair.publicKey);
    const commitment = membershipCommitment(42n, 99n);

    const { anchor, tree } = createGenesisAnchor(
      'general',
      keypair,
      did,
      commitment,
      1_700_000_000,
    );

    expect(verifyGenesisAnchor(anchor)).toBe(true);
    expect(tree.size).toBe(1);
    expect(tree.has(commitment)).toBe(true);
    expect(anchor.initialRoot).toBe(tree.root());
  });

  test('a joining peer rebuilds the same tree from the anchor alone', () => {
    const keypair = generateKeypair();
    const did = publicKeyToDidKey(keypair.publicKey);
    const commitment = membershipCommitment(7n, 11n);

    const { anchor, tree } = createGenesisAnchor('general', keypair, did, commitment);
    const rebuilt = bootstrapFromAnchor(anchor);

    expect(rebuilt.root()).toBe(tree.root());
    expect(rebuilt.has(commitment)).toBe(true);
  });

  test('a tampered anchor fails verification', () => {
    const keypair = generateKeypair();
    const did = publicKeyToDidKey(keypair.publicKey);
    const { anchor } = createGenesisAnchor(
      'general',
      keypair,
      did,
      membershipCommitment(1n, 2n),
    );

    expect(verifyGenesisAnchor({ ...anchor, channelId: 'other' })).toBe(false);
    expect(
      verifyGenesisAnchor({ ...anchor, creatorCommitment: anchor.creatorCommitment + 1n }),
    ).toBe(false);
    expect(verifyGenesisAnchor({ ...anchor, createdAt: anchor.createdAt + 1 })).toBe(false);
  });

  test('an anchor signed by a different key is rejected', () => {
    const creator = generateKeypair();
    const impostor = generateKeypair();
    const commitment = membershipCommitment(5n, 6n);

    // Impostor signs but claims the creator's DID.
    const { anchor } = createGenesisAnchor(
      'general',
      impostor,
      publicKeyToDidKey(creator.publicKey),
      commitment,
    );

    expect(verifyGenesisAnchor(anchor)).toBe(false);
    expect(() => bootstrapFromAnchor(anchor)).toThrow(/signature verification/);
  });

  test('an anchor whose initialRoot disagrees with its creator is rejected', () => {
    const keypair = generateKeypair();
    const did = publicKeyToDidKey(keypair.publicKey);
    const { anchor } = createGenesisAnchor(
      'general',
      keypair,
      did,
      membershipCommitment(3n, 4n),
    );

    // A different root requires a fresh signature, so this fails at the
    // signature check before the root comparison is even reached.
    expect(() =>
      bootstrapFromAnchor({ ...anchor, initialRoot: anchor.initialRoot + 1n }),
    ).toThrow(/signature verification/);
  });
});
