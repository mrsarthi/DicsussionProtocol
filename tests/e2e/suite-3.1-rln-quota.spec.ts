/**
 * Phase 3B — Test Suite 3.1: ZK-RLN Quota Enforcement
 *
 * Node A exceeds its epoch quota; Node B collects the resulting shares,
 * reconstructs `a_0`, and publishes a revocation tombstone that any
 * third party can verify.
 *
 * Uses real Groth16 proofs against the compiled circuit, so this also
 * pins the circuit's outputs to the TypeScript implementations — if they
 * ever diverge, every honest proof in production would fail to verify.
 */

import { join } from 'node:path';

import { expect, test } from '@playwright/test';

import { BoundedMembershipTree } from '../../packages/core/src/crdt/membership-tree.js';
import {
  membershipCommitment,
  rlnNullifier,
  slopeWitness,
} from '../../packages/core/src/crypto/poseidon.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import { messageCommitment, quotaForTier } from '../../packages/core/src/zk/rln.js';
import { evaluateShare } from '../../packages/core/src/zk/shamir.js';
import { ZekPocProver } from '../../packages/core/src/zk/prover.js';
import type { ProofInput } from '../../packages/core/src/zk/prover.js';
import { ShareCollector } from '../../packages/HLessEnd/src/slashing/share-collector.js';
import {
  createSlashingTombstone,
  verifyTombstone,
} from '../../packages/HLessEnd/src/slashing/tombstone.js';
import {
  decodeTombstone,
  encodeTombstone,
} from '../../packages/HLessEnd/src/slashing/gossip-protocol.js';

// Proving is ~1s per proof; several run per test.
test.describe.configure({ timeout: 180_000 });

const ARTIFACTS = join(process.cwd(), 'packages/core/src/zk/artifacts');
const CIRCUIT_JS = join(
  process.cwd(),
  'packages/core/src/zk/circuits/rln_range_unified_js',
);

const prover = new ZekPocProver({
  wasmPath: join(CIRCUIT_JS, 'rln_range_unified.wasm'),
  zkeyPath: join(ARTIFACTS, 'rln_final.zkey'),
  verificationKeyPath: join(ARTIFACTS, 'verification_key.json'),
});

/** Node A — the peer that will overspend. */
const SPAMMER_SECRET = 987_654_321n;
const SPAMMER_TRAPDOOR = 123_456_789n;

const EPOCH = 100;
const TIER = 50;
const SCORE = 75;

/** A channel tree containing the spammer plus some other members. */
function channelTree(): BoundedMembershipTree {
  const tree = new BoundedMembershipTree();

  for (let i = 1; i <= 8; i++) {
    tree.insert(membershipCommitment(BigInt(i * 1_000), BigInt(i * 7)), 1_000 + i);
  }
  tree.insert(membershipCommitment(SPAMMER_SECRET, SPAMMER_TRAPDOOR), 2_000);

  return tree;
}

/** Distinct message commitment per seed. */
function commitmentFor(seed: number): bigint {
  return messageCommitment({
    version: 1,
    streamId: 2,
    epoch: EPOCH,
    tier: TIER,
    ciphertextHash: new Uint8Array(32).fill(seed),
    recipientId: 42n,
  });
}

function proofInput(
  tree: BoundedMembershipTree,
  messageIndex: number,
  seed: number,
): ProofInput {
  const commitment = membershipCommitment(SPAMMER_SECRET, SPAMMER_TRAPDOOR);

  return {
    identitySecret: SPAMMER_SECRET,
    trapdoor: SPAMMER_TRAPDOOR,
    userScore: SCORE,
    merkleProof: tree.proveMembership(commitment),
    merkleRoot: tree.rawRoot(),
    tierThreshold: TIER,
    epoch: EPOCH,
    messageIndex,
    messageCommitment: commitmentFor(seed),
    quota: quotaForTier(TIER) * 3,
  };
}

test.describe('Suite 3.1 — ZK-RLN Quota Enforcement', () => {
  test('an honest proof verifies and matches the TypeScript signal', async () => {
    const tree = channelTree();
    const output = await prover.generateProof(proofInput(tree, 0, 1));

    expect(await prover.verifyProof(output.proof, output.publicSignals)).toBe(true);

    // The circuit and the host must agree exactly, or honest proofs would
    // be rejected in production.
    expect(output.nullifier).toBe(rlnNullifier(SPAMMER_SECRET, BigInt(EPOCH), 0n));
    expect(output.share).toBe(
      evaluateShare(
        SPAMMER_SECRET,
        slopeWitness(SPAMMER_SECRET, BigInt(EPOCH), 0n),
        commitmentFor(1),
      ),
    );
  });

  test('the proof reveals neither the identity secret nor the score', async () => {
    const tree = channelTree();
    const output = await prover.generateProof(proofInput(tree, 0, 1));

    const wire = JSON.stringify({
      proof: output.proof,
      publicSignals: output.publicSignals,
    });

    expect(wire).not.toContain(SPAMMER_SECRET.toString());
    expect(wire).not.toContain(SPAMMER_TRAPDOOR.toString());
    // Only the threshold is public, never the actual score.
    expect(output.publicSignals).toContain(String(TIER));
    expect(output.publicSignals).not.toContain(String(SCORE));
  });

  test('a proof is rejected once its public signals are altered', async () => {
    const tree = channelTree();
    const output = await prover.generateProof(proofInput(tree, 0, 1));

    const tampered = [...output.publicSignals];
    tampered[0] = (BigInt(tampered[0]!) + 1n).toString();

    expect(await prover.verifyProof(output.proof, tampered)).toBe(false);
  });

  test('membership in a different tree cannot be proven', async () => {
    const tree = channelTree();
    const foreign = new BoundedMembershipTree();
    foreign.insert(membershipCommitment(1n, 2n), 1_000);

    // Claiming a root the identity is not part of must fail at witness
    // generation — the Merkle constraint cannot be satisfied.
    await expect(
      prover.generateProof({ ...proofInput(tree, 0, 1), merkleRoot: foreign.rawRoot() }),
    ).rejects.toThrow();
  });

  test('a score below the claimed tier cannot be proven', async () => {
    const tree = channelTree();

    await expect(
      prover.generateProof({ ...proofInput(tree, 0, 1), userScore: 10 }),
    ).rejects.toThrow(/Cannot prove tier/);
  });

  test('a message index at or beyond quota is refused', async () => {
    const tree = channelTree();
    const quota = quotaForTier(TIER) * 3;

    await expect(
      prover.generateProof({ ...proofInput(tree, quota, 1), messageIndex: quota }),
    ).rejects.toThrow(/exceeds quota/);
  });

  test('Node A overspends; Node B recovers a_0 and publishes a tombstone', async () => {
    const tree = channelTree();

    // ── Node A sends two messages honestly, at indices 0 and 1.
    const first = await prover.generateProof(proofInput(tree, 0, 1));
    const second = await prover.generateProof(proofInput(tree, 1, 2));

    // ── Node B observes both. Distinct indices ⇒ distinct nullifiers.
    const collector = new ShareCollector();
    expect(
      collector.observe({
        x: commitmentFor(1),
        y: first.share,
        nullifier: first.nullifier,
        epoch: EPOCH,
      }),
    ).toBeUndefined();
    expect(
      collector.observe({
        x: commitmentFor(2),
        y: second.share,
        nullifier: second.nullifier,
        epoch: EPOCH,
      }),
    ).toBeUndefined();

    // ── Node A now reuses index 0 for a different message: overspending.
    const reused = await prover.generateProof(proofInput(tree, 0, 9));
    expect(reused.nullifier).toBe(first.nullifier);

    // Note the proof itself is perfectly valid — the circuit cannot stop
    // reuse. Enforcement comes from what reuse reveals.
    expect(await prover.verifyProof(reused.proof, reused.publicSignals)).toBe(true);

    const evidence = collector.observe({
      x: commitmentFor(9),
      y: reused.share,
      nullifier: reused.nullifier,
      epoch: EPOCH,
    });

    // ── Node B reconstructs the spammer's identity secret.
    expect(evidence).toBeDefined();
    expect(evidence!.identitySecret).toBe(SPAMMER_SECRET);

    // ── Node B publishes a tombstone; Node C verifies it independently.
    const keypair = generateKeypair();
    const tombstone = createSlashingTombstone(
      evidence!.shares,
      SPAMMER_TRAPDOOR,
      { keypair, did: publicKeyToDidKey(keypair.publicKey) },
    );

    expect(tombstone.membershipCommitment).toBe(
      membershipCommitment(SPAMMER_SECRET, SPAMMER_TRAPDOOR),
    );

    const gossiped = decodeTombstone(encodeTombstone(tombstone));
    expect(verifyTombstone(gossiped).valid).toBe(true);

    // The revoked commitment is the one that was in the channel tree.
    expect(tree.has(gossiped.membershipCommitment)).toBe(true);
  });

  test('staying within quota never yields recoverable evidence', async () => {
    const tree = channelTree();
    const collector = new ShareCollector();

    // Three messages at distinct indices — the Tier 1 per-epoch quota.
    for (let i = 0; i < 3; i++) {
      const output = await prover.generateProof(proofInput(tree, i, i + 1));

      expect(
        collector.observe({
          x: commitmentFor(i + 1),
          y: output.share,
          nullifier: output.nullifier,
          epoch: EPOCH,
        }),
      ).toBeUndefined();
    }

    expect(collector.trackedNullifiers).toBe(3);
  });

  test('a replayed message cannot be used to frame an honest sender', async () => {
    const tree = channelTree();
    const output = await prover.generateProof(proofInput(tree, 0, 1));

    const collector = new ShareCollector();
    const share = {
      x: commitmentFor(1),
      y: output.share,
      nullifier: output.nullifier,
      epoch: EPOCH,
    };

    // A hostile relay echoes the identical signal several times.
    expect(collector.observe(share)).toBeUndefined();
    expect(collector.observe(share)).toBeUndefined();
    expect(collector.observe(share)).toBeUndefined();
    expect(collector.size).toBe(1);
  });
});

test.describe('Suite 3.1 — Trusted Setup Provenance (RFC 003 §11)', () => {
  test('the bundled proving key came from the real ceremony', () => {
    // Inverted on 2026-08-11, when the multi-party ceremony completed:
    // six independent contributors plus a beacon derived from Bitcoin
    // block 962000, whose hash nobody could predict when the commitment
    // was published ~400 blocks earlier.
    //
    // This assertion is now a regression guard rather than a status
    // report. A single-party key can forge membership, tier, and
    // unlimited quota, and every forgery verifies — so if this ever goes
    // true again, a development key has been packaged and the SDK's
    // entire security argument is void.
    expect(prover.usesDevelopmentCeremony).toBe(false);
  });
});
