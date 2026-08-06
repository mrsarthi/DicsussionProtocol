/**
 * @dicsussion/sdk — Groth16 proof attachment
 *
 * Generates and verifies the `rln_range_unified` proof that rides with
 * an anonymous message, establishing in one shot that the sender is a
 * member of the channel, meets a reputation threshold, and is inside
 * their rate-limit quota (RFC 003 §3.4).
 *
 * This is **opt-in** (`ClientConfig.zkProofs`). Proving costs ~1s, and
 * in a two-person chat where the recipient already knows the sender it
 * buys nothing over the cheap RLN signal. It earns its cost in open
 * channels, where "this message came from *some* member in good
 * standing" is exactly the claim that cannot otherwise be made.
 *
 * The verification bindings below are the whole point of the feature. A
 * proof that is not tied to *this* message and *our* membership tree is
 * decorative: it proves someone, somewhere, once satisfied the circuit.
 */

import type { BoundedMembershipTree } from '@dicsussion/core/crdt';
import { deriveTrapdoor, membershipCommitment } from '@dicsussion/core/crypto';
import type { ProverArtifacts, RlnSignal } from '@dicsussion/core/zk';
import { quotaForTier, ZekPocProver } from '@dicsussion/core/zk';
import { isDevelopmentCeremony, requireArtifacts } from '@dicsussion/core/zk';

/** Public signal positions, outputs first then inputs in circuit order. */
const SIGNAL = {
  nullifier: 0,
  share: 1,
  merkleRoot: 2,
  tierThreshold: 3,
  epoch: 4,
  messageIndex: 5,
  messageCommitment: 6,
  quota: 7,
} as const;

const EXPECTED_SIGNAL_COUNT = 8;

/**
 * The only tier a proof may claim today.
 *
 * `userScore` is a **private input the prover supplies**, and nothing in
 * the circuit binds it to the identity commitment, the membership tree,
 * or any attestation. A peer whose real score is 0 can pass
 * `userScore = 999999`, claim `tierThreshold = 200`, and produce a proof
 * that verifies — because the only constraint is `userScore >=
 * tierThreshold`, which the prover satisfies by choosing both sides.
 *
 * Since `quota` is derived from the tier, an accepted forged tier would
 * also grant a 100x rate-limit allowance. Rejecting any non-zero claim
 * makes that unrepresentable rather than merely unused.
 */
const ONLY_SUPPORTED_TIER = 0;

/** A proof as it travels on the wire. */
export interface WireProof {
  readonly proof: unknown;
  readonly publicSignals: readonly string[];
}

export interface ProofServiceDeps {
  /** Filesystem locations of the compiled circuit. */
  readonly artifacts?: ProverArtifacts;
  /** The local identity secret a_0. */
  readonly getIdentitySecret: () => bigint;
  /** Membership tree for a channel, or undefined if none is held. */
  readonly getMembershipTree: (
    channelId: string,
  ) => BoundedMembershipTree | undefined;
  /** Reputation tier being claimed; 0 until tier gating is enabled. */
  readonly getTier?: () => number;
  /**
   * Permit a proving key from a single-party development ceremony.
   *
   * Such a key provides **no security**: whoever generated it can forge
   * membership, tier, and unlimited quota, all silently verifiable. It
   * exists so tests can run.
   *
   * Opting in must be explicit, because the failure mode is invisible —
   * proofs verify perfectly, so nothing looks wrong until someone
   * notices the anti-spam guarantee never held.
   */
  readonly allowDevelopmentCeremony?: boolean;
}

/**
 * Attaches and checks Groth16 proofs on anonymous messages.
 */
export class ProofService {
  private readonly prover: ZekPocProver;
  private readonly getTier: () => number;
  private readonly zkeyPath: string;

  constructor(private readonly deps: ProofServiceDeps) {
    const artifacts = deps.artifacts ?? requireArtifacts();
    this.prover = new ZekPocProver(artifacts);
    this.zkeyPath = artifacts.zkeyPath;
    this.getTier = deps.getTier ?? (() => 0);
  }

  /**
   * Refuse to operate on an unceremonied key unless told to.
   *
   * Checked here rather than in the constructor so a client that never
   * touches a proof-required channel still starts. The marker file
   * beside the zkey is written by the local circuit build and removed by
   * a real ceremony.
   */
  private assertCeremonyAcceptable(): void {
    if (this.deps.allowDevelopmentCeremony) return;
    if (!isDevelopmentCeremony(this.zkeyPath)) return;

    throw new Error(
      'Refusing to use a proving key from a single-party development ' +
        'ceremony: it provides no security, and forged proofs would verify ' +
        'silently. Run a multi-party ceremony (docs/TRUSTED_SETUP_CEREMONY.md), ' +
        'or pass `allowDevelopmentCeremony: true` if this is a test or a ' +
        'local development build.',
    );
  }

  /**
   * Prove membership and quota compliance for an outbound message.
   *
   * @param channelId Channel the message belongs to.
   * @param signal The RLN signal already computed for this message.
   * @throws If the channel has no membership tree, or this node is not
   *   in it. Both are refusals rather than silent downgrades: sending
   *   unproven on a channel configured to require proofs would defeat
   *   the setting.
   */
  async prove(channelId: string, signal: RlnSignal): Promise<WireProof> {
    this.assertCeremonyAcceptable();

    const tree = this.deps.getMembershipTree(channelId);
    if (!tree) {
      throw new Error(
        `Cannot prove membership for channel ${channelId}: no membership tree. ` +
          'Proof-gated sending requires a channel created or joined through ' +
          'GroupService, which is what establishes the member set.',
      );
    }

    const secret = this.deps.getIdentitySecret();
    const trapdoor = deriveTrapdoor(secret);
    const commitment = membershipCommitment(secret, trapdoor);

    let merkleProof;
    try {
      merkleProof = tree.proveMembership(commitment);
    } catch {
      throw new Error(
        `Cannot prove membership for channel ${channelId}: this identity is ` +
          'not in the channel membership tree.',
      );
    }

    const tier = this.getTier();
    if (tier !== ONLY_SUPPORTED_TIER) {
      throw new Error(
        `Cannot claim reputation tier ${tier}: the circuit does not bind ` +
          'userScore to any attestation, so a tier claim proves nothing and ' +
          'must not be made. See RFC 003 §3.4.2.',
      );
    }

    const output = await this.prover.generateProof({
      identitySecret: secret,
      trapdoor,
      userScore: tier,
      merkleProof,
      // The raw root: the version binding wraps the tree rather than
      // being part of it, so the in-circuit gadget sees it unwrapped.
      merkleRoot: tree.rawRoot(),
      tierThreshold: tier,
      epoch: signal.epoch,
      messageIndex: signal.messageIndex,
      messageCommitment: signal.x,
      quota: quotaForTier(tier),
    });

    return { proof: output.proof, publicSignals: output.publicSignals };
  }

  /**
   * Verify an inbound proof and confirm it describes this message.
   *
   * Cryptographic validity is necessary but nowhere near sufficient. A
   * valid proof for a tree the sender invented proves membership of a
   * group of one; a valid proof for a *different* message can be
   * replayed onto this one. So four bindings are checked:
   *
   *   1. `merkleRoot` matches our own view of the channel's members —
   *      without this, anyone can mint a tree containing themselves.
   *   2. `nullifier` matches the one on the message.
   *   3. `messageCommitment` matches the share's x.
   *   4. `share` matches the share's y.
   *   5. `tierThreshold` and `quota` are the tier-0 values — a higher
   *      claim is unbacked (see `ONLY_SUPPORTED_TIER`) and, because
   *      quota follows from tier, would buy a 100x rate-limit
   *      allowance.
   *
   * Bindings 2–4 are what stop a proof being lifted from one message
   * and stapled to another.
   *
   * @returns False on any failure, including a missing tree — an
   *   unverifiable proof is not a passing one.
   */
  async verify(
    channelId: string,
    wire: WireProof,
    expected: { nullifier: bigint; x: bigint; y: bigint },
  ): Promise<boolean> {
    // A verifier trusting an unceremonied key is accepting forgeries, so
    // this throws rather than returning false: a silent rejection would
    // read as "that peer sent a bad proof" and hide the real problem.
    this.assertCeremonyAcceptable();

    const signals = wire.publicSignals;
    if (!Array.isArray(signals) || signals.length !== EXPECTED_SIGNAL_COUNT) {
      return false;
    }

    const tree = this.deps.getMembershipTree(channelId);
    if (!tree) return false;

    let at: (i: number) => bigint;
    try {
      at = (i) => BigInt(signals[i]!);
    } catch {
      return false;
    }

    try {
      if (at(SIGNAL.merkleRoot) !== tree.rawRoot()) return false;
      if (at(SIGNAL.nullifier) !== expected.nullifier) return false;
      if (at(SIGNAL.messageCommitment) !== expected.x) return false;
      if (at(SIGNAL.share) !== expected.y) return false;
      if (at(SIGNAL.tierThreshold) !== BigInt(ONLY_SUPPORTED_TIER)) return false;
      if (at(SIGNAL.quota) !== BigInt(quotaForTier(ONLY_SUPPORTED_TIER))) {
        return false;
      }
    } catch {
      return false;
    }

    return this.prover.verifyProof(wire.proof, signals);
  }
}
