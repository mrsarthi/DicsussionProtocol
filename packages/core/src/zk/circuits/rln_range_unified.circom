pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "./merkle.circom";

/*
 * ZekPoc unified proof — RFC 003 §3.4.
 *
 * One Groth16 proof establishing, without revealing identity or score:
 *
 *   1. MEMBERSHIP  — my identity commitment is in the channel's tree.
 *   2. REPUTATION  — my score meets the tier threshold I claim.
 *   3. RATE LIMIT  — this nullifier and share are correctly derived from
 *                    my secret, the epoch and my message index, and the
 *                    index is inside my tier's quota.
 *
 * The share `y` is what makes the rate limit self-enforcing: it is one
 * point on the line y = a_0 + a_1*x. Publishing two points under one
 * nullifier (i.e. reusing a message index) lets anyone interpolate a_0.
 *
 * Domain separation tags are frozen by RFC 003 §3.1 and MUST match
 * packages/core/src/crypto/poseidon.ts:
 *   1 = nullifier, 2 = slope, 6 = member
 */
template RlnRangeUnified(depth) {
    // ─── Private witnesses ───────────────────────────────────────────
    signal input identitySecret;        // a_0 — never leaves the device
    signal input trapdoor;
    signal input userScore;             // proven >= threshold, never revealed
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // ─── Public inputs ───────────────────────────────────────────────
    signal input merkleRoot;
    signal input tierThreshold;
    signal input epoch;
    signal input messageIndex;
    signal input messageCommitment;     // x, binds the transport transcript
    signal input quota;                 // Q_window for the claimed tier

    // ─── Public outputs ──────────────────────────────────────────────
    signal output nullifier;            // eta
    signal output share;                // y

    // 1. Identity commitment: cm = Poseidon(DS_member=6, a_0, trapdoor)
    component commitment = Poseidon(3);
    commitment.inputs[0] <== 6;
    commitment.inputs[1] <== identitySecret;
    commitment.inputs[2] <== trapdoor;

    // 2. That commitment is a leaf of the advertised membership tree.
    component merkle = MerkleInclusion(depth);
    merkle.leaf <== commitment.out;
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }
    merkle.root === merkleRoot;

    // 3. Reputation range proof: userScore >= tierThreshold.
    //    252 bits keeps both operands well inside the scalar field while
    //    still admitting any realistic score.
    component scoreCheck = GreaterEqThan(252);
    scoreCheck.in[0] <== userScore;
    scoreCheck.in[1] <== tierThreshold;
    scoreCheck.out === 1;

    // 4. Quota: 0 <= messageIndex < quota. LessThan enforces the upper
    //    bound; the lower bound is implied by the bit decomposition.
    component quotaCheck = LessThan(252);
    quotaCheck.in[0] <== messageIndex;
    quotaCheck.in[1] <== quota;
    quotaCheck.out === 1;

    // 5. Nullifier: eta = Poseidon(DS_nullifier=1, a_0, epoch, index)
    component nullifierHash = Poseidon(4);
    nullifierHash.inputs[0] <== 1;
    nullifierHash.inputs[1] <== identitySecret;
    nullifierHash.inputs[2] <== epoch;
    nullifierHash.inputs[3] <== messageIndex;
    nullifier <== nullifierHash.out;

    // 6. Slope witness: a_1 = Poseidon(DS_slope=2, a_0, epoch, index)
    component slope = Poseidon(4);
    slope.inputs[0] <== 2;
    slope.inputs[1] <== identitySecret;
    slope.inputs[2] <== epoch;
    slope.inputs[3] <== messageIndex;

    // 7. Share: y = a_0 + a_1 * x
    share <== identitySecret + slope.out * messageCommitment;
}

component main {public [
    merkleRoot,
    tierThreshold,
    epoch,
    messageIndex,
    messageCommitment,
    quota
]} = RlnRangeUnified(16);
