pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

/*
 * Depth-D Merkle inclusion proof over Poseidon(2).
 *
 * Mirrors `verifyProof` in packages/core/src/crdt/sparse-merkle-tree.ts
 * exactly: at each level, pathIndex 0 means the running node is the LEFT
 * input, 1 means it is the RIGHT input. Any divergence here silently
 * breaks every honest proof, so the host implementation is the spec.
 */
template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];   // 0 = node is left, 1 = node is right
    signal output root;

    component hashers[depth];
    signal nodes[depth + 1];
    signal left[depth];
    signal right[depth];

    nodes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // Path indices must be boolean, otherwise the selector below
        // could be coerced into mixing the two inputs.
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        // index = 0 -> (node, sibling);  index = 1 -> (sibling, node)
        left[i]  <== nodes[i] + pathIndices[i] * (pathElements[i] - nodes[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (nodes[i] - pathElements[i]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];

        nodes[i + 1] <== hashers[i].out;
    }

    root <== nodes[depth];
}
