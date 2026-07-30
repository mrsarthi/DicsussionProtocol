# RFC 003: ZekPoc Security Envelope, Dynamic ZK-RLN Anti-Spam & Reputation Range Proofs

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-07-28

---

## 1. Overview
This specification defines the cryptographic security, privacy, dynamic anti-spam, and zero-knowledge reputation layer for the ZekPoc network stack. To eliminate spam without central authorities or identity leaks, ZekPoc uses a **Tiered Zero-Knowledge Rate-Limiting Nullifier (ZK-RLN)** system based on Groth16 zk-SNARKs over the BN254 curve. Users prove they meet a reputation score threshold using **ZK Range Proofs** and redeem **Blind Endorsement Vouchers** without revealing their identity or exact score balance. Messages are end-to-end encrypted (E2EE) using X25519 and AES-256-GCM, with compromised keys revoked via gossip tombstones on Sub-Stream `0x03`.

---

## 2. Non-Goals
- **Local Graph Storage & WoT Calculation:** Database schemas, local interaction scoring algorithms, and IndexedDB/SQLite persistence (defined in `specs/04-headless-backend.md`).
- **Transport Routing:** P2P NAT traversal, QUIC streams, or Render relaying (defined in `specs/01-transport.md`).
- **CRDT Sync:** Automerge document reconciliation or Merkle sync trees (defined in `specs/02-data-sync-lenses.md`).

---

## 3. ZK Reputation Tiering & Range Proofs

To prevent user fingerprinting, exact local Web-of-Trust (WoT) scores are never broadcast across the network. Instead, users generate a Groth16 Zero-Knowledge Range Proof proving their score meets or exceeds a target **Tier Threshold** ($\text{score} \ge \text{threshold}$).

### 3.1 Trust Tiers & Quota Allocation

| Tier Level | Score Range (POCs) | Dynamic Epoch Quota ($Q(T)$) | Message Interval |
| :--- | :--- | :--- | :--- |
| **Tier 0 (Untrusted)** | $0 \le \text{Score} < 50$ | 1 msg / 10s | Restricted |
| **Tier 1 (Standard)** | $50 \le \text{Score} < 100$ | 1 msg / 10s | Baseline |
| **Tier 2 (Established)** | $100 \le \text{Score} < 200$ | 3 msgs / 10s | Fast |
| **Tier 3 (High Reputation)**| $\text{Score} \ge 200$ | 10 msgs / 10s | Unrestricted |

The reputation tier proof MUST be bound to a fresh state root and a recent epoch. Verification MUST reject proofs older than a small tolerance window (default: 2 epochs, or 20 seconds) unless the proof explicitly includes the current state root hash and epoch. This prevents stale proofs from being reused after a peer has been slashed or their score has decayed.

### 3.2 Canonical Field Encodings
All scalar field elements $v$ submitted to circuits or transmitted across the wire MUST strictly conform to canonical BN254 scalar field bounds:
$$0 \le v < r$$
Where $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617 \approx 2^{254}$. Non-canonical encodings ($v \ge r$) MUST be rejected immediately prior to host processing or verification.

### 3.3 Circom Range Proof Circuit (`range_proof.circom`)

The circuit decomposes the difference $\Delta = \text{score} - \text{threshold}$ into bit constraints to cryptographically prove $\Delta \ge 0$:

    pragma circom 2.1.5;
    include "node_modules/circomlib/circuits/bitify.circom";

    template ScoreRangeProof(nBits) {
        // Public Inputs
        signal input tier_threshold;
        
        // Private Inputs
        signal private input user_score;
        
        // Output
        signal output valid_tier;

        // Compute difference
        signal diff;
        diff <== user_score - tier_threshold;

        // Enforce range constraint via bit decomposition (2^nBits capacity)
        component n2b = Num2Bits(nBits);
        n2b.in <== diff;

        valid_tier <== 1;
    }

---

## 4. Dynamic ZK-RLN Anti-Spam Engine

ZekPoc enforces rate limits using Poseidon hashing over the BN254 scalar field. Epochs are 10-second intervals ($\text{epoch} = \lfloor\text{unix\_timestamp} / 10\rfloor$).

### 4.1 Slashing Polynomial, Domain Separation & Transcript Binding
The RLN circuit evaluates a 2-of-2 Shamir Secret Sharing polynomial:
$$y = a_0 + a_1 \cdot x \pmod r$$

Where:
- $a_0$ is the user's private identity secret (`identity_secret`).
- $a_1$ is an internal private witness derived via Poseidon domain separation ($DS_{\text{slope}} = 2$):
  $$a_1 = \text{Poseidon}(2, a_0, \text{epoch}, \text{message\_index})$$
- $\eta$ is the public rate-limiting nullifier derived via Poseidon domain separation ($DS_{\text{nullifier}} = 1$):
  $$\eta = \text{Poseidon}(1, a_0, \text{epoch}, \text{message\_index})$$
- $x$ is the public message commitment fully binding transport context via domain separation ($DS_{\text{MSG}} = 3$):
  $$x = \text{Poseidon}(3, H(\text{version} \parallel \text{stream\_id} \parallel \text{epoch} \parallel \text{tier} \parallel \text{ciphertext\_hash} \parallel \text{recipient\_id}) \pmod r)$$

To prevent cross-epoch quota evasion, the circuit MUST enforce a rolling window constraint over multiple epochs. The effective quota is computed as:
$$i < Q_{\text{window}}(T, W)$$
where $W$ is the rolling window size (e.g. 3 epochs, 30 seconds). The nullifier MUST also be chained across epochs so that over-quota behavior cannot be split across adjacent epochs without detection:
$$\eta_t = \text{Poseidon}(\eta_{t-1}, a_1, \text{epoch})$$

Because $a_1$ is maintained strictly as an internal private witness and domain-separated from $\eta$, an adversary cannot extract $a_0$ from a single evaluation. 

#### In-Circuit Quota Bounding:
To prevent rate-limit evasion via arbitrary sequence choices, the private signal `message_index` ($i$) is strictly bounded inside the circuit against the public tier quota limit $Q(T)$ via a 32-bit comparator constraint:
$$0 \le i < Q(T)$$

If a user sends more messages than their proven **Tier Quota** within the same epoch, receiving peers combine two shares $(x_1, y_1)$ and $(x_2, y_2)$ under the same nullifier $\eta$ to reconstruct $a_0$:
$$a_0 \equiv \frac{y_1 \cdot x_2 - y_2 \cdot x_1}{x_2 - x_1} \pmod r$$

Reconstructing $a_0$ reveals the spammer's identity secret, enabling automated revocation tombstones across the P2P mesh.

### 4.2 Dynamic RLN Circuit Signals (`rln.circom`)

    // Public Inputs
    signal input x;                // Bound transcript message commitment Poseidon(3, H(Env))
    signal input epoch;            // Current 10s epoch ID
    signal input rln_merkle_root;  // Group membership Merkle root
    signal input tier_threshold;   // Claimed tier threshold (0, 50, 100, 200)
    signal input quota_limit;      // Public tier quota Q(T)
    
    // Public Outputs
    signal output y;               // Evaluation share (a_0 + a_1 * x)
    signal output nullifier;       // Poseidon(1, a_0, epoch, message_index)

    // Private Witnesses
    signal private input identity_secret; // User secret key (a_0)
    signal private input user_score;      // Raw local trust score
    signal private input message_index;   // Sequence index i within epoch quota
    signal private input path_elements[]; // Merkle path elements
    signal private input path_index[];    // Merkle path indices

---

## 5. Blind Endorsement Vouchers (+5 Gift)

To support metadata-private "+5 POC" gifts between peers, ZekPoc uses **Chaumian Blind Signatures** (e.g., Blind BLS or RSA-FDH).

1. **Blinding:** Receiver B generates a random serial token $s$ and scope parameter, computes blinded commitment $B = \text{Blind}(s)$, and transmits $B$ to Peer A.
2. **Signing:** Peer A signs $B$ using their private signing key and returns signature $S_A(B)$.
3. **Unblinding:** Receiver B unblinds the signature to obtain $S_A(s)$, a valid voucher signed by Peer A.
4. **Redemption Nullifier:** To prevent double-spending vouchers, redemption enforces a public voucher nullifier:
   $$\nu = H_{\text{voucher}}(\text{serial}, \text{scope}, cm_{\text{redeemer}})$$
   where $cm_{\text{redeemer}} = \text{Poseidon}(a_0^{\text{redeemer}})$ is a binding commitment to the redeemer's identity secret.
   This is the canonical nullifier formula for all compliant implementations. Any implementation that uses the legacy formula $\nu = H_{\text{voucher}}(\text{serial}, \text{scope})$ MUST be treated as non-compliant and rejected by the network.
5. **ZK Verification:** Peer B presents a Groth16 proof to the network proving the following three statements, and only this form is compliant:
   - *"I hold a valid blind signature $S_A(s)$ from a Tier 2+ peer."*
   - *"Nullifier $\nu$ has not been redeemed previously."*
   - *"The proof is bound to my redeemer identity commitment."*
   - **Privacy Result:** Neither Peer A's identity nor Peer B's identity is linked to the endorsement beyond the binding commitment used for replay prevention.

---

## 6. Encrypted Wire Envelope Structure

All payloads sent over Sub-Stream `0x02` MUST be wrapped in a binary security envelope containing the Groth16 proofs, ephemeral public key, and AES-256-GCM ciphertext.

### 6.1 Wire Format

The `version` field is mandatory and MUST appear as the first field in the envelope struct, at offset 0. Implementations MUST reject any envelope that omits this byte or that uses a different wire layout without a negotiated protocol version. This is the only compliant wire layout for the security envelope.

    pub struct SecurityEnvelope {
        pub version: u8,                    // 1 byte: Protocol version (0x01)
        pub epoch: u64,                     // 8 bytes: Epoch ID (10s window)
        pub tier_threshold: u16,            // 2 bytes: Proven Tier (0, 50, 100, 200)
        pub rln_nullifier: [u8; 32],        // 32 bytes: Poseidon nullifier
        pub zk_tier_proof: Vec<u8>,         // ~128 bytes: Groth16 Range Proof
        pub zk_rln_proof: Vec<u8>,          // ~128 bytes: Groth16 RLN Proof
        pub ephemeral_pubkey: [u8; 32],     // 32 bytes: Ephemeral X25519 key
        pub nonce: [u8; 12],                // 12 bytes: AES-256-GCM nonce
        pub ciphertext: Vec<u8>,            // Variable length encrypted payload
    }

#### Zero-Copy Parser View & Compression Limits:
Parsers extract `rln_nullifier` and proof byte buffers using exact zero-copy offsets (`frame.subarray()`). Compressed payloads enforce a maximum **1 MB** LZ4 decompression limit prior to memory expansion.

---

## 7. Key Revocation & Tombstone Gossip

Compromised or slashed identities are neutralized via signed **Revocation Tombstones** over Sub-Stream `0x03`.

### 7.1 Cryptographic Slashing Target & Record Structure
Revocation tombstones operate on the **RLN Membership Commitment** ($cm_{\text{identity}}$) rather than transport layer identifiers (e.g., `did:key`):
$$cm_{\text{identity}} = \text{Poseidon}(4, a_0, \text{trapdoor})$$

To prevent spoofed revocations, tombstones MUST include verifiable cryptographic proof of double-spending consisting of two distinct proofs ($\pi_1, \pi_2$) exhibiting identical nullifiers ($\eta_1 = \eta_2$) but different message commitments ($x_1 \neq x_2$).

    {
      "revocation_id": "rev-9a8b7c6d-1e2f",
      "membership_commitment": "0x1d2e3f...", // RLN Membership Commitment cm_identity
      "reason": "SLASHED_DOUBLE_SHARE",      // Options: USER_REVOKED, SLASHED_DOUBLE_SHARE
      "double_spend_proof": {
        "nullifier": "0x89ab...",
        "share_1": { "x": "0x12a...", "y": "0x34b...", "proof": "0x..." },
        "share_2": { "x": "0x56c...", "y": "0x78d...", "proof": "0x..." }
      },
      "reconstructed_secret": "0x45ef...",  // Reconstructed identity secret a_0
      "timestamp": 1785149200,
      "signature": "3045022100a8b9..."        // Validator Ed25519 signature
    }

---

## 8. Edge Cases & Error Handling

| Error Condition | Cause | System Action |
| :--- | :--- | :--- |
| `InvalidRangeProof` | `user_score < tier_threshold` in Circom proof. | Reject envelope; drop payload; log security alert. |
| `QuotaExceeded` | `message_index >= quota_limit` in circuit. | Reject envelope; fail ZK proof verification. |
| `NonCanonicalField` | Scalar element $v \ge r$. | Reject input immediately before hashing or verification. |
| `DoubleShareDetected`| Same nullifier seen twice in same epoch window. | Extract $a_0$; compute $cm_{\text{identity}}$; broadcast Revocation Tombstone. |
| `ReplayedVoucher` | Redemption nullifier $\nu$ exists in local database. | Reject endorsement voucher; do not update local WoT score. |
| `InvalidTombstone` | Tombstone double-spend proofs fail verification. | Reject tombstone broadcast; log malicious revocation attempt. |

---

## 9. Acceptance Criteria

- [ ] Circom circuits compile under BN254 with sub-50ms prover time on WASM.
- [ ] RLN circuit enforces domain separation ($DS_{\text{nullifier}}=1$, $DS_{\text{slope}}=2$, $DS_{\text{MSG}}=3$) and private slope witness $a_1$.
- [ ] In-circuit quota check $0 \le i < Q(T)$ rejects indices exceeding tier quota.
- [ ] All inputs $v \ge r$ are rejected by canonical field encoding checks.
- [ ] Groth16 Range Proof successfully verifies $\text{score} \ge \text{threshold}$ without exposing the raw score signal.
- [ ] Double-sending reveals $a_0$, issuing tombstones that target $cm_{\text{identity}}$ backed by double-spend proof verification.
- [ ] Blind Endorsement Vouchers verify redemption nullifiers $\nu$ without exposing signer or receiver DIDs.