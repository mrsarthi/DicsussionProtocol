# RFC 003: ZekPoc Security Envelope, Dynamic ZK-RLN Anti-Spam & Reputation Range Proofs

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-08-18

---

## 1. Overview
This specification defines the cryptographic security, privacy, dynamic anti-spam, and zero-knowledge reputation layer for the ZekPoc network stack. To eliminate spam without central authorities or identity leaks, ZekPoc uses a **Tiered Zero-Knowledge Rate-Limiting Nullifier (ZK-RLN)** system based on Groth16 zk-SNARKs over the BN254 curve. Users prove they meet a reputation score threshold using **ZK Range Proofs** and redeem **Blind Endorsement Vouchers** without revealing their identity or exact score balance. Messages are end-to-end encrypted (E2EE) using X25519 and AES-256-GCM, with compromised keys revoked via gossip tombstones on Sub-Stream `0x03`.

---

## 2. Non-Goals
- **Local Graph Storage & WoT Calculation:** Database schemas, local interaction scoring algorithms, and IndexedDB/SQLite persistence (defined in `specs/04-headless-backend.md`).
- **Transport Routing:** P2P NAT traversal, QUIC streams, or Iroh DERP relay fallback (defined in `specs/01-transport.md`).
- **CRDT Sync:** Automerge document reconciliation or Merkle sync trees (defined in `specs/02-data-sync-lenses.md`).

---

## 3. Frozen Protocol Parameters & ZK Reputation Tiering

To guarantee zero-knowledge proof validity and prevent protocol fragmentation, all circuits, scalar fields, and rate-limiting constants are strictly locked for v1.0.

### 3.0 Frozen Protocol Parameters (v1.0 Blueprint)

| Parameter | Frozen Value | Engineering Rationale |
| :--- | :--- | :--- |
| **Elliptic Curve** | `BN254` | Native pairing efficiency; standard support across SnarkJS, WASM, and Circom. |
| **Hash Primitive** | `Poseidon2` | Optimized algebraic hash over BN254 prime field with enhanced cryptanalytic security margins. |
| **Merkle Tree Depth** | `Depth 16` ($N_{\text{max}} = 65,536$) | Enforces bounded path verification to 16 hashes (~160 circuit constraints). |
| **Base Epoch Duration** | `10 Seconds` | $E = \lfloor (T_{\text{local}} + \Delta_{\text{peer}}) / 10\text{s} \rfloor$; synchronized via QUIC offset handshake. |
| **Rolling Window ($W$)** | `3 Epochs` (30 Seconds) | Enforces rolling window constraint $0 \le i < Q_{\text{window}}(T, W)$. |
| **Proof Scheme** | `Groth16` | Compact ~128-byte proof payload for sub-second wire transmission over QUIC. |
| **Blind Signature Scheme**| `Chaumian RSA-FDH (RSA-2048)` | Unlinkable voucher generation and offline redemption via standard RSA blind signatures over SHA-256. |
| **Protocol Versioning** | `version: u8` (`0x01`) | Mandatory wire header byte; 60-day dual-support migration window for circuit updates. |

### 3.1 Domain Separation Constants
To prevent cross-protocol collision attacks, scalar inputs MUST use explicit Poseidon domain separation tags:
- $DS_{\text{nullifier}} = 1$: Rate-limiting nullifier derivation.
- $DS_{\text{slope}} = 2$: Private witness slope derivation ($a_1$).
- $DS_{\text{MSG}} = 3$: Transport transcript message commitment.
- $DS_{\text{voucher}} = 4$: Blind endorsement voucher redemption nullifier ($\nu$).
- $DS_{\text{issue}} = 5$: Issuer allocation nullifier ($\text{nullifier}_{\text{issue}}$).
- $DS_{\text{member}} = 6$: Membership commitment derivation.
- $DS_{\text{root}} = 7$: Versioned membership root binding (RFC 002 §4.1).
- $DS_{\text{trapdoor}} = 8$: Identity trapdoor derivation (§7.1).

### 3.2 Trust Tiers & Quota Allocation

| Tier Level | Score Range (POCs) | Dynamic Epoch Quota ($Q(T)$) | Message Interval |
| :--- | :--- | :--- | :--- |
| **Tier 0 (Untrusted)** | $0 \le \text{Score} < 50$ | 1 msg / 10s | Restricted |
| **Tier 1 (Standard)** | $50 \le \text{Score} < 100$ | 3 msgs / 10s | Baseline |
| **Tier 2 (Established)** | $100 \le \text{Score} < 200$ | 10 msgs / 10s | Fast |
| **Tier 3 (High Reputation)**| $\text{Score} \ge 200$ | 100 messages / epoch | Full Access |

The reputation tier proof MUST be bound to a fresh state root and a recent epoch. Verification MUST reject proofs older than 2 epochs (20 seconds) unless the proof explicitly includes the current state root hash and epoch.

### 3.3 Canonical Field Encodings
All scalar field elements $v$ submitted to circuits or transmitted across the wire MUST strictly conform to canonical BN254 scalar field bounds:
$$0 \le v < r$$
Where $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617 \approx 2^{254}$. Non-canonical encodings ($v \ge r$) MUST be rejected immediately prior to host processing or verification.

### 3.4 Unified Groth16 Single-Proof Envelope Circuit
Rather than producing two separate proofs, ZekPoc unifies the reputation range check and RLN rate-limiting check into a **single merged Groth16 circuit** (`rln_range_unified.circom`), halving prover time and proof payload size.

---

## 4. Dynamic ZK-RLN Anti-Spam Engine

ZekPoc enforces rate limits using Poseidon hashing over the BN254 scalar field. Epochs are 10-second intervals ($\text{epoch} = \lfloor\text{unix\_timestamp} / 10\rfloor$).

### 4.1 Slashing Polynomial, Domain Separation & Transcript Binding
The RLN circuit evaluates a 2-of-2 Shamir Secret Sharing polynomial:
$$y = a_0 + a_1 \cdot x \pmod r$$

Where:
- $a_0$ is the user's private identity secret (`identity_secret`).
- $a_1$ is an internal private witness derived via Poseidon domain separation ($DS_{\text{slope}} = 2$):
  $$a_1 = \text{Poseidon}(DS_{\text{slope}}, a_0, \text{epoch}, \text{message\_index})$$
- $\eta$ is the public rate-limiting nullifier derived via Poseidon domain separation ($DS_{\text{nullifiers}} = 1$):
  $$\eta = \text{Poseidon}(DS_{\text{nullifiers}}, a_0, \text{epoch}, \text{message\_index})$$
- $x$ is the public message commitment fully binding transport context via domain separation ($DS_{\text{MSG}} = 3$):
  $$x = \text{Poseidon}(DS_{\text{MSG}}, H(\text{version} \parallel \text{stream\_id} \parallel \text{epoch} \parallel \text{tier} \parallel \text{ciphertext\_hash} \parallel \text{recipient\_id}) \pmod r)$$

To prevent cross-epoch quota evasion, the circuit MUST enforce a rolling window constraint over multiple epochs. The effective quota is computed as:
$$i < Q_window(T, W)$$
where $W = 3$ epochs (30 seconds).

---

## 5. Metadata-Private Blind Endorsement Vouchers (+5 Gift)

To support metadata-private "+5 POC" gifts between peers, ZekPoc uses **Chaumian Blind Signatures** paired with an **Eligible-Issuer Merkle Tree** to prevent social graph leaks.

1. **Blinding:** Receiver B generates a random serial token $s$ and scope parameter, computes blinded commitment $B = \text{Blind}(s)$, and transmits $B$ to Peer A.
2. **Signing & Issuance Burn:** Peer A signs $B$ using their private signing key and returns signature $S_A(B)$. Peer A incurs a direct issuance cost of 2 POC ($S(A) \leftarrow S(A) - 2$), recording an anonymized allocation record $(cm_A, \text{nullifier}_{\text{issue}}, \text{commitment}_{\text{voucher}})$ in the state store. No recipient DID or recipient commitment tuple is recorded, keeping the social graph edge completely private.
3. **Issuer Nullifier:** To enforce issuer quotas without tracking recipients, issuance uses an explicit domain-separated issuer nullifier:
   $$\text{nullifier}_{\text{issue}} = \text{Poseidon}(DS_{\text{issue}}, a_0^A, \text{epoch}, k)$$
4. **Unblinding:** Receiver B unblinds the signature to obtain $S_A(s)$, a valid voucher signed by Peer A.
5. **Redemption Nullifier & ZK Verification:** Receiver B redeems the voucher by presenting a single Groth16 proof verifying:
   - *"I hold a valid signature $S_A(s)$ issued by a public key contained in the Eligible-Issuer Accumulator Merkle Tree."*
   - *"Redemption nullifier $\nu = \text{Poseidon}(DS_{\text{voucher}}, \text{serial}, \text{scope}, cm_{\text{redeemer}})$ has not been redeemed previously."*
   - *"The proof is bound to my redeemer identity commitment $cm_{\text{redeemer}}$."*
   - **Privacy Result:** The endorsement graph $A \to B$ remains completely hidden during both issuance and redemption.

---

## 6. Encrypted Wire Envelope Structure

All payloads sent over Sub-Stream `0x02` MUST be wrapped in a binary security envelope containing the single unified Groth16 proof, ephemeral public key, and AES-256-GCM ciphertext.

### 6.1 Wire Format

The `version` field is mandatory and MUST appear as the first field in the envelope struct, at offset 0.

    pub struct SecurityEnvelope {
        pub version: u8,                    // 1 byte: Protocol version (0x01)
        pub epoch: u64,                     // 8 bytes: Epoch ID (10s window)
        pub tier_threshold: u16,            // 2 bytes: Proven Tier (0, 50, 100, 200)
        pub rln_nullifier: [u8; 32],        // 32 bytes: Poseidon nullifier
        pub zk_proof: Vec<u8>,              // ~128 bytes: Unified Single Groth16 Proof (Range + RLN)
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

## 9. Phase-2 Trusted Setup Ceremony & Circuit Versioning

1. **Phase-1 Reuse:** Circuit compilation reuses standard perpetual Powers of Tau Phase-1 ceremony parameters (e.g., Hermez 28-pot transcript for BN254).
2. **Phase-2 Ceremony:** Circuit-specific Phase-2 ceremonies MUST include contributions from at least **5 independent parties** with publicly verifiable contribution beacon hashes and published SnarkJS response files.
3. **Artifact Verification:** Published `.zkey` artifacts MUST be cryptographically verified using `snarkjs zkey verify` against the public circuit R1CS constraints prior to bundling into SDK releases.
4. **Dual-Support Upgrade Window:** Circuit updates trigger a 60-day dual-support deprecation window during which clients accept proofs generated under both `version: u8 = 0x01` and `0x02`.

---

## 10. Acceptance Criteria

- [x] Circom circuits compile under BN254. **Measured WASM prover time is
      ~1.1s on desktop at 5,307 constraints**, not the sub-50ms this
      document originally asserted — that figure was an estimate and was
      wrong by more than an order of magnitude. Sub-100ms is a native
      prover target (`rapidsnark`/`arkworks`), not a WASM one, and mobile
      is slower again. Implementations MUST NOT put WASM proving on an
      interactive send path without measuring on target hardware first.
- [ ] RLN circuit enforces domain separation ($DS_{\text{nullifier}}=1$, $DS_{\text{slope}}=2$, $DS_{\text{MSG}}=3$) and private slope witness $a_1$.
- [ ] In-circuit quota check $0 \le i < Q(T)$ rejects indices exceeding tier quota.
- [ ] All inputs $v \ge r$ are rejected by canonical field encoding checks.
- [ ] Groth16 Range Proof successfully verifies $\text{score} \ge \text{threshold}$ without exposing the raw score signal.
- [ ] Double-sending reveals $a_0$, issuing tombstones that target $cm_{\text{identity}}$ backed by double-spend proof verification.
- [ ] Blind Endorsement Vouchers verify redemption nullifiers $\nu$ without exposing signer or receiver DIDs.