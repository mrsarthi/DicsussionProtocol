# PROGRESS.md — Dicsussion Protocol Development Log

---

## Task 0: Project Scaffolding & Environment Setup
**Status:** ✅ COMPLETE
**Date:** 2026-08-01

### Completed
- [x] Read `AGENT_INSTRUCTIONS.md` — understood full architecture, 3-phase roadmap, modularity rules
- [x] Created `package.json` with devDependencies: `typescript`, `tsx`, `@types/node`, `@playwright/test`
- [x] Created `tsconfig.json` — ES2022 target, NodeNext module resolution, strict mode + extra strictness flags
- [x] Created modular `src/` directory structure:
  - `src/transport/index.ts` — Iroh QUIC, mDNS, DERP relay (RFC_001)
  - `src/crypto/index.ts` — X25519, AES-256-GCM, Ed25519 (did:key)
  - `src/storage/index.ts` — SQLite / IndexedDB drivers
  - `src/crdt/index.ts` — Automerge CRDT + Sparse Merkle Tree
  - `src/zk/index.ts` — Circom, SnarkJS, ZK-RLN engine
  - `src/wot/index.ts` — Web-of-Trust scoring, blind vouchers
  - `src/sdk/index.ts` — DicsussionClient public facade
- [x] Created `tests/smoke.spec.ts` — Playwright smoke test (3 assertions)
- [x] Created `playwright.config.ts` — headless mode, `tests/` directory, list reporter
- [x] Updated `.gitignore` — added `node_modules/`, `dist/`, `test-results/`, `playwright-report/`, `*.tsbuildinfo`
- [x] Ran `npm install` — 9 packages added, 0 vulnerabilities
- [x] Ran `npx playwright test` — **3 passed (1.0s)**

---

## Task 0.1: Monorepo Layout Refactor (RFC-Boundary Separation)
**Status:** ✅ COMPLETE
**Date:** 2026-08-01

### Changes
- [x] Moved core protocol modules from `src/` → `packages/core/src/` (initial pass)
- [x] Moved SDK module from `src/` → `packages/HLessEnd/src/` (initial pass)
- [x] Moved `PROGRESS.md` from `.agents/` → project root for auto-detection
- [x] Removed empty `src/` directory
- [x] Updated `tsconfig.json` — `rootDir` set to `.`, `include` covers both packages
- [x] **RFC-boundary cleanup:** Moved `wot/` and `storage/` from `packages/core/src/` → `packages/HLessEnd/src/`

### File Registry — Final Package Separation
```
packages/core/src/             # Low-level protocol engine (RFC 001–003)
├── transport/index.ts         # Iroh QUIC, mDNS, DERP relay       (RFC 001)
├── crypto/index.ts            # X25519, AES-256-GCM, Ed25519      (RFC 001)
├── crdt/index.ts              # Automerge CRDT, Sparse Merkle Tree (RFC 002)
└── zk/index.ts                # Circom, SnarkJS, ZK-RLN engine    (RFC 003)

packages/HLessEnd/src/         # Headless backend & SDK (RFC 004)
├── index.ts                   # @dicsussion/sdk — DicsussionClient facade
├── wot/index.ts               # Web-of-Trust scoring, blind vouchers
└── storage/index.ts           # SQLite / IndexedDB drivers

tests/                         # Playwright test suites
specs/                         # RFC specifications (001–004)
PROGRESS.md                    # This file (project root)
```

---

## Task 1A: Core P2P Mesh & E2EE Messaging — Functional Implementation
**Status:** ✅ COMPLETE
**Date:** 2026-08-03
**Verification:** `tsc --noEmit` clean · **104 Playwright tests passing** (stable across repeated runs)

### Audit of prior 1A work
An audit of the pre-existing implementation found these items already correct
and covered by tests: `did:key` derivation, the 12-byte frame codec (CRC32-C,
zero-copy `subarray` views, 1 MB LZ4 ceiling, unknown-stream rejection), the
handshake (clock skew ≤ 10s, nonce replay/expiry, epoch math), crypto
primitives (Ed25519 / X25519 / AES-256-GCM), `SecurityEnvelope` serialization,
the multi-document CRDT manager, schema lenses, and the SQLite driver with
migrations. These were left in place.

The audit also found seven gaps, all now closed:

| # | Gap | Resolution |
|---|-----|------------|
| 1 | mDNS discovery entirely absent (constants only) | `mdns-record.ts`, `mdns-discovery.ts`, `datagram-socket.ts` |
| 2 | DERP relay failover entirely absent (error enums only) | `relay-failover.ts` |
| 3 | `0x03` priority preemption never enforced | `priority-queue.ts`, wired into `LocalTransport` send path |
| 4 | CRDT never connected to Stream `0x01` | `sync-protocol.ts`, `state-root.ts`, `sync-engine.ts` |
| 5 | No CRDT persistence | migration v2 + `document-store.ts` |
| 6 | SDK facade hollow (`sendMessage` threw, bootstrap empty) | `client.ts`, `session-manager.ts`, `chat-service.ts`, `identity-service.ts` |
| 7 | Outbox in-memory only, no reconnect flush | `outbox.ts` persistence + `flush()` |

### Bugs found and fixed during implementation
- **Relay failover skipped on refusal.** A *rejected* direct hole-punch escaped
  as a raw error instead of falling through to the relay chain; only a *timeout*
  triggered failover. Both paths now converge on the same fallback ladder.
- **Crash writing to a sync-created document.** `ensureSyncDocument` builds an
  empty `Automerge.init()` replica, so `addMessage` dereferenced an undefined
  `messages` map. `addMessage` now seeds the RFC 002 §3.1 skeleton first.
- **Nondeterministic message order.** `timestamp` has one-second resolution, so
  messages sent in the same second were ordered by random UUID and differed
  between replicas. Added the spec's `message_index` (RFC 002 §4.3) as the
  tiebreak, giving every replica an identical total order.

### Deliverables
```
packages/core/src/transport/
├── datagram-socket.ts      # UDP multicast + in-process bus for tests
├── mdns-record.ts          # TXT beacon codec (_p2p-sync._udp.local)
├── mdns-discovery.ts       # 5s beacons, peer table, TTL eviction   (RFC 001 §4.1)
├── relay-failover.ts       # 3s hole-punch bound, relay chain, backoff (§4.2)
└── priority-queue.ts       # 0x03 preempts 0x02                     (§6)

packages/core/src/crdt/
├── sync-protocol.ts        # Stream 0x01 message codec              (RFC 002 §4.2)
├── state-root.ts           # canonical state root                   (§4.3)
└── sync-engine.ts          # Automerge sync driver

packages/HLessEnd/src/
├── client.ts               # bootstrap + public facade
├── session-manager.ts      # connections, frame routing, fan-out
├── peer-registry.ts        # did → X25519 key + connection
├── message-codec.ts        # payload ↔ SecurityEnvelope
├── outbox.ts               # persisted queue + reconnect flush      (RFC 004 §7.4)
└── storage/
    ├── document-store.ts   # Automerge snapshots                    (RFC 002 §4.4)
    └── message-store.ts    # message_stream projection              (RFC 004 §4.1)
```

### Deliberate scope boundaries
- **Transport backend.** `LocalTransport` implements `ITransport` in-process.
  The Iroh QUIC/NAPI backend implements the same interface and is the one
  remaining substitution; all protocol logic above it is backend-agnostic.
- **State root.** RFC 002 §4.1's bounded sparse Merkle tree (D=16, Poseidon) is
  Phase 2A. Phase 1A uses a SHA-256 root over the same canonical fields, giving
  the identical "equal roots ⇒ transfer nothing" short circuit.
- **ZK fields.** Envelopes reserve `zkProof` / `rlnNullifier` but carry empty
  values until Phase 3, so the wire format will not change when proofs land.
- **Identity secrets are stored unencrypted.** RFC 004 §4.1 requires OS-keychain
  wrapping; this MUST be addressed before any production use.
- `exportMnemonic` / `recoverFromMnemonic` / `revokeKey` throw explicit
  not-implemented errors rather than returning values that would not work.

### Tracked subtask: Implement Iroh Native/FFI Binding
- [ ] Build `IrohTransport` class implementing the existing `ITransport` interface
- [ ] Compile `iroh-net` Rust crate to native NAPI addon or WASM module
- [ ] Wire real QUIC streams, mDNS, STUN hole-punching, and DERP relay
- [ ] Replace `LocalTransport` usage in `DicsussionClient` with runtime detection
- **Note:** Not a blocker for Phase 2 or 3. All protocol logic (handshake, frame
  codec, CRDT sync, E2EE, outbox) is transport-agnostic by design — swapping
  the backend is a drop-in substitution against `ITransport`.

---

## Task 1B: Playwright Test Validation
**Status:** ✅ COMPLETE
**Date:** 2026-08-03

- [x] **Test Suite 1.1 (`tests/e2e/suite-1.1-peer-discovery.spec.ts`)** — 10 tests.
  Two headless peers discover each other over mDNS; stale peers evicted on TTL;
  foreign/malformed datagrams ignored; mutually authenticated handshake with
  clock sync; all six sub-streams multiplex over one connection; `0x03` preempts
  `0x02`; direct path preferred; failover to backup DERP relay; both exhaustion
  error paths.
- [x] **Test Suite 1.2 (`tests/e2e/suite-1.2-e2ee-exchange.spec.ts`)** — 9 tests.
  Node A → Node B encrypted delivery and decryption; wire ciphertext leaks
  neither plaintext, channel id, nor sender did; wrong key fails AES-GCM auth;
  offline sends queue in the outbox; **outbox flushes in order on simulated
  reconnection**; epoch refreshed on flush; CRDT state converges on both peers;
  bidirectional exchange; messages survive a SQLite checkpoint.

**Supporting unit suites added:** `tests/crdt/sync-engine.spec.ts` (14),
`tests/transport/priority-queue.spec.ts` (7), `tests/storage/document-store.spec.ts` (6).

---

## Task 2: Web-of-Trust & Anti-Spam Pipeline
**Status:** ✅ COMPLETE
**Date:** 2026-08-06

- [x] **Bounded Sparse Merkle Tree** (D=16, capacity 4,096) with lexicographic
  byte sorting — replaces the Phase 1A SHA-256 state root. Versioned root
  `H(version ‖ params ‖ tree)` so a parameter change cannot silently produce a
  colliding root.
- [x] **Local WoT score calculator** wired to real peer interaction counters.
- [x] **Chaumian RSA-FDH blind vouchers** (RSA-2048) over Stream `0x04` —
  full-domain hashing, so a receiver cannot exploit RSA's multiplicative
  homomorphism to forge a second signature from one issuance.
- [x] **Channel Creator Genesis Anchor** bootstrapping, with the proof policy
  inside the signature — otherwise a relaying peer could downgrade a channel
  to unproven in transit.
- [x] **Two-phase membership set** — joins minus departure tombstones, so a
  departure cannot be replayed into a different channel.

---

## Task 3: Zero-Knowledge RLN & Slashing
**Status:** ✅ COMPLETE
**Date:** 2026-08-06

- [x] **Unified Groth16 circuit** (`rln_range_unified.circom`) over BN254 —
  combines ZK range proof (reputation ≥ threshold) with RLN rate limiting in
  a single proof.
- [x] **2-of-2 Shamir polynomial** `y = a₀ + a₁·x`; a double-send in one epoch
  lets any peer reconstruct `a₀` by Lagrange interpolation.
- [x] **Poseidon domain separation** — 8 distinct tags, `assertCanonicalField`
  before every input to prevent wraparound forgeries.
- [x] **Trapdoor derivation fix.** `cm_identity` originally mixed `a₀` with
  *independent* randomness, which meant slashing could only ever fire against
  yourself. Now `trapdoor = Poseidon(DS_trapdoor, a₀)` — derived, not
  independent. The original code carried a comment rationalising the flaw
  circularly.
- [x] **Revocation tombstones** over Stream `0x03`, verified by re-deriving
  shares against the commitment rather than trusting the signature alone.

---

## Task 4: Browser Support & SDK Packaging
**Status:** ✅ COMPLETE
**Date:** 2026-08-07

- [x] **WebSocket relay transport** — Iroh has no WASM target and a browser
  cannot open a QUIC socket, so browser peers relay frames by `did:key`.
- [x] **IndexedDB storage driver** with a write queue, at parity with SQLite.
- [x] `@dicsussion/sdk/browser` entry point excluding the native SQLite driver,
  verified by an `esbuild --platform=browser` build in CI.
- [x] npm workspaces, `exports` maps, `browser` field mapping, TypeScript
  project references.

---

## Task 5: Trusted Setup Ceremony
**Status:** ✅ COMPLETE
**Date:** 2026-08-11

Six independent contributors, closed with a public beacon.

| # | Contributor | Date |
|---|---|---|
| 1 | Parth Sarthi Mishra | 2026-08-08 |
| 2 | Ramandeep Yadav | 2026-08-08 |
| 3 | Prakhar Srivastav | 2026-08-08 |
| 4 | Parth Mehrotra | 2026-08-08 |
| 5 | Shubham Vishwakarma | 2026-08-10 |
| 6 | Snehal Kumar | 2026-08-10 |
| 7 | Beacon — Bitcoin block 962000 | 2026-08-11 |

- [x] Beacon committed **2026-08-08 15:15:45 UTC**, block mined **2026-08-11
  11:07:57 UTC** — a lead time of 2 days 19 hours 52 minutes. The advance
  commitment is the entire security property; a beacon announced afterwards
  proves nothing.
- [x] Block hash verified against two independent explorers before applying.
- [x] `DEVELOPMENT_ONLY.md` deleted — the SDK is live on real ceremony
  artifacts. `rln_final.zkey` SHA-256 `b1d518ab…bec20f`.
- [x] Public record: https://github.com/mrsarthi/Ceremonial-Contributions

**Forging a proof now requires all six contributors to have colluded, all six
to have kept entropy they publicly attested to destroying, and control of a
Bitcoin block hash that did not exist when the commitment was published.**

---

## Task 6: Security Hardening
**Status:** ✅ COMPLETE (two findings deferred by design)
**Date:** 2026-08-11

Two independent audits. Full record — including disputed severities and the
items still open — in `docs/SECURITY_BACKLOG.md` (gitignored: it lists live
weaknesses with file and line).

- [x] **Pairing gate on inbound frames.** A completed handshake is not
  authorization — `HandshakeInit.didKey` is self-asserted. Previously any
  stranger holding a public ticket could inject messages into another user's
  chat history and drive CRDT reconciliation. Reproduced with the gate
  disabled before fixing.
- [x] **Storage fails closed.** Omitting `storageKey` on a real file now
  throws instead of warning. A `console.warn` is not a control.
- [x] **`Buffer` removed from browser-reachable code** — it appeared in
  `ticket-codec`, `secret-box`, and `gossip-protocol`, so browser pairing had
  never actually worked. The `esbuild` CI check could not catch it: `Buffer`
  is a global, not a builtin import.
- [x] **Argon2id for passphrases** (OWASP `t=2, m=19 MiB`), replacing HKDF.
  The `t=3, m=64 MiB` baseline measured 2638 ms with `@noble/hashes` — too
  slow to run at client open.
- [x] **Aggregate resource caps** — pending membership chunks and peer-named
  documents.
- [x] **Input bounds** — proof size, message content, identifiers, epoch
  safe-integer range.
- [x] **Per-transport nonce registry**, replacing module-level shared state.
- [x] Session keys wiped on close; ephemeral secrets wiped on all paths
  including handshake timeout.

### Known gaps, documented rather than hidden
- [ ] **WebSocket relay does not encrypt CRDT traffic** (browser only). Chat
  bodies are sealed; CRDT sync, membership, vouchers, and RLN signals cross
  the relay in the clear. Iroh/QUIC is unaffected. Stated in `README.md` and
  in the transport's own module docblock.
- [ ] **CRDT changes lack application-level authenticity.** The pairing gate
  means only paired peers can submit changes, but a peer you later distrust
  can still write arbitrary state. Fixing this is a wire-format change and an
  RFC amendment — design note first.
- [ ] **Message content at rest is unencrypted.** Identity secrets are
  protected; chat bodies and Automerge snapshots are not.

---

## Task 7: Licensing & Publication Readiness
**Status:** ✅ COMPLETE
**Date:** 2026-08-11

- [x] **Apache 2.0** across `LICENSE`, `NOTICE`, and both `package.json`
  files, resolving a contradiction where the README said Apache and the
  manifests said MIT.
- [x] `NOTICE` records the GPL-3.0 carve-outs honestly: `snarkjs` is an
  optional dependency loaded by dynamic `import()` and never redistributed;
  compiled circuit artifacts embed `circomlib` templates and ship under
  GPL-3.0, separately from the SDK source.
- [x] Both packages verified to carry `LICENSE` and `NOTICE` inside their
  tarballs, as Apache §4(a) and §4(d) require.
- [x] npm scope `@dicsussion` claimed; `publishConfig.access: public` set.

---

## Current State (2026-08-11)

| | |
|---|---|
| Tests | **488 passing, 0 failing** |
| Typecheck | clean |
| Build | clean |
| `npm audit` | 0 vulnerabilities |
| Proving key | real ceremony output, 6 contributors + beacon |
| License | Apache 2.0 |
| Published | **not yet** — pending commit |

**Test suites:** 10 e2e, 13 transport, 7 CRDT, 5 storage, 3 ZK, 2 WoT.

---

## Next Immediate Step

1. Commit the outstanding work in logical chunks (~40 files: licensing,
   ceremony artifacts, and roughly a dozen security fixes).
2. Publish `@dicsussion/core`, then `@dicsussion/sdk` — core first, the SDK
   depends on it.
3. Tag a GitHub release naming the three known gaps above.
4. Push `ATTESTATION.md`, `Contribution_7.txt`, and the README update to the
   Ceremonial-Contributions repo.

### Deferred (non-blocking)
- [ ] Relay transport encryption (~1 day) — closes the browser confidentiality gap
- [ ] CRDT operation authenticity — design note, then RFC amendment
- [ ] Message content encryption at rest — needs a granularity decision and
      WAL handling; measure before choosing
- [ ] OS-keychain integration for identity secrets (RFC 004 §4.1) — explicitly
      deferred to v1.1; SQLite with encryption at rest is sufficient for v1
- [ ] Native prover (rapidsnark) — WASM proving is ~1s per anonymous message
- [ ] Relay server implementation — the SDK speaks the protocol; no reference
      server ships yet
- [ ] Per-message ratchet — forward secrecy is currently per-session
- [ ] Tier gating — `userScore` is a self-asserted private input, held in check
      by application code on both sides. **Do not enable tiers without binding
      it in the circuit**, or quotas become forgeable 100×.
- [ ] `exportMnemonic` / `recoverFromMnemonic` / `revokeKey` implementation