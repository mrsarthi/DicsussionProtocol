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

## Next Immediate Step
**Phase 2A — Web-of-Trust & Anti-Spam Pipeline**
1. Bounded Sparse Merkle Tree (D=16) with lexicographic byte sorting and LRU
   eviction at N_max = 65,536 — replaces the Phase 1A SHA-256 state root.
2. Local WoT score calculator wired to real peer interaction counters.
3. Identifiable Blind Voucher issuance handshakes over Stream `0x04`.
4. Channel Creator Genesis Anchor bootstrapping.

### Deferred (non-blocking)
- [ ] Iroh Native/FFI Binding — swap `LocalTransport` for real QUIC (see tracked subtask above)
- [ ] OS-keychain encryption for identity secret keys (RFC 004 §4.1)
- [ ] `exportMnemonic` / `recoverFromMnemonic` / `revokeKey` implementation