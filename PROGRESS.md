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
  clock sync; every sub-stream multiplexes over one connection; `0x03` preempts
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

## Task: 0.3.0 — Bridged transport and the pairing seam
**Status:** ✅ COMPLETE — published, tagged, released
**Date:** 2026-08-16

Requested by the EchoIt app agent, which is blocked at its S1b gate: the
Rust half of its Tauri bridge is done, but no `ITransport` could be built
from the public API without reimplementing session-key derivation and
transcript binding outside the SDK.

### `createBridgedTransport` (RFC 001 §4)
- [x] `bridge-pipe.ts` — the host contract. **Ordered bytes, nothing
  more:** a host may split one `send` across several `onData` calls or
  coalesce many into one, and both are correct.
- [x] `pipe-reader.ts` — length-prefixed control messages during the
  handshake, frames afterwards. The prefix format is lifted verbatim from
  `iroh-transport.ts` (4-byte big-endian, 64 KB ceiling), because the
  Iroh control stream is a byte stream with the identical problem.
- [x] `bridged-transport.ts` — the transport. The handshake is
  `WebSocketTransport`'s, generalised over the byte sink.

**Why the SDK frames rather than the host.** The alternative was to
require hosts to preserve message boundaries. Rejected: it pushes
security-critical sequencing back out to every consumer, duplicates the
same framing in Tauri, React Native and Electron, and fails only
mid-handshake under coalescing — so it works on loopback and breaks on a
real network under load.

**Accepted cost, documented in the module header.** One pipe carries
every sub-stream, so RFC 001 §6 preemption weakens from QUIC stream
priority to send-queue ordering. Bounded by the frame ceiling, not a
stall. `IrohTransport` keeps the stronger guarantee.

### Pairing from tickets
`connect(ticket)` registers the peer's X25519 key on the **dialer's** side
only, so the accepter could not decrypt and dropped frames silently. Every
suite hid this by pairing through `addPeer` with raw keys out of band —
something no application can do.

- [x] `suite-4.3-ticket-pairing.spec.ts` — cross-process, real QUIC,
  paired from tickets alone. Includes the non-delivery assertion and the
  case that matters for an app: pairing *after* a stranger connects
  repairs delivery on the open connection, no redial.
- [x] `scripts/peer-cli.mts` — added `/pair`, and the ticket is now
  printed only after the endpoint has discovered a public address and
  registered with a relay. It previously printed at startup, so the
  ticket carried LAN addresses only and was undialable from any other
  network. **The CLI had never delivered a message; it now does, both
  directions, path direct.**

### Smaller items
- [x] `onPeerConnected` on `DicsussionClient` — `{ peerDid, paired,
  direction }`. A completed handshake is not authorization, so `paired`
  is the field that matters.
- [x] `@types/better-sqlite3` promoted to a runtime dependency; the
  shipped `.d.ts` files import it, so every TypeScript consumer of the
  root entry failed to typecheck without it.
- [x] Both packages bumped, including the SDK's exact pin on
  `@dicsussion/core`.

### snarkjs is now an optional peer dependency
Caught by the tarball pre-flight, not by the repo. `npm audit` here
reports zero because the root `package.json` overrides `underscore` —
**and npm overrides are root-only, so they do not reach consumers.**
Installing the tarballs into a clean project produced:

```
@dicsussion/core → snarkjs 0.7.6 → bfj 7.1.0 → jsonpath → underscore ≤1.13.7
3 high severity vulnerabilities
```

No upgrade clears it: 0.7.6 is the latest snarkjs and still requires
`bfj ^7.0.2`, and every `bfj` in range is flagged.

- [x] `snarkjs` moved from `optionalDependencies` to `peerDependencies`
  with `peerDependenciesMeta.optional`. It was already reached only
  through a lazy `import()` in `zk/prover.ts`, nothing references it
  statically, and v1 runs with `zkProofs: 'off'` — so the default
  install now carries neither the prover nor the advisory.
- [x] `loadSnarkjs` reports its absence in words. It is an expected
  state now, and `ERR_MODULE_NOT_FOUND` names the module without saying
  what to do about it.

Consumers who want proving run `npm install snarkjs`. **This needs a
release note** — it is one of two behaviour changes in this release.

### Pre-flight, against the packed tarballs rather than the repo
Every published artifact so far has had a bug invisible from inside the
repo (Findings 1, 8, 10), so this was verified from a clean project
installing `.tgz` files:

| Check | Result |
|---|---|
| Consumer typecheck, `skipLibCheck: false` | pass — Finding 12 closed, new exports reachable |
| Bridged transport, one byte per `onData` | pass — handshake, key agreement, delivery |
| EchoIt's own `two-peer.mts` | **3/3** over real QUIC, path direct |
| `npm audit` as a consumer | **0 vulnerabilities** |

### Then 0.2.0 shipped the bridge unusable, and 0.3.0 fixed it
Published as 0.2.0, and `createBridgedTransport` could not be reached
from an application at all. Two independent gaps, either fatal alone,
both found only while writing the documentation — because writing a
usage example is the first thing that forces the consumer's path.

1. **No way to obtain the identity.** The transport needs the node's
   Ed25519 keypair, derived inside `init()` from a seed the caller never
   holds. `transport: <ITransport>` was therefore usable only by a
   transport that does not authenticate as the node, and there is none.
   Fixed with `TransportFactory` — the client calls it during bootstrap
   with the derived identity.
2. **No way to publish a dialable ticket.** `getTicket()` special-cased
   `IrohTransport` with `instanceof`; every other transport got a
   synthesised ticket with no transport key and no addresses, so two
   bridged peers could never dial each other. Now a capability check,
   plus `BridgePipe.addresses()` — the SDK derives the key, only the host
   knows the addresses behind it.

**Why they were missed.** The transport had 25 tests across three
chunking modes, all constructing it directly with a generated keypair.
The unit was covered; the joint was not. The pre-flight did not catch it
either — it proved *packaging* (audit, typecheck, an external harness),
and that harness runs `transport: 'iroh'`, so it never touched the new
feature. Verifying the artifact ships correctly is not verifying the
feature works, and the two were reported as one.

Also worth recording: the app agent specified `createBridgedTransport(pipe)`
— **one argument** — in two separate documents. Implementing it with a
second `{ identity }` parameter is what created the circular dependency.
The stated reason for wanting the function was to keep security-critical
sequencing inside the SDK, and requiring the caller to supply an identity
key is the opposite of that.

Closed by a test that runs two real clients through a bridge, which is
the shape nothing exercised before.

### Released
- **0.3.0 on npm**, both packages. A minor rather than a patch because
  `BridgePipe` gained a required method; no implementation could exist,
  but a published interface changed and the version should say so.
- Tags `v0.2.0` and `v0.3.0` pushed. 0.2.0 was tagged retroactively so
  the published version is traceable to source, with no release page —
  advertising a version whose headline feature does not work is not
  useful, and the annotated tag says as much.
- GitHub releases cut for `v0.3.0` and, finally, `v0.1.0` — its notes had
  sat unused since launch, and there had been no releases at all.
- Both packages carry a README for the first time; their npm pages were
  blank through four published versions.

### Known gaps
`tsconfig.json` excludes `tests/`, so specs are never typechecked. A
plain type error in the new suite surfaced only as a 30-second timeout.
Not fixed here — it wants its own change.

A pre-flight can silently pass against a stale artifact: npm reuses an
extracted copy when the tarball filename and version are unchanged, so
re-packing into the same directory verifies the *previous* build. Caught
only because a value that should have changed did not. Pre-flights must
run in a directory that has never seen an earlier tarball.

---

## Task: 0.3.1 — connection liveness and the unreachable outbox
**Status:** ✅ COMPLETE
**Date:** 2026-08-17

Reported by the EchoIt agent from observed message loss: messages
disappeared while the sender showed them as sent. Confirmed, and the
cause was worse than reported.

### The chain
`PeerRegistry` read liveness as `connection !== undefined`. A transport
tearing a connection down sets `ConnectionState.Disconnected` and wipes
the session key, but the object stays referenced — so the peer counted as
reachable forever. **`ConnectionState` appeared nowhere in the SDK, and
`detachConnection()` had existed since Task 1A without a single caller.**

`getNetworkStatus().connected` and the outbox gate both read that count,
so `sendMessage` published into a dead connection and let the error
escape. `chat-service.ts` persists *before* the online branch, so the
message was already in local history and the channel document — that is
where the appearance of a successful send came from — and in no retry
queue.

And it was permanent. Nothing detached, so the count never fell, so every
later send repeated it. The outbox became unreachable for the life of the
client.

### One correction to the report
`publish()` does not resolve successfully — every `send()` throws on a
non-Active connection, so `sendMessage` *rejected*. Chasing that
discrepancy is what found the persist-before-branch ordering, i.e. the
actual source of the false success. Worth remembering that a diagnosis
can be right about cause and wrong about mechanism, and the wrong part is
where the remaining information is.

### Fixes
- [x] Liveness reads `ConnectionState.Active`; added `pruneDisconnected()`.
- [x] **Sends are attempted, then queued on failure**, not gated on a
      prediction. The decisive fix: there is always a window where the
      transport still believes it is connected — QUIC needs a timeout, a
      bridged host may never report at all — and no state check can catch
      it. Replay is safe because the outbox preserves the message id and
      channel documents key by id.
- [x] Reconnection drains the outbox, in both directions. Only
      `goOnline()` flushed before, so a returning peer left messages
      queued indefinitely. Queueing is half a recovery.
- [x] `onInbound` discards state held against a recycled connection id.
      Found by the reconnect test: a reused id kept a reader already in
      frame mode, so the new handshake reached the frame parser and never
      arrived — presenting as a handshake timeout on a healthy-looking
      connection. `BridgePipe` now states the rule rather than assuming
      it, which is the second time an unstated assumption in that
      contract has cost a debugging session.

### Lesson
Both this and the 0.2.0 bridge failure were invisible to a suite that
tested units in isolation. The transport had 25 tests and none went
through a `DicsussionClient`; the registry had liveness accessors and
nothing asserted what happened after a connection died. Neither bug
needed a clever test — only one that used the thing the way a consumer
does.

---

## Task: RFC reconciliation — specs vs shipped code
**Status:** ✅ COMPLETE
**Date:** 2026-08-18

The RFCs were last touched 2026-07-28/30, before three releases. Audited
all four against source; two had diverged materially, one had a wrong
number, one was sound.

### RFC 001 — Transport & Discovery
- [x] **`PeerTicket` was missing two shipped fields**, both load-bearing.
      `transport_key` is the Iroh `EndpointId`, derived by HKDF from the
      secret half and therefore not recomputable by anyone else — a
      ticket without it names an undialable peer. `encryption_key` is
      what makes a ticket a pairing artifact rather than an address.
- [x] Documented that pairing is **mutual**, that dialling registers the
      key on the dialling side only, and that a completed handshake is
      not pairing. This is the trap that cost this project two separate
      debugging sessions and was specified nowhere.
- [x] Added §4.3 Transport Backends. The overview asserted all traffic
      MUST cross peer-to-peer QUIC, which three shipped transports
      contradict. Direct QUIC is now stated as the reference transport,
      with the bridged and relayed backends and what each gives up.
- [x] Wrote down the `BridgePipe` contract as normative: ordered bytes
      with no boundary guarantee, host-reported addresses, connection-id
      recycling, and host-owned confidentiality. Two of those four were
      unstated assumptions that each cost a debugging session.
- [x] Stated that a relayed transport is **not** zero-knowledge —
      everything but chat bodies crosses it readable.

### RFC 003 — Security Envelope
- [x] "sub-50ms prover time on WASM" was wrong by more than an order of
      magnitude; measured is ~1.1s desktop at 5,307 constraints. Sub-100ms
      is a *native* prover target. Corrected, with a warning against
      putting WASM proving on an interactive path unmeasured.

### RFC 004 — Headless Backend
- [x] **Removed Electron.** The document specified Electron IPC process
      isolation throughout — overview, topology diagram, bootstrap
      comment, acceptance criteria — and it was never implemented. The
      engine is host-agnostic; the diagram now shows the storage and
      transport seams that make it so.
- [x] §7.1 rewritten: `ClientConfig` gained `storageKey`, `zkProofs` and
      `proofArtifacts`; `init` takes the runtime options it has always
      taken; `ClientRuntimeOptions`, `TransportFactory` and
      `onPeerConnected` documented for the first time.
- [x] §7.3 no longer files identity recovery under "Missing Service
      APIs" — it is implemented and tested, and the RSA re-pair caveat is
      recorded.
- [x] §7.4 `OutboxEntry` corrected (`proof` was never a field;
      `proofEpoch` and `retryCount` are), and **send semantics made
      normative**: attempt then queue, never predict reachability;
      `sendMessage` must not reject because a peer has gone; replay must
      be idempotent by message id; liveness from connection *state*, not
      the presence of an object; drain on reconnect in both directions.
      That clause is the 0.3.1 bug written down so it cannot recur.
- [x] §4.1 now requires `storageKey` whenever the store is a real file.

### RFC 002 — Data Sync
Checked and accurate; the document schema still matches the
implementation. Fixed one malformed autolink that rendered literally
inside a JSON example.

### Verification
Twelve claims the updated RFCs make were checked against source rather
than from memory — ticket fields, the factory, the storage seam, the
event, config fields, outbox fields, state-based liveness, the pipe
contract. All present.

### Note
Every divergence pointed the same way: the specs described an intended
design, and the code had moved past it without the documents following.
The Electron model had been dead for weeks. Worth rechecking the specs on
each release rather than each quarter, since a spec that is wrong is
worse than one that is merely thin — it is the thing a new implementer
would trust.

---

## Task: 0.3.2 — sync-delivered messages, and asking the right question
**Status:** ✅ COMPLETE
**Date:** 2026-08-21

Reported by the EchoIt agent as message loss with a false sent
indication. The cause in that report was exactly right; the consequence
was not, and the difference decided the fix.

### The reported bug, reproduced
A stranger dialling a node flipped `connected` to true, after which a
message meant for an offline contact was published to zero peers,
resolved as success, and was never queued.

### What the report got wrong, and why it mattered
"That message is lost — it won't even retry later." It was not. On
reconnect the peer's history held every supposedly-lost message: CRDT
sync converges the channel document, exactly as local-first intends.

Chasing that discrepancy found the real defect. Messages arrive two ways
— an envelope on `0x02` through `ingestRemote`, which emits, and a merge
by document sync on `0x01`, which announced nothing. `_emitMessage` had
exactly one caller. A synced message therefore appeared in `getHistory()`
and never in `onMessage`, which for a UI appending on the event is
indistinguishable from loss. That is what their users saw.

**A diagnosis can be right about cause and wrong about consequence, and
the wrong part is where the remaining information is.** Second time this
pattern has paid out — 0.3.1 was the same shape.

### Fixes
- [x] Subscribe to `CrdtSyncEngine.onDocumentUpdate` and emit what a sync
      added. The hook existed, was tested, and had no production
      subscriber. De-duplication by message id covers both duplicate
      paths; first sight of a channel seeds a baseline so the first sync
      after a restart does not replay history as new.
- [x] `publish()` returns how many peers it reached. Returning `void`
      meant an empty fan-out resolved identically to a successful one, so
      0.3.1's queue-on-failure never fired — nothing had failed.
- [x] `isOnline()` and `getNetworkStatus().connected` read
      `listPairedConnected()`. They were reading `connectedCount`, which
      includes unpaired peers, while `publish()` sends only to paired
      ones. `peerCount` still counts everything, since an application
      needs that to surface a stranger's request.

### Why nothing caught it
Every suite here used exactly one contact, where "is anyone connected"
and "can I reach my contact" are the same question. They diverge at two
peers, or at one stranger. The new suite uses three participants — the
smallest number that separates them — and that is the shape worth
reaching for first now.

### Tooling note
Used `macco` on the design question of where the emit belongs. It found
`onDocumentUpdate` and flagged the seeding trap: without a baseline on
first observation, the first sync after a restart replays the whole
history as new. That is a bug I would have shipped.

---

## Task: 0.4.0 — group messaging, and conversations that stay private
**Status:** ✅ COMPLETE
**Date:** 2026-08-23

Three defects in how conversations are stored, shared and propagated.
Two were reported by the EchoIt agent from observed behaviour; the third
was found by testing the answer to "how do group messages work", which
turned out to be "they do not".

### 1. Contacts could read each other's conversations
Every conversation a node held was offered to any paired peer, in
readable text, backdated. Reproduced: Alice talks to Bob, later pairs
Carol, and Carol ends up holding the message to Bob. Strangers were
unaffected — the boundary that failed was between people you trust.

**Two paths, not one.** Synchronisation offered every document to any
paired peer. Separately, `publish` fanned every message out to every
paired peer whatever channel it belonged to, and that one delivered the
message before sync even ran. The report named only the first.

- [x] Conversations carry a `participants` list; both paths consult it,
      both default to refusing.
- [x] The list lives in the document, so it survives device replacement
      alongside the history it governs.

**The first fix was wrong and its own test caught it.** Defaulting to
"everyone currently paired" recreated the leak for anyone with two
contacts. The SDK cannot infer who a conversation is for — only the
application knows a chat opened from Bob's card is for Bob — so it does
not guess, and callers declare membership.

### 2. Concurrent messages were silently deleted
Each node created its own copy of a channel, so merging contested the
container rather than the contents: one `messages` map won and the
others' contents vanished. Deterministic, so every replica converged on
the same truncated document, state roots then matched, and sync reported
success forever after.

- [x] Both creation paths start from byte-identical genesis derived from
      the docId.
- [x] Genesis pins the actor *and* the clock. `Automerge.from` stamps
      `Date.now()`, so two nodes minting a millisecond apart produced
      different bytes under the same actor and sequence — an
      intermittent duplicate-seq rejection that failed one run in five.

### 3. Groups did not work
Reconciliation ran once per connection, so nothing travelled beyond
directly connected peers. Three in a star held three different
conversations, permanently.

- [x] Local changes are relayed onward, including changes that arrived
      from elsewhere. Self-limiting: an up-to-date peer yields no sync
      message.
- [x] Emission is idempotent per message id, since a message can now
      arrive directly *and* relayed.
- [x] "Present when first observed" and "delivered to the application"
      are stored separately. Conflating them suppressed the first
      message on every channel, because seeding one marked messages
      delivered before anything delivered them.

### Cost
The membership requirement broke 32 tests that assumed a message goes to
everyone you are paired with. All migrated; pairing and membership are
now distinct gates and the suites assert the gap rather than assuming it.

### Also fixed
- The dialer reused a recycled connection id without resetting — the
  mirror of a bug already fixed on the accepting side, surfacing as a
  nonsense control-message length rather than as reuse.
- A node's own messages appeared to arrive from outside on first sync.
- One cross-process assertion removed with its reasoning: `goOffline`
  suppresses the outbox, it does not sever the connection, so an
  in-flight reconciliation may legitimately carry messages before the
  flush. That assumption only held while sync was failing to converge.

### Method note
Every one of these was found by running something, not by reading. The
leak, the deletion and the star-topology split were all reproduced before
being diagnosed, and two of the three fixes were wrong on the first
attempt in ways only a test revealed. `macco` located the genesis cause
after three readings of the sync path found nothing, because the defect
was one layer earlier than the symptom.

---

## Task: 0.5.0 — removal that reaches the protocol
**Status:** ✅ COMPLETE
**Date:** 2026-08-23

Closes the last three open upstream items from the EchoIt agent, and a
gap in 0.4.0's own membership work.

### Finding 6 — a distrusted peer could not be un-done
0.4.0 gave conversations a participant list that only ever grew.
`removeParticipant` now exists, and removal applies in both directions.

**0.4.0 checked membership outbound and never inbound.** A peer removed
from a conversation could keep writing into it — the half an application
cannot fix for itself, since replicated changes are not individually
authenticated and a local block suppresses display rather than
authorship. That is the behaviour change in this release: traffic 0.4.0
accepted is now refused.

The first inbound check was wrong instructively. Applied unconditionally
it refused the first message of every *new* conversation, because a
channel absent locally has no participant list and therefore no
participants. "Not a participant" and "never heard of it" decide opposite
things.

Not retroactive, and said so in the tests, the guide and RFC 004 rather
than left implied. What a peer already holds is theirs.

### Finding 12 — already fixed
`@types/better-sqlite3` has been a declared dependency since 0.3.0 and is
in published 0.4.0. The tracking note was stale, not the code.

### SDK-4 — ticket helpers re-exported
`encodeTicket` / `decodeTicket` / `TICKET_PREFIX` / `PeerTicket` from
`@dicsussion/sdk`. `connect()` takes a `PeerTicket`, so a second package
import to build one was friction with no purpose.

### A test rewritten rather than adjusted
The state-root check asserted wall-clock time while 500-odd tests ran
beside it, measuring contention instead of the algorithm. Best-of-N
batches narrowed it; sustained load defeated it anyway. Raising the
threshold would have hidden what it exists to catch, so it compares two
document counts measured back to back — load-independent, still failing
an O(n²) root.

### Method note
A slowdown from 40s to 9m looked like a regression from this work and was
not: stashing everything and timing the released commit reproduced it.
Machine load. Worth measuring before attributing — and worth measuring
*against a known-good commit* rather than against memory.

---

## Task: 0.6.0 — channel ids are not secrets
**Status:** ✅ COMPLETE
**Date:** 2026-08-25

### The vulnerability
Flagged by the EchoIt agent as an open entitlement gap they had "never
tested whether it's exploitable". It is. Reproduced: Carol, paired with
Alice but no part of her conversation with Bob, guessed the channel id
and sent to it first. That created the channel on Alice's node and
recorded Carol as a participant — a channel created from an inbound
message records its sender. When Alice later declared the same channel
for Bob and sent, Carol received `SECRET-FOR-BOB`.

Channel ids are chosen by applications and travel in the clear. This made
them load-bearing for confidentiality: one guess from failing.

**The cause was our own rule, unevenly applied.** RFC 004 requires
membership to be declared and never inferred; the code inferred it on
every inbound message.

- [x] Inference confined to creating a conversation in response to
      someone — that case is real, and removing it would strand every new
      conversation.
- [x] `createChannel` is authoritative rather than additive. Without
      this the fix above is insufficient: a squatter recorded at creation
      survives the owner declaring the real membership.
- [x] `addParticipant` added, so the safe reading is not also the
      awkward one.
- [x] RFC 004 now requires authoritative declaration as a security
      property, with the reasoning, rather than leaving it a style choice.

**Breaking**, and the reason for a minor: `createChannel(id, [x])` then
`createChannel(id, [y])` was documented one release earlier as additive
and now removes `x`. Three of our own suites used that pattern, which is
what proves it a real break rather than a theoretical one.

### Documentation reconciled against the code
An audit cross-referencing README, PROGRESS, HOW_TO_USE, the four RFCs
and source found eleven claims the docs made that the code did not
honour. All verified before changing anything; all real. Three misled:
capacity published as 65,536 against a working cap of 4,096; eviction
documented — and *mandated* by RFC 002 — as LRU, which the code
deliberately rejects because a local observation cannot produce a
convergent root; and Tier 3 published as "Unrestricted" against a hard
cap of 100 per epoch.

Two filed as cosmetic were not. The root `package.json` carried `snarkjs`
as a hard dependency, contradicting the 0.3.0 packaging decision and
pulling its transitive advisory for anyone cloning. And
`membership-sync.ts` warned of "LRU divergence at capacity" as a known
limitation that deterministic eviction had already fixed — a comment
inviting someone to fix what was already fixed.

The README's own example omitted `createChannel` and would have delivered
nothing since 0.4.0. Now runs; verified by running it.

### Usage check
No evidence of any external consumer: zero stars, forks or issues; 58
unique cloners against **one** unique page view; no code on GitHub
importing either package. npm shows ~1000 downloads a month, but
per-version figures give it away — superseded releases are still
downloaded more than the current one, which is scraper behaviour, not
adoption. Relevant here because it means a breaking change strands
nobody, and the 0.5.0 hole has no known victims.

---

## Task: signals that should not be stored (SDK-REQUESTS #1)

The app asked for presence, typing indicators and read receipts. All
three are the same shape: true only while both people are connected, and
misleading the moment they are not.

They could already be built on `sendMessage`, and that is the trap. A
thirty-second heartbeat is a few thousand permanent CRDT entries per
conversation per day, on every participant's device, replicated and
written to disk, for signals nobody will ever read back. The app would
have discovered this after shipping.

### What landed
Stream `0x07`, `sendEphemeral` / `onEphemeral`, and `onPeerDisconnected`.
Sealed under the session key and gated by channel membership exactly like
`0x02` — "X is typing" is still a disclosure. Deliberately none of
`sendMessage`'s guarantees: not stored, not queued, not retried, not
replayed on reconnect. Returns the number of peers reached, and **zero is
normal**.

The payload is opaque bytes. Giving it a schema would mean revising the
RFC every time the app invents a signal.

`onPeerDisconnected` exists because presence built on connection alone
switches on and never off — it would show "online" for someone who closed
the app hours ago. Required a new `IConnection.onClose` across all four
transports; `LocalTransport.close()` also had to propagate to the peer,
since each side of an in-process pair holds its own connection object.

### The bug the SDK tests could not see
`sendEphemeral` threw `Sub-stream 0x7 is not open` over real QUIC while
passing 8/8 in the SDK suite. `IrohTransport` opened sub-streams from a
hand-maintained list that had not grown; `LocalTransport` opens them on
demand. Every SDK test uses the latter.

So the feature was green in its own suite and broken on every real
network. What caught it was an unrelated e2e test that iterates
`StreamType` — and only because it iterates rather than lists. Both
multiplex tests now derive their counts from `StreamType`, as does
`SUB_STREAMS` itself.

### A silent hang, found while fixing that
The responder accepted a fixed number of sub-streams. Adding a seventh
meant a 0.7.0 responder would wait forever for a stream a 0.6.0 initiator
never opens — `acceptBi()` is untimed, and there is no handshake timeout
on that path. The connection is never surfaced to any handler, while the
initiator completes its handshake and believes the peer is reachable.
Traffic then disappears with no error on either side.

Fixed by having the initiator announce `HandshakeInit.subStreams` and the
responder accept exactly that many, treating absence as **6** — the count
peers built before this field opened. `LEGACY_SUB_STREAM_COUNT` describes
software already in the world, not this build, and tracking it to
`SUB_STREAMS.length` would restore the hang; there is a test saying so,
because the constant looks exactly like something worth tidying.
Recorded as RFC 001 §5 constraint 5.

**Not covered end to end.** No test runs a real pre-`subStreams` peer
against a current one — that would mean reimplementing the dialer's
handshake. The reasoning is above and the count invariants are tested;
the wire behaviour between versions is not.

---

## Task: 0.7.0 — profiles and media (SDK-REQUESTS #2 and #3)

### Profiles (Stream `0x08`)
A name, bio and picture, as a **single-writer mutable record** rather
than a message. Sent as tagged chat it would have to be filtered out of
every view forever, any client not knowing the convention would render
the tag as text, and each new avatar would sit in message history
permanently on both devices.

`identity.setMyProfile` / `getPeerProfile` / `onPeerProfile`. Paired
peers only in both directions — a ticket is shareable, so dialling one
must not disclose who is behind it. Accepting a connected stranger
delivers it without a redial. 256KB avatar cap enforced on receive as
well as send, so a modified build cannot write a 12MB row into a
contact's database. A frame is ignored unless strictly newer, which stops
a replayed one reverting a name.

The display name is deliberately not authoritative — it is what a peer
calls themselves, not what the local user calls them.

### Blobs (Stream `0x09`)
Content-addressed transfer, separate from the message referencing it.
`blobs.put/get/has/delete/onProgress`, `sendMessage({ attachments })`.
Request/chunk/unavailable, requests carry an offset so an interrupted
transfer resumes. 64MB cap. Three distinguishable errors, because
"could not attach that" is not something an app can say to a person.

Any paired peer holding the bytes may serve them, not only the sender —
in a group the first person to open a picture becomes a second source,
and the sender is frequently offline. A partial copy is never served on:
a truncated transfer is indistinguishable to the requester from a
complete one.

**No garbage collection**, decided rather than skipped. A peer that has
not synced yet holds references this node cannot see, so collecting on
their behalf discards data still in use. Deletion is explicit.

### The bug the local tests could not see, again
`encodePayload` names its fields explicitly, so `attachments` was dropped
on the wire while every test still passed — the CRDT carried it
separately, and the assertion that "a handle travels with the message"
was in fact watching it arrive by document sync. It surfaced only
because a *second* test checked history after a sync, where the peer's
attachment-less write of the same message id overwrote the sender's copy.

Same shape as the `0x07` bug one release earlier: a field added to a
structure and not to the encoder that serialises it. There is now a
round-trip test on the envelope specifically.

### A quadratic write, found by a slow test
Partial transfers were persisted on every chunk, and each write rewrote
the whole accumulated buffer — some 8GB through the disk for a 64MB
blob. Now checkpointed once, when a transfer gives up, which is the only
moment resumption needs it. The stall timeout is a dep rather than a
constant; the tests that exercise a dead link took a minute purely
waiting for it.

---

## Task: 0.7.1 — presence went dark on the wrong side

Found by exercising the **published** 0.7.0 from the registry rather than
the repo, over real QUIC.

`onPeerDisconnected` fired only for the peer that called `disconnect()`.
The remote side — the one that actually needs to know, and the entire
reason the event exists — was never told over `IrohTransport`.

Each sub-stream's `readLoop` returns quietly when its stream ends, and
that is correct in isolation: a finished sync stream must not take chat
down with it. But when a peer leaves, *every* stream ends, and nothing
was watching for that. The connection sat in `Active` indefinitely,
`onClose` never fired, and presence built on it showed someone as present
until the process exited.

Fixed by counting live read loops and treating zero as departure.

### Why the tests did not catch it
`LocalTransport.close()` propagates the close to the peer explicitly —
added in the same release, precisely so both sides are told. So every SDK
test passed, on a transport that cannot exhibit the bug. The QUIC
preflight tested ephemeral, profiles and blobs but not disconnect; the
disconnect check ran on the in-process transport. Each half was covered
and the intersection was not.

**Third time this release that in-process transport hid a QUIC-only
failure** (`0x07` sub-stream never opened, then attachments dropped from
the envelope, now this). The pattern is consistent enough to plan around:
anything touching connection lifecycle or the wire needs a test on
`IrohTransport`, not only through `DicsussionClient`.

`tests/e2e/suite-4.1-real-network.spec.ts` now covers departure over
QUIC. Verified it times out against the unfixed build rather than
assuming it would.

---

## Task: reply references belong in the SDK

Requested by the app, which was encoding them as a control line inside
`content` — the same shape rejected for profiles one release earlier, for
the same reasons: a convention every client must know indefinitely,
literal text in any client that does not, and inseparable from text the
user actually typed. A quoted excerpt cannot strip the marker without
risking stripping something real.

`readonly replyTo?: readonly string[]` on `SendMessageOptions` and
`SdkChatMessage`, threaded through the same five layers `attachments`
uses: SDK types, `MessagePayload`, the envelope codec, the CRDT message,
and `getHistory`.

### Two decisions worth not re-deriving

**Plural.** A reply may answer several messages, and widening a singular
field afterwards breaks every reader that already parses it.

**Ids are carried, never resolved.** A reply legitimately arrives before
the message it answers, and may name one this device will never hold.
Dropping an unresolved reference would silently convert a reply into an
ordinary message, so it is preserved and rendering is the app's call.
There is a test for exactly this.

Serialized into the CRDT rather than stored as a list, for the reason
`attachments` is: Automerge would treat a list as a list CRDT and
interleave two replicas' edits.

### Learned from the attachments bug
The envelope round-trip test was written first this time. `encodePayload`
names its fields explicitly, so a field added to `MessagePayload` and not
to the encoder vanishes on the wire while every local test still passes —
the CRDT carries it separately. That cost a debugging round last release;
here it cost one test.

Bounds on both the count (32) and the id length (`MAX_ID_LENGTH`), since
the value arrives from a peer and is written into the document.

---

## Current State (2026-08-25)

| | |
|---|---|
| Version | **0.7.1**, both packages |
| Tests | **619 passing, 0 failing** |
| Typecheck | clean |
| Build | clean |
| `npm audit` (as a consumer) | 0 vulnerabilities |
| Proving key | real ceremony output, 6 contributors + beacon |
| License | Apache 2.0 |
| Published | 0.7.0 on npm; **0.7.1 pending** — 0.7.0 has the presence bug above |
| Docs | `HOW_TO_USE.md` + a README on each package |

**Test suites:** 11 e2e, 14 transport, 7 CRDT, 5 storage, 3 ZK, 2 WoT, plus
the SDK bridge suite.

Verified from a clean install off the registry, not from the repo: consumer
typecheck with `skipLibCheck: false`, the factory path delivering a message
over a ticket carrying both a transport key and addresses, and an external
two-peer harness passing 3/3 over real QUIC.

---

## Next Immediate Step

Nothing blocks the consuming app. The protocol side of its mobile gate is
finished and published.

1. Relay transport encryption — the only open item that is a security hole
   rather than an unbuilt feature, and the smallest of the serious ones.
   Now specified: RFC 001 §4.3 states what a relayed transport exposes,
   which is the requirement this would satisfy.
2. A relay server. The SDK speaks the protocol and no reference
   implementation exists, which is the widest gap between the architecture
   documents and what is actually running.
3. Typecheck `tests/`.

### Deferred (non-blocking)
- [ ] Relay transport encryption (~1 day) — closes the browser confidentiality gap
- [ ] CRDT operation authenticity — design note, then RFC amendment
- [ ] Message content encryption at rest — `recordLocally` writes
      `content` into the document in the clear, and `storageKey` protects
      identity secrets only. Confirmed still true against 0.4.0.
      **Deferred deliberately, 2026-08-23.** There are no real users, so
      the two questions that were blocking it are not constraints:
      existing unencrypted databases can simply be discarded rather than
      migrated, and `storageKey` may become mandatory without stranding
      anyone. Whoever picks this up should not re-derive that — it was
      decided, not overlooked.
      Scope: encrypt snapshots on write in `DocumentStore` /
      `MessageStore`, decrypt on read. Sync is unaffected, since it
      operates on the in-memory document.
- [ ] OS-keychain integration for identity secrets (RFC 004 §4.1) — explicitly
      deferred to v1.1; SQLite with encryption at rest is sufficient for v1
- [ ] Native prover (rapidsnark) — WASM proving is ~1s per anonymous message
- [ ] Relay server implementation — the SDK speaks the protocol; no reference
      server ships yet
- [ ] Per-message ratchet — forward secrecy is currently per-session
- [ ] Tier gating — `userScore` is a self-asserted private input, held in check
      by application code on both sides. **Do not enable tiers without binding
      it in the circuit**, or quotas become forgeable 100×.
- [x] `exportMnemonic` / `recoverFromMnemonic` / `revokeKey` — **done**, in
      `identity-service.ts`, covered by `tests/sdk/identity-lifecycle.spec.ts`.
      Recovery yields the same `did:key` and `cm_identity`, so channel
      membership survives a lost device; the blind-signing key is regenerated
      and peers must re-pair before issuing endorsements.
- [ ] ZK artifacts are filesystem-bound, so proving does not work in a
      webview (`resolveArtifacts()` returns `null` there)
- [ ] `BridgePipe` confidentiality is the host's responsibility, and the
      contract should say so as plainly as the ordering rule does