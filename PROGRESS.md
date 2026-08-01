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

## Next Immediate Step
**Phase 1A — Core P2P Transport Engine**
Begin building the modular transport engine in `packages/core/src/transport/`:
1. Define TypeScript interfaces for QUIC stream types (0x01–0x06) per RFC_001
2. Define the peer addressing model (`did:key` from Ed25519)
3. Stub the transport manager class with connection lifecycle methods
4. Implement the handshake clock-sync logic (Δ_peer calculation)