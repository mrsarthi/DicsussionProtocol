<div align="center">

# Dicsussion Protocol

**A headless, local-first, zero-knowledge P2P messaging engine**

*Solving the decentralization–privacy–performance trilemma*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178c6.svg)](https://www.typescriptlang.org/)
[![Rust](https://img.shields.io/badge/Rust-iroh--net-orange.svg)](https://iroh.computer/)
[![Status](https://img.shields.io/badge/Status-Active_Development-yellow.svg)](#development-status)

</div>

---

## What is Dicsussion?

Dicsussion is a **headless protocol engine and SDK** for building fully decentralized, end-to-end encrypted messaging applications — with **zero central servers**, **metadata privacy**, and **cryptographic anti-spam** built into the wire protocol itself.

Unlike traditional messaging platforms that rely on central servers (or even federated home servers) to route messages, moderate spam, and manage identity, Dicsussion pushes all of those responsibilities to the cryptographic layer and the local device:

- **Messages route peer-to-peer** over encrypted QUIC streams via [Iroh](https://iroh.computer/).
- **Spam is stopped by math**, not moderators — zero-knowledge rate-limiting nullifiers (ZK-RLN) enforce per-epoch message quotas without revealing who you are.
- **Reputation is local and subjective** — your device computes trust scores from your own interactions, never from a global ledger.
- **Everything works offline** — state syncs seamlessly when you reconnect via conflict-free replicated data types (CRDTs).

The result is a messaging substrate where no single entity can read your messages, track who you talk to, censor your speech, or spam your inbox.

---

## Core Design Principles

| Principle | How It's Enforced |
|---|---|
| **Local-First** | All state owned locally in SQLite/IndexedDB. Offline-capable with automatic outbox sync on reconnect. |
| **Metadata Privacy** | No server sees sender/receiver pairs, user identities, or reputation balances. DERP relays are honest-but-curious and see only encrypted byte streams. |
| **Cryptographic Anti-Spam** | ZK-RLN Groth16 proofs enforce tiered rate limits. Exceeding quota triggers automatic identity slashing — no moderators needed. |
| **Sybil Resistance** | Web-of-Trust reputation via blind endorsement vouchers. Issuance costs POC to prevent voucher farming. |
| **Zero Trust** | All wire payloads carry attached zk-SNARK proofs. Every peer independently verifies every message. |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Application / Frontend                     │
│              (React, Electron, Mobile, CLI, etc.)             │
└──────────────────────────┬──────────────────────────────────┘
                           │  @dicsussion/sdk
┌──────────────────────────▼──────────────────────────────────┐
│                   HLessEnd (Headless Backend)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │  WoT Engine  │  │   Storage    │  │  DicsussionClient  │ │
│  │  Trust Scores │  │ SQLite/IDB  │  │   Facade API       │ │
│  └──────────────┘  └──────────────┘  └────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │  Internal APIs
┌──────────────────────────▼──────────────────────────────────┐
│                    Core Protocol Engine                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │Transport │  │  Crypto  │  │   CRDT   │  │  ZK Engine  │ │
│  │QUIC/mDNS │  │X25519/AES│  │ Automerge│  │Circom/RLN   │ │
│  │DERP relay│  │Ed25519   │  │Merkle SMT│  │Groth16/BN254│ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Monorepo Structure

```
DicsussionProtocol/
├── packages/
│   ├── core/src/                  # Low-level protocol engine
│   │   ├── transport/             # Iroh QUIC, mDNS discovery, DERP relay
│   │   ├── crypto/                # X25519 key exchange, AES-256-GCM, Ed25519
│   │   ├── crdt/                  # Automerge CRDT, Bounded Sparse Merkle Tree
│   │   └── zk/                    # Circom circuits, SnarkJS, ZK-RLN engine
│   │
│   └── HLessEnd/src/              # Headless backend & public SDK
│       ├── wot/                   # Web-of-Trust scoring, blind vouchers
│       ├── storage/               # SQLite / IndexedDB persistence
│       └── index.ts               # @dicsussion/sdk — DicsussionClient facade
│
├── specs/                         # Protocol RFCs (001–004)
├── tests/                         # Playwright integration test suites
└── PROGRESS.md                    # Development progress log
```

---

## Technical Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Runtime & SDK** | Node.js / TypeScript | Core engine and public API surface (`@dicsussion/sdk`) |
| **Networking** | Rust / [Iroh](https://iroh.computer/) (`iroh-net`) | QUIC streams, mDNS local discovery, STUN hole-punching, DERP relay fallback |
| **State Sync** | [Automerge](https://automerge.org/) | Conflict-free replicated data types (CRDTs) over direct QUIC byte streams |
| **Local Storage** | SQLite / IndexedDB | `better-sqlite3` on desktop, IndexedDB in browser contexts |
| **Zero-Knowledge** | [Circom 2.x](https://docs.circom.io/) + [SnarkJS](https://github.com/iden3/snarkjs) | Groth16 proving system over BN254 for ZK-RLN and range proofs |
| **Encryption** | X25519 + AES-256-GCM + Ed25519 | Key exchange, symmetric E2EE, signing keys (`did:key` identity) |
| **Testing** | [Playwright](https://playwright.dev/) | Multi-peer headless orchestration, protocol flow validation |

---

## Protocol Specifications

The protocol is defined by four RFCs that cover the full stack from wire transport to the public SDK:

### [RFC 001 — Transport & Discovery](specs/RFC_001-Transport-&-Discovery.md)
Peer-to-peer QUIC transport, `did:key` addressing, mDNS local discovery, NAT traversal via Iroh STUN hole-punching, and DERP relay fallback. Defines the 12-byte wire frame header and six multiplexed sub-stream types (`0x01`–`0x06`).

### [RFC 002 — Data Sync & Schema Lenses](specs/RFC_002-Data-Sync.md)
Multi-document Automerge CRDT architecture, Bounded Sparse Merkle Tree (depth 16, max 65,536 identities) with Poseidon hashing and LRU eviction, and declarative JSON Schema Lenses for cross-version compatibility.

### [RFC 003 — Security Envelope & ZK-RLN](specs/RFC_003-Security-Envelope.md)
Unified Groth16 single-proof envelope combining ZK range proofs (reputation ≥ threshold) with ZK-RLN rate-limiting. Tiered quota allocation, Poseidon domain separation, Chaumian blind endorsement vouchers, and cryptographic slashing via Lagrange secret reconstruction.

### [RFC 004 — Headless Backend & SDK](specs/RFC_004-Headless-Backend.md)
The `@dicsussion/sdk` (`DicsussionClient`) facade, Electron IPC process isolation, persistent Web Worker pool for proof generation, local Web-of-Trust scoring engine, and SQLite/IndexedDB persistence schemas.

---

## How Anti-Spam Works (ZK-RLN)

Traditional platforms moderate spam with centralized servers and phone number verification. Dicsussion uses **Zero-Knowledge Rate-Limiting Nullifiers** — a cryptographic construction that limits how many messages you can send per epoch *without revealing who you are*:

```
1. You prove (in zero-knowledge) that your reputation score ≥ tier threshold
2. You prove you haven't exceeded your epoch quota using a Shamir polynomial
3. If you double-send in the same slot, any peer can reconstruct your secret
4. Your identity commitment gets slashed via a Revocation Tombstone
```

| Reputation Tier | Score Range | Messages per 10s Epoch |
|---|---|---|
| Tier 0 (Untrusted) | 0–49 POC | 1 |
| Tier 1 (Standard) | 50–99 POC | 3 |
| Tier 2 (Established) | 100–199 POC | 10 |
| Tier 3 (High Rep) | ≥200 POC | Unrestricted |

The slashing is **automatic and trustless** — no moderator votes, no appeals, just math.

---

## How Trust Works (Web-of-Trust)

Reputation is **local, subjective, and privacy-preserving**. Your device computes a trust score for each peer based on your direct interactions:

```
S(P) = 10 × verified_sessions + 5 × vouchers_redeemed − 2 × vouchers_issued
```

- **+10 POC** per verified bidirectional chat session (≥3 epochs, both sides produced valid ZK proofs)
- **+5 POC** per redeemed blind endorsement voucher (unlinkable Chaumian blind signature)
- **−2 POC** per voucher issued (prevents voucher farming)
- **−∞** on slashing (immediate blacklist + Revocation Tombstone gossip)

No global score exists. Every peer sees a different trust landscape shaped by their own interactions.

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) ≥ 18
- [Rust](https://rustup.rs/) (for `iroh-net` native bindings)

### Install

```bash
git clone https://github.com/mrsarthi/DicsussionProtocol.git
cd DicsussionProtocol
npm install
```

### Run Tests

```bash
# Run all Playwright tests
npx playwright test

# Run in headed mode (visible browser)
npx playwright test --headed
```

### Type Check

```bash
npx tsc --noEmit
```

---

## Development Status

The project is under active development following a three-phase roadmap:

| Phase | Focus | Status |
|---|---|---|
| **Phase 1** | Core P2P mesh, E2EE messaging, Automerge CRDT sync | 🔨 In Progress |
| **Phase 2** | Web-of-Trust, Sparse Merkle Tree, blind voucher exchange | ⏳ Planned |
| **Phase 3** | ZK proving engine, Circom circuits, RLN slashing pipeline | ⏳ Planned |

See [PROGRESS.md](PROGRESS.md) for detailed task-level progress.

---

## SDK Preview

```typescript
import { DicsussionClient } from '@dicsussion/sdk';

// Initialize the headless engine
const client = await DicsussionClient.init({
  storagePath: './data',
  relayEndpoints: ['https://relay1.iroh.network'],
  proofBackend: 'wasm',
});

// Send an E2EE message with attached ZK proof
await client.chat.sendMessage({
  channelId: 'general',
  content: 'Hello, decentralized world!',
});

// Listen for incoming messages
client.chat.onMessage('general', (msg) => {
  console.log(`[Tier ${msg.verifiedTier}] ${msg.content}`);
});

// Check a peer's local trust score
const profile = await client.trust.getProfile('did:key:z6Mkf...');
console.log(`Trust: ${profile.subjectiveScore} POC (Tier ${profile.tier})`);

// Gift a blind endorsement voucher (+5 POC)
await client.trust.giftEndorsement('did:key:z6Mkf...');
```

---

## Wire Protocol at a Glance

Every frame on the wire carries a 12-byte binary header:

```
┌──────────┬─────────────┬───────┬────────────┬──────────┐
│ magic    │ stream_type │ flags │ payload_len│ checksum │
│ 0x5032   │ u8          │ u8    │ u32 BE     │ CRC32-C  │
│ 2 bytes  │ 1 byte      │ 1 byte│ 4 bytes    │ 4 bytes  │
└──────────┴─────────────┴───────┴────────────┴──────────┘
```

Six multiplexed sub-streams over a single QUIC connection:

| ID | Stream | Purpose |
|---|---|---|
| `0x01` | Channel Membership | Automerge CRDT state sync |
| `0x02` | E2EE Envelopes | Encrypted message payloads + ZK proofs |
| `0x03` | Revocation Gossip | Key/identity slashing tombstones (**high priority**) |
| `0x04` | Voucher Handshakes | Blind endorsement voucher issuance |
| `0x05` | RLN Broadcast | Rate-limiting nullifier signal propagation |
| `0x06` | Share Exchange | RLN polynomial share gossip for transitive slashing |

---

## Contributing

This project is in early active development. Contributions, feedback, and protocol review are welcome.

1. Read the [RFC specifications](specs/) to understand the protocol design
2. Check [PROGRESS.md](PROGRESS.md) for current task status
3. Open an issue to discuss changes before submitting PRs

---

## License

Licensed under the [Apache License 2.0](LICENSE).

---

<div align="center">

*No servers. No moderators. No metadata leaks. Just math.*

</div>