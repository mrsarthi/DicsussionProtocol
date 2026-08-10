<div align="center">

# Dicsussion Protocol

**A headless, local-first, zero-knowledge P2P messaging engine**

*Solving the decentralization–privacy–performance trilemma*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178c6.svg)](https://www.typescriptlang.org/)
[![Rust](https://img.shields.io/badge/Rust-iroh--net-orange.svg)](https://iroh.computer/)


</div>

---

> [!WARNING]
> **Not yet production-ready.** The bundled Groth16 proving key comes from a
> single-party development ceremony. Proving and verifying both refuse it
> unless explicitly overridden, and it must be replaced by a multi-party
> trusted setup before any real deployment — see
> [`docs/TRUSTED_SETUP_CEREMONY.md`](docs/TRUSTED_SETUP_CEREMONY.md).
>
> Reputation-tier proofs are also not enforceable yet: `userScore` is an
> unattested private input, so the range proof establishes nothing until
> scores are committed. It is blocked in code rather than silently trusted.

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
| **Forward Secrecy** | Each connection derives a session key from both peers' ephemeral X25519 halves, which are wiped once it exists. Stealing both long-term keys later does not decrypt past sessions. |
| **Zero Trust** | Every peer independently verifies what it receives. Anonymous messages carry an RLN rate-limit signal; Groth16 membership proofs are attached where a channel's signed anchor requires them. |

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
| **Browser transport** | WebSocket relay | Iroh has no WASM target, so browsers relay frames by `did:key`. The relay cannot read or impersonate, but does learn who talks to whom — Iroh is preferable wherever it runs |
| **State Sync** | [Automerge](https://automerge.org/) | Conflict-free replicated data types (CRDTs) over direct QUIC byte streams |
| **Local Storage** | SQLite / IndexedDB | `better-sqlite3` on desktop, IndexedDB in browser contexts |
| **Zero-Knowledge** | [Circom 2.x](https://docs.circom.io/) + [SnarkJS](https://github.com/iden3/snarkjs) | Groth16 proving system over BN254 for ZK-RLN and range proofs |
| **Encryption** | X25519 + HKDF-SHA256 + AES-256-GCM + Ed25519 | Ephemeral key agreement per session, symmetric E2EE, signing keys (`did:key` identity) |
| **Testing** | [Playwright](https://playwright.dev/) | Multi-peer headless orchestration, protocol flow validation |

---

## Platform Support

| | Node / desktop | Mobile (React Native, Termux) | Browser |
| :--- | :---: | :---: | :---: |
| Messaging, identity, CRDT sync | ✅ | ✅ | ✅ |
| Transport | Iroh QUIC | Iroh QUIC | WebSocket relay |
| Storage | SQLite | SQLite | IndexedDB |
| ZK-RLN rate limiting | ✅ | ✅ | ✅ |
| Groth16 proving | ✅ | ✅ | ❌ artifacts load from disk |
| mDNS discovery | ✅ | ⚠️ | ❌ pair by ticket |

Browser consumers import from `@dicsussion/sdk/browser`, which excludes the
native SQLite driver. Verified by an `esbuild --platform=browser` build in CI
that fails if any Node builtin reaches the bundle. Full breakdown in
[`docs/CAPABILITY_MATRIX.md`](docs/CAPABILITY_MATRIX.md).

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
The `@dicsussion/sdk` (`DicsussionClient`) facade, a persistent worker pool for proof generation, the local Web-of-Trust scoring engine, and the SQLite/IndexedDB persistence schemas.

The original requirement to mandate an Electron IPC topology was **withdrawn**: that is host-application plumbing, not protocol. The requirement is now "must not block the caller", which the worker pool satisfies equally in Electron, plain Node and React Native.

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

### Install

```bash
git clone https://github.com/mrsarthi/DicsussionProtocol.git
cd DicsussionProtocol
npm install
```

### Build and verify

```bash
npm run build       # compile both packages
npm test            # 464 Playwright tests
npm run typecheck   # tsc --noEmit
```

### Try it between two machines

`npm run peer` is a complete node with a terminal instead of a UI — no
application required. Run it on two machines, paste one's ticket into the
other, and type. See [`docs/DEVICE_TESTING.md`](docs/DEVICE_TESTING.md),
including the Termux route for Android.

```bash
npm run peer
```

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

// Send an E2EE message. Anonymous sends carry an RLN rate-limit signal;
// a Groth16 membership proof is attached only on channels whose signed
// genesis anchor requires one.
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

## License

**[Apache License 2.0](LICENSE)** — free for any use, including commercial,
with an explicit patent grant.

Use it, modify it, ship it in a product, build a business on it. The only
obligations are the usual Apache ones: keep the license and copyright notices,
state what you changed, and include the [NOTICE](NOTICE) file.

### Third-party terms

`snarkjs` (GPL-3.0) is an *optional* dependency loaded via dynamic `import()`
— it is not bundled or redistributed here, and installing it binds you to its
terms directly. Applications that don't generate or verify proofs need not
install it at all.

Compiled circuit artifacts (`*.r1cs`, `*.wasm`, `*.zkey`) incorporate
`circomlib` templates and are distributed under **GPL-3.0**, separately from
the SDK source. See [NOTICE](NOTICE) for the full component breakdown.

---

<div align="center">

*No servers. No moderators. No metadata leaks. Just math.*

</div>