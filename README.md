<div align="center">

# Dicsussion Protocol

**A headless, local-first, zero-knowledge P2P messaging engine**

*Solving the decentralization–privacy–performance trilemma*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178c6.svg)](https://www.typescriptlang.org/)
[![Rust](https://img.shields.io/badge/Rust-iroh--net-orange.svg)](https://iroh.computer/)


</div>

---

> [!IMPORTANT]
> **v0.7.2 — read this before depending on it.**
>
> The Groth16 proving key is the output of a **completed six-party trusted
> setup**, closed with a Bitcoin block hash committed to publicly two days
> before that block was mined. Every contribution hash, the beacon, and a full
> verification transcript are published at
> [Ceremonial-Contributions](https://github.com/mrsarthi/Ceremonial-Contributions)
> — verify it rather than taking our word for it.
>
> Three limits are known and unfixed. None is hidden, and each is scoped:
>
> - **The WebSocket relay does not encrypt CRDT traffic.** Chat bodies are
>   sealed end-to-end, but document sync, membership, vouchers, and RLN
>   signals cross the relay in the clear, so a relay operator can read message
>   history and the membership graph. **Browser only** — Iroh/QUIC has no
>   readable intermediary. See [Platform Support](#platform-support).
> - **Replicated CRDT changes are not individually authenticated.** Only
>   paired peers can submit changes at all, but a peer you later distrust can
>   still write arbitrary state.
> - **Reputation tiers are not enforceable.** `userScore` is an unattested
>   private input, so the range proof establishes nothing until scores are
>   committed to the membership tree. Blocked in code rather than silently
>   trusted — do not enable tiers without changing the circuit.
>
> Beyond those three: chat content at rest is unencrypted, though identity
> secrets are not. Forward secrecy is per-session rather than per-message. One
> device per identity. No relay server ships, so there is no offline delivery
> to a sleeping phone. No external security audit has been performed — two
> internal audits and their outcomes are recorded in `PROGRESS.md`.
>
> [`HOW_TO_USE.md`](HOW_TO_USE.md) states all of this in context, alongside
> the behaviours that will otherwise cost you a day.

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
| **Browser transport** | WebSocket relay | Iroh has no WASM target, so browsers relay frames by `did:key`. **The relay currently sees all traffic except chat envelopes in the clear** — see the warning below. Iroh is strongly preferable wherever it runs |
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

> [!WARNING]
> **The WebSocket relay transport does not yet encrypt CRDT traffic.**
>
> Chat payloads on Stream `0x02` are sealed end-to-end and stay private.
> Everything else — CRDT document sync, channel membership, endorsement
> vouchers, revocation gossip, and RLN signals — is handed to the relay as
> plaintext frames. A relay operator can therefore read message history
> replicated through CRDT sync and the full membership graph.
>
> This affects the **browser path only**. Iroh QUIC encrypts peer-to-peer
> with no readable intermediary, so Node, desktop, and mobile are not
> exposed. Treat the WebSocket relay as unsuitable for confidential use
> until this is fixed, and prefer Iroh wherever it runs.

---

## Protocol Specifications

The protocol is defined by four RFCs that cover the full stack from wire transport to the public SDK:

### [RFC 001 — Transport & Discovery](specs/RFC_001-Transport-&-Discovery.md)
Peer-to-peer QUIC transport, `did:key` addressing, mDNS local discovery, NAT traversal via Iroh STUN hole-punching, and DERP relay fallback. Defines the 12-byte wire frame header and nine multiplexed sub-stream types (`0x01`–`0x09`).

### [RFC 002 — Data Sync & Schema Lenses](specs/RFC_002-Data-Sync.md)
Multi-document Automerge CRDT architecture, Bounded Sparse Merkle Tree (depth 16, so 65,536 leaves — but the working cap is **4,096 members per channel**, because rebuild cost is O(N·D)) with Poseidon hashing and deterministic lowest-index eviction, and declarative JSON Schema Lenses for cross-version compatibility.

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
| Tier 3 (High Rep) | ≥200 POC | 100 msgs/epoch |

The slashing is **automatic and trustless** — no moderator votes, no appeals, just math.

> [!IMPORTANT]
> **This holds only on channels that require proofs**, set via
> `createGroup(..., { requireProofs: true })` or the `zkProofs: 'anonymous'`
> client default. Proofs are **off by default**, because generating one
> costs roughly a second per message and that is wasted effort in a
> two-person chat where nobody is anonymous.
>
> With proofs off, the nullifier and Shamir share still travel with each
> message, but nothing binds them to the sender's secret — they are values
> the sender chose. They catch an honest client that double-sends, and
> nothing else. **Do not present proof-disabled RLN to users as spam
> protection.** Turn proofs on for open or adversarial channels.

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

> **Building an app on this?** You want
> **[HOW_TO_USE.md](HOW_TO_USE.md)** — installing from npm, a working
> first message, and the behaviours that will otherwise cost you a day.
> What follows is for working on the protocol itself.

### Install

```bash
git clone https://github.com/mrsarthi/DicsussionProtocol.git
cd DicsussionProtocol
npm install
```

### Build and verify

```bash
npm run build       # compile both packages
npm test            # 552 Playwright tests
npm run typecheck   # tsc --noEmit
```

### Try it between two machines

`npm run peer` is a complete node with a terminal instead of a UI — no
application required.

```bash
npm run peer     # on both machines
```

Wait for each side to print its ticket — that takes a few seconds,
because a ticket is only dialable once the node has discovered a public
address and registered with a relay. Then:

1. `/pair <ticket>` on **both** sides, with each other's ticket
2. `/connect <ticket>` on **one** side
3. Type to chat; `/status` shows whether the path is direct or relayed

Pairing is mutual and both steps are load-bearing. A peer who has not
registered your key drops what you send with no error at either end, so
a single `/connect` looks connected and delivers nothing — see
[`HOW_TO_USE.md`](HOW_TO_USE.md#3-pairing-is-mutual-and-failure-is-silent).

See [`docs/DEVICE_TESTING.md`](docs/DEVICE_TESTING.md) for the full
procedure, including the Termux route for Android.

---

## SDK Preview

Two nodes, a paired connection, and a message. The full guide is
[`HOW_TO_USE.md`](HOW_TO_USE.md).

```typescript
import { DicsussionClient } from '@dicsussion/sdk';

const alice = await DicsussionClient.init({ storagePath: ':memory:' });
const bob = await DicsussionClient.init({ storagePath: ':memory:' });

bob.chat.onMessage('general', (msg) => {
  console.log(`[Tier ${msg.verifiedTier}] ${msg.content}`);
});

// Pairing is MUTUAL — both directions, or the receiver silently drops
// everything. A handshake proves key ownership, not that you know them.
alice.addPeer(bob.did, bob.encryptionPublicKey);
bob.addPeer(alice.did, alice.encryptionPublicKey);

// Pairing says who someone IS; the channel says which conversations they
// are in. Both are required — without this the message reaches nobody.
alice.chat.createChannel('general', [bob.did]);
bob.chat.createChannel('general', [alice.did]);

// Dialling, by contrast, happens once.
await alice.connect(bob.getTicket());

await alice.chat.sendMessage({
  channelId: 'general',
  content: 'Hello, decentralized world!',
});

// A peer's trust score, computed locally and subjectively.
const profile = await alice.trust.getProfile(bob.did);
console.log(`Trust: ${profile.subjectiveScore} POC (Tier ${profile.tier})`);
```

Three things a chat needs that a message is the wrong shape for:

```typescript
// Presence and typing: delivered now, or not at all. Never stored, so a
// heartbeat does not grow the conversation forever.
await alice.chat.sendEphemeral('general', new TextEncoder().encode('typing'));
bob.onPeerDisconnected.on('peer', ({ peerDid }) => { /* the dot goes out */ });

// A name and picture the other person controls — one current value,
// replaced rather than appended, and only for peers you have paired.
await alice.identity.setMyProfile({ displayName: 'Alice' });
bob.identity.onPeerProfile((did, profile) => { /* redraw */ });

// Files travel outside the message, which carries only a hash. Bytes
// move when a recipient asks, so an attachment nobody opens never sends.
const ref = await alice.blobs.put(photo, 'image/png');
await alice.chat.sendMessage({ channelId: 'general', content: 'look', attachments: [ref] });
const bytes = await bob.blobs.get(ref);   // resumes if interrupted
```

Real transports are chosen per host — `'iroh'` on desktop, a bridged
transport in a Tauri or React Native webview, `'websocket'` in a
browser. `init()` defaults to an in-process transport so the above runs
with no network and no native module.

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

Nine multiplexed sub-streams over a single QUIC connection:

| ID | Stream | Purpose |
|---|---|---|
| `0x01` | Channel Membership | Automerge CRDT state sync |
| `0x02` | E2EE Envelopes | Encrypted message payloads + ZK proofs |
| `0x03` | Revocation Gossip | Key/identity slashing tombstones (**high priority**) |
| `0x04` | Voucher Handshakes | Blind endorsement voucher issuance |
| `0x05` | RLN Broadcast | Rate-limiting nullifier signal propagation |
| `0x06` | Share Exchange | RLN polynomial share gossip for transitive slashing |
| `0x07` | Ephemeral | Presence, typing, read receipts — delivered, never stored |
| `0x08` | Peer Profiles | Self-published name, bio and picture; paired peers only |
| `0x09` | Blob Transfer | Content-addressed images and files, requested by hash |


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