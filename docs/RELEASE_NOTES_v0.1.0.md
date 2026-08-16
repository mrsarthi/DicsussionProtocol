# GitHub Release — v0.1.0

Paste the body below into the release form. Tag `v0.1.0` on commit `91b7800`.

---

**Release title:** `v0.1.0 — first public release`

---

## Body

First public release of Dicsussion Protocol — a headless, local-first P2P
messaging engine with zero-knowledge anti-spam.

```bash
npm install @dicsussion/sdk
```

- [`@dicsussion/core@0.1.0`](https://www.npmjs.com/package/@dicsussion/core) — transport, crypto, CRDT sync, ZK
- [`@dicsussion/sdk@0.1.0`](https://www.npmjs.com/package/@dicsussion/sdk) — client facade

Apache-2.0.

### The trusted setup is done

The Groth16 proving key shipped in this release is the output of a
**completed six-party trusted setup ceremony**, finalised with the hash of
Bitcoin block 962000.

The beacon was committed publicly on **2026-08-08 15:15:45 UTC**. That block
was mined on **2026-08-11 11:07:57 UTC** — a lead time of 2 days, 19 hours,
52 minutes. Committing to a value that does not yet exist is what makes the
claim checkable; a beacon announced afterwards proves nothing.

Forging a proof against this key requires all six contributors to have
colluded, all six to have retained entropy they publicly attested to
destroying, and control over a Bitcoin block hash that did not exist when the
commitment was published.

| Artifact | SHA-256 |
|---|---|
| `rln_final.zkey` | `b1d518ab7249d1ea22c790f13004575d7c2cfad8c846c71e3f332231b6bec20f` |
| `verification_key.json` | `83b3b0c5124a071698fc67d534ab84570bf57478a15e3dcdd3c4ae8ecaf5c716` |

Every contribution hash, the beacon, and the full verification transcript:
**https://github.com/mrsarthi/Ceremonial-Contributions**

Please verify it rather than taking our word for it:

```bash
snarkjs zkey verify rln_range_unified.r1cs pot15_final.ptau rln_final.zkey
```

### What's in it

- **P2P transport** — Iroh QUIC with mDNS discovery, NAT traversal, and DERP
  relay fallback; six multiplexed sub-streams
- **E2EE messaging** — X25519 + AES-256-GCM, forward secret via per-session
  ephemeral key exchange
- **ZK-RLN anti-spam** — Groth16 over BN254; exceeding an epoch quota reveals
  the sender's secret by Lagrange interpolation and slashes their identity
- **Web-of-Trust** — Chaumian RSA-FDH blind vouchers, so an endorsement
  cannot be linked to its issuer
- **CRDT sync** — Automerge with a bounded sparse Merkle tree for membership
- **Browser support** — WebSocket relay transport and an IndexedDB driver

488 tests. Node, desktop, mobile (React Native / Termux), and browsers.

### Known limitations

Stated plainly, because finding them yourself later is worse.

- **The WebSocket relay does not encrypt CRDT traffic.** Chat bodies are
  sealed end-to-end, but document sync, membership, vouchers, and RLN signals
  cross the relay in the clear — a relay operator can read message history and
  the membership graph. **Browser only.** Iroh/QUIC has no readable
  intermediary and is unaffected.
- **Replicated CRDT changes are not individually authenticated.** Only paired
  peers can submit changes, but a peer you later distrust can still write
  arbitrary state. Fixing this is a wire-format change.
- **Reputation tiers are not enforceable.** `userScore` is an unattested
  private input, so the range proof establishes nothing until scores are
  committed to the membership tree. Blocked in code rather than silently
  trusted — do not enable tiers without changing the circuit.
- **Chat content at rest is unencrypted.** Identity secrets are protected.
- **No external security audit.** Two internal audits; findings and disputed
  severities recorded in `PROGRESS.md`.

### Pairing is mandatory and mutual

Both devices must exchange tickets and call `addPeer()` before any traffic
flows. A completed handshake authenticates a key, not a relationship — the
`did:key` in a handshake is self-asserted, so a stranger with a fresh keypair
is indistinguishable from a friend until pairing separates them.

### Note on `@dicsussion/core`

It has no root entry point — import subpaths directly:

```js
import { generateEd25519Keypair } from '@dicsussion/core/crypto';
import { publicKeyToDidKey }      from '@dicsussion/core/transport';
```

`require('@dicsussion/core')` will fail by design.

---

**Full changelog:** https://github.com/mrsarthi/DicsussionProtocol/commits/v0.1.0
