# Backend & Platform Capability Matrix

What actually runs where. Verified on 2026-08-05 by a real
`esbuild --platform=browser` build, not by reading imports — the failures that
matter are resolution failures inside transitive dependencies, which no source
scan reveals. Every ❌ below names the specific dependency that blocks it.

---

## Runtime support

| Subsystem | Node / desktop | Mobile (React Native, Termux) | Browser |
| :--- | :---: | :---: | :---: |
| Transport — Iroh QUIC | ✅ | ✅ | ❌ |
| Transport — WebSocket relay | ✅ | ✅ | ✅ |
| Storage | ✅ | ✅ | ✅ |
| E2EE crypto | ✅ | ✅ | ✅ |
| Identity & vouchers | ✅ | ✅ | ✅ |
| CRDT sync | ✅ | ✅ | ✅ |
| ZK proving (Groth16) | ✅ | ✅ | ❌ |
| ZK-RLN rate limiting | ✅ | ✅ | ✅ |
| Ephemeral signals (0x07) | ✅ | ✅ | ✅ |
| Peer profiles (0x08) | ✅ | ✅ | ✅ |
| Blob transfer (0x09) | ✅ | ✅ | ✅ |
| mDNS discovery | ✅ | ⚠️ | ❌ |

**Browsers are supported.** Import from `@dicsussion/sdk/browser`, supply
`IndexedDbDriver` and the `'websocket'` transport. Verified by an
`esbuild --platform=browser` run in CI
(`tests/transport/browser-bundle.spec.ts`) that fails if any Node builtin
reaches the bundle.

Two things remain Node-only, and neither blocks messaging:
- **Groth16 proving** loads its 7.6 MB of artifacts from disk. RLN rate
  limiting — the part that is actually enforced on the wire — is pure field
  arithmetic and works everywhere.
- **mDNS** needs UDP multicast. Browser peers pair by ticket instead.

---

## Transports

Three implementations of `ITransport`.

| | `IrohTransport` | `WebSocketTransport` | `LocalTransport` |
| :--- | :--- | :--- | :--- |
| Wire protocol | Real QUIC | Frames over a relay | In-process calls |
| NAT traversal | Hole-punching + relay | n/a — always relayed | n/a |
| Cross-process | ✅ verified | ✅ | ❌ same process |
| Browser | ❌ native, no WASM target | ✅ | ❌ |
| Metadata exposure | Peers only | **Relay learns who talks to whom** | n/a |
| Use for | Everything real | Browsers and webviews | Tests, embedding |

`@number0/iroh` ships prebuilt binaries including `android-arm64` and
`android-arm-eabi`, which is why Termux works.

### What a relay can and cannot do

A relay is an untrusted third party that sees every byte and chooses how to
route it. It **cannot** read messages (payloads are sealed) and it **cannot**
impersonate a peer: the RFC 001 §5 handshake runs end-to-end through it, and the
accepter binds the relay's session label to the `did:key` inside the signed
init — so a relay that mislabels a session gets the handshake rejected. Both
properties are tested against a deliberately hostile relay.

It **can** drop or delay traffic, and it learns the social graph: who talks to
whom, and when. That is the real cost of using it, and it is why
`IrohTransport` remains the better choice on any platform that can run it.

---

## Storage drivers

Both implement `IStorageDriver`, and **their observable behaviour is tested for
parity** (`tests/storage/indexeddb-driver.spec.ts`).

| | `SQLiteDriver` | `IndexedDbDriver` |
| :--- | :--- | :--- |
| Runtime | Node (native `better-sqlite3`) | Browser, or Node with a shim |
| Transactions | ✅ | ❌ no equivalent |
| Constraint enforcement | ✅ NOT NULL, FK, types | ❌ none |
| Query filtering | SQL `WHERE` | in-memory scan after read |
| Binary values | BLOB | native typed array |

### Two behaviours callers must not depend on differing

**Value shapes are identical by design.** SQLite has no array or boolean type,
so objects are stored as JSON strings and booleans as `0`/`1`. The IndexedDB
driver stores the *same* shapes even though it could round-trip richer values —
matching the weaker backend is what keeps one set of callers correct on both.
Code doing `JSON.parse(row['peers'])` works unchanged.

**Constraint enforcement is not identical.** SQLite rejects a row missing a NOT
NULL column; IndexedDB accepts anything. A caller writing invalid records will
fail on desktop and silently succeed in a browser. Validate in the store, not in
the backend.

**There are no transactions on IndexedDB.** `checkpointAll()` writes documents
one at a time; a crash mid-run leaves some persisted and some not. Automerge
snapshots are independent, so this degrades to "some documents are older", not
corruption.

---

## Proving

One implementation: `ZekPocProver`, Groth16 over BN254 via snarkjs (WASM).

| | Status |
| :--- | :--- |
| Proving time | ~536 ms measured (desktop, WASM) |
| Worst event-loop stall | 52 ms — snarkjs yields internally |
| Verification | ~29 ms |
| Artifacts | 4.9 MB zkey + 2.7 MB wasm, published with `@dicsussion/core` |
| Browser | ❌ artifacts load via `node:fs`; needs `fetch` + caching |
| Native (`rapidsnark`) | Not integrated — would need a compiled binary per platform |

**The bundled proving key is from a single-party ceremony.** Proving and
verifying both refuse it unless `allowDevelopmentCeremony: true` is passed.
The six-party ceremony behind the shipped key is published at
[Ceremonial-Contributions](https://github.com/mrsarthi/Ceremonial-Contributions).

---

## How browser support was reached

Each of these was a hard blocker; all are resolved.

1. **A second `ITransport`.** `WebSocketTransport` routes through a relay.
2. **Crypto off `node:crypto`.** AES-256-GCM now uses `@noble/ciphers`, *not*
   Web Crypto — `crypto.subtle` is async and `encrypt`/`decrypt` are
   synchronous by contract, so adopting it would have pushed `await` through
   `sealMessage` and every caller above it for no behavioural gain. Noble is
   pure JS, constant-time, and synchronous everywhere. The ciphertext layout is
   byte-identical, so data written by an older build still decrypts.
3. **RSA keygen off `generateKeyPairSync`.** Now Web Crypto's async
   `generateKey`, and generated lazily on first endorsement rather than at
   every `init()` — it cost hundreds of milliseconds to seconds on a path most
   nodes never use.
4. **SQLite out of the browser graph.** `better-sqlite3` is reached from the
   main barrel and fails at *resolution*, so tree-shaking cannot help. The
   `browser` field maps it to an empty module and `@dicsussion/sdk/browser`
   does not advertise it.
5. **`node:events` replaced.** A local `Emitter` removes the polyfill
   requirement rather than documenting it.

Also ported: `state-root.ts` (`createHash` → `@noble/hashes`, verified to
produce byte-identical roots, since the state root is consensus-critical),
`handshake.ts`, and `identity-service.ts` (`randomBytes` → Web Crypto).

---

## Choosing a configuration

**Desktop app (Electron, Tauri):** `IrohTransport` + `SQLiteDriver`. Everything
works. This is the tested path.

**Mobile (React Native):** `IrohTransport` + SQLite. `better-sqlite3` is a
native module — either embed Node (`nodejs-mobile`) or swap in `op-sqlite`
behind `IStorageDriver`. Bundle the circuit artifacts with the app.

**Headless node / CLI:** what `npm run peer` does. See `DEVICE_TESTING.md`.

**Browser / webview:**

```ts
import { DicsussionClient, IndexedDbDriver } from '@dicsussion/sdk/browser';

const client = await DicsussionClient.init(
  { storagePath: 'unused' },
  {
    storage: new IndexedDbDriver(),
    transport: 'websocket',
    relayUrl: 'wss://relay.example',
  },
);
```

Both options are required — without `storage` the client falls back to SQLite,
and without a relay it cannot reach a peer at all. Your bundler needs a loader
for Automerge's `.wasm` asset. Groth16 proving is unavailable; RLN rate
limiting is not affected.

**Tests:** `LocalTransport` + `SQLiteDriver(':memory:')`, or `IndexedDbDriver`
with `fake-indexeddb` for browser-storage paths.
