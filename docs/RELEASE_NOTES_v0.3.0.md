# GitHub Release — v0.3.0

Paste the body below into the release form. Tag `v0.3.0` on the head of `main`.

---

**Release title:** `v0.3.0 — the bridged transport, actually usable`

---

## Body

This release makes `createBridgedTransport` work. It was published in 0.2.0
and could not be reached from an application — see below.

```bash
npm install @dicsussion/sdk
```

- [`@dicsussion/core@0.3.0`](https://www.npmjs.com/package/@dicsussion/core) — transport, crypto, CRDT sync, ZK
- [`@dicsussion/sdk@0.3.0`](https://www.npmjs.com/package/@dicsussion/sdk) — client facade

Apache-2.0.

### 0.2.0's headline feature did not work

`createBridgedTransport` lets a host that owns its own socket — Tauri, React
Native, Electron — supply the bytes while the SDK keeps the RFC 001 §5
handshake, session-key derivation, framing, and priority. A webview cannot
open a QUIC socket, so on mobile it is the only route to the network.

As published in 0.2.0 it was unusable, in two independent ways:

**No way to obtain the identity.** The transport needs the node's Ed25519
keypair to authenticate as it, and that key is derived inside `init()` from a
seed the caller never holds. `transport: <ITransport instance>` was therefore
only usable by a transport that does not authenticate as the node, and there
is no such transport.

**No way to publish a dialable ticket.** `getTicket()` special-cased
`IrohTransport`; every other transport received a synthesised ticket with no
transport key and no addresses. Two bridged peers could never have found each
other.

Either alone is fatal. Both were missed because the transport was only ever
tested in isolation, never through a `DicsussionClient` — the gap a test
added in this release now closes.

Anyone who installed 0.2.0 and tried to use the bridge hit a wall. Upgrade.

### Breaking: `BridgePipe` gained a required method

```ts
addresses(): Promise<{ directAddresses: readonly string[]; relayUrl?: string }>
```

The SDK derives the transport *key* from the identity by one-way HKDF; only
the host knows the *addresses* behind it. Neither half alone is dialable,
which is why this cannot be optional.

This is why the release is 0.3.0 rather than a patch. In practice no
implementation can exist — the bridge could not be wired at all in 0.2.0 —
but a published interface changed, and the version should say so.

### New: transport factories

```ts
transport: (identity) => createBridgedTransport(pipe, { identity })
```

The client calls the factory during bootstrap with the identity it derived.
`TransportFactory` is exported from both entries.

Deriving the identity outside the SDK was the alternative, and it is worse
than duplicated code: the transport public key comes from the identity by
one-way HKDF, so a transport minting its own would advertise an address no
peer could dial — presenting as a network fault rather than a key mismatch.

`getTicket()` is now a capability check rather than an `instanceof` test, so
any transport that knows how it is reachable publishes a real ticket.

### New: documentation

Both packages ship a README for the first time; until now their npm pages
were blank.

- [`HOW_TO_USE.md`](../HOW_TO_USE.md) — installing, a working first message,
  and the behaviours that will otherwise cost you a day
- `@dicsussion/sdk` README — building an application
- `@dicsussion/core` README — writing a `BridgePipe`, and what the contract
  does and does not promise

The guide is built from traps this project rediscovered the hard way, not
from the API surface. It also states plainly what does not work yet: no relay
server ships, forward secrecy is per-session, one device per identity,
Node-only proving, and `WebSocketTransport` leaves everything but chat bodies
readable to the relay operator.

### Also in this release

Carried over from 0.2.0, which shipped a day earlier and is superseded:

- **`snarkjs` is an optional peer dependency.** It pulls a transitive
  `underscore` carrying a known DoS advisory, and shipping it by default
  handed that to every consumer — including the majority who run with
  `zkProofs: 'off'`. Install it only if you generate or verify proofs; the
  SDK says so plainly if you reach a proving path without it. A default
  install now audits clean.
- **`@types/better-sqlite3` is a runtime dependency.** Without it, every
  TypeScript consumer of the root entry failed to typecheck.
- **`client.onPeerConnected`** emits `{ peerDid, paired, direction }`, so an
  application can surface a stranger's connection attempt rather than discard
  it silently.
- **Pairing from tickets is covered by tests**, including the non-delivery
  case and the recovery path: pairing *after* a peer connects repairs
  delivery on the open connection, with no redial.
- **`npm run peer` gained `/pair`**, and prints its ticket only once the node
  has discovered a public address and registered with a relay. It previously
  printed at startup, so the ticket carried LAN addresses only — undialable
  from any other network, and indistinguishable from NAT traversal failing.

### Upgrading

Nothing to change unless you implement `BridgePipe`, in which case add
`addresses()`. If you generate ZK proofs, `npm install snarkjs`.

### Verified before release

Installed from the packed tarballs into a clean project: consumer typecheck
with `skipLibCheck: false`, the bridged transport delivering under one-byte
chunking, an independent two-peer harness passing over real QUIC, and
`npm audit` reporting zero vulnerabilities. 530 tests pass in the repository.
