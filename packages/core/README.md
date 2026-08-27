# @dicsussion/core

The protocol engine beneath [`@dicsussion/sdk`](https://www.npmjs.com/package/@dicsussion/sdk):
transport, cryptography, CRDT sync, and zero-knowledge anti-spam
(RFC 001–003).

**Most applications want the SDK, not this package.** Reach for core
directly when you need a layer on its own — most often to supply a
transport from a host the SDK cannot open sockets in.

```bash
npm install @dicsussion/core
```

---

## There is no root export

Import from one of four subpaths. `import … from '@dicsussion/core'`
does not resolve.

| Entry | What's in it |
| :--- | :--- |
| `@dicsussion/core/transport` | Iroh QUIC, WebSocket relay, bridged transport, framing, tickets, `did:key` |
| `@dicsussion/core/crypto` | X25519, AES-256-GCM, Ed25519, blind signatures |
| `@dicsussion/core/crdt` | Automerge documents, sync engine, Sparse Merkle Tree |
| `@dicsussion/core/zk` | Groth16 prover, RLN signals |

---

## Bringing your own transport

The main reason to be here. A Tauri, React Native, or Electron app
already owns a real socket in its native layer and only lacks a way to
hand those bytes to the protocol. `createBridgedTransport` is that seam:
you supply the bytes, the SDK keeps the RFC 001 §5 handshake, session-key
derivation, framing, and priority.

```ts
import { createBridgedTransport } from '@dicsussion/core/transport';
import type { BridgePipe } from '@dicsussion/core/transport';

const pipe: BridgePipe = {
  addresses: async () => ({ directAddresses, relayUrl }),
  connect: async (target) => openConnection(target),  // → connection id
  send: async (id, bytes) => write(id, bytes),
  onData: (handler) => subscribe('data', handler),
  onInbound: (handler) => subscribe('inbound', handler),
  onClosed: (handler) => subscribe('closed', handler),
  disconnect: async (id) => close(id),
  close: async () => shutdown(),
};

const transport = createBridgedTransport(pipe, { identity });
```

With the SDK, pass it as a factory — the identity is derived during
`init()`:

```ts
transport: (identity) => createBridgedTransport(pipe, { identity })
```

### The contract is ordered bytes, and nothing else

Three rules, each of which has already cost someone real time:

**Do not add your own framing.** You may split one `send` across several
`onData` calls, or coalesce many into one. Both are correct. The SDK
length-prefixes control messages itself — if you prefix as well, the
handshake breaks.

**Confidentiality to the peer is yours.** This transport frames and
forwards; it does not encrypt beneath the protocol. Bridging a QUIC or
TLS channel is fine. Bridging a plaintext socket, or one that terminates
at a relay you don't control, exposes everything but chat bodies.

**Report addresses honestly and late.** The SDK derives the transport
*key* from the identity; only you know the *addresses* behind it. A
ticket assembled before STUN reports a public address carries LAN
addresses only — undialable from any other network, and it presents as
NAT traversal failing. `refreshAddresses()` re-reads your snapshot;
`getTicket()` is synchronous and serves the last one.

### What you give up

One pipe carries every RFC 001 §6 sub-stream, so priority weakens
from QUIC stream scheduling to send-queue ordering: urgent frames jump
the queue, but a frame already handed to you finishes first. Bounded by
the frame ceiling rather than a stall. `IrohTransport` keeps the
stronger guarantee wherever it can run.

---

## Browser builds differ

`/transport` and `/zk` resolve to different entries in a browser. These
are stubs that throw, because a browser cannot open a QUIC socket, join
a multicast group, or accept an inbound connection at all:

- `IrohTransport`
- `MdnsDiscovery` and the datagram sockets
- the filesystem ZK artifact loaders

`WebSocketTransport` and `createBridgedTransport` are exported
unchanged, and are how a browser or webview participates.

---

## Zero-knowledge

`snarkjs` is an **optional peer dependency** — install it only if you
generate or verify proofs. Omitting it keeps a transitive advisory out
of your tree, and the SDK says so plainly if you reach a proving path
without it.

Circuit artifacts are loaded from the filesystem, so proving is
Node-only today. In a browser `resolveArtifacts()` returns `null`.

Proving keys come from a six-contributor Phase 2 ceremony sealed with
the hash of Bitcoin block 962000 —
[every contribution hash, the beacon commitment, and the verification
transcript](https://github.com/mrsarthi/Ceremonial-Contributions).

---

## Know before you ship

**`WebSocketTransport` does not hide traffic from the relay.** Chat
bodies are sealed before reaching it, but CRDT sync, revocation gossip,
and voucher traffic cross in the clear — so a relay operator can
reconstruct the membership graph and read history replicated through
sync. A known gap, not a design decision. `IrohTransport` and a bridged
transport over an encrypted channel have no such intermediary.

**`IConnection` gained `onClose` in 0.7.0.** Only relevant if you
implement the interface directly — `createBridgedTransport` provides it.
It must fire once when the connection ends, from either side, and fire
immediately if attached to one that has already closed. Presence built on
connection events alone would otherwise switch on and never off.

**Stream types now run `0x01`–`0x09`**, having gained ephemeral signals,
peer profiles and blob transfer. If your transport enumerates them,
derive the list from `StreamType` rather than writing it out: a
hand-maintained one silently stops covering a stream the day another is
added, and the failure appears only at runtime, on the first send.

---

## More

- [How to use Dicsussion](https://github.com/mrsarthi/DicsussionProtocol/blob/main/HOW_TO_USE.md)
- [RFC 001 — Transport & Discovery](https://github.com/mrsarthi/DicsussionProtocol/blob/main/specs/RFC_001-Transport-&-Discovery.md)
- [RFC 003 — Security Envelope & ZK-RLN](https://github.com/mrsarthi/DicsussionProtocol/blob/main/specs/RFC_003-Security-Envelope.md)

Apache-2.0
