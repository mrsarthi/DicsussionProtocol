# How to use Dicsussion

A guide for building on `@dicsussion/sdk` and `@dicsussion/core`.

This is not an API reference — the TypeScript types carry that, and the
[RFCs](specs/) carry the protocol. This covers the things you cannot
discover by reading either: the shape of a working setup, and the
handful of behaviours that will otherwise cost you a day.

**Read section 3 before you write any code.** It is the one that catches
everyone, including both agents that built this project.

---

## 1. Which package

| You want to | Install |
| :--- | :--- |
| Build an app: chats, storage, identity | `@dicsussion/sdk` |
| Bring your own transport, or use one layer directly | `@dicsussion/core` |

The SDK depends on core, so installing the SDK gets you both. Reach for
core directly only when the SDK's seams aren't enough — most often to
supply a transport from a host the SDK cannot open sockets in.

```bash
npm install @dicsussion/sdk
```

**Zero-knowledge proving is opt-in.** `snarkjs` is an optional peer
dependency. Skip it unless you turn proofs on:

```bash
npm install snarkjs   # only if you need ZK proofs
```

---

## 2. A first message, end to end

Two nodes in one process, no network. Everything else in this guide is a
variation on this shape.

```ts
import { DicsussionClient } from '@dicsussion/sdk';

const alice = await DicsussionClient.init({ storagePath: ':memory:' });
const bob = await DicsussionClient.init({ storagePath: ':memory:' });

bob.chat.onMessage('general', (message) => {
  console.log(message.content); // "hello"
});

// Pairing — both directions. See section 3.
alice.addPeer(bob.did, bob.encryptionPublicKey);
bob.addPeer(alice.did, alice.encryptionPublicKey);

// Dial — one direction only.
await alice.connect(bob.getTicket());

await alice.chat.sendMessage({ channelId: 'general', content: 'hello' });
```

`init()` defaults to the in-process `local` transport, which needs no
native module and no network. Section 5 covers real ones.

---

## 3. Pairing is mutual, and failure is silent

**This is the single thing to understand before anything else.**

A peer who has not registered your X25519 key cannot decrypt what you
send, and drops it. There is no error — not on your side, not on theirs.
Your send resolves cleanly. Their inbox stays empty.

That is deliberate. Completing a handshake proves only that the far side
holds the secret behind the `did:key` it asserted, and anyone can
generate a fresh keypair. A stranger's handshake is indistinguishable
from a friend's, so pairing happens out of band and is the only thing
that separates them.

The consequence is a rule with two halves:

> **Pair in both directions. Dial in one.**

```ts
alice.addPeer(bob.did, bob.encryptionPublicKey);   // both
bob.addPeer(alice.did, alice.encryptionPublicKey); // sides

await alice.connect(bob.getTicket());              // one side
```

Dialling from both sides is not a substitute for pairing from both
sides. It opens two connections for one peer pair, and the session layer
expects one.

### Pairing from a ticket

`addPeer` takes a raw key, which no user ever sees. What a person can
paste or scan is a **ticket**, and it carries the key:

```ts
import { decodeTicket, encodeTicket } from '@dicsussion/core/transport';

const mine = encodeTicket(client.getTicket());  // send this to them

const theirs = decodeTicket(pastedString);
if (!theirs.encryptionKey) throw new Error('Ticket carries no encryption key');
client.addPeer(theirs.didKey, theirs.encryptionKey);
```

`connect(ticket)` registers the key too — but only on the dialling side,
which is exactly why the far side still needs its own `addPeer`.

### Accepting someone who connected first

Pairing after the fact repairs delivery on the connection that is
already open. No redial:

```ts
client.onPeerConnected.on('peer', ({ peerDid, paired, direction }) => {
  if (!paired && direction === 'inbound') {
    // A stranger completed a handshake. Show a request; call addPeer to accept.
  }
});
```

Messages sent before pairing are not replayed. They were dropped when
they arrived.

---

## 4. Tickets are not ready the instant you have one

A ticket carries the addresses a peer will dial. Discovery is not
instant: the socket binds immediately, but a public address arrives from
STUN some time later, and a relay is assigned later still.

Publish too early and the ticket holds LAN and link-local addresses
only. It works on your own network and is undialable from anywhere else
— which looks exactly like NAT traversal failing, and is not.

Wait for a relay before publishing:

```ts
for (let i = 0; i < 30; i++) {
  if (client.getTicket().derpRelay) break;
  await new Promise((r) => setTimeout(r, 500));
}
const ticket = encodeTicket(client.getTicket());
```

A settled ticket has both a public address and a relay URL:

```
directAddresses: ["203.0.113.9:31497", "192.168.1.186:49813", ...]
derpRelay:       "https://euc1-1.relay.n0.iroh.link./"
```

---

## 5. Choosing storage and transport

Both are chosen for the host you are running in. Getting either wrong
fails at startup, loudly, which is the easy case.

| Host | Storage | Transport |
| :--- | :--- | :--- |
| Node / desktop | default SQLite | `'iroh'` — real QUIC, direct with relay fallback |
| Tauri, React Native, Electron | `IndexedDbDriver` | bridged — your native socket |
| Browser | `IndexedDbDriver` | `'websocket'` — via a relay ⚠️ see §7 |
| Tests | `':memory:'` | `'local'` — in-process |

### Node

```ts
const client = await DicsussionClient.init(
  { storagePath: './data.db', storageKey: process.env.DB_KEY },
  { transport: 'iroh' },
);
```

`storageKey` is **required whenever `storagePath` names a real file** —
without it, secret key material sits on disk in plaintext and the SDK
warns on every start. Its provenance is yours to decide: an OS keychain,
a user passphrase, a hardware token.

### Webview host — Tauri, React Native, Electron

`better-sqlite3` is a native module that cannot load in a webview, and a
webview cannot open a QUIC socket. Supply both seams:

```ts
import { DicsussionClient, IndexedDbDriver } from '@dicsussion/sdk/browser';
import { createBridgedTransport } from '@dicsussion/core/transport';

const client = await DicsussionClient.init(
  {},
  {
    storage: new IndexedDbDriver(),
    transport: (identity) => createBridgedTransport(pipe, { identity }),
  },
);
```

Note the **factory**. A transport authenticates as the node, so it needs
the Ed25519 identity — and that is derived during `init()` from a seed
you never hold. The client hands it back through the factory. Deriving
it yourself would be worse than duplicated code: the transport public
key comes from the identity by one-way HKDF, so a transport that minted
its own would advertise an address no peer could dial.

Writing `pipe` is covered in
[`packages/core/README.md`](packages/core/README.md).

---

## 6. Sending and receiving

```ts
await client.chat.sendMessage({ channelId: 'general', content: 'hello' });

client.chat.onMessage('general', (message) => {
  message.content;    // string
  message.authorDid;  // undefined when sent anonymously
  message.timestamp;  // seconds
});

const history = await client.chat.getHistory('general');
const status = client.getNetworkStatus(); // { connected, peerCount, relayActive, ... }

await client.disconnect();
```

Messages sent while a peer is unreachable are queued and flushed on
reconnect. A resolved `sendMessage` means *accepted locally*, not
*delivered* — see section 3 for why those differ more than usual here.

---

## 7. What this does not do yet

Stated plainly, because the alternative is you finding out later.

- **No relay server ships.** The SDK speaks the relay protocol; no
  reference implementation exists. Offline delivery to a sleeping phone
  needs one.
- **`WebSocketTransport` does not hide traffic from the relay.** Chat
  bodies are sealed, but CRDT sync, revocation gossip, and voucher
  traffic cross a relay readable. A relay operator can reconstruct the
  membership graph and read message history replicated through sync.
  Tracked as a known gap, not a design decision. `IrohTransport` and the
  bridged transport have no such intermediary.
- **Forward secrecy is per-session, not per-message.** No double
  ratchet, so no post-compromise security.
- **One device per identity.** No multi-device sync.
- **ZK proving is Node-only.** Circuit artifacts are loaded from the
  filesystem, so proofs do not work in a webview yet.
- **Reputation tiers are not enforced in-circuit.** `userScore` is a
  self-asserted input. Do not gate anything on it.

Identity recovery *is* supported: `identity.exportMnemonic()` and
`recoverFromMnemonic()` restore the same `did:key` on a new device.

---

## 8. Further reading

- [`packages/HLessEnd/README.md`](packages/HLessEnd/README.md) — SDK
- [`packages/core/README.md`](packages/core/README.md) — engine, custom transports
- [RFC 001](specs/RFC_001-Transport-&-Discovery.md) — transport, tickets, handshake
- [RFC 004](specs/RFC_004-Headless-Backend.md) — SDK architecture
- `npm run peer` — a full node with a terminal instead of a UI, for
  testing between real machines
