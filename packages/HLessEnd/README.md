# @dicsussion/sdk

Local-first, end-to-end encrypted, peer-to-peer messaging engine.

Headless: no UI, no server, no account. Identities are Ed25519 keypairs
generated on the device, messages are stored locally, and peers talk
directly over QUIC where the network allows it.

```bash
npm install @dicsussion/sdk
```

Zero-knowledge proving is opt-in — `snarkjs` is an optional peer
dependency. Install it only if you turn proofs on.

---

## A first message

```ts
import { DicsussionClient } from '@dicsussion/sdk';

const alice = await DicsussionClient.init({ storagePath: ':memory:' });
const bob = await DicsussionClient.init({ storagePath: ':memory:' });

bob.chat.onMessage('general', (message) => console.log(message.content));

// 1. Pair, both ways — who each other is.
alice.addPeer(bob.did, bob.encryptionPublicKey);
bob.addPeer(alice.did, alice.encryptionPublicKey);

// 2. Say who the conversation is for.
alice.chat.createChannel('general', [bob.did]);
bob.chat.createChannel('general', [alice.did]);

// 3. Dial, once.
await alice.connect(bob.getTicket());

await alice.chat.sendMessage({ channelId: 'general', content: 'hello' });
```

All three steps matter. Skip the second and the message reaches nobody.

---

## Pairing is mutual, and failure is silent

The one thing to know before writing anything real.

A peer who has not registered your X25519 key **cannot decrypt what you
send, and drops it** — with no error on either side. Your send resolves.
Their inbox stays empty.

That is deliberate. A completed handshake proves the far side holds the
secret behind the `did:key` it claimed, and anyone can generate a fresh
keypair, so a stranger's handshake looks exactly like a friend's.
Pairing happens out of band and is the only thing separating them.

> **Pair in both directions. Dial in one.**

Dialling from both sides does not substitute for pairing from both
sides — it opens two connections for one peer pair.

Users exchange **tickets**, not raw keys, and a ticket carries the key:

```ts
import { decodeTicket } from '@dicsussion/core/transport';

const theirs = decodeTicket(pasted);
client.addPeer(theirs.didKey, theirs.encryptionKey!);
```

To surface a stranger who connects before you've paired them:

```ts
client.onPeerConnected.on('peer', ({ peerDid, paired, direction }) => {
  if (!paired && direction === 'inbound') {
    // Show a request. Call addPeer to accept — no redial needed.
  }
});
```

---

## Conversations have a guest list

Pairing says who a peer *is*. It does not say which conversations they
belong to — that is a separate list, kept per conversation, and a message
goes only to the people on it.

```ts
client.chat.createChannel('alice+bob', [bobDid]);
// or when sending the first message:
await client.chat.sendMessage({
  channelId: 'alice+bob',
  content: 'hello',
  participants: [bobDid],
});
```

**A channel with nobody on the list is shared with nobody.** The send
succeeds, appears in your own history, and queues — but nothing delivers
it. The SDK cannot infer who a conversation is for; only your application
knows that a chat opened from Bob's contact card is for Bob. Guessing is
how a contact ends up holding conversations they were never part of.

Pairing someone *later* does not admit them to existing conversations.
Call `createChannel` again — it is idempotent and keeps the current list.

## Groups

A group is a conversation with more than two people on its list; there is
no separate type.

Participants relay what they receive onward, so a message reaches people
the sender has no connection to — a group need not be a full mesh to
converge. Every device computes the same order from the messages
themselves, so everyone sees the same thread, and simultaneous messages
all survive because each occupies its own slot.

A message may arrive twice, directly and via a relay. You are told once.

## Storage and transport are chosen for the host

| Host | Storage | Transport |
| :--- | :--- | :--- |
| Node / desktop | default SQLite | `'iroh'` |
| Tauri, React Native, Electron | `IndexedDbDriver` | bridged (see below) |
| Browser | `IndexedDbDriver` | `'websocket'` ⚠️ |
| Tests | `':memory:'` | `'local'` (default) |

**Node:**

```ts
await DicsussionClient.init(
  { storagePath: './data.db', storageKey: process.env.DB_KEY },
  { transport: 'iroh' },
);
```

`storageKey` is required whenever `storagePath` names a real file —
without it, secret key material sits on disk in plaintext.

**Webview host.** `better-sqlite3` cannot load in a webview and a
webview cannot open a QUIC socket, so supply both seams:

```ts
import { DicsussionClient, IndexedDbDriver } from '@dicsussion/sdk/browser';
import { createBridgedTransport } from '@dicsussion/core/transport';

await DicsussionClient.init({}, {
  storage: new IndexedDbDriver(),
  transport: (identity) => createBridgedTransport(pipe, { identity }),
});
```

The transport arrives as a **factory** because it must authenticate as
this node, and the identity is derived during `init()` from a seed you
never hold. See [`@dicsussion/core`](https://www.npmjs.com/package/@dicsussion/core)
for writing the `pipe`.

---

## Everyday surface

```ts
client.did                       // did:key:z6Mk…
client.encryptionPublicKey       // X25519 public key
client.chat.createChannel(channelId, [theirDid])
client.getTicket()               // PeerTicket — see the ticket note below
client.addPeer(did, key)
await client.connect(ticket)

await client.chat.sendMessage({ channelId, content })
client.chat.onMessage(channelId, (message) => {})
await client.chat.getHistory(channelId)

client.getNetworkStatus()        // { connected, peerCount, relayActive, … }
client.onNetworkStatus.on('status', (s) => {})
await client.identity.exportMnemonic()
await client.disconnect()
```

Messages sent while a peer is unreachable are queued and flushed on
reconnect. A resolved `sendMessage` means *accepted locally*, not
*delivered*.

**Tickets need a moment.** Address discovery is not instant — a public
address arrives from STUN after the socket binds, a relay later still. A
ticket published before then carries LAN addresses only: fine on your
network, undialable from any other. Wait for `getTicket().derpRelay`
before handing it out.

---

## What this does not do yet

- No relay server ships, so no offline delivery to a sleeping device
- Forward secrecy is per-session, not per-message — no double ratchet
- One device per identity; no multi-device sync
- ZK proving is Node-only (artifacts load from the filesystem)
- Reputation tiers are not enforced in-circuit — do not gate on them

Identity recovery *is* supported: `exportMnemonic()` and
`recoverFromMnemonic()` restore the same `did:key` on a new device.

---

## More

- [How to use Dicsussion](https://github.com/mrsarthi/DicsussionProtocol/blob/main/HOW_TO_USE.md) — the full guide
- [RFC 004](https://github.com/mrsarthi/DicsussionProtocol/blob/main/specs/RFC_004-Headless-Backend.md) — SDK architecture
- [`@dicsussion/core`](https://www.npmjs.com/package/@dicsussion/core) — the engine underneath

Apache-2.0
