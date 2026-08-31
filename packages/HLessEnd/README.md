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
keypair, so a stranger's handshake looks exactly like a friend's. An
explicit decision to pair is the only thing separating them, and it
stays with a person — a peer can send you their ticket (see below), but
never pair themselves.

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

### Knocking, so nobody pastes anything

`onPeerConnected` tells you *who* connected and nothing else. That is not
an oversight: the handshake proves a `did:key` and carries neither the
peer's encryption key — derived under a separate label, so unrecoverable
from the identifier — nor their addresses. You know exactly who is
calling and can neither encrypt for them nor dial them back.

A pairing request closes that gap:

```ts
// Them, after dialling your ticket:
await client.requestPairing(theirDid, { displayName: 'Alice' });

// You:
client.onPairingRequest.on('request', ({ peerDid, ticket, displayName }) => {
  // Show a knock. On accept:
  client.acceptPairingRequest(request);   // or declinePairingRequest
});

// A knock can land before your UI mounts, and they only get one:
client.pendingPairingRequests();
```

The request carries **their ticket**, so accepting needs nothing copied
by hand, and it is the only thing an unpaired peer may send — one per
connection, everything else still shut to them.

> **`displayName` is a claim.** Their `did:key` is proven and the ticket
> is bound to it, so nobody can knock using someone else's ticket. But
> the name is a string they chose. Show it as asserted, not as identity —
> deciding who that identifier really belongs to is the whole reason
> there is an accept button.

If your app keeps a local nickname, it should win from that point on.

Accepting also asks them for their profile, so a name and picture they
published while you still treated them as a stranger arrive on accept
rather than waiting until they next edit it.

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

`createChannel` states the **whole** membership — anyone not named is
removed. A conversation can also be created by an inbound message, which
records its sender, so an additive reading would let a peer who guessed
the channel id stay in it. Channel ids are identifiers, not secrets.

To admit someone to a conversation that already exists:

```ts
client.chat.addParticipant('the-group', theirDid);
```

To remove someone:

```ts
client.chat.removeParticipant('the-group', theirDid);
```

They stop receiving messages and their own writes into that conversation
are refused — which a local block cannot do, since replicated changes are
not individually authenticated. It is **not** retroactive: what they
already hold stays theirs.

## Groups

A group is a conversation with more than two people on its list; there is
no separate type.

Participants relay what they receive onward, so a message reaches people
the sender has no connection to — a group need not be a full mesh to
converge. Every device computes the same order from the messages
themselves, so everyone sees the same thread, and simultaneous messages
all survive because each occupies its own slot.

A message may arrive twice, directly and via a relay. You are told once.

## Signals that should not be stored

Presence, typing and read receipts are true only while both peers are
connected. Sent as ordinary messages they would grow the conversation
forever — a heartbeat every thirty seconds is thousands of permanent
entries per day, per device.

```ts
await client.chat.sendEphemeral(channelId, payload);   // Uint8Array
client.chat.onEphemeral(channelId, (fromDid, payload) => {});
```

Not stored, not queued, not retried, not replayed. Returns how many peers
received it; **zero is normal**, meaning nobody was connected. Encrypted
and gated by conversation membership like any message — "X is typing" is
still a disclosure.

Pair it with both connection events:

```ts
client.onPeerConnected.on('peer', ({ peerDid, paired, direction }) => {});
client.onPeerDisconnected.on('peer', ({ peerDid, at }) => {});
```

A green dot driven by connection alone switches on and never off.

## Replies

```ts
const question = await client.chat.sendMessage({ channelId, content: 'what time?' });
await client.chat.sendMessage({ channelId, content: 'seven', replyTo: [question.id] });
```

A field rather than a marker inside `content`. A marker is a convention
every client must know forever, renders as literal text in any that does
not, and cannot be stripped from a quoted excerpt without also stripping
text a user typed.

An array, because a reply may answer several messages and widening a
singular field later breaks every reader.

**Ids are carried, not resolved.** `replyTo` may name a message this
device does not hold — replies arrive out of order, and a peer may
answer something from before you joined. Resolve against `getHistory()`
and decide what to show when it is absent; a dangling reference is not
an error.

## Reactions

```ts
client.chat.react(channelId, messageId, '👍');   // set, or replace
client.chat.unreact(channelId, messageId);       // withdraw

client.chat.getReactions(channelId, messageId);
// → [{ emoji: '👍', count: 3, reactors: [...], mine: true }]

client.chat.onReaction(channelId, ({ messageId, authorDid, emoji, removed }) => {});
```

**One per person per message.** Reacting again replaces, so somebody who
taps three things in a row leaves one mark rather than three.

Not a message: carrying one as a message would append a permanent entry
every time somebody tapped and untapped, and every client would have to
know to hide them from the conversation. Not ephemeral either — unlike
typing, a reaction is still true tomorrow and has to reach someone who
was offline when it was made. It lives in the conversation document, so
it syncs, survives a restart, and reaches a group through the same relay
path as messages.

`emoji` is a short opaque string. The SDK does not check that it is an
emoji — which sequences count is a moving target, and an application may
want something else — only that it is at most `MAX_REACTION_LENGTH`.

`getReactions` returns groups ordered by count then emoji, so the same
set renders identically on every device, and `mine` saves comparing DIDs.

## Names and pictures

What a peer calls themselves, kept as one current value rather than a
history. Not a message: sent as tagged chat it would have to be filtered
out of every view forever, and each new avatar would sit in message
history permanently on both devices.

```ts
await client.identity.setMyProfile({ displayName: 'Alice', bio: 'Hi' });
await client.identity.setMyProfile({
  avatar: { mime: 'image/png', bytes },   // 256KB cap
});

client.identity.getPeerProfile(theirDid);          // PeerProfile | undefined
client.identity.onPeerProfile((did, profile) => {});
```

Omitted fields are kept; pass `null` to clear one. Paired peers only, in
both directions — a ticket is shareable, so dialling one is not consent
to learn who is on the other end. Reaches connected peers immediately and
the rest when they next connect.

**The name is theirs, not yours.** It is what that person calls
themselves, which is not necessarily what your user should see. If your
app keeps local nicknames, prefer them.

## Images and files

```ts
const ref = await client.blobs.put(bytes, 'image/png');   // 64MB cap
await client.chat.sendMessage({ channelId, content: 'look', attachments: [ref] });

// On the other side:
client.chat.onMessage(channelId, async (message) => {
  for (const ref of message.attachments ?? []) {
    const bytes = await client.blobs.get(ref);
  }
});
```

The message carries only a handle — a hash, a size, a media type. Bytes
move when someone asks, so an attachment nobody opens never crosses the
wire and never enters the conversation document. Base64 in a message body
is the alternative: a third larger, permanent, and loaded whole into
memory on both sides.

Blobs are named by the hash of their content, so the same file is stored
once however often it arrives, and what arrives is checked against what
was asked for. Anyone connected who has the bytes can serve them, which
matters because the original sender is often offline.

```ts
client.blobs.onProgress(ref, (received, total) => {});
await client.blobs.has(ref);
await client.blobs.delete(ref);
```

An interrupted transfer resumes from where it stopped. Failures are
distinguishable, because "could not attach that" is not something an app
can phrase for a person: `BlobTooLargeError`, `BlobUnavailableError`
(nobody reachable has it — retry later), `BlobCorruptError`.

Blobs are **not** deleted when the message referencing them is. A peer
who has not synced yet holds references this device cannot see.

## Sending to someone who is asleep

Everything else here is encrypted with a key that exists only while both
people are connected. That is why offline delivery was not merely
unbuilt: with nobody there, there is no key and nothing to store.

A sealed message is encrypted to the long-term key their ticket already
carries, which exists whether or not they are awake.

```ts
const envelope = await client.sealForPeer(theirDid, {
  channelId: 'general',
  content: 'read this when you wake up',
});

// Opaque bytes. Hand them to anything — a mailbox, a file, a peer:
await client.deliverSealed(courierDid, envelope);

// On the other side, whenever it arrives:
await client.openSealed(envelope);   // → SdkChatMessage | undefined
```

Opening runs the same path as a live message, so it reaches `onMessage`,
lands in history, and is de-duplicated by id — one that arrived both ways
is surfaced once.

An envelope names nobody. Whoever stores it learns neither the sender,
the recipient, nor the conversation. It refuses to open if it was not for
you, is not signed by who it claims, has expired, is oversized, or comes
from someone you have not paired.

A courier need not be the recipient, and cannot read what it carries.

> **Sealed messages have no forward secrecy.** They are encrypted to a
> key that does not rotate, so if it ever leaks, every envelope an
> adversary kept opens — including old ones. Live traffic is unaffected.
> The fix is one-time prekeys, which need a relay to publish and refill
> them; none ships yet. Worth knowing before you store envelopes
> anywhere you do not control.

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
client.chat.addParticipant(channelId, theirDid)
client.chat.removeParticipant(channelId, theirDid)
client.getTicket()               // PeerTicket — see the ticket note below
client.addPeer(did, key)
await client.connect(ticket)

await client.chat.sendMessage({ channelId, content, attachments, replyTo })
client.chat.onMessage(channelId, (message) => {})   // message.replyTo
await client.chat.sendEphemeral(channelId, payload)
client.chat.onEphemeral(channelId, (fromDid, payload) => {})
await client.chat.getHistory(channelId)
client.chat.react(channelId, messageId, emoji)
client.chat.unreact(channelId, messageId)
client.chat.getReactions(channelId, messageId)
client.chat.onReaction(channelId, (event) => {})

await client.blobs.put(bytes, mime)      // → BlobRef
await client.blobs.get(ref)              // → Uint8Array
client.blobs.onProgress(ref, (received, total) => {})

await client.requestPairing(theirDid, { displayName })
client.onPairingRequest.on('request', (request) => {})
client.pendingPairingRequests()
client.acceptPairingRequest(request)
client.declinePairingRequest(request)

await client.sealForPeer(theirDid, { channelId, content })
await client.openSealed(envelope)
await client.deliverSealed(peerDid, envelope)

client.getNetworkStatus()        // { connected, peerCount, relayActive, … }
client.onNetworkStatus.on('status', (s) => {})
client.onPeerDisconnected.on('peer', ({ peerDid, at }) => {})
await client.identity.setMyProfile({ displayName, bio, avatar })
client.identity.getPeerProfile(did)
client.identity.onPeerProfile((did, profile) => {})
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

- No relay server ships. `sealForPeer` produces an envelope that
  survives being stored, but nothing to store it in ships with the SDK
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
