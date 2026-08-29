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

// 1. Pairing — both directions. See section 3.
alice.addPeer(bob.did, bob.encryptionPublicKey);
bob.addPeer(alice.did, alice.encryptionPublicKey);

// 2. Say who the conversation is for. See section 4.
alice.chat.createChannel('general', [bob.did]);
bob.chat.createChannel('general', [alice.did]);

// 3. Dial — one direction only.
await alice.connect(bob.getTicket());

await alice.chat.sendMessage({ channelId: 'general', content: 'hello' });
```

**Three steps, and all three are load-bearing.** Pairing says who a peer
is. The channel says which conversations they belong to. Dialling opens
the connection. Skip the middle one and the message goes nowhere — see
the next two sections for why each exists.

`init()` defaults to the in-process `local` transport, which needs no
native module and no network. Section 9 covers real ones.

---

## 3. Pairing is mutual, and failure is silent

**This is the single thing to understand before anything else.**

A peer who has not registered your X25519 key cannot decrypt what you
send, and drops it. There is no error — not on your side, not on theirs.
Your send resolves cleanly. Their inbox stays empty.

That is deliberate. Completing a handshake proves only that the far side
holds the secret behind the `did:key` it asserted, and anyone can
generate a fresh keypair. A stranger's handshake is indistinguishable
from a friend's, so an explicit decision to pair is the only thing that
separates them.

That decision stays with a person. What changed in 0.7.3 is only how the
material reaches them — a peer can now send their own ticket rather than
a human copying it (see below) — not that anyone is paired without
someone choosing to.

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

### Knocking, so nobody has to paste a ticket

Pasting is not a UX choice — until 0.7.3 it was the only way. The
handshake proves a `did:key` and carries nothing else: not the peer's
encryption key, which is derived under a separate label and cannot be
computed from the identifier, and not their addresses. So a node that
receives a connection from a stranger knows exactly who is calling and
can neither encrypt for them nor dial them back.

A pairing request carries the material that closes that gap:

```ts
// Alice, having dialled Bob's ticket from a QR code or link:
await alice.connect(bob.getTicket());
await alice.requestPairing(bob.did, { displayName: 'Alice' });

// Bob:
bob.onPairingRequest.on('request', (request) => {
  // request.peerDid      — proven by the handshake
  // request.ticket       — hers, bound to that did:key
  // request.displayName  — 'Alice', and only a claim
  bob.acceptPairingRequest(request);   // or declinePairingRequest(request)
});
```

Accepting is `addPeer` with the ticket's key. Both sides are now paired —
Alice registered Bob by dialling his ticket, Bob registered Alice by
accepting — and the existing connection starts working immediately. No
redial.

A knock may arrive before your interface is listening, and a stranger
only gets to send one, so read the backlog too:

```ts
for (const request of client.pendingPairingRequests()) { /* show it */ }
```

**Send it when your ticket is ready.** `requestPairing` sends a snapshot
of how reachable you are, and it is naturally called moments after
connecting — when the least is known. Too early and it carries LAN
addresses only: fine on the same network, undialable from anywhere else,
and it surfaces later as a contact who cannot be reached rather than as a
failed request. Section 8 covers this; wait for `getTicket().derpRelay`
where crossing networks matters.

**This is the only thing an unpaired peer may send**, once per
connection. Messages, presence, profiles and blobs all stay shut to them
before and after knocking.

> **The name is a claim, and the accept button is why.** Their `did:key`
> is proven and their ticket is bound to it, so nobody can knock using
> someone else's. What no protocol can tell you is whether the person
> behind that identifier is who the name says. That judgement is the
> user's, so present the name as something asserted — and once they
> accept, a nickname your app stores locally should take precedence.

---

## 4. Every conversation has a guest list

**Pairing is not the same as belonging to a conversation.**

Pairing means "I know who you are and I'm willing to talk to you". It
says nothing about *which* conversations you are part of. A conversation
keeps its own list of participants, and a message is only sent to — and
only synchronised with — the people on it.

```ts
client.chat.createChannel('alice+bob', [bobDid]);
// or, on the first message:
await client.chat.sendMessage({
  channelId: 'alice+bob',
  content: 'hello',
  participants: [bobDid],
});
```

The local node is always included; you name everyone else.

**A conversation with nobody on the list is shared with nobody.** That is
deliberate, and it is the one behaviour most likely to surprise you: a
`sendMessage` to an undeclared channel succeeds, appears in your own
history, and reaches no one. It queues in the outbox rather than being
lost, but nothing will deliver it until the channel has participants.

The reason is that the SDK cannot work out who a conversation is for.
Only your application knows that a chat opened from Bob's contact card
is for Bob. An earlier version of this guessed — it shared new
conversations with everyone you were paired with — and the result was
that adding a second contact handed them the first one's history. So it
does not guess.

**`createChannel` states the whole membership.** Anyone recorded and not
named is removed. That is deliberate: a conversation can also come into
existence from an inbound message, which records its sender — so if
declaring "this chat is for Bob" merely *added* Bob, a peer who had
already written itself in by guessing the channel id would stay, and
receive everything sent afterwards. Channel ids travel in the clear and
are identifiers, not secrets.

### Adding someone later

Pairing a peer after a conversation exists does **not** admit them to it.

```ts
client.chat.addParticipant('the-group', theirDid);
```

Use `addParticipant` rather than re-declaring with `createChannel`, which
would remove everyone you did not repeat.

```ts
client.addPeer(carol.did, carol.encryptionPublicKey); // now a contact
client.chat.createChannel('the-group', [carol.did]);  // now in this chat
```

They receive the conversation from that point, including its history —
so admit people deliberately rather than as a side effect of pairing.

### Removing someone

```ts
client.chat.removeParticipant('the-group', theirDid);
```

They stop receiving new messages, stop being offered the conversation,
and **their own messages into it are refused**. That last part is the one
a Block button in your own app cannot do on its own: replicated changes
are not individually authenticated, so a peer still on the list can keep
writing into the shared document however your UI feels about them.

**It is not retroactive.** Whatever they already received is on their
device and stays there. No messaging system can reach into someone else's
storage — so tell your users that blocking stops what comes next, rather
than implying a conversation can be un-shared.

---

## 5. Groups, and how messages travel

A group is a conversation with more than two people on its guest list.
There is no separate group type for ordinary chat.

**Messages do not only travel directly.** Each participant relays what
they receive onward to the others, so a message reaches people the
sender has no connection to. If Alice and Carol are both connected to
Bob but not to each other, Alice's message still reaches Carol.

That matters because a group is rarely a full mesh in practice — phones
come and go, and NAT traversal fails for some pairs. Convergence does
not depend on everyone being reachable at once.

**Everyone sees the same conversation in the same order.** Order is
computed identically on every device from the messages themselves —
timestamp, then position, then id — so nobody is in charge and no
central server decides. Two people scrolling the same group see the same
thread.

**Simultaneous messages all survive.** Each message occupies its own slot
keyed by its id, so two people typing at the same moment cannot overwrite
one another. This is the property a CRDT is chosen for.

A message may reach a device twice — directly and again via a relay. The
SDK tells your application once.

---

## 6. Signals that should not be stored

Presence, typing indicators and read receipts share a shape: true only
while both people are connected, and misleading afterwards.

Sending them as ordinary messages works and is a trap. A heartbeat every
thirty seconds is a few thousand permanent entries per conversation per
day, on every participant's device, replicated and written to disk — for
signals nobody will ever want to read back.

```ts
// Delivered now, or not at all.
await client.chat.sendEphemeral('the-group', new TextEncoder().encode('typing'));

client.chat.onEphemeral('the-group', (fromDid, payload) => {
  console.log(fromDid, new TextDecoder().decode(payload));
});
```

Deliberately none of `sendMessage`'s guarantees: **not stored, not
queued, not retried, not replayed** to someone who reconnects. It returns
how many peers received it, and **zero is normal** — it means nobody was
connected, not that anything failed.

The payload is opaque bytes. What a signal means is your decision; the
protocol carries it without inspecting it. It is encrypted and gated by
conversation membership exactly like a message, because "X is typing" is
still a disclosure.

### Knowing when someone leaves

```ts
client.onPeerConnected.on('peer', ({ peerDid }) => { /* … */ });
client.onPeerDisconnected.on('peer', ({ peerDid, at }) => { /* … */ });
```

Both halves matter. A green dot driven by connection alone switches on
and never off — it would show "online" for someone who closed the app
hours ago.

For presence, prefer a periodic ephemeral heartbeat over the connection
events alone: a peer can be connected and idle, or their connection can
drop in a way that takes time to notice. Absence of a recent heartbeat is
the more honest signal, and it fails in the safe direction — reporting
someone as away when they are present, rather than present when they are
gone.

---

## 7. Names, pictures, and files

### What a person calls themselves

Until you set one, a contact's name is whatever **you** typed when you
added them. The other person has no way to tell you what they are called.

```ts
await client.identity.setMyProfile({ displayName: 'Alice', bio: 'Hi' });
await client.identity.setMyProfile({
  avatar: { mime: 'image/png', bytes },   // 256KB cap
});

client.identity.getPeerProfile(theirDid);
client.identity.onPeerProfile((did, profile) => { /* redraw */ });
```

Omitted fields are kept, so setting a bio does not erase a picture; pass
`null` to clear one. A profile is one current value, not a history —
updating a picture replaces it.

Paired peers only, in both directions. A ticket is shareable, so someone
who dials one has not thereby earned your name and face. Accepting a
peer who is already connected delivers it immediately; no redial.

> **The name is theirs, not yours.** It is what that person calls
> themselves. If your app lets a user rename a contact, that name should
> win — otherwise anyone can change what they are called in someone
> else's contact list.

### Images and files

```ts
const ref = await client.blobs.put(bytes, 'image/png');   // 64MB cap

await client.chat.sendMessage({
  channelId: 'the-group',
  content: 'look at this',
  attachments: [ref],
});
```

The message carries a **handle** — a hash, a size, a media type — and
nothing else. The bytes stay put until someone asks:

```ts
client.chat.onMessage('the-group', async (message) => {
  for (const ref of message.attachments ?? []) {
    const bytes = await client.blobs.get(ref);
  }
});
```

The alternative is base64 in the message body, which is a third larger
than the file, enters the conversation document permanently, loads whole
into memory on both sides, and cannot be deleted afterwards. A handful of
phone photos would outweigh every sentence in a conversation, forever.

Blobs are named by the hash of their content. The same file is stored
once however many times it arrives, and a recipient can tell whether what
arrived is what was sent. Anyone connected who has the bytes can serve
them — in a group the first person to open a picture becomes a second
source, which matters because the person who sent it is frequently
offline.

```ts
client.blobs.onProgress(ref, (received, total) => { /* a bar */ });
```

An interrupted transfer resumes from where it stopped rather than
starting again.

**Failures are distinguishable on purpose.** "Could not attach that" is
not something an app can put in front of a person:

| Error | What happened | What to say |
| :--- | :--- | :--- |
| `BlobTooLargeError` | Over the 64MB cap | "That file is too big" |
| `BlobUnavailableError` | Nobody reachable has it | "Not available — try later" |
| `BlobCorruptError` | Bytes did not match the hash | "Download failed, retry" |

Blobs are **not** deleted when the message referencing them is. A peer
who has not synced yet holds references this device cannot see, so
deleting on their behalf would discard something still in use. Call
`client.blobs.delete(ref)` when you mean it.

---

## 8. Tickets are not ready the instant you have one

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

## 9. Choosing storage and transport

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

## 10. Sending and receiving

```ts
await client.chat.sendMessage({ channelId: 'general', content: 'hello' });

client.chat.onMessage('general', (message) => {
  message.content;    // string
  message.authorDid;  // undefined when sent anonymously
  message.timestamp;  // seconds
  message.replyTo;    // ids this answers, or undefined
});

const history = await client.chat.getHistory('general');
const status = client.getNetworkStatus(); // { connected, peerCount, relayActive, ... }

await client.disconnect();
```

Messages sent while a peer is unreachable are queued and flushed on
reconnect. A resolved `sendMessage` means *accepted locally*, not
*delivered* — see section 3 for why those differ more than usual here.

### Replying to a message

```ts
const question = await client.chat.sendMessage({
  channelId: 'general',
  content: 'what time?',
});

await client.chat.sendMessage({
  channelId: 'general',
  content: 'seven',
  replyTo: [question.id],
});
```

A field, not a marker inside `content`. Encoding the reference in the
body works and is a trap of the same shape as tagging profiles onto
chat: every client has to know the convention forever, any client that
does not renders it as literal text, and you cannot strip it from a
quoted excerpt without also stripping text a user typed.

It is an array because a reply may answer more than one message, and
because widening a singular field afterwards breaks every reader.

**Ids are carried, not resolved.** `replyTo` may name a message this
device does not hold — a reply legitimately arrives before the message
it answers, and a peer may be answering something from before you joined
the conversation. That is a rendering decision, not an error:

```ts
const history = await client.chat.getHistory('general');
const quoted = message.replyTo
  ?.map((id) => history.find((m) => m.id === id))
  .filter((m) => m !== undefined);
// quoted may be shorter than message.replyTo — show what you have.
```

---

## 11. Sending to someone who is asleep

Everything else in this guide is encrypted with a key that exists only
while both people are connected. So a message to someone who is offline
had nowhere to go — not because delivery was unbuilt, but because there
was no key to encrypt with and nothing to store.

A sealed message is encrypted to the long-term key their ticket already
carries, which exists whether or not they are awake.

```ts
const envelope = await client.sealForPeer(theirDid, {
  channelId: 'general',
  content: 'read this when you wake up',
});
```

`envelope` is opaque bytes. Put it anywhere — a file, a server you run, a
peer who happens to be reachable:

```ts
await client.deliverSealed(courierDid, envelope);
```

And on the other side, whenever it turns up:

```ts
const message = await client.openSealed(envelope);
```

That runs the same path a live message does, so it reaches `onMessage`,
appears in `getHistory`, and is de-duplicated by id. One that arrived
both by courier and over a connection is shown once.

### What it refuses, and why you do not have to check

`openSealed` returns `undefined` rather than throwing, for any of: not
addressed to you, not signed by whoever it claims, expired, oversized, or
from someone you have not paired. A caller holding raw bytes from an
untrusted store cannot make those checks itself, so the SDK makes all of
them.

Two are worth understanding:

- **Signed, not merely decryptable.** Decrypting proves only that
  something was sealed *to you*. Your key comes from a shareable ticket,
  so without a signature anyone who learned a mailbox address could write
  to it claiming to be anyone.
- **Bound to you specifically.** The signature names the recipient, so a
  message sealed to you cannot be re-sealed onward and still verify as
  its author's.

An envelope names nobody. Whoever stores it learns neither sender,
recipient, nor conversation.

> **The one real limitation.** Sealed messages have **no forward
> secrecy**. They are encrypted to a key that never rotates, so if that
> key ever leaks, every envelope an adversary kept opens — including ones
> stored months ago. Live traffic keeps its per-message secrecy and is
> unaffected.
>
> The fix is one-time prekeys, which need somewhere to publish a batch
> and a way to refill it. That waits on a relay existing. Until then:
> fine for delivery through something you control, worth thinking about
> before storing envelopes somewhere you do not.

### If you are running the store

Two very different things get called "a relay", and they have opposite
security properties. Decide which you are building before you build it.

**A mailbox for sealed envelopes** holds `0x0B` bytes for a recipient who
is offline. It is safe today. An envelope is opaque: the operator learns
neither sender, recipient, nor conversation, and cannot open one no
matter who runs the machine. What it needs is unglamorous — accept bytes
up to the size cap, hold them, hand them over, drop them when they
expire. Matching `DEFAULT_MAX_AGE_S` (7 days) means nothing is retained
past the point the SDK would refuse it anyway.

**A transport relay** carries live traffic for peers that cannot open
sockets — the `'websocket'` transport. It is **not** equivalent, and it
is where the known gap lives: `0x01` CRDT sync, `0x03` gossip, `0x04`
vouchers and the RLN streams cross it in the clear, so its operator can
reconstruct the membership graph and read message history. See
`docs/SECURITY_BACKLOG.md` §6. Running one is a decision to trust
whoever runs it.

**Addressing is not solved for you.** An envelope names nobody, which is
the point — and it means a mailbox cannot work out who to give it to. The
obvious fix, having the depositor supply the recipient's `did:key` as a
routing key, hands the operator the social graph: exactly what sealing
the envelope was for. A better shape is a per-recipient random mailbox
id, shared when peers pair and unlinkable to any identity, so the
operator sees opaque bytes arriving at an opaque address. The SDK does
not pick one, because the choice belongs to whatever protocol the store
speaks.

---

## 12. What this does not do yet

Stated plainly, because the alternative is you finding out later.

- **No relay server ships.** Section 11 gives you an envelope that
  survives being stored; nothing to store it in comes with the SDK, so
  delivery to a sleeping phone still needs somewhere to leave it.
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

## 13. Further reading

- [`packages/HLessEnd/README.md`](packages/HLessEnd/README.md) — SDK
- [`packages/core/README.md`](packages/core/README.md) — engine, custom transports
- [RFC 001](specs/RFC_001-Transport-&-Discovery.md) — transport, tickets, handshake
- [RFC 004](specs/RFC_004-Headless-Backend.md) — SDK architecture
- `npm run peer` — a full node with a terminal instead of a UI, for
  testing between real machines
