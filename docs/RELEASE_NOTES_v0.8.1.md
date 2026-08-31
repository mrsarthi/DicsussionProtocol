# GitHub Release — v0.8.1

Paste the body below into the release form. Tag `v0.8.1` on the head of `main`.

---

**Release title:** `v0.8.1 — reactions`

---

## Body

Adds reactions. Additive: nothing in 0.8.0 changes behaviour, no wire
format moves, and `^0.8.0` picks this up without a manifest edit.

```bash
npm install @dicsussion/sdk@0.8.1
```

- [`@dicsussion/core@0.8.1`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.8.1`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Reacting

```ts
client.chat.react(channelId, messageId, '👍');   // set, or replace
client.chat.unreact(channelId, messageId);       // withdraw

client.chat.getReactions(channelId, messageId);
// → [{ emoji: '👍', count: 3, reactors: [...], mine: true }]

client.chat.onReaction(channelId, ({ messageId, authorDid, emoji, removed }) => {});
```

**One per person per message.** Reacting again replaces, so somebody who
taps 👍 then ❤️ then 😂 has left one mark rather than three.

`getReactions` returns groups ordered by count then emoji, so the same
set renders identically everywhere, and `mine` saves comparing DIDs.
`onReaction` fires for the local identity's own reactions as well as
remote ones, so a view can be drawn from one path rather than updated
locally and again on synchronisation.

### Why it is not a message

Carried as messages, three taps would be three permanent entries in the
conversation for one gesture, and every client would have to know to hide
them from the thread. Carried as ephemeral signals they would vanish on
restart and never reach anyone who was offline.

A reaction is neither: mutable, withdrawable, and still true tomorrow. It
lives in the conversation document as one slot per (message, author), so
synchronisation, group relay and offline convergence all come from the
existing `0x01` path. No new stream type, no wire format.

The emoji is a short opaque string, bounded by `MAX_REACTION_LENGTH`.
Whether it *is* an emoji is deliberately not checked: which sequences
qualify changes with each Unicode revision, and an application may want
something that is not one.

### A bug worth naming, because the obvious design has it

The first implementation collected reactions into a nested map. The test
where two people react to the same message failed — the second reactor
saw one reaction rather than two.

A nested map must be created before its first entry, and two replicas
creating it concurrently produce conflicting assignments of the **whole
map**: Automerge keeps one, and the other person's reaction is lost. Two
people reacting to the same message at once is ordinary traffic.

Placing the map in deterministic genesis also fixes it, and changes the
genesis bytes — so a node on 0.8.0 and one on a later version would mint
different genesis for the same channel and fail to merge at all.

Reactions are therefore stored at the top level of the document under a
`reaction:` prefix, one key per (message, author) pair. Concurrent
writers touch different keys, and nothing about genesis moves.

Withdrawal stores an empty string rather than deleting the key: a delete
racing a set resolves by actor order and can resurrect a reaction
somebody removed. Recorded in RFC 002 §3.1.

### Trust model, unchanged

A reaction is a claim by the `did:key` in its slot, carried in the
conversation document alongside the messages. Replicated CRDT changes are
not individually authenticated, so a reaction is exactly as trustworthy
as the messages around it — neither more nor less. Worth not presenting
one as verified attribution.

### Verification

681 tests passing, 0 failing. Typecheck, build and `npm audit` clean.
Checked from freshly-packed tarballs.

Nothing else iterates the document's top level — confirmed rather than
assumed, since adding keys to the root is exactly the kind of change that
surfaces somewhere unrelated.

### Known limits, unchanged

- No relay server ships; an envelope survives storage, nothing to store
  it in comes with the SDK
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session for live traffic, and absent for sealed
  messages
- One device per identity
