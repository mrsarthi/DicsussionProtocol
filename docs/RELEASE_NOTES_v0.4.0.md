# GitHub Release — v0.4.0

Paste the body below into the release form. Tag `v0.4.0` on the head of `main`.

---

**Release title:** `v0.4.0 — group messaging, and conversations that stay private`

---

## Body

Three defects in how conversations are stored, shared, and propagated.
One of them disclosed private chats to the wrong people, one silently
deleted messages, and one prevented groups from working at all.

**This release requires a change to calling code.** See *Upgrading*.

```bash
npm install @dicsussion/sdk@0.4.0
```

- [`@dicsussion/core@0.4.0`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.4.0`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Your contacts could read your other conversations

A node handed every conversation it held to any paired peer, in readable
text, backdated to before that peer was added. With two contacts, each
received the other's chats. Strangers were unaffected throughout, which
is what made it easy to miss: the boundary that failed was the one
between people you trust.

There were two paths, not one. Synchronisation offered every document to
any paired peer; separately, publishing fanned every message out to every
paired peer whatever conversation it belonged to. The second delivered
the message before synchronisation even ran.

Conversations now carry a participant list, and both paths consult it.
The list lives in the document, so it survives a device replacement
alongside the history it governs.

### Concurrent messages were silently deleted

Each device created its own copy of a conversation, so the two had no
shared history. Merging them was a conflict over the container rather
than the contents: one copy's message map won, and everything written
into the other disappeared.

It never repaired itself. The winner is deterministic, so every replica
converged on the same truncated conversation, their state roots then
matched, and synchronisation reported everyone up to date indefinitely.

Documents now begin from byte-identical genesis derived from the channel
id, so concurrent messages land side by side.

### Groups did not work

Reconciliation ran once, when a connection opened, so a message never
travelled beyond the peers the sender was directly connected to. Three
people in a star — two connected to a middle node, not to each other —
held three different conversations permanently.

Every local change is now relayed onward, including changes that merely
arrived. Groups converge without being a full mesh, which matters because
they rarely are.

### Upgrading

**Conversations must declare who they are for.** This is the breaking
change, and code that worked on 0.3.2 will deliver nothing until it is
made:

```ts
client.chat.createChannel(channelId, [theirDid]);
// or when sending the first message in a channel:
await client.chat.sendMessage({ channelId, content, participants: [theirDid] });
```

Pairing is no longer sufficient on its own. It authorises a peer; the
participant list authorises a conversation. Admitting someone to a chat
you already have is an explicit call, not a side effect of adding them as
a contact.

A send to an undeclared channel still succeeds, appears in your history
and queues — but reaches nobody. That is deliberate. The alternative,
which the first attempt at this fix actually implemented, was to default
to sharing with everyone you were paired with; it recreated the
disclosure as soon as a user had two contacts, and its own test caught
it. The SDK cannot infer who a conversation is for, so it does not guess.

`SessionManager.publish` and `ChatServiceDeps.publish` return
`Promise<number>` — the count of peers reached. `SessionManagerDeps` and
`ChatServiceDeps` both gained members. These are internal wiring seams
that an application using `DicsussionClient` does not touch.

### Also fixed

- **A message can now arrive twice**, directly and via a relay. Both are
  legitimate; your application is told once.
- **The dialer reused a recycled connection id without resetting**, the
  mirror of a bug already fixed on the accepting side. It surfaced as a
  nonsense control-message length rather than as reuse.
- **A node's own messages no longer appear to arrive from outside** on
  the first reconciliation with a peer.

### Documentation

`HOW_TO_USE.md` gains two sections — the guest list, and how messages
travel in a group. RFC 002 gains deterministic genesis, participants, and
continuous reconciliation; RFC 004 gains conversation membership and
delivery scope. All four are normative, so the behaviour is specified
rather than merely implemented.

### Verified

546 tests, three consecutive clean runs. New suites cover conversation
isolation, star-topology propagation, simultaneous writes from every
participant, and order agreement across replicas — convergence alone is
not enough, since two people reading the same group must see the same
thread.

### Credit

The disclosure and the delivery bug behind it were reported by the agent
building EchoIt against this SDK, from observed behaviour rather than
from reading the code. Both reports were right about the cause; both were
incomplete in ways that turned out to matter, and chasing the difference
is what found the second leak path and the missing relay.
