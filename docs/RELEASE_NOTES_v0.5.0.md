# GitHub Release — v0.5.0

Paste the body below into the release form. Tag `v0.5.0` on the head of `main`.

---

**Release title:** `v0.5.0 — removing a participant actually removes them`

---

## Body

Blocking someone in an application was a local decision that never
reached the protocol. This release makes it real, and closes a gap in
0.4.0's own membership work.

```bash
npm install @dicsussion/sdk@0.5.0
```

- [`@dicsussion/core@0.5.0`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.5.0`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### You can now remove someone from a conversation

```ts
client.chat.removeParticipant(channelId, theirDid);
```

0.4.0 gave conversations a participant list but only ever added to it.
There was no way to take someone out, so an application's Block button
suppressed display and nothing else: the blocked peer kept receiving new
messages, and kept being able to write into shared documents.

Removal closes both directions. They are no longer sent messages, no
longer offered the document, and their own messages and pushes are
refused.

### The inbound half, which 0.4.0 missed

0.4.0 checked membership when *sending* and never when *receiving*. A
peer removed from a conversation could therefore keep writing into it
regardless — and that is precisely the half an application cannot fix for
itself, because replicated changes are not individually authenticated. A
local block suppresses display, not authorship.

**This is the behaviour change in the release.** Traffic that 0.4.0
accepted is now refused when the sender is not a participant of a
conversation this node already holds.

Inbound checking distinguishes *"not a participant"* from *"this node has
no such conversation"*, because they decide opposite things. A channel
absent locally has no participant list, so an unconditional check refuses
the first message of every new conversation a paired peer starts — which
the first implementation of this did, and its tests caught.

### Removal is not retroactive

Whatever a peer already received is on their device and stays there. No
messaging protocol can reach into another party's storage, and an
interface implying otherwise misleads the user about what was achieved.

The tests assert this explicitly rather than quietly, the guide says it,
and RFC 004 now requires implementations not to present removal as
though it undid the past. An application should tell users that blocking
stops what comes next.

### Ticket helpers are exported from the SDK

`encodeTicket`, `decodeTicket`, `TICKET_PREFIX` and `PeerTicket` are now
available from `@dicsussion/sdk` directly. `connect()` takes a
`PeerTicket` and every application has to move one between devices, so
needing a second package import to encode or decode one was friction with
no purpose.

### Upgrading

Nothing to change unless you relied on messages being accepted from peers
outside a conversation's participant list — which was the defect.

`@types/better-sqlite3` has been a declared dependency since 0.3.0, in
case an older tracking note still lists it as outstanding.

### A test rewritten rather than adjusted

The state-root check asserted a wall-clock budget while 500-odd other
tests ran alongside it, so it measured machine contention and passed or
failed by what else happened to be running. Raising the threshold would
have hidden the regressions it exists to catch, so it now compares two
document counts measured back to back — immune to machine speed, and
still failing an O(n²) root. Absolute conformance to the RFC's
millisecond budget belongs on target hardware, not in a suite running on
whatever machine is free.

### Verified

549 tests, zero failures. New coverage: removal stops delivery, removal
refuses the removed peer's writes, removal reports whether they were
there and is reversible, and a new conversation from a paired peer is
still accepted.
