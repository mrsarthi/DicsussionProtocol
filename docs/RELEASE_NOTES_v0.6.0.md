# GitHub Release — v0.6.0

Paste the body below into the release form. Tag `v0.6.0` on the head of `main`.

---

**Release title:** `v0.6.0 — channel ids are not secrets`

---

## Body

Fixes a confidentiality bug in 0.5.0 and earlier: a contact could join a
conversation it had no part in by guessing the channel id, and receive
everything sent there afterwards. **Upgrade.**

```bash
npm install @dicsussion/sdk@0.6.0
```

- [`@dicsussion/core@0.6.0`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.6.0`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Guessing a channel id was enough to join the conversation

Reproduced before fixing. Carol is paired with Alice but has nothing to
do with Alice's conversation with Bob. She guesses the channel id and
sends to it first:

```
carol is a participant of it : true
bob got it                   : [ 'squatting', 'SECRET-FOR-BOB' ]
CAROL got it                 : [ 'squatting', 'SECRET-FOR-BOB' ]
```

Carol received Alice's private message to Bob.

A conversation created by an inbound message recorded its sender as a
participant, so naming a channel was enough to be written into it.
Channel ids are chosen by applications and travel in the clear — they are
identifiers, not secrets — which made confidentiality depend on nobody
guessing one.

The cause was an inconsistency with the project's own rule. RFC 004
requires membership to be declared and never inferred; the code then
inferred it on every inbound message, including on conversations it
already held.

### Two changes, because one was not enough

**Inference is confined to creating a conversation in response to
someone.** That case is real: it records the sender so a reply has
somewhere to go, and removing it entirely would strand every new
conversation. Inferring on a conversation that already exists is what let
a peer write itself in.

**`createChannel` is now authoritative rather than additive.** Anyone
recorded and not named is removed. Without this the fix above is
insufficient, because a squatter recorded at creation survives the owner
declaring the real membership.

### Breaking: growing a conversation needs `addParticipant`

This is the reason for a minor rather than a patch. Under 0.5.0 this was
documented and legitimate:

```ts
client.chat.createChannel('team', [bob.did]);
client.chat.createChannel('team', [carol.did]);   // meant "and Carol"
```

Under 0.6.0 the second call **removes Bob**. Use:

```ts
client.chat.createChannel('team', [bob.did]);
client.chat.addParticipant('team', carol.did);
```

`createChannel` states the whole membership; `addParticipant` adds to it.
Declaring a conversation once with everyone in it — the common case — is
unaffected.

### Documentation corrected against the code

An audit cross-referencing the README, PROGRESS, the guide, the four RFCs
and the source found eleven claims the documentation made that the code
did not honour. All were verified against source; all were real. Three
actively misled:

- **Membership capacity** was published as 65,536. That is the depth-16
  tree's leaf count; the working cap is **4,096**, because a rebuild is
  O(N·D). A reader sizing a channel was wrong by 16×.
- **Eviction** was documented as LRU, and RFC 002 said nodes MUST use it.
  The code deliberately does not: last-activity is a local observation
  never committed, so two nodes with identical membership would evict
  different leaves and fork the root — at exactly the point the tree
  fills. The spec now requires the deterministic rule and says why.
- **Tier 3** was published as "Unrestricted" while the code caps it at
  **100 messages per epoch**. No code changed; the documentation was
  simply wrong, and anyone building rate-limit UX against it built
  against a number that never existed.

Also corrected: a test count frozen since the first milestone, a beacon
lead time rounded from 2d20h up to "three days" — overstating the
security window in the direction that flatters the project — two Poseidon
domain-separation tags RFC 003 never recorded, a source comment warning
about a divergence bug that deterministic eviction had already fixed, and
the README's own example, which omitted `createChannel` and would
therefore have delivered nothing since 0.4.0. It now runs; verified by
running it.

### Upgrading

Replace any `createChannel` call that meant "add someone" with
`addParticipant`. Nothing else changes.

### Verified

552 tests, zero failures, `npm audit` clean. New coverage: squatting a
channel id fails, a genuinely new conversation still works, and
`addParticipant` admits without erasing.
