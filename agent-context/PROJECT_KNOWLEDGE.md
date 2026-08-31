# Dicsussion Protocol — everything an agent needs to know

*Written 2026-08-31, at v0.8.1. This is the working understanding built
over the whole project, not a summary of the code. The code says what it
does; this says **why**, what was tried and rejected, and what will bite
you.*

Read `PROGRESS.md` for the chronological record, `specs/` for the
normative spec, and `agent-context/AGENT_INSTRUCTIONS.md` for the master
prompt this was built against. Read this first, or you will re-derive decisions that
were already made carefully and re-introduce bugs that were already
found.

---

## 1. What this is, and what it is not

`@dicsussion/core` and `@dicsussion/sdk` are a **headless, local-first,
peer-to-peer, end-to-end encrypted messaging engine**. No UI, no server,
no account. Identities are Ed25519 keypairs generated on the device;
messages live in local storage; peers talk directly over QUIC.

It is a **library**, not an application. The consuming app is EchoIt
(`Dicsussion-Rewrite` / `Dicsussion`), built by a separate agent. The
protocol repo is owned here; the app repo is not.

**What it is not:** it is not a product, not a network, and not a service.
There is no relay server, no directory, no discovery beyond mDNS and
tickets. Anything requiring infrastructure does not exist yet.

---

## 2. The three ideas everything else follows from

### 2.1 Pairing is an authorization boundary

A completed handshake proves the far side holds the secret behind the
`did:key` it presented. **That is all it proves.** Anyone can generate a
fresh keypair, so a stranger's handshake is indistinguishable from a
friend's.

Therefore an unpaired peer gets **nothing**: no messages, no presence, no
profile, no blobs. `SessionManager.handleFrame` returns before every
stream for an unpaired peer. The single exception is `0x0A` (§5.10),
added deliberately and bounded tightly.

The failure mode is **silent** by design: a peer who has not registered
your X25519 key cannot decrypt what you send and drops it, with no error
on either side. Your send resolves. Their inbox stays empty. Every doc
says "pair in both directions, dial in one" because this has confused
people repeatedly.

### 2.2 Conversation membership is a *separate* authorization boundary

Pairing says who a peer **is**. It does not say which conversations they
belong to. That is a per-conversation guest list, and a message goes only
to people on it.

**The SDK never infers membership.** This was learned the hard way twice:

- **0.4.0** — publishing fanned messages to every paired peer regardless
  of channel. A contact received conversations they were never part of.
- **0.6.0** — a conversation created by an inbound message recorded its
  sender as a participant. So a paired peer could *guess a channel id*,
  send to it, write itself into the guest list, and receive everything
  afterwards. Reproduced before fixing. Channel ids are identifiers, not
  secrets.

An intermediate fix of "everyone currently paired" was written and then
rejected — it recreates 0.4.0. The rule is: **the application declares
membership, or the conversation is shared with nobody.**

### 2.3 A session key exists only while both peers are connected

Everything on the wire is sealed under the key agreed during the
handshake. With no peer there is no session, no key, and nothing that
could be stored. This is why offline delivery was not an unbuilt feature
until 0.8.0 — it was **outside the shape** of the existing streams. See
§5.11.

---

## 3. Architecture in one pass

```
packages/core     — engine: transport, crypto, CRDT, ZK
packages/HLessEnd — the SDK (published as @dicsussion/sdk)
specs/            — RFC 001–004, normative
docs/             — release notes, security backlog, capability matrix
tests/            — Playwright: e2e, sdk, transport, crdt, crypto,
                    storage, zk, wot, plus harness/
```

The SDK package directory is named `HLessEnd` (headless end) — an
early name that stuck. It publishes as `@dicsussion/sdk`.

**Key modules in `packages/HLessEnd/src/`:**

| File | Holds |
| :--- | :--- |
| `client.ts` | `DicsussionClient` — the whole public surface |
| `session-manager.ts` | Connection registry and **all** stream routing |
| `chat-service.ts` | Messages, history, reactions, emit/dedup |
| `message-codec.ts` | The payload inside an envelope; `encodePayload` |
| `profile-service.ts` | `0x08` |
| `blob-service.ts` | `0x09` |
| `pairing-request.ts` | `0x0A` |
| `sealed-message.ts` | `0x0B` |
| `peer-registry.ts` | Who is paired, who is connected |
| `outbox.ts` | Queued sends, epoch helper |

---

## 4. Transports, and the single most important testing lesson

Three implementations of `ITransport`:

| Transport | Used for | Note |
| :--- | :--- | :--- |
| `LocalTransport` | Tests, default | In-process; **opens sub-streams on demand** |
| `IrohTransport` | Node/desktop/mobile | Real QUIC; **opens every sub-stream up front** |
| `WebSocketTransport` | Browser | Via a relay; see §7.2 |
| `createBridgedTransport` | Tauri/RN/Electron | Host supplies the bytes |

> ### The lesson, stated as bluntly as it deserves
>
> **`LocalTransport` has hidden a QUIC-only bug in three consecutive
> releases.** It opens sub-streams lazily and propagates close
> explicitly, so it cannot exhibit failures that real QUIC exhibits
> immediately.
>
> 1. **0.7.0** — `sendEphemeral` threw `Sub-stream 0x7 is not open` on
>    every real network while passing 8/8 in the SDK suite.
> 2. **0.7.0** — `attachments` was dropped by `encodePayload` while
>    every test passed, because the CRDT carried it separately.
> 3. **0.7.1** — `onPeerDisconnected` never fired on the *remote* side
>    over Iroh. Found only by testing the published package.
>
> **Anything touching the wire or connection lifecycle needs a test on
> `IrohTransport`, not only through `DicsussionClient`.** See
> `tests/e2e/suite-4.1-real-network.spec.ts`.

A second, related lesson: **verify the published package, not the repo.**
The 0.7.1 bug was found by installing from npm into a clean directory and
running it over QUIC. The suite was green.

---

## 5. The stream types, and why each exists

RFC 001 §6. `0x01`–`0x0B`. Adding one is cheap; the reasoning behind each
is not.

| ID | Stream | Why it is not something else |
| :--- | :--- | :--- |
| `0x01` | CRDT sync | Automerge state; how groups converge |
| `0x02` | E2EE envelopes | Ordinary chat |
| `0x03` | Revocation gossip | Unconditionally high priority |
| `0x04` | Voucher handshakes | Blind endorsement |
| `0x05` | RLN signal | Rate-limit nullifiers |
| `0x06` | RLN share exchange | Slashing |
| `0x07` | Ephemeral | §5.7 |
| `0x08` | Profiles | §5.8 |
| `0x09` | Blobs | §5.9 |
| `0x0A` | Pairing requests | §5.10 |
| `0x0B` | Sealed messages | §5.11 |

`0x07`–`0x0B` all reuse the `0x02` envelope via `sealOpaque`. That is
deliberate: otherwise a relay could tell a typing indicator, an avatar
and a sentence apart by frame shape alone without decrypting anything.

### 5.7 Ephemeral (`0x07`) — signals that must not be stored

Presence, typing, read receipts. True only while both peers are
connected, misleading afterwards.

They **could** have been built on `sendMessage`, and that is the trap: a
thirty-second heartbeat is a few thousand permanent CRDT entries per
conversation per day, on every device, for signals nobody will read back.

Deliberately none of `sendMessage`'s guarantees: **not stored, not
queued, not retried, not replayed.** Returns peers reached; **zero is
normal**. Payload is opaque bytes — giving it a schema would mean
revising the protocol every time an app invents a signal.

`onPeerDisconnected` is the half that makes presence honest. A dot driven
by `onPeerConnected` alone switches on and never off.

**Advise apps to prefer a heartbeat over connection events.** A peer can
be connected and idle, or drop in a way that takes time to notice.
Absence of a recent heartbeat fails in the safe direction.

### 5.8 Profiles (`0x08`) — mutable, single-writer

A name, bio and picture. Only the subject writes their own; a new version
**replaces** rather than joining a list.

Rejected alternative: specially-tagged chat messages. They would have to
be filtered from every view forever, any client not knowing the
convention renders the tag as text, and each avatar sits in message
history permanently on both devices.

- **256KB avatar cap, enforced on receive as well as send.** A peer on a
  modified build does not get to write a 12MB row into your database.
- **Paired peers only, both directions.** A ticket is shareable; dialling
  one is not consent to learn who is behind it.
- **Ignored unless strictly newer**, so a replayed frame cannot revert a
  name. `updatedAt` is the author's clock and orders only their own
  versions.
- **The display name is not authoritative.** It is what a peer calls
  *themselves*. A locally-typed nickname should win.
- **An empty `0x08` payload is a request** — "I have paired you, send
  yours". Added in 0.7.4; see §8.4 for the bug that forced it.

### 5.9 Blobs (`0x09`) — content-addressed, fetched on demand

Images and files travel outside the message, which carries only a
handle: SHA-256, size, media type.

Rejected alternative: base64 in the body — ~33% larger, permanent in the
CRDT, loaded whole into memory both sides, undeletable.

- **Nothing is sent until a recipient asks**, so an attachment nobody
  opens never crosses the wire.
- **Requests carry an offset**, so a transfer dying at 90% resumes.
- **Any paired peer holding the bytes may serve them.** In a group the
  first person to open a picture becomes a second source, which matters
  because the sender is frequently offline.
- **A partial copy is never served on** — truncated is indistinguishable
  from complete to the requester.
- **64MB cap**, three distinguishable errors (`BlobTooLargeError`,
  `BlobUnavailableError`, `BlobCorruptError`). "Could not attach that" is
  not something an app can say to a person.
- **No garbage collection**, decided rather than skipped: a peer that has
  not synced holds references this node cannot see.

### 5.10 Pairing requests (`0x0A`) — the one thing a stranger may send

**Why it had to exist.** The X25519 encryption key is derived under a
separate HKDF label (`dicsussion/identity/encryption/v1`) and **cannot be
recovered from the `did:key`**. Verified before building on it. So a node
receiving a stranger's connection knew exactly who was calling and could
neither encrypt for them nor dial back. Pasting a ticket was never a UX
choice — it was the only path.

The exception is bounded so it cannot become a channel:

- **One request per connection** (`SessionManager.requested`).
- **4KB cap** — parsing and storing it is the only work a stranger can
  cause.
- **The ticket must bind to the proven `did:key`.** Without this a peer
  could present a third party's ticket and have you register that party's
  key, or dial them, off a connection proving only its own identity.
- A ticket with no encryption key is dropped — it would produce an accept
  button that silently does nothing.

**What this gives up, deliberately.** RFC 001 §3.3 put pairing out of
band because a handshake proves key ownership, not that the owner is who
you meant to reach. In-band material does not weaken that — the
identifier is still proven, impersonation still impossible — but it
removes the out-of-band step where a human confirmed *which person* owns
a `did:key`. **Acceptance is now a judgement made on a self-asserted
name.** The SDK never pairs automatically and `displayName` is documented
as a claim everywhere it appears.

### 5.11 Sealed messages (`0x0B`) — for someone who is asleep

Sealed to the recipient's **long-term** X25519 key from their ticket,
which exists while they sleep — not to a session key. `crypto_box_seal`'s
construction: fresh ephemeral keypair, ECDH, AEAD, ephemeral public key
shipped alongside.

**Everything identifying is inside the ciphertext.** A store learns
neither sender, recipient, nor conversation. There is a test asserting
none of those strings appear in the bytes.

**The signature is not over the payload alone.** Signing only the payload
authenticates the author and still lets *the recipient* re-seal the
message to a third party where it verifies as genuinely yours. The
transcript covers sender, **recipient**, channel, id, time, payload and
this envelope's ephemeral key; the opener checks it names them. (A
signature over the ciphertext, as originally proposed, is circular.)

`encryptForPeer` could not be reused: it generates its own ephemeral
keypair and returns only the public half, but the transcript must name
the key of the envelope actually produced.

`openSealed` returns `undefined` — never throws — for every rejection: not
for us, bad signature, expired, future-dated, oversized, unpaired sender,
sender no longer in the conversation. A caller holding bytes from an
untrusted store cannot distinguish these, and a mix of throwing and
returning is impossible to handle correctly.

> **Sealed messages have no forward secrecy.** Encrypted to a key that
> does not rotate: if it leaks, every retained envelope opens, including
> old ones. Live `0x02` traffic is unaffected.
>
> The fix is X3DH one-time prekeys. **They were deliberately deferred**,
> and not merely for effort: a prekey batch needs somewhere to be
> *published* and a way to be *refilled*. No relay ships, so there is
> nowhere to put them. Building the harder half of X3DH against
> undecided infrastructure would mean redoing it.

---

## 6. Things that are not streams

### 6.1 Replies — `replyTo`, added 0.7.2

`readonly replyTo?: readonly string[]` on `SendMessageOptions` and
`SdkChatMessage`. Plural because a reply may answer several messages, and
widening a singular field later breaks every reader.

**Ids are carried, never resolved.** A reply legitimately arrives before
the message it answers, or names one this device never received. Dropping
an unresolved reference would silently turn a reply into an ordinary
message. Rendering is the app's decision.

Bounded on arrival: 32 references, each ≤256 chars.

### 6.2 Reactions — added 0.8.1

`react` / `unreact` / `getReactions` / `onReaction`. One mark per person
per message; reacting again **replaces**.

Not a message (three taps would be three permanent entries every client
must hide) and not ephemeral (still true tomorrow, must reach someone
offline). Lives in the conversation document, so sync, group relay and
offline convergence come free from `0x01`. **No new stream.**

> **The trap, and it is subtle.** The obvious design collects reactions
> into a nested `reactions` map. A nested map must be **created** before
> its first entry, and two replicas creating it concurrently produce
> conflicting assignments of the *whole map* — Automerge keeps one and
> the other person's reaction is lost. Two people reacting at once is
> ordinary traffic. A test caught this.
>
> Putting `reactions: {}` in deterministic genesis also fixes it **and
> changes the genesis bytes**, so nodes on either side of that change
> mint different genesis for the same channel and fail to merge at all.
>
> Reactions are therefore **top-level document keys** under a
> `reaction:` prefix, one per (message, author). Concurrent writers touch
> different keys; genesis does not move.

Withdrawal stores an empty string rather than deleting the key: a delete
racing a set resolves by actor order and can resurrect a removed
reaction.

Emoji length is capped; whether it *is* an emoji is not checked — which
sequences qualify moves with every Unicode release.

---

## 7. Known gaps, ranked by how much they matter

### 7.1 Relay transport encryption — the only open security hole

`WebSocketConnection` stores `sessionKey` and never uses it. A stream is
protected only if something above the transport already sealed it, so
`0x01` (CRDT sync — **message history and membership**), `0x03`, `0x04`,
`0x05` and `0x06` cross a relay **in the clear**. A relay operator can
reconstruct the membership graph and read history.

**Browser only.** Iroh/QUIC has no readable intermediary.

> **This matters right now**: a relay is being built on AWS. Two things
> get called "a relay" and they have opposite properties:
>
> - **A mailbox** holding `0x0B` envelopes is safe today. Opaque bytes;
>   the operator learns nothing and cannot open one.
> - **A transport relay** for the WebSocket path is the finding above.
>
> **Offline delivery needs only the mailbox.**
>
> **Addressing is deliberately unsolved.** An envelope names nobody, so a
> mailbox cannot tell who to hand it to. Routing on the recipient's
> `did:key` hands the operator the social graph — the thing sealing was
> for. A per-recipient random mailbox id, exchanged when peers pair, does
> not. The SDK does not choose; it belongs to the store's protocol.

### 7.2 Encryption at rest — closed in 0.8.1

Was deferred by explicit user decision, then requested and done. One
`storageKey` now seals message bodies, CRDT snapshots, **the outbox**,
blob bytes, and profile names, bios and avatars.

The outbox was not in the original finding and is where the first
implementation still leaked. It was caught by a test reading the **raw
database bytes**, WAL included — asserting through the SDK proves only
that a round trip works, which it would even with nothing encrypted.

**Still true:** a database written before 0.8.1 keeps its plaintext in
freed pages until reused. A key upgrades new writes, not old bytes. An
app with real history should start a fresh file.

### 7.3 Smaller, still open

- **No relay server ships.** Widest gap between the docs and what runs.
- **No forward secrecy for sealed messages** (§5.11).
- **Not test-covered:** a real pre-`subStreams` peer against a current
  one. Count invariants are tested; cross-version wire behaviour is not.
- Forward secrecy is per-session, not per-message — no double ratchet.
- One device per identity. Recovery works (`exportMnemonic` /
  `recoverFromMnemonic` restore the same `did:key`); multi-device sync
  does not exist.
- ZK proving is Node-only — artifacts load from the filesystem.
- **Reputation tiers are not enforced in-circuit.** `userScore` is a
  self-asserted private input. **Do not enable tiers without binding it
  in the circuit**, or quotas become forgeable 100×.
- `BridgePipe` confidentiality is the host's responsibility.

---

## 8. Bugs that were found, and how

Recorded because the *method* generalises, not for history's sake.

### 8.1 The sub-stream handshake could hang forever

`IrohTransport` accepted a **fixed number** of sub-streams. Adding `0x07`
meant a newer responder would wait forever for a stream an older
initiator never opens — `acceptBi()` is untimed and that path has no
handshake timeout. The connection is never surfaced while the initiator
completes its handshake and believes the peer reachable. **Traffic
disappears with no error on either side.**

Fixed by `HandshakeInit.subStreams`: the initiator announces how many it
will open; absence means the six that existed before the field. RFC 001
§5 constraint 5. `LEGACY_SUB_STREAM_COUNT` describes **software already
in the world** — tracking it to `SUB_STREAMS.length` restores the hang,
and there is a test saying so because the constant looks exactly like
something worth tidying.

### 8.2 Hand-maintained lists of stream types

Three separate places listed the six stream types by hand and silently
stopped covering new ones. All now derive from `StreamType`. **If you add
a stream type, derive; never list.**

### 8.3 `encodePayload` drops fields silently

It names its fields explicitly. A field added to `MessagePayload` and not
to the encoder **vanishes on the wire while every local test passes**,
because the CRDT carries it separately. This cost a debugging round with
`attachments`; for `replyTo` the envelope round-trip test was written
first and cost one test. **Write that test first.**

### 8.4 An accepted peer stayed nameless

A profile published while the peer still treated you as a stranger is
correctly dropped, and nothing resends it — you cannot learn you were
accepted. **My first fix was half a fix:** "answer a received profile
with your own" only works if the accepter *has* a profile. Silence is not
a signal. Hence the empty-payload request (§5.8).

### 8.5 A quadratic write, found by a slow test

Partial blob transfers were persisted on every chunk, each write
rewriting the whole accumulated buffer — some **8GB through the disk for
a 64MB blob**. Now checkpointed once, when a transfer gives up. Found
because three tests took a minute; the stall timeout is now a dep.

### 8.6 False alarms I raised, and the correction

Twice I reported a problem that was not real: a "bug in 0.4.0" that was a
**stale cached copy** in a scratch directory, and a "performance
regression" that was **machine load**. Both were corrected publicly after
checking properly.

**The habits that came out of it:** pre-flight in a directory that has
never seen an earlier version; download the registry tarball rather than
trusting a local extract; reproduce against the released commit before
blaming a change.

---

## 9. How work gets done here

### 9.1 The release ritual, in order

1. Build and run the **full** suite (currently 681 tests).
2. `npx tsc --noEmit` across the workspace.
3. Bump all three `package.json` files **and** the SDK's pin on
   `@dicsussion/core` — it is pinned exactly, not caret.
4. `npm install --package-lock-only`.
5. **Sweep the docs.** See §9.2.
6. `npm pack` both workspaces into a **virgin directory**, install the
   tarballs, and exercise the new surface — **over real QUIC** if it
   touches the wire.
7. Consumer typecheck with `skipLibCheck: false`.
8. Write `docs/RELEASE_NOTES_vX.Y.Z.md`.
9. Commit, tag `vX.Y.Z`, push both.
10. **The user publishes to npm.** Never publish.
11. Verify from the registry afterwards, in another virgin directory.
12. Post the GitHub release with `gh release create` when asked.

### 9.2 Doc files that go stale, and have

Sweeping is not optional — a pass once missed **seven files**. Check
every one:

| File | Goes stale when |
| :--- | :--- |
| `README.md` | Stream table, count, version banner |
| `HOW_TO_USE.md` | Section numbering, feature guidance |
| `packages/HLessEnd/README.md` | **Shipped to npm, immutable per version** |
| `packages/core/README.md` | **Also shipped.** Stream range — stale 3× |
| `specs/RFC_001` | Stream table, new `§6.x` |
| `specs/RFC_002` | Document schema |
| `specs/RFC_003` | Envelope reuse |
| `specs/RFC_004` | SDK surface |
| `docs/SECURITY_BACKLOG.md` | Relay exposure table |
| `docs/CAPABILITY_MATRIX.md` | Feature rows |
| `PROGRESS.md` | **Never forget this one** — explicit instruction |

npm always ships a package's own `README.md` regardless of `files`, and
**a version's README is immutable once published.** A wrong one is wrong
on that package page permanently. The root README is not shipped.

### 9.3 Standing instructions from the user

- **Do not call the Agent tool** unless explicitly requested. No
  workflows, no deep research.
- **Versions are the user's call.** Propose with reasoning; do not bump
  unilaterally. They have chosen patch where minor was suggested — at
  `0.x`, `^0.7.1` picks up `0.7.2` but not `0.8.0`, which they weigh.
- **Verify reports rather than taking them at face value.** Every claim
  the EchoIt agent has made was checked against the code first. They have
  all held so far, which is why the checking is cheap.
- **`macco`** is the user's multi-LLM analysis CLI, available for
  decisions or analysis worth a second opinion. Its citation gate has
  produced false negatives on dotted `Class.method` symbols.
- Report failures with the output. Never claim green without running it.

### 9.4 Writing style the user expects

Prose that explains **why**, not what. Comments earn their place by
recording a decision or a trap; no comment restates the line below it.
Tests are named as behaviours and carry the reason they exist. Docs state
limitations plainly rather than burying them — "the alternative is you
finding out later".

---

## 10. Release history, and what each was for

| Version | Date | For |
| :--- | :--- | :--- |
| 0.1.0–0.1.1 | Aug 11–12 | First publish; trusted setup ceremony |
| 0.2.0 | Aug 16 | Bridged transport, message boundaries |
| 0.3.0–0.3.2 | Aug 16–21 | Outbox durability; messages arriving by sync reach `onMessage` |
| 0.4.0 | Aug 23 | Groups; conversations stop leaking between contacts |
| 0.5.0 | Aug 24 | Removing a participant actually removes them |
| 0.6.0 | Aug 25 | **Channel ids are not secrets** — confidentiality fix |
| 0.7.0 | Aug 27 | Ephemeral, profiles, blobs |
| 0.7.1 | Aug 27 | Presence went dark on the wrong side |
| 0.7.2 | Aug 28 | `replyTo` |
| 0.7.3 | Aug 29 | Pairing requests — a stranger can knock |
| 0.7.4 | Aug 29 | A newly accepted contact has a face |
| 0.8.0 | Aug 29 | Sealed messages |
| 0.8.1 | Aug 31 | Reactions |

---

## 11. Facts about the world that shape decisions

- **There are no external users.** Verified: zero stars, forks or issues;
  58 unique cloners against **one** page view; no code on GitHub
  importing either package. ~1000 downloads a month, but superseded
  versions out-download the current one — scraper behaviour, not
  adoption.

  This is why breaking changes strand nobody and why Finding 11 could be
  deferred. **Re-check before assuming it still holds.**

- **`Dicsussion-Rewrite` has zero commits.** Flagged at every release
  since 0.2.0 — thirteen now. The protocol has been unblocked for all of
  them. Worth continuing to mention; not worth belabouring.

- **The proving key is real.** Output of a completed six-party trusted
  setup closed with a Bitcoin block hash committed publicly two days
  before that block was mined. Contribution hashes, beacon and transcript
  are published in a separate repo. Not a development ceremony.

- **A relay is being built on AWS**, as of 2026-08-31. See §7.1.

---

## 12. If you are picking this up

**Read in this order:** this file → `PROGRESS.md` current state →
`HOW_TO_USE.md` → the RFC for whatever you are touching.

**Before writing code:**

1. Is this a message, a signal, a document field, or a stream? Getting
   this wrong is the most expensive mistake available here — §5.7, §5.8
   and §6.2 are all records of choosing correctly after considering the
   cheap answer.
2. Does an unpaired peer get anything new? If so, justify it the way
   §5.10 does, and bound it.
3. Does it change the CRDT document? Then consider concurrent writers and
   whether genesis moves (§6.2).
4. Does it cross the wire? Then it needs a test on `IrohTransport` (§4),
   and if it adds a field to `MessagePayload`, an envelope round-trip
   test **first** (§8.3).

**Before saying it works:** run the full suite, pre-flight from tarballs
in a virgin directory, and — for anything on the wire — over real QUIC.
The suite has been green while the published package was broken.

---

*Everything here was true at v0.8.1 on 2026-08-31. Where this and the
code disagree, the code is right and this file is a bug.*
