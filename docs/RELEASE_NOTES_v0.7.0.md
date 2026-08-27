# GitHub Release — v0.7.0

Paste the body below into the release form. Tag `v0.7.0` on the head of `main`.

---

**Release title:** `v0.7.0 — presence, profiles and files`

---

## Body

Three things every chat needs that a message is the wrong shape for.
Additive: nothing in 0.6.0 changes behaviour.

```bash
npm install @dicsussion/sdk@0.7.0
```

- [`@dicsussion/core@0.7.0`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.7.0`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Signals that should not be stored — Stream `0x07`

Presence, typing indicators and read receipts are true only while both
peers are connected, and misleading afterwards.

```ts
await client.chat.sendEphemeral(channelId, payload);   // → peers reached
client.chat.onEphemeral(channelId, (fromDid, payload) => {});
client.onPeerDisconnected.on('peer', ({ peerDid, at }) => {});
```

They could already be built on `sendMessage`, and that is the trap: a
thirty-second heartbeat is a few thousand permanent entries per
conversation per day, on every participant's device, replicated and
written to disk, for signals nobody will ever read back.

Encrypted and membership-gated exactly like a chat message — "X is
typing" is still a disclosure — with none of `sendMessage`'s other
guarantees: **not stored, not queued, not retried, not replayed.**
Returns how many peers received it, and **zero is normal**.

`onPeerDisconnected` is the half that makes presence honest. A green dot
driven by `onPeerConnected` alone switches on and never off, and would
show "online" for someone who closed their app hours ago.

### Names and pictures — Stream `0x08`

```ts
await client.identity.setMyProfile({ displayName: 'Alice', bio: 'Hi' });
client.identity.getPeerProfile(theirDid);
client.identity.onPeerProfile((did, profile) => {});
```

A single-writer mutable record, not a message: a new picture replaces the
old rather than joining a list. Sent as specially-tagged chat it would
have to be filtered out of every view forever, any client not knowing the
convention would render the tag as text, and each avatar would sit in
message history permanently on both devices.

**Paired peers only, in both directions.** A ticket is shareable, so
dialling one is not consent to learn who is behind it. Accepting a peer
who is already connected delivers the profile without a redial.

The 256KB avatar cap is enforced on receive as well as send — a peer
running a modified build does not get to write a 12MB row into your
database. A frame is ignored unless strictly newer, so a replayed one
cannot revert someone's name.

The display name is deliberately **not** authoritative: it is what that
person calls themselves, not what your user calls them. If your app keeps
local nicknames, prefer them.

### Images and files — Stream `0x09`

```ts
const ref = await client.blobs.put(bytes, 'image/png');   // 64MB cap
await client.chat.sendMessage({ channelId, content: 'look', attachments: [ref] });

const fetched = await client.blobs.get(ref);
client.blobs.onProgress(ref, (received, total) => {});
```

The message carries only a handle — a hash, a size, a media type. Bytes
move when a recipient asks, so an attachment nobody opens never crosses
the wire. Base64 in a message body is the alternative: a third larger
than the file, permanent in the conversation document, loaded whole into
memory on both sides, and impossible to delete afterwards.

Blobs are named by the hash of their content, so the same file is stored
once however often it arrives and what arrives is checked against what
was requested. An interrupted transfer resumes from where it stopped.

Any paired peer holding the bytes may serve them, not only the sender —
in a group the first person to open a picture becomes a second source,
which matters because the sender is frequently offline. A partial copy is
never served on, since a truncated transfer is indistinguishable to the
requester from a complete one.

**Failures are distinguishable on purpose**, because "could not attach
that" is not something an app can put in front of a person:
`BlobTooLargeError`, `BlobUnavailableError`, `BlobCorruptError`.

Blobs are **not** garbage collected when the message referencing them is
gone. A peer that has not synchronised yet holds references this device
cannot see, so collecting on their behalf would discard data still in
use. Call `blobs.delete(ref)` when you mean it.

### Also in this release

**Sub-stream negotiation.** `HandshakeInit` now announces how many
sub-streams the initiator will open, and the responder accepts exactly
that many. Previously the count was fixed, so a peer that knew about a
stream type its counterpart did not would wait forever for a stream never
opened — `acceptBi()` is untimed, so it never surfaced the connection
while the initiator completed its handshake and believed the peer was
reachable. Traffic then disappeared with no error on either side. An
initiator that omits the field is read as opening the six types that
existed before it (RFC 001 §5, constraint 5).

**Attachment handles are validated on arrival.** Handles are written into
the conversation document, so a hash that is not a hash, or an absurd
number of them, is dropped — costing the picture, not the message it
came with.

### Compatibility

Additive on the SDK surface. `IConnection` gains a required `onClose`
member, which is breaking only for code implementing that interface
directly; applications using `DicsussionClient` are unaffected.

An existing SQLite database migrates automatically (schema version 6).
Browser installs move to IndexedDB schema version 2, which creates the
two new object stores on first open.

### Verification

602 tests passing, 0 failing. Typecheck, build and `npm audit` clean.

Checked from freshly-packed tarballs rather than the repository: a
consumer typecheck with `skipLibCheck: false`, and all three new streams
exercised end-to-end **over real QUIC** — including a multi-chunk blob
transfer — because the in-process transport opens sub-streams on demand
and has hidden a real bug before.

### Known limits, unchanged

- No relay server ships, so no offline delivery to a sleeping device
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session, not per-message
- One device per identity
