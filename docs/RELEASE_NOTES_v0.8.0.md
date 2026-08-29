# GitHub Release — v0.8.0

Paste the body below into the release form. Tag `v0.8.0` on the head of `main`.

---

**Release title:** `v0.8.0 — messages for someone who is asleep`

---

## Body

A message can now be sealed for a peer who is offline, stored by
something that cannot read it, and opened whenever it arrives. Additive:
nothing in 0.7.4 changes behaviour.

```bash
npm install @dicsussion/sdk@0.8.0
```

- [`@dicsussion/core@0.8.0`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.8.0`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Why this was not a small addition

Every stream until now seals under the session key agreed during the
handshake, and that key exists only while both peers are connected. With
nobody on the other end there is no session, no key, and nothing that
could be written down for later. Offline delivery was not an unbuilt
feature of `0x02` — it was outside its shape.

A ticket already publishes a static X25519 key, which exists whether or
not its owner is awake. Sealing to that is what makes an envelope
storable.

### The surface

```ts
const envelope = await client.sealForPeer(theirDid, {
  channelId: 'general',
  content: 'read this when you wake up',
});

// Opaque bytes. Hand them to anything — a mailbox, a file, a peer:
await client.deliverSealed(courierDid, envelope);

// On the other side, whenever it turns up:
await client.openSealed(envelope);   // → SdkChatMessage | undefined
```

Opening runs the same path as a live message: it reaches `onMessage`,
lands in history, and is de-duplicated by id, so one that arrived both by
courier and over a connection is surfaced once.

A courier need not be the recipient and cannot read what it carries.

### What an envelope gives away

Nothing. Sender, recipient, channel and content are all inside the
ciphertext; a store sees a version byte and noise. There is a test
asserting none of those strings appear in the bytes.

`crypto_box_seal`'s construction — a fresh ephemeral X25519 keypair per
message, ECDH against the recipient's static key, AEAD, and the ephemeral
public key shipped alongside so the recipient can repeat the agreement.

### What it refuses

`openSealed` returns `undefined` rather than throwing, for any of: not
addressed to you, not signed by whoever it claims, expired, dated in the
future, oversized, from an unpaired sender, or from someone no longer in
the conversation. A caller holding bytes from an untrusted store cannot
distinguish those itself, and a mix of throwing and returning would be
impossible to handle correctly.

Two are worth understanding:

- **Signed, not merely decryptable.** Decrypting proves only that
  something was sealed *to you*, and your key comes from a shareable
  ticket — so without a signature, anyone who learned a mailbox address
  could write to it as anyone.
- **Bound to you specifically.** The signature covers the recipient, so a
  message sealed to you cannot be re-sealed onward and still verify as
  its author's.

Age is bounded by the **lesser** of the sender's stated maximum and the
receiver's own limit, or a sender grants itself a century.

### The limitation, stated plainly

**Sealed messages have no forward secrecy.** They are encrypted to a key
that does not rotate, so if that key ever leaks, every envelope an
adversary retained opens — including ones stored months ago. Live traffic
on `0x02` is unaffected and keeps its per-session secrecy.

The remedy is X3DH one-time prekeys: a batch published in advance,
consumed once, the private half destroyed after use. That needs somewhere
to publish a batch and a way to refill it when exhausted, neither of
which exists while no relay is specified. This is what is implementable
now, and is expected to be superseded rather than extended.

Recorded in RFC 001 §6.5 rather than left implicit.

### If you are running a store

Two different things get called "a relay", with opposite properties.

A **mailbox** for `0x0B` envelopes is safe today: opaque bytes in, opaque
bytes out, and the operator learns nothing. Enforce the size cap and
expire at `DEFAULT_MAX_AGE_S`.

A **transport relay** for the `'websocket'` transport is not equivalent.
CRDT sync, gossip and voucher traffic cross it in the clear, so its
operator can reconstruct the membership graph and read message history —
a known gap, tracked in `docs/SECURITY_BACKLOG.md` §6. Offline delivery
needs only the mailbox.

**Addressing is deliberately unsolved.** An envelope names nobody, so a
mailbox cannot work out who to hand it to. Routing on the recipient's
`did:key` hands the operator the social graph, which is what sealing was
for; a per-recipient random mailbox id, exchanged when peers pair, does
not. The SDK does not choose, because the choice belongs to whatever
protocol the store speaks. Section 11 of `HOW_TO_USE.md` covers it.

### Verification

663 tests passing, 0 failing. Typecheck, build and `npm audit` clean.

Checked from freshly-packed tarballs and over real QUIC, including a
three-node case where sender and recipient never connect and a third peer
carries the envelope between them.

### Known limits, unchanged

- No relay server ships; an envelope survives storage, nothing to store
  it in comes with the SDK
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session for live traffic, and absent for sealed
  messages
- One device per identity
