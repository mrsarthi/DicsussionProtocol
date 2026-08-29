# GitHub Release — v0.7.3

Paste the body below into the release form. Tag `v0.7.3` on the head of `main`.

---

**Release title:** `v0.7.3 — a stranger can knock`

---

## Body

Pairing no longer requires a human to copy a ticket between devices.
Additive: nothing in 0.7.2 changes behaviour, and `^0.7.2` picks this up
without a manifest edit.

```bash
npm install @dicsussion/sdk@0.7.3
```

- [`@dicsussion/core@0.7.3`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.7.3`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Why pasting was never a UX choice

The handshake proves the far side holds the secret behind the `did:key`
it presented, and discloses nothing else. It does **not** carry that
peer's X25519 encryption key — derived from their seed under a separate
HKDF label, so unrecoverable from the identifier — nor their addresses.

So a node receiving a connection from someone it had never met knew
exactly who was calling and could do nothing with it: nothing to encrypt
for, nowhere to dial back. `onPeerConnected` could surface a stranger and
the application still had to ask a person to paste a ticket, because that
was the only route the material had.

### Knocking

```ts
// Them, having dialled your ticket from a QR code or link:
await client.requestPairing(theirDid, { displayName: 'Alice' });

// You:
client.onPairingRequest.on('request', (request) => {
  request.peerDid;      // proven by the handshake
  request.ticket;       // theirs, bound to that did:key
  request.displayName;  // 'Alice' — a claim, nothing more

  client.acceptPairingRequest(request);   // or declinePairingRequest
});

// A knock can arrive before your interface is listening, and a peer
// only gets to send one:
client.pendingPairingRequests();
```

Accepting is `addPeer` with the ticket's key. Both sides are then paired,
and the connection already open starts working immediately — no redial.

### The only stream an unpaired peer may use

Stream `0x0A` is a deliberate exception to "a stranger sends nothing",
and it is bounded so it cannot become anything more:

- **One request per connection.** Not a channel.
- **4KB cap.** Parsing and storing it is the only work a stranger can
  cause.
- **The ticket must belong to the proven `did:key`.** Without this a peer
  could present a third party's ticket and have you register that party's
  encryption key — or dial them — off a connection proving only the
  sender's own identity.
- **A ticket without an encryption key is dropped**, rather than
  surfaced as an accept button that silently achieves nothing.
- Sealed under the session key, so a relay carrying the connection sees
  ciphertext rather than a name and a ticket.

Messages, presence, profiles and blobs all stay shut to an unpaired peer
before and after a knock, and a test asserts it.

### What this gives up, on purpose

RFC 001 §3.3 placed pairing out of band because a handshake proves key
ownership, not that the owner is who a user meant to reach. Carrying the
material in-band does not weaken that — the identifier is still proven,
and impersonation is still impossible.

What it removes is the out-of-band step in which a person confirmed which
human a `did:key` belongs to. **Accepting is now a judgement made on a
self-asserted name.** The SDK never pairs on its own, and `displayName`
is a claim wherever it appears. Render it as asserted rather than as
identity, and let a locally-typed nickname win afterwards.

Recorded in RFC 001 §6.4 rather than left implicit.

### Timing worth knowing

`requestPairing` sends a snapshot of how reachable you are, and it is
naturally called moments after connecting — when the least is known.
Address discovery is not instant, so a request sent too early carries LAN
addresses only: fine on the same network, undialable from anywhere else,
and it surfaces later as a contact who cannot be reached rather than as a
failed request. Wait for `getTicket().derpRelay` where crossing networks
matters.

### Verification

638 tests passing, 0 failing. Typecheck, build and `npm audit` clean.

Checked from freshly-packed tarballs and **over real QUIC**, including
that the delivered ticket carries working addresses — something the
in-process transport cannot show, and which has caught a real bug in
three consecutive releases.

### Known limits, unchanged

- No relay server ships, so no offline delivery to a sleeping device
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session, not per-message
- One device per identity
