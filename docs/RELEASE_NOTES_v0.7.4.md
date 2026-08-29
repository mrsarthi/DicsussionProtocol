# GitHub Release — v0.7.4

Paste the body below into the release form. Tag `v0.7.4` on the head of `main`.

---

**Release title:** `v0.7.4 — a newly accepted contact has a face`

---

## Body

Fixes a gap in 0.7.3: someone you accepted showed only the name they
typed into their request — no picture, no bio — until they happened to
edit their profile again. **Upgrade if you use pairing requests.**

```bash
npm install @dicsussion/sdk@0.7.4
```

- [`@dicsussion/core@0.7.4`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.7.4`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### A contact who arrived half-empty

Alice knocks on Bob. Her app sends her profile; Bob's app discards it,
correctly, because she is still a stranger. Bob accepts.

Nothing then tells Alice she was accepted, so nothing resends her
profile. Bob has a contact whose name came from the request itself and
whose picture never arrives — until Alice edits her profile for some
unrelated reason.

The rule was one-directional: *on accepting someone, send them yours*.
Nobody ever asked for theirs, and the accepted side had no way to learn
anything had changed.

An empty `0x08` payload is now a request — "I have paired you, send
yours" — sent on accepting a peer that is already connected.

### Why answering a profile with your own is not enough

That was the first attempt, and it closes the gap only when the
accepting side happens to have a profile. A node with none sends
nothing, so the peer it just accepted has nothing to answer. Silence is
not a signal. Bob having no profile is exactly the case that matters, and
it is now the case the tests cover.

The exchange is bounded to one offer per connection, cleared when the
connection ends. Both sides treat a received profile as evidence of
having been paired and reply in kind, so without that bound they answer
each other indefinitely.

### Scope

Pre-existing since 0.7.0 for any flow where a stranger connects and is
accepted later. 0.7.3 made that the ordinary path, which is what brought
it into view.

Nothing else changes: no API, no wire format, no storage. Messages,
presence, profiles and blobs were all unaffected — the symptom was
cosmetic, a contact card missing its picture.

### Verification

641 tests passing, 0 failing. Typecheck, build and `npm audit` clean.

Found by exercising the published 0.7.3 from the registry over real QUIC;
the suite passed and that did not. It was not a transport-shaped bug —
the flow had only ever been tested with the *accepting* side holding a
profile. There is now a test with the accepter holding none, over real
QUIC, and one asserting the exchange settles at a single event each way.

### Known limits, unchanged

- No relay server ships, so no offline delivery to a sleeping device
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session, not per-message
- One device per identity
