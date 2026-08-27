# GitHub Release — v0.7.1

Paste the body below into the release form. Tag `v0.7.1` on the head of `main`.

---

**Release title:** `v0.7.1 — presence went dark on the wrong side`

---

## Body

Fixes a bug in 0.7.0: over `IrohTransport`, `onPeerDisconnected` fired
only for the peer that called `disconnect()`. The **remote** side — the
one that needs to know, and the whole reason the event exists — was never
told. **Upgrade if you use presence.**

```bash
npm install @dicsussion/sdk@0.7.1
```

- [`@dicsussion/core@0.7.1`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.7.1`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### A green dot that never went out

The symptom is the one 0.7.0 introduced `onPeerDisconnected` to prevent:
presence that switches on and never off. Someone who closed their app
stayed lit until the reading process exited.

Each sub-stream's read loop returns quietly when its stream ends, which
is right in isolation — a finished sync stream must not take chat down
with it. But when a peer actually leaves, *every* one of its streams
ends, and nothing was watching for that. The connection stayed in
`Active` indefinitely and `onClose` never fired.

Fixed by counting live read loops and treating zero as departure. One
stream ending is still not a departure; all of them ending is.

Nothing else changes. No API, no wire format, no storage.

### Why 0.7.0's testing missed it

`LocalTransport.close()` propagates the close to its peer explicitly —
added in 0.7.0 for exactly this reason — so both sides are notified on
the in-process transport, which is what the SDK tests use. The
release's QUIC checks covered ephemeral signals, profiles and blobs but
not disconnect; the disconnect check ran in-process. Each half was
covered and their intersection was not.

`tests/e2e/suite-4.1-real-network.spec.ts` now covers departure over real
QUIC, verified to fail against the unfixed build.

### Verification

605 tests passing, 0 failing. Typecheck, build and `npm audit` clean.
Checked against packages installed from the registry, over real QUIC.

### Known limits, unchanged

- No relay server ships, so no offline delivery to a sleeping device
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session, not per-message
- One device per identity
