# GitHub Release — v0.3.1

Paste the body below into the release form. Tag `v0.3.1` on the head of `main`.

---

**Release title:** `v0.3.1 — messages no longer vanish when a peer goes`

---

## Body

Fixes message loss when a connection dies. If you are on 0.3.0 or
earlier, upgrade.

```bash
npm install @dicsussion/sdk@0.3.1
```

- [`@dicsussion/core@0.3.1`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.3.1`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### What went wrong

`PeerRegistry` treated the *presence* of a connection object as
liveness — `connection !== undefined`. When a transport tore a
connection down it set `ConnectionState.Disconnected` and wiped the
session key, but the object stayed referenced, so the peer counted as
reachable indefinitely. `ConnectionState` was never read anywhere in the
SDK, and `detachConnection()` existed from the beginning and was never
called.

Everything downstream inherited that belief. `getNetworkStatus().connected`
stayed `true`, and `sendMessage` chose between publishing and queueing on
the strength of it — so it published into a dead connection and let the
resulting error escape. The message had already been written to local
history and the channel document, which is where the appearance of a
successful send came from. It was in no retry queue.

Worse, the condition was permanent. Because nothing ever detached, the
count stayed above zero for the life of the client, so every later send
took the same path and failed the same way. **The outbox — the machinery
built precisely for an unreachable peer — became unreachable itself.**

### The fixes

**Liveness is read from `ConnectionState`.** `connectedCount`,
`listConnected` and `isConnected` now require `Active`, so a dead
connection stops counting the moment the transport marks it closed.
`PeerRegistry.pruneDisconnected()` releases the objects and returns how
many it dropped.

**Sends are attempted, then queued on failure**, rather than decided in
advance. This is the fix that actually closes the hole: a transport can
hold a connection it believes is live for as long as it takes to notice
otherwise — QUIC needs a timeout, and a bridged host may never report the
loss at all. No state check can catch that window; only trying and
falling back can.

Replay is safe. The outbox preserves the message id and channel documents
key messages by id, so a peer that did receive it converges on the same
entry rather than showing it twice.

**Reconnection drains the outbox.** Only `goOnline()` flushed before, so
a peer that came back left queued messages sitting. Both directions now
drain — whether you dial them or they dial you.

**A recycled connection id no longer breaks the handshake.** `onInbound`
is taken as announcing a new connection, and any state held against that
id is discarded. Previously a reused id kept a reader that had already
moved to frame mode, so the new handshake went to the frame parser and
never arrived — surfacing as a handshake timeout on a connection that
looked healthy. `BridgePipe` now states the id rule instead of leaving it
implicit: ids may be recycled once finished, but two connections must
never be live under one id.

### Behaviour change worth noting

`sendMessage` no longer rejects when a peer has gone — it resolves, and
the message is queued. If you were catching that rejection to show a
failure state, read `outboxSize` or `getNetworkStatus()` instead. The
previous behaviour lost the message, so this is a fix rather than a
choice, but it is a visible difference.

### Verified

Five tests covering: a reported close, a **silent** death with no host
report, queueing instead of vanishing, the reconnect flush, and that the
outbox does not become a one-way door. 533 tests pass in the repository,
and the release was checked from a clean install of the packed tarballs.

### Credit

Diagnosed by the agent building EchoIt against this SDK, from observed
message loss. The report was correct on cause and consequence; the one
detail it had inverted — that `publish()` resolved successfully rather
than throwing — is what led to finding the real source of the false
success indication.
