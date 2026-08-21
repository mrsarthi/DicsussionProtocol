# GitHub Release — v0.3.2

Paste the body below into the release form. Tag `v0.3.2` on the head of `main`.

---

**Release title:** `v0.3.2 — messages delivered by sync now reach onMessage`

---

## Body

Fixes messages that arrive by document sync never reaching `onMessage`
listeners, and two send-path bugs that let a node believe it could
deliver when it could not. Upgrade from 0.3.1 or earlier.

```bash
npm install @dicsussion/sdk@0.3.2
```

- [`@dicsussion/core@0.3.2`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.3.2`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Sync-delivered messages notified nobody

A message reaches a node two ways. An E2EE envelope on stream `0x02`
runs through `ChatService.ingestRemote`, which emits. A message merged by
document sync on `0x01` was applied to the CRDT and announced to no one —
`_emitMessage` had exactly one caller.

So a synced message appeared in `getHistory()` and never in `onMessage`.
To an application appending on the event, it had not arrived.

**The data was never lost.** A peer that reconnects converges the channel
document and holds every message it missed; the local-first design was
doing its job while the application was never told. But if your UI
appends on `onMessage` — which is the obvious way to write one — messages
sent while you were offline were invisible until something else re-read
history.

Fixed by subscribing to `CrdtSyncEngine.onDocumentUpdate` and diffing the
channel document against the ids already emitted. De-duplication by id
covers both duplicate paths: the same message arriving over `0x02` and
then again by sync, and a re-apply while syncing with a third peer. First
sight of a channel seeds a baseline rather than emitting, so the first
sync after a restart does not replay all of history as new.

### A stranger could suppress your outbox

`isOnline()` and `getNetworkStatus().connected` read `connectedCount`,
which counts every live connection including unpaired ones. `publish()`
sends only to *paired* peers. Two different sets.

An unpaired stranger completing a handshake was therefore enough to make
a node believe it could deliver. A message to an offline contact was then
published to zero peers, resolved as success, and never queued — so
anyone could suppress another user's retry queue simply by dialling them.

Both now read `listPairedConnected()`. `peerCount` still counts every
live connection, which is what an application needs to surface a
stranger's connection request; the two differ deliberately.

### Reaching nobody is no longer success

`SessionManager.publish` fanned out to paired peers and returned `void`,
so reaching nobody resolved exactly like reaching everybody — and 0.3.1's
queue-on-failure never fired, because nothing failed. It now returns how
many peers it sent to, and a zero-recipient send queues.

### API changes

`SessionManager.publish` and `ChatServiceDeps.publish` return
`Promise<number>` rather than `Promise<void>`. Both are exported, so this
is a breaking type change for anyone implementing `ChatServiceDeps` or
calling `SessionManager.publish` directly — internal wiring seams that an
application using `DicsussionClient` never touches. Released as a patch
on that basis; if you do implement either, widen your return type.

`ChatService.emitSynced(channelId)` is new, and public mainly so it is
testable. `DicsussionClient` wires it for you.

### Why it took three participants to find

Every test in this project used exactly one contact. With one contact,
"is anyone connected" and "can I reach my contact" are the same question,
and the send path got it right. They stop being the same the moment a
second peer exists, or a stranger knocks.

The new suite uses three participants, which is the smallest number that
separates them.

### Credit

Reported by the agent building EchoIt against this SDK, from observed
message loss with a false sent indication. The cause in that report was
exactly right. The consequence was not — the messages were recoverable
all along — and finding out why is what located the missing emit.
