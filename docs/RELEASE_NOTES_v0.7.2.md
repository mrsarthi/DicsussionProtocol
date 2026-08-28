# GitHub Release — v0.7.2

Paste the body below into the release form. Tag `v0.7.2` on the head of `main`.

---

**Release title:** `v0.7.2 — replies are a field, not a marker`

---

## Body

Adds `replyTo` to messages. Additive: nothing in 0.7.1 changes behaviour,
and `^0.7.1` picks this up without a manifest edit.

```bash
npm install @dicsussion/sdk@0.7.2
```

- [`@dicsussion/core@0.7.2`](https://www.npmjs.com/package/@dicsussion/core)
- [`@dicsussion/sdk@0.7.2`](https://www.npmjs.com/package/@dicsussion/sdk)

Apache-2.0.

### Which messages a message answers

```ts
const question = await client.chat.sendMessage({
  channelId: 'general',
  content: 'what time?',
});

await client.chat.sendMessage({
  channelId: 'general',
  content: 'seven',
  replyTo: [question.id],
});

client.chat.onMessage('general', (message) => {
  message.replyTo;   // readonly string[] | undefined
});
```

`readonly replyTo?: readonly string[]` on `SendMessageOptions` and
`SdkChatMessage`.

Without it an application has one option: put the reference in `content`
behind a marker. That works and is a trap of the same shape as tagging
profiles onto chat messages — a convention every client has to know
indefinitely, rendered as literal text by any client that does not, and
impossible to strip from a quoted excerpt without risking stripping text
the author actually wrote. `content` now carries only what was typed.

**An array**, because a reply may answer more than one message, and
widening a singular field afterwards breaks every reader already parsing
it.

### Ids are carried, never resolved

`replyTo` may name a message this device does not hold. Replies arrive
out of order, and a peer may be answering something from before you
joined the conversation. The reference is preserved rather than dropped —
discarding it would silently turn a reply into an ordinary message — and
what to render for an unresolved one is the application's decision:

```ts
const history = await client.chat.getHistory('general');
const quoted = message.replyTo
  ?.map((id) => history.find((m) => m.id === id))
  .filter((m) => m !== undefined);
// May be shorter than replyTo. Show what you have.
```

References arriving from a peer are bounded — at most 32, each at most
256 characters — since they are written into the conversation document.
Malformed input yields no references rather than raising: a bad id should
cost the quoted excerpt, not the reply carrying it.

### Verification

619 tests passing, 0 failing. Typecheck, build and `npm audit` clean.
Checked from freshly-packed tarballs, over real QUIC.

The envelope round-trip test was written before the feature this time.
`encodePayload` names its fields explicitly, so a field added to the
payload and not to the encoder disappears on the wire while every local
test still passes — the CRDT carries it separately. That is how
`attachments` was lost before 0.7.0 shipped.

### Known limits, unchanged

- No relay server ships, so no offline delivery to a sleeping device
- The WebSocket relay does not encrypt CRDT traffic
- Message content is not encrypted at rest
- Forward secrecy is per-session, not per-message
- One device per identity
