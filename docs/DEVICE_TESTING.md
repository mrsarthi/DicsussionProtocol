# Physical Device Testing

**No application required.** `npm run peer` is a complete Dicsussion node with
a terminal instead of a UI. Everything the protocol does — real QUIC, NAT
traversal, relay fallback, E2EE, CRDT sync — works without EchoIt existing.

Building an app first would only add a second thing that could be broken.

---

## Two desktops, same network

On **both** machines:

```bash
git clone <repo> && cd DicsussionProtocol
npm install
npm run peer
```

Each prints a ticket:

```
  Your ticket — paste this into the other device:

  dicsussion1eyJkIjoiZGlkOmtleTp6Nk1rZmp3...
```

On machine **B**, paste machine A's ticket:

```
> /connect dicsussion1eyJkIjoiZGlkOmtleTp6Nk1rZmp3...
  … dialling did:key:z6Mkfjwzo…
  ✓ connected
```

Then just type. Messages appear on the other terminal prefixed with `←`.

```
> hello from the laptop
  → sent (9ab58ca5)
```

The ticket is the whole pairing step — it carries the `did:key`, the Iroh
endpoint id, direct addresses, the relay URL, and the X25519 encryption key
(RFC 001 §3.3).

### Commands

| Command | Purpose |
| :--- | :--- |
| `/connect <ticket>` | Dial a peer |
| `/status` | Peer count, and **direct vs relayed** |
| `/history` | Messages in this channel |
| `/ticket` | Reprint your ticket |
| `/peers` | mDNS-discovered peers |
| `/quit` | Shut down cleanly |

### Flags

```bash
npm run peer -- --store ./peer.db --key "some passphrase"
```

`--store` persists identity across restarts; `--key` encrypts secrets at rest.
Without `--store` the identity is in-memory and a fresh one is generated each
run — fine for connectivity testing, not for testing recovery.

---

## Two desktops, different networks — the real test

This is what has never been exercised. Same steps, but put the machines on
genuinely separate networks (one on home wifi, one tethered to a phone).

**What to watch:** `/status` after connecting.

```
  peers      1
  connected  true
  relay      direct        ← hole-punching worked
```

or

```
  relay      RELAYED       ← fell back through an n0 relay
```

Both are correct outcomes. `RELAYED` means NAT traversal failed and Iroh routed
around it — worth knowing which networks force that, since relay traffic is
what a hosted relay tier would eventually carry.

**To force the relay path**, block direct UDP between the machines with a
firewall rule and reconnect. The fallback ladder has never run for real.

---

## Desktop ↔ Android

Android needs no app either — **Termux** runs Node.js, and `@number0/iroh`
publishes `android-arm64` and `android-arm-eabi` prebuilt binaries.

1. Install [Termux](https://termux.dev) (F-Droid build; the Play Store one is
   outdated).
2. In Termux:
   ```bash
   pkg install nodejs-lts git
   git clone <repo> && cd DicsussionProtocol
   npm install
   npm run peer
   ```
3. Connect it to a desktop peer exactly as above.

If `npm install` fails on `better-sqlite3` (it compiles natively), try
`pkg install python clang make` first.

**Expect this to be the least smooth path.** It is also the most valuable: it
is the first time the protocol runs on the hardware EchoIt actually targets.

### What to measure

| Metric | How |
| :--- | :--- |
| Handshake time | Time from `/connect` to `✓ connected` |
| Direct vs relay | `/status` |
| Message latency | Send and watch the other terminal |
| Battery over 1 h idle | Leave connected, check Android battery stats |

---

## What this does *not* cover

- **UI/UX** — nothing about how a human experiences the app.
- **Background delivery** — Android kills backgrounded processes; a real app
  needs a foreground service or push. Termux tests the protocol, not the
  lifecycle.
- **Multiple channels, groups, vouchers** — the CLI drives one channel. Those
  paths are covered by the automated suite, not here.

The point of this tool is narrow and deliberate: prove the **transport and
crypto work between real machines on real networks**. Everything else is
already tested in CI.
