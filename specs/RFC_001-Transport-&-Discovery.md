# RFC 001: Core P2P Transport, NAT Traversal & Discovery Protocol

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-08-27

---

## 1. Overview
This specification defines the transport, peer discovery, and networking foundation for the protocol. All communication between nodes MUST use key-based addressing (`did:key`) rather than IP addresses, and MUST establish a session through the §5 handshake regardless of which transport carries the bytes.

**Direct peer-to-peer QUIC is the reference transport and the only one that meets this document's guarantees in full.** It is REQUIRED wherever the host can open a UDP socket. Two further transports exist because some hosts cannot, and §4.3 states plainly what each gives up. Nodes MUST automatically discover local network peers via mDNS and punch through complex NAT boundaries globally using Iroh. If direct STUN hole-punching fails, nodes MUST fall back to Iroh DERP relays as honest-but-curious fallback endpoints over direct QUIC streams so the mesh remains available even if one relay is unavailable or sleeping.

---

## 2. Non-Goals
- **Application State & CRDTs:** Handling message payloads, document structures, or operational history merging (covered in `specs/02-data-sync-lenses.md`).
- **Zero-Knowledge Proofs:** Enforcing anti-spam circuits or message encryption envelopes (covered in `specs/03-security-envelope.md`).
- **UI & High-Level Storage:** Managing UI state or persisting local records to IndexedDB/LevelDB (covered in `specs/04-headless-backend.md`).

---

## 3. Cryptographic Identity & Addressing

### 3.1 Keypair Generation
Every node MUST initialize a primary cryptographic keypair using the **Ed25519** signature scheme.

### 3.2 Addressing Format (`did:key`)
Peers are identified on the network strictly by their W3C `did:key` representation derived from their Ed25519 public key.
- **Encoding:** `did:key:z6M[Base58Btc-encoded-multicodec-public-key]`
- **Multicodec Prefix:** `0xed` (Ed25519 public key)

### 3.3 Connection Ticket Format
For out-of-band peer pairing, nodes MUST be able to serialize their endpoint information into a compact, Base64-encoded string ("Ticket"):

    pub struct PeerTicket {
        pub did_key: String,               // W3C did:key string
        pub node_id: [u8; 32],             // Ed25519 identity public key
        pub direct_addresses: Vec<String>, // e.g., ["192.168.1.104:4242", "10.0.0.12:4242"]
        pub derp_relay: Option<String>,    // Iroh DERP relay endpoint for fallback transport
        pub transport_key: Option<[u8; 32]>,  // Transport public key (Iroh EndpointId)
        pub encryption_key: Option<[u8; 32]>, // X25519 public key for E2EE key agreement
    }

**`transport_key`** is the peer's Iroh `EndpointId`, derived from the
identity key by domain-separated HKDF. It MUST be published in the ticket
because the derivation requires the secret half and therefore cannot be
recomputed from `did_key` by anyone else. A ticket without it names a peer
that cannot be dialled.

**`encryption_key`** is what makes a ticket a *pairing* artifact rather
than an address. Pairing under §3.3 is mutual: a node that has not
recorded a peer's X25519 key cannot decrypt what that peer sends and MUST
drop it. Dialling a ticket registers the key on the **dialling** side
only, so the accepting side MUST obtain the dialer's ticket by the same
out-of-band route. Implementations MUST NOT treat a completed handshake
as pairing — `HandshakeInit.did_key` is self-asserted, so a stranger with
a fresh keypair is indistinguishable from a known contact.

Both fields are optional in the wire encoding so that tickets from
transports which have no such key (for example an in-process transport
used in tests) remain representable.

**Publication timing.** Address discovery is not instantaneous: a public
address arrives from STUN some time after the socket binds, and a relay
is assigned later still. Implementations MUST NOT publish a ticket before
the endpoint has settled, or it will carry only link-local and LAN
addresses — dialable on the same network and nowhere else, which presents
as NAT traversal failure rather than as a malformed ticket.

### 3.4 Wire Frame Header Structure & Parser Bounds
Every raw frame sent across a transport sub-stream MUST be prefixed with a fixed 12-byte binary header:

| Offset (Bytes) | Field Name | Type | Description |
|---|---|---|---|
| 0..1 | `magic` | `u16` | Fixed protocol identifier (`0x5032`) |
| 2 | `stream_type` | `u8` | Sub-protocol ID (`0x01` Channel Membership & Automerge State Sync, `0x02` E2EE Message Envelopes, `0x03` Key/Identity/Slashing Revocation Gossip, `0x04` Voucher Issuance Handshakes, `0x05` RLN Signal Broadcast, `0x06` RLN Polynomial Share Exchange, `0x07` Ephemeral Payloads) |
| 3 | `flags` | `u8` | Bit flags (`0x01` Compressed via LZ4, `0x02` Priority) |
| 4..7 | `payload_len` | `u32` | Big-endian length of the following payload bytes |
| 8..11 | `checksum` | `u32` | CRC32-C checksum of the payload bytes |

#### Wire Memory Safety & Decompression Limits:
- **Zero-Copy View Extraction:** Wire parsers MUST instantiate payload buffers using exact byte-offsets (e.g., `frame.subarray()`) rather than re-allocating or slicing raw buffers to prevent `ArrayBuffer` boundary overruns.
- **LZ4 Decompression Limit:** If bit flag `0x01` (LZ4 compressed) is set, parsers MUST enforce a strict **1 MB (1,048,576 bytes)** decompression ceiling prior to memory allocation to prevent algorithmic compression bombs.

---

## 4. Peer Discovery & NAT Traversal

Nodes MUST execute discovery and connection establishment across two distinct tiers:

               ┌─────────────────────────────────────────┐
               │         Peer Discovery Initiated         │
               └────────────────────┬────────────────────┘
                                    │
                    Is Peer on Local Wi-Fi / LAN?
                   ┌────────────────┴────────────────┐
                  YES                                NO
                   │                                 │
                   ▼                                 ▼
      ┌───────────────────────────┐    ┌───────────────────────────┐
      │  mDNS Beacon Discovery    │    │   Iroh QUIC Hole Punch    │
      │  (_p2p-sync._udp.local)   │    │    (STUN / UDP Probes)    │
      └────────────┬──────────────┘    └─────────────┬─────────────┘
                   │                                 │
                   │                        Did Hole-Punch Fail?
                   │                       ┌─────────┴─────────┐
                   │                      YES                  NO
                   │                       │                   │
                   │                       ▼                   │
                   │             ┌───────────────────┐         │
                   │             │   Iroh DERP Relay │         │
                   │             │  Fallback Server  │         │
                   │             │   (relay endpoint) │         │
                   │             └─────────┬─────────┘         │
                   │                       │                   │
                   └───────────────────────┴───────────────────┘
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │  Direct / Encrypted   │
                               │      QUIC Stream      │
                               └───────────────────────┘

### 4.1 Local Network Discovery (mDNS)
1. **Service Identifier:** `_p2p-sync._udp.local`.
2. **Beacon Interval:** Nodes broadcast an mDNS TXT record every 5000ms on local network interfaces.
3. **TXT Record Payload:**
   - `did`: Full `did:key` string.
   - `port`: Local listening UDP port.
   - `ver`: Protocol version (`1`).

### 4.2 Global NAT Traversal & DERP Relay Fallback
1. **Direct Hole Punching:** Nodes exchange endpoint candidates (public IP/port tuples derived via STUN) and execute simultaneous UDP hole-punching via `iroh-net`.
2. **DERP Relay Failover:** Nodes MUST support an ordered chain of Iroh DERP relays configured via `relayEndpoints`. If symmetric NAT or restrictive firewalls prevent direct UDP connections within **3000ms**, traffic MUST fail over to the next configured DERP relay endpoint.
   - DERP relay transport operates over direct QUIC streams and acts as an honest-but-curious fallback endpoint.
   - Relays are **zero-knowledge**: they only forward end-to-end encrypted packet streams and CANNOT decrypt or view payload contents.
   - If the primary DERP relay is unavailable, nodes MUST retry using the backup relay without requiring a full application restart.

---

### 4.3 Transport Backends

An implementation MUST expose transports behind a single interface, so
that everything above the byte layer — the §5 handshake, session-key
derivation, §3.4 framing, and §6 stream priority — is written once and
shared. Three backends are defined.

| Backend | When it applies | What it gives up |
|---|---|---|
| **Direct QUIC (Iroh)** | Any host that can open a UDP socket | Nothing. The reference transport. |
| **Bridged byte pipe** | Hosts that cannot open sockets themselves but own one natively — a webview paired with a native layer | §6 priority weakens to send-queue ordering (see below) |
| **Relayed WebSocket** | Browsers, which can neither open a QUIC socket nor accept an inbound connection | Every byte crosses a third party; see the confidentiality note below |

#### Bridged transport contract

Where the host owns the socket, it supplies an ordered byte channel and
the protocol supplies everything else. The contract is deliberately
minimal, and implementations MUST observe all four points:

1. **Ordered bytes, and nothing more.** A host MAY split one write across
   several delivery callbacks, or coalesce several writes into one. Both
   are correct. Implementations MUST NOT require the host to preserve
   message boundaries — the protocol length-prefixes its own handshake
   control messages, and a host that also frames them will break the
   handshake.
2. **Reachability is reported by the host.** The transport key is derived
   from the identity and so is known only to the node; the addresses
   behind it are known only to the host. A dialable ticket requires both.
3. **Connection identifiers MAY be recycled once finished, but two live
   connections MUST NEVER share one.** An inbound notification is taken as
   announcing a new connection, and any state held against that identifier
   is discarded.
4. **Confidentiality to the peer is the host's responsibility.** This
   transport frames and forwards; it does not add encryption beneath the
   protocol. Bridging a QUIC or TLS channel satisfies §1. Bridging a
   plaintext socket does not.

Because one pipe carries every §6 sub-stream, priority degrades from
QUIC stream scheduling to send-queue ordering: an urgent frame jumps the
queue, but a frame already handed to the host completes first. Bounded by
the frame ceiling in §3.4 rather than a stall.

#### Relayed transport confidentiality

A relayed transport carries the §5 handshake end to end, so the relay
never holds a signing key and cannot impersonate a peer. It also cannot
read chat bodies, which are sealed under the session key before reaching
it.

It CAN read everything else. Unless an implementation encrypts beneath
this layer, CRDT sync on `0x01`, revocation gossip on `0x03`, voucher
handshakes on `0x04`, and RLN traffic on `0x05`/`0x06` cross the relay in
the clear — from which an operator can reconstruct the membership graph
and read history replicated through sync. Implementations MUST disclose
this to users rather than describing such a relay as zero-knowledge, and
MUST prefer a direct or bridged transport wherever one is available.

---

## 5. Connection Handshake Sequence

When Node A initiates a connection to Node B, the following mutually authenticated handshake MUST complete within **5000ms**:

Node A (Initiator)                                        Node B (Responder)
  │                                                               │
  │─ 1. HandshakeInit { timestamp, did_key_a, nonce_a, sub_streams } ─►│
  │                                                               │ (Check clock skew <= 10s)
  │◄─── 2. HandshakeChallenge { nonce_b, sig_b(nonce_a) } ────────│
  │                                                               │
  │──── 3. HandshakeAck { sig_a(nonce_b) } ──────────────────────►│
  │                                                               │ (Verify Ed25519 signature)
  │                                                               │
  │◄=================== Encrypted Active Session ================►│

### Handshake Constraints:
1. **Epoch Alignment:** The effective epoch for all RLN and message proofs is computed as $E = \left\lfloor \frac{T_{\text{local}} + \Delta_{\text{peer}}}{10\text{s}} \right\rfloor$, where $\Delta_{\text{peer}} = T_{\text{remote}} - T_{\text{local}}$ is exchanged during the initial QUIC handshake. The handshake MUST negotiate a shared clock offset before proofs are accepted.
2. **Clock Skew Verification:** Node B compares the remote timestamp to its system clock. If the absolute offset exceeds **10 seconds**, Node B MUST terminate the connection with `Err: ClockSkewTooHigh` and request relay-assisted drift alignment.
3. **Replay Protection:** `nonce_a` and `nonce_b` MUST be 32 cryptographically secure random bytes. Nodes MUST track nonces keyed by the handshake timestamp and MUST reject any handshake whose age exceeds **300 seconds**. The replay window MUST be bound to the handshake timestamp rather than a sliding timer so a stale handshake cannot be replayed after the initial window expires.
4. **Handshake Freshness:** Handshake messages MUST complete within **5000ms**; otherwise the initiator or responder MUST abort with `Err: HandshakeTimeout`.
5. **Sub-Stream Count:** On transports where each §6 sub-stream is a separate stream, `HandshakeInit.sub_streams` states how many the initiator will open, and the responder MUST accept exactly that many. A responder MUST NOT wait for a number derived from the stream types it happens to know: accepting a stream is untimed, so waiting on one the initiator never opens parks the responder indefinitely — it never surfaces the connection, while the initiator completes its handshake and treats the peer as reachable. Traffic then disappears with no error on either side. An initiator predating this field opened the six types defined at the time, so a responder MUST treat its absence as **6** and MUST NOT track that constant to the current count. A responder MUST adopt a stream whose tag it does not recognise, per §7.

---

## 6. Sub-Protocol Stream Multiplexing

Once the base encrypted connection is established (either direct or via Iroh DERP relay), all application traffic is multiplexed across isolated streams using the byte header defined in Section 3.4:

- `0x01` **Channel Membership & Automerge State Sync:** Transfers membership state and Automerge CRDT binary updates (`specs/02-data-sync-lenses.md`).
- `0x02` **E2EE Message Envelopes:** Carries encrypted message envelopes and associated proof metadata (`specs/03-security-envelope.md`).
- `0x03` **Key, Identity, & Slashing Revocation Gossip:** Broadcasts signed key revocation tombstones and high-priority identity changes (`specs/03-security-envelope.md`).
- `0x04` **Synchronous Voucher Issuance Handshakes:** Exchanges blinded voucher issuance messages and receipt acknowledgements (`specs/03-security-envelope.md`, `specs/04-headless-backend.md`).
- `0x05` **RLN Signal Broadcast:** Propagates RLN signals across the mesh for spam mitigation.
- `0x06` **RLN Polynomial Share Exchange:** Gossips evaluation shares $(x_k, y_k)$ keyed by the `(E, i)` tuple for deduplicated transitive slashing.

Revocation tombstones over `0x03` MUST be processed with strictly higher priority than `0x02` traffic. On partition reconnection, peers MUST process all pending revocation tombstones before executing Automerge state merges. Evaluation shares over `0x06` MUST be propagated to trigger transitive slashing when peers observe conflicting RLN nullifiers.

---

### 6.1 Ephemeral Payloads (`0x07`)

Stream `0x07` carries signals that are meaningful only while both peers
are connected — presence, typing indicators, read receipts. Frames MUST
be sealed under the session key exactly as `0x02` is, and MUST be subject
to the same membership rules in both directions: a signal is still a
disclosure.

Implementations MUST NOT persist a `0x07` payload, queue it for a peer
that is not connected, retry it, or replay it to a peer that reconnects.
A recipient who is absent when one is sent does not receive it, and that
is the intended behaviour: these signals are false by the time a retry
would arrive, and delivering a stale one is worse than delivering none.

The payload is opaque to the protocol. What a signal means belongs to the
application, and giving it a schema here would require revising this
document whenever an application invents a new one.

**Why a stream rather than an ordinary message.** Carrying these as
`0x02` envelopes would work and would append to the channel document
permanently. A thirty-second heartbeat is on the order of a few thousand
entries per conversation per day, replicated to every participant and
written to disk, for signals nobody will ever read back.

`0x07` was assigned after `0x06`, so an implementation predating it drops
the frame under §7's unknown-stream rule rather than failing on it.

---

## 7. Edge Cases & Error Handling

| Error Condition | Trigger | Expected System Action |
| :--- | :--- | :--- |
| `ClockSkewTooHigh` | Handshake timestamp differs by > 10s. | Close stream immediately; emit diagnostic warning to local logs. |
| `HolePunchTimeout` | Direct NAT traversal fails to resolve in 3000ms. | Seamlessly transition transport route to the next available Iroh DERP relay endpoint. |
| `IrohDerpRelayUnavailable` | Fallback DERP relay is unreachable or sleeping. | Retry connection with exponential backoff; prompt user to verify internet connection. |
| `ChecksumMismatch` | CRC32-C verification fails on incoming frame. | Drop corrupt frame; send `0xFF` frame retransmit request. |
| `DecompressionBomb` | LZ4 payload exceeds 1 MB decompressed limit. | Terminate stream connection immediately; issue security log alert. |
| `BufferOverrun` | Payload offset extends past `ArrayBuffer` bound. | Drop frame immediately; reject stream parser state. |
| `UnknownStreamType` | Sub-protocol ID not in `[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]`. | Silently drop frame; log unknown protocol attempt. |
| `HandshakeTimeout` | Handshake did not complete within 5000ms. | Abort connection attempt and retry with exponential backoff. |
| `ReplayRejected` | Nonce or timestamp indicates a replayed or expired handshake. | Reject the stale handshake and log a security warning. |

---

## 8. Acceptance Criteria

- [ ] Unit tests pass for Ed25519 key derivation and `did:key` string parsing.
- [ ] Integration test verifies two virtual nodes discovering each other over local mDNS without external internet access.
- [ ] Integration test confirms direct connection via Iroh hole-punching behind simulated Cone NAT.
- [ ] Integration test verifies automatic failover to the Iroh DERP relay endpoint when direct UDP hole-punching fails.
- [ ] Test verifies that clock skew exceeding 10s rejects handshake initialization.
- [ ] Frame parser correctly validates CRC32-C checksums, enforces zero-copy offset safety, and rejects LZ4 compressed payloads exceeding 1 MB.