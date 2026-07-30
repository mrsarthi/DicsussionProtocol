# RFC 001: Core P2P Transport, NAT Traversal & Discovery Protocol

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-07-28

---

## 1. Overview
This specification defines the transport, peer discovery, and networking foundation for the protocol. All communication between nodes MUST occur over encrypted, peer-to-peer QUIC streams using key-based addressing (`did:key`) rather than IP addresses. Nodes MUST automatically discover local network peers via mDNS and punch through complex NAT boundaries globally using Iroh. If direct STUN hole-punching fails, nodes MUST fall back to an ordered set of encrypted relay endpoints, with primary and backup hosts configured by the client so the mesh remains available even if one relay is unavailable or sleeping.

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
        pub node_id: [u8; 32],             // Public key bytes
        pub direct_addresses: Vec<String>, // e.g., ["192.168.1.104:4242", "10.0.0.12:4242"]
        pub relay_url: Option<String>,      // Render Fallback Relay: "https://<app>-relay.onrender.com"
    }

### 3.4 Wire Frame Header Structure & Parser Bounds
Every raw frame sent across a transport sub-stream MUST be prefixed with a fixed 12-byte binary header:

| Offset (Bytes) | Field Name | Type | Description |
|---|---|---|---|
| 0..1 | `magic` | `u16` | Fixed protocol identifier (`0x5032`) |
| 2 | `stream_type` | `u8` | Sub-protocol ID (`0x01` Sync, `0x02` ZK Envelope, `0x03` Revocation) |
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
                   │             │   Render Relay    │         │
                   │             │  Fallback Server  │         │
                   │             │   (*.onrender.com)│         │
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

### 4.2 Global NAT Traversal & Relay Fallback
1. **Direct Hole Punching:** Nodes exchange endpoint candidates (public IP/port tuples derived via STUN) and execute simultaneous UDP hole-punching via `iroh-net`.
2. **Relay Failover:** Nodes MUST support an ordered relay chain (`primary`, `fallback`, and optional additional relays) configured via `relayEndpoints`. If symmetric NAT or restrictive firewalls prevent direct UDP connections within **3000ms**, traffic MUST fail over to the next configured relay endpoint.
   - Relay transport operates over **WSS / HTTPS (Port 443)** to guarantee traversal through strict firewalls.
   - Relays are **zero-knowledge**: they only forward end-to-end encrypted packet streams and CANNOT decrypt or view payload contents.
   - If the primary relay is unavailable, nodes MUST retry using the backup relay without requiring a full application restart.

---

## 5. Connection Handshake Sequence

When Node A initiates a connection to Node B, the following mutually authenticated handshake MUST complete within **5000ms**:

Node A (Initiator)                                        Node B (Responder)
  │                                                               │
  │──── 1. HandshakeInit { timestamp, did_key_a, nonce_a } ──────►│
  │                                                               │ (Check clock skew <= 30s)
  │◄─── 2. HandshakeChallenge { nonce_b, sig_b(nonce_a) } ────────│
  │                                                               │
  │──── 3. HandshakeAck { sig_a(nonce_b) } ──────────────────────►│
  │                                                               │ (Verify Ed25519 signature)
  │                                                               │
  │◄=================== Encrypted Active Session ================►│

### Handshake Constraints:
1. **Clock Skew Verification:** Node B compares `timestamp` to its system clock. If the delta exceeds **30 seconds**, Node B MUST terminate the connection with `Err: ClockSkewTooHigh`.
2. **Replay Protection:** `nonce_a` and `nonce_b` MUST be 32 cryptographically secure random bytes. Nodes MUST track nonces keyed by the handshake timestamp and MUST reject any handshake whose age exceeds **300 seconds**. The replay window MUST be bound to the handshake timestamp rather than a sliding timer so a stale handshake cannot be replayed after the initial window expires.
3. **Handshake Freshness:** Handshake messages MUST complete within **5000ms**; otherwise the initiator or responder MUST abort with `Err: HandshakeTimeout`.

---

## 6. Sub-Protocol Stream Multiplexing

Once the base encrypted connection is established (either direct or via Render relay), all application traffic is multiplexed across isolated streams using the byte header defined in Section 3.4:

- `0x01` **Data Sync Stream:** Transfers Merkle root state hashes and Automerge CRDT binary updates (`specs/02-data-sync-lenses.md`).
- `0x02` **Security Envelope Stream:** Carries ZK-SNARK rate-limiting nullifier (RLN) proofs and encrypted message envelopes (`specs/03-security-envelope.md`).
- `0x03` **Key Revocation Gossip Stream:** Broadcasts signed key revocation tombstones across peers (`specs/03-security-envelope.md`).

---

## 7. Edge Cases & Error Handling

| Error Condition | Trigger | Expected System Action |
| :--- | :--- | :--- |
| `ClockSkewTooHigh` | Handshake timestamp differs by > 30s. | Close stream immediately; emit diagnostic warning to local logs. |
| `HolePunchTimeout` | Direct NAT traversal fails to resolve in 3000ms. | Seamlessly transition transport route to the Render fallback relay endpoint. |
| `RenderRelayUnavailable` | Fallback relay on Render unreachable or sleeping. | Retry connection with exponential backoff; prompt user to verify internet connection. |
| `ChecksumMismatch` | CRC32-C verification fails on incoming frame. | Drop corrupt frame; send `0xFF` frame retransmit request. |
| `DecompressionBomb` | LZ4 payload exceeds 1 MB decompressed limit. | Terminate stream connection immediately; issue security log alert. |
| `BufferOverrun` | Payload offset extends past `ArrayBuffer` bound. | Drop frame immediately; reject stream parser state. |
| `UnknownStreamType` | Sub-protocol ID not in `[0x01, 0x02, 0x03]`. | Silently drop frame; log unknown protocol attempt. |
| `HandshakeTimeout` | Handshake did not complete within 5000ms. | Abort connection attempt and retry with exponential backoff. |
| `ReplayRejected` | Nonce or timestamp indicates a replayed or expired handshake. | Reject the stale handshake and log a security warning. |

---

## 8. Acceptance Criteria

- [ ] Unit tests pass for Ed25519 key derivation and `did:key` string parsing.
- [ ] Integration test verifies two virtual nodes discovering each other over local mDNS without external internet access.
- [ ] Integration test confirms direct connection via Iroh hole-punching behind simulated Cone NAT.
- [ ] Integration test verifies automatic failover to the Render relay endpoint when direct UDP hole-punching fails.
- [ ] Test verifies that clock skew exceeding 30s rejects handshake initialization.
- [ ] Frame parser correctly validates CRC32-C checksums, enforces zero-copy offset safety, and rejects LZ4 compressed payloads exceeding 1 MB.