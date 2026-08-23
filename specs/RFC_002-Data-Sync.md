# RFC 002: Local-First CRDT Storage, Merkle State Sync & Schema Lenses

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-08-23

---

## 1. Overview
This specification defines the local-first state management, conflict-free data synchronization, and schema version migration layers. Application state MUST be split across independent **Automerge CRDT documents** (Multi-Doc Granularity) and persisted locally via **SQLite** on desktop and **IndexedDB** in browser contexts. Binary delta propagation is handled directly by **Automerge over Iroh QUIC streams**. Peers reconcile state differences efficiently using a **Bounded Sparse Merkle Tree** over the canonical document set, and handle protocol schema version mismatches using declarative **Simple JSON Schema Lenses**.

---

## 2. Non-Goals
- **Network Transport:** Handling P2P sockets, mDNS discovery, or Iroh QUIC streams (covered in `specs/01-transport.md`).
- **Zero-Knowledge Proofs:** Generating or verifying RLN zero-knowledge envelopes (covered in `specs/03-security-envelope.md`).
- **Low-Level Disk I/O:** Managing raw IndexedDB key-value stores or SQLite files (covered in `specs/04-headless-backend.md`).

---

## 3. Multi-Doc CRDT Architecture

Application state MUST NOT be stored in a single monolithic document. Instead, every channel, chat room, or list is an independent Automerge document identified by a unique 16-byte UUID (`doc_id`).

### 3.1 Document Schema Structure
Every document MUST conform to a registered schema structure:

    {
      "$schema": "https://schemas.dicsussion.org/v1/chat-room.json",
      "doc_id": "c7a8f902-3b1d-4e5f-9a1b-2c3d4e5f6a7b",
      "meta": {
        "title": "General Chat",
        "created_at": 1785148000
      },
      "participants": {
        "did:key:z6Mk...": { "did": "did:key:z6Mk...", "added_at": 1785148000 }
      },
      "messages": {
        "msg-uuid-1": {
          "id": "msg-uuid-1",
          "author_did": null,
          "nullifier_hash": "poseidon-hash",
          "content": "Hello P2P world",
          "timestamp": 1785148100,
          "zk_proof": "base64-serialized-groth16-proof",
          "rln_nullifier": "base64-serialized-nullifier",
          "zk_envelope_ref": "hash-of-rln-proof"
        }
      }
    }

`author_did` MAY be `null` when `nullifier_hash` is present for anonymous RLN channels. Received messages MUST persist the serialized Groth16 proof (`zk_proof`) and RLN nullifier (`rln_nullifier`) locally for offline dispute resolution.

---

### 3.2 Deterministic Genesis

**Every replica of a document MUST begin from byte-identical genesis
derived from its `doc_id`.** A replica that instead *creates* the
document locally has a root history of its own, and merging two such
histories is a conflict over the container: the `messages` map was
assigned concurrently in each, one assignment wins, and every message
written into the loser disappears from the merged document.

The failure is silent and permanent. The winner is deterministic, so all
replicas converge on the same truncated document; their state roots then
agree, and §4 reports them in sync forever after. The lost operations
remain in history but are unreachable.

Genesis MUST therefore contain only values derived from `doc_id`, minted
under a fixed actor and a fixed timestamp:

- A per-node actor produces per-node operation ids, hence a per-node root.
- A wall-clock timestamp is worse, because it fails *intermittently*: two
  nodes minting genesis in the same millisecond agree and any other pair
  does not, surfacing as a duplicate-sequence rejection on merge.

Anything varying per node — a title, a creation time — MUST be applied as
a change *after* genesis, where it merges as an ordinary
last-write-wins scalar rather than forking the root.

### 3.3 Participants

`participants` is an authorization boundary, not metadata. A document
MUST be synchronised only with peers named in it, in both directions:
refusing to offer it, and refusing to adopt it when pushed. **A document
with no participants MUST NOT be shared with anyone.**

Being paired is not sufficient. Pairing (RFC 001 §3.3) authorises a peer
to hold a session, not to receive every conversation a node happens to
store — and an implementation that conflates them discloses each contact's
history to every other contact, backdated to before they were added.

The list lives inside the document so it survives device replacement
alongside the history it governs, at the cost of being readable by
everyone legitimately holding that document.

---

## 4. Bounded Sparse Merkle State Sync Protocol

To minimize mobile battery drain and cellular bandwidth, peers compare a single **Document-Level Sparse Merkle Root Hash** before transferring full CRDT change histories.

### 4.1 Tree Construction
1. Each document's current state is represented by its 32-byte Automerge Head Hash (`head_hash`).
2. Active identity commitments are collected, sorted lexicographically, and mapped to a bounded sparse tree index $\text{Index}(cm_x) = \text{Rank}(cm_x \in \text{Sorted}(cm_1, cm_2, \dots))$.
3. The tree is a **Bounded Sparse Merkle Tree** of depth $D = 16$ with Poseidon path elements and a maximum active commitment set size $N_{\text{max}} = 65{,}536$.
4. When $N = 65{,}536$, nodes MUST evict the oldest inactive commitment using an LRU frame and replace it with a tombstone leaf $cm_{\text{empty}} = 0$.
5. Poseidon hashing is used for path elements and the resulting root is the canonical state root for the document set.

### 4.2 Sync Sequence (Sub-Stream `0x01`)

Node A (Mobile)                                          Node B (Peer)
  │                                                            │
  │────── 1. SparseMerkleRootSync { root_hash: 0xA1B2... } ───►│
  │                                                            │ (Compares roots)
  │◄───── 2. RootMatch: TRUE (Sync Complete - 0 Bytes) ────────│ (If hashes match)
  │                                                            │
  │   --- IF HASHES DIFFER ---                                 │
  │◄───── 3. GetSparseSubtree { path: [0] } ───────────────────│ (Requests differing branch)
  │                                                            │
  │────── 4. SendSparseSubtree { hashes: [...] } ─────────────►│ (Pinpoints differing commitment)
  │                                                            │
  │◄───── 5. RequestCRDTDelta { doc_id, have_heads } ──────────│
  │────── 6. SendCRDTDelta { doc_id, binary_changes } ────────►│ (Applies Automerge merge)
  │                                                            │
  │────── 7. PersistLocalState { storage: SQLite|IndexedDB } ─►│ (Persists the merged state locally)

### 4.3 Canonical State Fields & Quota Awareness
The Merkle root MUST be computed only after the Automerge document and any canonically tracked counters have been merged. The canonical state payload for each document MUST include the following fields:
- `doc_id`
- `head_hash`
- `epoch`
- `message_count`
- `quota_window_id`
- `message_index`

The `message_index` and quota-window state MUST be included in the canonical document state so that peers can detect quota drift after partitions. The Merkle root MUST be recomputed from the merged state, not from a stale snapshot that predates the last local merge.

The bounded sparse Merkle tree is the authoritative reconciliation protocol. Local SQLite or IndexedDB persistence is only the storage layer for the already-merged Automerge state. If a conflict arises between the Merkle root comparison and a persisted local delta, the Merkle root and canonical document state take precedence. Nodes MUST NOT initiate separate merge loops that ignore the Merkle root.

### 4.4 Automerge Snapshotting & State Pruning Policy
To prevent unbounded CRDT history bloat over extended chat operation:
1. **Periodic Checkpointing:** Every 1,000 document changes or 7 days, nodes MUST generate a compressed binary snapshot of the active Automerge document state (`automerge.save()`).
2. **Delta Pruning:** Local stores MAY discard raw historical change deltas older than the latest canonical snapshot, retaining only the head state hash and active leaf nodes for state reconciliation.
3. **Channel Archival:** Inactive channels (no messages exchanged within 30 days) are evicted from the active Merkle state tree into content-addressed blob storage on Iroh, releasing hot SQLite/IndexedDB memory paths.

---

### 4.5 Continuous Reconciliation

Reconciling once per connection is **not sufficient**. A node MUST push a
document to eligible peers whenever it changes locally, including when
the change merely arrived from another peer.

Without onward relay, a message reaches only peers the sender is directly
connected to. Three participants in a star — two outer nodes each
connected to a middle one, and not to each other — then hold three
different conversations indefinitely: the middle node sees everything and
each outer node sees half, with nothing to indicate a split. Groups are
rarely a full mesh in practice, so this is the normal case rather than an
edge one.

Relaying is self-limiting: once a peer is up to date the sync protocol
yields no message, so propagation terminates without extra bookkeeping.

**A message may consequently arrive twice** — once as a Stream `0x02`
envelope and again inside a relayed document. Both deliveries are
legitimate. An implementation MUST surface it to the application once,
de-duplicated by message id, or a group displays every message as many
times as there are paths to it.

Implementations MUST also distinguish *"present when this replica first
observed the channel"* from *"already delivered to the application"*.
The first prevents replaying stored history as new arrivals after a
restart; the second prevents double delivery. Conflating them suppresses
the first message on every channel, because seeding the one marks
messages delivered before anything delivered them.

---

## 5. Schema Lenses Migration Layer

When peers running different app versions (e.g., v1.0 and v2.0) exchange data, Simple JSON Lenses apply bidirectional transformation operations to guarantee backwards compatibility.

### 5.1 Simple JSON Lens Format
Lenses are defined as declarative JSON transformation pipelines:

    {
      "lens_id": "chat-room-v1-to-v2",
      "from_schema": "v1/chat-room.json",
      "to_schema": "v2/chat-room.json",
      "operations": [
        { "op": "add_field", "path": "/messages/*/reactions", "default": {} },
        { "op": "rename_field", "from": "/meta/title", "to": "/meta/channel_name" }
      ]
    }

### 5.2 Transformation Rules
- **Downcast Lens (v2 -> v1):** When sending data to an older peer, unknown fields (`reactions`) are safely stripped out so the v1 peer's schema validation passes.
- **Upcast Lens (v1 -> v2):** When receiving data from an older peer, missing fields are populated with clean default values (`reactions = {}`).

---

## 6. Edge Cases & Error Handling

| Error Condition | Trigger | Expected System Action |
| :--- | :--- | :--- |
| `AutomergeMergeConflict` | Concurrent offline edits to same field. | Automerge deterministic CRDT engine resolves value automatically; no runtime crash. |
| `UnknownSchemaVersion` | Peer receives doc with no valid Lens path. | Reject document delta; send `Err: LensNotFound`; prompt user to update app software. |
| `CorruptCRDTDelta` | Binary change bytes fail signature or checksum. | Discard delta; log security alert; fall back to full document snapshot fetch. |
| `QuotaStateMismatch` | A peer observes divergent `message_index` or quota-window counters after a merge. | Reject the conflicting delta, recompute the canonical Merkle root, and force a full state resync for the affected document. |

---

## 7. Acceptance Criteria

- [ ] Unit test verifies multi-document creation and local state isolation by `doc_id`.
- [ ] Test verifies that Merkle root computation for 50 documents completes in < 2ms on mobile hardware.
- [ ] Integration test verifies zero bytes transferred (beyond the 32-byte root hash) when two nodes are already in sync.
- [ ] Test confirms declarative JSON Lens transforms v1 schema data to v2 format without losing message history.