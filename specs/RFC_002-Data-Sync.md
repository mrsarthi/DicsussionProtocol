# RFC 002: Local-First CRDT Storage, Merkle State Sync & Schema Lenses

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-08-27

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
          "zk_envelope_ref": "hash-of-rln-proof",
          "attachments": "[{\"hash\":\"<sha256-hex>\",\"size\":40213,\"mime\":\"image/png\"}]",
          "reply_to": "[\"msg-uuid-0\"]"
        }
      }
    }

`author_did` MAY be `null` when `nullifier_hash` is present for anonymous RLN channels. Received messages MUST persist the serialized Groth16 proof (`zk_proof`) and RLN nullifier (`rln_nullifier`) locally for offline dispute resolution.

`attachments` holds handles to blob content transferred on Sub-Stream
`0x09` (RFC 001 §6.3) — a content hash, a length and a media type. The
bytes themselves MUST NOT be inlined here: a document is replicated in
full to every participant and kept indefinitely, so an inlined picture is
copied to people who never opened it and cannot afterwards be removed.

`reply_to` names the messages this one answers. It is a field rather
than a marker inside `content` because a marker is a convention every
implementation must know indefinitely, is rendered as literal text by any
that does not, and cannot be separated from text the author actually
wrote.

An implementation MUST NOT require that a referenced id resolve. A reply
may arrive before the message it answers, or name one this replica will
never hold, so a dangling reference MUST be preserved rather than
dropped: discarding it silently converts a reply into an ordinary
message. Whether to render an unresolved reference, and how, is the
application's decision.

Both fields are stored **serialized**, not as structured lists. Automerge merges
nested maps field by field, so two replicas editing the same message
could otherwise combine halves of two different handles into a reference
to content neither of them holds. A malformed value MUST be read as no
attachments rather than raising: one bad row must not make a conversation
unreadable.

#### Reactions

A reaction is a mutable, withdrawable mark by one person on one message.
It MUST NOT be represented as a message: reacting, withdrawing and
reacting again would append three permanent entries for one gesture, and
every implementation would then have to know to hide them from the
conversation. It MUST NOT be ephemeral either — a reaction remains true
after both parties disconnect and MUST reach a replica that was offline
when it was made.

Reactions are stored at the **top level** of the document under a
`reaction:` prefix, one key per (message, author) pair:

    "reaction:[\"msg-uuid-1\",\"did:key:z6Mk...\"]": {
      "messageId": "msg-uuid-1",
      "authorDid": "did:key:z6Mk...",
      "emoji": "👍",
      "updatedAt": 1785148200
    }

One key per pair is what makes reacting a replacement rather than an
append, and means only the author ever writes a given key.

They are **not** collected into a nested map. A nested map must be
created before its first entry, and two replicas creating it
concurrently produce conflicting assignments of the whole map — one
survives and the other replica's reaction is lost. Two people reacting to
the same message at once is ordinary traffic, not an edge case. Placing
the map in genesis would also resolve it and would change the genesis
bytes, so replicas on either side of that change would mint different
genesis for the same `doc_id` and fail to merge at all (§3.2).

Withdrawal MUST store an empty `emoji` rather than deleting the key. A
delete racing a set resolves by actor order and can resurrect a
withdrawn reaction; an empty value cannot. The key space is bounded by
messages × participants either way.

`updatedAt` is the author's clock and is for display ordering only.

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
4. At capacity, nodes MUST evict deterministically — the **lowest occupied
   leaf index** — and replace it with a tombstone leaf $cm_{\text{empty}} = 0$.

   **Not LRU**, despite earlier revisions of this document specifying it.
   The root must be a pure function of committed state, and last-activity
   is a local observation that is never committed: two nodes holding
   identical membership would evict different leaves and compute
   different roots, so the tree would stop converging exactly when it
   filled up. Determinism here is a correctness requirement, not a
   simplification.

   Depth 16 admits 65,536 leaves, but implementations SHOULD apply a
   lower working cap — the reference implementation uses **4,096** —
   because a rebuild is O(N·D) and the full depth is impractical on
   mobile hardware.
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