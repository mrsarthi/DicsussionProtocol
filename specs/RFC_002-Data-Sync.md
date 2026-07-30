# RFC 002: Local-First CRDT Storage, Merkle State Sync & Schema Lenses

- **Target Module:** `packages/core`
- **Status:** Draft
- **Authors:** Parth
- **Last Updated:** 2026-07-28

---

## 1. Overview
This specification defines the local-first state management, conflict-free data synchronization, and schema version migration layers. Application state MUST be split across independent **Automerge CRDT documents** (Multi-Doc Granularity) and persisted through **Gun.js** as the local-first graph store. Gun.js provides storage and delta propagation, while Automerge provides deterministic CRDT merge semantics. Peers reconcile state differences efficiently using a **Shallow Merkle State Tree** over the canonical document set, and handle protocol schema version mismatches using declarative **Simple JSON Schema Lenses**.

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
      "$schema": "[https://schemas.dicsussion.org/v1/chat-room.json](https://schemas.dicsussion.org/v1/chat-room.json)",
      "doc_id": "c7a8f902-3b1d-4e5f-9a1b-2c3d4e5f6a7b",
      "meta": {
        "title": "General Chat",
        "created_at": 1785148000
      },
      "messages": {
        "msg-uuid-1": {
          "id": "msg-uuid-1",
          "author_did": "did:key:z6M...",
          "content": "Hello P2P world",
          "timestamp": 1785148100,
          "zk_envelope_ref": "hash-of-rln-proof"
        }
      }
    }

---

## 4. Shallow Merkle State Sync Protocol

To minimize mobile battery drain and cellular bandwidth, peers compare a single **Document-Level Merkle Root Hash** before transferring full CRDT change histories.

### 4.1 Tree Construction
1. Each document's current state is represented by its 32-byte Automerge Head Hash (`head_hash`).
2. Documents are sorted deterministically by `doc_id`.
3. A binary Merkle Tree is constructed where each leaf node is `BLAKE3(doc_id || head_hash)`.

                     [ Root State Hash: 0xA1B2... ]
                              /          \
                             /            \
                  [ Branch Hash L ]     [ Branch Hash R ]
                     /       \             /        \
                 Doc 1       Doc 2     Doc 3        Doc 4

### 4.2 Sync Sequence (Sub-Stream `0x01`)

Node A (Mobile)                                          Node B (Peer)
  │                                                            │
  │────── 1. MerkleRootSync { root_hash: 0xA1B2... } ─────────►│
  │                                                            │ (Compares roots)
  │◄───── 2. RootMatch: TRUE (Sync Complete - 0 Bytes) ────────│ (If hashes match)
  │                                                            │
  │   --- IF HASHES DIFFER ---                                 │
  │                                                            │
  │◄───── 3. GetSubBranches { path: [0] } ────────────────────│ (Requests differing branch)
  │                                                            │
  │────── 4. SendSubBranches { hashes: [...] } ───────────────►│ (Pinpoints differing doc_id)
  │                                                            │
  │◄───── 5. RequestCRDTDelta { doc_id, have_heads } ──────────│
  │────── 6. SendCRDTDelta { doc_id, binary_changes } ────────►│ (Applies Automerge merge)
  │                                                            │
  │────── 7. Gun.js Delta Sync { namespace, seq } ─────────────►│ (Persists the merged state locally)

### 4.3 Canonical State Fields & Quota Awareness
The Merkle root MUST be computed only after the Automerge document and any canonically tracked counters have been merged. The canonical state payload for each document MUST include the following fields:
- `doc_id`
- `head_hash`
- `epoch`
- `message_count`
- `quota_window_id`
- `message_index`

The `message_index` and quota-window state MUST be included in the canonical document state so that peers can detect quota drift after partitions. The Merkle root MUST be recomputed from the merged state, not from a stale snapshot that predates the last local merge.

The Shallow Merkle State Tree is the authoritative reconciliation protocol. Gun.js delta sync operates only as the persistence and propagation layer for the already-merged Automerge state. If a conflict arises between the Merkle root comparison and a Gun.js-received delta, the Merkle root and canonical document state take precedence. Nodes MUST NOT initiate separate merge loops that ignore the Merkle root.

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