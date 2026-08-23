/**
 * @dicsussion/crdt — Multi-Document Manager
 *
 * Manages multiple independent Automerge CRDT documents keyed by UUID.
 * Each channel/chat is a separate document to prevent monolithic state
 * per RFC 002 §3 and AGENT_INSTRUCTIONS §4.2 rule 4.
 */

import * as Automerge from '@automerge/automerge';

/** Schema URL stamped into every channel document (RFC 002 §3.1). */
const SCHEMA_URL = 'https://schemas.dicsussion.org/v1/chat-room.json';

/**
 * Actor id used only to mint genesis, so the bytes match on every node.
 *
 * Automerge derives operation ids from the actor, so a per-node actor
 * here would produce a per-node root — precisely what genesis exists to
 * prevent.
 */
const GENESIS_ACTOR = '0'.repeat(32);

/** A fresh actor id for local changes; Automerge wants 32 hex chars. */
function localActor(): string {
  let out = '';
  for (let i = 0; i < 32; i++) {
    out += Math.floor(Math.random() * 16).toString(16);
  }
  return out;
}
import { v4 as uuidv4 } from 'uuid';

import type { ChatMessage, DocumentMeta, DocumentSchema } from './types.js';

/** Snapshot policy: create snapshot every N changes. */
const SNAPSHOT_CHANGE_THRESHOLD = 1000;

/**
 * Ceiling on documents held in memory at once.
 *
 * Generous for any real user — a person in a thousand channels is beyond
 * the design point — and small enough that a peer naming document ids at
 * line rate hits a wall instead of the heap.
 */
const MAX_DOCUMENTS = 1_024;

/** Internal document wrapper tracking change count for snapshot policy. */
interface ManagedDoc {
  doc: Automerge.Doc<DocumentSchema>;
  changeCount: number;
  lastSnapshotAt: number;
}

/**
 * Manages a collection of independent Automerge CRDT documents.
 *
 * Each document is identified by a UUID (`doc_id`) and operates
 * independently for conflict-free concurrent editing.
 */
export class DocumentManager {
  private readonly documents = new Map<string, ManagedDoc>();

  /** Genesis bytes per docId; deterministic, so worth computing once. */
  private readonly genesisCache = new Map<string, Uint8Array>();

  /**
   * The identical starting point every replica of a document must share.
   *
   * **This is load-bearing, not a tidiness measure.** Automerge merges
   * histories, and two replicas that each *created* the document have no
   * shared history: each independently assigned the `messages` map, and
   * merging those concurrent assignments keeps one map object and
   * discards the other — silently deleting every message written into
   * the loser. Because the winner is deterministic, all replicas then
   * converge on the same truncated document and their state roots match,
   * so synchronisation reports success and never repairs it.
   *
   * Starting from byte-identical genesis means the container objects are
   * the *same* object in every replica, so concurrent writes land in it
   * side by side, which is the behaviour a CRDT is chosen for.
   *
   * Every field here must be derived from `docId` alone. Anything
   * varying per node — a title, a creation timestamp — belongs in a
   * change applied afterwards, where it merges as an ordinary
   * last-write-wins scalar instead of forking the root.
   *
   * The returned document is loaded under a **fresh local actor**. The
   * fixed actor exists only to make the genesis bytes identical; leaving
   * it in place would attribute every later change to it, and two nodes
   * editing would then claim the same actor and sequence number, which
   * Automerge rejects outright as a duplicate.
   */
  private genesis(docId: string): Automerge.Doc<DocumentSchema> {
    let bytes = this.genesisCache.get(docId);

    if (!bytes) {
      // `Automerge.from` stamps the wall clock into the change it
      // creates, so two nodes minting genesis a millisecond apart would
      // produce different bytes under the same actor and sequence —
      // which Automerge rejects on merge as a duplicate seq, and only
      // sometimes, depending on timing. Building it as an explicit
      // change with a pinned time keeps the bytes identical forever.
      const seed = Automerge.change(
        Automerge.init<DocumentSchema>({ actor: GENESIS_ACTOR }),
        { time: 0 },
        (draft) => {
          draft.$schema = SCHEMA_URL;
          draft.doc_id = docId;
          draft.meta = { title: '', createdAt: 0 };
          draft.messages = {};
          draft.participants = {};
        },
      );

      bytes = Automerge.save(seed);
      this.genesisCache.set(docId, bytes);
    }

    return Automerge.load<DocumentSchema>(bytes, { actor: localActor() });
  }

  /**
   * Create a new CRDT document with initial metadata.
   *
   * @param title Human-readable document title.
   * @param docId Optional UUID; auto-generated if omitted.
   * @returns The new document's ID.
   */
  createDocument(title: string, docId?: string): string {
    const id = docId ?? uuidv4();

    if (this.documents.has(id)) {
      throw new Error(`Document already exists: ${id}`);
    }

    // From shared genesis, then the local details as a change — see
    // `genesis` for why this cannot be a plain `Automerge.from`.
    const doc = Automerge.change(this.genesis(id), (draft) => {
      draft.meta.title = title;
      draft.meta.createdAt = Math.floor(Date.now() / 1000);
    });

    this.documents.set(id, {
      doc,
      changeCount: 0,
      lastSnapshotAt: Date.now(),
    });

    return id;
  }

  /**
   * Add a participant to a conversation's guest list.
   *
   * The list decides who a document may be synchronised with, so this is
   * an authorization boundary rather than a display detail. It lives in
   * the document so it survives a device replacement alongside the
   * history it governs.
   *
   * Idempotent: re-adding keeps the original `addedAt`, so two replicas
   * adding the same person do not fight over the timestamp.
   *
   * @param docId The conversation.
   * @param did Participant's did:key.
   */
  addParticipant(docId: string, did: string): void {
    const managed = this.documents.get(docId);
    if (!managed) throw new Error(`Unknown document: ${docId}`);
    if (managed.doc.participants?.[did]) return;

    managed.doc = Automerge.change(managed.doc, (draft) => {
      // A document minted before participants existed has no map.
      if (!draft.participants) draft.participants = {};
      draft.participants[did] = { did, addedAt: Math.floor(Date.now() / 1000) };
    });
    managed.changeCount++;
  }

  /**
   * Remove a participant from a conversation's guest list.
   *
   * **This stops future sharing. It cannot undo past sharing.** Anything
   * the peer already received is on their device and stays there — no
   * message protocol can reach into someone else's storage, and any
   * claim otherwise would be theatre. What removal does achieve is
   * real, and in both directions: they are no longer sent new messages,
   * no longer offered the document, and their pushes are refused rather
   * than merged.
   *
   * That second half matters as much as the first. CRDT changes are not
   * individually authenticated, so a peer who remains in the list can
   * keep writing into the shared document regardless of any local block.
   *
   * @param docId The conversation.
   * @param did Participant to remove.
   * @returns Whether they were on the list.
   */
  removeParticipant(docId: string, did: string): boolean {
    const managed = this.documents.get(docId);
    if (!managed?.doc.participants?.[did]) return false;

    managed.doc = Automerge.change(managed.doc, (draft) => {
      delete draft.participants[did];
    });
    managed.changeCount++;

    return true;
  }

  /**
   * Whether a `did:key` belongs to a conversation.
   *
   * Absent document or empty list means no — a conversation nobody is
   * recorded in is shared with nobody, which is what makes the default
   * safe for anything created before the list existed.
   */
  isParticipant(docId: string, did: string): boolean {
    return this.documents.get(docId)?.doc.participants?.[did] !== undefined;
  }

  /** Everyone recorded in a conversation. */
  participants(docId: string): string[] {
    return Object.keys(this.documents.get(docId)?.doc.participants ?? {});
  }

  /**
   * Get the current state of a document.
   *
   * @param docId The document UUID.
   * @returns The Automerge document or undefined.
   */
  getDocument(docId: string): Automerge.Doc<DocumentSchema> | undefined {
    return this.documents.get(docId)?.doc;
  }

  /**
   * Check if a document exists.
   */
  hasDocument(docId: string): boolean {
    return this.documents.has(docId);
  }

  /**
   * Apply a local change to a document.
   *
   * @param docId The document UUID.
   * @param changeFn Function that mutates the document.
   * @returns Binary change bytes for sync transmission.
   */
  applyChange(
    docId: string,
    changeFn: (doc: DocumentSchema) => void,
  ): Uint8Array {
    const managed = this.documents.get(docId);
    if (!managed) {
      throw new Error(`Document not found: ${docId}`);
    }

    const oldDoc = managed.doc;
    const newDoc = Automerge.change(oldDoc, changeFn);
    managed.doc = newDoc;
    managed.changeCount++;

    // Get the binary changes between old and new
    const changes = Automerge.getChanges(oldDoc, newDoc);

    // Concatenate all change bytes
    if (changes.length === 0) {
      return new Uint8Array(0);
    }

    return changes.length === 1
      ? changes[0]!
      : concatUint8Arrays(changes);
  }

  /**
   * Add a chat message to a document.
   *
   * @param docId The document UUID.
   * @param message The chat message to add.
   * @returns Binary change bytes.
   */
  addMessage(docId: string, message: ChatMessage): Uint8Array {
    return this.applyChange(docId, (doc) => {
      // A document created by `ensureSyncDocument` starts empty, so the
      // schema skeleton may not exist yet. Seed it before writing rather
      // than dereferencing an undefined `messages` map.
      if (!doc.$schema) {
        doc.$schema = 'https://schemas.dicsussion.org/v1/chat-room.json';
      }
      if (!doc.doc_id) doc.doc_id = docId;
      if (!doc.meta) {
        doc.meta = { title: docId, createdAt: Math.floor(Date.now() / 1000) };
      }
      if (!doc.messages) doc.messages = {};

      // Automerge rejects `undefined` outright rather than treating it as
      // absent, and both `authorDid` and `nullifierHash` are legitimately
      // absent — an attributed message has no nullifier, an anonymous one
      // has no author. Spreading the object as-is throws on every write.
      doc.messages[message.id] = stripUndefined(message);
    });
  }

  /**
   * Apply remote binary changes received from a peer.
   *
   * @param docId The document UUID.
   * @param binaryChanges Array of binary change byte arrays.
   */
  applyRemoteChanges(docId: string, binaryChanges: Uint8Array[]): void {
    const managed = this.documents.get(docId);
    if (!managed) {
      throw new Error(`Document not found: ${docId}`);
    }

    const [newDoc] = Automerge.applyChanges(managed.doc, binaryChanges);
    managed.doc = newDoc;
    managed.changeCount += binaryChanges.length;
  }

  /**
   * Get the Automerge head hashes for a document (for sync comparison).
   *
   * @param docId The document UUID.
   * @returns Array of head hash strings.
   */
  getHeads(docId: string): string[] {
    const managed = this.documents.get(docId);
    if (!managed) {
      throw new Error(`Document not found: ${docId}`);
    }
    return Automerge.getHeads(managed.doc) as string[];
  }

  /**
   * Generate a compressed binary snapshot of the document.
   * Per RFC 002 §4.4: every 1000 changes or 7 days.
   *
   * @param docId The document UUID.
   * @returns Compressed binary snapshot.
   */
  generateSnapshot(docId: string): Uint8Array {
    const managed = this.documents.get(docId);
    if (!managed) {
      throw new Error(`Document not found: ${docId}`);
    }

    managed.lastSnapshotAt = Date.now();
    managed.changeCount = 0;

    return Automerge.save(managed.doc);
  }

  /**
   * Load a document from a binary snapshot.
   *
   * @param docId The document UUID.
   * @param snapshot Binary snapshot bytes.
   */
  loadFromSnapshot(docId: string, snapshot: Uint8Array): void {
    const doc = Automerge.load<DocumentSchema>(snapshot);
    this.documents.set(docId, {
      doc,
      changeCount: 0,
      lastSnapshotAt: Date.now(),
    });
  }

  /**
   * Check if a document needs snapshotting based on change threshold.
   */
  needsSnapshot(docId: string): boolean {
    const managed = this.documents.get(docId);
    if (!managed) return false;

    const daysSinceSnapshot =
      (Date.now() - managed.lastSnapshotAt) / (1000 * 60 * 60 * 24);

    return (
      managed.changeCount >= SNAPSHOT_CHANGE_THRESHOLD ||
      daysSinceSnapshot >= 7
    );
  }

  /**
   * Get a document for synchronisation, creating an empty one if absent.
   *
   * Uses the same genesis as `createDocument`, so a replica that only
   * ever receives a document shares history with one that created it.
   * An empty `Automerge.init()` here would be a *different* root, which
   * is the conflict this exists to avoid.
   *
   * @param docId The document UUID.
   * @returns The existing or newly created document.
   */
  ensureSyncDocument(docId: string): Automerge.Doc<DocumentSchema> {
    const existing = this.documents.get(docId);
    if (existing) return existing.doc;

    // Refuse to mint beyond the ceiling.
    //
    // This is reached from inbound sync, where `docId` is a value the
    // *peer* chose. Without a bound, a peer can name an unlimited number
    // of documents and each one allocates an Automerge replica that never
    // goes away — memory exhaustion with no malformed frame anywhere and
    // nothing in a log to explain it.
    //
    // Throwing rather than silently ignoring: the sync engine drops
    // frames it cannot handle (RFC 001 §7), so the connection survives,
    // but the failure is visible instead of manifesting as a slow leak.
    if (this.documents.size >= MAX_DOCUMENTS) {
      throw new Error(
        `Document limit reached (${MAX_DOCUMENTS}); refusing to create ${docId}`,
      );
    }

    const doc = this.genesis(docId);
    this.documents.set(docId, {
      doc,
      changeCount: 0,
      lastSnapshotAt: Date.now(),
    });

    return doc;
  }

  /**
   * Replace a document's state after an out-of-band merge.
   *
   * Intended for the sync engine, which advances documents through
   * `Automerge.receiveSyncMessage` rather than through `applyChange`.
   *
   * @param docId The document UUID.
   * @param doc The updated document state.
   */
  replaceDocument(docId: string, doc: Automerge.Doc<DocumentSchema>): void {
    const managed = this.documents.get(docId);

    if (managed) {
      managed.doc = doc;
      managed.changeCount++;
      return;
    }

    this.documents.set(docId, {
      doc,
      changeCount: 1,
      lastSnapshotAt: Date.now(),
    });
  }

  /**
   * Count the messages currently held in a document.
   *
   * Part of the canonical state payload used for root computation
   * (RFC 002 §4.3).
   */
  getMessageCount(docId: string): number {
    const managed = this.documents.get(docId);
    if (!managed) return 0;
    return Object.keys(managed.doc.messages ?? {}).length;
  }

  /**
   * List all active document IDs.
   */
  listDocuments(): string[] {
    return Array.from(this.documents.keys());
  }

  /**
   * Delete a document.
   */
  deleteDocument(docId: string): boolean {
    return this.documents.delete(docId);
  }

  /**
   * Merge two documents (concurrent offline edits).
   *
   * @param docId The document UUID.
   * @param remoteDoc The remote document to merge.
   * @returns The merged document.
   */
  mergeDocument(
    docId: string,
    remoteDoc: Automerge.Doc<DocumentSchema>,
  ): Automerge.Doc<DocumentSchema> {
    const managed = this.documents.get(docId);
    if (!managed) {
      throw new Error(`Document not found: ${docId}`);
    }

    const merged = Automerge.merge(managed.doc, remoteDoc);
    managed.doc = merged;
    return merged;
  }
}

/** Concatenate multiple Uint8Arrays into one. */
function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Drop keys whose value is `undefined`.
 *
 * Automerge distinguishes "absent" from "present but undefined" and
 * refuses the latter, so an optional field left unset must not appear in
 * the object at all. Returns a plain copy — the input is never mutated,
 * because callers reuse their payload after the write.
 */
function stripUndefined<T extends Record<string, unknown>>(value: T): T {
  const out: Record<string, unknown> = {};

  for (const [key, entry] of Object.entries(value)) {
    if (entry !== undefined) out[key] = entry;
  }

  return out as T;
}
