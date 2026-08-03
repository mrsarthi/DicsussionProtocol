/**
 * @dicsussion/storage — CRDT Snapshot Store
 *
 * Persists Automerge document snapshots to SQLite so merged state
 * survives restarts, per RFC 002 §4.4 (periodic checkpointing) and
 * §4.2 step 7 (PersistLocalState).
 *
 * Only already-merged state is written here. The canonical state root
 * remains authoritative for reconciliation — this table is storage,
 * never a second source of truth (RFC 002 §4.3).
 */

import type Database from 'better-sqlite3';

import type { DocumentManager } from '../../../core/src/crdt/document-manager.js';

/** A persisted document row. */
export interface StoredDocument {
  readonly docId: string;
  readonly snapshot: Uint8Array;
  /** Comma-joined sorted Automerge heads at time of write. */
  readonly headHash: string;
  readonly messageCount: number;
  readonly updatedAt: number;
}

/** Row shape as returned by better-sqlite3. */
interface DocumentRow {
  doc_id: string;
  snapshot: Buffer;
  head_hash: string;
  message_count: number;
  updated_at: number;
}

/**
 * SQLite-backed persistence for Automerge document snapshots.
 */
export class DocumentStore {
  constructor(private readonly db: Database.Database) {}

  /**
   * Write (or replace) a document snapshot.
   *
   * @param docId The document UUID.
   * @param snapshot Binary output of `Automerge.save()`.
   * @param heads Automerge head hashes at time of save.
   * @param messageCount Messages held in the document.
   */
  save(
    docId: string,
    snapshot: Uint8Array,
    heads: readonly string[],
    messageCount: number,
  ): void {
    const headHash = [...heads].sort().join(',');

    this.db
      .prepare(
        `INSERT INTO crdt_documents
           (doc_id, snapshot, head_hash, message_count, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(doc_id) DO UPDATE SET
           snapshot = excluded.snapshot,
           head_hash = excluded.head_hash,
           message_count = excluded.message_count,
           updated_at = excluded.updated_at`,
      )
      .run(
        docId,
        Buffer.from(snapshot),
        headHash,
        messageCount,
        Math.floor(Date.now() / 1000),
      );
  }

  /** Load one document snapshot, or undefined if absent. */
  load(docId: string): StoredDocument | undefined {
    const row = this.db
      .prepare('SELECT * FROM crdt_documents WHERE doc_id = ?')
      .get(docId) as DocumentRow | undefined;

    return row ? toStoredDocument(row) : undefined;
  }

  /** Load every persisted document. */
  loadAll(): StoredDocument[] {
    const rows = this.db
      .prepare('SELECT * FROM crdt_documents ORDER BY updated_at DESC')
      .all() as DocumentRow[];

    return rows.map(toStoredDocument);
  }

  /** List persisted document ids without materialising snapshots. */
  listDocumentIds(): string[] {
    const rows = this.db
      .prepare('SELECT doc_id FROM crdt_documents ORDER BY doc_id')
      .all() as { doc_id: string }[];

    return rows.map((r) => r.doc_id);
  }

  /** Delete a persisted document. */
  delete(docId: string): boolean {
    const result = this.db
      .prepare('DELETE FROM crdt_documents WHERE doc_id = ?')
      .run(docId);

    return result.changes > 0;
  }

  /**
   * Checkpoint one document from a DocumentManager.
   *
   * @param documents The in-memory document manager.
   * @param docId The document to persist.
   */
  checkpoint(documents: DocumentManager, docId: string): void {
    if (!documents.hasDocument(docId)) {
      throw new Error(`Cannot checkpoint unknown document: ${docId}`);
    }

    this.save(
      docId,
      documents.generateSnapshot(docId),
      documents.getHeads(docId),
      documents.getMessageCount(docId),
    );
  }

  /** Checkpoint every document held by a DocumentManager. */
  checkpointAll(documents: DocumentManager): number {
    const ids = documents.listDocuments();
    const persist = this.db.transaction(() => {
      for (const docId of ids) {
        this.checkpoint(documents, docId);
      }
    });

    persist();
    return ids.length;
  }

  /**
   * Rehydrate every persisted document into a DocumentManager.
   *
   * @returns The document ids restored.
   */
  restoreAll(documents: DocumentManager): string[] {
    const restored: string[] = [];

    for (const stored of this.loadAll()) {
      documents.loadFromSnapshot(stored.docId, stored.snapshot);
      restored.push(stored.docId);
    }

    return restored;
  }
}

function toStoredDocument(row: DocumentRow): StoredDocument {
  return {
    docId: row.doc_id,
    // Copy out of the Buffer so callers get a plain, detached Uint8Array.
    snapshot: new Uint8Array(row.snapshot),
    headHash: row.head_hash,
    messageCount: row.message_count,
    updatedAt: row.updated_at,
  };
}
