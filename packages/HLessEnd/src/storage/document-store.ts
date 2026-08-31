/**
 * @dicsussion/storage — CRDT Snapshot Store
 *
 * Persists Automerge document snapshots so merged state survives
 * restarts, per RFC 002 §4.4 (periodic checkpointing) and §4.2 step 7
 * (PersistLocalState).
 *
 * Only already-merged state is written here. The canonical state root
 * remains authoritative for reconciliation — this is storage, never a
 * second source of truth (RFC 002 §4.3).
 *
 * Backed by `IStorageDriver` rather than a raw SQLite handle, so the
 * same store works on IndexedDB in a browser. Writes are queued because
 * `checkpoint()` is synchronous by contract; call `flush()` when
 * durability matters — the client does so on disconnect.
 */

import type { DocumentManager } from '@dicsussion/core/crdt';

import { StorageCollections } from './types.js';
import { SecretBox } from './secret-box.js';
import type { IStorageDriver } from './types.js';
import { WriteQueue } from './write-queue.js';

/** A persisted document row. */
export interface StoredDocument {
  readonly docId: string;
  readonly snapshot: Uint8Array;
  /** Comma-joined sorted Automerge heads at time of write. */
  readonly headHash: string;
  readonly messageCount: number;
  readonly updatedAt: number;
}

/**
 * Persistence for Automerge document snapshots.
 */
export class DocumentStore {
  private readonly writes = new WriteQueue();

  /**
   * @param box Encryption at rest. A snapshot contains every message in
   *   the conversation, so sealing message rows and leaving snapshots in
   *   the clear would protect nothing — the same content is in both.
   */
  constructor(
    private readonly storage: IStorageDriver,
    private readonly box: SecretBox = new SecretBox(null),
  ) {}

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
    const record = {
      doc_id: docId,
      // Copied before sealing: the caller may reuse or detach its
      // buffer before the queued write actually runs.
      snapshot: this.box.sealBytes(new Uint8Array(snapshot)),
      head_hash: [...heads].sort().join(','),
      message_count: messageCount,
      updated_at: Math.floor(Date.now() / 1000),
    };

    this.writes.enqueue(() =>
      this.storage.put(StorageCollections.CRDT_DOCUMENTS, docId, record),
    );
  }

  /** Load one document snapshot, or undefined if absent. */
  async load(docId: string): Promise<StoredDocument | undefined> {
    await this.writes.flush();

    const row = await this.storage.get(StorageCollections.CRDT_DOCUMENTS, docId);

    return row ? toStoredDocument(row, this.box) : undefined;
  }

  /** Load every persisted document, newest first. */
  async loadAll(): Promise<StoredDocument[]> {
    await this.writes.flush();

    const rows = await this.storage.query(StorageCollections.CRDT_DOCUMENTS);

    return rows
      .map((row) => toStoredDocument(row, this.box))
      .sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** List persisted document ids. */
  async listDocumentIds(): Promise<string[]> {
    await this.writes.flush();

    const rows = await this.storage.query(StorageCollections.CRDT_DOCUMENTS);

    return rows.map((row) => String(row['doc_id'])).sort();
  }

  /** Delete a persisted document. */
  async delete(docId: string): Promise<boolean> {
    await this.writes.flush();

    return this.storage.delete(StorageCollections.CRDT_DOCUMENTS, docId);
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

  /**
   * Checkpoint every document held by a DocumentManager.
   *
   * Snapshots are taken synchronously, so the returned count describes
   * state at the moment of the call; the writes drain in the background
   * and `flush()` waits for them.
   */
  checkpointAll(documents: DocumentManager): number {
    const ids = documents.listDocuments();
    for (const docId of ids) {
      this.checkpoint(documents, docId);
    }

    return ids.length;
  }

  /**
   * Rehydrate every persisted document into a DocumentManager.
   *
   * @returns The document ids restored.
   */
  async restoreAll(documents: DocumentManager): Promise<string[]> {
    const restored: string[] = [];

    for (const stored of await this.loadAll()) {
      documents.loadFromSnapshot(stored.docId, stored.snapshot);
      restored.push(stored.docId);
    }

    return restored;
  }

  /** Wait for queued snapshot writes to land. */
  async flush(): Promise<void> {
    await this.writes.flush();
  }
}

function toStoredDocument(
  row: Record<string, unknown>,
  box: SecretBox,
): StoredDocument {
  return {
    docId: String(row['doc_id']),
    snapshot: box.openBytes(row['snapshot'] as Uint8Array),
    headHash: String(row['head_hash'] ?? ''),
    messageCount: Number(row['message_count'] ?? 0),
    updatedAt: Number(row['updated_at'] ?? 0),
  };
}
