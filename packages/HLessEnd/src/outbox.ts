/**
 * @dicsussion/sdk — OutboxManager
 *
 * Offline message queue per RFC 004 §7.5. Messages sent while the node
 * is disconnected are queued locally, persisted to SQLite so they
 * survive a restart, and flushed automatically on reconnection.
 *
 * On flush, each entry's proof epoch is refreshed against the current
 * 10-second window: a proof generated before a partition is stale by the
 * time connectivity returns and would be rejected by the peer.
 */

import type { IStorageDriver, OutboxEntry } from './storage/types.js';
import { StorageCollections } from './storage/types.js';

/** Attempts a single delivery. Resolves on success, rejects to retry later. */
export type OutboxSender = (entry: OutboxEntry) => Promise<void>;

/** Outcome of a flush pass. */
export interface FlushResult {
  readonly sent: number;
  readonly failed: number;
}

/** Epoch window length in seconds (RFC 001 §5). */
const EPOCH_DURATION_S = 10;

/**
 * Manages the offline outbox queue for messages pending delivery.
 */
export class OutboxManager {
  private readonly entries = new Map<string, OutboxEntry>();
  private readonly maxSize: number;
  private storage: IStorageDriver | null;

  constructor(maxSize: number = 1000, storage: IStorageDriver | null = null) {
    this.maxSize = maxSize;
    this.storage = storage;
  }

  /** Attach a storage driver so the queue survives restarts. */
  attachStorage(storage: IStorageDriver): void {
    this.storage = storage;
  }

  /**
   * Add a message to the outbox queue.
   * @throws If the outbox is full.
   */
  enqueue(entry: OutboxEntry): void {
    if (this.entries.size >= this.maxSize) {
      throw new Error(`Outbox full: ${this.entries.size} >= ${this.maxSize}`);
    }
    this.entries.set(entry.id, entry);
    void this.persist(entry);
  }

  /**
   * Get all pending entries for delivery, oldest first.
   */
  getPending(): OutboxEntry[] {
    return Array.from(this.entries.values())
      .filter((e) => e.status === 'pending' || e.status === 'failed')
      .sort((a, b) => a.createdAt - b.createdAt);
  }

  /**
   * Mark an entry as currently sending.
   */
  markSending(id: string): void {
    this.updateStatus(id, 'sending');
  }

  /**
   * Mark an entry as successfully sent and remove from queue.
   */
  markSent(id: string): void {
    this.entries.delete(id);
    void this.storage?.delete(StorageCollections.OUTBOX, id).catch(() => undefined);
  }

  /**
   * Mark an entry as failed (will be retried).
   */
  markFailed(id: string): void {
    const entry = this.entries.get(id);
    if (entry) {
      const updated: OutboxEntry = {
        ...entry,
        status: 'failed',
        retryCount: entry.retryCount + 1,
      };
      this.entries.set(id, updated);
      void this.persist(updated);
    }
  }

  /**
   * Deliver every pending entry via `sender`.
   *
   * Called on reconnection. Each entry's `proofEpoch` is regenerated
   * against the current epoch before the attempt, since a proof built
   * before the partition no longer matches the live window.
   *
   * Delivery is sequential so ordering within a channel is preserved.
   *
   * @returns Counts of delivered and still-pending entries.
   */
  async flush(sender: OutboxSender): Promise<FlushResult> {
    const pending = this.getPending();
    let sent = 0;
    let failed = 0;

    for (const entry of pending) {
      const refreshed: OutboxEntry = {
        ...entry,
        status: 'sending',
        proofEpoch: currentEpoch(),
      };
      this.entries.set(entry.id, refreshed);

      try {
        await sender(refreshed);
        this.markSent(entry.id);
        sent++;
      } catch {
        this.markFailed(entry.id);
        failed++;
      }
    }

    return { sent, failed };
  }

  /**
   * Reload persisted entries from storage into memory.
   *
   * @returns The number of entries restored.
   */
  async hydrate(): Promise<number> {
    if (!this.storage) return 0;

    const rows = await this.storage.query(StorageCollections.OUTBOX);
    let restored = 0;

    for (const row of rows) {
      const entry = rowToEntry(row);
      if (!entry || this.entries.size >= this.maxSize) continue;
      this.entries.set(entry.id, entry);
      restored++;
    }

    return restored;
  }

  /**
   * Get the current queue size.
   */
  get size(): number {
    return this.entries.size;
  }

  /**
   * Clear all entries.
   */
  clear(): void {
    this.entries.clear();
  }

  private updateStatus(id: string, status: OutboxEntry['status']): void {
    const entry = this.entries.get(id);
    if (entry) {
      const updated: OutboxEntry = { ...entry, status };
      this.entries.set(id, updated);
      void this.persist(updated);
    }
  }

  /**
   * Mirror an entry into SQLite.
   *
   * Persistence is best-effort: the in-memory queue remains correct even
   * if the write fails, so a storage error must not fail the send path.
   */
  private async persist(entry: OutboxEntry): Promise<void> {
    if (!this.storage) return;

    try {
      await this.storage.put(StorageCollections.OUTBOX, entry.id, {
        id: entry.id,
        channel_id: entry.channelId,
        content: entry.content,
        created_at: entry.createdAt,
        status: entry.status,
        proof_epoch: entry.proofEpoch ?? null,
        retry_count: entry.retryCount,
      });
    } catch {
      // Non-fatal — see doc comment.
    }
  }
}

/** The current 10-second epoch. */
export function currentEpoch(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 1000 / EPOCH_DURATION_S);
}

/** Convert a SQLite row back into an OutboxEntry, or null if malformed. */
function rowToEntry(row: Record<string, unknown>): OutboxEntry | null {
  const id = row['id'];
  const channelId = row['channel_id'];
  const content = row['content'];
  const createdAt = row['created_at'];
  const status = row['status'];

  if (
    typeof id !== 'string' ||
    typeof channelId !== 'string' ||
    typeof content !== 'string' ||
    typeof createdAt !== 'number'
  ) {
    return null;
  }

  const proofEpoch = row['proof_epoch'];
  const retryCount = row['retry_count'];

  return {
    id,
    channelId,
    content,
    createdAt,
    status: isOutboxStatus(status) ? status : 'pending',
    proofEpoch: typeof proofEpoch === 'number' ? proofEpoch : undefined,
    retryCount: typeof retryCount === 'number' ? retryCount : 0,
  };
}

function isOutboxStatus(value: unknown): value is OutboxEntry['status'] {
  return (
    value === 'pending' ||
    value === 'sending' ||
    value === 'failed' ||
    value === 'sent'
  );
}
