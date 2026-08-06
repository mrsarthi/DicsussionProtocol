/**
 * @dicsussion/storage — Serialised background writes
 *
 * `IStorageDriver` is async because IndexedDB cannot be otherwise, but
 * several callers are synchronous and must stay so: `checkpoint()`
 * returns a count, `saveGenesisAnchor()` returns void, and
 * `onNullifierSpent` is a callback the voucher service invokes inline.
 * Making those async would push `await` through the public API for a
 * reason that is purely a storage-backend detail.
 *
 * So writes are enqueued and drained in order, and callers that need
 * durability call `flush()`. Ordering matters as much as completion: two
 * writes to the same key must land in the order they were issued, which
 * a bare `void promise` per write does not guarantee.
 */

/** Serialises async writes issued from synchronous call sites. */
export class WriteQueue {
  private tail: Promise<void> = Promise.resolve();
  private failure: Error | null = null;

  /**
   * Append a write.
   *
   * A rejection is captured rather than becoming an unhandled rejection,
   * and re-thrown from the next `flush()` — losing a persistence error
   * silently is how a store ends up quietly not storing anything.
   */
  enqueue(write: () => Promise<void>): void {
    this.tail = this.tail.then(
      async () => {
        try {
          await write();
        } catch (error) {
          this.failure ??=
            error instanceof Error ? error : new Error(String(error));
        }
      },
      () => undefined,
    );
  }

  /**
   * Wait for every queued write to land.
   *
   * @throws The first error seen since the last flush.
   */
  async flush(): Promise<void> {
    await this.tail;

    if (this.failure) {
      const error = this.failure;
      this.failure = null;
      throw error;
    }
  }

  /** Whether a write has failed since the last flush. */
  get hasFailure(): boolean {
    return this.failure !== null;
  }
}
