import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

import { expect, test } from '@playwright/test';

import { DocumentManager } from '../../packages/core/src/crdt/document-manager.js';
import { DocumentStore } from '../../packages/HLessEnd/src/storage/document-store.js';
import { SQLiteDriver } from '../../packages/HLessEnd/src/storage/sqlite-driver.js';

function testDbPath(): string {
  return join(process.cwd(), `test-docstore-${crypto.randomUUID()}.db`);
}

function cleanupDb(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    const file = dbPath + suffix;
    if (existsSync(file)) {
      try {
        unlinkSync(file);
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}

/** Open an in-memory driver plus a store over it. */
async function openStore(): Promise<{
  store: DocumentStore;
  driver: SQLiteDriver;
}> {
  const driver = new SQLiteDriver(':memory:');
  await driver.initialize();
  return { store: new DocumentStore(driver.getDatabase()), driver };
}

test.describe('Storage — CRDT Document Store', () => {
  test('save and load round-trips a snapshot', async () => {
    const { store, driver } = await openStore();

    try {
      const docs = new DocumentManager();
      docs.createDocument('General', 'doc-1');
      docs.addMessage('doc-1', {
        id: 'm1',
        content: 'persisted',
        timestamp: 1_700_000_000,
        authorDid: 'did:key:zA',
      });

      store.checkpoint(docs, 'doc-1');

      const stored = store.load('doc-1');
      expect(stored).toBeDefined();
      expect(stored!.messageCount).toBe(1);
      expect(stored!.snapshot.length).toBeGreaterThan(0);
      expect(stored!.headHash).not.toBe('');
    } finally {
      await driver.close();
    }
  });

  test('restoreAll rehydrates documents into a fresh manager', async () => {
    const { store, driver } = await openStore();

    try {
      const original = new DocumentManager();
      original.createDocument('General', 'doc-1');
      original.addMessage('doc-1', {
        id: 'm1',
        content: 'survives restart',
        timestamp: 1_700_000_000,
        authorDid: 'did:key:zA',
      });
      original.createDocument('Random', 'doc-2');

      expect(store.checkpointAll(original)).toBe(2);

      const restored = new DocumentManager();
      const ids = store.restoreAll(restored);

      expect(ids.sort()).toEqual(['doc-1', 'doc-2']);
      expect(restored.getDocument('doc-1')!.messages['m1']!.content).toBe(
        'survives restart',
      );
      expect(restored.getMessageCount('doc-1')).toBe(1);
    } finally {
      await driver.close();
    }
  });

  test('saving the same document twice replaces the snapshot', async () => {
    const { store, driver } = await openStore();

    try {
      const docs = new DocumentManager();
      docs.createDocument('General', 'doc-1');

      store.checkpoint(docs, 'doc-1');
      expect(store.load('doc-1')!.messageCount).toBe(0);

      docs.addMessage('doc-1', {
        id: 'm1',
        content: 'later',
        timestamp: 1,
        authorDid: 'did:key:zA',
      });
      store.checkpoint(docs, 'doc-1');

      expect(store.listDocumentIds()).toEqual(['doc-1']);
      expect(store.load('doc-1')!.messageCount).toBe(1);
    } finally {
      await driver.close();
    }
  });

  test('delete removes a persisted document', async () => {
    const { store, driver } = await openStore();

    try {
      const docs = new DocumentManager();
      docs.createDocument('General', 'doc-1');
      store.checkpoint(docs, 'doc-1');

      expect(store.delete('doc-1')).toBe(true);
      expect(store.load('doc-1')).toBeUndefined();
      expect(store.delete('doc-1')).toBe(false);
    } finally {
      await driver.close();
    }
  });

  test('checkpointing an unknown document is rejected', async () => {
    const { store, driver } = await openStore();

    try {
      expect(() => store.checkpoint(new DocumentManager(), 'nope')).toThrow(
        /unknown document/i,
      );
    } finally {
      await driver.close();
    }
  });

  test('snapshots survive closing and reopening the database file', async () => {
    const dbPath = testDbPath();

    try {
      const first = new SQLiteDriver(dbPath);
      await first.initialize();

      const docs = new DocumentManager();
      docs.createDocument('General', 'doc-1');
      docs.addMessage('doc-1', {
        id: 'm1',
        content: 'durable across restarts',
        timestamp: 1_700_000_000,
        authorDid: 'did:key:zA',
      });
      new DocumentStore(first.getDatabase()).checkpointAll(docs);
      await first.close();

      const second = new SQLiteDriver(dbPath);
      await second.initialize();

      const restored = new DocumentManager();
      new DocumentStore(second.getDatabase()).restoreAll(restored);

      expect(restored.getDocument('doc-1')!.messages['m1']!.content).toBe(
        'durable across restarts',
      );

      await second.close();
    } finally {
      cleanupDb(dbPath);
    }
  });
});
