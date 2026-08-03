import { test, expect } from '@playwright/test';
import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

/** Generate a unique test DB path to avoid lock contention in parallel tests. */
function testDbPath(): string {
  return join(process.cwd(), 'tests', `test-storage-${randomUUID()}.db`);
}

test.describe('Storage — SQLite Driver', () => {
  test('initialize creates all tables', async () => {
    const dbPath = testDbPath();
    try {
      const { SQLiteDriver } = await import(
        '../../packages/HLessEnd/src/storage/sqlite-driver.js'
      );

      const driver = new SQLiteDriver(dbPath);
      await driver.initialize();

      const db = driver.getDatabase();
      const tables = db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )
        .all() as { name: string }[];

      const tableNames = tables.map((t) => t.name);
      expect(tableNames).toContain('identity');
      expect(tableNames).toContain('wot_peers');
      expect(tableNames).toContain('voucher_redeemed');
      expect(tableNames).toContain('channel_meta');
      expect(tableNames).toContain('message_stream');
      expect(tableNames).toContain('outbox');
      expect(tableNames).toContain('_migrations');

      await driver.close();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('put and get round-trip', async () => {
    const dbPath = testDbPath();
    try {
      const { SQLiteDriver } = await import(
        '../../packages/HLessEnd/src/storage/sqlite-driver.js'
      );

      const driver = new SQLiteDriver(dbPath);
      await driver.initialize();

      await driver.put('channel_meta', 'ch-1', {
        channel_id: 'ch-1',
        title: 'General',
        peers: ['did:key:z6M...'],
        access_threshold: 50,
        created_at: Math.floor(Date.now() / 1000),
        last_activity: Math.floor(Date.now() / 1000),
      });

      const result = await driver.get('channel_meta', 'ch-1');
      expect(result).toBeDefined();
      expect(result!['title']).toBe('General');
      expect(result!['access_threshold']).toBe(50);

      await driver.close();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('delete removes a record', async () => {
    const dbPath = testDbPath();
    try {
      const { SQLiteDriver } = await import(
        '../../packages/HLessEnd/src/storage/sqlite-driver.js'
      );

      const driver = new SQLiteDriver(dbPath);
      await driver.initialize();

      await driver.put('channel_meta', 'ch-del', {
        channel_id: 'ch-del',
        title: 'Delete Me',
        peers: [],
        access_threshold: 0,
        created_at: 0,
        last_activity: 0,
      });

      const deleted = await driver.delete('channel_meta', 'ch-del');
      expect(deleted).toBe(true);

      const result = await driver.get('channel_meta', 'ch-del');
      expect(result).toBeUndefined();

      await driver.close();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('query with filter', async () => {
    const dbPath = testDbPath();
    try {
      const { SQLiteDriver } = await import(
        '../../packages/HLessEnd/src/storage/sqlite-driver.js'
      );

      const driver = new SQLiteDriver(dbPath);
      await driver.initialize();

      await driver.put('outbox', 'out-1', {
        id: 'out-1',
        channel_id: 'ch-1',
        content: 'msg 1',
        created_at: 1,
        status: 'pending',
        retry_count: 0,
      });
      await driver.put('outbox', 'out-2', {
        id: 'out-2',
        channel_id: 'ch-1',
        content: 'msg 2',
        created_at: 2,
        status: 'sent',
        retry_count: 0,
      });

      const pending = await driver.query('outbox', { status: 'pending' });
      expect(pending.length).toBe(1);
      expect(pending[0]!['id']).toBe('out-1');

      await driver.close();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('message_stream allows nullable author_did', async () => {
    const dbPath = testDbPath();
    try {
      const { SQLiteDriver } = await import(
        '../../packages/HLessEnd/src/storage/sqlite-driver.js'
      );

      const driver = new SQLiteDriver(dbPath);
      await driver.initialize();

      // Insert parent channel first (FK constraint)
      await driver.put('channel_meta', 'ch-1', {
        channel_id: 'ch-1',
        title: 'Anonymous Channel',
        peers: [],
        access_threshold: 0,
        created_at: 0,
        last_activity: 0,
      });

      await driver.put('message_stream', 'msg-anon', {
        id: 'msg-anon',
        channel_id: 'ch-1',
        content: 'anonymous message',
        timestamp: Date.now(),
        epoch: 1,
        verified_tier: 0,
      });

      const result = await driver.get('message_stream', 'msg-anon');
      expect(result).toBeDefined();
      expect(result!['author_did']).toBeNull();

      await driver.close();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('migrations are idempotent', async () => {
    const dbPath = testDbPath();
    try {
      const { SQLiteDriver } = await import(
        '../../packages/HLessEnd/src/storage/sqlite-driver.js'
      );
      const { migrations: defined } = await import(
        '../../packages/HLessEnd/src/storage/migrations.js'
      );

      // Initialize twice — should not throw
      const driver1 = new SQLiteDriver(dbPath);
      await driver1.initialize();
      await driver1.close();

      const driver2 = new SQLiteDriver(dbPath);
      await driver2.initialize();

      const applied = driver2
        .getDatabase()
        .prepare('SELECT version FROM _migrations ORDER BY version')
        .all() as { version: number }[];

      // Each migration is applied exactly once, however many exist.
      expect(applied.map((r) => r.version)).toEqual(defined.map((m) => m.version));

      await driver2.close();
    } finally {
      cleanupDb(dbPath);
    }
  });
});

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
