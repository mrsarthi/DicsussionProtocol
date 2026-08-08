/**
 * @dicsussion/storage — SQLite Driver
 *
 * SQLite-based implementation of IStorageDriver using better-sqlite3
 * for desktop runtime persistence per RFC 004 §4.
 */

import Database from 'better-sqlite3';

import {
  assertKnownCollection,
  assertSafeColumn,
  deserializeRecord,
  getPrimaryKeyColumn,
  serializeValue,
} from './driver-shared.js';
import { runMigrations } from './migrations.js';
import type { IStorageDriver } from './types.js';

/**
 * SQLite storage driver for desktop runtimes.
 *
 * Creates all RFC 004 §4.1 tables via migrations and provides
 * generic CRUD operations across collections.
 */
export class SQLiteDriver implements IStorageDriver {
  private db: Database.Database | null = null;

  constructor(private readonly dbPath: string) {}

  async initialize(): Promise<void> {
    this.db = new Database(this.dbPath);

    // Enable WAL mode for better concurrent read performance
    this.db.pragma('journal_mode = WAL');

    // Run schema migrations
    runMigrations(this.db);
  }

  async put(
    collection: string,
    key: string,
    value: Record<string, unknown>,
  ): Promise<void> {
    this.ensureOpen();
    assertKnownCollection(collection);

    const columns = Object.keys(value);
    for (const column of columns) assertSafeColumn(column);

    const placeholders = columns.map(() => '?').join(', ');
    const updates = columns.map((c) => `${c} = excluded.${c}`).join(', ');

    const sql = `
      INSERT INTO ${collection} (${columns.join(', ')})
      VALUES (${placeholders})
      ON CONFLICT DO UPDATE SET ${updates}
    `;

    this.db!.prepare(sql).run(...columns.map((c) => bindable(value[c])));
  }

  async get(
    collection: string,
    key: string,
  ): Promise<Record<string, unknown> | undefined> {
    this.ensureOpen();
    assertKnownCollection(collection);

    // Determine primary key column by collection
    const pkColumn = getPrimaryKeyColumn(collection);
    const sql = `SELECT * FROM ${collection} WHERE ${pkColumn} = ?`;
    const row = this.db!.prepare(sql).get(key) as
      | Record<string, unknown>
      | undefined;

    return row ? deserializeRecord(row) : undefined;
  }

  async delete(collection: string, key: string): Promise<boolean> {
    this.ensureOpen();
    assertKnownCollection(collection);

    const pkColumn = getPrimaryKeyColumn(collection);
    const sql = `DELETE FROM ${collection} WHERE ${pkColumn} = ?`;
    const result = this.db!.prepare(sql).run(key);

    return result.changes > 0;
  }

  async query(
    collection: string,
    filter?: Record<string, unknown>,
    limit?: number,
  ): Promise<Record<string, unknown>[]> {
    this.ensureOpen();
    assertKnownCollection(collection);

    let sql = `SELECT * FROM ${collection}`;
    const params: unknown[] = [];

    if (filter && Object.keys(filter).length > 0) {
      const conditions = Object.entries(filter).map(([col, val]) => {
        assertSafeColumn(col);
        params.push(bindable(val));
        return `${col} = ?`;
      });
      sql += ` WHERE ${conditions.join(' AND ')}`;
    }

    if (limit !== undefined) {
      sql += ` LIMIT ${limit}`;
    }

    return (this.db!.prepare(sql).all(...params) as Record<string, unknown>[]).map(
      deserializeRecord,
    );
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /** Get the underlying database instance for direct queries. */
  getDatabase(): Database.Database {
    this.ensureOpen();
    return this.db!;
  }

  private ensureOpen(): void {
    if (!this.db) {
      throw new Error('SQLite database is not initialized. Call initialize() first.');
    }
  }
}

/**
 * Prepare a value for a better-sqlite3 parameter slot.
 *
 * The driver binds `Buffer` to BLOB but rejects a bare `Uint8Array`, so
 * binary is converted here rather than in `serializeValue` — the shared
 * helper stays backend-neutral and IndexedDB keeps storing the typed
 * array natively.
 */
function bindable(value: unknown): unknown {
  const serialized = serializeValue(value);
  return serialized instanceof Uint8Array
    ? Buffer.from(serialized)
    : serialized;
}
