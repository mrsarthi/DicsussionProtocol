/**
 * @dicsussion/storage — SQLite Driver
 *
 * SQLite-based implementation of IStorageDriver using better-sqlite3
 * for desktop runtime persistence per RFC 004 §4.
 */

import Database from 'better-sqlite3';

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

    const columns = Object.keys(value);
    const placeholders = columns.map(() => '?').join(', ');
    const updates = columns.map((c) => `${c} = excluded.${c}`).join(', ');

    const sql = `
      INSERT INTO ${collection} (${columns.join(', ')})
      VALUES (${placeholders})
      ON CONFLICT DO UPDATE SET ${updates}
    `;

    this.db!.prepare(sql).run(...columns.map((c) => serializeValue(value[c])));
  }

  async get(
    collection: string,
    key: string,
  ): Promise<Record<string, unknown> | undefined> {
    this.ensureOpen();

    // Determine primary key column by collection
    const pkColumn = getPrimaryKeyColumn(collection);
    const sql = `SELECT * FROM ${collection} WHERE ${pkColumn} = ?`;
    const row = this.db!.prepare(sql).get(key) as Record<string, unknown> | undefined;

    return row ?? undefined;
  }

  async delete(collection: string, key: string): Promise<boolean> {
    this.ensureOpen();

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

    let sql = `SELECT * FROM ${collection}`;
    const params: unknown[] = [];

    if (filter && Object.keys(filter).length > 0) {
      const conditions = Object.entries(filter).map(([col, val]) => {
        params.push(serializeValue(val));
        return `${col} = ?`;
      });
      sql += ` WHERE ${conditions.join(' AND ')}`;
    }

    if (limit !== undefined) {
      sql += ` LIMIT ${limit}`;
    }

    return this.db!.prepare(sql).all(...params) as Record<string, unknown>[];
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

/** Map collection names to their primary key columns. */
function getPrimaryKeyColumn(collection: string): string {
  const pkMap: Record<string, string> = {
    identity: 'did',
    wot_peers: 'did',
    voucher_redeemed: 'nullifier',
    channel_meta: 'channel_id',
    message_stream: 'id',
    outbox: 'id',
  };
  return pkMap[collection] ?? 'id';
}

/** Serialize a value for SQLite storage. */
function serializeValue(value: unknown): unknown {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (Array.isArray(value)) return JSON.stringify(value);
  if (typeof value === 'object') return JSON.stringify(value);
  return value;
}
