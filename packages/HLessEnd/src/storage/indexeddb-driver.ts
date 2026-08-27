/**
 * @dicsussion/storage — IndexedDB Driver
 *
 * Browser-side `IStorageDriver` for SDK consumers building web apps
 * (RFC 004 §4). EchoIt targets phones and desktop and uses SQLite; this
 * exists so a third-party browser developer is not blocked on a backend
 * that cannot load `better-sqlite3`.
 *
 * **Semantics are deliberately matched to the SQLite driver**, down to
 * storing JSON strings where IndexedDB could hold real objects — see
 * `driver-shared.ts`. A driver that round-tripped richer values would
 * make caller code that works on desktop fail in a browser.
 *
 * The storage layer is fully backend-neutral: every store now runs on
 * `IStorageDriver`, so this driver serves the whole SDK. Storage is no
 * longer what blocks a browser client — transport, `node:crypto`, and
 * filesystem artifact loading all still do. See
 * `docs/CAPABILITY_MATRIX.md`.
 */

import {
  deserializeRecord,
  getPrimaryKeyColumn,
  serializeRecord,
  serializeValue,
} from './driver-shared.js';
import { StorageCollections } from './types.js';
import type { IStorageDriver } from './types.js';

/**
 * Schema version; bump when the object-store set changes.
 *
 * 2 added `peer_profiles` and `blobs`. Without the bump
 * `onupgradeneeded` never fires for an existing database, so those
 * stores are missing and every read of them throws — on upgraded
 * installs only, never on a fresh one.
 */
export const INDEXEDDB_SCHEMA_VERSION = 2;

/** Default database name. */
export const DEFAULT_DATABASE_NAME = 'dicsussion';

/*
 * IndexedDB types are declared structurally rather than pulled from the
 * DOM lib. Adding `"lib": ["DOM"]` to a Node package would put `window`
 * and `document` in scope across the whole SDK, and re-declaring the
 * real global names would collide with consumers who *do* compile with
 * DOM. Structural types with local names avoid both.
 */

/** A pending IndexedDB operation. */
export interface IdbRequestLike<T> {
  result: T;
  error: unknown;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
}

/** An open-database request, which also reports schema upgrades. */
export interface IdbOpenRequestLike extends IdbRequestLike<IdbDatabaseLike> {
  onupgradeneeded: (() => void) | null;
  onblocked: (() => void) | null;
}

/** The subset of an object store this driver uses. */
export interface IdbObjectStoreLike {
  put(value: unknown): IdbRequestLike<unknown>;
  get(key: string): IdbRequestLike<unknown>;
  delete(key: string): IdbRequestLike<unknown>;
  getAll(): IdbRequestLike<unknown[]>;
}

export interface IdbTransactionLike {
  objectStore(name: string): IdbObjectStoreLike;
}

export interface IdbDatabaseLike {
  objectStoreNames: { contains(name: string): boolean };
  createObjectStore(
    name: string,
    options?: { keyPath?: string },
  ): IdbObjectStoreLike;
  transaction(name: string, mode: 'readonly' | 'readwrite'): IdbTransactionLike;
  close(): void;
}

/**
 * Minimal surface we need from the IndexedDB global.
 *
 * Injectable so the driver is testable under Node without pretending a
 * browser exists, and so an embedder can supply a shim.
 */
export interface IndexedDbFactoryLike {
  open(name: string, version?: number): IdbOpenRequestLike;
}

export interface IndexedDbDriverOptions {
  /** Database name (default: `dicsussion`). */
  readonly databaseName?: string;
  /** IndexedDB implementation; defaults to `globalThis.indexedDB`. */
  readonly factory?: IndexedDbFactoryLike;
}

/** Every collection gets an object store keyed by its primary key. */
const COLLECTIONS: readonly string[] = Object.values(StorageCollections);

/**
 * IndexedDB-backed storage driver.
 */
export class IndexedDbDriver implements IStorageDriver {
  private db: IdbDatabaseLike | null = null;
  private readonly databaseName: string;
  private readonly factory: IndexedDbFactoryLike;

  constructor(options: IndexedDbDriverOptions = {}) {
    this.databaseName = options.databaseName ?? DEFAULT_DATABASE_NAME;

    const factory =
      options.factory ??
      (globalThis as { indexedDB?: IndexedDbFactoryLike }).indexedDB;
    if (!factory) {
      throw new Error(
        'No IndexedDB implementation available. Pass `factory` explicitly ' +
          'when running outside a browser.',
      );
    }
    this.factory = factory;
  }

  /**
   * Open the database, creating object stores on first use.
   *
   * There is no migration runner here: unlike SQLite the schema is just
   * the set of object stores, and `onupgradeneeded` creates any that are
   * missing. Record shape is enforced by the callers, as it is on the
   * SQLite side once migrations have run.
   */
  async initialize(): Promise<void> {
    this.db = await new Promise<IdbDatabaseLike>((resolve, reject) => {
      const request = this.factory.open(
        this.databaseName,
        INDEXEDDB_SCHEMA_VERSION,
      );

      request.onupgradeneeded = () => {
        const db = request.result;
        for (const collection of COLLECTIONS) {
          if (!db.objectStoreNames.contains(collection)) {
            db.createObjectStore(collection, {
              keyPath: getPrimaryKeyColumn(collection),
            });
          }
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          (request.error as Error | null) ??
            new Error('Failed to open IndexedDB'),
        );
      request.onblocked = () =>
        reject(
          new Error(
            `IndexedDB "${this.databaseName}" is blocked by another open ` +
              'connection; close other tabs holding it.',
          ),
        );
    });
  }

  async put(
    collection: string,
    key: string,
    value: Record<string, unknown>,
  ): Promise<void> {
    const store = this.storeFor(collection, 'readwrite');

    // The key column must be present and must match `key`, or an
    // in-line-keyed store rejects the write. Callers of the SQLite
    // driver may pass the key only as the argument, so fill it in.
    const record = serializeRecord(value);
    record[getPrimaryKeyColumn(collection)] = key;

    await promisify(store.put(record));
  }

  async get(
    collection: string,
    key: string,
  ): Promise<Record<string, unknown> | undefined> {
    const store = this.storeFor(collection, 'readonly');
    const row = await promisify(store.get(key));

    return row === undefined
      ? undefined
      : deserializeRecord(row as Record<string, unknown>);
  }

  async delete(collection: string, key: string): Promise<boolean> {
    const store = this.storeFor(collection, 'readwrite');

    // IndexedDB's delete resolves identically whether or not anything
    // matched, but the interface promises "was something removed", so
    // the existence check is required rather than defensive.
    const existing = await promisify(store.get(key));
    if (existing === undefined) return false;

    await promisify(store.delete(key));
    return true;
  }

  /**
   * Read a collection, optionally filtered.
   *
   * IndexedDB has no WHERE clause, so filtering happens after the read.
   * The collections here are bounded by channel and message counts on a
   * single device, so a scan is acceptable; if a store ever grows
   * unbounded this is the line that needs an index.
   */
  async query(
    collection: string,
    filter?: Record<string, unknown>,
    limit?: number,
  ): Promise<Record<string, unknown>[]> {
    const store = this.storeFor(collection, 'readonly');
    const all = (await promisify(store.getAll())) as Record<string, unknown>[];

    let rows = all;

    if (filter && Object.keys(filter).length > 0) {
      const conditions = Object.entries(filter).map(
        ([column, value]) => [column, serializeValue(value)] as const,
      );
      rows = rows.filter((row) =>
        conditions.every(([column, value]) => row[column] === value),
      );
    }

    const capped = limit !== undefined ? rows.slice(0, limit) : rows;
    return capped.map(deserializeRecord);
  }

  async close(): Promise<void> {
    this.db?.close();
    this.db = null;
  }

  private storeFor(
    collection: string,
    mode: 'readonly' | 'readwrite',
  ): IdbObjectStoreLike {
    if (!this.db) {
      throw new Error(
        'IndexedDB database is not initialized. Call initialize() first.',
      );
    }
    if (!this.db.objectStoreNames.contains(collection)) {
      throw new Error(`Unknown storage collection: ${collection}`);
    }

    return this.db.transaction(collection, mode).objectStore(collection);
  }
}

/** Adapt an IndexedDB request to a promise. */
function promisify<T>(request: IdbRequestLike<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(
        (request.error as Error | null) ??
          new Error('IndexedDB request failed'),
      );
  });
}
