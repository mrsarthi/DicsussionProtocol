/**
 * @dicsussion/storage — Semantics shared by every storage driver
 *
 * Two drivers backing one interface will diverge unless the parts that
 * shape the *data* are shared rather than reimplemented. Both of these
 * are observable by callers:
 *
 *   - `getPrimaryKeyColumn` decides what `get(collection, key)` matches
 *     on. A driver that guessed differently would silently return
 *     nothing for a key the other driver finds.
 *   - `serializeValue` decides what comes back out. SQLite has no
 *     boolean and no array type, so objects are JSON strings and
 *     booleans are 0/1 — and callers parse accordingly
 *     (`parseMembers(row['peers'])` expects a string). IndexedDB stores
 *     structured clones natively and *could* round-trip a real array,
 *     which is exactly the problem: the same code would then work on
 *     desktop and break in a browser.
 *
 * So the browser driver deliberately stores the SQLite-shaped value.
 * Matching the weaker backend is what keeps one set of callers correct
 * on both.
 */

import { StorageCollections } from './types.js';

/**
 * Reject a collection name that is not one of ours.
 *
 * Table and column names cannot be parameterised in SQL — `better-sqlite3`
 * binds values, not identifiers — so `SQLiteDriver` interpolates the
 * collection straight into the statement. Today every caller passes a
 * `StorageCollections` constant, so nothing is exploitable; this exists
 * so that stays true if a future caller ever forwards something derived
 * from a peer.
 *
 * @throws If the name is not a known collection.
 */
const KNOWN_COLLECTIONS: ReadonlySet<string> = new Set(
  Object.values(StorageCollections),
);

export function assertKnownCollection(collection: string): void {
  if (!KNOWN_COLLECTIONS.has(collection)) {
    throw new Error(
      `Unknown storage collection: ${collection}. Collection names are ` +
        'interpolated into SQL and must come from StorageCollections.',
    );
  }
}

/**
 * Reject a column name that cannot be a plain SQL identifier.
 *
 * Column names are interpolated, not bound — `better-sqlite3` cannot
 * parameterise identifiers. Today they come from internally-built record
 * objects, so nothing hostile reaches here; this is the guard that keeps
 * that true if a future caller passes a key it did not construct.
 */
export function assertSafeColumn(column: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(column)) {
    throw new Error(
      `Unsafe column name: ${column}. Column names are interpolated into ` +
        'SQL and must be plain identifiers.',
    );
  }
}

/** Primary key column for a collection (RFC 004 §4.1). */
export function getPrimaryKeyColumn(collection: string): string {
  const pkMap: Record<string, string> = {
    identity: 'did',
    wot_peers: 'did',
    voucher_redeemed: 'nullifier',
    channel_meta: 'channel_id',
    message_stream: 'id',
    outbox: 'id',
    crdt_documents: 'doc_id',
    voucher_nullifiers: 'nullifier',
    genesis_anchors: 'channel_id',
    peer_profiles: 'did',
    blobs: 'hash',
  };
  return pkMap[collection] ?? 'id';
}

/** Whether a value is binary and must bypass JSON encoding. */
function isBinary(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/** Normalise a value to the shape callers read back. */
export function serializeValue(value: unknown): unknown {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  // Binary first: a Uint8Array is an object, and JSON-encoding one
  // yields `{"0":31,"1":139,…}` — a snapshot or signature mangled into
  // something that still *looks* like data on the way back out.
  if (isBinary(value)) return value;
  if (Array.isArray(value)) return JSON.stringify(value);
  if (typeof value === 'object') return JSON.stringify(value);
  return value;
}

/**
 * Normalise a value read back out of a driver.
 *
 * SQLite hands back Node `Buffer`s and IndexedDB hands back
 * `Uint8Array`s. `Buffer` is a `Uint8Array` subclass so most code would
 * not notice — until something does an `instanceof` check, compares
 * constructors, or structured-clones it. Both are copied into a plain
 * `Uint8Array` so callers see one type.
 */
export function deserializeValue(value: unknown): unknown {
  return isBinary(value) ? new Uint8Array(value) : value;
}

/** Apply `deserializeValue` across a record. */
export function deserializeRecord(
  row: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [column, raw] of Object.entries(row)) {
    out[column] = deserializeValue(raw);
  }
  return out;
}

/** Apply `serializeValue` across a record. */
export function serializeRecord(
  value: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [column, raw] of Object.entries(value)) {
    out[column] = serializeValue(raw);
  }
  return out;
}
