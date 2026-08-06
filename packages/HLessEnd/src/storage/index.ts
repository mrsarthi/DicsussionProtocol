/**
 * @dicsussion/storage
 *
 * Public API surface for the storage module.
 */
export { StorageCollections } from './types.js';

export type {
  ChannelMetaRecord,
  IdentityRecord,
  IStorageDriver,
  MessageRecord,
  OutboxEntry,
  VoucherRecord,
  WotPeerRecord,
} from './types.js';
export { runMigrations } from './migrations.js';

export type { Migration } from './migrations.js';
export { SQLiteDriver } from './sqlite-driver.js';
export { DocumentStore } from './document-store.js';

export type { StoredDocument } from './document-store.js';
export { MessageStore } from './message-store.js';
// Browser persistence for SDK consumers (RFC 004 §4)
export {
  DEFAULT_DATABASE_NAME,
  IndexedDbDriver,
  INDEXEDDB_SCHEMA_VERSION,
} from './indexeddb-driver.js';

export type {
  IdbDatabaseLike,
  IdbObjectStoreLike,
  IdbOpenRequestLike,
  IdbRequestLike,
  IdbTransactionLike,
  IndexedDbDriverOptions,
  IndexedDbFactoryLike,
} from './indexeddb-driver.js';
// Shared driver semantics — exported so a third-party driver can match
// them rather than guess.
export {
  getPrimaryKeyColumn,
  serializeRecord,
  serializeValue,
} from './driver-shared.js';
