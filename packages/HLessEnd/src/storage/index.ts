/**
 * @dicsussion/storage
 *
 * Public API surface for the storage module.
 */

export type {
  ChannelMetaRecord,
  IdentityRecord,
  IStorageDriver,
  MessageRecord,
  OutboxEntry,
  VoucherRecord,
  WotPeerRecord,
} from './types.js';

export { StorageCollections } from './types.js';

export { runMigrations } from './migrations.js';
export type { Migration } from './migrations.js';

export { SQLiteDriver } from './sqlite-driver.js';

export { DocumentStore } from './document-store.js';
export type { StoredDocument } from './document-store.js';

export { MessageStore } from './message-store.js';
