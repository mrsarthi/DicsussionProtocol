/**
 * @dicsussion/sdk/browser — Browser and webview entry point
 *
 * Identical to the main entry except that it never references
 * `SQLiteDriver`.
 *
 * This file exists because of how bundlers work, not because of what
 * runs. The main barrel re-exports `SQLiteDriver`, which statically
 * imports `better-sqlite3` — a NAPI module. A bundler resolving the
 * barrel therefore pulls `better-sqlite3` into the graph and fails on
 * its `require('fs')`, even for an application that only ever
 * constructs an `IndexedDbDriver`. Tree-shaking does not save you: the
 * failure happens at resolution, before anything is shaken.
 *
 * Import from here in a browser:
 *
 * ```ts
 * import { DicsussionClient, IndexedDbDriver } from '@dicsussion/sdk/browser';
 *
 * const client = await DicsussionClient.init(
 *   { storagePath: 'unused' },
 *   {
 *     storage: new IndexedDbDriver(),
 *     transport: 'websocket',
 *     relayUrl: 'wss://relay.example',
 *   },
 * );
 * ```
 *
 * Both options are required. Without `storage` the client falls back to
 * SQLite; without a relay transport it has no way to reach a peer, since
 * a browser can neither open a QUIC socket nor accept an inbound
 * connection.
 */

export { DicsussionClient } from './client.js';
export type { ClientRuntimeOptions } from './client.js';

export { ChatService } from './chat-service.js';
export { GroupService } from './group-service.js';
export { IdentityService } from './identity-service.js';
export { TrustService } from './trust-service.js';

export type { TransportFactory } from './engine-bootstrap.browser.js';
export { IndexedDbDriver } from './storage/indexeddb-driver.js';
export type {
  IndexedDbDriverOptions,
  IndexedDbFactoryLike,
} from './storage/indexeddb-driver.js';

export { StorageCollections } from './storage/types.js';
export type { IStorageDriver } from './storage/types.js';

export { WebSocketTransport } from '@dicsussion/core/transport';
export type {
  WebSocketLike,
  WebSocketTransportOptions,
} from '@dicsussion/core/transport';

export {
  decodeRelayMessage,
  encodeRelayMessage,
  RelayMessageType,
} from '@dicsussion/core/transport';
export type {
  RelayMessage,
  RelayMessageTypeValue,
} from '@dicsussion/core/transport';

export type {
  ClientConfig,
  GroupInfo,
  GroupInvite,
  Identity,
  NetworkStatus,
  PeerConnectedEvent,
  PeerDisconnectedEvent,
  ReactionEvent,
  ReactionSummary,
  SdkChatMessage,
  SendMessageOptions,
} from './types.js';

export type { BlobRef } from './blob-service.js';
export {
  BLOB_CHUNK_BYTES,
  BlobCorruptError,
  BlobTooLargeError,
  BlobUnavailableError,
  MAX_BLOB_BYTES,
} from './blob-service.js';
export type { OpenedSeal, SealedRejection } from './sealed-message.js';
export {
  DEFAULT_MAX_AGE_S,
  MAX_SEALED_BYTES,
} from './sealed-message.js';
export { MAX_REACTION_LENGTH } from './types.js';
export type { PairingRequest } from './pairing-request.js';
export {
  MAX_REQUEST_BYTES,
  MAX_REQUEST_NAME_LENGTH,
} from './pairing-request.js';
export type { PeerProfile, ProfileUpdate } from './profile-service.js';
export {
  MAX_AVATAR_BYTES,
  MAX_BIO_LENGTH,
  MAX_DISPLAY_NAME_LENGTH,
  ProfileTooLargeError,
} from './profile-service.js';

/**
 * Ticket helpers, re-exported for convenience.
 *
 * `connect()` takes a `PeerTicket`, and every application has to move one
 * between devices somehow — so needing a second package import to encode
 * or decode one is friction with no purpose. The canonical definitions
 * live in `@dicsussion/core/transport`; these are the same symbols.
 */
export { decodeTicket, encodeTicket, TICKET_PREFIX } from '@dicsussion/core/transport';
export type { PeerTicket } from '@dicsussion/core/transport';
