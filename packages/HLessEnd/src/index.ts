/**
 * @dicsussion/sdk
 *
 * Public API surface for the Dicsussion SDK.
 * This is the primary entry point for application frontends.
 */
// Main client
export { DicsussionClient } from './client.js';

export type { ClientRuntimeOptions } from './client.js';
export type { TransportFactory } from './engine-bootstrap.js';
// Services (for advanced usage / testing)
export { ChatService } from './chat-service.js';

export type { ChatServiceDeps } from './chat-service.js';
export { GroupService } from './group-service.js';
export { IdentityService } from './identity-service.js';

export type { LocalIdentity } from './identity-service.js';
export { TrustService } from './trust-service.js';
export { currentEpoch, OutboxManager } from './outbox.js';

export type { FlushResult, OutboxSender } from './outbox.js';
// Peer directory
export { PeerRegistry } from './peer-registry.js';

export type { PeerRecord } from './peer-registry.js';
// Message payload / envelope codec
export {
  decodePayload,
  encodePayload,
  openMessage,
  sealMessage,
} from './message-codec.js';

export type { MessagePayload, OpenedMessage } from './message-codec.js';
// Storage
export {
  DocumentStore,
  IndexedDbDriver,
  MessageStore,
  SQLiteDriver,
} from './storage/index.js';

export type {
  IndexedDbDriverOptions,
  IndexedDbFactoryLike,
} from './storage/index.js';
// Peer sessions & frame routing
export { SessionManager } from './session-manager.js';

export type { SessionManagerDeps } from './session-manager.js';
export { TrustTier } from './wot/types.js';

export type { PeerTrustProfile } from './wot/types.js';

export type {
  ClientConfig,
  GroupInfo,
  GroupInvite,
  Identity,
  NetworkStatus,
  PeerConnectedEvent,
  PeerDisconnectedEvent,
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
