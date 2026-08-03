/**
 * @dicsussion/sdk
 *
 * Public API surface for the Dicsussion SDK.
 * This is the primary entry point for application frontends.
 */

// Main client
export { DicsussionClient } from './client.js';
export type { ClientRuntimeOptions } from './client.js';

// SDK types
export type {
  ClientConfig,
  GroupInfo,
  GroupInvite,
  Identity,
  NetworkStatus,
  SdkChatMessage,
  SendMessageOptions,
} from './types.js';

// Services (for advanced usage / testing)
export { ChatService } from './chat-service.js';
export { GroupService } from './group-service.js';
export { IdentityService } from './identity-service.js';
export { TrustService } from './trust-service.js';
export { currentEpoch, OutboxManager } from './outbox.js';
export type { FlushResult, OutboxSender } from './outbox.js';

export type { ChatServiceDeps } from './chat-service.js';
export type { LocalIdentity } from './identity-service.js';

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
export { DocumentStore, MessageStore, SQLiteDriver } from './storage/index.js';

// Peer sessions & frame routing
export { SessionManager } from './session-manager.js';
export type { SessionManagerDeps } from './session-manager.js';

// Re-export WoT types for consumers
export type { PeerTrustProfile } from './wot/types.js';
export { TrustTier } from './wot/types.js';
