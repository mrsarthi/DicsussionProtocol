/**
 * @dicsussion/crdt
 *
 * Public API surface for the CRDT module.
 */

// Types
export type {
  CanonicalDocState,
  ChatMessage,
  DocumentMeta,
  DocumentSchema,
  LensOperation,
  RequestCRDTDelta,
  RootMatchResponse,
  SchemaLens,
  SendCRDTDelta,
  SparseMerkleRootSync,
  SyncMessage,
} from './types.js';

// Document Manager
export { DocumentManager } from './document-manager.js';

// Schema Lenses
export {
  applyLens,
  clearLensRegistry,
  findLensPath,
  getLens,
  registerLens,
} from './schema-lens.js';

// Stream 0x01 sync message codec (RFC 002 §4.2)
export {
  decodeBoolBody,
  decodeSyncFrame,
  encodeBoolBody,
  encodeSyncFrame,
  MAX_SYNC_BODY_SIZE,
  SyncMessageType,
} from './sync-protocol.js';

export type { SyncFrame, SyncMessageTypeValue } from './sync-protocol.js';

// Canonical state root (RFC 002 §4.3)
export {
  collectDocumentState,
  computeManagerStateRoot,
  computeStateRoot,
  rootsEqual,
} from './state-root.js';

export type { DocumentStateEntry } from './state-root.js';

// Automerge sync engine
export { CrdtSyncEngine } from './sync-engine.js';

export type { DocumentUpdate, DocumentUpdateHandler } from './sync-engine.js';
