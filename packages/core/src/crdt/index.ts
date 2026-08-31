/**
 * @dicsussion/crdt
 *
 * Public API surface for the CRDT module.
 */
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
// Bounded sparse Merkle tree, D=16 (RFC 002 §4.1)
export {
  buildLevels,
  computeRoot,
  EMPTY_LEAF,
  emptyRoot,
  generateProof,
  MAX_LEAVES,
  proofFromLevels,
  rootFromLevels,
  TREE_DEPTH,
  verifyProof,
  zeroHashes,
} from './sparse-merkle-tree.js';

export type { MerkleProof, TreeLevels } from './sparse-merkle-tree.js';
// Bounded identity membership set with LRU eviction
export {
  BoundedMembershipTree,
  DEFAULT_MAX_MEMBERS,
  MEMBERSHIP_ROOT_VERSION,
} from './membership-tree.js';

export type { InsertResult, MemberRecord } from './membership-tree.js';
// Channel membership reconciliation (Stream 0x01)
export { MembershipSyncEngine } from './membership-sync.js';

export type {
  MembershipResolver,
  MembershipUpdate,
  MembershipUpdateHandler,
} from './membership-sync.js';
export {
  decodeDepartureBody,
  decodeMemberListBody,
  decodeMemberRootBody,
  encodeDepartureBody,
  encodeMemberListBody,
  encodeMemberRootBody,
  MAX_DEPARTURES_PER_FRAME,
  MAX_MEMBERS_PER_FRAME,
} from './sync-protocol.js';
// Signed membership departures (the 2P-set's remove half)
export {
  createDeparture,
  DepartureSet,
  encodeDepartureForSigning,
  verifyDeparture,
} from './membership-departure.js';

export type { DepartureRecord } from './membership-departure.js';

export type {
  CanonicalDocState,
  ChatMessage,
  ChatReaction,
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
