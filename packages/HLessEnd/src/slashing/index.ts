/**
 * @dicsussion/slashing
 *
 * RLN double-spend detection, revocation tombstones, and the
 * Stream 0x03 / 0x06 gossip codecs (RFC 003 §7, §8).
 */

export { SlashingCoordinator } from './slashing-coordinator.js';
export type {
  SlashingCoordinatorDeps,
  SlashingEvent,
} from './slashing-coordinator.js';

export { ShareCollector } from './share-collector.js';
export type {
  ObservedShare,
  ShareCollectorOptions,
  SlashingEvidence,
} from './share-collector.js';

export {
  createSlashingTombstone,
  createUserRevocation,
  encodeTombstoneForSigning,
  RevocationReason,
  verifyTombstone,
} from './tombstone.js';

export type {
  DoubleSpendProof,
  RevocationReasonValue,
  RevocationTombstone,
  TombstoneRejection,
  TombstoneVerdict,
} from './tombstone.js';

export {
  decodeShareMessage,
  decodeTombstone,
  encodeShare,
  encodeShareBatch,
  encodeTombstone,
  MAX_GOSSIP_BODY,
  MAX_SHARE_BATCH,
  RevocationMessageType,
  ShareMessageType,
} from './gossip-protocol.js';
