/**
 * @dicsussion/wot
 *
 * Public API surface for the Web-of-Trust module.
 */
export { TIER_QUOTA, TIER_THRESHOLDS, TrustTier } from './types.js';

export type { PeerTrustProfile } from './types.js';
export { buildProfile, calculateScore, scoreTier } from './score-calculator.js';
// Verified bidirectional sessions (RFC 004 §6.2)
export {
  MIN_SESSION_DURATION_S,
  MIN_SESSION_EPOCHS,
  SESSION_COOLDOWN_S,
  SessionTracker,
} from './session-tracker.js';

export type {
  SessionBlocker,
  SessionEvaluation,
  SessionMessage,
  SessionTrackerOptions,
} from './session-tracker.js';
// Counter persistence (RFC 004 §4.1)
export { TrustStore } from './trust-store.js';

export type { TrustCounters } from './trust-store.js';
// Blind endorsement vouchers (RFC 003 §5)
export {
  DEFAULT_ISSUANCE_QUOTA,
  VOUCHER_ISSUE_COST,
  VOUCHER_REDEEM_VALUE,
  VoucherService,
} from './voucher-service.js';

export type {
  IssuanceRecord,
  PendingVoucher,
  RedemptionResult,
  VoucherServiceOptions,
  VoucherToken,
} from './voucher-service.js';
// Stream 0x04 handshake codec
export {
  decodeVoucherMessage,
  encodeVoucherMessage,
  MAX_VOUCHER_BODY,
  VoucherMessageType,
  VoucherRejectReason,
} from './voucher-protocol.js';

export type {
  VoucherMessage,
  VoucherMessageTypeValue,
  VoucherReject,
  VoucherRejectReasonValue,
  VoucherRequest,
  VoucherResponse,
} from './voucher-protocol.js';
// Stream 0x04 handshake driver
export {
  VOUCHER_HANDSHAKE_TIMEOUT_MS,
  VoucherHandshake,
} from './voucher-handshake.js';

export type { VoucherHandshakeDeps } from './voucher-handshake.js';
// Trust stack assembly
export { createTrustStack } from './trust-bootstrap.js';

export type {
  TrustIdentity,
  TrustStack,
  TrustStackOptions,
} from './trust-bootstrap.js';
// Channel Creator Genesis Anchor
export {
  bootstrapFromAnchor,
  createGenesisAnchor,
  encodeAnchorForSigning,
  verifyGenesisAnchor,
} from './genesis-anchor.js';

export type { GenesisAnchor } from './genesis-anchor.js';
// Nullifier & anchor persistence
export { VoucherStore } from './voucher-store.js';

export type { SpentNullifier } from './voucher-store.js';
