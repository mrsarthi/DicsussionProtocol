/**
 * @dicsussion/zk
 *
 * Circom circuit artifacts, witness generation, SnarkJS Groth16 wrapper,
 * and ZK-RLN rate-limiting nullifier engine (RFC 003).
 */
// Slashing polynomial (RFC 003 §4.1)
export {
  evaluateShare,
  findSlashablePair,
  recoverSecret,
  verifyRecovery,
} from './shamir.js';

export type {
  PolynomialShare,
  RecoveryFailure,
  RecoveryResult,
} from './shamir.js';
// RLN signal construction
export {
  createSignal,
  currentEpoch,
  EPOCH_DURATION_S,
  isEpochFresh,
  isWithinQuota,
  messageCommitment,
  quotaForTier,
  ROLLING_WINDOW_EPOCHS,
  signalToShare,
} from './rln.js';

export type { MessageContext, RlnSignal } from './rln.js';
// Groth16 prover over rln_range_unified (RFC 003 §3.4)
export {
  DEV_CEREMONY_MARKER,
  isDevelopmentCeremony,
  toCircuitSignals,
  ZekPocProver,
} from './prover.js';

export type { ProofInput, ProofOutput, ProverArtifacts } from './prover.js';
// Circuit artifact location (src or dist layout)
export { requireArtifacts, resolveArtifacts } from './artifact-paths.js';
// Persistent proof worker pool (RFC 004 §5)
export { DEFAULT_PROOF_TIMEOUT_MS, ProofWorkerPool } from './worker-pool.js';

export type {
  PoolStats,
  ProofExecutor,
  ProofJob,
  WorkerPoolOptions,
} from './worker-pool.js';
