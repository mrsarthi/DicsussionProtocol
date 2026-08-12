/**
 * @dicsussion/zk — browser barrel
 *
 * Same export surface as `index.ts`, minus the two modules that reach for
 * `node:fs`, `node:path`, and `node:url` — `prover.js` and
 * `artifact-paths.js`.
 *
 * ## Why this file exists rather than a `browser: false` mapping
 *
 * `package.json`'s `browser` field mapped those modules to `false`, which
 * yields an **empty module**. That works for a namespace import, and fails
 * for a named one: `import { resolveArtifacts } from '@dicsussion/core/zk'`
 * is checked at resolution, so an empty module is a hard error before any
 * runtime guard can observe `undefined`. The failure also only appeared
 * under esbuild's dependency pre-bundling and not under Rollup, so it
 * survived a passing `vite build` and surfaced only in `vite dev`.
 *
 * Real stub modules that export the real names fix it in every pipeline.
 *
 * ## The rule these stubs follow
 *
 * A stub may return a value only when that value is one the caller is
 * designed to receive. Anything else must throw.
 *
 * `resolveArtifacts()` returns `null` because `null` is its documented
 * "no artifacts here" answer and `DicsussionClient` reads it as "skip ZK".
 * `isDevelopmentCeremony()` throws, because its safe-looking answer —
 * `false`, meaning "this key came from a real ceremony" — is a claim this
 * module cannot substantiate. Returning it would be a fabricated security
 * guarantee, which is worse than an error.
 */

// ─── Unchanged: no Node dependency ───────────────────────────────────────
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

export { DEFAULT_PROOF_TIMEOUT_MS, ProofWorkerPool } from './worker-pool.js';

export type {
  PoolStats,
  ProofExecutor,
  ProofJob,
  WorkerPoolOptions,
} from './worker-pool.js';

// Types are erased at build time, so the real declarations are safe to
// re-export even though their implementations are not.
export type { ProofInput, ProofOutput, ProverArtifacts } from './prover.js';

// ─── Stubbed: `prover.js` and `artifact-paths.js` ────────────────────────

/** Marker filename. Pure data, identical to the Node build. */
export const DEV_CEREMONY_MARKER = 'DEVELOPMENT_ONLY.md';

const UNAVAILABLE =
  'Groth16 proving is not available in browsers: it reads circuit ' +
  'artifacts from the filesystem. Generate proofs in a Node or native ' +
  'host and pass them in, or run over the Iroh transport.';

/**
 * Always `null` in a browser.
 *
 * This is the genuine contract, not a stub's approximation:
 * `resolveArtifacts` returns `null` wherever artifacts cannot be located,
 * and `DicsussionClient.init` treats `null` as "no local proving, carry
 * on". Throwing here would break `init()` even with `zkProofs: 'off'`.
 */
export function resolveArtifacts(): null {
  return null;
}

/** Throws: the caller demanded artifacts, and there are none. */
export function requireArtifacts(): never {
  throw new Error(UNAVAILABLE);
}

/**
 * Throws rather than answering.
 *
 * The tempting stub is `return false` — "not a development ceremony" — and
 * it is exactly the wrong one. That is the answer meaning *the proving key
 * is trustworthy*, and this build cannot check. A caller acting on a
 * fabricated `false` would accept a development key silently, which is the
 * one failure this function exists to prevent.
 */
export function isDevelopmentCeremony(): never {
  throw new Error(
    'isDevelopmentCeremony cannot be evaluated in a browser: it checks for ' +
      `a ${DEV_CEREMONY_MARKER} file beside the proving key. Returning ` +
      'false here would assert a trusted setup this build cannot verify.',
  );
}

/** Throws: witness generation belongs with the prover. */
export function toCircuitSignals(): never {
  throw new Error(UNAVAILABLE);
}

/** Throws on construction, so the failure names its own cause. */
export class ZekPocProver {
  constructor() {
    throw new Error(UNAVAILABLE);
  }
}
