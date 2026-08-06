/**
 * @dicsussion/zk — Circuit artifact resolution
 *
 * The proving key, verification key, and witness generator are data
 * files, not code, so they do not move through TypeScript compilation.
 * A consumer who installs the package gets `dist/` but the artifacts
 * still live under `src/zk/`, and the same code has to find them whether
 * it is running from source (tests) or from a build (installed SDK).
 *
 * Resolution walks up to the package root and looks in both layouts,
 * rather than assuming a fixed depth from this module — that assumption
 * breaks the moment the build output nests differently.
 */

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ProverArtifacts } from './prover.js';

/** Name of the compiled circuit, shared by the wasm and zkey names. */
const CIRCUIT = 'rln_range_unified';

/** Walk up from `start` until a directory containing package.json. */
function findPackageRoot(start: string): string | null {
  let dir = start;

  for (let depth = 0; depth < 10; depth += 1) {
    if (existsSync(join(dir, 'package.json'))) return dir;

    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return null;
}

/**
 * Locate the compiled circuit artifacts.
 *
 * @returns Absolute paths, or null when the artifacts are absent —
 *   which is the normal state of a fresh clone, since the zkey is a
 *   4.8 MB binary that is not checked in on every branch.
 */
export function resolveArtifacts(): ProverArtifacts | null {
  // A filesystem lookup only means anything on Node. In a browser this
  // whole module is mapped out by the `browser` field, but a bundler
  // that ignores that field would otherwise reach `fileURLToPath` below
  // and fail at runtime rather than returning "no artifacts".
  const isNode =
    typeof process !== 'undefined' &&
    process.versions?.node !== undefined &&
    !('window' in globalThis);

  if (!isNode) return null;

  const here = dirname(fileURLToPath(import.meta.url));
  const root = findPackageRoot(here);
  if (!root) return null;

  // `src` first: when both exist it is the authority, because a stale
  // `dist` would otherwise silently prove against an older circuit.
  for (const base of [join(root, 'src', 'zk'), join(root, 'dist', 'zk')]) {
    const artifacts: ProverArtifacts = {
      wasmPath: join(base, 'circuits', `${CIRCUIT}_js`, `${CIRCUIT}.wasm`),
      zkeyPath: join(base, 'artifacts', 'rln_final.zkey'),
      verificationKeyPath: join(base, 'artifacts', 'verification_key.json'),
    };

    if (
      existsSync(artifacts.wasmPath) &&
      existsSync(artifacts.zkeyPath) &&
      existsSync(artifacts.verificationKeyPath)
    ) {
      return artifacts;
    }
  }

  return null;
}

/**
 * Locate artifacts, or explain what is missing.
 *
 * @throws If any artifact is absent, naming the build step that
 *   produces them rather than reporting a bare ENOENT.
 */
export function requireArtifacts(): ProverArtifacts {
  const artifacts = resolveArtifacts();

  if (!artifacts) {
    throw new Error(
      'Circuit artifacts not found. Groth16 proving needs ' +
        `${CIRCUIT}.wasm, rln_final.zkey and verification_key.json — ` +
        'run `npm run zk:build` to compile and set them up, or pass ' +
        '`proofArtifacts` explicitly in ClientConfig.',
    );
  }

  return artifacts;
}
