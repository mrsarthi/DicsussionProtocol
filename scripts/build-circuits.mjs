#!/usr/bin/env node
/**
 * Compile the ZekPoc circuits and run a Groth16 trusted setup.
 *
 *   npm run build:circuits
 *
 * ⚠️  DEVELOPMENT SETUP ONLY.
 *
 * The Powers of Tau transcript and Phase-2 contribution generated here
 * come from a single party — this machine. Anyone who reproduces that
 * entropy can forge proofs. RFC 003 §9 requires:
 *   - Phase 1: the public Hermez BN254 perpetual ceremony, not a local
 *     `powersoftau new`.
 *   - Phase 2: contributions from ≥5 independent parties with published
 *     beacon hashes.
 *
 * The artifacts produced here MUST NOT ship in a release.
 *
 * Expect this to take several minutes — `groth16 setup` over a 2^15
 * transcript is the slow step and shows no progress output. An existing
 * `pot*_final.ptau` is reused, so repeat runs skip Phase 1 entirely.
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CIRCUITS = join(ROOT, 'packages/core/src/zk/circuits');
const ARTIFACTS = join(ROOT, 'packages/core/src/zk/artifacts');

/** Powers of Tau size. 2^15 covers the ~5.3k-constraint circuit. */
const POT_POWER = 15;
const CIRCUIT = 'rln_range_unified';

/**
 * Run a command, surfacing its output when it fails.
 *
 * `shell: true` is required because on Windows `npx` resolves to
 * `npx.cmd`, which `execFileSync` cannot invoke directly. Output is
 * inherited rather than piped: these steps run for minutes, and a silent
 * pipe makes a slow step indistinguishable from a hung one.
 */
function run(command, args, cwd = ROOT) {
  const quoted = args.map((arg) => (/[\s"]/.test(arg) ? `"${arg}"` : arg));

  try {
    execFileSync(command, quoted, { cwd, shell: true, stdio: 'inherit' });
  } catch (error) {
    throw new Error(
      `Command failed: ${command} ${quoted.join(' ')}\n` +
        `  cwd: ${cwd}\n  exit: ${error.status ?? error.signal ?? 'unknown'}`,
      { cause: error },
    );
  }
}

function snarkjs(...args) {
  run('npx', ['--prefix', ROOT, 'snarkjs', ...args]);
}

function mb(path) {
  return (statSync(path).size / 1_048_576).toFixed(2);
}

function step(label, fn) {
  console.log(`\n▶ ${label}`);
  const started = Date.now();
  fn();
  console.log(`✓ ${label} (${((Date.now() - started) / 1000).toFixed(1)}s)`);
}

mkdirSync(ARTIFACTS, { recursive: true });

console.log('\nBuilding ZekPoc circuits (development setup)\n');

step('compile circuit', () => {
  run(
    'npx',
    [
      '--prefix', ROOT,
      'circom2', `${CIRCUIT}.circom`,
      '--r1cs', '--wasm',
      '-l', join(ROOT, 'node_modules'),
      '-o', '.',
    ],
    CIRCUITS,
  );
});

const potFinal = join(ARTIFACTS, `pot${POT_POWER}_final.ptau`);

if (existsSync(potFinal)) {
  console.log(`  powers of tau ... reusing ${potFinal} (${mb(potFinal)} MB)`);
} else {
  const stage0 = join(ARTIFACTS, `pot${POT_POWER}_0000.ptau`);
  const stage1 = join(ARTIFACTS, `pot${POT_POWER}_0001.ptau`);

  step('powers of tau (new)', () => {
    snarkjs('powersoftau', 'new', 'bn128', String(POT_POWER), stage0);
  });
  step('powers of tau (contribute)', () => {
    snarkjs(
      'powersoftau', 'contribute', stage0, stage1,
      '--name=dev-only', `-e=dev entropy ${Date.now()}`,
    );
  });
  step('powers of tau (phase 2)', () => {
    snarkjs('powersoftau', 'prepare', 'phase2', stage1, potFinal);
  });
}

const zkey0 = join(ARTIFACTS, `${CIRCUIT}_0000.zkey`);
const zkeyFinal = join(ARTIFACTS, 'rln_final.zkey');

step('groth16 setup', () => {
  snarkjs('groth16', 'setup', join(CIRCUITS, `${CIRCUIT}.r1cs`), potFinal, zkey0);
});
step('zkey contribute', () => {
  snarkjs(
    'zkey', 'contribute', zkey0, zkeyFinal,
    '--name=dev-only', `-e=phase2 dev ${Date.now()}`,
  );
});
step('export verification key', () => {
  snarkjs(
    'zkey', 'export', 'verificationkey',
    zkeyFinal, join(ARTIFACTS, 'verification_key.json'),
  );
});

console.log(`\n  proving key : rln_final.zkey (${mb(zkeyFinal)} MB — ships in the app)`);
console.log(`  ptau        : pot${POT_POWER}_final.ptau (${mb(potFinal)} MB — build only)\n`);
console.log('  ⚠️  Single-party setup. Not safe for production — see RFC 003 §9.\n');
