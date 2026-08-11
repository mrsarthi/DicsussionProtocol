/**
 * Browser-Reachable Code Must Not Reference Node Globals
 *
 * The existing `browser-bundle.spec.ts` check runs `esbuild
 * --platform=browser` and fails if a Node *builtin module* reaches the
 * bundle. That misses globals entirely: `Buffer.from(...)` is a bare
 * identifier, not `import('buffer')`, so esbuild resolves it happily and
 * the bundle only explodes at runtime with
 * `ReferenceError: Buffer is not defined`.
 *
 * This gap shipped three real defects at once — ticket encoding, at-rest
 * encryption, and revocation gossip all used `Buffer` — and no test caught
 * any of them, because the browser test paths never executed those lines.
 * A source-level scan is crude but it fails at the point the reference is
 * introduced rather than the first time a browser user hits it.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { expect, test } from '@playwright/test';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

/**
 * Modules excluded from the browser bundle.
 *
 * Each is mapped away by the `browser` field in `package.json`, so a Node
 * global here is intentional and unreachable from a browser build.
 */
const NODE_ONLY = [
  'storage/sqlite-driver.ts',
  'transport/datagram-socket.ts',
  'transport/iroh-connection.ts',
  'transport/iroh-transport.ts',
  'transport/mdns-discovery.ts',
  'transport/mdns-record.ts',
  'zk/prover.ts',
  'zk/artifact-paths.ts',
  'zk/worker-pool.ts',
];

/** Globals that exist in Node but not in a browser. */
const FORBIDDEN = [
  { name: 'Buffer', pattern: /\bBuffer\s*\./g },
  { name: 'process', pattern: /\bprocess\s*\.(env|cwd|platform|version)/g },
  { name: '__dirname', pattern: /\b__dirname\b/g },
  { name: '__filename', pattern: /\b__filename\b/g },
];

function sourceFiles(dir: string): string[] {
  const found: string[] = [];

  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);

    if (statSync(full).isDirectory()) {
      found.push(...sourceFiles(full));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      found.push(full);
    }
  }

  return found;
}

test.describe('Browser Safety — no Node globals in shared code', () => {
  test('no browser-reachable module references a Node-only global', () => {
    const roots = [
      join(REPO_ROOT, 'packages', 'core', 'src'),
      join(REPO_ROOT, 'packages', 'HLessEnd', 'src'),
    ];

    const violations: string[] = [];

    for (const root of roots) {
      for (const file of sourceFiles(root)) {
        const rel = relative(REPO_ROOT, file).replaceAll('\\', '/');
        if (NODE_ONLY.some((exempt) => rel.endsWith(exempt))) continue;

        // Strip comments so prose about `Buffer` does not trip the scan —
        // several modules explain *why* they avoid it.
        const source = readFileSync(file, 'utf8')
          .replace(/\/\*[\s\S]*?\*\//g, '')
          .replace(/^\s*\/\/.*$/gm, '');

        for (const { name, pattern } of FORBIDDEN) {
          // `ArrayBuffer.isView` and friends must not count as `Buffer.`.
          const hits = [...source.matchAll(pattern)].filter(
            (m) => !/\w/.test(source[m.index - 1] ?? ''),
          );

          if (hits.length > 0) {
            violations.push(`${rel}: ${name} (${hits.length}x)`);
          }
        }
      }
    }

    expect(violations, `Node-only globals in browser-reachable code:\n  ${violations.join('\n  ')}`)
      .toEqual([]);
  });
});
