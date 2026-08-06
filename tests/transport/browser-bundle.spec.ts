/**
 * The browser entry point must actually bundle for a browser.
 *
 * Every other test in this suite runs under Node, where a stray
 * `node:crypto` import is invisible. This one is the only thing standing
 * between the SDK and a browser consumer discovering — at bundle time,
 * in their own project — that the package cannot build.
 *
 * It is a real `esbuild --platform=browser` run rather than an import
 * scan, because the failures that matter are resolution failures deep in
 * transitive dependencies (`better-sqlite3` requiring `fs`), which no
 * amount of reading our own source would reveal.
 */

import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import * as esbuild from 'esbuild';
import { expect, test } from '@playwright/test';

const REPO = resolve(process.cwd()).replaceAll('\\', '/');

/** Node builtins that must not survive into a browser bundle. */
const FORBIDDEN = [
  'fs',
  'path',
  'crypto',
  'dgram',
  'events',
  'url',
  'os',
  'net',
  'tls',
  'child_process',
  'worker_threads',
];

interface BundleResult {
  readonly ok: boolean;
  readonly code: string;
  readonly errors: string;
}

async function bundleForBrowser(entryModule: string): Promise<BundleResult> {
  const dir = mkdtempSync(join(tmpdir(), 'dicsussion-bundle-'));
  const entry = join(dir, 'entry.mjs');
  writeFileSync(entry, `export * from '${entryModule}';`, 'utf8');

  try {
    const outdir = join(dir, 'out');
    await esbuild.build({
      entryPoints: [entry],
      bundle: true,
      platform: 'browser',
      format: 'esm',
      outdir,
      // Automerge ships WASM; a real app loads it as an asset.
      loader: { '.wasm': 'file' },
      logLevel: 'silent',
      absWorkingDir: REPO,
    });

    const code = readdirSync(outdir)
      .filter((f) => f.endsWith('.js'))
      .map((f) => readFileSync(join(outdir, f), 'utf8'))
      .join('\n');

    return { ok: true, code, errors: '' };
  } catch (error) {
    return { ok: false, code: '', errors: String(error) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test.describe('Browser — Bundle Integrity', () => {
  // esbuild plus a 3.8 MB WASM copy; slower than a unit test by design.
  test.setTimeout(180_000);

  test('the browser entry bundles with no Node builtins', async () => {
    const result = await bundleForBrowser(
      `${REPO}/packages/HLessEnd/dist/browser.js`,
    );

    // On failure the esbuild output names the exact import and file that
    // broke, which is the whole value of running a real bundler here.
    expect(result.ok, result.errors).toBe(true);
    expect(result.code.length).toBeGreaterThan(0);

    const leaked = FORBIDDEN.filter((mod) =>
      new RegExp(`from\\s*["'](?:node:)?${mod}["']|require\\(["'](?:node:)?${mod}["']\\)`).test(
        result.code,
      ),
    );

    expect(
      leaked,
      `Node builtins reached the browser bundle: ${leaked.join(', ')}. ` +
        'Replace the dependency with a portable one, or map the module out ' +
        "via the package's `browser` field.",
    ).toEqual([]);
  });

  test('the browser entry offers nothing that cannot run in a browser', async () => {
    // What the separate entry is actually for. The `browser` field maps
    // `sqlite-driver` to an empty module, so the *main* entry bundles
    // for a browser too — but it still advertises `SQLiteDriver`, which
    // would then be `undefined` at the point of use. The failure would
    // surface as "SQLiteDriver is not a constructor" somewhere far from
    // the cause. This entry simply does not offer it.
    const [main, browser] = await Promise.all([
      import('../../packages/HLessEnd/dist/index.js'),
      import('../../packages/HLessEnd/dist/browser.js'),
    ]);

    expect(Object.keys(main)).toContain('SQLiteDriver');
    expect(Object.keys(browser)).not.toContain('SQLiteDriver');

    // And it does offer the two things a browser build genuinely needs.
    expect(Object.keys(browser)).toEqual(
      expect.arrayContaining([
        'DicsussionClient',
        'IndexedDbDriver',
        'WebSocketTransport',
      ]),
    );
  });
});
