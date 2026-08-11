/**
 * Migration 5 — proof policy column on genesis anchors.
 *
 * A developer with an existing local database must be able to upgrade
 * without losing data or silently gaining a policy nobody signed.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import Database from 'better-sqlite3';
import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '@dicsussion/core/transport';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { migrations } from '../../packages/HLessEnd/src/storage/migrations.js';
import { verifyGenesisAnchor } from '../../packages/HLessEnd/src/wot/genesis-anchor.js';

/** A database at schema v4, holding one pre-policy anchor. */
function seedLegacyDatabase(path: string): void {
  const db = new Database(path);

  db.exec(`CREATE TABLE IF NOT EXISTS _migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at INTEGER NOT NULL);`);

  for (const migration of migrations.filter((m) => m.version <= 4)) {
    migration.up(db);
    db.prepare('INSERT INTO _migrations VALUES (?,?,?)').run(
      migration.version,
      migration.description,
      0,
    );
  }

  db.prepare(
    `INSERT INTO genesis_anchors
       (channel_id, creator_did, creator_commitment, initial_root, created_at, signature)
     VALUES (?,?,?,?,?,?)`,
  ).run('legacy', 'did:key:zLegacy', '123', '456', 1_700_000_000, Buffer.alloc(64, 7));

  db.close();
}

test.describe('Storage — Anchor Proof-Policy Migration', () => {
  let dir: string;

  test.beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'dicsussion-mig-'));
  });

  test.afterEach(() => {
    clearTransportRegistry();
    rmSync(dir, { recursive: true, force: true });
  });

  test('an existing database upgrades without losing anchors', async () => {
    const path = join(dir, 'legacy.db');
    seedLegacyDatabase(path);

    const client = await DicsussionClient.init({ storagePath: path, storageKey: 'test-at-rest-key' });

    try {
      const anchor = client.getGenesisAnchor('legacy');
      expect(anchor).toBeDefined();

      // Pre-policy anchors read as not requiring proofs, which preserves
      // their effective behaviour.
      expect(anchor!.requireProofs).toBe(false);

      // But they must NOT verify: their signature never covered a
      // policy, so treating one as signed would be a forgery performed
      // on the creator's behalf. Such a channel needs a re-issued anchor.
      expect(verifyGenesisAnchor(anchor!)).toBe(false);
    } finally {
      await client.disconnect();
    }
  });

  test('anchors created after the upgrade carry a signed policy', async () => {
    const path = join(dir, 'legacy.db');
    seedLegacyDatabase(path);

    const client = await DicsussionClient.init({ storagePath: path, storageKey: 'test-at-rest-key' });

    try {
      const group = await client.groups.createGroup('fresh', [], {
        requireProofs: true,
      });
      const anchor = client.getGenesisAnchor(group.groupId)!;

      expect(anchor.requireProofs).toBe(true);
      expect(verifyGenesisAnchor(anchor)).toBe(true);
    } finally {
      await client.disconnect();
    }
  });
});
