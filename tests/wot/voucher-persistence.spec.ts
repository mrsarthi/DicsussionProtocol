/**
 * Voucher replay protection across restarts.
 *
 * Regression guard for a real defect: `VoucherService` held spent
 * redemption nullifiers only in memory, so a restarted node forgot every
 * voucher it had already paid out. An attacker who kept one voucher
 * could redeem it once per restart and inflate reputation without bound,
 * defeating RFC 003 §8 `ReplayedVoucher`.
 */

import { existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import { membershipCommitment } from '../../packages/core/src/crypto/poseidon.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { SQLiteDriver } from '../../packages/HLessEnd/src/storage/sqlite-driver.js';
import { createGenesisAnchor } from '../../packages/HLessEnd/src/wot/genesis-anchor.js';
import { VoucherStore } from '../../packages/HLessEnd/src/wot/voucher-store.js';

function testDbPath(): string {
  return join(tmpdir(), `test-voucher-${crypto.randomUUID()}.db`);
}

function cleanupDb(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    const file = dbPath + suffix;
    if (existsSync(file)) {
      try {
        unlinkSync(file);
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}

test.describe('WoT — Voucher Store', () => {
  test('spent nullifiers survive reopening the database', async () => {
    const dbPath = testDbPath();

    try {
      const first = new SQLiteDriver(dbPath);
      await first.initialize();
      const firstStore = new VoucherStore(first);
      await firstStore.hydrate();
      firstStore.recordSpent(12_345n, 7n, 1_700_000_000);
      // Writes are queued, so closing without flushing would drop them.
      await firstStore.flush();
      await first.close();

      const second = new SQLiteDriver(dbPath);
      await second.initialize();
      const store = new VoucherStore(second);
      await store.hydrate();

      expect(store.isSpent(12_345n)).toBe(true);
      expect(store.isSpent(99_999n)).toBe(false);
      expect(store.countNullifiers()).toBe(1);
      await second.close();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('recording the same nullifier twice is idempotent', async () => {
    const driver = new SQLiteDriver(':memory:');
    await driver.initialize();

    try {
      const store = new VoucherStore(driver);
      await store.hydrate();
      store.recordSpent(1n, 0n, 100);
      store.recordSpent(1n, 0n, 200);

      expect(store.countNullifiers()).toBe(1);
    } finally {
      await driver.close();
    }
  });

  test('genesis anchors round-trip through storage', async () => {
    const driver = new SQLiteDriver(':memory:');
    await driver.initialize();

    try {
      const keypair = generateKeypair();
      const did = publicKeyToDidKey(keypair.publicKey);
      const { anchor } = createGenesisAnchor(
        'general',
        keypair,
        did,
        membershipCommitment(1n, 2n),
        1_700_000_000,
      );

      const store = new VoucherStore(driver);
      await store.hydrate();
      store.saveAnchor(anchor);

      const loaded = store.loadAnchor('general');
      expect(loaded).toBeDefined();
      expect(loaded!.creatorCommitment).toBe(anchor.creatorCommitment);
      expect(loaded!.initialRoot).toBe(anchor.initialRoot);
      expect(Array.from(loaded!.signature)).toEqual(Array.from(anchor.signature));

      expect(store.loadAllAnchors()).toHaveLength(1);
      expect(store.deleteAnchor('general')).toBe(true);
      expect(store.loadAnchor('general')).toBeUndefined();
    } finally {
      await driver.close();
    }
  });
});

test.describe('WoT — Replay Protection Across Restart', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('a redeemed voucher cannot be redeemed again after a restart', async () => {
    const alicePath = testDbPath();

    try {
      const bob = await DicsussionClient.init({ storagePath: ':memory:' });
      let alice = await DicsussionClient.init({ storagePath: alicePath, storageKey: 'test-at-rest-key' });

      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);

      // Redeem a voucher the ordinary way.
      const pending = alice.trust.beginVoucherRequest(await bob.getEndorsementKey(), 5n);
      const blindSignature = await bob.trust.issueEndorsement(
        pending.blinded,
        0,
        bob.did,
      );
      const token = alice.trust.completeVoucher(pending, blindSignature);

      expect(await alice.trust.redeemVoucher(token, bob.did)).toBe(true);
      expect((await alice.trust.getProfile(bob.did)).subjectiveScore).toBe(5);
      expect(alice.spentVoucherCount).toBe(1);

      // Restart Alice against the same database file.
      await alice.disconnect();
      alice = await DicsussionClient.init({ storagePath: alicePath, storageKey: 'test-at-rest-key' });

      // The nullifier must still be known, so the replay is refused and
      // the score does not move.
      expect(alice.spentVoucherCount).toBe(1);
      expect(await alice.trust.redeemVoucher(token, bob.did)).toBe(false);
      expect((await alice.trust.getProfile(bob.did)).subjectiveScore).toBe(5);

      await alice.disconnect();
      await bob.disconnect();
    } finally {
      cleanupDb(alicePath);
    }
  });

  test('an unverifiable genesis anchor is refused at persistence', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const keypair = generateKeypair();
      const { anchor } = createGenesisAnchor(
        'general',
        keypair,
        publicKeyToDidKey(keypair.publicKey),
        membershipCommitment(3n, 4n),
      );

      expect(() =>
        client.saveGenesisAnchor({ ...anchor, channelId: 'tampered' }),
      ).toThrow(/signature verification failed/);

      expect(() => client.saveGenesisAnchor(anchor)).not.toThrow();
      expect(client.listGenesisAnchors()).toHaveLength(1);
    } finally {
      await client.disconnect();
    }
  });
});
