/**
 * Browser storage driver — behaviour, and parity with SQLite.
 *
 * The parity tests are the point. Two drivers behind one interface will
 * drift, and the drift shows up as "works on desktop, broken in the
 * browser" — the worst class of bug to chase, because the code is
 * identical and only the backend differs.
 *
 * So every assertion here runs the same operations through both drivers
 * and compares, rather than asserting what IndexedDB alone returns.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { IDBFactory } from 'fake-indexeddb';
import { expect, test } from '@playwright/test';

import { IndexedDbDriver } from '../../packages/HLessEnd/src/storage/indexeddb-driver.js';
import type { IndexedDbFactoryLike } from '../../packages/HLessEnd/src/storage/indexeddb-driver.js';
import { SQLiteDriver } from '../../packages/HLessEnd/src/storage/sqlite-driver.js';
import { StorageCollections } from '../../packages/HLessEnd/src/storage/types.js';
import type { IStorageDriver } from '../../packages/HLessEnd/src/storage/types.js';
import { DocumentStore } from '../../packages/HLessEnd/src/storage/document-store.js';
import { VoucherStore } from '../../packages/HLessEnd/src/wot/voucher-store.js';
import {
  createGenesisAnchor,
  verifyGenesisAnchor,
} from '../../packages/HLessEnd/src/wot/genesis-anchor.js';
import { DocumentManager } from '@dicsussion/core/crdt';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { membershipCommitment } from '@dicsussion/core/crypto';
import {
  generateKeypair,
  publicKeyToDidKey,
} from '../../packages/core/src/transport/did-key.js';

/** A fresh in-memory IndexedDB per driver. */
function browserDriver(): IndexedDbDriver {
  return new IndexedDbDriver({
    factory: new IDBFactory() as unknown as IndexedDbFactoryLike,
  });
}

/** Run a body against both drivers and hand back each result. */
async function onBoth<T>(
  body: (driver: IStorageDriver) => Promise<T>,
): Promise<{ sqlite: T; indexeddb: T }> {
  const dir = mkdtempSync(join(tmpdir(), 'dicsussion-parity-'));

  const sqlite = new SQLiteDriver(join(dir, 'parity.db'));
  const indexeddb = browserDriver();

  try {
    await sqlite.initialize();
    await indexeddb.initialize();

    return { sqlite: await body(sqlite), indexeddb: await body(indexeddb) };
  } finally {
    await sqlite.close();
    await indexeddb.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test.describe('Storage — IndexedDB Driver', () => {
  test('a record round-trips', async () => {
    const driver = browserDriver();
    await driver.initialize();

    try {
      await driver.put(StorageCollections.CHANNEL_META, 'c1', {
        channel_id: 'c1',
        title: 'General',
        created_at: 1_700_000_000,
      });

      const row = await driver.get(StorageCollections.CHANNEL_META, 'c1');
      expect(row?.['title']).toBe('General');
    } finally {
      await driver.close();
    }
  });

  test('the key is filled in even when the caller omits it', async () => {
    // The SQLite driver takes the key as an argument and does not
    // require it in the record. An in-line-keyed object store does, so
    // omitting it there would throw — callers must not have to care.
    const driver = browserDriver();
    await driver.initialize();

    try {
      await driver.put(StorageCollections.CHANNEL_META, 'c2', {
        title: 'No key supplied',
      });

      const row = await driver.get(StorageCollections.CHANNEL_META, 'c2');
      expect(row?.['channel_id']).toBe('c2');
    } finally {
      await driver.close();
    }
  });

  test('using the driver before initialize() is an error, not a silent no-op', async () => {
    const driver = browserDriver();

    await expect(
      driver.get(StorageCollections.CHANNEL_META, 'c1'),
    ).rejects.toThrow(/not initialized/);
  });

  test('an unknown collection is rejected', async () => {
    const driver = browserDriver();
    await driver.initialize();

    try {
      await expect(driver.get('not_a_collection', 'x')).rejects.toThrow(
        /Unknown storage collection/,
      );
    } finally {
      await driver.close();
    }
  });

  test('constructing without any IndexedDB explains itself', () => {
    expect(() => new IndexedDbDriver({ factory: undefined })).toThrow(
      /No IndexedDB implementation available/,
    );
  });
});

test.describe('Storage — SQLite / IndexedDB Parity', () => {
  test('objects and arrays come back in the same shape', async () => {
    // This is the divergence that would bite hardest. SQLite has no
    // array type, so `peers` is stored as JSON and callers parse it
    // (`parseMembers(row['peers'])`). IndexedDB *could* round-trip a
    // real array — and then the same caller would get an array on the
    // browser and a string on the desktop.
    const { sqlite, indexeddb } = await onBoth(async (driver) => {
      await driver.put(StorageCollections.CHANNEL_META, 'c1', {
        channel_id: 'c1',
        title: 'Shapes',
        peers: ['did:key:zA', 'did:key:zB'],
        created_at: 1,
      });

      const row = await driver.get(StorageCollections.CHANNEL_META, 'c1');
      return row?.['peers'];
    });

    expect(indexeddb).toBe(sqlite);
    expect(typeof indexeddb).toBe('string');
    expect(JSON.parse(indexeddb as string)).toEqual([
      'did:key:zA',
      'did:key:zB',
    ]);
  });

  test('booleans survive as the same representation', async () => {
    const { sqlite, indexeddb } = await onBoth(async (driver) => {
      await driver.put(StorageCollections.WOT_PEERS, 'did:key:zX', {
        did: 'did:key:zX',
        verified_sessions: 0,
        vouchers_redeemed: 0,
        vouchers_issued: 0,
        subjective_score: 0,
        is_blacklisted: true,
        last_interaction: 1,
      });

      const row = await driver.get(StorageCollections.WOT_PEERS, 'did:key:zX');
      return row?.['is_blacklisted'];
    });

    // SQLite has no boolean; both must agree on 1.
    expect(indexeddb).toBe(sqlite);
    expect(indexeddb).toBe(1);
  });

  test('a missing record is undefined on both', async () => {
    const { sqlite, indexeddb } = await onBoth((driver) =>
      driver.get(StorageCollections.CHANNEL_META, 'absent'),
    );

    expect(indexeddb).toBe(undefined);
    expect(sqlite).toBe(undefined);
  });

  test('delete reports whether anything was removed', async () => {
    const { sqlite, indexeddb } = await onBoth(async (driver) => {
      await driver.put(StorageCollections.CHANNEL_META, 'c1', {
        channel_id: 'c1',
        title: 'Doomed',
        created_at: 1,
      });

      return {
        removedExisting: await driver.delete(
          StorageCollections.CHANNEL_META,
          'c1',
        ),
        removedAbsent: await driver.delete(
          StorageCollections.CHANNEL_META,
          'never-existed',
        ),
      };
    });

    expect(indexeddb).toEqual(sqlite);
    expect(indexeddb).toEqual({ removedExisting: true, removedAbsent: false });
  });

  test('query filters and limits identically', async () => {
    const { sqlite, indexeddb } = await onBoth(async (driver) => {
      for (const channel of ['alpha', 'beta']) {
        await driver.put(StorageCollections.CHANNEL_META, channel, {
          channel_id: channel,
          title: channel,
          created_at: 1,
        });
      }

      for (const [id, channel] of [
        ['m1', 'alpha'],
        ['m2', 'alpha'],
        ['m3', 'beta'],
      ]) {
        await driver.put(StorageCollections.MESSAGE_STREAM, id!, {
          id,
          channel_id: channel,
          author_did: 'did:key:zA',
          content: 'x',
          timestamp: 1,
          epoch: 1,
        });
      }

      const filtered = await driver.query(StorageCollections.MESSAGE_STREAM, {
        channel_id: 'alpha',
      });
      const limited = await driver.query(
        StorageCollections.MESSAGE_STREAM,
        undefined,
        2,
      );

      return {
        filtered: filtered.map((r) => r['id']).sort(),
        limitedCount: limited.length,
      };
    });

    expect(indexeddb).toEqual(sqlite);
    expect(indexeddb).toEqual({ filtered: ['m1', 'm2'], limitedCount: 2 });
  });

  test('writing the same key twice updates rather than duplicating', async () => {
    const { sqlite, indexeddb } = await onBoth(async (driver) => {
      await driver.put(StorageCollections.CHANNEL_META, 'c1', {
        channel_id: 'c1',
        title: 'First',
        created_at: 1,
      });
      await driver.put(StorageCollections.CHANNEL_META, 'c1', {
        channel_id: 'c1',
        title: 'Second',
        created_at: 2,
      });

      const rows = await driver.query(StorageCollections.CHANNEL_META);
      return { count: rows.length, title: rows[0]?.['title'] };
    });

    expect(indexeddb).toEqual(sqlite);
    expect(indexeddb).toEqual({ count: 1, title: 'Second' });
  });
});

test.describe('Storage — Real Stores on IndexedDB', () => {
  test('CRDT snapshots round-trip through the browser driver', async () => {
    // The point of the port: DocumentStore used to hold a raw
    // better-sqlite3 handle, which no browser can provide. Snapshots are
    // binary, and binary is exactly what a JSON-shaped serializer
    // destroys — `{"0":133,"1":111,…}` would still *look* like data.
    const driver = browserDriver();
    await driver.initialize();

    try {
      const store = new DocumentStore(driver);

      const original = new DocumentManager();
      original.createDocument('General', 'doc-1');
      original.addMessage('doc-1', {
        id: 'm1',
        content: 'survives a browser restart',
        timestamp: 1_700_000_000,
        authorDid: 'did:key:zA',
      });

      expect(store.checkpointAll(original)).toBe(1);
      await store.flush();

      const stored = await store.load('doc-1');
      expect(stored!.snapshot).toBeInstanceOf(Uint8Array);
      expect(stored!.snapshot.length).toBeGreaterThan(0);
      expect(stored!.messageCount).toBe(1);

      // The real proof: Automerge can parse it back.
      const restored = new DocumentManager();
      await store.restoreAll(restored);

      expect(restored.getDocument('doc-1')!.messages['m1']!.content).toBe(
        'survives a browser restart',
      );
    } finally {
      await driver.close();
    }
  });

  test('nullifiers and signed anchors persist through the browser driver', async () => {
    const driver = browserDriver();
    await driver.initialize();

    try {
      const store = new VoucherStore(driver);
      await store.hydrate();

      store.recordSpent(12_345n, 7n, 1_700_000_000);

      const keypair = generateKeypair();
      const did = publicKeyToDidKey(keypair.publicKey);
      const { anchor } = createGenesisAnchor(
        'general',
        keypair,
        did,
        membershipCommitment(1n, 2n),
        1_700_000_000,
        true,
      );
      store.saveAnchor(anchor);
      await store.flush();

      // Re-read through a *fresh* store, so the assertions come from
      // storage rather than the in-memory write-through cache.
      const reopened = new VoucherStore(driver);
      await reopened.hydrate();

      expect(reopened.isSpent(12_345n)).toBe(true);
      expect(reopened.isSpent(99_999n)).toBe(false);
      expect(reopened.countNullifiers()).toBe(1);

      const loaded = reopened.loadAnchor('general');
      expect(loaded!.creatorCommitment).toBe(anchor.creatorCommitment);
      expect(loaded!.requireProofs).toBe(true);

      // A signature that survived as binary still verifies; one mangled
      // into JSON would not.
      expect(loaded!.signature).toBeInstanceOf(Uint8Array);
      expect(verifyGenesisAnchor(loaded!)).toBe(true);
    } finally {
      await driver.close();
    }
  });
});

test.describe('Storage — Full Client on IndexedDB', () => {
  test('a client boots, sends, and persists with no SQLite at all', async () => {
    // SDK-1: `better-sqlite3` is a NAPI module that cannot load in a
    // webview. Until the driver was injectable, `initStorage` hardcoded
    // it, so the whole SDK was unreachable from a browser regardless of
    // what `IStorageDriver` allowed.
    const factory = new IDBFactory() as unknown as IndexedDbFactoryLike;

    const client = await DicsussionClient.init(
      { storagePath: 'unused-when-injected' },
      { storage: new IndexedDbDriver({ factory }) },
    );

    try {
      expect(client.did).toMatch(/^did:key:z/);

      const sent = await client.chat.sendMessage({
        channelId: 'general',
        content: 'sent without sqlite',
      });
      expect(sent.id).toBeTruthy();

      const history = await client.chat.getHistory('general');
      expect(history.map((m) => m.content)).toEqual(['sent without sqlite']);
    } finally {
      await client.disconnect();
    }
  });

  test('identity survives a restart on the same IndexedDB', async () => {
    // One factory, two clients: the second must find the first's
    // identity rather than minting a new one. This is also what catches
    // a restore path that discards an identity whose optional columns
    // are absent.
    const factory = new IDBFactory() as unknown as IndexedDbFactoryLike;

    const first = await DicsussionClient.init(
      { storagePath: 'unused' },
      { storage: new IndexedDbDriver({ factory }) },
    );
    const originalDid = first.did;
    await first.disconnect();

    const second = await DicsussionClient.init(
      { storagePath: 'unused' },
      { storage: new IndexedDbDriver({ factory }) },
    );

    try {
      expect(second.did).toBe(originalDid);
    } finally {
      await second.disconnect();
    }
  });

  test('the endorsement key is generated on demand, not at init', async () => {
    // RSA-2048 keygen costs hundreds of ms to seconds. Paying it on
    // every first `init()` — when most nodes never issue an endorsement
    // — is the kind of cost that shows up as a slow cold start.
    const factory = new IDBFactory() as unknown as IndexedDbFactoryLike;
    const driver = new IndexedDbDriver({ factory });

    const client = await DicsussionClient.init(
      { storagePath: 'unused' },
      { storage: driver },
    );

    try {
      const stored = await driver.query(StorageCollections.IDENTITY);
      expect(stored[0]?.['blind_modulus'] ?? null).toBeNull();

      const key = await client.getEndorsementKey();
      expect(key.n).toBeGreaterThan(0n);

      // And it is persisted, so the cost is paid once.
      const after = await driver.query(StorageCollections.IDENTITY);
      expect(after[0]?.['blind_modulus']).toBe(key.n.toString());

      // Stable across calls.
      expect((await client.getEndorsementKey()).n).toBe(key.n);
    } finally {
      await client.disconnect();
    }
  });
});
