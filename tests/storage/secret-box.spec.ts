/**
 * Encryption at rest for secret key material (RFC 004 §4.1).
 *
 * The `identity` table's columns were always named `*_encrypted`; until
 * now that was aspirational. These tests assert the names are true, and
 * that a database written without a key still opens — upgrading must not
 * be a migration that can fail halfway.
 */

import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { SecretBox } from '../../packages/HLessEnd/src/storage/secret-box.js';

function testDbPath(): string {
  return join(process.cwd(), `test-secretbox-${crypto.randomUUID()}.db`);
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

const KEY = 'correct horse battery staple';

test.describe('Storage — Secret Box', () => {
  test('a sealed value round-trips', () => {
    const box = new SecretBox(KEY);
    const sealed = box.seal('super-secret');

    expect(box.isEnabled).toBe(true);
    expect(sealed).not.toContain('super-secret');
    expect(sealed.startsWith('v1:')).toBe(true);
    expect(box.open(sealed)).toBe('super-secret');
  });

  test('sealing twice yields different ciphertexts', () => {
    const box = new SecretBox(KEY);

    // A fresh nonce per seal — identical ciphertexts would leak that two
    // columns hold the same value.
    expect(box.seal('same')).not.toBe(box.seal('same'));
  });

  test('a wrong key fails loudly rather than yielding garbage', () => {
    const sealed = new SecretBox(KEY).seal('secret');

    // AES-GCM authenticates, so this is a rejection, not silent nonsense
    // that would later be used as a private key.
    expect(() => new SecretBox('wrong key').open(sealed)).toThrow();
  });

  test('an unsealed value passes through, so old databases still open', () => {
    const box = new SecretBox(KEY);

    expect(box.open('plain-legacy-value')).toBe('plain-legacy-value');
    expect(SecretBox.isSealed('plain-legacy-value')).toBe(false);
  });

  test('a disabled box is a pass-through', () => {
    const box = new SecretBox(null);

    expect(box.isEnabled).toBe(false);
    expect(box.seal('plain')).toBe('plain');
    expect(box.open('plain')).toBe('plain');
  });

  test('a disabled box refuses to open sealed data', () => {
    const sealed = new SecretBox(KEY).seal('secret');

    expect(() => new SecretBox(null).open(sealed)).toThrow(/no storage key/);
  });

  test('malformed sealed values are rejected', () => {
    expect(() => new SecretBox(KEY).open('v1:onlyonepart')).toThrow(/Malformed/);
  });

  test('an empty key is refused rather than silently weakening', () => {
    expect(() => new SecretBox('')).toThrow(/must not be empty/);
  });
});

test.describe('Storage — Identity Secrets at Rest', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('secrets are unreadable in the database file', async () => {
    const dbPath = testDbPath();

    try {
      const client = await DicsussionClient.init({
        storagePath: dbPath,
        storageKey: KEY,
      });

      const mnemonic = await client.identity.exportMnemonic();
      const firstWord = mnemonic.split(' ')[0]!;
      await client.disconnect();

      // Read the raw file the way a thief with the disk would.
      const raw = readFileSync(dbPath).toString('latin1');

      expect(raw).not.toContain(mnemonic);
      // Even one word of the phrase must not be recoverable.
      expect(raw).not.toContain(` ${firstWord} `);
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('an identity survives a restart with the same key', async () => {
    const dbPath = testDbPath();

    try {
      const first = await DicsussionClient.init({
        storagePath: dbPath,
        storageKey: KEY,
      });
      const did = first.did;
      const commitment = first.identityCommitment;
      await first.disconnect();

      const second = await DicsussionClient.init({
        storagePath: dbPath,
        storageKey: KEY,
      });

      expect(second.did).toBe(did);
      expect(second.identityCommitment).toBe(commitment);
      await second.disconnect();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('the wrong key cannot open an encrypted identity', async () => {
    const dbPath = testDbPath();

    try {
      const first = await DicsussionClient.init({
        storagePath: dbPath,
        storageKey: KEY,
      });
      const did = first.did;
      await first.disconnect();

      // A different key must not silently produce a *new* identity in the
      // same database — that would look like data loss rather than an
      // authentication failure.
      await expect(
        DicsussionClient.init({ storagePath: dbPath, storageKey: 'wrong key' }),
      ).rejects.toThrow();

      // The original key still works.
      const recovered = await DicsussionClient.init({
        storagePath: dbPath,
        storageKey: KEY,
      });
      expect(recovered.did).toBe(did);
      await recovered.disconnect();
    } finally {
      cleanupDb(dbPath);
    }
  });

  test('omitting a key still works, for development', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Plaintext storage is permitted but should be a deliberate choice.
      expect(client.did).toBeTruthy();
      expect(await client.identity.exportMnemonic()).toBeTruthy();
    } finally {
      await client.disconnect();
    }
  });
});
