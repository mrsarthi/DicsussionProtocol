/**
 * What a stolen database file gives away.
 *
 * `storageKey` protected identity secrets from 0.3.x onward and left the
 * messages beside them in plaintext — so the thing the key was for was
 * readable by anyone holding the file. This closes that.
 *
 * The only test that means anything here reads the **raw bytes off
 * disk** and looks for the content. Asserting through the SDK proves
 * only that a round trip works, which it would even if nothing were
 * encrypted at all.
 */

import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

const KEY = 'correct horse battery staple';

/** A distinctive string is findable in a hex dump; "hello" is not. */
const SECRET = 'zqxjkv-the-money-is-under-the-floorboards-zqxjkv';
const SECRET_NAME = 'zqxjkv-my-display-name-zqxjkv';

function dbPath(name: string): string {
  return join(tmpdir(), `dicsussion-at-rest-${name}-${Date.now()}.db`);
}

/**
 * Every byte on disk, as text and as hex, for searching.
 *
 * The write-ahead log counts. SQLite runs in WAL mode, so a row can sit
 * in `-wal` long after it was written, and checking only the main file
 * would miss content that is plainly there.
 */
function raw(path: string): { text: string; hex: string } {
  const parts: Buffer[] = [];

  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    try {
      parts.push(readFileSync(candidate));
    } catch {
      // Absent is fine — WAL files come and go with checkpoints.
    }
  }

  const bytes = Buffer.concat(parts);
  return { text: bytes.toString('latin1'), hex: bytes.toString('hex') };
}

function contains(file: { text: string; hex: string }, needle: string): boolean {
  return (
    file.text.includes(needle) ||
    file.hex.includes(Buffer.from(needle).toString('hex'))
  );
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('Encryption at rest', () => {
  test('a message body is not readable in the database file', async () => {
    const path = dbPath('message');

    try {
      const alice = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });

      alice.chat.createChannel('room', []);
      await alice.chat.sendMessage({ channelId: 'room', content: SECRET });
      await alice.disconnect();

      expect(contains(raw(path), SECRET)).toBe(false);
    } finally {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        rmSync(f, { force: true });
      }
    }
  });

  test('and it still reads back through the SDK', async () => {
    const path = dbPath('roundtrip');

    try {
      const alice = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });
      alice.chat.createChannel('room', []);
      await alice.chat.sendMessage({ channelId: 'room', content: SECRET });
      await alice.disconnect();

      // A new client on the same file, so this exercises the load path
      // rather than an in-memory cache.
      const again = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });
      const history = await again.chat.getHistory('room');
      await again.disconnect();

      expect(history.some((m) => m.content === SECRET)).toBe(true);
    } finally {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        rmSync(f, { force: true });
      }
    }
  });

  test('a profile name and picture are not readable either', async () => {
    const path = dbPath('profile');

    try {
      // A contact list with faces is worth as much to whoever steals the
      // file as the messages are.
      const picture = new Uint8Array(2048);
      for (let i = 0; i < picture.length; i++) picture[i] = (i * 37) % 256;

      const alice = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });
      await alice.identity.setMyProfile({
        displayName: SECRET_NAME,
        avatar: { mime: 'image/png', bytes: picture },
      });
      await alice.disconnect();

      const file = raw(path);
      expect(contains(file, SECRET_NAME)).toBe(false);
      expect(file.hex.includes(Buffer.from(picture).toString('hex'))).toBe(false);
    } finally {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        rmSync(f, { force: true });
      }
    }
  });

  test('an attachment is not readable in the database file', async () => {
    const path = dbPath('blob');

    try {
      const secretFile = Buffer.from(SECRET.repeat(20));

      const alice = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });
      const ref = await alice.blobs.put(
        new Uint8Array(secretFile),
        'text/plain',
      );
      await alice.disconnect();

      expect(contains(raw(path), SECRET)).toBe(false);

      // And it comes back byte for byte.
      const again = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });
      const back = await again.blobs.get(ref);
      await again.disconnect();

      expect(Buffer.from(back).equals(secretFile)).toBe(true);
    } finally {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        rmSync(f, { force: true });
      }
    }
  });

  test('without a key the content is readable, and says so', async () => {
    const path = dbPath('nokey');

    try {
      // Not a bug — it is what an unconfigured `storageKey` means, and
      // `allowUnencryptedStorage` is how a caller says they accept it.
      // A test asserting it keeps the trade-off visible rather than
      // letting someone assume protection they did not ask for.
      const alice = await DicsussionClient.init({
        storagePath: path,
        allowUnencryptedStorage: true,
      });

      alice.chat.createChannel('room', []);
      await alice.chat.sendMessage({ channelId: 'room', content: SECRET });
      await alice.disconnect();

      expect(contains(raw(path), SECRET)).toBe(true);
    } finally {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        rmSync(f, { force: true });
      }
    }
  });

  test('a database written without a key still opens with one', async () => {
    const path = dbPath('upgrade');

    try {
      // Upgrading is rewriting rows, not a migration that can fail
      // halfway: unsealed values are returned unchanged, so old rows
      // load and new writes are sealed.
      const before = await DicsussionClient.init({
        storagePath: path,
        allowUnencryptedStorage: true,
      });
      before.chat.createChannel('room', []);
      await before.chat.sendMessage({ channelId: 'room', content: SECRET });
      await before.disconnect();

      const after = await DicsussionClient.init({
        storagePath: path,
        storageKey: KEY,
      });
      const history = await after.chat.getHistory('room');
      await after.disconnect();

      expect(history.some((m) => m.content === SECRET)).toBe(true);
    } finally {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        rmSync(f, { force: true });
      }
    }
  });
});
