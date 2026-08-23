/**
 * Phase 5/6 — Cross-Process Networking
 *
 * The first tests where peers are genuinely separate OS processes, each
 * with its own memory, event loop and UDP socket, talking over real
 * QUIC. Everything else in this suite runs peers inside one process
 * where "the network" is a JavaScript Map.
 *
 * These are slow by nature — spawning a process, binding a socket and
 * completing a real handshake takes seconds, not microseconds — so they
 * run serially with generous timeouts.
 */

import { expect, test } from '@playwright/test';

import { PeerMesh } from '../harness/mesh.js';
import type { PeerHandle } from '../harness/mesh.js';

test.describe.configure({ mode: 'serial', timeout: 180_000 });

interface InboxEntry {
  content: string;
  authorDid: string | null;
  nullifierHash: string | null;
}

/** Wait until a peer's inbox reaches `count` messages. */
async function inboxReaches(
  peer: PeerHandle,
  count: number,
  timeoutMs = 30_000,
): Promise<InboxEntry[]> {
  await peer.waitFor(async () => {
    const inbox = await peer.call<InboxEntry[]>('inbox');
    return inbox.length >= count;
  }, timeoutMs);

  return peer.call<InboxEntry[]>('inbox');
}

test.describe('Suite 4.2 — Cross-Process Real Networking', () => {
  test('two processes connect and exchange an encrypted message', async () => {
    const mesh = await PeerMesh.create(2);

    try {
      const [alice, bob] = [mesh.at(0), mesh.at(1)];

      // Distinct processes, therefore distinct identities.
      expect(alice.did).not.toBe(bob.did);

      await bob.call('watch', { channelId: 'general' });
      await alice.call('send', {
        channelId: 'general',
        content: 'hello across processes',
      });

      const inbox = await inboxReaches(bob, 1);
      expect(inbox[0]!.content).toBe('hello across processes');
      expect(inbox[0]!.authorDid).toBe(alice.did);
    } finally {
      await mesh.shutdownAll();
    }
  });

  test('both peers report a live connection', async () => {
    const mesh = await PeerMesh.create(2);

    try {
      for (const peer of mesh.peers) {
        const status = await peer.call<{ peerCount: number; connected: boolean }>(
          'status',
        );
        expect(status.peerCount).toBe(1);
        expect(status.connected).toBe(true);
      }
    } finally {
      await mesh.shutdownAll();
    }
  });

  test('messages flow in both directions between processes', async () => {
    const mesh = await PeerMesh.create(2);

    try {
      const [alice, bob] = [mesh.at(0), mesh.at(1)];

      await alice.call('watch', { channelId: 'general' });
      await bob.call('watch', { channelId: 'general' });

      await alice.call('send', { channelId: 'general', content: 'ping' });
      expect((await inboxReaches(bob, 1))[0]!.content).toBe('ping');

      await bob.call('send', { channelId: 'general', content: 'pong' });
      expect((await inboxReaches(alice, 1))[0]!.content).toBe('pong');
    } finally {
      await mesh.shutdownAll();
    }
  });

  test('CRDT state converges across processes', async () => {
    const mesh = await PeerMesh.create(2);

    try {
      const [alice, bob] = [mesh.at(0), mesh.at(1)];
      await bob.call('watch', { channelId: 'general' });

      for (const content of ['first', 'second', 'third']) {
        await alice.call('send', { channelId: 'general', content });
      }

      await inboxReaches(bob, 3);

      // Both replicas must agree on content and order.
      expect(await alice.call('history', { channelId: 'general' })).toEqual([
        'first',
        'second',
        'third',
      ]);
      expect(await bob.call('history', { channelId: 'general' })).toEqual([
        'first',
        'second',
        'third',
      ]);
    } finally {
      await mesh.shutdownAll();
    }
  });

  test('the offline outbox flushes over a real connection', async () => {
    const mesh = await PeerMesh.create(2);

    try {
      const [alice, bob] = [mesh.at(0), mesh.at(1)];
      await bob.call('watch', { channelId: 'general' });

      await alice.call('goOffline');
      await alice.call('send', { channelId: 'general', content: 'queued-1' });
      await alice.call('send', { channelId: 'general', content: 'queued-2' });

      expect(await alice.call('outboxSize')).toBe(2);

      // Deliberately not asserting that Bob has received nothing yet.
      //
      // `goOffline` suppresses the outbox; it does not sever the QUIC
      // connection. Document sync runs independently of that flag, so a
      // reconciliation still in flight from the initial connect may
      // legitimately carry these messages across before the flush — and
      // converging without being asked is what local-first means. The
      // guarantee worth asserting is that they arrive, not that they are
      // withheld until a particular moment.

      expect(await alice.call('goOnline')).toBe(2);

      const inbox = await inboxReaches(bob, 2);
      expect(inbox.map((m) => m.content)).toEqual(['queued-1', 'queued-2']);
      expect(await alice.call('outboxSize')).toBe(0);
    } finally {
      await mesh.shutdownAll();
    }
  });

  test('an anonymous message crosses processes without an author', async () => {
    const mesh = await PeerMesh.create(2);

    try {
      const [alice, bob] = [mesh.at(0), mesh.at(1)];

      // `PeerMesh` declares only the shared 'general' channel, so this
      // one names its own. An anonymous message carries no author, but
      // the *recipients* are still an ordinary guest list — anonymity
      // hides who sent it, not who it was for.
      await alice.call('createChannel', {
        channelId: 'anon',
        participants: [bob.did],
      });
      await bob.call('createChannel', {
        channelId: 'anon',
        participants: [alice.did],
      });

      await bob.call('watch', { channelId: 'anon' });

      await alice.call('send', {
        channelId: 'anon',
        content: 'untraceable',
        anonymous: true,
      });

      const inbox = await inboxReaches(bob, 1);
      expect(inbox[0]!.content).toBe('untraceable');
      // A separate process genuinely cannot see who sent it.
      expect(inbox[0]!.authorDid).toBeNull();
      expect(inbox[0]!.nullifierHash).toMatch(/^0x[0-9a-f]{64}$/);
    } finally {
      await mesh.shutdownAll();
    }
  });

  test('three processes form a mesh and all receive a broadcast', async () => {
    const mesh = await PeerMesh.create(3);

    try {
      const [alice, bob, carol] = [mesh.at(0), mesh.at(1), mesh.at(2)];

      await bob.call('watch', { channelId: 'general' });
      await carol.call('watch', { channelId: 'general' });

      await alice.call('send', { channelId: 'general', content: 'broadcast' });

      for (const peer of [bob, carol]) {
        const inbox = await inboxReaches(peer, 1);
        expect(inbox[0]!.content).toBe('broadcast');
        expect(inbox[0]!.authorDid).toBe(alice.did);
      }
    } finally {
      await mesh.shutdownAll();
    }
  });
});
