/**
 * Phase 4.3 — Pairing from tickets, which is what users actually do
 *
 * Every other suite pairs peers by calling `addPeer` with a raw X25519
 * key that both sides somehow already hold. No application can do that.
 * What a person has is a **ticket** — pasted, scanned, or sent over
 * another channel — and pairing has to work from that alone.
 *
 * The gap matters because pairing is mutual (RFC 001 §3.3) and failure
 * is silent: an unpaired receiver drops frames with no error at either
 * end, so the sender sees a clean send and the recipient sees nothing.
 * A suite that pre-shares keys out of band can be fully green while the
 * real flow delivers nothing at all.
 *
 * Cross-process and over real QUIC, for the same reason as Suite 4.2:
 * peers sharing a heap can appear to work for reasons unrelated to the
 * network.
 */

import { expect, test } from '@playwright/test';

import { PeerHandle } from '../harness/mesh.js';

test.describe.configure({ mode: 'serial', timeout: 180_000 });

interface InboxEntry {
  content: string;
  authorDid: string | null;
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

/** Two peers watching `general`, with nothing paired yet. */
async function spawnPair(): Promise<[PeerHandle, PeerHandle]> {
  const alice = await PeerHandle.spawn('alice');
  const bob = await PeerHandle.spawn('bob');

  await alice.call('watch', { channelId: 'general' });
  await bob.call('watch', { channelId: 'general' });

  return [alice, bob];
}

test.describe('Suite 4.3 — Pairing from tickets', () => {
  test('tickets alone are enough to pair and converse', async () => {
    const [alice, bob] = await spawnPair();

    try {
      // The whole out-of-band exchange: each side gets the other's
      // ticket and nothing else.
      await alice.call('pairFromTicket', { ticket: bob.ticket });
      await bob.call('pairFromTicket', { ticket: alice.ticket });

      // One dial. Two would open two connections for one peer pair.
      await alice.call('connect', { ticket: bob.ticket });

      await alice.call('send', { channelId: 'general', content: 'from alice' });
      const bobInbox = await inboxReaches(bob, 1);
      expect(bobInbox[0]?.content).toBe('from alice');

      await bob.call('send', { channelId: 'general', content: 'from bob' });
      const aliceInbox = await inboxReaches(alice, 1);
      expect(aliceInbox[0]?.content).toBe('from bob');

      // Each side attributed the message to the other's real did:key,
      // which only the handshake could have established.
      expect(bobInbox[0]?.authorDid).toBe(alice.did);
      expect(aliceInbox[0]?.authorDid).toBe(bob.did);
    } finally {
      await Promise.all([alice.shutdown(), bob.shutdown()]);
    }
  });

  test('dialling without pairing leaves the accepter unable to read', async () => {
    // The silent-drop trap, asserted as a non-delivery. `connect`
    // registers the dialer's view of the peer and nothing on the far
    // side, so Bob never learns Alice's key.
    const [alice, bob] = await spawnPair();

    try {
      await alice.call('connect', { ticket: bob.ticket });
      await alice.call('send', { channelId: 'general', content: 'unheard' });

      // Long enough that a working delivery would have landed.
      await new Promise((resolve) => setTimeout(resolve, 3_000));

      expect(await bob.call<InboxEntry[]>('inbox')).toEqual([]);
    } finally {
      await Promise.all([alice.shutdown(), bob.shutdown()]);
    }
  });

  test('pairing after the fact repairs delivery without redialling', async () => {
    // The recovery path an app needs when a stranger connects first and
    // the user accepts them afterwards.
    const [alice, bob] = await spawnPair();

    try {
      await alice.call('pairFromTicket', { ticket: bob.ticket });
      await alice.call('connect', { ticket: bob.ticket });

      await alice.call('send', { channelId: 'general', content: 'too early' });
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      expect(await bob.call<InboxEntry[]>('inbox')).toEqual([]);

      // Bob accepts, on the connection that is already open.
      await bob.call('pairFromTicket', { ticket: alice.ticket });

      await alice.call('send', { channelId: 'general', content: 'heard' });
      const inbox = await inboxReaches(bob, 1);

      // Only the message sent after pairing arrives; the earlier one was
      // dropped at the time and is not replayed.
      expect(inbox.map((entry) => entry.content)).toEqual(['heard']);
    } finally {
      await Promise.all([alice.shutdown(), bob.shutdown()]);
    }
  });
});
