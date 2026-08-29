import { expect, test } from '@playwright/test';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

const settle = (ms = 1500) => new Promise((r) => setTimeout(r, ms));
test.describe.configure({ mode: 'serial', timeout: 90_000 });

const opts = { transport: 'iroh' as const, localOnly: true, bindAddr: '127.0.0.1:0' };

test.describe('Knocking end to end over QUIC', () => {
  test('a stranger knocks, is accepted, and can then talk', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' }, opts);
    const bob = await DicsussionClient.init({ storagePath: ':memory:' }, opts);

    try {
      await alice.connect(bob.getTicket());
      await settle();

      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      const [request] = bob.pendingPairingRequests();
      expect(request?.peerDid).toBe(alice.did);
      expect(request?.displayName).toBe('Alice');

      // Over a real transport the ticket carries addresses, which is
      // what makes it usable for reconnecting later.
      expect(request?.ticket.directAddresses.length).toBeGreaterThan(0);
      expect(request?.ticket.encryptionKey).toBeDefined();

      bob.acceptPairingRequest(request!);
      await settle();

      alice.chat.createChannel('room', [bob.did]);
      bob.chat.createChannel('room', [alice.did]);

      const arrived = new Promise<string>((resolve) => {
        bob.chat.onMessage('room', (m) => resolve(m.content));
      });
      await alice.chat.sendMessage({ channelId: 'room', content: 'hello' });

      expect(await arrived).toBe('hello');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the ticket that arrived is genuinely dialable', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' }, opts);
    const bob = await DicsussionClient.init({ storagePath: ':memory:' }, opts);
    const carol = await DicsussionClient.init({ storagePath: ':memory:' }, opts);

    try {
      await alice.connect(bob.getTicket());
      await settle();
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      const [request] = bob.pendingPairingRequests();

      // Dialled by a third peer rather than by Bob, who already holds a
      // connection to her — this is about whether the ticket carries
      // working addresses, not whether an existing link still works.
      await carol.connect(request!.ticket);
      await settle();

      expect(carol.getNetworkStatus().peerCount).toBeGreaterThan(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      await carol.disconnect();
    }
  });
});
