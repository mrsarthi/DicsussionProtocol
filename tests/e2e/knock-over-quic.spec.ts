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

test.describe('Profiles after a knock, over QUIC', () => {
  test('a profile published before acceptance arrives on accept', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' }, opts);
    const bob = await DicsussionClient.init({ storagePath: ':memory:' }, opts);

    try {
      await alice.connect(bob.getTicket());
      await settle();
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      // Published while Bob still treats her as a stranger, so he drops
      // it. Nothing resends it on its own — she cannot learn she was
      // accepted — so before this was fixed she stayed nameless until
      // she happened to edit her profile again.
      await alice.identity.setMyProfile({ displayName: 'Alice', bio: 'boats' });
      await settle();
      expect(bob.identity.getPeerProfile(alice.did)).toBeUndefined();

      // Bob has no profile of his own, which is the case that matters:
      // announcing on accept sends nothing, so accepting has to ask.
      bob.acceptPairingRequest(bob.pendingPairingRequests()[0]!);
      await settle(2500);

      expect(bob.identity.getPeerProfile(alice.did)?.bio).toBe('boats');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('Sealed delivery over QUIC', () => {
  test('a courier carries a message between peers that never meet', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' }, opts);
    const bob = await DicsussionClient.init({ storagePath: ':memory:' }, opts);
    const carol = await DicsussionClient.init({ storagePath: ':memory:' }, opts);

    try {
      // Alice and Bob are paired and never connect to each other. Carol
      // is the only one who reaches Bob.
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
      alice.chat.createChannel('room', [bob.did]);
      bob.chat.createChannel('room', [alice.did]);

      carol.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(carol.did, carol.encryptionPublicKey);
      await carol.connect(bob.getTicket());
      await settle();

      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'carried over QUIC',
      });

      const heard = new Promise<string>((resolve) => {
        bob.chat.onMessage('room', (m) => resolve(m.content));
      });

      expect(await carol.deliverSealed(bob.did, envelope)).toBe(true);
      expect(await heard).toBe('carried over QUIC');

      // Carol relayed it and still cannot read it.
      expect(await carol.openSealed(envelope)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      await carol.disconnect();
    }
  });
});
