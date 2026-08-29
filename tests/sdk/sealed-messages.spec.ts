/**
 * Messages sealed for someone who is not there (Stream `0x0b`).
 *
 * Live traffic is sealed under a session key that exists only while both
 * peers are connected, so there has been nothing to store for a sleeping
 * recipient. These are sealed instead to the static key a ticket already
 * carries.
 *
 * The happy path is one test. The rest are the attacks, because an
 * envelope is handed to something untrusted by design: a mailbox learns
 * nothing, a stranger cannot inject, a recipient cannot forward as its
 * author, and nothing opens twice or forever.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { MAX_SEALED_BYTES } from '../../packages/HLessEnd/src/sealed-message.js';

const settle = (ms = 800) => new Promise((r) => setTimeout(r, ms));

/** Paired both ways, never connected — the point is offline delivery. */
async function pairedButApart(): Promise<[DicsussionClient, DicsussionClient]> {
  const a = await DicsussionClient.init({ storagePath: ':memory:' });
  const b = await DicsussionClient.init({ storagePath: ':memory:' });

  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
  a.chat.createChannel('room', [b.did]);
  b.chat.createChannel('room', [a.did]);

  return [a, b];
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('SDK — sealing for someone who is away', () => {
  test('a message survives with no connection at any point', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      // Neither has ever dialled the other. This is the whole point:
      // nothing here needs a session, because there is no session.
      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'left on your doorstep',
      });

      const opened = await bob.openSealed(envelope);

      expect(opened?.content).toBe('left on your doorstep');
      expect(opened?.authorDid).toBe(alice.did);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('it reaches onMessage and history like any other message', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      const heard = new Promise<string>((resolve) => {
        bob.chat.onMessage('room', (m) => resolve(m.content));
      });

      await bob.openSealed(
        await alice.sealForPeer(bob.did, {
          channelId: 'room',
          content: 'delivered late',
        }),
      );

      expect(await heard).toBe('delivered late');
      const history = await bob.chat.getHistory('room');
      expect(history.some((m) => m.content === 'delivered late')).toBe(true);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('attachments and replies survive the round trip', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      const ref = await alice.blobs.put(new Uint8Array([1, 2, 3]), 'image/png');
      const opened = await bob.openSealed(
        await alice.sealForPeer(bob.did, {
          channelId: 'room',
          content: 'with things',
          attachments: [ref],
          replyTo: ['earlier-message'],
        }),
      );

      expect(opened?.attachments?.[0]?.hash).toBe(ref.hash);
      expect(opened?.replyTo).toEqual(['earlier-message']);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the same message delivered twice is surfaced once', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      // A mailbox that retries, or an envelope that also arrived by a
      // courier peer. Both are legitimate; the user must see one message.
      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'once please',
      });

      let seen = 0;
      bob.chat.onMessage('room', () => seen++);

      await bob.openSealed(envelope);
      await bob.openSealed(envelope);
      await settle();

      expect(seen).toBe(1);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('sealing for an unknown peer fails with a reason', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Sealing needs their static key, which only pairing supplies.
      await expect(
        alice.sealForPeer('did:key:zStranger', {
          channelId: 'room',
          content: 'hello?',
        }),
      ).rejects.toThrow(/addPeer/);
    } finally {
      await alice.disconnect();
    }
  });
});

test.describe('SDK — what a mailbox learns', () => {
  test('an envelope names nobody and no conversation', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'a-very-distinctive-channel',
        content: 'a very distinctive sentence',
      });

      const asText = new TextDecoder().decode(envelope);
      const asHex = Buffer.from(envelope).toString('hex');

      // Whoever stores this learns a version byte and noise.
      for (const secret of [
        'a-very-distinctive-channel',
        'a very distinctive sentence',
        alice.did,
        bob.did,
      ]) {
        expect(asText).not.toContain(secret);
        expect(asHex).not.toContain(Buffer.from(secret).toString('hex'));
      }
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a third party cannot open one', async () => {
    const [alice, bob] = await pairedButApart();
    const carol = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      carol.addPeer(alice.did, alice.encryptionPublicKey);

      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'for bob only',
      });

      expect(await carol.openSealed(envelope)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      await carol.disconnect();
    }
  });
});

test.describe('SDK — what an envelope refuses', () => {
  test('a stranger cannot drop a message into a mailbox', async () => {
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // The stranger knows Bob's key — a ticket is shareable — so the
      // envelope decrypts. Pairing is what decides whether it counts,
      // exactly as on a live connection.
      stranger.addPeer(bob.did, bob.encryptionPublicKey);

      const envelope = await stranger.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'unsolicited',
      });

      expect(await bob.openSealed(envelope)).toBeUndefined();
    } finally {
      await bob.disconnect();
      await stranger.disconnect();
    }
  });

  test('a recipient cannot forward one as its author', async () => {
    const [alice, bob] = await pairedButApart();
    const carol = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      carol.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(carol.did, carol.encryptionPublicKey);

      const forAlice = await bob.sealForPeer(alice.did, {
        channelId: 'room',
        content: 'between us',
      });

      // Carol is named in neither the envelope nor the signature. Were
      // the recipient not bound into the signed transcript, a message
      // could be re-sealed onward and still verify as its author's.
      expect(await carol.openSealed(forAlice)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      await carol.disconnect();
    }
  });

  test('a tampered envelope does not open', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'unmodified',
      });

      const tampered = new Uint8Array(envelope);
      tampered[tampered.length - 1] ^= 0xff;

      expect(await bob.openSealed(tampered)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('junk and truncation are refused rather than throwing', async () => {
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      expect(await bob.openSealed(new Uint8Array(0))).toBeUndefined();
      expect(await bob.openSealed(new Uint8Array(10))).toBeUndefined();
      expect(await bob.openSealed(new Uint8Array(200).fill(7))).toBeUndefined();
      expect(
        await bob.openSealed(new Uint8Array(MAX_SEALED_BYTES + 1)),
      ).toBeUndefined();
    } finally {
      await bob.disconnect();
    }
  });

  test('a peer removed from a conversation cannot write into it', async () => {
    const [alice, bob] = await pairedButApart();

    try {
      // Bob's copy of the conversation no longer lists Alice. A sealed
      // envelope must not be a way around that, or removal means only
      // "stops receiving" and never "stops sending".
      bob.chat.removeParticipant('room', alice.did);

      const envelope = await alice.sealForPeer(bob.did, {
        channelId: 'room',
        content: 'still here',
      });

      expect(await bob.openSealed(envelope)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — carried by someone else', () => {
  test('a courier delivers an envelope it cannot read', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });
    const carol = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Alice and Bob are paired but never meet. Carol is paired with
      // both and is the only one connected to Bob.
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
        content: 'passed along',
      });

      // Carol holds it. She is not the recipient and cannot open it.
      expect(await carol.openSealed(envelope)).toBeUndefined();

      const heard = new Promise<string>((resolve) => {
        bob.chat.onMessage('room', (m) => resolve(m.content));
      });

      expect(await carol.deliverSealed(bob.did, envelope)).toBe(true);

      // It is Alice's message, not Carol's, and the signature says so.
      const message = await heard;
      expect(message).toBe('passed along');
      expect(
        (await bob.chat.getHistory('room')).find((m) => m.content === message)
          ?.authorDid,
      ).toBe(alice.did);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
      await carol.disconnect();
    }
  });

  test('delivering to an unreachable peer reports false', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      expect(
        await alice.deliverSealed('did:key:zNobody', new Uint8Array(50)),
      ).toBe(false);
    } finally {
      await alice.disconnect();
    }
  });
});
