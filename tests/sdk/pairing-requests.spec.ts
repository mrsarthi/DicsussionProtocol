/**
 * A stranger knocking (Stream `0x0a`).
 *
 * A handshake proves a peer's `did:key` and discloses nothing else — not
 * their encryption key, derived under a separate HKDF label, nor their
 * addresses. So before this existed a node could know exactly who was
 * calling and still be unable to encrypt for them or dial them back,
 * which is why a human had to copy a ticket between devices.
 *
 * The tests that matter are the boundaries: a request must not become a
 * channel a stranger can talk on, and a ticket must not be presentable
 * on behalf of someone else.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import {
  decodeRequest,
  encodeRequest,
  MAX_REQUEST_NAME_LENGTH,
} from '../../packages/HLessEnd/src/pairing-request.js';
import type { PairingRequest } from '../../packages/HLessEnd/src/pairing-request.js';

const settle = (ms = 800) => new Promise((r) => setTimeout(r, ms));

/** A dials B's ticket. B has never heard of A. */
async function knockingPair(): Promise<[DicsussionClient, DicsussionClient]> {
  const a = await DicsussionClient.init({ storagePath: ':memory:' });
  const b = await DicsussionClient.init({ storagePath: ':memory:' });

  await a.connect(b.getTicket());
  await settle();

  return [a, b];
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('SDK — knocking', () => {
  test('a stranger can ask, and carries their ticket with them', async () => {
    const [alice, bob] = await knockingPair();

    try {
      const knock = new Promise<PairingRequest>((resolve) => {
        bob.onPairingRequest.on('request', resolve);
      });

      const sent = await alice.requestPairing(bob.did, { displayName: 'Alice' });
      expect(sent).toBe(true);

      const request = await knock;
      expect(request.peerDid).toBe(alice.did);
      expect(request.displayName).toBe('Alice');
      // The point of the whole exercise: Bob now holds what he needs.
      expect(request.ticket.encryptionKey).toBeDefined();
      expect(Array.from(request.ticket.encryptionKey!)).toEqual(
        Array.from(alice.encryptionPublicKey),
      );
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('accepting pairs them without anything pasted', async () => {
    const [alice, bob] = await knockingPair();

    try {
      const knock = new Promise<PairingRequest>((resolve) => {
        bob.onPairingRequest.on('request', resolve);
      });
      await alice.requestPairing(bob.did, { displayName: 'Alice' });

      bob.acceptPairingRequest(await knock);
      await settle();

      // Paired both ways now: Alice registered Bob by dialling his
      // ticket, Bob registered Alice by accepting her knock.
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

  test('a name is optional', async () => {
    const [alice, bob] = await knockingPair();

    try {
      const knock = new Promise<PairingRequest>((resolve) => {
        bob.onPairingRequest.on('request', resolve);
      });
      await alice.requestPairing(bob.did);

      const request = await knock;
      expect(request.displayName).toBeUndefined();
      expect(request.ticket.encryptionKey).toBeDefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a knock that arrives before anyone is listening is not lost', async () => {
    const [alice, bob] = await knockingPair();

    try {
      // An inbound connection and a UI mounting are not ordered, and a
      // stranger only gets one request.
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      const pending = bob.pendingPairingRequests();
      expect(pending).toHaveLength(1);
      expect(pending[0]?.displayName).toBe('Alice');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('accepting clears it from pending', async () => {
    const [alice, bob] = await knockingPair();

    try {
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      bob.acceptPairingRequest(bob.pendingPairingRequests()[0]!);
      expect(bob.pendingPairingRequests()).toHaveLength(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('declining clears it without pairing', async () => {
    const [alice, bob] = await knockingPair();

    try {
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      bob.declinePairingRequest(bob.pendingPairingRequests()[0]!);
      expect(bob.pendingPairingRequests()).toHaveLength(0);

      // Declining is not pairing. Bob still cannot receive from her.
      bob.chat.createChannel('room', [alice.did]);
      alice.chat.createChannel('room', [bob.did]);

      let seen = 0;
      bob.chat.onMessage('room', () => seen++);
      await alice.chat.sendMessage({ channelId: 'room', content: 'still here' });
      await settle();

      expect(seen).toBe(0);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('an over-long name is refused before it is sent', async () => {
    const [alice, bob] = await knockingPair();

    try {
      await expect(
        alice.requestPairing(bob.did, {
          displayName: 'x'.repeat(MAX_REQUEST_NAME_LENGTH + 1),
        }),
      ).rejects.toThrow(/limit/);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('requesting from an unreachable peer reports false', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      expect(await alice.requestPairing('did:key:zNobody')).toBe(false);
    } finally {
      await alice.disconnect();
    }
  });
});

test.describe('SDK — a knock is not a channel', () => {
  test('a stranger gets one request, not a stream', async () => {
    const [alice, bob] = await knockingPair();

    try {
      const seen: PairingRequest[] = [];
      bob.onPairingRequest.on('request', (r) => seen.push(r));

      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await alice.requestPairing(bob.did, { displayName: 'Alice again' });
      await alice.requestPairing(bob.did, { displayName: 'and again' });
      await settle();

      // Otherwise an unpaired peer has found a way to send us whatever
      // it likes, as often as it likes.
      expect(seen).toHaveLength(1);
      expect(seen[0]?.displayName).toBe('Alice');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('knocking still sends nothing else', async () => {
    const [alice, bob] = await knockingPair();

    try {
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      // Bob has a knock. Alice is still unpaired, so every other stream
      // stays shut to her.
      alice.chat.createChannel('room', [bob.did]);
      bob.chat.createChannel('room', [alice.did]);

      let messages = 0;
      let ephemeral = 0;
      bob.chat.onMessage('room', () => messages++);
      bob.chat.onEphemeral('room', () => ephemeral++);

      await alice.chat.sendMessage({ channelId: 'room', content: 'sneaking in' });
      await alice.chat.sendEphemeral('room', new TextEncoder().encode('typing'));
      await alice.identity.setMyProfile({ displayName: 'Alice' });
      await settle();

      expect(messages).toBe(0);
      expect(ephemeral).toBe(0);
      expect(bob.identity.getPeerProfile(alice.did)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('Pairing request wire format', () => {
  test('a round trip preserves the ticket and the name', () => {
    const ticket = {
      didKey: 'did:key:zAlice',
      nodeId: new Uint8Array(32).fill(1),
      directAddresses: ['127.0.0.1:4242'],
      encryptionKey: new Uint8Array(32).fill(2),
    };

    const back = decodeRequest(encodeRequest(ticket, 'Alice'), 'did:key:zAlice');

    expect(back?.displayName).toBe('Alice');
    expect(back?.ticket.didKey).toBe('did:key:zAlice');
    expect(Array.from(back?.ticket.encryptionKey ?? [])).toEqual(
      Array.from(ticket.encryptionKey),
    );
  });

  test('a ticket belonging to someone else is refused', () => {
    // The check the whole thing rests on. Without it a peer could
    // present a stranger's ticket and have this node register that
    // stranger's key — or dial a third party — off a connection it
    // proved only its own identity on.
    const someoneElse = {
      didKey: 'did:key:zVictim',
      nodeId: new Uint8Array(32).fill(1),
      directAddresses: [],
      encryptionKey: new Uint8Array(32).fill(2),
    };

    expect(
      decodeRequest(encodeRequest(someoneElse, 'Victim'), 'did:key:zAttacker'),
    ).toBeUndefined();
  });

  test('a ticket without an encryption key is refused', () => {
    // It would produce an accept button that silently does nothing.
    const useless = {
      didKey: 'did:key:zAlice',
      nodeId: new Uint8Array(32).fill(1),
      directAddresses: [],
    };

    expect(
      decodeRequest(encodeRequest(useless, 'Alice'), 'did:key:zAlice'),
    ).toBeUndefined();
  });

  test('an over-long name is dropped, the request is not', () => {
    const ticket = {
      didKey: 'did:key:zAlice',
      nodeId: new Uint8Array(32).fill(1),
      directAddresses: [],
      encryptionKey: new Uint8Array(32).fill(2),
    };

    const back = decodeRequest(
      encodeRequest(ticket, 'x'.repeat(MAX_REQUEST_NAME_LENGTH + 1)),
      'did:key:zAlice',
    );

    expect(back).toBeDefined();
    expect(back?.displayName).toBeUndefined();
  });

  test('an oversized payload is refused', () => {
    expect(decodeRequest(new Uint8Array(5000), 'did:key:zAlice')).toBeUndefined();
  });

  test('junk is refused rather than throwing', () => {
    expect(
      decodeRequest(new TextEncoder().encode('not json'), 'did:key:zAlice'),
    ).toBeUndefined();
    expect(
      decodeRequest(new TextEncoder().encode('{"ticket":"garbage"}'), 'did:key:zA'),
    ).toBeUndefined();
    expect(decodeRequest(new Uint8Array(0), 'did:key:zAlice')).toBeUndefined();
  });
});

test.describe('SDK — a profile set before being accepted', () => {
  test('arrives once the knock is accepted', async () => {
    const [alice, bob] = await knockingPair();

    try {
      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();

      // Set while Bob still treats her as a stranger. He drops it,
      // correctly — and nothing used to re-send it, because she has no
      // way to learn he later accepted. That left an accepted peer
      // nameless until she happened to edit her profile again.
      await alice.identity.setMyProfile({ displayName: 'Alice', bio: 'hi' });
      await settle();
      expect(bob.identity.getPeerProfile(alice.did)).toBeUndefined();

      bob.acceptPairingRequest(bob.pendingPairingRequests()[0]!);
      await settle(1500);

      expect(bob.identity.getPeerProfile(alice.did)?.bio).toBe('hi');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the exchange settles instead of echoing', async () => {
    const [alice, bob] = await knockingPair();

    try {
      // Both sides answer a received profile with their own, so without
      // a per-connection guard they would reply to each other forever.
      await alice.identity.setMyProfile({ displayName: 'Alice' });
      await bob.identity.setMyProfile({ displayName: 'Bob' });

      let atAlice = 0;
      let atBob = 0;
      alice.identity.onPeerProfile(() => atAlice++);
      bob.identity.onPeerProfile(() => atBob++);

      await alice.requestPairing(bob.did, { displayName: 'Alice' });
      await settle();
      bob.acceptPairingRequest(bob.pendingPairingRequests()[0]!);
      await settle(2500);

      expect(bob.identity.getPeerProfile(alice.did)?.displayName).toBe('Alice');
      expect(alice.identity.getPeerProfile(bob.did)?.displayName).toBe('Bob');
      expect(atAlice).toBe(1);
      expect(atBob).toBe(1);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});
