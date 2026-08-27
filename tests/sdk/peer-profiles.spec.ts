/**
 * Profiles — what a person publishes about themselves.
 *
 * Mutable and single-writer, which is why they are not messages: a new
 * picture replaces the old one rather than joining a list, and none of
 * it should ever appear in a conversation view.
 *
 * The tests that matter here are the boundaries — a stranger learns
 * nothing, an oversized avatar is refused from both directions, and a
 * replayed old frame does not revert someone's name.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import {
  decodeProfile,
  encodeProfile,
  MAX_AVATAR_BYTES,
  ProfileTooLargeError,
} from '../../packages/HLessEnd/src/profile-service.js';

const settle = () => new Promise((r) => setTimeout(r, 800));

async function pairedPair(): Promise<[DicsussionClient, DicsussionClient]> {
  const a = await DicsussionClient.init({ storagePath: ':memory:' });
  const b = await DicsussionClient.init({ storagePath: ':memory:' });

  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
  await a.connect(b.getTicket());

  return [a, b];
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('SDK — profile exchange', () => {
  test('a name reaches a paired peer', async () => {
    const [alice, bob] = await pairedPair();

    try {
      await alice.identity.setMyProfile({ displayName: 'Alice' });
      await settle();

      expect(bob.identity.getPeerProfile(alice.did)?.displayName).toBe('Alice');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a picture survives the round trip byte for byte', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const picture = new Uint8Array(4096);
      for (let i = 0; i < picture.length; i++) picture[i] = (i * 7) % 256;

      await alice.identity.setMyProfile({
        avatar: { mime: 'image/png', bytes: picture },
      });
      await settle();

      const seen = bob.identity.getPeerProfile(alice.did)?.avatar;
      expect(seen?.mime).toBe('image/png');
      expect(Array.from(seen?.bytes ?? [])).toEqual(Array.from(picture));
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('an update replaces rather than accumulates', async () => {
    const [alice, bob] = await pairedPair();

    try {
      await alice.identity.setMyProfile({ displayName: 'Alice' });
      await settle();
      await alice.identity.setMyProfile({ displayName: 'Alice B.' });
      await settle();

      // The whole point of not being a message: one current value, not
      // a history of every name this person has ever used.
      expect(bob.identity.getPeerProfile(alice.did)?.displayName).toBe(
        'Alice B.',
      );
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('setting one field keeps the others', async () => {
    const [alice, bob] = await pairedPair();

    try {
      await alice.identity.setMyProfile({
        displayName: 'Alice',
        bio: 'Likes boats',
      });
      await settle();
      await alice.identity.setMyProfile({ bio: 'Likes bigger boats' });
      await settle();

      const seen = bob.identity.getPeerProfile(alice.did);
      expect(seen?.displayName).toBe('Alice');
      expect(seen?.bio).toBe('Likes bigger boats');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('null clears a field', async () => {
    const [alice, bob] = await pairedPair();

    try {
      await alice.identity.setMyProfile({ displayName: 'Alice', bio: 'Hello' });
      await settle();
      await alice.identity.setMyProfile({ bio: null });
      await settle();

      const seen = bob.identity.getPeerProfile(alice.did);
      expect(seen?.displayName).toBe('Alice');
      expect(seen?.bio).toBeUndefined();
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a listener is told when a peer changes theirs', async () => {
    const [alice, bob] = await pairedPair();

    try {
      const seen: string[] = [];
      bob.identity.onPeerProfile((did, profile) => {
        if (did === alice.did && profile.displayName) {
          seen.push(profile.displayName);
        }
      });

      await alice.identity.setMyProfile({ displayName: 'Alice' });
      await settle();

      expect(seen).toEqual(['Alice']);
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('a profile set before connecting still arrives', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Set while nobody is connected: the broadcast reaches zero peers,
      // and the profile has to travel when the connection opens instead.
      const reached = await alice.identity.setMyProfile({
        displayName: 'Alice',
      });
      expect(reached).toBe(0);

      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
      await alice.connect(bob.getTicket());
      await settle();

      expect(bob.identity.getPeerProfile(alice.did)?.displayName).toBe('Alice');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — a profile is not public', () => {
  test('an unpaired peer who dials learns nothing', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      await alice.identity.setMyProfile({ displayName: 'Alice' });

      // A ticket is shareable, and dialling one is not consent to learn
      // who is on the other end. Alice never accepts this peer.
      await stranger.connect(alice.getTicket());
      await settle();

      expect(stranger.identity.getPeerProfile(alice.did)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await stranger.disconnect();
    }
  });

  test('a profile from an unpaired peer is refused', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const stranger = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Dialling a ticket registers its owner, so the stranger considers
      // Alice paired and will announce itself to her. Alice has agreed
      // to nothing, and stores nothing.
      await stranger.identity.setMyProfile({ displayName: 'Nobody' });
      await stranger.connect(alice.getTicket());
      await settle();

      expect(alice.identity.getPeerProfile(stranger.did)).toBeUndefined();
    } finally {
      await alice.disconnect();
      await stranger.disconnect();
    }
  });

  test('accepting a connected peer delivers it without a redial', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      await alice.identity.setMyProfile({ displayName: 'Alice' });

      await bob.connect(alice.getTicket());
      await settle();

      // Connected, but Alice has not accepted him.
      expect(bob.identity.getPeerProfile(alice.did)).toBeUndefined();

      // Accepting is the moment he becomes entitled to it. Waiting for a
      // reconnection instead would leave him nameless for as long as
      // this connection happens to last.
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      await settle();

      expect(bob.identity.getPeerProfile(alice.did)?.displayName).toBe('Alice');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });
});

test.describe('SDK — profile limits', () => {
  test('an oversized avatar is refused', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // Without a cap the first person to set a 12MB photo replicates it
      // to everyone they ever talk to.
      const huge = new Uint8Array(MAX_AVATAR_BYTES + 1);

      await expect(
        alice.identity.setMyProfile({
          avatar: { mime: 'image/png', bytes: huge },
        }),
      ).rejects.toThrow(ProfileTooLargeError);
    } finally {
      await alice.disconnect();
    }
  });

  test('the error names the field and the limit', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      // The app has to phrase this for a human, so it needs more than a
      // rejected call it cannot explain.
      const error = await alice.identity
        .setMyProfile({ bio: 'x'.repeat(2000) })
        .catch((e: unknown) => e as ProfileTooLargeError);

      expect(error).toBeInstanceOf(ProfileTooLargeError);
      expect(error.field).toBe('bio');
      expect(error.limit).toBe(1024);
      expect(error.actual).toBe(2000);
    } finally {
      await alice.disconnect();
    }
  });
});

test.describe('Profile wire format', () => {
  test('a round trip preserves every field', () => {
    const profile = {
      displayName: 'Alice',
      bio: 'Likes boats',
      avatar: { mime: 'image/webp', bytes: new Uint8Array([1, 2, 3, 4, 5]) },
      updatedAt: 1_700_000_000_000,
    };

    const back = decodeProfile(encodeProfile(profile));

    expect(back.displayName).toBe('Alice');
    expect(back.bio).toBe('Likes boats');
    expect(back.avatar?.mime).toBe('image/webp');
    expect(Array.from(back.avatar?.bytes ?? [])).toEqual([1, 2, 3, 4, 5]);
    expect(back.updatedAt).toBe(1_700_000_000_000);
  });

  test('a profile without a picture round trips', () => {
    const back = decodeProfile(
      encodeProfile({ displayName: 'Alice', updatedAt: 1 }),
    );

    expect(back.displayName).toBe('Alice');
    expect(back.avatar).toBeUndefined();
  });

  test('a frame missing its clock sorts to the bottom', () => {
    // Taking Date.now() here would let a malformed frame outrank every
    // legitimate version that follows it.
    const forged = new TextEncoder().encode(JSON.stringify({ bio: 'no clock' }));
    const framed = new Uint8Array(4 + forged.length);
    new DataView(framed.buffer).setUint32(0, forged.length, false);
    framed.set(forged, 4);

    expect(decodeProfile(framed).updatedAt).toBe(0);
  });

  test('a truncated frame is rejected rather than half-read', () => {
    const framed = new Uint8Array(8);
    new DataView(framed.buffer).setUint32(0, 999, false);

    expect(() => decodeProfile(framed)).toThrow(/does not carry/);
  });
});
