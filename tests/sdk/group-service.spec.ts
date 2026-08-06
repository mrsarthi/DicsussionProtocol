/**
 * Group management (RFC 004 §7.3).
 *
 * A group is a channel: same CRDT document, same `channel_meta` row,
 * same membership tree. Creation produces a Channel Creator Genesis
 * Anchor, so joining peers verify the group's origin cryptographically
 * rather than trusting whoever invited them.
 */

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '../../packages/core/src/transport/local-transport.js';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import type { GroupInvite } from '../../packages/HLessEnd/src/types.js';

test.describe('SDK — Group Service', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('creating a group makes the creator its genesis anchor', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const group = await client.groups.createGroup('Weekend Plans', []);

      expect(group.groupId).toBeTruthy();
      expect(group.name).toBe('Weekend Plans');
      // The creator is a member even though none were passed.
      expect(group.members).toEqual([client.did]);

      const anchor = client.getGenesisAnchor(group.groupId);
      expect(anchor).toBeDefined();
      expect(anchor!.creatorDid).toBe(client.did);
      expect(anchor!.creatorCommitment).toBe(client.identityCommitment);
    } finally {
      await client.disconnect();
    }
  });

  test('initial members are recorded without duplicating the creator', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const group = await client.groups.createGroup('Team', [
        'did:key:z6MkAlice',
        'did:key:z6MkBob',
        client.did,
      ]);

      expect(group.members).toEqual([
        client.did,
        'did:key:z6MkAlice',
        'did:key:z6MkBob',
      ]);
    } finally {
      await client.disconnect();
    }
  });

  test('a group gets its own CRDT document and accepts messages', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const group = await client.groups.createGroup('Chat', []);

      await client.chat.sendMessage({
        channelId: group.groupId,
        content: 'first group message',
      });

      const history = await client.chat.getHistory(group.groupId);
      expect(history.map((m) => m.content)).toEqual(['first group message']);
    } finally {
      await client.disconnect();
    }
  });

  test('group metadata round-trips through storage', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const created = await client.groups.createGroup('Persisted', [
        'did:key:z6MkCarol',
      ]);
      const loaded = await client.groups.getGroupInfo(created.groupId);

      expect(loaded).toEqual(created);
    } finally {
      await client.disconnect();
    }
  });

  test('listGroups returns every known group', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      await client.groups.createGroup('One', []);
      await client.groups.createGroup('Two', []);

      const names = (await client.groups.listGroups()).map((g) => g.name).sort();
      expect(names).toEqual(['One', 'Two']);
    } finally {
      await client.disconnect();
    }
  });

  test('an unknown group is reported clearly', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      await expect(client.groups.getGroupInfo('nope')).rejects.toThrow(
        /Unknown group/,
      );
    } finally {
      await client.disconnect();
    }
  });

  test('joining verifies the genesis anchor and adds the member', async () => {
    const creator = await DicsussionClient.init({ storagePath: ':memory:' });
    const joiner = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const group = await creator.groups.createGroup('Open', []);
      const anchor = creator.getGenesisAnchor(group.groupId)!;

      // The joiner receives the group metadata and anchor out of band,
      // then joins as a separate, deliberate step.
      await joiner.groups.importGroup(group, anchor);
      await joiner.groups.joinGroup(group.groupId);

      const info = await joiner.groups.getGroupInfo(group.groupId);
      expect(info.members).toContain(joiner.did);

      // Membership tree was rebuilt from the anchor and now holds both.
      const tree = joiner.groups.getMembershipTree(group.groupId)!;
      expect(tree.has(creator.identityCommitment)).toBe(true);
      expect(tree.has(joiner.identityCommitment)).toBe(true);
    } finally {
      await creator.disconnect();
      await joiner.disconnect();
    }
  });

  test('importing a group whose anchor names a different channel is refused', async () => {
    const creator = await DicsussionClient.init({ storagePath: ':memory:' });
    const joiner = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const real = await creator.groups.createGroup('Real', []);
      const other = await creator.groups.createGroup('Other', []);
      const otherAnchor = creator.getGenesisAnchor(other.groupId)!;

      // A validly signed anchor for a *different* group must not be able
      // to vouch for this one.
      await expect(joiner.groups.importGroup(real, otherAnchor)).rejects.toThrow(
        /not group/,
      );
    } finally {
      await creator.disconnect();
      await joiner.disconnect();
    }
  });

  test('a tampered anchor cannot be persisted, so the group stays unjoinable', async () => {
    const creator = await DicsussionClient.init({ storagePath: ':memory:' });
    const joiner = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const group = await creator.groups.createGroup('Secure', []);
      const anchor = creator.getGenesisAnchor(group.groupId)!;

      expect(() =>
        joiner.saveGenesisAnchor({ ...anchor, creatorDid: joiner.did }),
      ).toThrow(/signature verification failed/);
    } finally {
      await creator.disconnect();
      await joiner.disconnect();
    }
  });

  test('leaving removes the member from the local roster', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const group = await client.groups.createGroup('Temporary', [
        'did:key:z6MkOther',
      ]);

      await client.groups.leaveGroup(group.groupId);

      const info = await client.groups.getGroupInfo(group.groupId);
      expect(info.members).toEqual(['did:key:z6MkOther']);
      expect(client.groups.getMembershipTree(group.groupId)).toBeUndefined();
    } finally {
      await client.disconnect();
    }
  });

  test('invite listeners fire and can unsubscribe', async () => {
    const client = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      const received: GroupInvite[] = [];
      const off = client.groups.onInvite((invite) => received.push(invite));

      const invite: GroupInvite = {
        groupId: 'g1',
        name: 'Invited',
        inviterDid: 'did:key:z6MkInviter',
        timestamp: 1_700_000_000,
      };

      client.groups.emitInvite(invite);
      expect(received).toEqual([invite]);

      off();
      client.groups.emitInvite(invite);
      expect(received).toHaveLength(1);
    } finally {
      await client.disconnect();
    }
  });
});
