/**
 * A peer must not be able to write itself into a conversation by naming
 * its channel id.
 *
 * Channel ids are chosen by applications and travel in plaintext frames.
 * They are identifiers, not secrets, and anything that treats them as
 * secrets is one guess away from failing.
 *
 * The hole: a channel came into existence from an inbound message, which
 * recorded its sender as a participant. A paired peer could therefore
 * name the id of a conversation it had no part in, be recorded in it, and
 * receive everything sent there afterwards — including messages the
 * sender believed were private to someone else. Reproduced before the
 * fix; Carol received Alice's message to Bob.
 */

import { expect, test } from '@playwright/test';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';

const settle = () => new Promise((r) => setTimeout(r, 1200));
const history = async (c: DicsussionClient, ch: string): Promise<string[]> =>
  (await c.chat.getHistory(ch)).map((m) => m.content);

function pair(a: DicsussionClient, b: DicsussionClient): void {
  a.addPeer(b.did, b.encryptionPublicKey);
  b.addPeer(a.did, a.encryptionPublicKey);
}

test.describe.configure({ mode: 'serial', timeout: 60_000 });

test.describe('SDK — channel ids are not secrets', () => {
  test('squatting a channel id does not grant the conversation', async () => {
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });
    const carol = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      pair(alice, bob);
      pair(alice, carol);

      // Carol guesses the id Alice will use for Bob, and speaks first.
      carol.chat.createChannel('alice+bob', [alice.did]);
      await carol.connect(alice.getTicket());
      await carol.chat.sendMessage({ channelId: 'alice+bob', content: 'squatting' });
      await settle();

      // Alice then starts what she believes is a private chat with Bob.
      alice.chat.createChannel('alice+bob', [bob.did]);
      await alice.connect(bob.getTicket());
      await alice.chat.sendMessage({
        channelId: 'alice+bob',
        content: 'SECRET-FOR-BOB',
      });
      await settle();

      expect(await history(bob, 'alice+bob')).toContain('SECRET-FOR-BOB');

      // Declaring the conversation states who is in it, so Carol — only
      // ever there by inference — is not.
      expect(await history(carol, 'alice+bob')).not.toContain('SECRET-FOR-BOB');
      expect(
        (alice as unknown as { documents: { isParticipant(a: string, b: string): boolean } })
          .documents.isParticipant('alice+bob', carol.did),
      ).toBe(false);
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });

  test('someone opening a new conversation with you still works', async () => {
    // The flow the inference exists for. Removing it entirely would mean
    // a reply had nowhere to go.
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      pair(alice, bob);
      alice.chat.createChannel('fresh', [bob.did]);
      await alice.connect(bob.getTicket());
      await alice.chat.sendMessage({ channelId: 'fresh', content: 'hello' });
      await settle();

      expect(await history(bob, 'fresh')).toEqual(['hello']);

      // Bob can answer without declaring anything: the channel was
      // created in response to Alice, so she is recorded in it.
      await bob.chat.sendMessage({ channelId: 'fresh', content: 'hi back' });
      await settle();

      expect(await history(alice, 'fresh')).toContain('hi back');
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect()]);
    }
  });

  test('addParticipant admits without erasing', async () => {
    // `createChannel` states the whole membership, which is what closes
    // the hole above — so growing a group needs its own verb.
    const alice = await DicsussionClient.init({ storagePath: ':memory:' });
    const bob = await DicsussionClient.init({ storagePath: ':memory:' });
    const carol = await DicsussionClient.init({ storagePath: ':memory:' });

    try {
      alice.chat.createChannel('team', [bob.did]);
      alice.chat.addParticipant('team', carol.did);

      const docs = (alice as unknown as {
        documents: { participants(id: string): string[] };
      }).documents;

      expect(docs.participants('team').sort()).toEqual(
        [alice.did, bob.did, carol.did].sort(),
      );

      // Re-declaring, by contrast, is authoritative.
      alice.chat.createChannel('team', [bob.did]);
      expect(docs.participants('team').sort()).toEqual([alice.did, bob.did].sort());
    } finally {
      await Promise.all([alice.disconnect(), bob.disconnect(), carol.disconnect()]);
    }
  });
});
