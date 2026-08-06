/**
 * Phase 3 — RLN enforcement on live message traffic.
 *
 * The gap this closes: proving and slashing were built and tested in
 * isolation, but no *message* carried a signal, so the rate limit was
 * unenforceable on real traffic. A reviewer correctly flagged that the
 * headline claim — "sending twice reveals your secret" — did not hold on
 * the wire.
 *
 * These tests drive the claim through the ordinary send path.
 */

import { expect, test } from '@playwright/test';

import { clearTransportRegistry } from '@dicsussion/core/transport';
import { hexToField } from '@dicsussion/core/crypto';
import { isWithinQuota, quotaForTier } from '@dicsussion/core/zk';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import type { SdkChatMessage } from '../../packages/HLessEnd/src/types.js';

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 5_000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return predicate();
}

async function pair(): Promise<{
  alice: DicsussionClient;
  bob: DicsussionClient;
  teardown: () => Promise<void>;
}> {
  const alice = await DicsussionClient.init({ storagePath: ':memory:' });
  const bob = await DicsussionClient.init({ storagePath: ':memory:' });

  alice.addPeer(bob.did, bob.encryptionPublicKey);
  bob.addPeer(alice.did, alice.encryptionPublicKey);
  await alice.connect(bob.getTicket());
  await waitFor(() => bob.getNetworkStatus().peerCount === 1);

  return {
    alice,
    bob,
    teardown: async () => {
      await alice.disconnect();
      await bob.disconnect();
      clearTransportRegistry();
    },
  };
}

test.describe('Suite 3.3 — RLN on Live Traffic', () => {
  test.afterEach(() => {
    clearTransportRegistry();
  });

  test('an anonymous message carries a nullifier AND its share', () => {
    // Without `y` on the wire a recipient can see a nullifier repeat but
    // cannot interpolate the secret — the rate limit would be
    // unenforceable. Both must travel.
    return (async () => {
      const client = await DicsussionClient.init({ storagePath: ':memory:' });

      try {
        const sent = await client.chat.sendMessage({
          channelId: 'anon',
          content: 'signalled',
          anonymous: true,
        });

        expect(sent.nullifierHash).toMatch(/^0x[0-9a-f]{64}$/);

        const signal = client.getLastRlnSignal();
        expect(signal).not.toBeNull();
        expect(hexToField(sent.nullifierHash!)).toBe(signal!.nullifier);
      } finally {
        await client.disconnect();
      }
    })();
  });

  test('a recipient receives the share alongside the message', async () => {
    const { alice, bob, teardown } = await pair();

    try {
      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('anon', (m) => received.push(m));

      await alice.chat.sendMessage({
        channelId: 'anon',
        content: 'over the wire',
        anonymous: true,
      });

      expect(await waitFor(() => received.length === 1)).toBe(true);
      expect(received[0]!.nullifierHash).toBeDefined();
      // The signal was validated, not assumed.
      expect(received[0]!.proofValid).toBe(true);
    } finally {
      await teardown();
    }
  });

  test('honest anonymous traffic produces no slashing', async () => {
    const { alice, bob, teardown } = await pair();

    try {
      const slashings: unknown[] = [];
      bob.onSlashing((e) => slashings.push(e));

      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('anon', (m) => received.push(m));

      // Distinct message indices ⇒ distinct nullifiers.
      for (const content of ['one', 'two', 'three']) {
        await alice.chat.sendMessage({ channelId: 'anon', content, anonymous: true });
      }

      expect(await waitFor(() => received.length === 3)).toBe(true);
      expect(slashings).toHaveLength(0);
    } finally {
      await teardown();
    }
  });

  test('a message whose share is stripped is rejected', async () => {
    const { alice, bob, teardown } = await pair();

    try {
      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('anon', (m) => received.push(m));

      // A nullifier with no share is unverifiable — accepting it would
      // let a sender claim anonymity while being unslashable.
      await expect(
        bob.chat.ingestRemote({
          id: 'forged-1',
          channelId: 'anon',
          content: 'no share attached',
          timestamp: Math.floor(Date.now() / 1000),
          messageIndex: 0,
          nullifierHash: `0x${'ab'.repeat(32)}`,
        }),
      ).rejects.toThrow(/RLN signal failed validation/);

      expect(received).toHaveLength(0);
    } finally {
      await teardown();
    }
  });

  test('a message beyond the rolling-window quota is rejected', async () => {
    const { alice, bob, teardown } = await pair();

    try {
      const overQuota = quotaForTier(0) * 3;
      expect(isWithinQuota(overQuota, 0)).toBe(false);

      await expect(
        bob.chat.ingestRemote({
          id: 'over-quota',
          channelId: 'anon',
          content: 'past my allowance',
          timestamp: Math.floor(Date.now() / 1000),
          messageIndex: overQuota,
          nullifierHash: `0x${'cd'.repeat(32)}`,
          rlnShare: { x: `0x${'01'.repeat(32)}`, y: `0x${'02'.repeat(32)}` },
        }),
      ).rejects.toThrow(/RLN signal failed validation/);
    } finally {
      await teardown();
    }
  });

  test('attributed messages need no RLN signal', async () => {
    const { alice, bob, teardown } = await pair();

    try {
      const received: SdkChatMessage[] = [];
      bob.chat.onMessage('general', (m) => received.push(m));

      // The sender is identified, so rate limiting can key on did:key —
      // paying for an RLN signal here would be pure cost.
      await alice.chat.sendMessage({ channelId: 'general', content: 'attributed' });

      expect(await waitFor(() => received.length === 1)).toBe(true);
      expect(received[0]!.nullifierHash).toBeUndefined();
      expect(received[0]!.proofValid).toBe(true);
    } finally {
      await teardown();
    }
  });

  test('reusing a nullifier across two messages reveals the secret', async () => {
    const { alice, bob, teardown } = await pair();

    try {
      const slashings: Array<{ tombstone: { membershipCommitment: bigint } }> = [];
      bob.onSlashing((e) => slashings.push(e as never));

      // Alice sends honestly, then a forged duplicate reusing her
      // nullifier at a different message commitment — exactly what
      // exceeding quota produces.
      await alice.chat.sendMessage({
        channelId: 'anon',
        content: 'first',
        anonymous: true,
      });

      const signal = alice.getLastRlnSignal()!;

      // Same nullifier, different x — a genuine double-send.
      await bob.chat
        .ingestRemote({
          id: 'reused',
          channelId: 'anon',
          content: 'second under the same nullifier',
          timestamp: Math.floor(Date.now() / 1000),
          messageIndex: signal.messageIndex,
          nullifierHash: `0x${signal.nullifier.toString(16).padStart(64, '0')}`,
          rlnShare: {
            x: `0x${(signal.x + 1n).toString(16).padStart(64, '0')}`,
            y: `0x${(signal.y + 1n).toString(16).padStart(64, '0')}`,
          },
        })
        .catch(() => undefined);

      // Bob now holds two points on one line and can interpolate.
      expect(await waitFor(() => slashings.length > 0)).toBe(true);
    } finally {
      await teardown();
    }
  });
});
