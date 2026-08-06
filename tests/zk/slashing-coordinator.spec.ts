/**
 * Phase 3A — Live slashing gossip (Streams 0x03 / 0x06).
 *
 * Detection must be a side effect of ordinary participation: any node
 * that receives the traffic can slash, and no node can be silenced by an
 * accusation it cannot verify.
 */

import { expect, test } from '@playwright/test';

import { membershipCommitment } from '../../packages/core/src/crypto/poseidon.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import { StreamType } from '../../packages/core/src/transport/types.js';
import type { IConnection } from '../../packages/core/src/transport/transport-interface.js';
import { createSignal, signalToShare } from '../../packages/core/src/zk/rln.js';
import {
  encodeShare,
  encodeTombstone,
} from '../../packages/HLessEnd/src/slashing/gossip-protocol.js';
import type { ObservedShare } from '../../packages/HLessEnd/src/slashing/share-collector.js';
import { SlashingCoordinator } from '../../packages/HLessEnd/src/slashing/slashing-coordinator.js';
import type { SlashingEvent } from '../../packages/HLessEnd/src/slashing/slashing-coordinator.js';
import {
  createSlashingTombstone,
  RevocationReason,
} from '../../packages/HLessEnd/src/slashing/tombstone.js';

const SECRET = 424_242n;
const TRAPDOOR = 313_131n;
const EPOCH = 100;

/** A connection that records what was sent, without a real transport. */
function recordingConnection(): {
  connection: IConnection;
  sent: Array<{ stream: number; payload: Uint8Array }>;
} {
  const sent: Array<{ stream: number; payload: Uint8Array }> = [];

  const connection = {
    peerDid: 'did:key:zRecorder',
    async send(stream: number, payload: Uint8Array) {
      sent.push({ stream, payload });
    },
    onFrame: () => () => undefined,
    close: async () => undefined,
  } as unknown as IConnection;

  return { connection, sent };
}

function share(index: number, seed: number): ObservedShare {
  const signal = createSignal(
    SECRET,
    {
      version: 1,
      streamId: 2,
      epoch: EPOCH,
      tier: 50,
      ciphertextHash: new Uint8Array(32).fill(seed),
      recipientId: 42n,
    },
    index,
  );

  return { ...signalToShare(signal), epoch: EPOCH };
}

function validator() {
  const keypair = generateKeypair();
  return { keypair, did: publicKeyToDidKey(keypair.publicKey) };
}

interface Harness {
  coordinator: SlashingCoordinator;
  revoked: bigint[];
  events: SlashingEvent[];
  sent: Array<{ stream: number; payload: Uint8Array }>;
}

function harness(options: { knowsTrapdoor?: boolean } = {}): Harness {
  const { connection, sent } = recordingConnection();
  const revoked: bigint[] = [];
  const events: SlashingEvent[] = [];
  const v = validator();

  const coordinator = new SlashingCoordinator({
    validator: () => v,
    connections: () => [connection],
    onRevoked: async (tombstone) => {
      revoked.push(tombstone.membershipCommitment);
    },
    resolveTrapdoor: options.knowsTrapdoor === false ? undefined : () => TRAPDOOR,
  });

  coordinator.onSlashing((event) => events.push(event));

  return { coordinator, revoked, events, sent };
}

test.describe('Slashing — Stream 0x06 share gossip', () => {
  test('honest shares produce no revocation', async () => {
    const h = harness();

    expect(await h.coordinator.handleShareFrame(encodeShare(share(0, 1)))).toBeUndefined();
    expect(await h.coordinator.handleShareFrame(encodeShare(share(1, 2)))).toBeUndefined();

    expect(h.revoked).toHaveLength(0);
    expect(h.coordinator.trackedNullifiers).toBe(2);
  });

  test('a reused index is detected and revoked', async () => {
    const h = harness();

    await h.coordinator.handleShareFrame(encodeShare(share(0, 1)));
    const evidence = await h.coordinator.handleShareFrame(encodeShare(share(0, 9)));

    expect(evidence).toBeDefined();
    expect(evidence!.identitySecret).toBe(SECRET);
    expect(h.revoked).toEqual([membershipCommitment(SECRET, TRAPDOOR)]);
  });

  test('detection gossips a tombstone on the priority stream', async () => {
    const h = harness();

    await h.coordinator.handleShareFrame(encodeShare(share(0, 1)));
    await h.coordinator.handleShareFrame(encodeShare(share(0, 9)));

    const tombstones = h.sent.filter(
      (f) => f.stream === StreamType.REVOCATION_GOSSIP,
    );

    // 0x03 preempts chat so a compromised identity cannot outrun its own
    // revocation (RFC 001 §6).
    expect(tombstones).toHaveLength(1);
    expect(h.events).toHaveLength(1);
    expect(h.events[0]!.local).toBe(true);
    expect(h.events[0]!.tombstone.reason).toBe(RevocationReason.SLASHED_DOUBLE_SHARE);
  });

  test('no tombstone is published when the trapdoor is unknown', async () => {
    const h = harness({ knowsTrapdoor: false });

    await h.coordinator.handleShareFrame(encodeShare(share(0, 1)));
    const evidence = await h.coordinator.handleShareFrame(encodeShare(share(0, 9)));

    // The secret was still recovered, but an accusation nobody could
    // verify is worse than none at all.
    expect(evidence).toBeDefined();
    expect(h.sent).toHaveLength(0);
    expect(h.revoked).toHaveLength(0);
  });

  test('malformed share frames are dropped, not fatal', async () => {
    const h = harness();

    expect(await h.coordinator.handleShareFrame(new Uint8Array(3))).toBeUndefined();
    expect(await h.coordinator.handleShareFrame(new Uint8Array(0))).toBeUndefined();
    expect(h.coordinator.trackedNullifiers).toBe(0);
  });

  test('broadcasting a share sends it on Stream 0x06', async () => {
    const h = harness();

    await h.coordinator.broadcastShare(share(0, 1));

    expect(h.sent).toHaveLength(1);
    expect(h.sent[0]!.stream).toBe(StreamType.RLN_SHARE_EXCHANGE);
  });

  test('pruning drops shares past the retention window', async () => {
    const h = harness();

    await h.coordinator.handleShareFrame(encodeShare(share(0, 1)));
    expect(h.coordinator.prune(EPOCH + 20)).toBe(1);
    expect(h.coordinator.trackedNullifiers).toBe(0);
  });
});

test.describe('Slashing — Stream 0x03 tombstone gossip', () => {
  /** A genuine tombstone authored by some other node. */
  function remoteTombstone() {
    const first = share(0, 1);
    const second = share(0, 9);

    return createSlashingTombstone([first, second], TRAPDOOR, validator());
  }

  test('a verified tombstone revokes its target', async () => {
    const h = harness();
    const tombstone = remoteTombstone();

    expect(await h.coordinator.handleTombstoneFrame(encodeTombstone(tombstone))).toBe(
      true,
    );
    expect(h.revoked).toEqual([tombstone.membershipCommitment]);
    expect(h.coordinator.isRevoked(tombstone.membershipCommitment)).toBe(true);
  });

  test('a tombstone with fabricated shares is refused', async () => {
    const h = harness();
    const tombstone = remoteTombstone();

    const forged = {
      ...tombstone,
      doubleSpendProof: {
        nullifier: tombstone.doubleSpendProof!.nullifier,
        shareOne: { x: 1n, y: 2n },
        shareTwo: { x: 3n, y: 4n },
      },
    };

    // Evidence beats authority — otherwise any peer could silence any
    // other by gossiping a signed lie.
    expect(await h.coordinator.handleTombstoneFrame(encodeTombstone(forged))).toBe(false);
    expect(h.revoked).toHaveLength(0);
  });

  test('a tampered tombstone is refused', async () => {
    const h = harness();
    const tombstone = remoteTombstone();

    const tampered = { ...tombstone, timestamp: tombstone.timestamp + 1 };

    expect(await h.coordinator.handleTombstoneFrame(encodeTombstone(tampered))).toBe(
      false,
    );
    expect(h.revoked).toHaveLength(0);
  });

  test('a repeated tombstone is applied only once', async () => {
    const h = harness();
    const frame = encodeTombstone(remoteTombstone());

    expect(await h.coordinator.handleTombstoneFrame(frame)).toBe(true);
    expect(await h.coordinator.handleTombstoneFrame(frame)).toBe(true);

    // Gossip floods duplicates; the revocation must be idempotent.
    expect(h.revoked).toHaveLength(1);
  });

  test('malformed tombstone frames are dropped', async () => {
    const h = harness();

    expect(await h.coordinator.handleTombstoneFrame(new Uint8Array(2))).toBe(false);
    expect(h.revoked).toHaveLength(0);
  });
});
