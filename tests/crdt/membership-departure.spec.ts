/**
 * Signed membership departures — the remove half of the two-phase set.
 *
 * The property under test is that leaving *sticks*: a peer that has not
 * yet seen a departure will keep offering the commitment back during
 * reconciliation, and re-admitting it would silently undo the leave.
 * The second property is that only you can announce your own departure.
 */

import { expect, test } from '@playwright/test';

import { BoundedMembershipTree } from '../../packages/core/src/crdt/membership-tree.js';
import { MembershipSyncEngine } from '../../packages/core/src/crdt/membership-sync.js';
import {
  createDeparture,
  DepartureSet,
  verifyDeparture,
} from '../../packages/core/src/crdt/membership-departure.js';
import {
  decodeSyncFrame,
  SyncMessageType,
} from '../../packages/core/src/crdt/sync-protocol.js';
import { membershipCommitment } from '../../packages/core/src/crypto/poseidon.js';
import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';

const CHANNEL = 'general';

const cm = (i: number): bigint => membershipCommitment(BigInt(i), BigInt(i * 7));

/** A member with a signing identity and a commitment. */
function member(index: number) {
  const keypair = generateKeypair();
  return {
    keypair,
    did: publicKeyToDidKey(keypair.publicKey),
    commitment: cm(index),
  };
}

interface Node {
  tree: BoundedMembershipTree;
  engine: MembershipSyncEngine;
}

function node(commitments: readonly bigint[]): Node {
  const tree = new BoundedMembershipTree();
  commitments.forEach((c, i) => tree.insert(c, 1_000 + i));

  return {
    tree,
    engine: new MembershipSyncEngine((c) => (c === CHANNEL ? tree : undefined)),
  };
}

/** Feed frames into a node, returning replies. */
function deliver(target: Node, from: string, frames: readonly Uint8Array[]): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (const frame of frames) {
    const decoded = decodeSyncFrame(frame);

    if (decoded.type === SyncMessageType.MEMBER_ROOT) {
      out.push(...target.engine.handleMemberRoot(from, decoded.docId, decoded.body));
    } else if (decoded.type === SyncMessageType.MEMBER_LIST) {
      out.push(...target.engine.handleMemberList(from, decoded.docId, decoded.body));
    } else if (decoded.type === SyncMessageType.MEMBER_DEPARTURE) {
      out.push(...target.engine.handleDeparture(from, decoded.docId, decoded.body));
    }
  }

  return out;
}

/** Drive an exchange to a fixed point. */
function reconcile(a: Node, b: Node, maxRounds = 20): void {
  let inflight: Array<{ to: 'A' | 'B'; frames: Uint8Array[] }> = [
    { to: 'B', frames: [a.engine.advertise(CHANNEL)!] },
  ];
  let rounds = 0;

  while (inflight.length > 0 && rounds < maxRounds) {
    rounds++;
    const next: Array<{ to: 'A' | 'B'; frames: Uint8Array[] }> = [];

    for (const { to, frames } of inflight) {
      const target = to === 'A' ? a : b;
      const sender = to === 'A' ? 'B' : 'A';
      const replies = deliver(target, sender, frames);
      if (replies.length > 0) next.push({ to: sender as 'A' | 'B', frames: replies });
    }

    inflight = next;
  }

  expect(inflight).toHaveLength(0);
}

test.describe('CRDT — Departure Records', () => {
  test('a departure verifies against the did that signed it', () => {
    const alice = member(1);
    const departure = createDeparture(
      CHANNEL,
      alice.did,
      alice.commitment,
      alice.keypair,
    );

    expect(verifyDeparture(departure)).toBe(true);
    expect(verifyDeparture(departure, CHANNEL)).toBe(true);
  });

  test('a departure for one channel cannot evict from another', () => {
    const alice = member(1);
    const departure = createDeparture(
      'other-channel',
      alice.did,
      alice.commitment,
      alice.keypair,
    );

    // Validly signed, wrong channel — must not apply here.
    expect(verifyDeparture(departure)).toBe(true);
    expect(verifyDeparture(departure, CHANNEL)).toBe(false);
  });

  test('you cannot sign a departure on someone else behalf', () => {
    const alice = member(1);
    const mallory = member(2);

    // Mallory signs, but claims to be Alice.
    const forged = createDeparture(
      CHANNEL,
      alice.did,
      alice.commitment,
      mallory.keypair,
    );

    expect(verifyDeparture(forged, CHANNEL)).toBe(false);
  });

  test('any tampering breaks the signature', () => {
    const alice = member(1);
    const departure = createDeparture(
      CHANNEL,
      alice.did,
      alice.commitment,
      alice.keypair,
    );

    expect(
      verifyDeparture({ ...departure, commitment: alice.commitment + 1n }, CHANNEL),
    ).toBe(false);
    expect(
      verifyDeparture({ ...departure, departedAt: departure.departedAt + 1 }, CHANNEL),
    ).toBe(false);
  });

  test('the departure set is idempotent and rejects invalid records', () => {
    const alice = member(1);
    const set = new DepartureSet(CHANNEL);
    const departure = createDeparture(
      CHANNEL,
      alice.did,
      alice.commitment,
      alice.keypair,
    );

    expect(set.add(departure)).toBe(true);
    // Gossip floods duplicates; adding twice must not double-count.
    expect(set.add(departure)).toBe(false);
    expect(set.size).toBe(1);
    expect(set.has(alice.commitment)).toBe(true);

    const forged = createDeparture(CHANNEL, alice.did, cm(9), member(3).keypair);
    expect(set.add(forged)).toBe(false);
  });
});

test.describe('CRDT — Departures Survive Reconciliation', () => {
  test('a departed member is not re-added by a peer that still holds them', () => {
    const alice = member(1);

    // Both peers know Alice plus one other member.
    const departing = node([alice.commitment, cm(2)]);
    const other = node([alice.commitment, cm(2)]);

    expect(departing.tree.has(alice.commitment)).toBe(true);

    // Alice leaves; the tombstone is announced.
    const departure = createDeparture(
      CHANNEL,
      alice.did,
      alice.commitment,
      alice.keypair,
    );
    const frames = departing.engine.announceDeparture(departure);

    expect(departing.tree.has(alice.commitment)).toBe(false);
    expect(frames).toHaveLength(1);

    // The peer applies it.
    deliver(other, 'A', frames);
    expect(other.tree.has(alice.commitment)).toBe(false);

    // Now reconcile: neither side may resurrect the commitment.
    reconcile(departing, other);
    expect(departing.tree.has(alice.commitment)).toBe(false);
    expect(other.tree.has(alice.commitment)).toBe(false);
    expect(departing.tree.root()).toBe(other.tree.root());
  });

  test('the remove half wins over a peer that never saw the departure', () => {
    const alice = member(1);

    const departing = node([alice.commitment, cm(2)]);
    const unaware = node([alice.commitment, cm(2)]);

    departing.engine.announceDeparture(
      createDeparture(CHANNEL, alice.did, alice.commitment, alice.keypair),
    );

    // `unaware` still holds Alice and will offer her back during sync.
    expect(unaware.tree.has(alice.commitment)).toBe(true);
    reconcile(departing, unaware);

    // The tombstone must beat the stale join.
    expect(departing.tree.has(alice.commitment)).toBe(false);
  });

  test('a rejoin with a fresh commitment is not blocked by the old tombstone', () => {
    const alice = member(1);
    const local = node([alice.commitment]);

    local.engine.announceDeparture(
      createDeparture(CHANNEL, alice.did, alice.commitment, alice.keypair),
    );
    expect(local.tree.has(alice.commitment)).toBe(false);

    // Rejoining means a new trapdoor, hence a different commitment.
    const rejoined = membershipCommitment(1n, 999n);
    local.tree.insert(rejoined);

    expect(local.tree.has(rejoined)).toBe(true);
    expect(local.engine.hasDeparted(CHANNEL, rejoined)).toBe(false);
  });

  test('a forged departure gossiped by a peer is ignored', () => {
    const alice = member(1);
    const mallory = member(2);

    const target = node([alice.commitment, mallory.commitment]);

    // Mallory tries to evict Alice by signing a departure for her.
    const forged = createDeparture(
      CHANNEL,
      alice.did,
      alice.commitment,
      mallory.keypair,
    );

    const attacker = node([alice.commitment]);
    // `announceDeparture` refuses to even publish it.
    expect(attacker.engine.announceDeparture(forged)).toHaveLength(0);

    // And a hand-built frame is rejected on receipt.
    target.engine.handleDeparture(
      'mallory',
      CHANNEL,
      Buffer.from(
        JSON.stringify({
          isFinal: true,
          departures: [
            {
              channelId: CHANNEL,
              did: alice.did,
              commitment: alice.commitment.toString(),
              departedAt: 1,
              signature: Buffer.from(forged.signature).toString('base64'),
            },
          ],
        }),
      ),
    );

    expect(target.tree.has(alice.commitment)).toBe(true);
  });

  test('departure frames can be replayed to a peer joining later', () => {
    const alice = member(1);
    const origin = node([alice.commitment, cm(2)]);

    origin.engine.announceDeparture(
      createDeparture(CHANNEL, alice.did, alice.commitment, alice.keypair),
    );

    // A peer that was offline gets the backlog.
    const latecomer = node([alice.commitment, cm(2)]);
    deliver(latecomer, 'origin', origin.engine.departureFrames(CHANNEL));

    expect(latecomer.tree.has(alice.commitment)).toBe(false);
    expect(latecomer.engine.hasDeparted(CHANNEL, alice.commitment)).toBe(true);
  });

  test('malformed departure bodies are dropped, not fatal', () => {
    const target = node([cm(1)]);

    expect(() =>
      target.engine.handleDeparture('peer', CHANNEL, new Uint8Array([1, 2, 3])),
    ).not.toThrow();
    expect(target.tree.has(cm(1))).toBe(true);
  });
});
