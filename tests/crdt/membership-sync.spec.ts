/**
 * Phase 3A — Channel membership reconciliation over Stream 0x01.
 *
 * The RLN circuit proves "my commitment is in this tree" against a root
 * the verifier computed independently. If peers disagreed on membership
 * they would compute different roots and honest proofs would fail, so
 * convergence here is a correctness prerequisite for proving.
 */

import { expect, test } from '@playwright/test';

import { BoundedMembershipTree } from '../../packages/core/src/crdt/membership-tree.js';
import { MembershipSyncEngine } from '../../packages/core/src/crdt/membership-sync.js';
import {
  decodeMemberListBody,
  decodeMemberRootBody,
  decodeSyncFrame,
  encodeMemberListBody,
  encodeMemberRootBody,
  MAX_MEMBERS_PER_FRAME,
  SyncMessageType,
} from '../../packages/core/src/crdt/sync-protocol.js';
import { membershipCommitment } from '../../packages/core/src/crypto/poseidon.js';

const CHANNEL = 'general';

/** Deterministic mock commitment. */
const cm = (i: number): bigint => membershipCommitment(BigInt(i), BigInt(i * 7));

interface Node {
  tree: BoundedMembershipTree;
  engine: MembershipSyncEngine;
}

function node(members: readonly bigint[], capacity?: number): Node {
  const tree = new BoundedMembershipTree(capacity);
  members.forEach((m, i) => tree.insert(m, 1_000 + i));

  return {
    tree,
    engine: new MembershipSyncEngine((c) => (c === CHANNEL ? tree : undefined)),
  };
}

/** Feed frames into a node, returning its replies. */
function deliver(target: Node, from: string, frames: readonly Uint8Array[]): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (const frame of frames) {
    const decoded = decodeSyncFrame(frame);

    if (decoded.type === SyncMessageType.MEMBER_ROOT) {
      out.push(...target.engine.handleMemberRoot(from, decoded.docId, decoded.body));
    } else if (decoded.type === SyncMessageType.MEMBER_LIST) {
      out.push(...target.engine.handleMemberList(from, decoded.docId, decoded.body));
    }
  }

  return out;
}

/** Run an exchange to a fixed point, returning the round count. */
function reconcile(a: Node, b: Node, maxRounds = 20): number {
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

      if (replies.length > 0) {
        next.push({ to: sender as 'A' | 'B', frames: replies });
      }
    }

    inflight = next;
  }

  expect(inflight).toHaveLength(0);
  return rounds;
}

test.describe('CRDT — Membership Sync Protocol Codec', () => {
  test('MEMBER_ROOT body round-trips', () => {
    const body = encodeMemberRootBody(12_345n, 42);

    expect(body).toHaveLength(36);
    expect(decodeMemberRootBody(body)).toEqual({ root: 12_345n, memberCount: 42 });
  });

  test('MEMBER_ROOT rejects a wrong-sized body', () => {
    expect(() => decodeMemberRootBody(new Uint8Array(35))).toThrow(/36 bytes/);
  });

  test('MEMBER_LIST round-trips with the final flag', () => {
    const commitments = [cm(1), cm(2), cm(3)];

    expect(decodeMemberListBody(encodeMemberListBody(commitments, true))).toEqual({
      commitments,
      isFinal: true,
    });
    expect(decodeMemberListBody(encodeMemberListBody([], false))).toEqual({
      commitments: [],
      isFinal: false,
    });
  });

  test('MEMBER_LIST refuses oversized and truncated bodies', () => {
    const tooMany = Array.from({ length: MAX_MEMBERS_PER_FRAME + 1 }, (_, i) => cm(i + 1));
    expect(() => encodeMemberListBody(tooMany, true)).toThrow(/at most/);

    const valid = encodeMemberListBody([cm(1), cm(2)], true);
    expect(() => decodeMemberListBody(valid.subarray(0, 2))).toThrow(/truncated/);
    expect(() => decodeMemberListBody(valid.subarray(0, valid.length - 8))).toThrow(
      /truncated/,
    );
  });

  test('membership frames carry the channel id through Stream 0x01', () => {
    const { engine } = node([cm(1)]);
    const decoded = decodeSyncFrame(engine.advertise(CHANNEL)!);

    expect(decoded.type).toBe(SyncMessageType.MEMBER_ROOT);
    expect(decoded.docId).toBe(CHANNEL);
  });
});

test.describe('CRDT — Membership Convergence', () => {
  test('disjoint member sets converge to the union', () => {
    const a = node([cm(1), cm(2), cm(3)]);
    const b = node([cm(4), cm(5)]);

    expect(a.tree.root()).not.toBe(b.tree.root());
    reconcile(a, b);

    expect(a.tree.size).toBe(5);
    expect(b.tree.size).toBe(5);
    expect(a.tree.root()).toBe(b.tree.root());
  });

  test('overlapping sets converge without duplicating members', () => {
    const a = node([cm(1), cm(2), cm(3)]);
    const b = node([cm(3), cm(4), cm(5)]);

    reconcile(a, b);

    expect(a.tree.size).toBe(5);
    expect(b.tree.size).toBe(5);
    expect(a.tree.root()).toBe(b.tree.root());
  });

  test('a peer joining an established channel receives every member', () => {
    const established = node([cm(1), cm(2), cm(3), cm(4)]);
    const joiner = node([cm(99)]);

    reconcile(joiner, established);

    expect(joiner.tree.size).toBe(5);
    expect(established.tree.has(cm(99))).toBe(true);
    expect(joiner.tree.root()).toBe(established.tree.root());
  });

  test('already-converged peers exchange nothing', () => {
    const a = node([cm(1), cm(2)]);
    const b = node([cm(1), cm(2)]);

    expect(a.tree.root()).toBe(b.tree.root());

    // Equal roots short-circuit: the whole point of deterministic
    // lexicographic indexing.
    const replies = deliver(b, 'A', [a.engine.advertise(CHANNEL)!]);
    expect(replies).toHaveLength(0);
  });

  test('reconciliation terminates rather than trading lists forever', () => {
    const a = node([cm(1), cm(2), cm(3)]);
    const b = node([cm(4), cm(5), cm(6)]);

    // reconcile() asserts the exchange drained; a ping-pong loop would
    // exhaust maxRounds and fail here.
    expect(reconcile(a, b)).toBeLessThanOrEqual(6);
  });

  test('convergence is order independent', () => {
    const forward = { a: node([cm(1), cm(2)]), b: node([cm(3), cm(4)]) };
    const reverse = { a: node([cm(3), cm(4)]), b: node([cm(1), cm(2)]) };

    reconcile(forward.a, forward.b);
    reconcile(reverse.a, reverse.b);

    expect(forward.a.tree.root()).toBe(reverse.a.tree.root());
  });

  test('three peers converge pairwise to one root', () => {
    const a = node([cm(1)]);
    const b = node([cm(2)]);
    const c = node([cm(3)]);

    reconcile(a, b);
    reconcile(b, c);
    reconcile(a, c);

    expect(a.tree.size).toBe(3);
    expect(a.tree.root()).toBe(b.tree.root());
    expect(b.tree.root()).toBe(c.tree.root());
  });

  test('re-running a completed exchange changes nothing', () => {
    const a = node([cm(1), cm(2)]);
    const b = node([cm(3)]);

    reconcile(a, b);
    const settled = a.tree.root();

    // Union is idempotent, so replayed frames are harmless.
    reconcile(a, b);
    expect(a.tree.root()).toBe(settled);
    expect(a.tree.size).toBe(3);
  });

  test('updates are emitted with the commitments actually admitted', () => {
    const a = node([cm(1), cm(2)]);
    const b = node([cm(3)]);

    const updates: Array<{ admitted: readonly bigint[]; root: bigint }> = [];
    b.engine.onUpdate((u) => updates.push({ admitted: u.admitted, root: u.root }));

    reconcile(a, b);

    expect(updates).toHaveLength(1);
    expect(updates[0]!.admitted).toEqual([cm(1), cm(2)].sort((x, y) => (x < y ? -1 : 1)));
    expect(updates[0]!.root).toBe(b.tree.root());
  });

  test('isConverged reflects the last advertised root', () => {
    const a = node([cm(1)]);
    const b = node([cm(2)]);

    expect(b.engine.isConverged('A', CHANNEL)).toBe(false);
    reconcile(a, b);

    // Re-advertise now that both sides hold the union.
    deliver(b, 'A', [a.engine.advertise(CHANNEL)!]);
    expect(b.engine.isConverged('A', CHANNEL)).toBe(true);
  });
});

test.describe('CRDT — Membership Sync Robustness', () => {
  test('an unknown channel is ignored rather than throwing', () => {
    const { engine } = node([cm(1)]);

    expect(engine.advertise('no-such-channel')).toBeUndefined();
    expect(
      engine.handleMemberRoot('peer', 'no-such-channel', encodeMemberRootBody(1n, 1)),
    ).toEqual([]);
  });

  test('the empty-leaf tombstone is never admitted as a member', () => {
    const target = node([cm(1)]);

    deliver(target, 'hostile', [
      // Hand-built frame carrying commitment 0.
      (() => {
        const body = encodeMemberListBody([], true);
        const withZero = new Uint8Array(3 + 32);
        withZero.set(body.subarray(0, 1), 0);
        new DataView(withZero.buffer).setUint16(1, 1, false);
        return encodeFrame(withZero);
      })(),
    ]);

    expect(target.tree.size).toBe(1);
    expect(target.tree.has(0n)).toBe(false);
  });

  test('a set larger than one frame is split into chunks', () => {
    // Root computation is O(N) Poseidon hashes (see PROGRESS.md), so this
    // asserts the framing directly rather than driving a full exchange
    // over a thousand members — convergence is covered above.
    const commitments = Array.from(
      { length: MAX_MEMBERS_PER_FRAME + 50 },
      (_, i) => BigInt(i + 1),
    );

    const chunks: Array<{ count: number; isFinal: boolean }> = [];

    for (let i = 0; i < commitments.length; i += MAX_MEMBERS_PER_FRAME) {
      const slice = commitments.slice(i, i + MAX_MEMBERS_PER_FRAME);
      const isFinal = i + MAX_MEMBERS_PER_FRAME >= commitments.length;
      const decoded = decodeMemberListBody(encodeMemberListBody(slice, isFinal));

      chunks.push({ count: decoded.commitments.length, isFinal: decoded.isFinal });
    }

    expect(chunks).toEqual([
      { count: MAX_MEMBERS_PER_FRAME, isFinal: false },
      { count: 50, isFinal: true },
    ]);
  });

  test('removing a peer clears its reconciliation state', () => {
    const a = node([cm(1)]);
    const b = node([cm(2)]);

    reconcile(a, b);
    b.engine.removePeer('A');

    expect(b.engine.isConverged('A', CHANNEL)).toBe(false);
  });
});

/** Wrap a MEMBER_LIST body in a Stream 0x01 frame for the hostile-input test. */
function encodeFrame(body: Uint8Array): Uint8Array {
  const channelBytes = new TextEncoder().encode(CHANNEL);
  const out = new Uint8Array(1 + 1 + channelBytes.length + 4 + body.length);
  const view = new DataView(out.buffer);

  view.setUint8(0, SyncMessageType.MEMBER_LIST);
  view.setUint8(1, channelBytes.length);
  out.set(channelBytes, 2);
  view.setUint32(2 + channelBytes.length, body.length, false);
  out.set(body, 2 + channelBytes.length + 4);

  return out;
}
