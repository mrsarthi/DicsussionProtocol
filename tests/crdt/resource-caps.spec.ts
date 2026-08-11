/**
 * Aggregate Resource Caps
 *
 * Individual frames were always bounded by the frame codec. These cover
 * the *aggregate* paths, where a peer stays within every per-frame limit
 * and still grows local state without end (backlog item 2, audit A-6).
 */

import { expect, test } from '@playwright/test';

import { DocumentManager } from '../../packages/core/src/crdt/document-manager.js';
import { BoundedMembershipTree } from '../../packages/core/src/crdt/membership-tree.js';
import { MembershipSyncEngine } from '../../packages/core/src/crdt/membership-sync.js';
import {
  encodeMemberListBody,
  MAX_MEMBERS_PER_FRAME,
} from '../../packages/core/src/crdt/sync-protocol.js';

test.describe('DocumentManager — document ceiling', () => {
  test('documents below the ceiling are created normally', () => {
    const manager = new DocumentManager();

    for (let i = 0; i < 50; i++) manager.ensureSyncDocument(`doc-${i}`);
    expect(manager.ensureSyncDocument('doc-0')).toBeDefined();
  });

  test('an unbounded stream of document ids is refused', () => {
    // `docId` arrives from the peer during sync. Each unique value used to
    // allocate an Automerge replica that was never released.
    const manager = new DocumentManager();

    expect(() => {
      for (let i = 0; i < 2_000; i++) manager.ensureSyncDocument(`flood-${i}`);
    }).toThrow(/document limit/i);
  });

  test('an existing document is still reachable once the cap is hit', () => {
    // The cap must not lock a peer out of documents it legitimately holds.
    const manager = new DocumentManager();
    manager.ensureSyncDocument('real');

    try {
      for (let i = 0; i < 2_000; i++) manager.ensureSyncDocument(`flood-${i}`);
    } catch {
      // expected
    }

    expect(manager.ensureSyncDocument('real')).toBeDefined();
  });
});

test.describe('MembershipSyncEngine — pending chunk ceiling', () => {
  const CHANNEL = 'general';

  function engine(): MembershipSyncEngine {
    const tree = new BoundedMembershipTree();
    return new MembershipSyncEngine(() => tree);
  }

  /** A non-final MEMBER_LIST chunk of distinct commitments. */
  function chunk(from: bigint, count: number): Uint8Array {
    const commitments = Array.from({ length: count }, (_, i) => from + BigInt(i));
    return encodeMemberListBody(commitments, false);
  }

  test('chunks below the ceiling accumulate normally', () => {
    const sync = engine();

    // Two legal chunks, neither final — the engine holds them and asks
    // for more rather than merging early.
    expect(sync.handleMemberList('peer', CHANNEL, chunk(1n, 10))).toEqual([]);
    expect(sync.handleMemberList('peer', CHANNEL, chunk(100n, 10))).toEqual([]);
  });

  test('a peer that never sends is_final is cut off', () => {
    // Every frame here is individually legal. The abuse is only visible
    // in aggregate: without a cap the accumulator grows until memory runs
    // out, and nothing in a log explains why.
    const sync = engine();
    let base = 1n;

    for (let i = 0; i < 40; i++) {
      sync.handleMemberList('peer', CHANNEL, chunk(base, MAX_MEMBERS_PER_FRAME));
      base += BigInt(MAX_MEMBERS_PER_FRAME);
    }

    // Discarded rather than trimmed: a truncated member list would merge
    // as though the peer had genuinely departed everyone past the cut.
    const afterReset = sync.handleMemberList('peer', CHANNEL, chunk(base, 5));
    expect(afterReset).toEqual([]);
  });
});
