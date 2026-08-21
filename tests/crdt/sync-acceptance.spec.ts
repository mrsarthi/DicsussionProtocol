/**
 * RFC 002 §7 acceptance criteria that had no test.
 *
 * Both were listed in the spec and implemented in behaviour, but nothing
 * asserted them — so a regression in either would have gone unnoticed:
 *
 *   - "zero bytes transferred (beyond the 32-byte root hash) when two
 *     nodes are already in sync"
 *   - "Merkle root computation for 50 documents completes in < 2ms"
 */

import { expect, test } from '@playwright/test';

import { DocumentManager } from '../../packages/core/src/crdt/document-manager.js';
import { CrdtSyncEngine } from '../../packages/core/src/crdt/sync-engine.js';
import {
  computeManagerStateRoot,
  rootsEqual,
} from '../../packages/core/src/crdt/state-root.js';
import {
  decodeBoolBody,
  decodeSyncFrame,
  SyncMessageType,
} from '../../packages/core/src/crdt/sync-protocol.js';

/** A manager holding `count` documents, each with one message. */
function populated(count: number, seed = 0): DocumentManager {
  const documents = new DocumentManager();

  for (let i = 0; i < count; i++) {
    const docId = `doc-${i}`;
    documents.createDocument(`Channel ${i}`, docId);
    documents.addMessage(docId, {
      id: `m-${seed}-${i}`,
      authorDid: 'did:key:z6MkTestAuthor',
      content: `message ${i}`,
      timestamp: 1_700_000_000 + i,
      messageIndex: 0,
    });
  }

  return documents;
}

/**
 * Drive two engines until neither has anything left to say.
 *
 * @returns Total frames exchanged.
 */
function reconcile(
  a: CrdtSyncEngine,
  b: CrdtSyncEngine,
  maxRounds = 30,
): number {
  let inflight: Array<{ to: 'a' | 'b'; frames: Uint8Array[] }> = [
    { to: 'b', frames: [a.beginSync('b')] },
  ];
  let exchanged = 1;

  for (let round = 0; round < maxRounds && inflight.length > 0; round++) {
    const next: Array<{ to: 'a' | 'b'; frames: Uint8Array[] }> = [];

    for (const { to, frames } of inflight) {
      const target = to === 'a' ? a : b;
      const sender = to === 'a' ? 'b' : 'a';

      const replies: Uint8Array[] = [];
      for (const frame of frames) {
        replies.push(...target.handleMessage(sender, frame));
      }

      exchanged += replies.length;
      if (replies.length > 0) next.push({ to: sender, frames: replies });
    }

    inflight = next;
  }

  expect(inflight).toHaveLength(0);
  return exchanged;
}

test.describe('CRDT — RFC 002 §7 Acceptance Criteria', () => {
  test('nodes that have converged transfer nothing on a re-sync', () => {
    // NOTE: "in sync" means *converged*, not merely holding equivalent
    // content. The state root incorporates Automerge head hashes, which
    // are history-dependent — two nodes that independently created the
    // same documents have different histories and will still exchange
    // deltas. Only a real sync makes their histories match.
    const alice = new CrdtSyncEngine(populated(5));
    const bob = new CrdtSyncEngine(new DocumentManager());

    alice.registerPeer('b');
    bob.registerPeer('a');

    // First sync: Bob is empty, so data must flow.
    expect(reconcile(alice, bob)).toBeGreaterThan(1);

    // Second sync: the roots now match, so Bob answers ROOT_MATCH(true)
    // and nothing else — the short circuit the spec asks for.
    const replies = bob.handleMessage('a', alice.beginSync('b'));
    expect(replies).toHaveLength(1);

    const reply = decodeSyncFrame(replies[0]!);
    expect(reply.type).toBe(SyncMessageType.ROOT_MATCH);
    expect(decodeBoolBody(reply.body)).toBe(true);

    // And Alice sends nothing further on hearing it.
    expect(alice.handleMessage('b', replies[0]!)).toHaveLength(0);
  });

  test('divergent nodes do exchange data, so the check is meaningful', () => {
    // Guards against the previous test passing because sync is broken.
    const alice = new CrdtSyncEngine(populated(5, 1));
    const bob = new CrdtSyncEngine(new DocumentManager());

    alice.registerPeer('b');
    bob.registerPeer('a');

    const replies = bob.handleMessage('a', alice.beginSync('b'));
    expect(decodeBoolBody(decodeSyncFrame(replies[0]!).body)).toBe(false);
  });

  test('converged nodes agree on the state root', () => {
    const aliceDocs = populated(5);
    const bobDocs = new DocumentManager();

    const alice = new CrdtSyncEngine(aliceDocs);
    const bob = new CrdtSyncEngine(bobDocs);
    alice.registerPeer('b');
    bob.registerPeer('a');

    reconcile(alice, bob);

    const rootA = computeManagerStateRoot(aliceDocs);
    expect(rootsEqual(rootA, computeManagerStateRoot(bobDocs))).toBe(true);
    // 32 bytes — the only thing on the wire once converged.
    expect(rootA).toHaveLength(32);
  });

  test('the root is stable for unchanged state', () => {
    const documents = populated(10);

    expect(
      rootsEqual(
        computeManagerStateRoot(documents),
        computeManagerStateRoot(documents),
      ),
    ).toBe(true);
  });

  test('a single changed message changes the root', () => {
    const documents = populated(10);
    const before = computeManagerStateRoot(documents);

    documents.addMessage('doc-3', {
      id: 'extra',
      authorDid: 'did:key:z6MkTestAuthor',
      content: 'one more',
      timestamp: 1_700_000_999,
      messageIndex: 1,
    });

    expect(rootsEqual(before, computeManagerStateRoot(documents))).toBe(false);
  });

  test('state root for 50 documents completes within budget', () => {
    const documents = populated(50);

    // Warm up, so the measurement is not dominated by first-call JIT.
    computeManagerStateRoot(documents);

    // Best of several batches, not the mean of one.
    //
    // This runs alongside 500-odd other tests across parallel workers, so
    // any single batch can be preempted by the scheduler — and a mean is
    // dominated by that pause rather than by the work. The fastest batch
    // is the least-contended observation, which is the one that actually
    // says something about the algorithm. Averaging instead made this the
    // only test in the suite that failed under load and passed alone.
    const iterations = 20;
    const batches = 5;
    let perCall = Infinity;

    for (let batch = 0; batch < batches; batch++) {
      const started = performance.now();
      for (let i = 0; i < iterations; i++) {
        computeManagerStateRoot(documents);
      }
      perCall = Math.min(perCall, (performance.now() - started) / iterations);
    }

    // RFC 002 §7 specifies < 2 ms on mobile hardware. This is a desktop,
    // so the bar is set generously — the point is to catch an algorithmic
    // regression, not to certify mobile performance.
    expect(perCall).toBeLessThan(2);
  });
});
