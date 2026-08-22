/**
 * Independently created replicas must merge without losing messages.
 *
 * Automerge merges histories, and two replicas that each *created* a
 * document share none: each independently assigned the `messages` map,
 * and merging those concurrent assignments keeps one map and discards
 * the other — deleting every message written into the loser.
 *
 * It is a quiet failure. The winner is deterministic, so all replicas
 * converge on the same truncated document, their state roots then match,
 * and sync reports success forever after. Shared genesis is what stops
 * it, and this is what would have caught it.
 */

import { expect, test } from '@playwright/test';
import * as Automerge from '@automerge/automerge';

import { DocumentManager } from '../../packages/core/src/crdt/document-manager.js';
import type { DocumentSchema } from '../../packages/core/src/crdt/types.js';

/** A manager that created the channel and wrote one message. */
function writer(docId: string, tag: string, index: number): DocumentManager {
  const manager = new DocumentManager();
  manager.createDocument('General', docId);
  manager.addMessage(docId, {
    id: `m-${tag}`,
    authorDid: `did:key:z6Mk${tag}`,
    content: `MSG-${tag}`,
    timestamp: 1000 + index,
    messageIndex: index,
  } as never);
  return manager;
}

function mergeAll(docs: Automerge.Doc<DocumentSchema>[]): Automerge.Doc<DocumentSchema> {
  return docs.reduce((acc, next) => Automerge.merge(acc, next));
}

const contents = (doc: Automerge.Doc<DocumentSchema>): string[] =>
  Object.values(doc.messages)
    .map((m) => (m as { content: string }).content)
    .sort();

test.describe('CRDT — genesis convergence', () => {
  test('three independently created replicas keep every message', () => {
    const docs = ['a', 'b', 'c'].map((tag, i) =>
      writer('g', tag, i).getDocument('g')!,
    );

    const merged = mergeAll(docs);

    expect(contents(merged)).toEqual(['MSG-a', 'MSG-b', 'MSG-c']);
    // The container itself must not be contested — a conflict here means
    // one replica's whole map is being discarded.
    expect(Object.keys(Automerge.getConflicts(merged, 'messages') ?? {})).toHaveLength(0);
  });

  test('merge order does not change the result', () => {
    const [a, b, c] = ['a', 'b', 'c'].map((tag, i) =>
      writer('g', tag, i).getDocument('g')!,
    );

    expect(contents(mergeAll([a!, b!, c!]))).toEqual(contents(mergeAll([c!, a!, b!])));
  });

  test('a replica that only ever receives shares the same root', () => {
    // `ensureSyncDocument` is the path taken by a node that never wrote
    // to the channel. An empty init() here would be a different root,
    // and the first merge would contest the container.
    const receiver = new DocumentManager();
    const blank = receiver.ensureSyncDocument('g');

    const merged = Automerge.merge(blank, writer('g', 'a', 0).getDocument('g')!);

    expect(contents(merged)).toEqual(['MSG-a']);
    expect(Object.keys(Automerge.getConflicts(merged, 'messages') ?? {})).toHaveLength(0);
  });

  test('local details still differ per node without forking the root', () => {
    // Genesis must be byte-identical, so anything per-node — a title, a
    // creation time — has to arrive as a later change.
    const one = new DocumentManager();
    const two = new DocumentManager();
    one.createDocument('Alice and Bob', 'g');
    two.createDocument('Different Title', 'g');

    const merged = Automerge.merge(one.getDocument('g')!, two.getDocument('g')!);

    // One title wins as an ordinary scalar; neither replica is discarded.
    expect(['Alice and Bob', 'Different Title']).toContain(merged.meta.title);
    expect(Object.keys(Automerge.getConflicts(merged, 'messages') ?? {})).toHaveLength(0);
  });
});
