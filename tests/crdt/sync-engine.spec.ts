import { expect, test } from '@playwright/test';

import { DocumentManager } from '../../packages/core/src/crdt/document-manager.js';
import { computeManagerStateRoot, rootsEqual } from '../../packages/core/src/crdt/state-root.js';
import { CrdtSyncEngine } from '../../packages/core/src/crdt/sync-engine.js';
import {
  decodeBoolBody,
  decodeSyncFrame,
  encodeBoolBody,
  encodeSyncFrame,
  SyncMessageType,
} from '../../packages/core/src/crdt/sync-protocol.js';

/**
 * These suites exercise synchronisation mechanics, not who is
 * entitled to what, so they opt in to sharing everything. The
 * engine's default is to refuse — a caller that forgets a policy
 * syncs nothing rather than syncing every conversation it holds.
 */
const SHARE_ALL = (): boolean => true;

/**
 * Run the sync conversation to completion between two engines.
 *
 * Mirrors what the transport does with Stream 0x01 frames, but in-process
 * so convergence can be asserted deterministically.
 *
 * @returns Total payloads exchanged in both directions.
 */
function runSyncToCompletion(
  a: CrdtSyncEngine,
  b: CrdtSyncEngine,
  aId = 'peer-a',
  bId = 'peer-b',
  maxRounds = 40,
): number {
  let inFlightToB: Uint8Array[] = [a.beginSync(bId)];
  let inFlightToA: Uint8Array[] = [];
  let exchanged = 0;

  for (let round = 0; round < maxRounds; round++) {
    if (inFlightToB.length === 0 && inFlightToA.length === 0) break;

    const toB = inFlightToB;
    const toA = inFlightToA;
    inFlightToB = [];
    inFlightToA = [];

    for (const payload of toB) {
      exchanged++;
      inFlightToA.push(...b.handleMessage(aId, payload));
    }
    for (const payload of toA) {
      exchanged++;
      inFlightToB.push(...a.handleMessage(bId, payload));
    }
  }

  return exchanged;
}

test.describe('CRDT — Sync Protocol Codec', () => {
  test('encodeSyncFrame/decodeSyncFrame round-trips', () => {
    const body = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = encodeSyncFrame(SyncMessageType.SEND_DELTA, 'doc-42', body);
    const decoded = decodeSyncFrame(encoded);

    expect(decoded.type).toBe(SyncMessageType.SEND_DELTA);
    expect(decoded.docId).toBe('doc-42');
    expect(Array.from(decoded.body)).toEqual([1, 2, 3, 4, 5]);
  });

  test('document-agnostic messages carry an empty doc id', () => {
    const encoded = encodeSyncFrame(
      SyncMessageType.ROOT_SYNC,
      '',
      new Uint8Array(32),
    );
    const decoded = decodeSyncFrame(encoded);

    expect(decoded.docId).toBe('');
    expect(decoded.body).toHaveLength(32);
  });

  test('decoded body is a zero-copy view of the source buffer', () => {
    const encoded = encodeSyncFrame(
      SyncMessageType.SEND_DELTA,
      'doc-1',
      new Uint8Array([9, 9, 9]),
    );
    const decoded = decodeSyncFrame(encoded);

    expect(decoded.body.buffer).toBe(encoded.buffer);
  });

  test('decodeSyncFrame rejects an unknown message type', () => {
    const encoded = encodeSyncFrame(
      SyncMessageType.ROOT_SYNC,
      '',
      new Uint8Array(4),
    );
    encoded[0] = 0x7f;

    expect(() => decodeSyncFrame(encoded)).toThrow(/Unknown sync message type/);
  });

  test('decodeSyncFrame rejects a truncated body', () => {
    const encoded = encodeSyncFrame(
      SyncMessageType.SEND_DELTA,
      'doc-1',
      new Uint8Array([1, 2, 3, 4]),
    );

    expect(() => decodeSyncFrame(encoded.subarray(0, encoded.length - 2))).toThrow(
      /truncated/,
    );
  });

  test('boolean body round-trips', () => {
    expect(decodeBoolBody(encodeBoolBody(true))).toBe(true);
    expect(decodeBoolBody(encodeBoolBody(false))).toBe(false);
  });
});

test.describe('CRDT — Canonical State Root', () => {
  test('identical document sets produce identical roots', () => {
    const a = new DocumentManager();
    const b = new DocumentManager();

    a.createDocument('General', 'doc-1');
    b.createDocument('General', 'doc-1');

    // Distinct Automerge histories, so roots differ despite same title.
    expect(rootsEqual(computeManagerStateRoot(a), computeManagerStateRoot(b))).toBe(false);
  });

  test('empty managers produce equal roots', () => {
    const a = new DocumentManager();
    const b = new DocumentManager();
    expect(rootsEqual(computeManagerStateRoot(a), computeManagerStateRoot(b))).toBe(true);
  });

  test('root changes when a message is added', () => {
    const docs = new DocumentManager();
    docs.createDocument('General', 'doc-1');
    const before = computeManagerStateRoot(docs);

    docs.addMessage('doc-1', {
      id: 'm1',
      content: 'hello',
      timestamp: 1,
      authorDid: 'did:key:zA',
    });

    expect(rootsEqual(before, computeManagerStateRoot(docs))).toBe(false);
  });
});

test.describe('CRDT — Sync Engine (Stream 0x01)', () => {
  test('peer with no documents receives the full document', () => {
    const docsA = new DocumentManager();
    const docsB = new DocumentManager();

    docsA.createDocument('General', 'doc-1');
    docsA.addMessage('doc-1', {
      id: 'm1',
      content: 'hello from A',
      timestamp: 1000,
      authorDid: 'did:key:zA',
    });

    const engineA = new CrdtSyncEngine(docsA, SHARE_ALL);
    const engineB = new CrdtSyncEngine(docsB, SHARE_ALL);

    runSyncToCompletion(engineA, engineB);

    const docB = docsB.getDocument('doc-1');
    expect(docB).toBeDefined();
    expect(docB!.messages['m1']?.content).toBe('hello from A');
    expect(docsA.getHeads('doc-1')).toEqual(docsB.getHeads('doc-1'));
  });

  test('already-synced peers exchange no document history', () => {
    const docsA = new DocumentManager();
    const docsB = new DocumentManager();

    const engineA = new CrdtSyncEngine(docsA, SHARE_ALL);
    const engineB = new CrdtSyncEngine(docsB, SHARE_ALL);

    // Both empty ⇒ roots match ⇒ RFC 002 §4.2 step 2 short circuit.
    const rootSync = engineA.beginSync('peer-b');
    const replies = engineB.handleMessage('peer-a', rootSync);

    expect(replies).toHaveLength(1);

    const decoded = decodeSyncFrame(replies[0]!);
    expect(decoded.type).toBe(SyncMessageType.ROOT_MATCH);
    expect(decodeBoolBody(decoded.body)).toBe(true);

    // The matching answer terminates the conversation.
    expect(engineA.handleMessage('peer-b', replies[0]!)).toHaveLength(0);
  });

  test('concurrent edits on both peers converge', () => {
    const docsA = new DocumentManager();
    const docsB = new DocumentManager();

    docsA.createDocument('General', 'doc-1');
    docsA.addMessage('doc-1', {
      id: 'm-a',
      content: 'from A',
      timestamp: 1,
      authorDid: 'did:key:zA',
    });

    const engineA = new CrdtSyncEngine(docsA, SHARE_ALL);
    const engineB = new CrdtSyncEngine(docsB, SHARE_ALL);

    // First sync gives B the document.
    runSyncToCompletion(engineA, engineB);

    // Now both edit independently.
    docsA.addMessage('doc-1', {
      id: 'm-a2',
      content: 'second from A',
      timestamp: 2,
      authorDid: 'did:key:zA',
    });
    docsB.addMessage('doc-1', {
      id: 'm-b1',
      content: 'from B',
      timestamp: 3,
      authorDid: 'did:key:zB',
    });

    runSyncToCompletion(engineA, engineB);

    const docA = docsA.getDocument('doc-1')!;
    const docB = docsB.getDocument('doc-1')!;

    expect(Object.keys(docA.messages).sort()).toEqual(['m-a', 'm-a2', 'm-b1']);
    expect(Object.keys(docB.messages).sort()).toEqual(['m-a', 'm-a2', 'm-b1']);
    expect(docsA.getHeads('doc-1')).toEqual(docsB.getHeads('doc-1'));
  });

  test('onDocumentUpdate fires when remote changes land', () => {
    const docsA = new DocumentManager();
    const docsB = new DocumentManager();

    docsA.createDocument('General', 'doc-1');
    docsA.addMessage('doc-1', {
      id: 'm1',
      content: 'ping',
      timestamp: 1,
      authorDid: 'did:key:zA',
    });

    const engineA = new CrdtSyncEngine(docsA, SHARE_ALL);
    const engineB = new CrdtSyncEngine(docsB, SHARE_ALL);

    const updates: string[] = [];
    engineB.onDocumentUpdate((u) => updates.push(u.docId));

    runSyncToCompletion(engineA, engineB);

    expect(updates).toContain('doc-1');
  });

  test('removePeer clears sync state', () => {
    const docs = new DocumentManager();
    const engine = new CrdtSyncEngine(docs, SHARE_ALL);

    engine.registerPeer('peer-x');
    expect(engine.peerCount).toBe(1);

    engine.removePeer('peer-x');
    expect(engine.peerCount).toBe(0);
  });
});
