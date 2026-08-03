import { test, expect } from '@playwright/test';

test.describe('CRDT — Document Manager', () => {
  test('create and retrieve a document', async () => {
    const { DocumentManager } = await import(
      '../../packages/core/src/crdt/document-manager.js'
    );

    const mgr = new DocumentManager();
    const docId = mgr.createDocument('Test Channel');
    const doc = mgr.getDocument(docId);

    expect(doc).toBeDefined();
    expect(doc!.meta.title).toBe('Test Channel');
    expect(doc!.$schema).toContain('chat-room');
  });

  test('addMessage and retrieve from document', async () => {
    const { DocumentManager } = await import(
      '../../packages/core/src/crdt/document-manager.js'
    );

    const mgr = new DocumentManager();
    const docId = mgr.createDocument('Chat Room');

    const changes = mgr.addMessage(docId, {
      id: 'msg-1',
      content: 'Hello world',
      timestamp: Date.now(),
    });

    expect(changes.length).toBeGreaterThan(0);

    const doc = mgr.getDocument(docId);
    expect(doc!.messages['msg-1']!.content).toBe('Hello world');
  });

  test('concurrent edits merge without conflicts', async () => {
    const { DocumentManager } = await import(
      '../../packages/core/src/crdt/document-manager.js'
    );
    const Automerge = await import('@automerge/automerge');

    const mgr1 = new DocumentManager();
    const docId = mgr1.createDocument('Concurrent', 'shared-id');

    // Clone doc for second manager
    const doc1 = mgr1.getDocument(docId)!;
    const snapshot = Automerge.save(doc1);

    const mgr2 = new DocumentManager();
    mgr2.loadFromSnapshot(docId, snapshot);

    // Both add messages concurrently
    mgr1.addMessage(docId, { id: 'a', content: 'from mgr1', timestamp: 1 });
    mgr2.addMessage(docId, { id: 'b', content: 'from mgr2', timestamp: 2 });

    // Merge
    const doc2 = mgr2.getDocument(docId)!;
    const merged = mgr1.mergeDocument(docId, doc2);

    expect(merged.messages['a']!.content).toBe('from mgr1');
    expect(merged.messages['b']!.content).toBe('from mgr2');
  });

  test('snapshot and restore', async () => {
    const { DocumentManager } = await import(
      '../../packages/core/src/crdt/document-manager.js'
    );

    const mgr = new DocumentManager();
    const docId = mgr.createDocument('Snapshot Test');
    mgr.addMessage(docId, { id: 'm1', content: 'persist me', timestamp: 1 });

    const snapshot = mgr.generateSnapshot(docId);
    expect(snapshot.length).toBeGreaterThan(0);

    const mgr2 = new DocumentManager();
    mgr2.loadFromSnapshot(docId, snapshot);
    const restored = mgr2.getDocument(docId);
    expect(restored!.messages['m1']!.content).toBe('persist me');
  });

  test('listDocuments and deleteDocument', async () => {
    const { DocumentManager } = await import(
      '../../packages/core/src/crdt/document-manager.js'
    );

    const mgr = new DocumentManager();
    mgr.createDocument('Doc A', 'id-a');
    mgr.createDocument('Doc B', 'id-b');

    expect(mgr.listDocuments()).toContain('id-a');
    expect(mgr.listDocuments()).toContain('id-b');

    mgr.deleteDocument('id-a');
    expect(mgr.listDocuments()).not.toContain('id-a');
  });
});
