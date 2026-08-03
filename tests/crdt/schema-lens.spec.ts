import { test, expect } from '@playwright/test';

test.describe('CRDT — Schema Lenses', () => {
  test('upcast adds default field', async () => {
    const { applyLens, registerLens, clearLensRegistry } = await import(
      '../../packages/core/src/crdt/schema-lens.js'
    );
    clearLensRegistry();

    const lens = {
      lensId: 'v1-to-v2',
      fromSchema: 'v1',
      toSchema: 'v2',
      operations: [
        { op: 'add_field' as const, path: 'reactions', default: {} },
      ],
    };
    registerLens(lens);

    const data = { id: 'msg-1', content: 'hello' };
    const result = applyLens(data, lens, 'upcast');

    expect(result).toHaveProperty('reactions');
    expect(result['reactions']).toEqual({});
    expect(result['content']).toBe('hello');
  });

  test('downcast strips added field', async () => {
    const { applyLens, clearLensRegistry } = await import(
      '../../packages/core/src/crdt/schema-lens.js'
    );
    clearLensRegistry();

    const lens = {
      lensId: 'v1-to-v2',
      fromSchema: 'v1',
      toSchema: 'v2',
      operations: [
        { op: 'add_field' as const, path: 'reactions', default: {} },
      ],
    };

    const data = { id: 'msg-1', content: 'hello', reactions: { '👍': 3 } };
    const result = applyLens(data, lens, 'downcast');

    expect(result).not.toHaveProperty('reactions');
    expect(result['content']).toBe('hello');
  });

  test('rename_field works bidirectionally', async () => {
    const { applyLens, clearLensRegistry } = await import(
      '../../packages/core/src/crdt/schema-lens.js'
    );
    clearLensRegistry();

    const lens = {
      lensId: 'rename-test',
      fromSchema: 'v1',
      toSchema: 'v2',
      operations: [
        { op: 'rename_field' as const, from: 'author', to: 'authorDid' },
      ],
    };

    // Upcast: author → authorDid
    const v1Data = { author: 'did:key:z6M...' };
    const upcasted = applyLens(v1Data, lens, 'upcast');
    expect(upcasted).toHaveProperty('authorDid', 'did:key:z6M...');
    expect(upcasted).not.toHaveProperty('author');

    // Downcast: authorDid → author
    const v2Data = { authorDid: 'did:key:z6M...' };
    const downcasted = applyLens(v2Data, lens, 'downcast');
    expect(downcasted).toHaveProperty('author', 'did:key:z6M...');
    expect(downcasted).not.toHaveProperty('authorDid');
  });

  test('applyLens does not mutate original data', async () => {
    const { applyLens, clearLensRegistry } = await import(
      '../../packages/core/src/crdt/schema-lens.js'
    );
    clearLensRegistry();

    const lens = {
      lensId: 'immut',
      fromSchema: 'v1',
      toSchema: 'v2',
      operations: [
        { op: 'add_field' as const, path: 'newField', default: 42 },
      ],
    };

    const original = { existing: 'value' };
    applyLens(original, lens, 'upcast');
    expect(original).not.toHaveProperty('newField');
  });

  test('findLensPath locates registered lens', async () => {
    const { registerLens, findLensPath, clearLensRegistry } = await import(
      '../../packages/core/src/crdt/schema-lens.js'
    );
    clearLensRegistry();

    const lens = {
      lensId: 'find-me',
      fromSchema: 'schema-a',
      toSchema: 'schema-b',
      operations: [],
    };
    registerLens(lens);

    const found = findLensPath('schema-a', 'schema-b');
    expect(found).toBeDefined();
    expect(found!.lensId).toBe('find-me');

    const notFound = findLensPath('schema-a', 'schema-c');
    expect(notFound).toBeUndefined();
  });
});
