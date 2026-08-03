import { test, expect } from '@playwright/test';

test.describe('Transport — did:key Identity', () => {
  test('generateKeypair produces 32-byte keys', async () => {
    const { generateKeypair } = await import('../../packages/core/src/transport/did-key.js');
    const kp = generateKeypair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.secretKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(32);
  });

  test('publicKeyToDidKey produces valid did:key format', async () => {
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const kp = generateKeypair();
    const did = publicKeyToDidKey(kp.publicKey);
    expect(did).toMatch(/^did:key:z6M/);
  });

  test('didKeyToPublicKey round-trips correctly', async () => {
    const { generateKeypair, publicKeyToDidKey, didKeyToPublicKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const kp = generateKeypair();
    const did = publicKeyToDidKey(kp.publicKey);
    const recovered = didKeyToPublicKey(did);
    expect(Buffer.from(recovered)).toEqual(Buffer.from(kp.publicKey));
  });

  test('validateDidKey accepts valid and rejects invalid', async () => {
    const { generateKeypair, publicKeyToDidKey, validateDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const kp = generateKeypair();
    const did = publicKeyToDidKey(kp.publicKey);
    expect(validateDidKey(did)).toBe(true);
    expect(validateDidKey('did:key:invalid')).toBe(false);
    expect(validateDidKey('not-a-did')).toBe(false);
  });

  test('didKeyToPublicKey rejects wrong prefix', async () => {
    const { didKeyToPublicKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    expect(() => didKeyToPublicKey('did:web:example.com')).toThrow();
  });

  test('publicKeyToDidKey rejects non-32-byte keys', async () => {
    const { publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    expect(() => publicKeyToDidKey(new Uint8Array(16))).toThrow(/expected 32/);
  });
});
