import { test, expect } from '@playwright/test';

test.describe('Crypto — Key Generation', () => {
  test('generateEd25519Keypair produces 32-byte keys', async () => {
    const { generateEd25519Keypair } = await import(
      '../../packages/core/src/crypto/keys.js'
    );
    const kp = generateEd25519Keypair();
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(32);
  });

  test('generateX25519Keypair produces 32-byte keys', async () => {
    const { generateX25519Keypair } = await import(
      '../../packages/core/src/crypto/keys.js'
    );
    const kp = generateX25519Keypair();
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(32);
  });

  test('ECDH shared secret is symmetric', async () => {
    const { generateX25519Keypair, deriveSharedSecret } = await import(
      '../../packages/core/src/crypto/keys.js'
    );
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();

    const secretA = deriveSharedSecret(alice.secretKey, bob.publicKey);
    const secretB = deriveSharedSecret(bob.secretKey, alice.publicKey);

    expect(Buffer.from(secretA)).toEqual(Buffer.from(secretB));
    expect(secretA.length).toBe(32);
  });

  test('different keypairs produce different keys', async () => {
    const { generateEd25519Keypair } = await import(
      '../../packages/core/src/crypto/keys.js'
    );
    const kp1 = generateEd25519Keypair();
    const kp2 = generateEd25519Keypair();
    expect(Buffer.from(kp1.publicKey)).not.toEqual(Buffer.from(kp2.publicKey));
  });
});
