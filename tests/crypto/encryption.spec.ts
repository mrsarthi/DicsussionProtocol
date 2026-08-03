import { test, expect } from '@playwright/test';

test.describe('Crypto — AES-256-GCM Encryption', () => {
  test('encrypt/decrypt round-trips with shared secret', async () => {
    const { encrypt, decrypt } = await import(
      '../../packages/core/src/crypto/encryption.js'
    );
    const { generateX25519Keypair, deriveSharedSecret } = await import(
      '../../packages/core/src/crypto/keys.js'
    );
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();
    const secret = deriveSharedSecret(alice.secretKey, bob.publicKey);

    const plaintext = new TextEncoder().encode('Hello, encrypted world!');
    const { ciphertext, nonce } = encrypt(plaintext, secret);

    expect(ciphertext.length).toBeGreaterThan(plaintext.length); // includes auth tag
    expect(nonce.length).toBe(12);

    const decrypted = decrypt(ciphertext, nonce, secret);
    expect(new TextDecoder().decode(decrypted)).toBe('Hello, encrypted world!');
  });

  test('decrypt fails with wrong key', async () => {
    const { encrypt, decrypt } = await import(
      '../../packages/core/src/crypto/encryption.js'
    );
    const { randomBytes } = await import('node:crypto');

    const key1 = new Uint8Array(randomBytes(32));
    const key2 = new Uint8Array(randomBytes(32));

    const plaintext = new TextEncoder().encode('secret');
    const { ciphertext, nonce } = encrypt(plaintext, key1);

    expect(() => decrypt(ciphertext, nonce, key2)).toThrow();
  });

  test('encryptForPeer/decryptFromPeer ephemeral E2EE', async () => {
    const { encryptForPeer, decryptFromPeer } = await import(
      '../../packages/core/src/crypto/encryption.js'
    );
    const { generateX25519Keypair } = await import(
      '../../packages/core/src/crypto/keys.js'
    );

    const bob = generateX25519Keypair();
    const plaintext = new TextEncoder().encode('E2EE message');

    const payload = encryptForPeer(plaintext, bob.publicKey);
    expect(payload.ephemeralPubkey.length).toBe(32);
    expect(payload.nonce.length).toBe(12);

    const decrypted = decryptFromPeer(payload, bob.secretKey);
    expect(new TextDecoder().decode(decrypted)).toBe('E2EE message');
  });
});
