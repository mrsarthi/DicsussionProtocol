import { test, expect } from '@playwright/test';
import { x25519 } from '@noble/curves/ed25519.js';

import {
  deriveSharedSecret,
  generateX25519Keypair,
} from '../../packages/core/src/crypto/keys.js';

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

test.describe('Crypto — ECDH Output Is Key-Derived, Not Raw', () => {
  test('the exchange key is not the raw curve output', () => {
    // The raw X25519 result is a curve u-coordinate: it has algebraic
    // structure and biased bits, so it is not safe to use directly as an
    // AES key. TLS 1.3, Signal, Noise and WireGuard all run it through a
    // KDF first. If this ever equals the raw output again, that step has
    // been lost.
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();

    const derived = deriveSharedSecret(alice.secretKey, bob.publicKey);
    const raw = x25519.getSharedSecret(alice.secretKey, bob.publicKey);

    expect(Buffer.from(derived).toString('hex')).not.toBe(
      Buffer.from(raw).toString('hex'),
    );
    expect(derived).toHaveLength(32);
  });

  test('both parties still derive the same key', () => {
    // The whole point of ECDH — a KDF that broke this would break
    // messaging outright, so it is asserted separately.
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();

    expect(
      Buffer.from(deriveSharedSecret(alice.secretKey, bob.publicKey)).toString('hex'),
    ).toBe(
      Buffer.from(deriveSharedSecret(bob.secretKey, alice.publicKey)).toString('hex'),
    );
  });

  test('different peers yield unrelated keys', () => {
    const alice = generateX25519Keypair();
    const bob = generateX25519Keypair();
    const carol = generateX25519Keypair();

    expect(
      Buffer.from(deriveSharedSecret(alice.secretKey, bob.publicKey)).toString('hex'),
    ).not.toBe(
      Buffer.from(deriveSharedSecret(alice.secretKey, carol.publicKey)).toString('hex'),
    );
  });
});
