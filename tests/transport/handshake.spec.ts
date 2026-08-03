import { test, expect } from '@playwright/test';

test.describe('Transport — Handshake Protocol', () => {
  test('full handshake sequence succeeds', async () => {
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const {
      createHandshakeInit,
      processHandshakeInit,
      createHandshakeAck,
      verifyHandshakeAck,
      verifyHandshakeChallenge,
      clearNonceRegistry,
    } = await import('../../packages/core/src/transport/handshake.js');

    clearNonceRegistry();

    const alice = generateKeypair();
    const bob = generateKeypair();
    const aliceDid = publicKeyToDidKey(alice.publicKey);
    const now = Math.floor(Date.now() / 1000);

    // Step 1: Alice sends init
    const init = createHandshakeInit(alice, aliceDid, now);
    expect(init.nonce.length).toBe(32);
    expect(init.didKey).toBe(aliceDid);

    // Step 2: Bob processes init, produces challenge
    const { challenge, clockOffset } = processHandshakeInit(init, bob, now);
    expect(challenge.nonce.length).toBe(32);
    expect(challenge.signature.length).toBe(64);
    expect(clockOffset).toBe(0);

    // Verify challenge signature
    expect(verifyHandshakeChallenge(challenge, bob.publicKey, init.nonce)).toBe(true);

    // Step 3: Alice sends ack
    const ack = createHandshakeAck(alice, challenge.nonce);
    expect(ack.signature.length).toBe(64);

    // Bob verifies ack
    expect(verifyHandshakeAck(ack, alice.publicKey, challenge.nonce)).toBe(true);
  });

  test('rejects clock skew > 10 seconds', async () => {
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const { createHandshakeInit, processHandshakeInit, clearNonceRegistry } = await import(
      '../../packages/core/src/transport/handshake.js'
    );

    clearNonceRegistry();

    const alice = generateKeypair();
    const bob = generateKeypair();
    const aliceDid = publicKeyToDidKey(alice.publicKey);
    const now = Math.floor(Date.now() / 1000);

    const init = createHandshakeInit(alice, aliceDid, now);
    // Bob's clock is 15 seconds ahead
    expect(() => processHandshakeInit(init, bob, now + 15)).toThrow(/Clock skew/);
  });

  test('rejects nonce replay', async () => {
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const { createHandshakeInit, processHandshakeInit, clearNonceRegistry } = await import(
      '../../packages/core/src/transport/handshake.js'
    );

    clearNonceRegistry();

    const alice = generateKeypair();
    const bob = generateKeypair();
    const aliceDid = publicKeyToDidKey(alice.publicKey);
    const now = Math.floor(Date.now() / 1000);

    const init = createHandshakeInit(alice, aliceDid, now);
    processHandshakeInit(init, bob, now);

    // Replay the same nonce
    expect(() => processHandshakeInit(init, bob, now)).toThrow(/replay/i);
  });

  test('calculateEpoch computes correctly', async () => {
    const { calculateEpoch } = await import(
      '../../packages/core/src/transport/handshake.js'
    );
    // T_local = 100, Δ = 0 → epoch = 10
    expect(calculateEpoch(100, 0)).toBe(10);
    // T_local = 105, Δ = 5 → epoch = 11
    expect(calculateEpoch(105, 5)).toBe(11);
  });
});
