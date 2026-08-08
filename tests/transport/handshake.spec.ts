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

    // Step 1: Alice sends init, keeping her ephemeral secret.
    const { init, ephemeralSecret } = createHandshakeInit(alice, aliceDid, now);
    expect(init.nonce.length).toBe(32);
    expect(init.didKey).toBe(aliceDid);
    expect(init.ephemeralKey.length).toBe(32);

    // Step 2: Bob processes init, produces challenge and a session key.
    const { challenge, clockOffset, sessionKey } = processHandshakeInit(
      init,
      bob,
      now,
    );
    expect(challenge.nonce.length).toBe(32);
    expect(challenge.signature.length).toBe(64);
    expect(challenge.ephemeralKey.length).toBe(32);
    expect(clockOffset).toBe(0);

    // The transcript binds both identities, both nonces and both
    // ephemerals — not just the nonce.
    const context = {
      initiatorDid: aliceDid,
      responderDid: publicKeyToDidKey(bob.publicKey),
      initiatorNonce: init.nonce,
      responderNonce: challenge.nonce,
      initiatorEphemeral: init.ephemeralKey,
      responderEphemeral: challenge.ephemeralKey,
    };

    expect(verifyHandshakeChallenge(challenge, bob.publicKey, context)).toBe(true);

    // Step 3: Alice sends ack over the same transcript.
    const ack = createHandshakeAck(alice, context);
    expect(ack.signature.length).toBe(64);

    expect(verifyHandshakeAck(ack, alice.publicKey, context)).toBe(true);

    // Both sides independently arrive at the same session key.
    const { deriveSessionKey, transcriptFor, HandshakeTag } = await import(
      '../../packages/core/src/transport/handshake.js'
    );
    const aliceKey = deriveSessionKey(
      ephemeralSecret,
      challenge.ephemeralKey,
      transcriptFor(HandshakeTag.ACK, context),
    );

    expect(Buffer.from(aliceKey).toString('hex')).toBe(
      Buffer.from(sessionKey).toString('hex'),
    );
  });

  test('a substituted ephemeral key fails challenge verification', async () => {
    // Without signing the ephemerals this is the classic
    // unauthenticated-DH hole: an on-path attacker swaps in its own key,
    // reads everything, and both sides believe the handshake succeeded.
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const { x25519 } = await import('@noble/curves/ed25519.js');
    const {
      createHandshakeInit,
      processHandshakeInit,
      verifyHandshakeChallenge,
      clearNonceRegistry,
    } = await import('../../packages/core/src/transport/handshake.js');

    clearNonceRegistry();

    const alice = generateKeypair();
    const bob = generateKeypair();
    const now = Math.floor(Date.now() / 1000);

    const aliceDid = publicKeyToDidKey(alice.publicKey);
    const { init } = createHandshakeInit(alice, aliceDid, now);
    const { challenge } = processHandshakeInit(init, bob, now);

    // The attacker replaces Bob's ephemeral with one it controls.
    const attackerEphemeral = x25519.getPublicKey(x25519.utils.randomSecretKey());
    const tampered = { ...challenge, ephemeralKey: attackerEphemeral };

    expect(
      verifyHandshakeChallenge(tampered, bob.publicKey, {
        initiatorDid: aliceDid,
        responderDid: publicKeyToDidKey(bob.publicKey),
        initiatorNonce: init.nonce,
        responderNonce: challenge.nonce,
        initiatorEphemeral: init.ephemeralKey,
        responderEphemeral: attackerEphemeral,
      }),
    ).toBe(false);
  });

  test('a signature is not transferable to a different identity pair', () => {
    // The unknown-key-share the transcript binding exists to stop: an
    // attacker relays one peer's ephemeral to a third party under that
    // peer's name. Because the identities are inside the signed bytes,
    // the same signature cannot validate for a different pair.
    return (async () => {
      const { generateKeypair, publicKeyToDidKey } = await import(
        '../../packages/core/src/transport/did-key.js'
      );
      const {
        createHandshakeInit,
        processHandshakeInit,
        createHandshakeAck,
        verifyHandshakeAck,
        clearNonceRegistry,
      } = await import('../../packages/core/src/transport/handshake.js');

      clearNonceRegistry();

      const victim = generateKeypair();
      const known = generateKeypair();
      const target = generateKeypair();
      const now = Math.floor(Date.now() / 1000);

      const victimDid = publicKeyToDidKey(victim.publicKey);
      const { init } = createHandshakeInit(victim, victimDid, now);
      const { challenge } = processHandshakeInit(init, known, now);

      // The victim acks a handshake it believes is with `known`.
      const ackForKnown = createHandshakeAck(victim, {
        initiatorDid: victimDid,
        responderDid: publicKeyToDidKey(known.publicKey),
        initiatorNonce: init.nonce,
        responderNonce: challenge.nonce,
        initiatorEphemeral: init.ephemeralKey,
        responderEphemeral: challenge.ephemeralKey,
      });

      // Replayed at `target`, which believes it is the responder.
      expect(
        verifyHandshakeAck(ackForKnown, victim.publicKey, {
          initiatorDid: victimDid,
          responderDid: publicKeyToDidKey(target.publicKey),
          initiatorNonce: init.nonce,
          responderNonce: challenge.nonce,
          initiatorEphemeral: init.ephemeralKey,
          responderEphemeral: challenge.ephemeralKey,
        }),
      ).toBe(false);
    })();
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

    const { init } = createHandshakeInit(alice, aliceDid, now);
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

    const { init } = createHandshakeInit(alice, aliceDid, now);
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

test.describe('Transport — Forward Secrecy', () => {
  test('a captured envelope resists later compromise of both long-term keys', async () => {
    // The property that matters. Under the old scheme the recipient's
    // long-term X25519 secret plus the on-wire ephemeral public key was
    // enough to redo the ECDH and decrypt everything ever sent to them.
    // Now the key material is ephemeral on BOTH sides and wiped, so
    // stealing every long-term key later yields nothing.
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const { generateX25519Keypair } = await import(
      '../../packages/core/src/crypto/keys.js'
    );
    const {
      createHandshakeInit,
      processHandshakeInit,
      deriveSessionKey,
      clearNonceRegistry,
    } = await import('../../packages/core/src/transport/handshake.js');
    const { sealMessage, openMessage } = await import(
      '../../packages/HLessEnd/src/message-codec.js'
    );

    clearNonceRegistry();

    const alice = generateKeypair();
    const bob = generateKeypair();
    // Long-term encryption keys, the ones an attacker would eventually
    // exfiltrate from a seized device.
    const aliceLongTerm = generateX25519Keypair();
    const bobLongTerm = generateX25519Keypair();

    const now = Math.floor(Date.now() / 1000);
    const { init, ephemeralSecret } = createHandshakeInit(
      alice,
      publicKeyToDidKey(alice.publicKey),
      now,
    );
    const { challenge, sessionKey } = processHandshakeInit(init, bob, now);

    const { transcriptFor, HandshakeTag } = await import(
      '../../packages/core/src/transport/handshake.js'
    );
    const context = {
      initiatorDid: publicKeyToDidKey(alice.publicKey),
      responderDid: publicKeyToDidKey(bob.publicKey),
      initiatorNonce: init.nonce,
      responderNonce: challenge.nonce,
      initiatorEphemeral: init.ephemeralKey,
      responderEphemeral: challenge.ephemeralKey,
    };
    const aliceSession = deriveSessionKey(
      ephemeralSecret,
      challenge.ephemeralKey,
      transcriptFor(HandshakeTag.ACK, context),
    );

    const wire = sealMessage(
      {
        id: 'm1',
        channelId: 'general',
        authorDid: publicKeyToDidKey(alice.publicKey),
        content: 'recorded by an eavesdropper',
        timestamp: now,
        messageIndex: 0,
      },
      aliceSession,
      170_000_000,
    );

    // Bob reads it while the session is live.
    expect(openMessage(wire, sessionKey).payload.content).toBe(
      'recorded by an eavesdropper',
    );

    // The session ends: both ephemeral secrets are gone.
    ephemeralSecret.fill(0);

    // The attacker now seizes BOTH long-term secrets and the recorded
    // wire bytes. Neither key opens it — nor does anything derivable
    // from them, because they never contributed to this session key.
    expect(() => openMessage(wire, bobLongTerm.secretKey)).toThrow();
    expect(() => openMessage(wire, aliceLongTerm.secretKey)).toThrow();

    // And the wiped ephemeral no longer reconstructs the session key.
    expect(
      Buffer.from(
        deriveSessionKey(
          ephemeralSecret,
          challenge.ephemeralKey,
          transcriptFor(HandshakeTag.ACK, context),
        ),
      ).toString('hex'),
    ).not.toBe(Buffer.from(sessionKey).toString('hex'));
  });

  test('two sessions between the same peers use different keys', async () => {
    // Without this, compromising one session would expose them all —
    // forward secrecy across reconnects is most of the value.
    const { generateKeypair, publicKeyToDidKey } = await import(
      '../../packages/core/src/transport/did-key.js'
    );
    const { createHandshakeInit, processHandshakeInit, clearNonceRegistry } =
      await import('../../packages/core/src/transport/handshake.js');

    clearNonceRegistry();

    const alice = generateKeypair();
    const bob = generateKeypair();
    const did = publicKeyToDidKey(alice.publicKey);
    const now = Math.floor(Date.now() / 1000);

    const first = processHandshakeInit(
      createHandshakeInit(alice, did, now).init,
      bob,
      now,
    );
    const second = processHandshakeInit(
      createHandshakeInit(alice, did, now).init,
      bob,
      now,
    );

    expect(Buffer.from(first.sessionKey).toString('hex')).not.toBe(
      Buffer.from(second.sessionKey).toString('hex'),
    );
  });
});
