/**
 * A sealed envelope does not stay openable forever.
 *
 * An envelope is handed to something untrusted and may be copied. Left
 * unbounded, one captured today could be re-delivered next year and
 * appear as something just said. Driven through `seal`/`open` directly,
 * because the clock has to move and a real one will not.
 */

import { expect, test } from '@playwright/test';

import {
  DEFAULT_MAX_AGE_S,
  open,
  seal,
} from '../../packages/HLessEnd/src/sealed-message.js';
import { generateKeypair } from '../../packages/core/src/transport/did-key.js';
import { publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import { generateX25519Keypair } from '../../packages/core/src/crypto/keys.js';

function party() {
  const signing = generateKeypair();
  const encryption = generateX25519Keypair();
  return { signing, encryption, did: publicKeyToDidKey(signing.publicKey) };
}

const payload = (content: string) => ({
  id: 'm1',
  channelId: 'room',
  content,
  timestamp: 1000,
  messageIndex: 0,
});

test.describe('Sealed envelopes and time', () => {
  const alice = party();
  const bob = party();

  const context = (now: number) => ({
    selfDid: bob.did,
    encryptionSecret: bob.encryption.secretKey,
    isPaired: () => true,
    now: () => now,
  });

  test('opens well within its life', () => {
    const envelope = seal(
      payload('fresh'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 1_000_000 },
    );

    const result = open(envelope, context(1_000_000 + 60));
    expect(result.ok).toBe(true);
  });

  test('a replay after its life is refused', () => {
    const envelope = seal(
      payload('stale'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 1_000_000 },
    );

    const result = open(envelope, context(1_000_000 + DEFAULT_MAX_AGE_S + 1));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('expired');
  });

  test('a sender cannot buy itself extra life', () => {
    // The cap is the lower of what the sender asked for and what this
    // node allows, or an attacker sets maxAge to a century.
    const envelope = seal(
      payload('forever'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 1_000_000, maxAgeS: 100 * 365 * 24 * 60 * 60 },
    );

    const result = open(envelope, context(1_000_000 + DEFAULT_MAX_AGE_S + 1));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('expired');
  });

  test('a shorter life the sender chose is honoured', () => {
    const envelope = seal(
      payload('brief'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 1_000_000, maxAgeS: 60 },
    );

    expect(open(envelope, context(1_000_000 + 30)).ok).toBe(true);
    expect(open(envelope, context(1_000_000 + 61)).ok).toBe(false);
  });

  test('a wildly future-dated envelope is refused', () => {
    // Otherwise dating one ahead outlives its own limit.
    const envelope = seal(
      payload('from tomorrow'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 2_000_000 },
    );

    const result = open(envelope, context(1_000_000));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('expired');
  });

  test('a small clock difference is tolerated', () => {
    const envelope = seal(
      payload('slightly ahead'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 1_000_060 },
    );

    expect(open(envelope, context(1_000_000)).ok).toBe(true);
  });

  test('an unpaired sender is refused even when everything else holds', () => {
    const envelope = seal(
      payload('stranger'),
      alice.did,
      alice.signing.secretKey,
      bob.did,
      bob.encryption.publicKey,
      { sentAt: 1_000_000 },
    );

    const result = open(envelope, {
      ...context(1_000_000),
      isPaired: () => false,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('unpaired-sender');
  });
});
