/**
 * Input Bounds and Instance Isolation
 *
 * Covers the hardening batch applied 2026-08-11 (backlog items 1 and 3).
 * Every test here fails against the code as it stood before that change —
 * a bounds check with no test is indistinguishable from no bounds check
 * once someone refactors around it.
 */

import { expect, test } from '@playwright/test';

import {
  deserializeEnvelope,
  serializeEnvelope,
} from '../../packages/core/src/crypto/envelope.js';
import { PROTOCOL_VERSION } from '../../packages/core/src/crypto/types.js';
import { NonceRegistry } from '../../packages/core/src/transport/handshake.js';
import {
  decodePayload,
  encodePayload,
} from '../../packages/HLessEnd/src/message-codec.js';

/** A minimal well-formed envelope, overridable field by field. */
function envelope(overrides: Record<string, unknown> = {}) {
  return {
    version: PROTOCOL_VERSION,
    epoch: 1_000,
    tierThreshold: 0,
    rlnNullifier: new Uint8Array(32),
    zkProof: new Uint8Array(128),
    ephemeralPubkey: new Uint8Array(32),
    nonce: new Uint8Array(12),
    ciphertext: new Uint8Array(16),
    ...overrides,
  } as Parameters<typeof serializeEnvelope>[0];
}

test.describe('Envelope — input bounds', () => {
  test('a realistic envelope still round-trips', () => {
    // The negative tests below would pass just as well if deserialization
    // were broken outright, so pin the positive case first.
    const opened = deserializeEnvelope(serializeEnvelope(envelope()));

    expect(opened.epoch).toBe(1_000);
    expect(opened.zkProof).toHaveLength(128);
    expect(opened.ciphertext).toHaveLength(16);
  });

  test('an oversized zk proof is rejected', () => {
    // proofLen is a u16, so the wire admits up to 65,535 bytes. A Groth16
    // proof is ~128. Anything in between is corruption or an attempt to
    // make the parser allocate on demand.
    const bytes = serializeEnvelope(
      envelope({ zkProof: new Uint8Array(5_000) }),
    );

    expect(() => deserializeEnvelope(bytes)).toThrow(/proof too large/i);
  });

  test('a proof at the ceiling is still accepted', () => {
    // Guards against the check being tightened to the point of rejecting
    // legitimate future proof systems.
    const bytes = serializeEnvelope(
      envelope({ zkProof: new Uint8Array(4_096) }),
    );

    expect(deserializeEnvelope(bytes).zkProof).toHaveLength(4_096);
  });

  test('an epoch beyond the safe integer range is rejected', () => {
    // The wire carries a u64; JS numbers are exact only to 2^53. Past
    // that the reconstruction silently rounds, so two distinct epochs can
    // compare equal — enough to slip a replay past a freshness check.
    const bytes = serializeEnvelope(
      envelope({ epoch: Number.MAX_SAFE_INTEGER + 2 }),
    );

    expect(() => deserializeEnvelope(bytes)).toThrow(/safe integer/i);
  });

  test('the largest exactly-representable epoch is accepted', () => {
    const bytes = serializeEnvelope(
      envelope({ epoch: Number.MAX_SAFE_INTEGER }),
    );

    expect(deserializeEnvelope(bytes).epoch).toBe(Number.MAX_SAFE_INTEGER);
  });
});

test.describe('Message payload — input bounds', () => {
  const base = {
    id: 'msg-1',
    channelId: 'general',
    content: 'hello',
    timestamp: Date.now(),
    messageIndex: 0,
  };

  test('an ordinary payload round-trips', () => {
    expect(decodePayload(encodePayload(base)).content).toBe('hello');
  });

  test('an oversized content field is rejected', () => {
    // AES-GCM authenticates, so reaching here means the sender is paired.
    // Pairing is "accepted once", not "trusted forever" — and the cost of
    // a multi-gigabyte string lands on memory and on every row the
    // message store then writes.
    const huge = encodePayload({ ...base, content: 'x'.repeat(70_000) });

    expect(() => decodePayload(huge)).toThrow(/content too large/i);
  });

  test('content at the ceiling is accepted', () => {
    const atLimit = encodePayload({ ...base, content: 'x'.repeat(65_536) });

    expect(decodePayload(atLimit).content).toHaveLength(65_536);
  });

  test('an oversized channel id is rejected', () => {
    const bad = encodePayload({ ...base, channelId: 'c'.repeat(300) });

    expect(() => decodePayload(bad)).toThrow(/channel id too large/i);
  });

  test('an oversized message id is rejected', () => {
    const bad = encodePayload({ ...base, id: 'i'.repeat(300) });

    expect(() => decodePayload(bad)).toThrow(/id too large/i);
  });
});

test.describe('NonceRegistry — instance isolation', () => {
  const NONCE = 'a'.repeat(64);
  const NOW = 1_800_000_000;

  test('a replayed nonce is rejected within one registry', () => {
    const registry = new NonceRegistry();

    registry.admit(NONCE, NOW);
    expect(() => registry.admit(NONCE, NOW)).toThrow(/replay/i);
  });

  test('two registries do not see each other', () => {
    // The point of the change: this was module-level state, so every
    // client in a process shared one map. Two independent nodes must be
    // able to observe the same nonce value without interfering.
    const a = new NonceRegistry();
    const b = new NonceRegistry();

    a.admit(NONCE, NOW);
    expect(() => b.admit(NONCE, NOW)).not.toThrow();

    expect(a.size).toBe(1);
    expect(b.size).toBe(1);
  });

  test('expired entries are pruned', () => {
    const registry = new NonceRegistry();

    registry.admit(NONCE, NOW);
    expect(registry.size).toBe(1);

    // Well past NONCE_EXPIRY_S (300s).
    registry.prune(NOW + 3_600);
    expect(registry.size).toBe(0);

    // And the nonce is admissible again, since it can no longer be a
    // replay of anything still in the acceptance window.
    expect(() => registry.admit(NONCE, NOW + 3_600)).not.toThrow();
  });
});
