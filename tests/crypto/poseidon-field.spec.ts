import { expect, test } from '@playwright/test';

import {
  assertCanonicalField,
  BN254_SCALAR_FIELD,
  bytesToField,
  compareFieldBytes,
  FIELD_BYTES,
  fieldToBytes,
  fieldToHex,
  hexToField,
  isCanonicalField,
  reduceToField,
} from '../../packages/core/src/crypto/field.js';
import {
  DomainSeparator,
  issuanceNullifier,
  membershipCommitment,
  poseidonDomain,
  poseidonHash,
  poseidonPair,
  rlnNullifier,
  slopeWitness,
  voucherNullifier,
} from '../../packages/core/src/crypto/poseidon.js';

test.describe('Crypto — BN254 Scalar Field', () => {
  test('canonical range is enforced at both ends', () => {
    expect(isCanonicalField(0n)).toBe(true);
    expect(isCanonicalField(BN254_SCALAR_FIELD - 1n)).toBe(true);
    expect(isCanonicalField(BN254_SCALAR_FIELD)).toBe(false);
    expect(isCanonicalField(-1n)).toBe(false);

    expect(() => assertCanonicalField(BN254_SCALAR_FIELD)).toThrow(
      /NonCanonicalField/,
    );
  });

  test('field elements round-trip through 32 big-endian bytes', () => {
    const values = [0n, 1n, 255n, 256n, BN254_SCALAR_FIELD - 1n];

    for (const value of values) {
      const bytes = fieldToBytes(value);
      expect(bytes).toHaveLength(FIELD_BYTES);
      expect(bytesToField(bytes)).toBe(value);
    }
  });

  test('bytesToField rejects wrong widths and out-of-field values', () => {
    expect(() => bytesToField(new Uint8Array(31))).toThrow(/32 bytes/);

    const overflow = new Uint8Array(FIELD_BYTES).fill(0xff);
    expect(() => bytesToField(overflow)).toThrow(/NonCanonicalField/);
  });

  test('byte comparison matches numeric ordering', () => {
    expect(compareFieldBytes(1n, 2n)).toBeLessThan(0);
    expect(compareFieldBytes(2n, 1n)).toBeGreaterThan(0);
    expect(compareFieldBytes(7n, 7n)).toBe(0);

    // Fixed-width big-endian means no short-string ordering surprises.
    expect(compareFieldBytes(255n, 256n)).toBeLessThan(0);
  });

  test('sorting by the byte comparator is a total order', () => {
    const values = [500n, 1n, 256n, 0n, 255n, BN254_SCALAR_FIELD - 1n];
    const sorted = [...values].sort(compareFieldBytes);

    expect(sorted).toEqual([0n, 1n, 255n, 256n, 500n, BN254_SCALAR_FIELD - 1n]);
  });

  test('hex round-trips and rejects malformed input', () => {
    const value = 123_456_789n;
    const hex = fieldToHex(value);

    expect(hex).toMatch(/^0x[0-9a-f]{64}$/);
    expect(hexToField(hex)).toBe(value);
    expect(hexToField(hex.slice(2))).toBe(value);

    expect(() => hexToField('0xzz')).toThrow(/Invalid field hex/);
    expect(() => hexToField('')).toThrow(/Invalid field hex/);
  });

  test('reduceToField maps oversized digests into the field', () => {
    const oversized = new Uint8Array(64).fill(0xff);
    const reduced = reduceToField(oversized);

    expect(isCanonicalField(reduced)).toBe(true);
  });
});

test.describe('Crypto — Domain-Separated Poseidon', () => {
  test('matches the published circomlib test vector', () => {
    // Well-known circomlib value for Poseidon([1, 2]).
    expect(poseidonHash([1n, 2n])).toBe(
      7853200120776062878684798364095072458815029376092732009249414926327459813530n,
    );
  });

  test('hashing is deterministic and in-field', () => {
    const first = poseidonHash([1n, 2n, 3n]);
    const second = poseidonHash([1n, 2n, 3n]);

    expect(first).toBe(second);
    expect(isCanonicalField(first)).toBe(true);
  });

  test('arity 1 through 5 are supported and distinct', () => {
    const digests = [
      poseidonHash([1n]),
      poseidonHash([1n, 1n]),
      poseidonHash([1n, 1n, 1n]),
      poseidonHash([1n, 1n, 1n, 1n]),
      poseidonHash([1n, 1n, 1n, 1n, 1n]),
    ];

    expect(new Set(digests).size).toBe(5);
    expect(() => poseidonHash([])).toThrow(/1–5 inputs/);
    expect(() => poseidonHash([1n, 1n, 1n, 1n, 1n, 1n])).toThrow(/1–5 inputs/);
  });

  test('non-canonical inputs are rejected before hashing', () => {
    expect(() => poseidonHash([BN254_SCALAR_FIELD])).toThrow(
      /NonCanonicalField/,
    );
    expect(() => poseidonHash([1n, -5n])).toThrow(/NonCanonicalField/);
  });

  test('domain separation makes identical inputs hash differently', () => {
    const a = poseidonDomain(DomainSeparator.NULLIFIER, 10n, 20n);
    const b = poseidonDomain(DomainSeparator.SLOPE, 10n, 20n);
    const c = poseidonDomain(DomainSeparator.MEMBER, 10n, 20n);

    expect(new Set([a, b, c]).size).toBe(3);
  });

  test('domain tags match the frozen RFC 003 §3.1 table', () => {
    expect(DomainSeparator.NULLIFIER).toBe(1n);
    expect(DomainSeparator.SLOPE).toBe(2n);
    expect(DomainSeparator.MSG).toBe(3n);
    expect(DomainSeparator.VOUCHER).toBe(4n);
    expect(DomainSeparator.ISSUE).toBe(5n);
    expect(DomainSeparator.MEMBER).toBe(6n);
  });

  test('protocol commitments are distinct under the same inputs', () => {
    const secret = 111n;
    const epoch = 222n;
    const index = 333n;

    const nullifier = rlnNullifier(secret, epoch, index);
    const slope = slopeWitness(secret, epoch, index);
    const issuance = issuanceNullifier(secret, epoch, index);

    // A slope witness must never collide with a public nullifier — that
    // would leak the private witness.
    expect(new Set([nullifier, slope, issuance]).size).toBe(3);
  });

  test('membership commitment binds both secret and trapdoor', () => {
    const base = membershipCommitment(1n, 2n);

    expect(membershipCommitment(2n, 1n)).not.toBe(base);
    expect(membershipCommitment(1n, 3n)).not.toBe(base);
    expect(membershipCommitment(1n, 2n)).toBe(base);
  });

  test('voucher nullifier is stable per (serial, scope, redeemer)', () => {
    const first = voucherNullifier(7n, 8n, 9n);

    expect(voucherNullifier(7n, 8n, 9n)).toBe(first);
    // A different redeemer produces a different nullifier, which is what
    // keeps redemptions unlinkable across users.
    expect(voucherNullifier(7n, 8n, 10n)).not.toBe(first);
    expect(voucherNullifier(7n, 9n, 9n)).not.toBe(first);
  });

  test('Merkle pair hashing is order sensitive', () => {
    expect(poseidonPair(1n, 2n)).not.toBe(poseidonPair(2n, 1n));
  });
});
