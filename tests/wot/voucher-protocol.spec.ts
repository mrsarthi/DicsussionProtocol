import { expect, test } from '@playwright/test';

import {
  blind,
  generateBlindKeyPair,
  generateSerial,
  modInverse,
  modPow,
  toPublicKey,
  unblind,
  verifyBlindSignature,
  blindSign,
  fullDomainHash,
} from '../../packages/core/src/crypto/blind-signature.js';
import {
  decodeVoucherMessage,
  encodeVoucherMessage,
  MAX_VOUCHER_BODY,
  VoucherMessageType,
} from '../../packages/HLessEnd/src/wot/voucher-protocol.js';
import { VoucherService } from '../../packages/HLessEnd/src/wot/voucher-service.js';

/** RSA-2048 keygen is slow; share one keypair across the suite. */
let sharedKeypair: Awaited<ReturnType<typeof generateBlindKeyPair>>;

test.beforeAll(async () => {
  sharedKeypair = await generateBlindKeyPair();
});

test.describe('Crypto — Modular Arithmetic', () => {
  test('modPow matches small known values', () => {
    expect(modPow(2n, 10n, 1_000n)).toBe(24n);
    expect(modPow(3n, 0n, 7n)).toBe(1n);
    expect(modPow(5n, 3n, 13n)).toBe(8n);
  });

  test('modInverse inverts and rejects non-invertible values', () => {
    expect((modInverse(3n, 11n) * 3n) % 11n).toBe(1n);
    expect((modInverse(7n, 26n) * 7n) % 26n).toBe(1n);
    expect(() => modInverse(4n, 8n)).toThrow(/not invertible/);
  });
});

test.describe('Crypto — Chaumian Blind Signatures', () => {
  test('full blind/sign/unblind cycle verifies', () => {
    const publicKey = toPublicKey(sharedKeypair);
    const serial = generateSerial();

    const { blinded, blindingFactor } = blind(serial, publicKey);
    const signature = unblind(blindSign(blinded, sharedKeypair), blindingFactor, publicKey);

    expect(verifyBlindSignature(serial, signature, publicKey)).toBe(true);
  });

  test('the blinded value the issuer sees differs from the final signature', () => {
    const publicKey = toPublicKey(sharedKeypair);
    const serial = generateSerial();

    const { blinded, blindingFactor } = blind(serial, publicKey);
    const blindResponse = blindSign(blinded, sharedKeypair);
    const signature = unblind(blindResponse, blindingFactor, publicKey);

    // Unlinkability: nothing the issuer held equals what is presented later.
    expect(signature).not.toBe(blindResponse);
    expect(signature).not.toBe(blinded);
  });

  test('blinding the same serial twice yields different requests', () => {
    const publicKey = toPublicKey(sharedKeypair);
    const serial = generateSerial();

    const first = blind(serial, publicKey);
    const second = blind(serial, publicKey);

    expect(first.blinded).not.toBe(second.blinded);
    expect(first.blindingFactor).not.toBe(second.blindingFactor);
  });

  test('a signature does not verify for a different serial', () => {
    const publicKey = toPublicKey(sharedKeypair);
    const serial = generateSerial();

    const { blinded, blindingFactor } = blind(serial, publicKey);
    const signature = unblind(blindSign(blinded, sharedKeypair), blindingFactor, publicKey);

    expect(verifyBlindSignature(generateSerial(), signature, publicKey)).toBe(false);
  });

  test('tampered and out-of-range signatures are rejected', () => {
    const publicKey = toPublicKey(sharedKeypair);
    const serial = generateSerial();

    const { blinded, blindingFactor } = blind(serial, publicKey);
    const signature = unblind(blindSign(blinded, sharedKeypair), blindingFactor, publicKey);

    expect(verifyBlindSignature(serial, signature + 1n, publicKey)).toBe(false);
    expect(verifyBlindSignature(serial, 0n, publicKey)).toBe(false);
    expect(verifyBlindSignature(serial, publicKey.n, publicKey)).toBe(false);
  });

  test('blindSign rejects values outside the modulus', () => {
    expect(() => blindSign(0n, sharedKeypair)).toThrow(/out of range/);
    expect(() => blindSign(sharedKeypair.n, sharedKeypair)).toThrow(/out of range/);
  });

  test('full-domain hash is deterministic and non-zero', () => {
    const serial = generateSerial();
    const first = fullDomainHash(serial, sharedKeypair.n);

    expect(fullDomainHash(serial, sharedKeypair.n)).toBe(first);
    expect(first).toBeGreaterThan(0n);
    expect(first).toBeLessThan(sharedKeypair.n);
  });
});

test.describe('WoT — Stream 0x04 Voucher Codec', () => {
  test('request round-trips', () => {
    const encoded = encodeVoucherMessage({ type: 'request', blinded: 123_456_789n });
    const decoded = decodeVoucherMessage(encoded);

    expect(decoded.type).toBe('request');
    expect(decoded).toMatchObject({ blinded: 123_456_789n });
    expect(encoded[0]).toBe(VoucherMessageType.REQUEST);
  });

  test('response round-trips all three big integers', () => {
    const encoded = encodeVoucherMessage({
      type: 'response',
      blindSignature: sharedKeypair.n - 12_345n,
      modulus: sharedKeypair.n,
      exponent: sharedKeypair.e,
    });
    const decoded = decodeVoucherMessage(encoded);

    expect(decoded).toEqual({
      type: 'response',
      blindSignature: sharedKeypair.n - 12_345n,
      modulus: sharedKeypair.n,
      exponent: sharedKeypair.e,
    });
  });

  test('reject round-trips its reason', () => {
    const decoded = decodeVoucherMessage(
      encodeVoucherMessage({ type: 'reject', reason: 'quota_exhausted' }),
    );

    expect(decoded).toEqual({ type: 'reject', reason: 'quota_exhausted' });
  });

  test('zero encodes and decodes cleanly', () => {
    const decoded = decodeVoucherMessage(
      encodeVoucherMessage({ type: 'request', blinded: 0n }),
    );

    expect(decoded).toMatchObject({ blinded: 0n });
  });

  test('unknown message types are rejected', () => {
    const encoded = encodeVoucherMessage({ type: 'request', blinded: 1n });
    encoded[0] = 0x7f;

    expect(() => decodeVoucherMessage(encoded)).toThrow(/Unknown voucher message type/);
  });

  test('truncated frames are rejected', () => {
    const encoded = encodeVoucherMessage({ type: 'request', blinded: 999_999n });

    expect(() => decodeVoucherMessage(encoded.subarray(0, 4))).toThrow(/too small/);
    expect(() => decodeVoucherMessage(encoded.subarray(0, encoded.length - 2))).toThrow(
      /truncated/,
    );
  });

  test('oversized bodies are refused', () => {
    expect(() =>
      encodeVoucherMessage({ type: 'reject', reason: 'x'.repeat(MAX_VOUCHER_BODY + 1) }),
    ).toThrow(/exceeds/);
  });
});

test.describe('WoT — Voucher Service', () => {
  test('a node without an issuing key cannot issue', () => {
    const service = new VoucherService();

    expect(service.canIssue).toBe(false);
    expect(service.issuerPublicKey()).toBeUndefined();
    expect(() => service.issueVoucher(1n, 0)).toThrow(/no blind-signing key/);
  });

  test('issuance quota is enforced per epoch and resets across epochs', () => {
    const service = new VoucherService({
      issuerKeypair: sharedKeypair,
      identitySecret: 42n,
      issuanceQuota: 2,
    });
    const publicKey = toPublicKey(sharedKeypair);

    for (let i = 0; i < 2; i++) {
      const { blinded } = blind(generateSerial(), publicKey);
      expect(() => service.issueVoucher(blinded, 5)).not.toThrow();
    }

    const { blinded } = blind(generateSerial(), publicKey);
    expect(() => service.issueVoucher(blinded, 5)).toThrow(/quota exhausted/);

    // The next epoch starts with a fresh allowance.
    expect(service.hasIssuanceQuota(6)).toBe(true);
    expect(() => service.issueVoucher(blinded, 6)).not.toThrow();
  });

  test('issuance records carry no recipient identifier', () => {
    const service = new VoucherService({
      issuerKeypair: sharedKeypair,
      identitySecret: 42n,
    });

    const { blinded } = blind(generateSerial(), toPublicKey(sharedKeypair));
    const { record } = service.issueVoucher(blinded, 3);

    expect(Object.keys(record).sort()).toEqual([
      'counter',
      'epoch',
      'issuedAt',
      'nullifier',
    ]);
  });

  test('redeeming twice with the same nullifier is refused', () => {
    const service = new VoucherService({ issuerKeypair: sharedKeypair });
    const publicKey = toPublicKey(sharedKeypair);

    const pending = service.requestVoucher(publicKey, 1n);
    const token = service.completeVoucher(
      pending,
      blindSign(pending.blinded, sharedKeypair),
    );

    const first = service.redeemVoucher(token, 99n);
    expect(first.accepted).toBe(true);
    expect(first.value).toBe(5);

    const second = service.redeemVoucher(token, 99n);
    expect(second.accepted).toBe(false);
    expect(second.reason).toBe('already_redeemed');
    expect(second.nullifier).toBe(first.nullifier);
  });

  test('the same voucher redeemed by a different identity is a distinct nullifier', () => {
    const service = new VoucherService({ issuerKeypair: sharedKeypair });
    const publicKey = toPublicKey(sharedKeypair);

    const pending = service.requestVoucher(publicKey, 1n);
    const token = service.completeVoucher(
      pending,
      blindSign(pending.blinded, sharedKeypair),
    );

    const first = service.redeemVoucher(token, 100n);
    const second = service.redeemVoucher(token, 200n);

    expect(first.nullifier).not.toBe(second.nullifier);
  });

  test('restored nullifiers still block replay after a restart', () => {
    const service = new VoucherService({ issuerKeypair: sharedKeypair });
    const publicKey = toPublicKey(sharedKeypair);

    const pending = service.requestVoucher(publicKey, 2n);
    const token = service.completeVoucher(
      pending,
      blindSign(pending.blinded, sharedKeypair),
    );

    const { nullifier } = service.redeemVoucher(token, 55n);

    // A fresh process seeded from persisted nullifiers.
    const restarted = new VoucherService({ issuerKeypair: sharedKeypair });
    restarted.loadSpentNullifiers([nullifier]);

    expect(restarted.isSpent(nullifier)).toBe(true);
    expect(restarted.redeemVoucher(token, 55n).reason).toBe('already_redeemed');
  });
});
