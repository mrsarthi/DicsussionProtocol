import { test, expect } from '@playwright/test';

test.describe('Crypto — SecurityEnvelope', () => {
  test('serialize/deserialize round-trips correctly', async () => {
    const { serializeEnvelope, deserializeEnvelope, PROTOCOL_VERSION } = await import(
      '../../packages/core/src/crypto/index.js'
    );

    const envelope = {
      version: PROTOCOL_VERSION,
      epoch: 12345678,
      tierThreshold: 100,
      rlnNullifier: new Uint8Array(32).fill(0xab),
      zkProof: new Uint8Array(128).fill(0xcd),
      ephemeralPubkey: new Uint8Array(32).fill(0xef),
      nonce: new Uint8Array(12).fill(0x01),
      ciphertext: new TextEncoder().encode('encrypted content'),
    };

    const binary = serializeEnvelope(envelope);
    const parsed = deserializeEnvelope(binary);

    expect(parsed.version).toBe(PROTOCOL_VERSION);
    expect(parsed.epoch).toBe(12345678);
    expect(parsed.tierThreshold).toBe(100);
    expect(Buffer.from(parsed.rlnNullifier)).toEqual(Buffer.from(envelope.rlnNullifier));
    expect(Buffer.from(parsed.zkProof)).toEqual(Buffer.from(envelope.zkProof));
    expect(Buffer.from(parsed.ephemeralPubkey)).toEqual(Buffer.from(envelope.ephemeralPubkey));
    expect(Buffer.from(parsed.nonce)).toEqual(Buffer.from(envelope.nonce));
    expect(new TextDecoder().decode(parsed.ciphertext)).toBe('encrypted content');
  });

  test('version appears at offset 0', async () => {
    const { serializeEnvelope, PROTOCOL_VERSION } = await import(
      '../../packages/core/src/crypto/index.js'
    );

    const envelope = {
      version: PROTOCOL_VERSION,
      epoch: 0,
      tierThreshold: 0,
      rlnNullifier: new Uint8Array(32),
      zkProof: new Uint8Array(0),
      ephemeralPubkey: new Uint8Array(32),
      nonce: new Uint8Array(12),
      ciphertext: new Uint8Array(0),
    };

    const binary = serializeEnvelope(envelope);
    expect(binary[0]).toBe(PROTOCOL_VERSION);
  });

  test('deserialize rejects unsupported version', async () => {
    const { serializeEnvelope, deserializeEnvelope, PROTOCOL_VERSION } = await import(
      '../../packages/core/src/crypto/index.js'
    );

    const envelope = {
      version: PROTOCOL_VERSION,
      epoch: 0,
      tierThreshold: 0,
      rlnNullifier: new Uint8Array(32),
      zkProof: new Uint8Array(0),
      ephemeralPubkey: new Uint8Array(32),
      nonce: new Uint8Array(12),
      ciphertext: new Uint8Array(0),
    };

    const binary = serializeEnvelope(envelope);
    binary[0] = 0xff; // corrupt version
    expect(() => deserializeEnvelope(binary)).toThrow(/Unsupported/);
  });

  test('deserialize rejects truncated buffer', async () => {
    const { deserializeEnvelope } = await import(
      '../../packages/core/src/crypto/index.js'
    );
    expect(() => deserializeEnvelope(new Uint8Array(10))).toThrow(/too small/);
  });

  test('parsed fields are copies, not views into the source buffer', async () => {
    const { serializeEnvelope, deserializeEnvelope, PROTOCOL_VERSION } = await import(
      '../../packages/core/src/crypto/index.js'
    );

    const envelope = {
      version: PROTOCOL_VERSION,
      epoch: 1,
      tierThreshold: 50,
      rlnNullifier: new Uint8Array(32).fill(0x11),
      zkProof: new Uint8Array(64).fill(0x22),
      ephemeralPubkey: new Uint8Array(32).fill(0x33),
      nonce: new Uint8Array(12).fill(0x44),
      ciphertext: new TextEncoder().encode('payload'),
    };

    const binary = serializeEnvelope(envelope);
    const parsed = deserializeEnvelope(binary);

    // Views would alias the caller's buffer. A transport that pools or
    // reuses its receive buffer would then mutate these fields under
    // code still holding the envelope — and a mutated GCM nonce means
    // key/nonce reuse, which leaks the XOR of both plaintexts.
    expect(parsed.rlnNullifier.buffer).not.toBe(binary.buffer);
    expect(parsed.ephemeralPubkey.buffer).not.toBe(binary.buffer);
    expect(parsed.nonce.buffer).not.toBe(binary.buffer);
    expect(parsed.ciphertext.buffer).not.toBe(binary.buffer);
  });

  test('overwriting the source buffer cannot corrupt a parsed envelope', async () => {
    // The concrete failure the copies prevent, driven end to end.
    const { serializeEnvelope, deserializeEnvelope, PROTOCOL_VERSION } = await import(
      '../../packages/core/src/crypto/index.js'
    );

    const binary = serializeEnvelope({
      version: PROTOCOL_VERSION,
      epoch: 1,
      tierThreshold: 0,
      rlnNullifier: new Uint8Array(32).fill(0x11),
      zkProof: new Uint8Array(0),
      ephemeralPubkey: new Uint8Array(32).fill(0x33),
      nonce: new Uint8Array(12).fill(0x44),
      ciphertext: new TextEncoder().encode('payload'),
    });

    const parsed = deserializeEnvelope(binary);
    const nonceBefore = Buffer.from(parsed.nonce).toString('hex');

    // Simulate a pooled receive buffer being reused for the next frame.
    binary.fill(0xff);

    expect(Buffer.from(parsed.nonce).toString('hex')).toBe(nonceBefore);
    expect(Buffer.from(parsed.ephemeralPubkey).every((b) => b === 0x33)).toBe(true);
  });
});
