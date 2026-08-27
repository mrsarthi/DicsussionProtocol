import { test, expect } from '@playwright/test';

test.describe('Transport — Wire Frame Codec', () => {
  test('encodeFrame produces correct header layout', async () => {
    const { encodeFrame, HEADER_SIZE, PROTOCOL_MAGIC, StreamType } = await import(
      '../../packages/core/src/transport/index.js'
    );
    const payload = new TextEncoder().encode('hello');
    const frame = encodeFrame(StreamType.E2EE_MESSAGE, payload);

    expect(frame.length).toBe(HEADER_SIZE + payload.length);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    expect(view.getUint16(0, false)).toBe(PROTOCOL_MAGIC);
    expect(view.getUint8(2)).toBe(StreamType.E2EE_MESSAGE);
    expect(view.getUint32(4, false)).toBe(payload.length);
  });

  test('decodeFrame round-trips with encodeFrame', async () => {
    const { encodeFrame, decodeFrame, StreamType } = await import(
      '../../packages/core/src/transport/index.js'
    );
    const payload = new TextEncoder().encode('test payload');
    const encoded = encodeFrame(StreamType.CRDT_SYNC, payload);
    const decoded = decodeFrame(encoded);

    expect(decoded.header.streamType).toBe(StreamType.CRDT_SYNC);
    expect(decoded.header.payloadLen).toBe(payload.length);
    expect(Buffer.from(decoded.payload)).toEqual(Buffer.from(payload));
  });

  test('decodeFrame uses zero-copy subarray', async () => {
    const { encodeFrame, decodeFrame, StreamType } = await import(
      '../../packages/core/src/transport/index.js'
    );
    const payload = new TextEncoder().encode('zero-copy');
    const encoded = encodeFrame(StreamType.RLN_SIGNAL, payload);
    const decoded = decodeFrame(encoded);

    // The payload should share the same ArrayBuffer as the encoded frame
    expect(decoded.payload.buffer).toBe(encoded.buffer);
  });

  test('decodeFrame detects checksum mismatch', async () => {
    const { encodeFrame, decodeFrame, StreamType } = await import(
      '../../packages/core/src/transport/index.js'
    );
    const payload = new TextEncoder().encode('corrupt me');
    const encoded = encodeFrame(StreamType.E2EE_MESSAGE, payload);

    // Corrupt a payload byte
    encoded[12] = (encoded[12]! ^ 0xff) & 0xff;

    expect(() => decodeFrame(encoded)).toThrow(/CRC32-C/);
  });

  test('decodeFrame rejects invalid magic', async () => {
    const { decodeFrameHeader } = await import(
      '../../packages/core/src/transport/index.js'
    );
    const buf = new Uint8Array(12);
    const view = new DataView(buf.buffer);
    view.setUint16(0, 0xdead, false);

    expect(() => decodeFrameHeader(buf)).toThrow(/Invalid magic/);
  });

  test('encodeFrame rejects unknown stream type', async () => {
    const { encodeFrame } = await import(
      '../../packages/core/src/transport/index.js'
    );
    expect(() => encodeFrame(0xff as any, new Uint8Array(0))).toThrow(
      /Invalid stream type/,
    );
  });

  test('decodeFrame rejects buffer too small', async () => {
    const { decodeFrameHeader } = await import(
      '../../packages/core/src/transport/index.js'
    );
    expect(() => decodeFrameHeader(new Uint8Array(4))).toThrow(/too small/);
  });

  test('every stream type encodes correctly', async () => {
    const { encodeFrame, decodeFrame, StreamType } = await import(
      '../../packages/core/src/transport/index.js'
    );
    // Read from StreamType, not listed: a hand-kept list quietly stops
    // covering a stream type the day one is added.
    const types = Object.values(StreamType);

    for (const st of types) {
      const payload = new Uint8Array([st]);
      const frame = encodeFrame(st, payload);
      const decoded = decodeFrame(frame);
      expect(decoded.header.streamType).toBe(st);
    }
  });
});
