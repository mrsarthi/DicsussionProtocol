/**
 * Bounds on attacker-controlled input.
 *
 * Every value checked here arrives from a peer and is used to size an
 * allocation, key a map, or drive arithmetic. None of these are clever
 * attacks — they are the ordinary consequence of trusting a length field
 * or a numeric string that someone else chose.
 */

import { expect, test } from '@playwright/test';

import { decodeFrame, encodeFrame } from '../../packages/core/src/transport/frame-codec.js';
import {
  MAX_FRAME_PAYLOAD,
  StreamType,
} from '../../packages/core/src/transport/types.js';
import { isEpochFresh } from '../../packages/core/src/zk/rln.js';
import { decodeTombstone } from '../../packages/HLessEnd/src/slashing/gossip-protocol.js';

test.describe('Hardening — Frame Payload Bounds', () => {
  test('a frame claiming more than the payload ceiling is rejected', () => {
    // `payloadLen` is a u32 the sender picks. Without a cap a peer can
    // claim 4 GB and make a reassembling reader buffer toward it — no
    // data need ever arrive.
    const frame = encodeFrame(
      StreamType.E2EE_MESSAGE,
      new TextEncoder().encode('small'),
    );

    // Overwrite the length field with something enormous.
    new DataView(frame.buffer, frame.byteOffset).setUint32(4, 0xffffffff, false);

    expect(() => decodeFrame(frame)).toThrow(/over the .* limit/);
  });

  test('a frame at exactly the ceiling is still refused when truncated', () => {
    const frame = encodeFrame(StreamType.E2EE_MESSAGE, new Uint8Array(16));
    new DataView(frame.buffer, frame.byteOffset).setUint32(
      4,
      MAX_FRAME_PAYLOAD,
      false,
    );

    // The length is legal, but the bytes are not there — this must fail
    // on the buffer check rather than reading past the end.
    expect(() => decodeFrame(frame)).toThrow(/Buffer too small/);
  });

  test('an ordinary frame still round-trips', () => {
    // The bound must not have broken the normal path.
    const payload = new TextEncoder().encode('ordinary traffic');
    const decoded = decodeFrame(encodeFrame(StreamType.E2EE_MESSAGE, payload));

    expect(new TextDecoder().decode(decoded.payload)).toBe('ordinary traffic');
  });
});

/** Wrap a tombstone JSON body in its gossip frame (type ‖ len ‖ body). */
function frameTombstone(json: string): Uint8Array {
  const body = new TextEncoder().encode(json);
  const out = new Uint8Array(5 + body.length);

  out[0] = 0x01; // RevocationMessageType.TOMBSTONE
  new DataView(out.buffer).setUint32(1, body.length, false);
  out.set(body, 5);

  return out;
}

function tombstoneJson(commitment: string): string {
  return JSON.stringify({
    revocationId: 'x',
    membershipCommitment: commitment,
    reason: 'USER_REVOKED',
    timestamp: 1,
    validatorDid: 'did:key:zA',
    signature: '',
  });
}

test.describe('Hardening — Gossip Field Bounds', () => {
  test('an over-long field element is rejected without parsing it', () => {
    // `MAX_GOSSIP_BODY` already caps the whole frame at 64 KB, so the
    // multi-megabyte case cannot reach here. What can is a field padded
    // to just under that — 60,000 digits, far past any real field
    // element, and enough for `BigInt()` to do pointless work.
    const started = Date.now();

    expect(() =>
      decodeTombstone(frameTombstone(tombstoneJson('9'.repeat(60_000)))),
    ).toThrow(/over the .* limit/);

    expect(Date.now() - started).toBeLessThan(500);
  });

  test('a field element of plausible length but wrong shape is rejected', () => {
    expect(() =>
      decodeTombstone(frameTombstone(tombstoneJson('12; DROP TABLE'))),
    ).toThrow(/decimal integer/);
  });

  test('a real field element still decodes', () => {
    // The bound must not reject legitimate values: a BN254 scalar is up
    // to 78 decimal digits.
    const real = (2n ** 250n).toString();
    expect(real.length).toBeLessThanOrEqual(78);

    // Fails later on signature verification, not on the field bound —
    // which is the point.
    expect(() => decodeTombstone(frameTombstone(tombstoneJson(real)))).not.toThrow(
      /digits|decimal integer/,
    );
  });
});

test.describe('Hardening — Epoch Bounds', () => {
  test('an epoch beyond safe-integer range is not fresh', () => {
    // Past 2^53 a JS number cannot hold the value exactly, so two
    // distinct epochs can compare equal — precisely the collision the
    // nullifier scheme depends on not happening.
    expect(isEpochFresh(Number.MAX_SAFE_INTEGER + 2, 100)).toBe(false);
    expect(isEpochFresh(1e300, 100)).toBe(false);
    expect(isEpochFresh(Number.NaN, 100)).toBe(false);
    expect(isEpochFresh(Number.POSITIVE_INFINITY, 100)).toBe(false);
  });

  test('a negative epoch is not fresh', () => {
    expect(isEpochFresh(-1, 100)).toBe(false);
  });

  test('ordinary epochs are unaffected', () => {
    expect(isEpochFresh(100, 100)).toBe(true);
    expect(isEpochFresh(99, 100)).toBe(true);
    expect(isEpochFresh(98, 100)).toBe(true);
    expect(isEpochFresh(97, 100)).toBe(false);
    // Future-dated proofs stay rejected.
    expect(isEpochFresh(101, 100)).toBe(false);
  });
});
