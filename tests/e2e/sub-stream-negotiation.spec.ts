/**
 * How many sub-streams a responder waits for.
 *
 * The responder opens no streams of its own; it accepts as many as the
 * initiator said it would open. Getting that number wrong is not a
 * visible failure — `acceptBi()` has no timeout, so waiting for a stream
 * that is never opened parks the responder forever, the connection is
 * never surfaced to any handler, and the initiator meanwhile completes
 * its handshake and believes it is connected. Messages then vanish with
 * no error on either side.
 */

import { expect, test } from '@playwright/test';

import {
  LEGACY_SUB_STREAM_COUNT,
  SUB_STREAMS,
} from '../../packages/core/src/transport/iroh-transport.js';
import { StreamType } from '../../packages/core/src/transport/types.js';

test.describe('Sub-stream negotiation', () => {
  test('every declared stream type is opened', () => {
    // The list used to be maintained by hand, and a type declared but
    // left out of it throws "sub-stream is not open" on first use —
    // over real QUIC only, since in-process transport opens on demand.
    expect([...SUB_STREAMS].sort()).toEqual(
      [...Object.values(StreamType)].sort(),
    );
  });

  test('the legacy count describes peers already built, not this build', () => {
    // Six stream types existed when `subStreams` was introduced, and a
    // peer from before then announces nothing. Tracking this to the
    // current count instead would make the responder wait for streams
    // such a peer never opens — the silent hang described above.
    expect(LEGACY_SUB_STREAM_COUNT).toBe(6);
    expect(SUB_STREAMS.length).toBeGreaterThanOrEqual(LEGACY_SUB_STREAM_COUNT);
  });

  test('stream types are only ever appended', () => {
    // A peer announcing the legacy count opens the six types it knew.
    // Renumbering an existing type would leave both sides holding the
    // same tag for different sub-protocols.
    expect(StreamType.CRDT_SYNC).toBe(0x01);
    expect(StreamType.E2EE_MESSAGE).toBe(0x02);
    expect(StreamType.REVOCATION_GOSSIP).toBe(0x03);
    expect(StreamType.VOUCHER_HANDSHAKE).toBe(0x04);
    expect(StreamType.RLN_SIGNAL).toBe(0x05);
    expect(StreamType.RLN_SHARE_EXCHANGE).toBe(0x06);
    expect(StreamType.EPHEMERAL).toBe(0x07);
  });
});
