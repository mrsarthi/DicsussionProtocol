/**
 * Browser Barrel Parity
 *
 * `index.browser.ts` shadows `index.ts` for browser consumers. Two ways
 * that goes wrong silently:
 *
 *  1. A name exported by the Node barrel is missing from the browser one.
 *     The consumer's build fails at resolution with an error naming a
 *     symbol they never wrote, in a file they cannot see.
 *  2. A constant duplicated into the browser barrel drifts from its
 *     original — two peers then disagree about a wire constant, and the
 *     disagreement shows up as a mysterious protocol failure.
 *
 * Neither is caught by the existing browser-bundle or browser-globals
 * checks, which verify that nothing Node-only *reaches* a bundle, not that
 * what remains is complete or correct.
 */

import { expect, test } from '@playwright/test';

import * as nodeTransport from '../../packages/core/src/transport/index.js';
import * as browserTransport from '../../packages/core/src/transport/index.browser.js';
import * as nodeZk from '../../packages/core/src/zk/index.js';
import * as browserZk from '../../packages/core/src/zk/index.browser.js';

/** Value exports only — types erase and cannot be compared at runtime. */
function names(mod: object): string[] {
  return Object.keys(mod).sort();
}

test.describe('Browser barrels — export parity', () => {
  test('transport/index.browser exports every name index does', () => {
    const missing = names(nodeTransport).filter(
      (n) => !names(browserTransport).includes(n),
    );

    expect(missing, `missing from the browser transport barrel: ${missing.join(', ')}`)
      .toEqual([]);
  });

  test('zk/index.browser exports every name index does', () => {
    const missing = names(nodeZk).filter((n) => !names(browserZk).includes(n));

    expect(missing, `missing from the browser zk barrel: ${missing.join(', ')}`)
      .toEqual([]);
  });

  test('the browser barrels add nothing the Node ones lack', () => {
    // An extra export means a consumer could depend on something that
    // vanishes when their bundler picks the Node condition instead.
    const extraTransport = names(browserTransport).filter(
      (n) => !names(nodeTransport).includes(n),
    );
    const extraZk = names(browserZk).filter((n) => !names(nodeZk).includes(n));

    expect(extraTransport).toEqual([]);
    expect(extraZk).toEqual([]);
  });
});

test.describe('Browser barrels — mirrored constants', () => {
  test('transport constants match their Node originals', () => {
    // Duplicated in index.browser.ts because importing them would drag
    // node:dgram back in. This is the guard that keeps them honest.
    expect(browserTransport.MDNS_MULTICAST_ADDRESS).toBe(
      nodeTransport.MDNS_MULTICAST_ADDRESS,
    );
    expect(browserTransport.MDNS_PORT).toBe(nodeTransport.MDNS_PORT);
    expect(browserTransport.DICSUSSION_ALPN).toBe(nodeTransport.DICSUSSION_ALPN);
    expect(browserTransport.CONTROL_STREAM_TAG).toBe(
      nodeTransport.CONTROL_STREAM_TAG,
    );
    expect(browserTransport.STREAM_PRIORITY).toEqual(
      nodeTransport.STREAM_PRIORITY,
    );
  });

  test('DEV_CEREMONY_MARKER matches', () => {
    expect(browserZk.DEV_CEREMONY_MARKER).toBe(nodeZk.DEV_CEREMONY_MARKER);
  });
});

test.describe('Browser stubs — behaviour', () => {
  test('resolveArtifacts returns null rather than throwing', () => {
    // The contract DicsussionClient.init depends on. Throwing here broke
    // init() even with proofs disabled — the stub must return a value the
    // caller is designed to receive.
    expect(browserZk.resolveArtifacts()).toBeNull();
  });

  test('isDevelopmentCeremony throws instead of answering', () => {
    // Its safe-looking answer, `false`, asserts a trusted setup this build
    // cannot verify. A fabricated security guarantee is worse than an
    // error, so this one must refuse.
    expect(() => browserZk.isDevelopmentCeremony()).toThrow(/cannot be evaluated/i);
  });

  test('proving machinery throws with a cause, not a TypeError', () => {
    expect(() => new browserZk.ZekPocProver()).toThrow(/not available in browsers/i);
    expect(() => browserZk.requireArtifacts()).toThrow(/not available in browsers/i);
    expect(() => browserZk.toCircuitSignals()).toThrow(/not available in browsers/i);
  });

  test('QUIC and mDNS stubs name the alternative', () => {
    expect(() => new browserTransport.IrohTransport()).toThrow(/WebSocketTransport/);
    expect(() => new browserTransport.MdnsDiscovery()).toThrow(/ticket/i);
  });

  test('clearDatagramBuses is a safe no-op', () => {
    // Test-cleanup helpers get called from shared setup; throwing would
    // break suites that never touch datagrams.
    expect(() => browserTransport.clearDatagramBuses()).not.toThrow();
  });
});
