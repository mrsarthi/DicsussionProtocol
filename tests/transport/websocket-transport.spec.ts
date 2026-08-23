/**
 * Browser transport over a WebSocket relay.
 *
 * The relay below is a complete, minimal implementation of the envelope
 * protocol in `relay-protocol.ts` — it is test infrastructure, but it is
 * also the reference for anyone writing a real one.
 *
 * The tests that matter most are the hostile-relay ones. A relay is an
 * untrusted third party that sees every byte and chooses how to route
 * it, so "a relay cannot impersonate a peer" is a claim that has to be
 * demonstrated, not asserted.
 */

import { expect, test } from '@playwright/test';

import { generateKeypair, publicKeyToDidKey } from '../../packages/core/src/transport/did-key.js';
import type { Ed25519KeyPair } from '../../packages/core/src/transport/did-key.js';
import {
  decodeRelayMessage,
  encodeRelayMessage,
  RelayMessageType,
} from '../../packages/core/src/transport/relay-protocol.js';
import { WebSocketTransport } from '../../packages/core/src/transport/websocket-transport.js';
import type { WebSocketLike } from '../../packages/core/src/transport/websocket-transport.js';
import { StreamType } from '../../packages/core/src/transport/types.js';
import { IDBFactory } from 'fake-indexeddb';
import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import { IndexedDbDriver } from '../../packages/HLessEnd/src/storage/indexeddb-driver.js';
import type { IndexedDbFactoryLike } from '../../packages/HLessEnd/src/storage/indexeddb-driver.js';
import type { PeerTicket } from '../../packages/core/src/transport/types.js';

/** An in-process relay speaking the envelope protocol. */
class TestRelay {
  private readonly sockets = new Map<string, FakeSocket>();
  /** Set when the relay should mislabel a session, to model a liar. */
  misroute: { from: string; claimAs: string } | null = null;

  /** Hand out a socket endpoint for a client to hold. */
  createSocket(): WebSocketLike {
    const socket = new FakeSocket((bytes) => this.receive(socket, bytes));
    queueMicrotask(() => socket.open());
    return socket;
  }

  private receive(socket: FakeSocket, bytes: Uint8Array): void {
    const message = decodeRelayMessage(bytes);

    switch (message.type) {
      case RelayMessageType.REGISTER:
        socket.did = message.did;
        this.sockets.set(message.did, socket);
        break;

      case RelayMessageType.DIAL: {
        const target = this.sockets.get(message.did);
        if (!target) {
          socket.deliver(
            encodeRelayMessage({
              type: RelayMessageType.CLOSED,
              did: message.did,
              payload: new Uint8Array(0),
            }),
          );
          return;
        }

        // Dialer learns the session is up; target learns who called.
        socket.deliver(
          encodeRelayMessage({
            type: RelayMessageType.OPENED,
            did: message.did,
            payload: new Uint8Array(0),
          }),
        );
        target.deliver(
          encodeRelayMessage({
            type: RelayMessageType.OPENED,
            did: this.labelFor(socket.did!),
            payload: new Uint8Array(0),
          }),
        );
        break;
      }

      case RelayMessageType.DATA:
      case RelayMessageType.CLOSED: {
        const target = this.sockets.get(message.did);
        target?.deliver(
          encodeRelayMessage({
            type: message.type,
            did: this.labelFor(socket.did!),
            payload: message.payload,
          }),
        );
        break;
      }

      default:
        break;
    }
  }

  /** Apply the misrouting rule, if one is set. */
  private labelFor(did: string): string {
    return this.misroute && this.misroute.from === did
      ? this.misroute.claimAs
      : did;
  }
}

/** A WebSocket endpoint wired straight to the relay. */
class FakeSocket implements WebSocketLike {
  binaryType = 'arraybuffer';
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: ((error: unknown) => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;

  did: string | null = null;
  private closed = false;

  constructor(private readonly toRelay: (bytes: Uint8Array) => void) {}

  open(): void {
    this.onopen?.();
  }

  send(data: ArrayBufferView | ArrayBuffer): void {
    if (this.closed) return;

    const bytes =
      data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

    // Copy before handing over: the caller may reuse its buffer.
    queueMicrotask(() => this.toRelay(new Uint8Array(bytes)));
  }

  deliver(bytes: Uint8Array): void {
    if (this.closed) return;
    queueMicrotask(() => this.onmessage?.({ data: bytes }));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    queueMicrotask(() => this.onclose?.());
  }
}

function ticketFor(identity: Ed25519KeyPair): PeerTicket {
  return {
    didKey: publicKeyToDidKey(identity.publicKey),
    nodeId: identity.publicKey,
    directAddresses: [],
  };
}

/** Build two transports sharing one relay. */
function pair(relay = new TestRelay()) {
  const aliceKeys = generateKeypair();
  const bobKeys = generateKeypair();

  const make = (identity: Ed25519KeyPair) =>
    new WebSocketTransport({
      relayUrl: 'wss://relay.test',
      identity,
      createSocket: () => relay.createSocket(),
      timeoutMs: 3_000,
    });

  return {
    relay,
    aliceKeys,
    bobKeys,
    alice: make(aliceKeys),
    bob: make(bobKeys),
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 3_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 5));
  }
  return predicate();
}

test.describe('Transport — WebSocket Relay', () => {
  test('two peers complete the handshake and exchange a frame', async () => {
    const { alice, bob, aliceKeys, bobKeys } = pair();

    try {
      await bob.start();

      const accepted: string[] = [];
      bob.onConnection((connection) => {
        accepted.push(connection.peerDid);
        connection.onFrame((frame) => {
          received.push(new TextDecoder().decode(frame.payload));
        });
      });
      const received: string[] = [];

      const connection = await alice.connect(ticketFor(bobKeys));
      expect(connection.peerDid).toBe(publicKeyToDidKey(bobKeys.publicKey));

      expect(await waitFor(() => accepted.length === 1)).toBe(true);
      expect(accepted[0]).toBe(publicKeyToDidKey(aliceKeys.publicKey));

      await connection.send(
        StreamType.E2EE_MESSAGE,
        new TextEncoder().encode('through the relay'),
      );

      expect(await waitFor(() => received.length === 1)).toBe(true);
      expect(received[0]).toBe('through the relay');
    } finally {
      await alice.close();
      await bob.close();
    }
  });

  test('frames flow in both directions', async () => {
    const { alice, bob, bobKeys, aliceKeys } = pair();

    try {
      await bob.start();

      const atAlice: string[] = [];
      const atBob: string[] = [];

      bob.onConnection((connection) => {
        connection.onFrame((frame) =>
          atBob.push(new TextDecoder().decode(frame.payload)),
        );
        void connection.send(
          StreamType.E2EE_MESSAGE,
          new TextEncoder().encode('reply'),
        );
      });

      const connection = await alice.connect(ticketFor(bobKeys));
      connection.onFrame((frame) =>
        atAlice.push(new TextDecoder().decode(frame.payload)),
      );

      await connection.send(
        StreamType.E2EE_MESSAGE,
        new TextEncoder().encode('hello'),
      );

      expect(await waitFor(() => atBob.length === 1 && atAlice.length === 1)).toBe(
        true,
      );
      expect(atBob[0]).toBe('hello');
      expect(atAlice[0]).toBe('reply');
      expect(publicKeyToDidKey(aliceKeys.publicKey)).toBeTruthy();
    } finally {
      await alice.close();
      await bob.close();
    }
  });

  test('dialling an unregistered peer fails rather than hanging', async () => {
    const { alice, bobKeys } = pair();

    try {
      // Bob never started, so the relay has no socket for him.
      await expect(alice.connect(ticketFor(bobKeys))).rejects.toThrow(
        /refused a session/,
      );
    } finally {
      await alice.close();
    }
  });

  test('a relay that mislabels a session cannot make it stick', async () => {
    // The relay chooses the label on every session, so it can present
    // Alice's handshake as coming from someone else. The accepter binds
    // the label to the did:key inside the signed init and refuses.
    const relay = new TestRelay();
    const { alice, bob, aliceKeys, bobKeys } = pair(relay);

    try {
      await bob.start();

      const accepted: string[] = [];
      bob.onConnection((c) => accepted.push(c.peerDid));

      relay.misroute = {
        from: publicKeyToDidKey(aliceKeys.publicKey),
        claimAs: 'did:key:z6MkImpersonatedVictimIdentifier',
      };

      await alice.connect(ticketFor(bobKeys)).catch(() => undefined);

      // Give the rejected handshake time to have gone wrong.
      await new Promise((r) => setTimeout(r, 300));
      expect(accepted).toHaveLength(0);
    } finally {
      await alice.close();
      await bob.close();
    }
  });

  test('a peer presenting the wrong identity key is rejected', async () => {
    // The ticket says Bob, but the relay routes to a third party. The
    // challenge is signed with the wrong Ed25519 key, so verification
    // fails and no session is established.
    const { alice, bob } = pair();
    const impostorKeys = generateKeypair();

    try {
      await bob.start();

      await expect(
        alice.connect({
          didKey: bob.didKey,
          // Wrong public half for that did:key.
          nodeId: impostorKeys.publicKey,
          directAddresses: [],
        }),
      ).rejects.toThrow(/failed challenge verification/);
    } finally {
      await alice.close();
      await bob.close();
    }
  });

  test('a closed transport stops delivering frames', async () => {
    const { alice, bob, bobKeys } = pair();

    await bob.start();

    const received: string[] = [];
    bob.onConnection((c) =>
      c.onFrame((f) => received.push(new TextDecoder().decode(f.payload))),
    );

    const connection = await alice.connect(ticketFor(bobKeys));
    await bob.close();

    await connection
      .send(StreamType.E2EE_MESSAGE, new TextEncoder().encode('after close'))
      .catch(() => undefined);

    await new Promise((r) => setTimeout(r, 200));
    expect(received).toHaveLength(0);

    await alice.close();
  });
});

test.describe('Transport — Relay Envelope Codec', () => {
  test('an envelope round-trips', () => {
    const message = {
      type: RelayMessageType.DATA,
      did: 'did:key:z6MkExample',
      payload: new Uint8Array([1, 2, 3, 250]),
    };

    const decoded = decodeRelayMessage(encodeRelayMessage(message));

    expect(decoded.type).toBe(message.type);
    expect(decoded.did).toBe(message.did);
    expect(Array.from(decoded.payload)).toEqual([1, 2, 3, 250]);
  });

  test('control messages carry an empty payload', () => {
    const decoded = decodeRelayMessage(
      encodeRelayMessage({
        type: RelayMessageType.REGISTER,
        did: 'did:key:z6MkExample',
        payload: new Uint8Array(0),
      }),
    );

    expect(decoded.payload).toHaveLength(0);
  });

  test('a truncated envelope is rejected, not guessed at', () => {
    const full = encodeRelayMessage({
      type: RelayMessageType.DATA,
      did: 'did:key:z6MkExample',
      payload: new Uint8Array([9]),
    });

    expect(() => decodeRelayMessage(full.subarray(0, 2))).toThrow(
      /shorter than its 3-byte header/,
    );
    expect(() => decodeRelayMessage(full.subarray(0, 6))).toThrow(
      /truncated inside its did:key/,
    );
  });

  test('an unknown message type is rejected', () => {
    const bytes = encodeRelayMessage({
      type: RelayMessageType.DATA,
      did: 'did:key:zA',
      payload: new Uint8Array(0),
    });
    bytes[0] = 0x7f;

    expect(() => decodeRelayMessage(bytes)).toThrow(/Unknown relay message type/);
  });

  test('a did:key length beyond the buffer is refused', () => {
    // A hostile relay controls this field; using it to size an
    // allocation without a bound is how a decoder becomes a DoS.
    const bytes = new Uint8Array(8);
    bytes[0] = RelayMessageType.DATA;
    bytes[1] = 0xff;
    bytes[2] = 0xff;

    expect(() => decodeRelayMessage(bytes)).toThrow(/claims a \d+-byte did:key/);
  });

  test('invalid UTF-8 in the did is rejected', () => {
    const bytes = new Uint8Array([RelayMessageType.DATA, 0x00, 0x02, 0xff, 0xfe]);

    expect(() => decodeRelayMessage(bytes)).toThrow(/not valid UTF-8/);
  });
});

test.describe('Transport — Full Client over the Relay', () => {
  test('two clients exchange an encrypted message through a relay', async () => {
    // The browser-shaped configuration end to end: IndexedDB for
    // storage, a relay for transport, and no native module anywhere on
    // the path.
    const relay = new TestRelay();

    const make = async () =>
      DicsussionClient.init(
        { storagePath: 'unused', allowUnencryptedStorage: true },
        {
          storage: new IndexedDbDriver({
            factory: new IDBFactory() as unknown as IndexedDbFactoryLike,
          }),
          transport: 'websocket',
          relayUrl: 'wss://relay.test',
          createSocket: () => relay.createSocket(),
        },
      );

    const alice = await make();
    const bob = await make();

    try {
      alice.addPeer(bob.did, bob.encryptionPublicKey);
      bob.addPeer(alice.did, alice.encryptionPublicKey);
  for (const channel of ['general']) {
    alice.chat.createChannel(channel, [bob.did]);
  }
  for (const channel of ['general']) {
    bob.chat.createChannel(channel, [alice.did]);
  }

      const received: string[] = [];
      bob.chat.onMessage('general', (m) => received.push(m.content));

      await alice.connect(bob.getTicket());
      expect(await waitFor(() => bob.getNetworkStatus().peerCount === 1)).toBe(
        true,
      );

      await alice.chat.sendMessage({
        channelId: 'general',
        content: 'browser to browser',
      });

      expect(await waitFor(() => received.length === 1)).toBe(true);
      expect(received[0]).toBe('browser to browser');
    } finally {
      await alice.disconnect();
      await bob.disconnect();
    }
  });

  test('the websocket backend refuses to start without a relay', async () => {
    // Failing loudly beats falling back to a transport a browser cannot
    // run, which would surface much later as "no peers ever connect".
    await expect(
      DicsussionClient.init(
        { storagePath: ':memory:' },
        { transport: 'websocket' },
      ),
    ).rejects.toThrow(/needs a relayUrl/);
  });
});
