/**
 * @dicsussion/transport — Iroh QUIC Transport
 *
 * Real networking backend: binds an Iroh endpoint, dials peers, and
 * accepts inbound connections over QUIC with NAT traversal and relay
 * fallback handled by Iroh itself (RFC 001 §4.2).
 *
 * TWO IDENTITIES, DELIBERATELY. Iroh authenticates the *transport* key
 * during its TLS handshake. That proves who owns the endpoint, but not
 * who owns the `did:key` the rest of the protocol is built on — the
 * transport key is derived from the identity key, and a verifier cannot
 * check that derivation without the secret. Our RFC 001 §5 handshake
 * therefore still runs, over the already-authenticated channel, to prove
 * `did:key` ownership and negotiate the clock offset epochs depend on.
 *
 * Iroh types are confined to this file and `iroh-connection.ts`; nothing
 * else in the codebase imports `@number0/iroh`.
 */

import type { Ed25519KeyPair } from './did-key.js';
import { didKeyToPublicKey, publicKeyToDidKey } from './did-key.js';
import {
  calculateClockOffset,
  createHandshakeAck,
  createHandshakeInit,
  deriveSessionKey,
  HandshakeTag,
  transcriptFor,
  NonceRegistry,
  processHandshakeInit,
  verifyHandshakeAck,
  verifyHandshakeChallenge,
} from './handshake.js';
import { decodeControlJson, encodeControlJson } from './json-bytes.js';
import type { IrohBiStream, IrohConnectionHandle } from './iroh-connection.js';
import {
  CONTROL_STREAM_TAG,
  IrohConnection,
  readStreamTag,
} from './iroh-connection.js';
import { deriveTransportKey } from './transport-key.js';
import type {
  ConnectionHandler,
  IConnection,
  ITransport,
} from './transport-interface.js';
import type {
  HandshakeAck,
  HandshakeChallenge,
  HandshakeInit,
  PeerTicket,
  StreamTypeValue,
} from './types.js';
import { StreamType } from './types.js';

/** Responder's challenge plus the timestamp the dialer needs for clock sync. */
interface ChallengeMessage {
  readonly challenge: HandshakeChallenge;
  readonly timestamp: number;
}

/** ALPN identifying this protocol during the QUIC handshake. */
export const DICSUSSION_ALPN = 'dicsussion/1';

/**
 * Sub-streams opened on every connection, in RFC 001 §6 order.
 *
 * Taken from `StreamType` rather than listed by hand: a type declared but
 * missing here is never opened, and `send` then throws "sub-stream is not
 * open" the first time anything tries to use it — at runtime, over real
 * QUIC only, since the in-process transport opens streams on demand.
 */
export const SUB_STREAMS: StreamTypeValue[] = Object.values(StreamType);

/**
 * Sub-streams opened by peers predating `HandshakeInit.subStreams`.
 *
 * Those peers opened the six types defined at the time and announced
 * nothing, so a missing count means exactly six. Never change this: it
 * describes software already built, not what this version does.
 */
export const LEGACY_SUB_STREAM_COUNT = 6;

export interface IrohTransportOptions {
  /** This node's identity keypair; the transport key is derived from it. */
  readonly identity: Ed25519KeyPair;
  /** Bind address, e.g. `0.0.0.0:0`. Defaults to an ephemeral port. */
  readonly bindAddr?: string;
  /**
   * Disable relays and discovery — a fully local endpoint.
   *
   * Set for tests, so a "local" run cannot silently traverse the real
   * network.
   */
  readonly localOnly?: boolean;
}

/** The subset of the Iroh module this transport uses. */
export interface IrohModule {
  Endpoint: {
    builder(): {
      alpns(alpns: Array<Array<number>>): void;
      secretKey(bytes: Array<number>): void;
      bindAddr(addr: string): void;
      relayMode(mode: unknown): void;
      bind(): Promise<IrohEndpoint>;
    };
  };
  RelayMode: { disabled(): unknown; defaultMode(): unknown };
  EndpointAddr: new (
    id: unknown,
    relayUrl?: string | null,
    addresses?: Array<string> | null,
  ) => unknown;
  EndpointId: { fromBytes(bytes: Array<number>): unknown };
  presetMinimal(builder: unknown): void;
  presetN0(builder: unknown): void;
}

interface IrohEndpoint {
  addr(): { directAddresses(): Array<string>; relayUrl(): string | null };
  boundSockets(): Array<string>;
  connect(addr: unknown, alpn: Array<number>): Promise<IrohConnectionHandle>;
  acceptNext(): Promise<IrohIncoming | null>;
  close(): Promise<void>;
}

interface IrohIncoming {
  accept(): Promise<{ connect(): Promise<IrohConnectionHandle> }>;
}

/**
 * QUIC transport backed by Iroh.
 *
 * Construct via {@link IrohTransport.create}, which loads the native
 * bindings lazily so importing this module never forces the dependency.
 */
export class IrohTransport implements ITransport {
  /** Replay tracker scoped to this transport, not shared across instances. */
  private readonly nonces = new NonceRegistry();

  private readonly handlers: ConnectionHandler[] = [];
  private readonly connections = new Set<IrohConnection>();
  private accepting = true;

  private constructor(
    private readonly endpoint: IrohEndpoint,
    private readonly iroh: IrohModule,
    private readonly identity: Ed25519KeyPair,
    public readonly didKey: string,
  ) {
    void this.acceptLoop();
  }

  /**
   * Bind an endpoint and start accepting connections.
   *
   * @param options Identity and binding configuration.
   */
  static async create(options: IrohTransportOptions): Promise<IrohTransport> {
    const iroh = (await import('@number0/iroh')) as unknown as IrohModule;
    const transportKey = deriveTransportKey(options.identity);

    const builder = iroh.Endpoint.builder();
    if (options.localOnly) {
      iroh.presetMinimal(builder);
      builder.relayMode(iroh.RelayMode.disabled());
    } else {
      iroh.presetN0(builder);
    }

    builder.alpns([Array.from(new TextEncoder().encode(DICSUSSION_ALPN))]);
    builder.secretKey(Array.from(transportKey.secretKey));
    builder.bindAddr(options.bindAddr ?? '0.0.0.0:0');

    const endpoint = await builder.bind();

    return new IrohTransport(
      endpoint,
      iroh,
      options.identity,
      publicKeyToDidKey(options.identity.publicKey),
    );
  }

  /** A ticket other peers can dial. */
  getTicket(): PeerTicket {
    const addr = this.endpoint.addr();

    return {
      didKey: this.didKey,
      nodeId: this.identity.publicKey,
      directAddresses: addr.directAddresses(),
      derpRelay: addr.relayUrl() ?? undefined,
      transportKey: deriveTransportKey(this.identity).publicKey,
    };
  }

  /** Socket addresses this endpoint is bound to. */
  boundSockets(): string[] {
    return this.endpoint.boundSockets();
  }

  async connect(ticket: PeerTicket): Promise<IConnection> {
    if (!ticket.transportKey) {
      throw new Error(
        `Ticket for ${ticket.didKey} has no transportKey; cannot derive an Iroh EndpointId`,
      );
    }

    const addr = new this.iroh.EndpointAddr(
      this.iroh.EndpointId.fromBytes(Array.from(ticket.transportKey)),
      ticket.derpRelay ?? null,
      [...ticket.directAddresses],
    );

    const handle = await this.endpoint.connect(
      addr,
      Array.from(new TextEncoder().encode(DICSUSSION_ALPN)),
    );

    return this.setUpDialer(handle, ticket);
  }

  onConnection(handler: ConnectionHandler): () => void {
    this.handlers.push(handler);

    return () => {
      const index = this.handlers.indexOf(handler);
      if (index >= 0) this.handlers.splice(index, 1);
    };
  }

  async close(): Promise<void> {
    this.accepting = false;

    await Promise.all(Array.from(this.connections, (c) => c.close()));
    this.connections.clear();
    this.handlers.length = 0;

    await this.endpoint.close();
  }

  /**
   * Dialer side: run the RFC 001 §5 handshake, then open every sub-stream.
   *
   * Three messages: Init → Challenge → Ack. The challenge proves the
   * responder controls the `did:key` in the ticket (Iroh only proved it
   * controls the *transport* key), and carries the responder's timestamp
   * so both sides derive the same clock offset.
   */
  private async setUpDialer(
    handle: IrohConnectionHandle,
    ticket: PeerTicket,
  ): Promise<IrohConnection> {
    const control = await handle.openBi();
    await control.send.writeAll([CONTROL_STREAM_TAG]);

    const { init, ephemeralSecret } = createHandshakeInit(
      this.identity,
      this.didKey,
    );

    // Announced here rather than in `createHandshakeInit`, because
    // opening a stream per type is how this transport works and not how
    // the bridged one does.
    await writeJson(control, { ...init, subStreams: SUB_STREAMS.length });

    const { challenge, timestamp } = await readJson<ChallengeMessage>(control);

    // The ticket's nodeId is the did:key public half. Verifying the
    // challenge against it is what binds this QUIC connection to the
    // identity the rest of the protocol trusts — and the transcript it
    // signs covers both ephemeral keys, so the session key cannot be
    // substituted by anyone on the path.
    const context = {
      initiatorDid: this.didKey,
      responderDid: ticket.didKey,
      initiatorNonce: init.nonce,
      responderNonce: challenge.nonce,
      initiatorEphemeral: init.ephemeralKey,
      responderEphemeral: challenge.ephemeralKey,
    };

    if (!verifyHandshakeChallenge(challenge, ticket.nodeId, context)) {
      handle.close(1n, []);
      ephemeralSecret.fill(0);
      throw new Error(`Handshake with ${ticket.didKey} failed challenge verification`);
    }

    await writeJson(control, createHandshakeAck(this.identity, context));

    const sessionKey = deriveSessionKey(
      ephemeralSecret,
      challenge.ephemeralKey,
      transcriptFor(HandshakeTag.ACK, context),
    );
    ephemeralSecret.fill(0);

    const connection = new IrohConnection(
      ticket.didKey,
      calculateClockOffset(timestamp, init.timestamp),
      handle,
      sessionKey,
    );

    for (const streamType of SUB_STREAMS) {
      const stream = await handle.openBi();
      await stream.send.writeAll([streamType]);
      await connection.registerStream(streamType, stream);
    }

    this.track(connection);
    return connection;
  }

  /** Accepter side: answer the handshake, then adopt every sub-stream. */
  private async setUpAccepter(handle: IrohConnectionHandle): Promise<void> {
    const control = await handle.acceptBi();
    if ((await readStreamTag(control.recv)) !== CONTROL_STREAM_TAG) {
      handle.close(1n, []);
      return;
    }

    const init = await readJson<HandshakeInit>(control);

    // Throws on clock skew, replayed nonce, or an expired nonce.
    const localTimestamp = Math.floor(Date.now() / 1000);
    const { challenge, clockOffset, sessionKey } = processHandshakeInit(
      init,
      this.identity,
      localTimestamp,
      this.nonces,
    );

    await writeJson(control, { challenge, timestamp: localTimestamp });

    const ack = await readJson<HandshakeAck>(control);
    const context = {
      initiatorDid: init.didKey,
      responderDid: this.didKey,
      initiatorNonce: init.nonce,
      responderNonce: challenge.nonce,
      initiatorEphemeral: init.ephemeralKey,
      responderEphemeral: challenge.ephemeralKey,
    };

    if (!verifyHandshakeAck(ack, didKeyToPublicKey(init.didKey), context)) {
      handle.close(1n, []);
      return;
    }

    const connection = new IrohConnection(
      init.didKey,
      clockOffset,
      handle,
      sessionKey,
    );

    // How many the initiator said it would open — not how many this
    // build knows about. Waiting for a stream an older peer never opens
    // would hang here forever, and the initiator would meanwhile believe
    // the connection succeeded.
    const expected = init.subStreams ?? LEGACY_SUB_STREAM_COUNT;

    // Streams may be accepted in any order, so each is identified by its
    // tag rather than by position. A tag this build does not recognise is
    // still adopted: RFC 001 §7 makes unknown stream types ignorable, not
    // fatal, and that is what lets a newer peer talk to this one.
    for (let i = 0; i < expected; i++) {
      const stream = await handle.acceptBi();
      const tag = await readStreamTag(stream.recv);
      if (tag === undefined || tag === CONTROL_STREAM_TAG) continue;

      await connection.registerStream(tag as StreamTypeValue, stream);
    }

    this.track(connection);
    for (const handler of this.handlers) handler(connection);
  }

  /** Pump inbound connections into the push-based handler API. */
  private async acceptLoop(): Promise<void> {
    while (this.accepting) {
      try {
        const incoming = await this.endpoint.acceptNext();
        if (!incoming) return;

        const accepting = await incoming.accept();
        const handle = await accepting.connect();

        // One bad peer must not stop the accept loop.
        void this.setUpAccepter(handle).catch(() => undefined);
      } catch {
        if (!this.accepting) return;
      }
    }
  }

  private track(connection: IrohConnection): void {
    this.connections.add(connection);
    void connection.close;
  }
}

/** Write a length-prefixed JSON message on a control stream. */
async function writeJson(stream: IrohBiStream, value: unknown): Promise<void> {
  const body = encodeControlJson(value);
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, body.length, false);

  await stream.send.writeAll(Array.from(header));
  await stream.send.writeAll(Array.from(body));
}

/** Read a length-prefixed JSON message from a control stream. */
async function readJson<T>(stream: IrohBiStream): Promise<T> {
  const header = await stream.recv.readExact(4);
  const length = new DataView(Uint8Array.from(header).buffer).getUint32(0, false);

  if (length > 64 * 1024) {
    throw new Error(`Control message claims ${length} bytes, over the limit`);
  }

  const body = await stream.recv.readExact(length);
  return decodeControlJson<T>(Uint8Array.from(body));
}


