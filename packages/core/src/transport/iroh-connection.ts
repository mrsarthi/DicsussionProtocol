/**
 * @dicsussion/transport — Iroh QUIC Connection
 *
 * Maps RFC 001 §6's six sub-streams onto six long-lived bidirectional
 * QUIC streams, one per stream type.
 *
 * WHY SIX STREAMS RATHER THAN ONE: a single multiplexed stream would
 * reintroduce head-of-line blocking — a large `0x01` CRDT delta would
 * stall the `0x03` revocation gossip queued behind it. Revocations exist
 * to outrun the traffic they revoke, so they get their own stream with
 * QUIC-native priority.
 *
 * Each stream opens with a one-byte type tag so the accepting side knows
 * what it received. Relying on open *order* would be fragile: QUIC does
 * not guarantee accept order matches open order.
 */

import { Emitter } from './emitter.js';

import { decompressPayload, maybeCompress } from './compression.js';
import { encodeFrame } from './frame-codec.js';
import { FrameReader } from './frame-reader.js';
import type { FrameHandler, IConnection } from './transport-interface.js';
import type { Frame, StreamTypeValue } from './types.js';
import {
  ConnectionState,
  FrameFlags,
  StreamType,
  VALID_STREAM_TYPES,
} from './types.js';

/** Tag written first on the handshake/control stream. */
export const CONTROL_STREAM_TAG = 0x00;

/**
 * QUIC send priority per sub-stream (higher wins).
 *
 * Mirrors the userspace banding in `priority-queue.ts` so both transports
 * satisfy the same RFC 001 §6 guarantee.
 */
export const STREAM_PRIORITY: Record<number, number> = {
  [StreamType.REVOCATION_GOSSIP]: 100,
  [StreamType.RLN_SHARE_EXCHANGE]: 60,
  [StreamType.VOUCHER_HANDSHAKE]: 50,
  [StreamType.CRDT_SYNC]: 40,
  [StreamType.RLN_SIGNAL]: 30,
  [StreamType.E2EE_MESSAGE]: 20,
};

/** Bytes requested per read. Frames are reassembled, so this is a hint. */
const READ_CHUNK = 64 * 1024;

/** Minimal shape of the Iroh objects used here, to keep them contained. */
export interface IrohSendStream {
  writeAll(buf: Array<number>): Promise<void>;
  setPriority(p: number): Promise<void>;
  finish(): Promise<void>;
}

export interface IrohRecvStream {
  read(sizeLimit: number): Promise<Array<number>>;
  readExact(size: number): Promise<Array<number>>;
}

export interface IrohBiStream {
  readonly send: IrohSendStream;
  readonly recv: IrohRecvStream;
}

export interface IrohConnectionHandle {
  openBi(): Promise<IrohBiStream>;
  acceptBi(): Promise<IrohBiStream>;
  close(errorCode: bigint, reason: Array<number>): void;
  closed(): Promise<string>;
  paths(): Array<{ isRelay?: boolean; rttMs?: number }>;
}

/** One sub-stream and its reassembly buffer. */
interface SubStream {
  readonly send: IrohSendStream;
  readonly reader: FrameReader;
}

/**
 * A live QUIC connection to one peer.
 */
export class IrohConnection implements IConnection {
  private readonly frameEmitter = new Emitter<{ frame: [Frame] }>();
  private readonly streams = new Map<number, SubStream>();
  private _state: ConnectionState = ConnectionState.Active;

  constructor(
    public readonly peerDid: string,
    public readonly clockOffset: number,
    private readonly connection: IrohConnectionHandle,
  ) {
    // 64 sub-stream readers plus application handlers; the default of 10
    // would warn spuriously.
    this.frameEmitter.setMaxListeners(64);
  }

  get state(): ConnectionState {
    return this._state;
  }

  /** Whether the current path is relayed rather than direct. */
  get isRelayed(): boolean {
    return this.connection.paths().some((path) => path.isRelay === true);
  }

  /** Round-trip time in milliseconds, when known. */
  get rttMs(): number | undefined {
    return this.connection.paths()[0]?.rttMs;
  }

  /**
   * Register a sub-stream and begin reading it.
   *
   * @param streamType Which sub-stream this carries.
   * @param stream The bidirectional QUIC stream.
   */
  async registerStream(
    streamType: StreamTypeValue,
    stream: IrohBiStream,
  ): Promise<void> {
    await stream.send.setPriority(STREAM_PRIORITY[streamType] ?? 10);

    this.streams.set(streamType, { send: stream.send, reader: new FrameReader() });
    void this.readLoop(streamType, stream.recv);
  }

  /**
   * Send a payload on a sub-stream.
   *
   * Priority is enforced by QUIC via `setPriority`, so no userspace
   * queue is needed here (unlike `LocalTransport`).
   */
  async send(
    streamType: StreamTypeValue,
    payload: Uint8Array,
    flags = 0,
  ): Promise<void> {
    if (this._state !== ConnectionState.Active) {
      throw new Error(`Cannot send on a ${this._state} connection`);
    }

    const stream = this.streams.get(streamType);
    if (!stream) {
      throw new Error(`Sub-stream 0x${streamType.toString(16)} is not open`);
    }

    // Compress before framing, so the CRC covers what is actually sent.
    // Encrypted payloads do not compress, so `maybeCompress` leaves them
    // alone rather than paying CPU to grow them.
    const { payload: body, compressed } = maybeCompress(payload);
    const frameFlags = compressed ? flags | FrameFlags.COMPRESSED : flags;

    // The bindings take Array<number>; this conversion is the dominant
    // per-frame cost on the send path (~0.05 ms/KB — see the plan §5).
    await stream.send.writeAll(Array.from(encodeFrame(streamType, body, frameFlags)));
  }

  onFrame(handler: FrameHandler): () => void {
    const wrapped = (frame: Frame) => handler(frame, this);
    this.frameEmitter.on('frame', wrapped);

    return () => {
      this.frameEmitter.off('frame', wrapped);
    };
  }

  async close(): Promise<void> {
    if (this._state === ConnectionState.Disconnected) return;

    this._state = ConnectionState.Disconnected;
    this.streams.clear();
    this.frameEmitter.removeAllListeners();

    try {
      this.connection.close(0n, []);
    } catch {
      // Already closed by the peer — nothing to do.
    }
  }

  /**
   * Continuously read one sub-stream, emitting reassembled frames.
   *
   * A read error ends this stream only. Tearing down the whole
   * connection because one sub-stream ended would take chat down with a
   * finished sync stream.
   */
  private async readLoop(
    streamType: StreamTypeValue,
    recv: IrohRecvStream,
  ): Promise<void> {
    const stream = this.streams.get(streamType);
    if (!stream) return;

    while (this._state === ConnectionState.Active) {
      let chunk: Array<number>;

      try {
        chunk = await recv.read(READ_CHUNK);
      } catch {
        return;
      }

      // Empty read means the peer finished the stream.
      if (!chunk || chunk.length === 0) return;

      let frames: Frame[];
      try {
        frames = stream.reader.push(Uint8Array.from(chunk));
      } catch {
        // A malformed or corrupted frame poisons this stream's framing,
        // so the buffer is reset rather than left desynchronised.
        stream.reader.reset();
        continue;
      }

      for (const frame of frames) {
        this.frameEmitter.emit('frame', inflate(frame));
      }
    }
  }
}

/**
 * Decompress a frame's payload when the COMPRESSED flag is set.
 *
 * A decompression failure drops the frame rather than tearing down the
 * stream — the same treatment a corrupted frame gets.
 */
function inflate(frame: Frame): Frame {
  if ((frame.header.flags & FrameFlags.COMPRESSED) === 0) return frame;

  return { ...frame, payload: decompressPayload(frame.payload) };
}

/**
 * Read the one-byte type tag that opens every sub-stream.
 *
 * @returns The stream type, or undefined if the tag is not recognised.
 */
export async function readStreamTag(
  recv: IrohRecvStream,
): Promise<number | undefined> {
  const tag = await recv.readExact(1);
  const value = tag[0];

  if (value === undefined) return undefined;
  if (value === CONTROL_STREAM_TAG) return CONTROL_STREAM_TAG;

  return VALID_STREAM_TYPES.has(value) ? value : undefined;
}
