/**
 * Content-addressed blobs — images and files (Stream `0x09`).
 *
 * Bytes travel on their own stream rather than inside the message that
 * references them. Base64 in a message body is the only alternative an
 * application has, and it is about a third larger than the file, enters
 * the CRDT permanently, loads whole into memory on both sides, and
 * cannot be deleted afterwards. A handful of phone photos would outweigh
 * every sentence in a conversation, forever.
 *
 * A blob is named by the hash of its content, which decides three things
 * at once: the same file sent twice is stored once, a recipient can tell
 * whether what arrived is what was sent, and a reference stays valid no
 * matter who it is fetched from.
 *
 * ### Settled here rather than left to the application
 *
 * - **Resumption.** A transfer records how much it has, and a later
 *   request resumes from that offset. A 10MB send over a flaky link that
 *   dies at 90% does not start again.
 * - **A cap**, with a named error rather than a rejected send the app
 *   cannot explain to anyone.
 * - **No garbage collection.** Blobs outlive the messages that reference
 *   them until `delete()` is called. Collecting them automatically would
 *   mean deciding that a reference nobody currently holds will never be
 *   used again — and a peer who has not synced yet holds a reference this
 *   node cannot see. Deleting on their behalf is worse than keeping
 *   bytes nobody asked for.
 * - **A sender who is offline.** The fetch fails with
 *   `BlobUnavailableError` rather than hanging. Anyone connected who has
 *   the bytes can serve them, so a group member who already downloaded a
 *   picture can pass it on.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { SecretBox } from './storage/secret-box.js';
import type { IStorageDriver } from './storage/types.js';
import { StorageCollections } from './storage/types.js';

/**
 * Largest blob accepted, in bytes.
 *
 * 64MB is comfortably more than a phone photo or a short video and small
 * enough that one arriving does not exhaust a mobile device's memory —
 * blobs are assembled whole before the hash can be checked, so this is
 * also the peak working set of a single transfer.
 */
export const MAX_BLOB_BYTES = 64 * 1024 * 1024;

/**
 * Bytes per chunk on the wire.
 *
 * `MAX_FRAME_PAYLOAD` is 1MB and the envelope adds a fixed overhead on
 * top, so 256KB leaves room for both without a per-chunk calculation
 * that would have to track the envelope's size.
 */
export const BLOB_CHUNK_BYTES = 256 * 1024;

/**
 * How long a transfer waits for the next chunk before giving up on the
 * peer serving it and trying another.
 *
 * A stalled transfer produces no error of its own — the serving peer
 * simply stops sending — so this is the only thing that distinguishes
 * "slow" from "never coming".
 */
export const DEFAULT_STALL_TIMEOUT_MS = 30_000;

/** Used when no box is supplied, so reads and writes stay symmetric. */
const passThrough = new SecretBox(null);

/** A handle to blob content, safe to put in a message. */
export interface BlobRef {
  /** Lowercase hex SHA-256 of the content. */
  readonly hash: string;
  readonly size: number;
  readonly mime: string;
}

/** Raised when a blob exceeds the cap this SDK enforces. */
export class BlobTooLargeError extends Error {
  constructor(
    readonly limit: number,
    readonly actual: number,
  ) {
    super(
      `Blob is ${actual} bytes against a limit of ${limit}. ` +
        'Compress or resize it before sending.',
    );
    this.name = 'BlobTooLargeError';
  }
}

/** Raised when nobody reachable can supply a blob's bytes. */
export class BlobUnavailableError extends Error {
  constructor(readonly ref: BlobRef) {
    super(
      `No connected peer could supply blob ${ref.hash.slice(0, 12)}…. ` +
        'Whoever sent it may be offline; the fetch can be retried later, ' +
        'and resumes from whatever arrived.',
    );
    this.name = 'BlobUnavailableError';
  }
}

/** Raised when assembled bytes do not hash to the reference they claim. */
export class BlobCorruptError extends Error {
  constructor(readonly ref: BlobRef) {
    super(
      `Blob ${ref.hash.slice(0, 12)}… did not match its hash and was ` +
        'discarded. The transfer can be retried.',
    );
    this.name = 'BlobCorruptError';
  }
}

/** Wire message kinds on Stream `0x09`. */
const Wire = {
  REQUEST: 0x01,
  CHUNK: 0x02,
  UNAVAILABLE: 0x03,
} as const;

/** Collaborators the blob service needs. */
export interface BlobServiceDeps {
  readonly storage: IStorageDriver;
  /**
   * Send a `0x09` payload to one peer.
   *
   * @returns Whether it went anywhere.
   */
  readonly sendTo: (peerDid: string, payload: Uint8Array) => Promise<boolean>;
  /** Paired peers with a live connection, in no particular order. */
  readonly reachablePeers: () => readonly string[];
  /**
   * Encryption at rest for stored bytes.
   *
   * A photograph on disk is the content, not a reference to it. Sealing
   * message bodies while leaving the pictures beside them readable would
   * protect the caption and not the picture.
   */
  readonly box?: SecretBox;
  /**
   * How long to wait on a silent peer before trying another.
   *
   * Defaults to `DEFAULT_STALL_TIMEOUT_MS`. Worth raising on a link
   * where a long pause is normal, and lowering where a fast answer
   * matters more than tolerating one.
   */
  readonly stallTimeoutMs?: number;
}

type ProgressListener = (received: number, total: number) => void;

interface PendingFetch {
  readonly ref: BlobRef;
  readonly buffer: Uint8Array;
  received: number;
  resolve: (bytes: Uint8Array) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  /** Peers already asked, so a retry moves on rather than repeating. */
  readonly asked: Set<string>;
}

/**
 * Stores blobs and moves them between peers.
 */
export class BlobService {
  private readonly pending = new Map<string, PendingFetch>();
  private readonly progress = new Map<string, Set<ProgressListener>>();

  constructor(private readonly deps: BlobServiceDeps) {}

  /**
   * Store bytes locally and return a handle to them.
   *
   * Nothing is sent: a blob travels when a recipient asks for it, which
   * is what keeps a picture out of the conversations of people who never
   * opened it.
   *
   * @throws {BlobTooLargeError} If it exceeds the cap.
   */
  async put(bytes: Uint8Array, mime: string): Promise<BlobRef> {
    if (bytes.length > MAX_BLOB_BYTES) {
      throw new BlobTooLargeError(MAX_BLOB_BYTES, bytes.length);
    }

    const hash = toHex(sha256(bytes));
    const ref: BlobRef = { hash, size: bytes.length, mime };

    await this.write(ref, bytes, bytes.length);

    return ref;
  }

  /**
   * Fetch a blob's bytes, from local storage or from a peer.
   *
   * Resumes a partial transfer rather than restarting it.
   *
   * @throws {BlobUnavailableError} If nobody reachable has it.
   * @throws {BlobCorruptError} If what arrived does not match the hash.
   */
  async get(ref: BlobRef): Promise<Uint8Array> {
    const held = await this.read(ref.hash);
    if (held && held.received >= ref.size) return held.bytes.subarray(0, ref.size);

    // Two callers wanting the same blob wait on one transfer rather than
    // asking every peer twice.
    const inFlight = this.pending.get(ref.hash);
    if (inFlight) {
      return new Promise<Uint8Array>((resolve, reject) => {
        const previous = inFlight.resolve;
        const previousReject = inFlight.reject;
        inFlight.resolve = (bytes) => {
          previous(bytes);
          resolve(bytes);
        };
        inFlight.reject = (error) => {
          previousReject(error);
          reject(error);
        };
      });
    }

    return this.fetch(ref, held);
  }

  /** Whether this node holds the complete blob. */
  async has(ref: BlobRef): Promise<boolean> {
    const held = await this.read(ref.hash);
    return held !== undefined && held.received >= ref.size;
  }

  /**
   * Forget a blob's bytes.
   *
   * Local only: a copy a peer already fetched stays theirs, exactly as a
   * message they already received does.
   */
  async delete(ref: BlobRef): Promise<void> {
    await this.deps.storage.delete(StorageCollections.BLOBS, ref.hash);
  }

  /**
   * Watch a transfer's progress.
   *
   * Fires as chunks land. A blob already held locally never fires,
   * because nothing is transferred.
   *
   * @returns An unsubscribe function.
   */
  onProgress(ref: BlobRef, listener: ProgressListener): () => void {
    const listeners = this.progress.get(ref.hash) ?? new Set<ProgressListener>();
    listeners.add(listener);
    this.progress.set(ref.hash, listeners);

    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.progress.delete(ref.hash);
    };
  }

  /** Handle an inbound `0x09` payload from a paired peer. */
  async handleFrame(peerDid: string, payload: Uint8Array): Promise<void> {
    if (payload.length < 1) return;

    switch (payload[0]) {
      case Wire.REQUEST:
        await this.serve(peerDid, payload);
        break;
      case Wire.CHUNK:
        await this.absorb(payload);
        break;
      case Wire.UNAVAILABLE:
        this.tryNextPeer(decodeHashOnly(payload));
        break;
      default:
        // An unrecognised kind is ignored, never fatal — the same rule
        // that applies to unknown stream types (RFC 001 §7).
        break;
    }
  }

  /** Abandon every in-flight fetch. Called during shutdown. */
  dispose(): void {
    for (const fetch of this.pending.values()) {
      // Not checkpointed: shutdown races storage teardown, and a write
      // that loses that race would be a spurious error on a clean exit.
      // A transfer interrupted by quitting starts again.
      if (fetch.timer) clearTimeout(fetch.timer);
      fetch.reject(new BlobUnavailableError(fetch.ref));
    }

    this.pending.clear();
    this.progress.clear();
  }

  // ─── Fetching ───────────────────────────────────────────────────────

  private async fetch(
    ref: BlobRef,
    partial: { bytes: Uint8Array; received: number } | undefined,
  ): Promise<Uint8Array> {
    if (ref.size > MAX_BLOB_BYTES) {
      throw new BlobTooLargeError(MAX_BLOB_BYTES, ref.size);
    }

    const buffer = new Uint8Array(ref.size);
    if (partial) buffer.set(partial.bytes.subarray(0, partial.received), 0);

    return new Promise<Uint8Array>((resolve, reject) => {
      const entry: PendingFetch = {
        ref,
        buffer,
        received: partial?.received ?? 0,
        resolve,
        reject,
        timer: undefined,
        asked: new Set(),
      };

      this.pending.set(ref.hash, entry);
      this.tryNextPeer(ref.hash);
    });
  }

  /**
   * Ask the next peer that has not already been asked.
   *
   * Anyone connected may hold the bytes, not only whoever sent the
   * message: in a group the first person to download a picture becomes a
   * second source for it.
   */
  private tryNextPeer(hash: string | undefined): void {
    if (!hash) return;

    const entry = this.pending.get(hash);
    if (!entry) return;

    const next = this.deps
      .reachablePeers()
      .find((did) => !entry.asked.has(did));

    if (!next) {
      void this.settleFailed(entry, new BlobUnavailableError(entry.ref));
      return;
    }

    entry.asked.add(next);
    this.arm(entry);

    void this.deps
      .sendTo(next, encodeRequest(entry.ref.hash, entry.received))
      .then((sent) => {
        // A send that went nowhere is the same as a refusal, and waiting
        // for a timeout that will certainly expire wastes thirty seconds
        // per unreachable peer.
        if (!sent) this.tryNextPeer(hash);
      })
      .catch(() => this.tryNextPeer(hash));
  }

  /** (Re)start the stall timer for a transfer. */
  private arm(entry: PendingFetch): void {
    if (entry.timer) clearTimeout(entry.timer);

    entry.timer = setTimeout(
      () => this.tryNextPeer(entry.ref.hash),
      this.deps.stallTimeoutMs ?? DEFAULT_STALL_TIMEOUT_MS,
    );

    // Node keeps the process alive for a pending timer, which would hold
    // a CLI open for thirty seconds after its last transfer stalled.
    entry.timer.unref?.();
  }

  private async absorb(payload: Uint8Array): Promise<void> {
    const chunk = decodeChunk(payload);
    if (!chunk) return;

    const entry = this.pending.get(chunk.hash);
    if (!entry) return;

    // Out of order, or a duplicate from a second peer we also asked.
    if (chunk.offset !== entry.received) return;
    if (chunk.offset + chunk.bytes.length > entry.buffer.length) return;

    entry.buffer.set(chunk.bytes, chunk.offset);
    entry.received += chunk.bytes.length;

    for (const listener of this.progress.get(chunk.hash) ?? []) {
      listener(entry.received, entry.ref.size);
    }

    if (entry.received < entry.ref.size) {
      // Deliberately no write here. Persisting each chunk means
      // rewriting the whole accumulated buffer every time, which is
      // quadratic in the blob's size — a 64MB file would put some 8GB
      // through the disk. Progress is checkpointed once, when a transfer
      // gives up, which is the only moment resumption needs it.
      this.arm(entry);
      return;
    }

    // Content addressing is only worth anything if it is checked.
    if (toHex(sha256(entry.buffer)) !== entry.ref.hash) {
      await this.deps.storage.delete(StorageCollections.BLOBS, entry.ref.hash);
      // Nothing kept: resuming from bytes known to be wrong would fail
      // the same check every time, forever.
      await this.settleFailed(entry, new BlobCorruptError(entry.ref), false);
      return;
    }

    await this.write(entry.ref, entry.buffer, entry.ref.size);

    if (entry.timer) clearTimeout(entry.timer);
    this.pending.delete(entry.ref.hash);
    entry.resolve(entry.buffer);
  }

  /**
   * End a transfer that will not finish, keeping what arrived.
   *
   * The checkpoint happens before the rejection, so a caller that
   * retries the moment it sees the failure finds the partial bytes
   * already on disk rather than racing a write it cannot see.
   */
  private async settleFailed(
    entry: PendingFetch,
    error: Error,
    keepPartial = true,
  ): Promise<void> {
    if (entry.timer) clearTimeout(entry.timer);
    this.pending.delete(entry.ref.hash);

    if (keepPartial && entry.received > 0) {
      try {
        await this.write(entry.ref, entry.buffer, entry.received);
      } catch {
        // Losing the checkpoint costs a restart, not the transfer.
      }
    }

    entry.reject(error);
  }

  // ─── Serving ────────────────────────────────────────────────────────

  private async serve(peerDid: string, payload: Uint8Array): Promise<void> {
    const request = decodeRequest(payload);
    if (!request) return;

    const held = await this.read(request.hash);

    // Only a complete blob is served. Passing on a partial one would let
    // a recipient believe a transfer finished when the bytes stop.
    if (!held || held.received < held.size) {
      await this.deps.sendTo(peerDid, encodeUnavailable(request.hash));
      return;
    }

    if (request.offset > held.size) return;

    for (
      let offset = request.offset;
      offset < held.size;
      offset += BLOB_CHUNK_BYTES
    ) {
      const end = Math.min(offset + BLOB_CHUNK_BYTES, held.size);
      const sent = await this.deps.sendTo(
        peerDid,
        encodeChunk(request.hash, offset, held.mime, held.bytes.subarray(offset, end)),
      );

      // They went away mid-transfer. Their partial copy is on their disk
      // and resumes from there when they ask again.
      if (!sent) return;
    }
  }

  // ─── Storage ────────────────────────────────────────────────────────

  private async write(
    ref: BlobRef,
    bytes: Uint8Array,
    received: number,
  ): Promise<void> {
    await this.deps.storage.put(StorageCollections.BLOBS, ref.hash, {
      hash: ref.hash,
      mime: ref.mime,
      size: ref.size,
      received,
      // Copied before sealing: the caller may reuse its buffer after we
      // return.
      bytes: (this.deps.box ?? passThrough).sealBytes(new Uint8Array(bytes)),
      created_at: Math.floor(Date.now() / 1000),
    });
  }

  private async read(hash: string): Promise<
    { bytes: Uint8Array; size: number; received: number; mime: string } | undefined
  > {
    const row = await this.deps.storage.get(StorageCollections.BLOBS, hash);
    if (!row) return undefined;

    return {
      bytes: (this.deps.box ?? passThrough).openBytes(
        row['bytes'] as Uint8Array,
      ),
      size: row['size'] as number,
      received: row['received'] as number,
      mime: row['mime'] as string,
    };
  }
}

// ─── Wire format ──────────────────────────────────────────────────────
//
// Every payload starts with a one-byte kind, then a 32-byte hash. Hashes
// travel as raw bytes rather than the hex used everywhere else, which
// halves the per-chunk overhead for the one message sent thousands of
// times.

/** `REQUEST`: kind, hash, offset. */
export function encodeRequest(hash: string, offset: number): Uint8Array {
  const out = new Uint8Array(1 + 32 + 4);

  out[0] = Wire.REQUEST;
  out.set(fromHex(hash), 1);
  new DataView(out.buffer).setUint32(33, offset, false);

  return out;
}

function decodeRequest(
  payload: Uint8Array,
): { hash: string; offset: number } | undefined {
  if (payload.length < 37) return undefined;

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

  return {
    hash: toHex(payload.subarray(1, 33)),
    offset: view.getUint32(33, false),
  };
}

/** `CHUNK`: kind, hash, offset, mime, bytes. */
export function encodeChunk(
  hash: string,
  offset: number,
  mime: string,
  bytes: Uint8Array,
): Uint8Array {
  const mimeBytes = new TextEncoder().encode(mime);
  const out = new Uint8Array(1 + 32 + 4 + 2 + mimeBytes.length + bytes.length);
  const view = new DataView(out.buffer);

  out[0] = Wire.CHUNK;
  out.set(fromHex(hash), 1);
  view.setUint32(33, offset, false);
  view.setUint16(37, mimeBytes.length, false);
  out.set(mimeBytes, 39);
  out.set(bytes, 39 + mimeBytes.length);

  return out;
}

function decodeChunk(
  payload: Uint8Array,
): { hash: string; offset: number; mime: string; bytes: Uint8Array } | undefined {
  if (payload.length < 39) return undefined;

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const mimeLength = view.getUint16(37, false);

  if (payload.length < 39 + mimeLength) return undefined;

  return {
    hash: toHex(payload.subarray(1, 33)),
    offset: view.getUint32(33, false),
    mime: new TextDecoder().decode(payload.subarray(39, 39 + mimeLength)),
    bytes: payload.slice(39 + mimeLength),
  };
}

/** `UNAVAILABLE`: kind, hash. */
export function encodeUnavailable(hash: string): Uint8Array {
  const out = new Uint8Array(1 + 32);

  out[0] = Wire.UNAVAILABLE;
  out.set(fromHex(hash), 1);

  return out;
}

function decodeHashOnly(payload: Uint8Array): string | undefined {
  if (payload.length < 33) return undefined;
  return toHex(payload.subarray(1, 33));
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
