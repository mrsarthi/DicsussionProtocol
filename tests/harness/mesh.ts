/**
 * Spawn and drive `DicsussionClient` peers in separate OS processes.
 *
 * Leaked child processes wedge CI, so every spawn is tracked and
 * `shutdownAll` is safe to call twice — tests must be able to call it
 * from a `finally` without worrying whether it already ran.
 */

import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import { join } from 'node:path';

import type { PeerTicket } from '../../packages/core/src/transport/types.js';

const PEER_SCRIPT = join(process.cwd(), 'tests/harness/peer-process.mts');

/** How long to wait for a peer to boot and bind a socket. */
const READY_TIMEOUT_MS = 30_000;

/** Default per-command timeout — real handshakes take hundreds of ms. */
const COMMAND_TIMEOUT_MS = 20_000;

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

/** A peer running in its own process. */
export class PeerHandle {
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private exited = false;

  private constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    readonly did: string,
    readonly ticket: PeerTicket,
    readonly encryptionKey: Uint8Array,
  ) {}

  /** Spawn a peer and wait until it has bound a socket. */
  static async spawn(label: string): Promise<PeerHandle> {
    // Invoke the local tsx binary directly rather than through `npx` with
    // a shell — passing args to a shelled child concatenates rather than
    // escapes them (Node DEP0190).
    const child = spawn(
      process.execPath,
      [join(process.cwd(), 'node_modules/tsx/dist/cli.mjs'), PEER_SCRIPT],
      { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] },
    );

    // Surface child stderr — otherwise a crashing peer is a silent timeout.
    child.stderr.on('data', (chunk: Buffer) => {
      const text = chunk.toString().trim();
      if (text) process.stderr.write(`[${label}] ${text}\n`);
    });

    const messages = parseJsonLines(createInterface({ input: child.stdout }));

    const ready = await withTimeout(
      nextJson(messages),
      READY_TIMEOUT_MS,
      `${label} did not become ready`,
    );

    if (ready['event'] !== 'ready') {
      throw new Error(`${label} sent an unexpected first message`);
    }

    const handle = new PeerHandle(
      child,
      ready['did'] as string,
      ready['ticket'] as PeerTicket,
      ready['encryptionKey'] as Uint8Array,
    );

    void handle.pump(messages);
    return handle;
  }

  /** Send a command and await its reply. */
  async call<T = unknown>(op: string, args: Record<string, unknown> = {}): Promise<T> {
    if (this.exited) throw new Error(`Peer ${this.did} has exited`);

    const id = this.nextId++;

    const reply = new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Command '${op}' timed out after ${COMMAND_TIMEOUT_MS}ms`));
      }, COMMAND_TIMEOUT_MS);
      timer.unref?.();

      this.pending.set(id, { resolve, reject, timer });
    });

    this.child.stdin.write(`${JSON.stringify({ id, op, ...args }, serialiseBytes)}\n`);
    return (await reply) as T;
  }

  /** Poll until `predicate` holds or the budget expires. */
  async waitFor(
    predicate: () => Promise<boolean>,
    timeoutMs = 15_000,
    pollMs = 100,
  ): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      if (await predicate()) return true;
      await new Promise((r) => setTimeout(r, pollMs));
    }

    return predicate();
  }

  /** Terminate the process, gracefully if possible. */
  async shutdown(): Promise<void> {
    if (this.exited) return;
    this.exited = true;

    try {
      this.child.stdin.write(`${JSON.stringify({ id: -1, op: 'shutdown' })}\n`);
      await new Promise((r) => setTimeout(r, 200));
    } catch {
      // Already gone.
    }

    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(new Error('Peer shut down'));
    }
    this.pending.clear();

    this.child.kill();
  }

  /** Route replies to whoever is awaiting them. */
  private async pump(messages: AsyncIterator<Record<string, unknown>>): Promise<void> {
    for (;;) {
      let message: Record<string, unknown>;
      try {
        const next = await messages.next();
        if (next.done) break;
        message = next.value;
      } catch {
        break;
      }

      const id = message['id'] as number | undefined;
      if (id === undefined) continue;

      const entry = this.pending.get(id);
      if (!entry) continue;

      this.pending.delete(id);
      clearTimeout(entry.timer);

      if (message['ok'] === true) entry.resolve(message['result']);
      else entry.reject(new Error(String(message['error'] ?? 'unknown error')));
    }

    this.exited = true;
  }
}

/** A set of peers, fully paired and connected. */
export class PeerMesh {
  private constructor(readonly peers: PeerHandle[]) {}

  /**
   * Spawn `count` peers, exchange keys, and dial every pair once.
   *
   * @param count Number of peers.
   */
  static async create(count: number): Promise<PeerMesh> {
    const peers = await Promise.all(
      Array.from({ length: count }, (_, i) => PeerHandle.spawn(`peer${i}`)),
    );

    // Out-of-band pairing: everyone learns everyone's encryption key.
    for (const self of peers) {
      for (const other of peers) {
        if (self === other) continue;
        await self.call('addPeer', { did: other.did, key: other.encryptionKey });
      }
    }

    // Pairing authorises each peer; one declaration names the whole
    // conversation. `createChannel` states membership rather than adding
    // to it, so a call per peer would leave only the last one in.
    for (const self of peers) {
      await self.call('createChannel', {
        channelId: 'general',
        participants: peers.filter((p) => p !== self).map((p) => p.did),
      });
    }

    // One connection per pair — dialling both ways would double up.
    for (let i = 0; i < peers.length; i++) {
      for (let j = i + 1; j < peers.length; j++) {
        await peers[i]!.call('connect', { ticket: peers[j]!.ticket });
      }
    }

    // `connect()` resolves once the *dialer* finishes its handshake, but
    // the accepting side is still adopting its sub-streams and has not
    // yet surfaced the connection. Returning here would hand back a mesh
    // that is not actually formed, so every peer must confirm it sees
    // the others first.
    const expected = peers.length - 1;
    for (const peer of peers) {
      const connected = await peer.waitFor(async () => {
        const status = await peer.call<{ peerCount: number }>('status');
        return status.peerCount >= expected;
      });

      if (!connected) {
        await Promise.all(peers.map((p) => p.shutdown()));
        throw new Error(
          `Peer ${peer.did} saw fewer than ${expected} peers; mesh did not form`,
        );
      }
    }

    return new PeerMesh(peers);
  }

  /** Peer by index. */
  at(index: number): PeerHandle {
    const peer = this.peers[index];
    if (!peer) throw new Error(`No peer at index ${index}`);
    return peer;
  }

  /** Terminate every peer; safe to call more than once. */
  async shutdownAll(): Promise<void> {
    await Promise.all(this.peers.map((p) => p.shutdown()));
  }
}

/**
 * Turn a line stream into parsed JSON messages.
 *
 * Non-JSON lines are skipped rather than fatal — a child that logs a
 * stray line to stdout should not kill the harness.
 */
async function* parseJsonLines(
  lines: AsyncIterable<string>,
): AsyncGenerator<Record<string, unknown>> {
  for await (const line of lines) {
    if (!line.trim()) continue;

    try {
      yield JSON.parse(line, reviveBytes) as Record<string, unknown>;
    } catch {
      continue;
    }
  }
}

function reviveBytes(_key: string, value: unknown): unknown {
  const wrapped = value as { __bytes?: string } | null;
  if (wrapped && typeof wrapped === 'object' && typeof wrapped.__bytes === 'string') {
    return new Uint8Array(Buffer.from(wrapped.__bytes, 'base64'));
  }
  return value;
}

async function nextJson(
  messages: AsyncIterator<Record<string, unknown>>,
): Promise<Record<string, unknown>> {
  const next = await messages.next();
  if (next.done) throw new Error('Peer process closed before sending a message');
  return next.value;
}

function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      const timer = setTimeout(() => reject(new Error(message)), ms);
      timer.unref?.();
    }),
  ]);
}

function serialiseBytes(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return { __bytes: Buffer.from(value).toString('base64') };
  }
  return value;
}
