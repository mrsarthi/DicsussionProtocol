/**
 * A `DicsussionClient` running in its own OS process, driven over stdio.
 *
 * Every other test in this project runs peers inside one process, where
 * "the network" is a JavaScript Map. This harness is what makes genuine
 * cross-process testing possible: each peer is a real process with its
 * own memory, event loop and UDP socket, talking over real QUIC.
 *
 * Protocol: newline-delimited JSON on stdin/stdout. Commands carry an
 * `id` that is echoed on the reply, so the parent can await a specific
 * response rather than assuming ordering.
 */

import { createInterface } from 'node:readline';

import { DicsussionClient } from '../../packages/HLessEnd/src/client.js';
import type { PeerTicket } from '../../packages/core/src/transport/types.js';
import type { SdkChatMessage } from '../../packages/HLessEnd/src/types.js';

interface Command {
  readonly id: number;
  readonly op: string;
  readonly [key: string]: unknown;
}

/** Messages this peer has received, so the parent can assert on them. */
const inbox: SdkChatMessage[] = [];

function emit(payload: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(payload, serialiseBytes)}\n`);
}

/** `Uint8Array` has no JSON representation; tickets are full of them. */
function serialiseBytes(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return { __bytes: Buffer.from(value).toString('base64') };
  }
  return value;
}

function reviveBytes(_key: string, value: unknown): unknown {
  const wrapped = value as { __bytes?: string } | null;
  if (wrapped && typeof wrapped === 'object' && typeof wrapped.__bytes === 'string') {
    return new Uint8Array(Buffer.from(wrapped.__bytes, 'base64'));
  }
  return value;
}

const client = await DicsussionClient.init(
  { storagePath: ':memory:' },
  { transport: 'iroh', localOnly: true, bindAddr: '127.0.0.1:0' },
);

// Announce readiness with everything the parent needs to pair us.
emit({
  event: 'ready',
  did: client.did,
  ticket: client.getTicket(),
  encryptionKey: client.encryptionPublicKey,
});

const lines = createInterface({ input: process.stdin });

for await (const line of lines) {
  if (!line.trim()) continue;

  let command: Command;
  try {
    command = JSON.parse(line, reviveBytes) as Command;
  } catch {
    continue;
  }

  try {
    emit({ id: command.id, ok: true, result: await handle(command) });
  } catch (error) {
    emit({
      id: command.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

async function handle(command: Command): Promise<unknown> {
  switch (command.op) {
    case 'addPeer':
      client.addPeer(command['did'] as string, command['key'] as Uint8Array);
      return null;

    /**
     * Pair from a ticket alone — what an application actually has.
     *
     * `addPeer` above takes a raw X25519 key, which a user never sees. A
     * real pairing flow starts from a pasted or scanned ticket, so this
     * op exists to exercise that path rather than the harness shortcut.
     */
    case 'pairFromTicket': {
      const ticket = command['ticket'] as PeerTicket;
      if (!ticket.encryptionKey) {
        throw new Error(`Ticket for ${ticket.didKey} carries no encryption key`);
      }
      client.addPeer(ticket.didKey, ticket.encryptionKey);
      return null;
    }

    /**
     * Declare a conversation and who belongs to it.
     *
     * Pairing authorises a peer; it does not admit them to every
     * conversation on the device. A harness that only pairs therefore
     * sends into a channel with no eligible recipients, which is exactly
     * what a real application would do if it forgot to say who a chat is
     * for — so the op exists rather than the behaviour being special-cased.
     */
    case 'createChannel':
      client.chat.createChannel(
        command['channelId'] as string,
        (command['participants'] as string[] | undefined) ?? [],
      );
      return null;

    case 'connect':
      await client.connect(command['ticket'] as PeerTicket);
      return null;

    case 'watch':
      // Register before sending so nothing is missed.
      client.chat.onMessage(command['channelId'] as string, (msg) => {
        inbox.push(msg);
      });
      return null;

    case 'send':
      return client.chat.sendMessage({
        channelId: command['channelId'] as string,
        content: command['content'] as string,
        anonymous: command['anonymous'] === true,
      });

    case 'inbox':
      return inbox.map((m) => ({
        content: m.content,
        authorDid: m.authorDid ?? null,
        nullifierHash: m.nullifierHash ?? null,
      }));

    case 'history':
      return (await client.chat.getHistory(command['channelId'] as string)).map(
        (m) => m.content,
      );

    case 'status':
      return client.getNetworkStatus();

    case 'goOffline':
      client.goOffline();
      return null;

    case 'goOnline':
      return client.goOnline();

    case 'outboxSize':
      return client.outboxSize;

    case 'shutdown':
      await client.disconnect();
      // Give the reply a chance to flush before the process ends.
      setTimeout(() => process.exit(0), 50);
      return null;

    default:
      throw new Error(`Unknown op: ${command.op}`);
  }
}
