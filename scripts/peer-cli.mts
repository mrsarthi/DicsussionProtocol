#!/usr/bin/env -S npx tsx
/**
 * Interactive terminal peer — for testing between real devices.
 *
 *   npm run peer
 *
 * This is a complete Dicsussion node with a terminal instead of a UI. It
 * exists so the protocol can be tested on real hardware, over real
 * networks, without first building an application on top of it.
 *
 * Two machines:
 *   1. Run `npm run peer` on both.
 *   2. Copy the ticket printed by one, paste it into the other's
 *      `/connect` command.
 *   3. Type to chat. `/status` shows whether the path is direct or
 *      relayed — the thing that actually needs verifying on real NATs.
 *
 * Relays are ENABLED here (unlike the test suite), because traversing a
 * real NAT is the point.
 */

import { createInterface } from 'node:readline';

import {
  decodeTicket,
  encodeTicket,
} from '../packages/core/src/transport/ticket-codec.js';
import { DicsussionClient } from '../packages/HLessEnd/src/client.js';

const CHANNEL = 'general';

const args = process.argv.slice(2);
const storagePath = valueOf('--store') ?? ':memory:';
const storageKey = valueOf('--key');

function valueOf(flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function say(text = ''): void {
  process.stdout.write(`${text}\n`);
}

const client = await DicsussionClient.init(
  { storagePath, ...(storageKey ? { storageKey } : {}) },
  { transport: 'iroh' },
);

say();
say('  Dicsussion peer');
say('  ───────────────');
say(`  did      ${client.did}`);
say(`  storage  ${storagePath}${storageKey ? ' (encrypted)' : ' (PLAINTEXT — dev only)'}`);
say();
say('  Your ticket — paste this into the other device:');
say();
say(`  ${encodeTicket(client.getTicket())}`);
say();
say('  Commands: /connect <ticket> · /status · /peers · /history · /ticket · /quit');
say('  Anything else is sent as a message.');
say();

client.chat.onMessage(CHANNEL, (message) => {
  const who = message.authorDid
    ? `${message.authorDid.slice(0, 20)}…`
    : `anon:${message.nullifierHash?.slice(0, 10)}…`;

  say(`\n  ← ${who}: ${message.content}`);
  prompt();
});

const rl = createInterface({ input: process.stdin, output: process.stdout });

let closed = false;

function prompt(): void {
  if (closed) return;
  rl.setPrompt('> ');
  rl.prompt();
}

prompt();

/**
 * Commands run one at a time.
 *
 * `readline` emits every buffered line at once when stdin is piped, so
 * without this a scripted `/connect` followed by a message would race —
 * the message would be sent before the connection existed.
 */
let queue: Promise<void> = Promise.resolve();

rl.on('line', (line) => {
  const input = line.trim();
  if (!input) return prompt();

  queue = queue.then(async () => {
    try {
      await handle(input);
    } catch (error) {
      say(`  ✗ ${error instanceof Error ? error.message : String(error)}`);
    }
    prompt();
  });
});

async function handle(input: string): Promise<void> {
  if (!input.startsWith('/')) {
    const sent = await client.chat.sendMessage({
      channelId: CHANNEL,
      content: input,
    });
    say(`  → sent (${sent.id.slice(0, 8)})`);
    return;
  }

  const [command, ...rest] = input.split(/\s+/);
  const argument = rest.join(' ');

  switch (command) {
    case '/connect': {
      if (!argument) throw new Error('Usage: /connect <ticket>');

      const ticket = decodeTicket(argument);
      // The ticket carries the X25519 key, so pasting it *is* the
      // pairing step (RFC 001 §3.3).
      say(`  … dialling ${ticket.didKey.slice(0, 24)}…`);

      await client.connect(ticket);
      say('  ✓ connected');
      return;
    }

    case '/status': {
      const status = client.getNetworkStatus();
      say(`  peers      ${status.peerCount}`);
      say(`  connected  ${status.connected}`);
      say(`  relay      ${status.relayActive ? 'RELAYED' : 'direct'}`);
      say(`  last sync  ${status.lastSyncTimestamp || 'never'}`);
      return;
    }

    case '/peers': {
      const peers = client.getDiscoveredPeers();
      say(peers.length === 0 ? '  (none discovered)' : '');
      for (const peer of peers) say(`  ${peer.did} @ ${peer.address}:${peer.port}`);
      return;
    }

    case '/history': {
      const history = await client.chat.getHistory(CHANNEL);
      say(history.length === 0 ? '  (empty)' : '');
      for (const message of history) {
        const who = message.authorDid ? message.authorDid.slice(0, 16) : 'anon';
        say(`  ${who}… ${message.content}`);
      }
      return;
    }

    case '/ticket':
      say(`  ${encodeTicket(client.getTicket())}`);
      return;

    case '/quit':
      closed = true;
      await client.disconnect();
      rl.close();
      process.exit(0);
      return;

    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

rl.on('close', () => {
  closed = true;

  // Let any in-flight command finish before tearing the node down —
  // exiting mid-connect looks like a connection failure.
  void queue.finally(() =>
    client.disconnect().finally(() => process.exit(0)),
  );
});
