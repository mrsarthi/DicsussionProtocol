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
 *   2. `/pair` each other's tickets — BOTH sides, in both directions.
 *   3. `/connect` on ONE side only.
 *   4. Type to chat. `/status` shows whether the path is direct or
 *      relayed — the thing that actually needs verifying on real NATs.
 *
 * WHY PAIRING IS ITS OWN STEP. Pairing is mutual (RFC 001 §3.3): a peer
 * that has not registered your X25519 key cannot decrypt anything you
 * send, and drops it with no error at either end. `/connect` registers
 * the key of whoever you dial, which covers the dialer and nobody else —
 * so a single `/connect` leaves the accepting side unable to read a word.
 * Dialling from both sides does not fix it either; that opens two
 * connections for one peer pair, and the session layer expects one.
 *
 * Hence: pair both ways, dial once.
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

/**
 * Wait until the endpoint has finished discovering how it is reachable.
 *
 * Binding is instant; learning a public address via STUN and registering
 * with a relay is not. A ticket printed before that carries only LAN and
 * link-local addresses, so it works on the same network and is undialable
 * from anywhere else — which looks exactly like a NAT traversal failure
 * and is the single easiest way to waste an afternoon with two laptops.
 */
async function awaitReachability(timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (client.getTicket().derpRelay) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

say();
say('  Dicsussion peer');
say('  ───────────────');
say(`  did      ${client.did}`);
say(`  storage  ${storagePath}${storageKey ? ' (encrypted)' : ' (PLAINTEXT — dev only)'}`);
say();
say('  … discovering how this node is reachable');

await awaitReachability();

const ticket = client.getTicket();
if (!ticket.derpRelay) {
  say('  ! no relay registered — this ticket may only work on your own network');
}

say();
say('  Your ticket — paste this into the other device:');
say();
say(`  ${encodeTicket(ticket)}`);
say();
say('  1. /pair <ticket>     on BOTH sides, with each other\'s ticket');
say('  2. /connect <ticket>  on ONE side only');
say();
say('  Also: /status · /peers · /history · /ticket · /quit');
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
    case '/pair': {
      if (!argument) throw new Error('Usage: /pair <ticket>');

      const peer = decodeTicket(argument);
      if (!peer.encryptionKey) {
        throw new Error(`Ticket for ${peer.didKey} carries no encryption key`);
      }

      client.addPeer(peer.didKey, peer.encryptionKey);
      say(`  ✓ paired with ${peer.didKey.slice(0, 24)}…`);
      say('    (they must /pair you too, or nothing you send arrives)');
      return;
    }

    case '/connect': {
      if (!argument) throw new Error('Usage: /connect <ticket>');

      const peer = decodeTicket(argument);
      // Dialling registers this peer's key on *our* side only. The far
      // side needs its own `/pair` — see the note at the top of the file.
      say(`  … dialling ${peer.didKey.slice(0, 24)}…`);

      await client.connect(peer);
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
