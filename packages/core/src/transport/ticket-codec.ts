/**
 * @dicsussion/transport — Peer Ticket Serialization (RFC 001 §3.3)
 *
 * A ticket is how one peer tells another where to find it. RFC 001 §3.3
 * specifies a Base64 string so it can travel through whatever channel
 * two people already share — a QR code, a chat message, or a human
 * pasting it into a terminal.
 *
 * Binary fields are Base64-encoded inside the JSON because `Uint8Array`
 * has no JSON representation and would otherwise silently become `{}`.
 */

import type { PeerTicket } from './types.js';

/** Prefix identifying the ticket format, so a future one is distinguishable. */
export const TICKET_PREFIX = 'dicsussion1';

interface WireTicket {
  readonly d: string;
  readonly n: string;
  readonly a: readonly string[];
  readonly r?: string;
  readonly t?: string;
  readonly e?: string;
}

/**
 * Encode a ticket as a shareable string.
 *
 * @param ticket The ticket to serialise.
 * @returns `dicsussion1<base64url>`.
 */
export function encodeTicket(ticket: PeerTicket): string {
  const wire: WireTicket = {
    d: ticket.didKey,
    n: Buffer.from(ticket.nodeId).toString('base64'),
    a: [...ticket.directAddresses],
    ...(ticket.derpRelay ? { r: ticket.derpRelay } : {}),
    ...(ticket.transportKey
      ? { t: Buffer.from(ticket.transportKey).toString('base64') }
      : {}),
    ...(ticket.encryptionKey
      ? { e: Buffer.from(ticket.encryptionKey).toString('base64') }
      : {}),
  };

  return TICKET_PREFIX + Buffer.from(JSON.stringify(wire)).toString('base64url');
}

/**
 * Decode a ticket string.
 *
 * Tolerates surrounding whitespace and line breaks, since tickets are
 * routinely copied out of terminals and messages.
 *
 * @throws If the string is not a well-formed ticket.
 */
export function decodeTicket(encoded: string): PeerTicket {
  const trimmed = encoded.trim().replace(/\s+/g, '');

  if (!trimmed.startsWith(TICKET_PREFIX)) {
    throw new Error(`Not a Dicsussion ticket: expected a ${TICKET_PREFIX} prefix`);
  }

  let wire: WireTicket;
  try {
    wire = JSON.parse(
      Buffer.from(trimmed.slice(TICKET_PREFIX.length), 'base64url').toString('utf8'),
    ) as WireTicket;
  } catch {
    throw new Error('Malformed ticket: could not decode the payload');
  }

  if (typeof wire.d !== 'string' || typeof wire.n !== 'string') {
    throw new Error('Malformed ticket: missing did:key or node id');
  }

  return {
    didKey: wire.d,
    nodeId: new Uint8Array(Buffer.from(wire.n, 'base64')),
    directAddresses: Array.isArray(wire.a) ? wire.a : [],
    derpRelay: wire.r,
    transportKey: wire.t
      ? new Uint8Array(Buffer.from(wire.t, 'base64'))
      : undefined,
    encryptionKey: wire.e
      ? new Uint8Array(Buffer.from(wire.e, 'base64'))
      : undefined,
  };
}
