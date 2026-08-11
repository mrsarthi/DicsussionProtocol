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

import {
  base64ToBytes,
  base64UrlToUtf8,
  bytesToBase64,
  utf8ToBase64Url,
} from '../crypto/base64.js';

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
    n: bytesToBase64(ticket.nodeId),
    a: [...ticket.directAddresses],
    ...(ticket.derpRelay ? { r: ticket.derpRelay } : {}),
    ...(ticket.transportKey
      ? { t: bytesToBase64(ticket.transportKey) }
      : {}),
    ...(ticket.encryptionKey
      ? { e: bytesToBase64(ticket.encryptionKey) }
      : {}),
  };

  return TICKET_PREFIX + utf8ToBase64Url(JSON.stringify(wire));
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
      base64UrlToUtf8(trimmed.slice(TICKET_PREFIX.length)),
    ) as WireTicket;
  } catch {
    throw new Error('Malformed ticket: could not decode the payload');
  }

  if (typeof wire.d !== 'string' || typeof wire.n !== 'string') {
    throw new Error('Malformed ticket: missing did:key or node id');
  }

  return {
    didKey: wire.d,
    nodeId: base64ToBytes(wire.n),
    directAddresses: Array.isArray(wire.a) ? wire.a : [],
    derpRelay: wire.r,
    transportKey: wire.t
      ? base64ToBytes(wire.t)
      : undefined,
    encryptionKey: wire.e
      ? base64ToBytes(wire.e)
      : undefined,
  };
}
