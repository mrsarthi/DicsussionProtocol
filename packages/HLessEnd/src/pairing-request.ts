/**
 * Pairing requests — a stranger knocking (Stream `0x0a`).
 *
 * ### Why this has to exist
 *
 * A completed handshake proves the far side holds the secret behind the
 * `did:key` it claimed. That is all it proves. It does **not** disclose
 * that peer's X25519 encryption key, which is derived from their seed
 * under a separate HKDF label and cannot be recovered from the
 * identifier — nor their addresses.
 *
 * So a node receiving a connection from someone it has never met knows
 * who is calling and can do nothing with that: it cannot encrypt for
 * them, and cannot dial them back. Pairing has therefore had to happen
 * entirely out of band, with a human copying a ticket between devices.
 *
 * This carries the initiator's own ticket, so a recipient who accepts
 * already holds the material to pair.
 *
 * ### What is proven and what is merely claimed
 *
 * The `did:key` is **proven** by the handshake. The ticket is **bound**
 * to it — a request whose ticket names a different identity is dropped,
 * so nobody can present someone else's ticket and have it registered
 * against their own connection.
 *
 * `displayName` is **neither**. It is a string the sender chose, with no
 * more authority than a name typed into a form, and it must be presented
 * to a person as a claim rather than as an identity. An application that
 * renders it as though it were verified has undone the point of pairing.
 *
 * ### The boundary this moves
 *
 * RFC 001 §3.3 put pairing out of band deliberately: a handshake shows
 * key ownership, not that the owner is anyone you meant to talk to.
 * Moving the material in-band does not weaken *that* — the identifier is
 * still proven, and impersonation is still impossible. What it removes
 * is the out-of-band step that confirmed which person a `did:key`
 * belongs to. Accepting a request is a decision made on a self-asserted
 * name, and it is the application's job to present it that way.
 */

import type { PeerTicket } from '@dicsussion/core/transport';
import { decodeTicket, encodeTicket } from '@dicsussion/core/transport';

/**
 * Longest display name accepted on a request.
 *
 * Matches the profile cap, so a name does not change size the moment a
 * stranger becomes a contact.
 */
export const MAX_REQUEST_NAME_LENGTH = 128;

/**
 * Largest request accepted, in bytes.
 *
 * An unpaired peer can cause this to be parsed and stored, which is the
 * only work a stranger can make this node do. A ticket and a short name
 * are well under a kilobyte; four leaves room without inviting anything.
 */
export const MAX_REQUEST_BYTES = 4096;

/** A stranger asking to be paired. */
export interface PairingRequest {
  /**
   * The requester's did:key, proven by the RFC 001 §5 handshake.
   *
   * Proven, not trusted: it shows they hold the secret behind this
   * identifier, not that they are anyone you know.
   */
  readonly peerDid: string;
  /**
   * Their ticket — the encryption key and addresses needed to pair.
   *
   * Verified to belong to `peerDid` before this is emitted.
   */
  readonly ticket: PeerTicket;
  /**
   * What they call themselves.
   *
   * A claim with no more authority than a name typed into a form. Show
   * it as one.
   */
  readonly displayName?: string;
  /** Unix seconds when the request arrived. */
  readonly at: number;
}

/** Encode a request for the wire. */
export function encodeRequest(
  ticket: PeerTicket,
  displayName?: string,
): Uint8Array {
  const body = JSON.stringify({
    ticket: encodeTicket(ticket),
    displayName,
  });

  return new TextEncoder().encode(body);
}

/**
 * Decode and validate an inbound request.
 *
 * @param bytes The decrypted `0x0a` payload.
 * @param provenDid The did:key the handshake proved for this connection.
 * @returns The request, or undefined if it is malformed, oversized, or
 *   carries a ticket belonging to someone else.
 */
export function decodeRequest(
  bytes: Uint8Array,
  provenDid: string,
): Omit<PairingRequest, 'at'> | undefined {
  if (bytes.length === 0 || bytes.length > MAX_REQUEST_BYTES) return undefined;

  let parsed: { ticket?: unknown; displayName?: unknown };
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes)) as typeof parsed;
  } catch {
    return undefined;
  }

  if (typeof parsed !== 'object' || parsed === null) return undefined;
  if (typeof parsed.ticket !== 'string') return undefined;

  let ticket: PeerTicket;
  try {
    ticket = decodeTicket(parsed.ticket);
  } catch {
    return undefined;
  }

  // The whole reason a request can be trusted at all. Without this a
  // peer could present someone else's ticket and have this node register
  // that stranger's key — or dial a third party — under the name of the
  // identity it actually proved.
  if (ticket.didKey !== provenDid) return undefined;

  // A ticket without an encryption key cannot be paired from, and
  // emitting one would produce an accept button that silently does
  // nothing.
  if (!ticket.encryptionKey) return undefined;

  const name = parsed.displayName;
  const displayName =
    typeof name === 'string' && name.length > 0 && name.length <= MAX_REQUEST_NAME_LENGTH
      ? name
      : undefined;

  return { peerDid: provenDid, ticket, displayName };
}
