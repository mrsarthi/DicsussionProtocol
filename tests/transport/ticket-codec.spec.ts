/**
 * Ticket serialization (RFC 001 §3.3).
 *
 * A ticket must survive being copied out of a terminal and pasted into
 * another machine — including the line breaks and stray whitespace that
 * introduces.
 */

import { expect, test } from '@playwright/test';

import {
  decodeTicket,
  encodeTicket,
  TICKET_PREFIX,
} from '../../packages/core/src/transport/ticket-codec.js';
import type { PeerTicket } from '../../packages/core/src/transport/types.js';

const ticket: PeerTicket = {
  didKey: 'did:key:z6MkExampleIdentifier',
  nodeId: new Uint8Array(32).fill(7),
  directAddresses: ['192.168.1.4:4242', '[2001:db8::1]:4242'],
  derpRelay: 'https://relay.example',
  transportKey: new Uint8Array(32).fill(9),
  encryptionKey: new Uint8Array(32).fill(11),
};

test.describe('Transport — Ticket Codec', () => {
  test('a full ticket round-trips', () => {
    const decoded = decodeTicket(encodeTicket(ticket));

    expect(decoded.didKey).toBe(ticket.didKey);
    expect(Array.from(decoded.nodeId)).toEqual(Array.from(ticket.nodeId));
    expect(decoded.directAddresses).toEqual(ticket.directAddresses);
    expect(decoded.derpRelay).toBe(ticket.derpRelay);
    expect(Array.from(decoded.transportKey!)).toEqual(
      Array.from(ticket.transportKey!),
    );
    expect(Array.from(decoded.encryptionKey!)).toEqual(
      Array.from(ticket.encryptionKey!),
    );
  });

  test('optional fields are omitted rather than nulled', () => {
    const minimal: PeerTicket = {
      didKey: ticket.didKey,
      nodeId: ticket.nodeId,
      directAddresses: [],
    };

    const decoded = decodeTicket(encodeTicket(minimal));

    expect(decoded.derpRelay).toBeUndefined();
    expect(decoded.transportKey).toBeUndefined();
    expect(decoded.encryptionKey).toBeUndefined();
  });

  test('it carries a recognisable prefix', () => {
    expect(encodeTicket(ticket).startsWith(TICKET_PREFIX)).toBe(true);
  });

  test('whitespace and line breaks from copy-paste are tolerated', () => {
    const encoded = encodeTicket(ticket);
    const mangled = `  ${encoded.slice(0, 40)}\n   ${encoded.slice(40)}  \n`;

    expect(decodeTicket(mangled).didKey).toBe(ticket.didKey);
  });

  test('non-tickets are rejected with a clear message', () => {
    expect(() => decodeTicket('hello world')).toThrow(/Not a Dicsussion ticket/);
    expect(() => decodeTicket(`${TICKET_PREFIX}!!!not-base64!!!`)).toThrow(
      /Malformed ticket/,
    );
  });

  test('a ticket missing required fields is rejected', () => {
    const bad =
      TICKET_PREFIX + Buffer.from(JSON.stringify({ a: [] })).toString('base64url');

    expect(() => decodeTicket(bad)).toThrow(/missing did:key or node id/);
  });
});
