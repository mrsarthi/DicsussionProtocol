/**
 * @dicsussion/transport — mDNS Beacon Record Codec
 *
 * Encodes/decodes the TXT record payload broadcast on
 * `_p2p-sync._udp.local` per RFC 001 §4.1.
 *
 * Wire format (DNS TXT character-string convention):
 *   [u8 len][utf8 "key=value"] repeated until end of buffer
 *
 * Required keys: `svc`, `did`, `port`, `ver`.
 */

import { MDNS_SERVICE_ID, TransportError, TransportException } from './types.js';

/** Protocol version advertised in the `ver` TXT key. */
export const MDNS_PROTOCOL_VERSION = 1;

/** Maximum beacon size in bytes — stays inside a single Ethernet MTU. */
export const MAX_BEACON_SIZE = 1400;

/** Decoded mDNS beacon announcement. */
export interface MdnsBeacon {
  /** Service identifier — must equal MDNS_SERVICE_ID. */
  readonly service: string;
  /** Full did:key string of the announcing node. */
  readonly did: string;
  /** Local listening UDP port. */
  readonly port: number;
  /** Protocol version. */
  readonly version: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Encode a beacon into its TXT record byte representation.
 *
 * @throws TransportException if the encoded record exceeds MAX_BEACON_SIZE.
 */
export function encodeBeacon(beacon: MdnsBeacon): Uint8Array {
  const entries = [
    `svc=${beacon.service}`,
    `did=${beacon.did}`,
    `port=${beacon.port}`,
    `ver=${beacon.version}`,
  ];

  const chunks = entries.map((entry) => {
    const bytes = encoder.encode(entry);
    if (bytes.length > 255) {
      throw new TransportException(
        TransportError.BufferOverrun,
        `TXT entry exceeds 255 bytes: ${entry.slice(0, 32)}…`,
      );
    }
    return bytes;
  });

  const totalLen = chunks.reduce((sum, c) => sum + 1 + c.length, 0);
  if (totalLen > MAX_BEACON_SIZE) {
    throw new TransportException(
      TransportError.BufferOverrun,
      `Beacon exceeds ${MAX_BEACON_SIZE} bytes: ${totalLen}`,
    );
  }

  const buffer = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    buffer[offset] = chunk.length;
    offset += 1;
    buffer.set(chunk, offset);
    offset += chunk.length;
  }

  return buffer;
}

/**
 * Decode a TXT record payload into a beacon.
 *
 * Returns `null` for datagrams that are not well-formed beacons for this
 * service — foreign traffic on port 5353 is common and must be ignored
 * rather than treated as an error.
 */
export function decodeBeacon(buffer: Uint8Array): MdnsBeacon | null {
  if (buffer.length === 0 || buffer.length > MAX_BEACON_SIZE) return null;

  const fields = new Map<string, string>();
  let offset = 0;

  while (offset < buffer.length) {
    const len = buffer[offset]!;
    offset += 1;

    // Truncated record — the declared length runs past the buffer.
    if (len === 0 || offset + len > buffer.length) return null;

    let entry: string;
    try {
      entry = decoder.decode(buffer.subarray(offset, offset + len));
    } catch {
      return null;
    }
    offset += len;

    const eq = entry.indexOf('=');
    if (eq <= 0) return null;
    fields.set(entry.slice(0, eq), entry.slice(eq + 1));
  }

  const service = fields.get('svc');
  const did = fields.get('did');
  const portRaw = fields.get('port');
  const versionRaw = fields.get('ver');

  if (service !== MDNS_SERVICE_ID) return null;
  if (!did || !did.startsWith('did:key:')) return null;
  if (!portRaw || !versionRaw) return null;

  const port = Number(portRaw);
  const version = Number(versionRaw);

  if (!Number.isInteger(port) || port < 1 || port > 65_535) return null;
  if (!Number.isInteger(version) || version < 1) return null;

  return { service, did, port, version };
}
