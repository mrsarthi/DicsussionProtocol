/**
 * @dicsussion/wot — Synchronous Voucher Handshake (Stream 0x04)
 *
 * Drives the live request/response exchange described in RFC 003 §5 and
 * RFC 001 §6 sub-stream `0x04`.
 *
 *   requester → issuer : VOUCHER_REQUEST  { blinded }
 *   issuer    → requester : VOUCHER_RESPONSE { sig, n, e }  (or REJECT)
 *
 * The exchange is synchronous by design, so at most one request per peer
 * is in flight; a second concurrent request would be unable to tell the
 * two responses apart without adding a correlation id to the wire format.
 */

import type { IConnection } from '@dicsussion/core/transport';
import { StreamType } from '@dicsussion/core/transport';
import type { PendingVoucher, VoucherToken } from './voucher-service.js';
import type { VoucherService } from './voucher-service.js';
import type { VoucherMessage } from './voucher-protocol.js';
import {
  decodeVoucherMessage,
  encodeVoucherMessage,
  VoucherRejectReason,
} from './voucher-protocol.js';

/** Default time a requester waits for an issuer's response. */
export const VOUCHER_HANDSHAKE_TIMEOUT_MS = 5_000;

/** An in-flight request awaiting its response. */
interface InFlight {
  readonly pending: PendingVoucher;
  readonly resolve: (token: VoucherToken) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

export interface VoucherHandshakeDeps {
  readonly vouchers: VoucherService;
  /** Current 10-second epoch, for issuance quota accounting. */
  readonly currentEpoch: () => number;
  /** Called after we successfully issue, so the −2 POC cost is recorded. */
  readonly onIssued: () => Promise<void>;
  /**
   * Materialise the issuer keypair before answering a request.
   *
   * The keypair is generated lazily, so without this an inbound request
   * arriving before anything else touched the key would be declined as
   * `UNKNOWN_PEER` — refusing to issue with a key we are perfectly able
   * to produce.
   */
  readonly ensureIssuerKey?: () => Promise<void>;
  /** Handshake timeout override. */
  readonly timeoutMs?: number;
}

/**
 * Coordinates blind-voucher exchanges over live connections.
 */
export class VoucherHandshake {
  private readonly inFlight = new Map<string, InFlight>();
  private readonly timeoutMs: number;

  constructor(private readonly deps: VoucherHandshakeDeps) {
    this.timeoutMs = deps.timeoutMs ?? VOUCHER_HANDSHAKE_TIMEOUT_MS;
  }

  /**
   * Ask a connected peer to blind-sign an endorsement voucher.
   *
   * The issuer's public key must already be known — blinding happens
   * before the request goes out, so it cannot be learned from the
   * response. Peers exchange it during pairing, alongside the X25519
   * encryption key.
   *
   * @param connection Live connection to the issuing peer.
   * @param issuerPublicKey The issuer's RSA public key.
   * @param scope Redemption scope bound into the nullifier.
   * @returns The unblinded, verified voucher.
   * @throws If a request to this peer is already in flight, the peer
   *   rejects, or the response does not arrive in time.
   */
  async request(
    connection: IConnection,
    issuerPublicKey: { n: bigint; e: bigint },
    scope: bigint,
  ): Promise<VoucherToken> {
    const peerDid = connection.peerDid;

    if (this.inFlight.has(peerDid)) {
      throw new Error(
        `A voucher request to ${peerDid} is already in flight; the 0x04 handshake is synchronous`,
      );
    }

    const pending = this.deps.vouchers.requestVoucher(issuerPublicKey, scope);

    const token = new Promise<VoucherToken>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inFlight.delete(peerDid);
        reject(
          new Error(`Voucher handshake with ${peerDid} timed out after ${this.timeoutMs}ms`),
        );
      }, this.timeoutMs);
      timer.unref?.();

      this.inFlight.set(peerDid, { pending, resolve, reject, timer });
    });

    await connection.send(
      StreamType.VOUCHER_HANDSHAKE,
      encodeVoucherMessage({ type: 'request', blinded: pending.blinded }),
    );

    return token;
  }

  /**
   * Handle an inbound Stream 0x04 frame.
   *
   * @param payload Raw frame payload.
   * @param connection The connection it arrived on.
   */
  async handleMessage(payload: Uint8Array, connection: IConnection): Promise<void> {
    let message: VoucherMessage;
    try {
      message = decodeVoucherMessage(payload);
    } catch {
      // Malformed frames are dropped, never fatal (RFC 001 §7).
      return;
    }

    switch (message.type) {
      case 'request':
        await this.handleRequest(message.blinded, connection);
        break;
      case 'response':
        this.handleResponse(message, connection.peerDid);
        break;
      case 'reject':
        this.handleReject(message.reason, connection.peerDid);
        break;
    }
  }

  /** Whether a request to this peer is currently awaiting a response. */
  isPending(peerDid: string): boolean {
    return this.inFlight.has(peerDid);
  }

  /** Fail and clear every in-flight request. */
  cancelAll(reason = 'Voucher handshake cancelled'): void {
    for (const [peerDid, entry] of this.inFlight) {
      clearTimeout(entry.timer);
      entry.reject(new Error(`${reason} (${peerDid})`));
    }
    this.inFlight.clear();
  }

  /** Issuer side: blind-sign the request, or decline. */
  private async handleRequest(
    blinded: bigint,
    connection: IConnection,
  ): Promise<void> {
    const epoch = this.deps.currentEpoch();

    await this.deps.ensureIssuerKey?.();

    if (!this.deps.vouchers.canIssue) {
      await this.sendReject(connection, VoucherRejectReason.UNKNOWN_PEER);
      return;
    }
    if (!this.deps.vouchers.hasIssuanceQuota(epoch)) {
      await this.sendReject(connection, VoucherRejectReason.QUOTA_EXHAUSTED);
      return;
    }

    let blindSignature: bigint;
    try {
      ({ blindSignature } = this.deps.vouchers.issueVoucher(blinded, epoch));
    } catch {
      await this.sendReject(connection, VoucherRejectReason.MALFORMED_REQUEST);
      return;
    }

    // Issuance burns 2 POC of our own score (RFC 003 §5.2).
    await this.deps.onIssued();

    const issuerKey = this.deps.vouchers.issuerPublicKey();
    if (!issuerKey) {
      await this.sendReject(connection, VoucherRejectReason.UNKNOWN_PEER);
      return;
    }

    await connection.send(
      StreamType.VOUCHER_HANDSHAKE,
      encodeVoucherMessage({
        type: 'response',
        blindSignature,
        modulus: issuerKey.n,
        exponent: issuerKey.e,
      }),
    );
  }

  /** Requester side: unblind and settle the pending promise. */
  private handleResponse(
    message: { blindSignature: bigint; modulus: bigint; exponent: bigint },
    peerDid: string,
  ): void {
    const entry = this.inFlight.get(peerDid);
    if (!entry) return;

    this.inFlight.delete(peerDid);
    clearTimeout(entry.timer);

    try {
      entry.resolve(
        this.deps.vouchers.completeVoucher(entry.pending, message.blindSignature),
      );
    } catch (err) {
      entry.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private handleReject(reason: string, peerDid: string): void {
    const entry = this.inFlight.get(peerDid);
    if (!entry) return;

    this.inFlight.delete(peerDid);
    clearTimeout(entry.timer);
    entry.reject(new Error(`Peer ${peerDid} declined to issue a voucher: ${reason}`));
  }

  private async sendReject(
    connection: IConnection,
    reason: string,
  ): Promise<void> {
    await connection.send(
      StreamType.VOUCHER_HANDSHAKE,
      encodeVoucherMessage({ type: 'reject', reason }),
    );
  }
}
