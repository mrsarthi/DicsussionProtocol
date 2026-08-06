/**
 * @dicsussion/sdk — TrustService
 *
 * Public trust API: peer profile lookup, verified-session crediting,
 * and endorsement gifting per RFC 004 §7.2.
 *
 * The service is constructed bare and wired via `attach()`, so it can be
 * used standalone (returning the RFC 004 §8 default profile) without
 * standing up storage.
 */

import type { BlindPublicKey } from '@dicsussion/core/crypto';
import type { WotPeerRecord } from './storage/types.js';
import { buildProfile } from './wot/score-calculator.js';
import type { SessionMessage } from './wot/session-tracker.js';
import type { SessionTracker } from './wot/session-tracker.js';
import type { TrustStore } from './wot/trust-store.js';
import type { PeerTrustProfile } from './wot/types.js';
import type { PendingVoucher, VoucherToken } from './wot/voucher-service.js';
import type { VoucherService } from './wot/voucher-service.js';

/** Collaborators supplied once the engine is running. */
export interface TrustServiceDeps {
  readonly store: TrustStore;
  readonly vouchers: VoucherService;
  readonly sessions: SessionTracker;
  /** This node's identity commitment, bound into redemption nullifiers. */
  readonly getLocalCommitment: () => bigint;
}

/**
 * Trust service for querying and managing peer reputation.
 */
export class TrustService {
  private deps: TrustServiceDeps | null = null;

  /** Wire the service to the running engine. */
  attach(deps: TrustServiceDeps): void {
    this.deps = deps;
  }

  /**
   * Get the local trust profile for a peer.
   *
   * Unknown peers resolve to the S_base = 0 untrusted profile rather
   * than an error (RFC 004 §8).
   *
   * @param peerDid The peer's did:key identifier.
   */
  async getProfile(peerDid: string): Promise<PeerTrustProfile> {
    if (!this.deps) return buildProfile(peerDid, 0, 0, 0, false);

    const record = await this.deps.store.get(peerDid);
    return buildProfile(
      record.did || peerDid,
      record.verifiedSessions,
      record.vouchersRedeemed,
      record.vouchersIssued,
      record.isBlacklisted,
    );
  }

  /** Raw counters behind a peer's score. */
  async getCounters(peerDid: string): Promise<WotPeerRecord | null> {
    if (!this.deps) return null;
    return this.deps.store.get(peerDid);
  }

  /**
   * Record a message toward a verified bidirectional session.
   *
   * When the RFC 004 §6.2 conditions are all met the peer is credited
   * +10 POC exactly once, then the accumulator resets.
   *
   * @returns True if this message completed a newly credited session.
   */
  async recordSessionMessage(message: SessionMessage): Promise<boolean> {
    const deps = this.requireDeps();

    const evaluation = deps.sessions.record(message);
    if (!evaluation.credited) return false;

    await deps.store.creditVerifiedSession(message.peerDid, message.timestamp);
    return true;
  }

  /**
   * Begin gifting a +5 POC blind endorsement voucher to a peer.
   *
   * Returns the blinded request to transmit on Stream 0x04. The issuer
   * never sees the serial, so the endorsement edge stays private.
   *
   * @param issuerPublicKey The issuing peer's RSA public key.
   * @param scope Redemption scope bound into the nullifier.
   */
  beginVoucherRequest(
    issuerPublicKey: BlindPublicKey,
    scope: bigint,
  ): PendingVoucher {
    return this.requireDeps().vouchers.requestVoucher(issuerPublicKey, scope);
  }

  /**
   * Sign a peer's blinded voucher request, burning 2 POC of our own score.
   *
   * @param blinded The peer's blinded value.
   * @param epoch Current epoch, for issuance quota accounting.
   * @param selfDid Our own did:key, against which the cost is recorded.
   */
  async issueEndorsement(
    blinded: bigint,
    epoch: number,
    selfDid: string,
    now: number = Date.now(),
  ): Promise<bigint> {
    const deps = this.requireDeps();

    const { blindSignature } = deps.vouchers.issueVoucher(blinded, epoch, now);
    await deps.store.debitVoucherIssued(selfDid, Math.floor(now / 1000));

    return blindSignature;
  }

  /**
   * Unblind an issuer's response into a redeemable voucher.
   */
  completeVoucher(
    pending: PendingVoucher,
    blindSignature: bigint,
  ): VoucherToken {
    return this.requireDeps().vouchers.completeVoucher(pending, blindSignature);
  }

  /**
   * Redeem a voucher, crediting +5 POC to the issuing peer's profile.
   *
   * @param token The unblinded voucher.
   * @param creditTo The peer whose local score should rise.
   * @returns True if the voucher was accepted.
   */
  async redeemVoucher(
    token: VoucherToken,
    creditTo: string,
    now: number = Math.floor(Date.now() / 1000),
  ): Promise<boolean> {
    const deps = this.requireDeps();

    const result = deps.vouchers.redeemVoucher(token, deps.getLocalCommitment());
    if (!result.accepted) return false;

    await deps.store.creditVoucherRedeemed(creditTo, now);
    return true;
  }

  /**
   * Blacklist a peer, driving its local score to −∞.
   *
   * Invoked when a peer's RLN nullifiers reveal double-spending
   * (RFC 004 §6.1).
   */
  async blacklist(
    peerDid: string,
    now: number = Math.floor(Date.now() / 1000),
  ): Promise<void> {
    await this.requireDeps().store.blacklist(peerDid, now);
  }

  /**
   * Gift a +5 POC blind endorsement voucher to a peer.
   *
   * Kept for the RFC 004 §7.2 surface. The full exchange is synchronous
   * and requires a live Stream 0x04 connection, so callers driving it
   * themselves should use `beginVoucherRequest` / `issueEndorsement` /
   * `completeVoucher` / `redeemVoucher` directly.
   */
  async giftEndorsement(_recipientDid: string): Promise<void> {
    throw new Error(
      'giftEndorsement requires a live Stream 0x04 voucher handshake; ' +
        'drive it via beginVoucherRequest/issueEndorsement/completeVoucher',
    );
  }

  private requireDeps(): TrustServiceDeps {
    if (!this.deps) {
      throw new Error(
        'TrustService is not attached to a running client. Use DicsussionClient.init().',
      );
    }
    return this.deps;
  }
}
