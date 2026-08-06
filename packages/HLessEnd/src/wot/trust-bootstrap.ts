/**
 * @dicsussion/wot — Trust Stack Assembly
 *
 * Builds and wires the Web-of-Trust components (RFC 003 §5, RFC 004 §6)
 * so the client facade stays an API surface rather than an assembler.
 */

import type { IStorageDriver } from '../storage/types.js';
import type { TrustService } from '../trust-service.js';
import { SessionTracker } from './session-tracker.js';
import { TrustStore } from './trust-store.js';
import { VoucherHandshake } from './voucher-handshake.js';
import { VoucherService } from './voucher-service.js';
import { VoucherStore } from './voucher-store.js';

/** Identity material the trust stack needs. */
export interface TrustIdentity {
  readonly did: string;
  readonly identitySecret: bigint;
  readonly commitment: bigint;
  readonly blindKeypair: { n: bigint; e: bigint; d: bigint } | null;
}

/** The assembled, already-attached trust components. */
export interface TrustStack {
  readonly store: TrustStore;
  readonly vouchers: VoucherService;
  readonly handshake: VoucherHandshake;
  readonly sessions: SessionTracker;
  readonly voucherStore: VoucherStore;
  /** Spent nullifiers restored from disk at boot. */
  readonly restoredNullifiers: number;
}

export interface TrustStackOptions {
  readonly storage: IStorageDriver;
  readonly trust: TrustService;
  /** Resolves the live local identity on each use, never a stale copy. */
  readonly getIdentity: () => TrustIdentity;
  /** Current 10-second epoch, for issuance quota accounting. */
  readonly currentEpoch: () => number;
  /** Produce the RSA blind-signing keypair, generating it on first use. */
  readonly ensureBlindKeypair?: () => Promise<{
    n: bigint;
    e: bigint;
    d: bigint;
  }>;
}

/**
 * Construct the trust stack and attach it to a TrustService.
 *
 * The voucher service is seeded with this identity's blind-signing key
 * so the node can act as an issuer, and with its RLN secret so issuance
 * nullifiers are bound to it.
 */
export async function createTrustStack(
  options: TrustStackOptions,
): Promise<TrustStack> {
  const identity = options.getIdentity();

  const store = new TrustStore(options.storage);
  const voucherStore = new VoucherStore(options.storage);

  // Replay protection must be in memory before the voucher service can
  // accept anything (RFC 003 §8 `ReplayedVoucher`).
  await voucherStore.hydrate();

  const vouchers = new VoucherService({
    issuerKeypair: identity.blindKeypair ?? undefined,
    identitySecret: identity.identitySecret,
    onNullifierSpent: (nullifier, scope) => {
      voucherStore.recordSpent(nullifier, scope, Math.floor(Date.now() / 1000));
    },
  });

  // Restore replay protection before any redemption can be attempted.
  // Skipping this would make every previously redeemed voucher spendable
  // again after a restart (RFC 003 §8 `ReplayedVoucher`).
  const restored = voucherStore.loadAllNullifiers();
  vouchers.loadSpentNullifiers(restored.map((entry) => entry.nullifier));

  const sessions = new SessionTracker({ localDid: identity.did });

  const handshake = new VoucherHandshake({
    vouchers,
    currentEpoch: options.currentEpoch,
    ensureIssuerKey: async () => {
      if (vouchers.canIssue) return;

      const keypair = await options.ensureBlindKeypair?.();
      if (keypair) vouchers.setIssuerKeypair(keypair);
    },
    onIssued: async () => {
      // RFC 003 §5.2: issuance burns 2 POC on the issuer's own books.
      await store.debitVoucherIssued(
        options.getIdentity().did,
        Math.floor(Date.now() / 1000),
      );
    },
  });

  options.trust.attach({
    store,
    vouchers,
    sessions,
    getLocalCommitment: () => options.getIdentity().commitment,
  });

  return {
    store,
    vouchers,
    handshake,
    sessions,
    voucherStore,
    restoredNullifiers: restored.length,
  };
}
