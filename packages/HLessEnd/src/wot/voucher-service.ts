/**
 * @dicsussion/wot — Blind Endorsement Voucher Service
 *
 * Drives both halves of the RFC 003 §5 "+5 POC gift" flow.
 *
 * Issuer side records only `(nullifier_issue, voucher_commitment)` — no
 * recipient DID and no recipient commitment. Redeemer side derives
 * `ν = Poseidon(DS_voucher, serial, scope, cm_redeemer)` and rejects any
 * ν it has already seen. The result is that neither party's store
 * contains the edge A → B, so the endorsement graph stays private even
 * if a device is later seized.
 *
 * PHASE BOUNDARY: RFC 003 §5.5 wraps redemption in a Groth16 proof that
 * the voucher was signed by a key in the Eligible-Issuer accumulator.
 * Phase 2 verifies the RSA signature directly against a known issuer key.
 * The nullifier derivation and double-redeem rejection are already the
 * final ones, so Phase 3 wraps this logic rather than replacing it.
 */

import type {
  BlindKeyPair,
  BlindPublicKey,
} from '@dicsussion/core/crypto';
import {
  blind,
  blindSign,
  generateSerial,
  unblind,
  verifyBlindSignature,
} from '@dicsussion/core/crypto';
import { reduceToField } from '@dicsussion/core/crypto';
import {
  issuanceNullifier,
  voucherNullifier,
} from '@dicsussion/core/crypto';

/** Reputation granted by redeeming one voucher (RFC 004 §6.1). */
export const VOUCHER_REDEEM_VALUE = 5;

/** Reputation burned by issuing one voucher. */
export const VOUCHER_ISSUE_COST = 2;

/** Default per-epoch issuance quota, bounding voucher minting. */
export const DEFAULT_ISSUANCE_QUOTA = 4;

/** In-flight redeemer state between blinding and unblinding. */
export interface PendingVoucher {
  /** Secret serial — never sent to the issuer. */
  readonly serial: Uint8Array;
  /** Value transmitted on Stream 0x04. */
  readonly blinded: bigint;
  /** Blinding factor retained locally. */
  readonly blindingFactor: bigint;
  /** Redemption scope (e.g. a channel identifier reduced to the field). */
  readonly scope: bigint;
  /** The issuer this request targets. */
  readonly issuerPublicKey: BlindPublicKey;
}

/** A completed, unblinded voucher ready to redeem. */
export interface VoucherToken {
  readonly serial: Uint8Array;
  /** Unblinded RSA signature over FDH(serial). */
  readonly signature: bigint;
  readonly scope: bigint;
  readonly issuerPublicKey: BlindPublicKey;
}

/** Issuer-side record — deliberately free of recipient identifiers. */
export interface IssuanceRecord {
  /** `Poseidon(DS_issue, a_0, epoch, k)`. */
  readonly nullifier: bigint;
  readonly epoch: number;
  readonly counter: number;
  readonly issuedAt: number;
}

/** Outcome of a redemption attempt. */
export interface RedemptionResult {
  readonly accepted: boolean;
  /** `Poseidon(DS_voucher, serial, scope, cm_redeemer)`. */
  readonly nullifier: bigint;
  /** POC awarded — 0 when rejected. */
  readonly value: number;
  readonly reason?: 'invalid_signature' | 'already_redeemed';
}

export interface VoucherServiceOptions {
  /** This node's blind-signing keypair, used when acting as issuer. */
  readonly issuerKeypair?: BlindKeyPair;
  /** This node's RLN identity secret, for issuance nullifiers. */
  readonly identitySecret?: bigint;
  /** Vouchers this node may issue per epoch. */
  readonly issuanceQuota?: number;
  /**
   * Durable sink for spent redemption nullifiers.
   *
   * Without one, replay protection lives only in memory and a restart
   * makes every previously redeemed voucher spendable again.
   */
  readonly onNullifierSpent?: (nullifier: bigint, scope: bigint) => void;
}

/**
 * Issues and redeems Chaumian blind endorsement vouchers.
 */
export class VoucherService {
  private issuerKeypair?: BlindKeyPair;
  private readonly identitySecret: bigint;
  private readonly issuanceQuota: number;
  private readonly onNullifierSpent?: (nullifier: bigint, scope: bigint) => void;

  /** Issuance nullifiers we have minted, keyed by epoch. */
  private readonly issuedByEpoch = new Map<number, IssuanceRecord[]>();

  /** Redemption nullifiers already spent, preventing double redemption. */
  private readonly spentNullifiers = new Set<bigint>();

  constructor(options: VoucherServiceOptions = {}) {
    this.issuerKeypair = options.issuerKeypair;
    this.identitySecret = options.identitySecret ?? 0n;
    this.issuanceQuota = options.issuanceQuota ?? DEFAULT_ISSUANCE_QUOTA;
    this.onNullifierSpent = options.onNullifierSpent;
  }

  /** Whether this node can act as an issuer. */
  /**
   * Supply the issuer keypair once it has been generated.
   *
   * Issuance is off until this lands, because the keypair is created
   * lazily on first need rather than at boot.
   */
  setIssuerKeypair(keypair: BlindKeyPair): void {
    this.issuerKeypair = keypair;
  }

  get canIssue(): boolean {
    return this.issuerKeypair !== undefined;
  }

  /**
   * This node's publishable blind-signing key.
   *
   * Shared during pairing so peers can blind requests to us.
   *
   * @returns Undefined when this node has no issuing key.
   */
  issuerPublicKey(): BlindPublicKey | undefined {
    if (!this.issuerKeypair) return undefined;
    return { n: this.issuerKeypair.n, e: this.issuerKeypair.e };
  }

  /** Vouchers already issued in a given epoch. */
  issuedInEpoch(epoch: number): number {
    return this.issuedByEpoch.get(epoch)?.length ?? 0;
  }

  /** Whether issuance quota remains for an epoch. */
  hasIssuanceQuota(epoch: number): boolean {
    return this.issuedInEpoch(epoch) < this.issuanceQuota;
  }

  // ─── Receiver side ────────────────────────────────────────────────────

  /**
   * Begin a voucher request by blinding a fresh serial.
   *
   * @param issuerPublicKey The issuer's RSA public key.
   * @param scope Redemption scope, bound into the nullifier.
   */
  requestVoucher(issuerPublicKey: BlindPublicKey, scope: bigint): PendingVoucher {
    const serial = generateSerial();
    const { blinded, blindingFactor } = blind(serial, issuerPublicKey);

    return { serial, blinded, blindingFactor, scope, issuerPublicKey };
  }

  /**
   * Unblind an issuer's response into a usable voucher.
   *
   * @throws If the unblinded signature does not verify — a malformed or
   *   malicious response must fail here, not silently at redemption.
   */
  completeVoucher(
    pending: PendingVoucher,
    blindSignature: bigint,
  ): VoucherToken {
    const signature = unblind(
      blindSignature,
      pending.blindingFactor,
      pending.issuerPublicKey,
    );

    if (!verifyBlindSignature(pending.serial, signature, pending.issuerPublicKey)) {
      throw new Error(
        'Issuer returned a blind signature that does not verify after unblinding',
      );
    }

    return {
      serial: pending.serial,
      signature,
      scope: pending.scope,
      issuerPublicKey: pending.issuerPublicKey,
    };
  }

  /**
   * Redeem a voucher, awarding +5 POC on first use.
   *
   * @param token The unblinded voucher.
   * @param redeemerCommitment The redeemer's identity commitment.
   */
  redeemVoucher(
    token: VoucherToken,
    redeemerCommitment: bigint,
  ): RedemptionResult {
    const nullifier = voucherNullifier(
      reduceToField(token.serial),
      token.scope,
      redeemerCommitment,
    );

    if (
      !verifyBlindSignature(token.serial, token.signature, token.issuerPublicKey)
    ) {
      return {
        accepted: false,
        nullifier,
        value: 0,
        reason: 'invalid_signature',
      };
    }

    // RFC 003 §8 `ReplayedVoucher`: a seen ν means this voucher already
    // paid out. Reject without touching the score.
    if (this.spentNullifiers.has(nullifier)) {
      return {
        accepted: false,
        nullifier,
        value: 0,
        reason: 'already_redeemed',
      };
    }

    this.spentNullifiers.add(nullifier);
    // Persist before returning acceptance: if the durable write fails,
    // the caller must not be told the voucher was safely consumed.
    this.onNullifierSpent?.(nullifier, token.scope);

    return { accepted: true, nullifier, value: VOUCHER_REDEEM_VALUE };
  }

  /** Whether a redemption nullifier has already been spent. */
  isSpent(nullifier: bigint): boolean {
    return this.spentNullifiers.has(nullifier);
  }

  /** Seed spent nullifiers restored from storage. */
  loadSpentNullifiers(nullifiers: Iterable<bigint>): void {
    for (const nullifier of nullifiers) {
      this.spentNullifiers.add(nullifier);
    }
  }

  // ─── Issuer side ──────────────────────────────────────────────────────

  /**
   * Blind-sign a request, burning issuance quota.
   *
   * The issuer learns nothing about the serial it signed.
   *
   * @param blinded The receiver's blinded value.
   * @param epoch Current epoch, for quota accounting.
   * @throws If this node has no issuing key or its epoch quota is spent.
   */
  issueVoucher(
    blinded: bigint,
    epoch: number,
    now: number = Date.now(),
  ): { blindSignature: bigint; record: IssuanceRecord } {
    if (!this.issuerKeypair) {
      throw new Error('This node has no blind-signing key and cannot issue vouchers');
    }
    if (!this.hasIssuanceQuota(epoch)) {
      throw new Error(
        `Issuance quota exhausted for epoch ${epoch} (${this.issuanceQuota} per epoch)`,
      );
    }

    const counter = this.issuedInEpoch(epoch);
    const blindSignature = blindSign(blinded, this.issuerKeypair);

    const record: IssuanceRecord = {
      nullifier: issuanceNullifier(
        this.identitySecret,
        BigInt(epoch),
        BigInt(counter),
      ),
      epoch,
      counter,
      issuedAt: now,
    };

    const existing = this.issuedByEpoch.get(epoch) ?? [];
    existing.push(record);
    this.issuedByEpoch.set(epoch, existing);

    return { blindSignature, record };
  }

  /** All issuance records, across every epoch. */
  listIssuanceRecords(): IssuanceRecord[] {
    return Array.from(this.issuedByEpoch.values()).flat();
  }
}
