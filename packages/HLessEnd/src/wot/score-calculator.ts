/**
 * @dicsussion/wot — Local Trust Score Calculator
 *
 * Subjective peer trust score computation per RFC 004 §6.1:
 *   S(P) = 10 × C_verified + 5 × V_valid − 2 × I_issued
 *
 * All scores are local and subjective — no global ledger.
 */

import { TIER_THRESHOLDS, TrustTier } from './types.js';
import type { PeerTrustProfile } from './types.js';

/** Score weights per RFC 004 §6.1. */
const WEIGHT_VERIFIED_SESSION = 10;
const WEIGHT_VOUCHER_REDEEMED = 5;
const WEIGHT_VOUCHER_ISSUED = 2;

/**
 * Calculate the subjective trust score for a peer.
 *
 * S(P) = 10 × C_verified + 5 × V_valid − 2 × I_issued
 *
 * @param verifiedSessions Number of verified bidirectional chat sessions.
 * @param vouchersRedeemed Number of redeemed +5 POC blind vouchers.
 * @param vouchersIssued Number of vouchers issued by this peer.
 * @returns The computed subjective trust score (can be negative).
 */
export function calculateScore(
  verifiedSessions: number,
  vouchersRedeemed: number,
  vouchersIssued: number,
): number {
  return (
    WEIGHT_VERIFIED_SESSION * verifiedSessions +
    WEIGHT_VOUCHER_REDEEMED * vouchersRedeemed -
    WEIGHT_VOUCHER_ISSUED * vouchersIssued
  );
}

/**
 * Determine the trust tier for a given score.
 *
 * @param score The subjective trust score.
 * @returns The corresponding TrustTier.
 */
export function scoreTier(score: number): TrustTier {
  if (score >= TIER_THRESHOLDS[TrustTier.HighReputation]) return TrustTier.HighReputation;
  if (score >= TIER_THRESHOLDS[TrustTier.Established]) return TrustTier.Established;
  if (score >= TIER_THRESHOLDS[TrustTier.Standard]) return TrustTier.Standard;
  return TrustTier.Untrusted;
}

/**
 * Build a complete PeerTrustProfile from interaction counters.
 *
 * @param did The peer's did:key identifier.
 * @param verifiedSessions Number of verified sessions.
 * @param vouchersRedeemed Number of redeemed vouchers.
 * @param vouchersIssued Number of issued vouchers.
 * @param isBlacklisted Whether the peer has been slashed.
 * @returns A full PeerTrustProfile.
 */
export function buildProfile(
  did: string,
  verifiedSessions: number,
  vouchersRedeemed: number,
  vouchersIssued: number,
  isBlacklisted: boolean = false,
): PeerTrustProfile {
  const subjectiveScore = isBlacklisted
    ? -Infinity
    : calculateScore(verifiedSessions, vouchersRedeemed, vouchersIssued);

  return {
    did,
    subjectiveScore,
    tier: isBlacklisted ? TrustTier.Untrusted : scoreTier(subjectiveScore),
    isBlacklisted,
  };
}
