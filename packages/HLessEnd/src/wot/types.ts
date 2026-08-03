/**
 * @dicsussion/wot — Type Definitions
 *
 * Trust profile and tier types per RFC 004 §6.
 */

/** Trust tier thresholds matching RFC 003 §3.2. */
export enum TrustTier {
  /** 0–49 POC: 1 msg/10s */
  Untrusted = 0,
  /** 50–99 POC: 3 msgs/10s */
  Standard = 1,
  /** 100–199 POC: 10 msgs/10s */
  Established = 2,
  /** ≥200 POC: Unrestricted */
  HighReputation = 3,
}

/** Trust tier score thresholds. */
export const TIER_THRESHOLDS = {
  [TrustTier.Untrusted]: 0,
  [TrustTier.Standard]: 50,
  [TrustTier.Established]: 100,
  [TrustTier.HighReputation]: 200,
} as const;

/** Epoch quota per tier (messages per 10s epoch). */
export const TIER_QUOTA = {
  [TrustTier.Untrusted]: 1,
  [TrustTier.Standard]: 3,
  [TrustTier.Established]: 10,
  [TrustTier.HighReputation]: 100, // "Unrestricted" capped at 100 for safety
} as const;

/** Local trust profile for a peer. */
export interface PeerTrustProfile {
  readonly did: string;
  readonly subjectiveScore: number;
  readonly tier: TrustTier;
  readonly isBlacklisted: boolean;
}
