/**
 * @dicsussion/wot
 *
 * Public API surface for the Web-of-Trust module.
 */

export type { PeerTrustProfile } from './types.js';
export { TIER_QUOTA, TIER_THRESHOLDS, TrustTier } from './types.js';

export { buildProfile, calculateScore, scoreTier } from './score-calculator.js';
