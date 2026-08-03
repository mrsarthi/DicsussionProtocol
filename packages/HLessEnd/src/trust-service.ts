/**
 * @dicsussion/sdk — TrustService
 *
 * Public trust API: peer profile lookup and endorsement gifting
 * per RFC 004 §7.2.
 */

import { buildProfile } from './wot/score-calculator.js';
import type { PeerTrustProfile } from './wot/types.js';

/**
 * Trust service for querying and managing peer reputation.
 */
export class TrustService {
  /**
   * Get the local trust profile for a peer.
   *
   * @param peerDid The peer's did:key identifier.
   * @returns The computed PeerTrustProfile.
   */
  async getProfile(peerDid: string): Promise<PeerTrustProfile> {
    // Phase 1A: return default untrusted profile
    // Full implementation queries storage for interaction counters
    return buildProfile(peerDid, 0, 0, 0, false);
  }

  /**
   * Gift a +5 POC blind endorsement voucher to a peer.
   * Costs 2 POC to the issuer to prevent voucher farming.
   */
  async giftEndorsement(_recipientDid: string): Promise<void> {
    throw new Error('TrustService.giftEndorsement not yet implemented');
  }
}
