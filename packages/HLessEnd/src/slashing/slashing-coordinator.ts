/**
 * @dicsussion/slashing — Live Slashing Coordinator
 *
 * Connects the detection machinery to real traffic: consumes RLN shares
 * from Stream `0x06`, and publishes/consumes revocation tombstones on
 * Stream `0x03`.
 *
 * Detection is a side effect of ordinary participation — every node runs
 * this against traffic it already receives, so there is no committee to
 * bribe and no single observer to take offline. The first honest node to
 * see both halves of a double-send can slash.
 *
 * Inbound tombstones are verified *before* they blacklist anyone
 * (RFC 003 §8 `InvalidTombstone`). A tombstone is a permanent, gossiped
 * accusation, so accepting one on the strength of its signature alone
 * would let any peer silence any other.
 */

import type { IConnection } from '@dicsussion/core/transport';
import { StreamType } from '@dicsussion/core/transport';
import type { Ed25519KeyPair } from '@dicsussion/core/transport';
import {
  decodeShareMessage,
  decodeTombstone,
  encodeShare,
  encodeTombstone,
} from './gossip-protocol.js';
import type { ObservedShare, SlashingEvidence } from './share-collector.js';
import { ShareCollector } from './share-collector.js';
import type { RevocationTombstone } from './tombstone.js';
import { createSlashingTombstone, verifyTombstone } from './tombstone.js';

/** Emitted when this node detects and revokes an offender. */
export interface SlashingEvent {
  readonly tombstone: RevocationTombstone;
  /** Absent for voluntary revocations, which carry no evidence. */
  readonly evidence: SlashingEvidence | undefined;
  /** True when this node produced the tombstone rather than receiving it. */
  readonly local: boolean;
}

export interface SlashingCoordinatorDeps {
  /** This node's signing keypair and did:key, for authoring tombstones. */
  readonly validator: () => { keypair: Ed25519KeyPair; did: string };
  /** Live connections to gossip over. */
  readonly connections: () => Iterable<IConnection>;
  /**
   * Blacklist a revoked identity commitment.
   *
   * Called only after `verifyTombstone` passes.
   */
  readonly onRevoked: (tombstone: RevocationTombstone) => Promise<void>;
  /**
   * Resolve an offender's trapdoor so `cm_identity` can be bound.
   *
   * Returns undefined when unknown, in which case no tombstone is
   * published — an unverifiable accusation is worse than none.
   */
  readonly resolveTrapdoor?: (identitySecret: bigint) => bigint | undefined;
}

/**
 * Routes Stream 0x03 / 0x06 traffic into the slashing pipeline.
 */
export class SlashingCoordinator {
  private readonly collector = new ShareCollector();
  private readonly handlers: Array<(event: SlashingEvent) => void> = [];
  /** Commitments already revoked, so a gossiped tombstone is applied once. */
  private readonly revoked = new Set<bigint>();

  constructor(private readonly deps: SlashingCoordinatorDeps) {}

  /** Subscribe to slashing events. @returns Unsubscribe function. */
  onSlashing(handler: (event: SlashingEvent) => void): () => void {
    this.handlers.push(handler);
    return () => {
      const i = this.handlers.indexOf(handler);
      if (i >= 0) this.handlers.splice(i, 1);
    };
  }

  /** Whether a commitment has been revoked. */
  isRevoked(commitment: bigint): boolean {
    return this.revoked.has(commitment);
  }

  /** Distinct nullifiers currently tracked. */
  get trackedNullifiers(): number {
    return this.collector.trackedNullifiers;
  }

  /**
   * Publish one of our own shares so peers can police us too.
   *
   * Broadcasting our shares is what makes the scheme symmetric: a node
   * that withheld them could overspend undetected.
   */
  async broadcastShare(share: ObservedShare): Promise<void> {
    const frame = encodeShare(share);

    await Promise.all(
      Array.from(this.deps.connections(), (connection) =>
        connection.send(StreamType.RLN_SHARE_EXCHANGE, frame),
      ),
    );
  }

  /**
   * Apply a voluntary revocation authored by this node — locally only.
   *
   * **Deliberately not gossiped.** A `USER_REVOKED` tombstone proves
   * nothing about who owns the commitment it names, so peers reject it
   * (`verifyTombstone` → `unprovable-ownership`). Broadcasting it would
   * be noise at best; honouring it would be an authorization bypass,
   * since commitments are public and anyone could revoke anyone.
   *
   * To make peers stop counting this identity as a member, leave the
   * channels — `GroupService.leaveGroup` announces a departure bound to
   * this node's did:key, which *is* verifiable.
   */
  async applyLocalRevocation(tombstone: RevocationTombstone): Promise<void> {
    this.revoked.add(tombstone.membershipCommitment);
    await this.deps.onRevoked(tombstone);

    for (const handler of this.handlers) {
      handler({ tombstone, evidence: undefined, local: true });
    }
  }

  /**
   * Observe a share that arrived attached to a message.
   *
   * Same detection path as gossiped shares — a message-borne share is
   * evidence exactly like any other, and this is what makes the rate
   * limit enforceable on ordinary traffic rather than only on explicit
   * `0x06` gossip.
   *
   * @returns Evidence if this share completed a violation.
   */
  async handleObservedShare(
    share: ObservedShare,
  ): Promise<SlashingEvidence | undefined> {
    const evidence = this.collector.observe(share);
    if (evidence) await this.publishTombstone(evidence);
    return evidence;
  }

  /**
   * Handle an inbound Stream 0x06 frame.
   *
   * @returns Evidence if this share completed a violation.
   */
  async handleShareFrame(payload: Uint8Array): Promise<SlashingEvidence | undefined> {
    let shares: ObservedShare[];
    try {
      shares = decodeShareMessage(payload);
    } catch {
      // Malformed gossip is dropped, never fatal (RFC 001 §7).
      return undefined;
    }

    for (const share of shares) {
      const evidence = this.collector.observe(share);
      if (evidence) {
        await this.publishTombstone(evidence);
        return evidence;
      }
    }

    return undefined;
  }

  /**
   * Handle an inbound Stream 0x03 tombstone.
   *
   * @returns True if the tombstone was accepted and applied.
   */
  async handleTombstoneFrame(payload: Uint8Array): Promise<boolean> {
    let tombstone: RevocationTombstone;
    try {
      tombstone = decodeTombstone(payload);
    } catch {
      return false;
    }

    // Evidence, not authority: a valid signature over fabricated shares
    // is still rejected.
    if (!verifyTombstone(tombstone).valid) return false;

    if (this.revoked.has(tombstone.membershipCommitment)) return true;
    this.revoked.add(tombstone.membershipCommitment);

    await this.deps.onRevoked(tombstone);
    return true;
  }

  /** Drop shares older than the retention window. */
  prune(currentEpoch: number): number {
    return this.collector.prune(currentEpoch);
  }

  /**
   * Author a tombstone for locally detected evidence and gossip it.
   *
   * Silently does nothing when the offender's trapdoor is unknown —
   * without it `cm_identity` cannot be bound, and peers would rightly
   * reject the tombstone as unverifiable.
   */
  private async publishTombstone(evidence: SlashingEvidence): Promise<void> {
    const trapdoor = this.deps.resolveTrapdoor?.(evidence.identitySecret);
    if (trapdoor === undefined) return;

    const tombstone = createSlashingTombstone(
      evidence.shares,
      trapdoor,
      this.deps.validator(),
    );

    this.revoked.add(tombstone.membershipCommitment);
    await this.deps.onRevoked(tombstone);

    const frame = encodeTombstone(tombstone);
    await Promise.all(
      Array.from(this.deps.connections(), (connection) =>
        // Stream 0x03 preempts chat traffic: a compromised identity must
        // outrun the messages it is still sending (RFC 001 §6).
        connection.send(StreamType.REVOCATION_GOSSIP, frame),
      ),
    );

    for (const handler of this.handlers) {
      handler({ tombstone, evidence, local: true });
    }
  }
}
