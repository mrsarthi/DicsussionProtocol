/**
 * @dicsussion/crdt — Channel Membership Reconciliation (Stream 0x01)
 *
 * Converges the identity-commitment set behind each channel's depth-16
 * Merkle tree, so every peer derives the same membership root.
 *
 * This matters because the Phase 3 RLN circuit proves *"my commitment is
 * in this tree"* against a root the verifier independently computed. If
 * two peers disagreed on membership they would compute different roots,
 * and honest proofs would fail to verify.
 *
 * The protocol is deliberately simple: exchange roots, and if they
 * differ, exchange the member sets and union them.
 *
 * Membership is a **two-phase set**: a grow-only set of joins minus a
 * grow-only set of signed departure tombstones. Both halves converge
 * regardless of message order or duplication — no vector clocks or
 * tie-breaking needed — and the remove half always wins, so a peer that
 * has not yet seen a departure cannot re-add the member by offering the
 * commitment back. Departure is permanent for a given commitment;
 * rejoining means presenting a fresh one. Revocations for misconduct are
 * separate and arrive on Stream `0x03`.
 *
 * KNOWN LIMITATION — LRU divergence at capacity. `BoundedMembershipTree`
 * evicts by `lastActive`, which is a *local* observation. Below N_max
 * (65,536) nothing is ever evicted and roots agree. At capacity two
 * peers could evict different members and fork the root. The fix is to
 * derive activity from a globally observable event — the last epoch a
 * member published an RLN signal — rather than local wall-clock. Not yet
 * implemented; see PROGRESS.md.
 */

import { compareFieldBytes } from '../crypto/field.js';
import type { DepartureRecord } from './membership-departure.js';
import { DepartureSet } from './membership-departure.js';
import type { BoundedMembershipTree } from './membership-tree.js';
import { DEFAULT_MAX_MEMBERS } from './membership-tree.js';
import {
  decodeDepartureBody,
  decodeMemberListBody,
  decodeMemberRootBody,
  encodeDepartureBody,
  encodeMemberListBody,
  encodeMemberRootBody,
  encodeSyncFrame,
  MAX_DEPARTURES_PER_FRAME,
  MAX_MEMBERS_PER_FRAME,
  SyncMessageType,
} from './sync-protocol.js';

/**
 * Ceiling on commitments buffered from one peer before `is_final`.
 *
 * A membership set larger than the tree's own capacity cannot describe a
 * valid membership, so anything beyond this is either a bug or an attempt
 * to grow the buffer one legally-sized frame at a time.
 */
const MAX_PENDING_COMMITMENTS = DEFAULT_MAX_MEMBERS;

/** Resolves the membership tree backing a channel. */
export type MembershipResolver = (
  channelId: string,
) => BoundedMembershipTree | undefined;

/** Emitted when reconciliation admits commitments from a peer. */
export interface MembershipUpdate {
  readonly channelId: string;
  readonly peerId: string;
  /** Commitments newly admitted by this exchange. */
  readonly admitted: readonly bigint[];
  /** Membership root after the merge. */
  readonly root: bigint;
}

export type MembershipUpdateHandler = (update: MembershipUpdate) => void;

/** Per-peer, per-channel reconciliation state. */
interface PeerChannelState {
  /** Root the peer last advertised. */
  advertisedRoot?: bigint;
  /** Commitments accumulated across chunked MEMBER_LIST frames. */
  pending: bigint[];
  /** Whether we have already answered with our own set this round. */
  responded: boolean;
}

/**
 * Drives membership convergence over Stream 0x01.
 */
export class MembershipSyncEngine {
  private readonly state = new Map<string, Map<string, PeerChannelState>>();
  private readonly handlers: MembershipUpdateHandler[] = [];

  /** Departure tombstones per channel — the 2P-set's remove half. */
  private readonly departures = new Map<string, DepartureSet>();

  constructor(private readonly resolve: MembershipResolver) {}

  /**
   * Record a locally authored departure and produce frames announcing it.
   *
   * The commitment is removed from the tree *and* tombstoned, so the
   * next reconciliation cannot re-add it.
   *
   * @returns Frames to broadcast, or an empty array if invalid.
   */
  announceDeparture(departure: DepartureRecord): Uint8Array[] {
    if (!this.departuresFor(departure.channelId).add(departure)) return [];

    this.resolve(departure.channelId)?.remove(departure.commitment);

    return [
      encodeSyncFrame(
        SyncMessageType.MEMBER_DEPARTURE,
        departure.channelId,
        encodeDepartureBody([departure], true),
      ),
    ];
  }

  /**
   * Handle an inbound MEMBER_DEPARTURE frame.
   *
   * Each record is signature-checked against the did:key it names, so a
   * peer cannot evict anyone but itself.
   *
   * @returns Frames to send back (our own departures, if the peer lacks any).
   */
  handleDeparture(
    peerId: string,
    channelId: string,
    body: Uint8Array,
  ): Uint8Array[] {
    void peerId;

    let decoded: { departures: DepartureRecord[]; isFinal: boolean };
    try {
      decoded = decodeDepartureBody(body);
    } catch {
      return [];
    }

    const set = this.departuresFor(channelId);
    const tree = this.resolve(channelId);

    for (const departure of decoded.departures) {
      // `add` verifies the signature and binds the channel id.
      if (set.add(departure)) tree?.remove(departure.commitment);
    }

    return [];
  }

  /** Departure tombstones held for a channel. */
  listDepartures(channelId: string): DepartureRecord[] {
    return this.departures.get(channelId)?.list() ?? [];
  }

  /** Whether a commitment has been tombstoned in a channel. */
  hasDeparted(channelId: string, commitment: bigint): boolean {
    return this.departures.get(channelId)?.has(commitment) ?? false;
  }

  private departuresFor(channelId: string): DepartureSet {
    let set = this.departures.get(channelId);
    if (!set) {
      set = new DepartureSet(channelId);
      this.departures.set(channelId, set);
    }
    return set;
  }

  /** Subscribe to membership merges. @returns Unsubscribe function. */
  onUpdate(handler: MembershipUpdateHandler): () => void {
    this.handlers.push(handler);
    return () => {
      const i = this.handlers.indexOf(handler);
      if (i >= 0) this.handlers.splice(i, 1);
    };
  }

  /** Drop all state for a peer that disconnected. */
  removePeer(peerId: string): void {
    this.state.delete(peerId);
  }

  /**
   * Advertise our membership root for a channel.
   *
   * @returns A MEMBER_ROOT frame, or undefined if the channel is unknown.
   */
  advertise(channelId: string): Uint8Array | undefined {
    const tree = this.resolve(channelId);
    if (!tree) return undefined;

    return encodeSyncFrame(
      SyncMessageType.MEMBER_ROOT,
      channelId,
      encodeMemberRootBody(tree.root(), tree.size),
    );
  }

  /**
   * Handle an inbound MEMBER_ROOT.
   *
   * Equal roots mean equal sets — the whole point of deterministic
   * lexicographic indexing — so nothing is transferred.
   *
   * @returns Frames to send back.
   */
  handleMemberRoot(
    peerId: string,
    channelId: string,
    body: Uint8Array,
  ): Uint8Array[] {
    const tree = this.resolve(channelId);
    if (!tree) return [];

    const { root } = decodeMemberRootBody(body);
    const state = this.stateFor(peerId, channelId);
    state.advertisedRoot = root;

    if (root === tree.root()) {
      state.responded = false;
      return [];
    }

    // Roots differ: send our set so the peer can union it, and it will
    // send its own back if it still holds commitments we lack.
    return this.encodeOurSet(channelId, tree);
  }

  /**
   * Handle an inbound MEMBER_LIST chunk.
   *
   * Chunks accumulate until `is_final`, then merge in one step so the
   * root is recomputed once rather than per chunk.
   *
   * @returns Frames to send back.
   */
  handleMemberList(
    peerId: string,
    channelId: string,
    body: Uint8Array,
  ): Uint8Array[] {
    const tree = this.resolve(channelId);
    if (!tree) return [];

    const { commitments, isFinal } = decodeMemberListBody(body);
    const state = this.stateFor(peerId, channelId);

    // Cap the accumulator.
    //
    // Individual frames are bounded by the frame codec, but chunks only
    // merge when `is_final` arrives — so a peer that never sets that flag
    // could grow this array indefinitely, one bounded frame at a time.
    //
    // The tree holds at most `DEFAULT_MAX_MEMBERS` commitments, so a
    // pending set larger than that cannot describe a valid membership
    // regardless of intent. Discard the whole accumulation rather than
    // trimming it: a truncated member list would merge as though the peer
    // had genuinely departed everyone past the cut.
    if (state.pending.length + commitments.length > MAX_PENDING_COMMITMENTS) {
      state.pending = [];
      state.responded = false;
      return [];
    }

    state.pending.push(...commitments);

    if (!isFinal) return [];

    const incoming = state.pending;
    state.pending = [];

    const admitted = this.merge(tree, incoming, channelId);
    if (admitted.length > 0) {
      const root = tree.root();
      for (const handler of this.handlers) {
        handler({ channelId, peerId, admitted, root });
      }
    }

    // Reply once per round with anything the peer is missing, and only
    // if we actually hold something extra — otherwise two converged
    // peers would trade lists forever.
    if (state.responded) {
      state.responded = false;
      return [];
    }

    const theirs = new Set(incoming);
    const missing = tree
      .sortedCommitments()
      .filter((commitment) => !theirs.has(commitment));

    if (missing.length === 0) return [];

    state.responded = true;
    return this.chunk(channelId, missing);
  }

  /** Whether we and a peer last agreed on a channel's root. */
  isConverged(peerId: string, channelId: string): boolean {
    const tree = this.resolve(channelId);
    const advertised = this.state.get(peerId)?.get(channelId)?.advertisedRoot;

    return tree !== undefined && advertised !== undefined && advertised === tree.root();
  }

  /** Admit commitments we do not already hold and that have not departed. */
  private merge(
    tree: BoundedMembershipTree,
    incoming: readonly bigint[],
    channelId: string,
  ): bigint[] {
    const admitted: bigint[] = [];
    const departed = this.departures.get(channelId);

    for (const commitment of incoming) {
      // Zero is the empty-leaf tombstone, never a real member.
      if (commitment === 0n || tree.has(commitment)) continue;

      // The remove half of the 2P-set wins: a peer that has not yet seen
      // the departure will keep offering this commitment, and re-adding
      // it would undo the leave.
      if (departed?.has(commitment)) continue;

      try {
        tree.insert(commitment);
        admitted.push(commitment);
      } catch {
        // A non-canonical commitment from a hostile peer is dropped
        // rather than aborting the whole exchange.
      }
    }

    return admitted.sort(compareFieldBytes);
  }

  private encodeOurSet(
    channelId: string,
    tree: BoundedMembershipTree,
  ): Uint8Array[] {
    return this.chunk(channelId, tree.sortedCommitments());
  }

  /** Frames announcing every departure we hold, for a joining peer. */
  departureFrames(channelId: string): Uint8Array[] {
    const records = this.listDepartures(channelId);
    if (records.length === 0) return [];

    const frames: Uint8Array[] = [];
    for (let i = 0; i < records.length; i += MAX_DEPARTURES_PER_FRAME) {
      const slice = records.slice(i, i + MAX_DEPARTURES_PER_FRAME);
      frames.push(
        encodeSyncFrame(
          SyncMessageType.MEMBER_DEPARTURE,
          channelId,
          encodeDepartureBody(slice, i + MAX_DEPARTURES_PER_FRAME >= records.length),
        ),
      );
    }

    return frames;
  }

  /** Split a commitment set across MEMBER_LIST frames. */
  private chunk(channelId: string, commitments: readonly bigint[]): Uint8Array[] {
    if (commitments.length === 0) {
      return [
        encodeSyncFrame(
          SyncMessageType.MEMBER_LIST,
          channelId,
          encodeMemberListBody([], true),
        ),
      ];
    }

    const frames: Uint8Array[] = [];

    for (let i = 0; i < commitments.length; i += MAX_MEMBERS_PER_FRAME) {
      const slice = commitments.slice(i, i + MAX_MEMBERS_PER_FRAME);
      const isFinal = i + MAX_MEMBERS_PER_FRAME >= commitments.length;

      frames.push(
        encodeSyncFrame(
          SyncMessageType.MEMBER_LIST,
          channelId,
          encodeMemberListBody(slice, isFinal),
        ),
      );
    }

    return frames;
  }

  private stateFor(peerId: string, channelId: string): PeerChannelState {
    let channels = this.state.get(peerId);
    if (!channels) {
      channels = new Map();
      this.state.set(peerId, channels);
    }

    let state = channels.get(channelId);
    if (!state) {
      state = { pending: [], responded: false };
      channels.set(channelId, state);
    }

    return state;
  }
}
