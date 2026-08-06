/**
 * @dicsussion/wot — Verified Bidirectional Session Tracker
 *
 * Decides when a conversation counts as a "verified bidirectional chat
 * session" worth +10 POC, per the five conditions in RFC 004 §6.2:
 *
 *   1. At least one message from each participant.
 *   2. Both participants produced a valid RLN proof for ≥1 message.
 *   3. The session spans ≥ 3 distinct epochs AND ≥ 30 seconds elapsed.
 *   4. The participants are distinct identities (no self-chat).
 *   5. At most one credited session per peer per 24-hour window.
 *
 * Conditions 3 and 5 are what make this expensive to farm: a bot cannot
 * mint reputation by blasting messages, because credit requires wall-clock
 * time and is rate-limited per counterparty per day.
 */

/** Minimum distinct epochs a session must span (RFC 004 §6.2 condition 3). */
export const MIN_SESSION_EPOCHS = 3;

/** Minimum elapsed wall-clock seconds for a session. */
export const MIN_SESSION_DURATION_S = 30;

/** Cooldown before the same peer can be credited again (24 hours). */
export const SESSION_COOLDOWN_S = 86_400;

/** One observed message in a conversation. */
export interface SessionMessage {
  /** The counterparty's did:key. */
  readonly peerDid: string;
  /** True when the local node authored the message. */
  readonly fromLocal: boolean;
  /** The 10-second epoch the message belongs to. */
  readonly epoch: number;
  /** Unix timestamp in seconds. */
  readonly timestamp: number;
  /**
   * Whether the message carried a valid RLN proof.
   *
   * Phase 2 has no proving engine, so callers pass the envelope's
   * `proofValid` flag. Phase 3 replaces this with real verification —
   * the condition is enforced here either way.
   */
  readonly proofValid: boolean;
}

/** Why a session did not qualify, for diagnostics. */
export type SessionBlocker =
  | 'no-local-message'
  | 'no-remote-message'
  | 'local-proof-missing'
  | 'remote-proof-missing'
  | 'insufficient-epochs'
  | 'insufficient-duration'
  | 'self-chat'
  | 'cooldown-active';

/** Outcome of evaluating a peer's accumulated session. */
export interface SessionEvaluation {
  /** True when this evaluation credited a new verified session. */
  readonly credited: boolean;
  /** Unmet conditions, empty when credited. */
  readonly blockers: readonly SessionBlocker[];
}

/** Mutable accumulator for one peer's in-progress session. */
interface SessionState {
  localMessages: number;
  remoteMessages: number;
  localProofSeen: boolean;
  remoteProofSeen: boolean;
  epochs: Set<number>;
  firstTimestamp: number;
  lastTimestamp: number;
  lastCreditedAt?: number;
}

export interface SessionTrackerOptions {
  /** This node's did:key, used to reject self-chats. */
  readonly localDid: string;
  readonly minEpochs?: number;
  readonly minDurationS?: number;
  readonly cooldownS?: number;
}

/**
 * Tracks per-peer conversation state and credits verified sessions.
 */
export class SessionTracker {
  private readonly sessions = new Map<string, SessionState>();
  private readonly localDid: string;
  private readonly minEpochs: number;
  private readonly minDurationS: number;
  private readonly cooldownS: number;

  constructor(options: SessionTrackerOptions) {
    this.localDid = options.localDid;
    this.minEpochs = options.minEpochs ?? MIN_SESSION_EPOCHS;
    this.minDurationS = options.minDurationS ?? MIN_SESSION_DURATION_S;
    this.cooldownS = options.cooldownS ?? SESSION_COOLDOWN_S;
  }

  /**
   * Record a message and re-evaluate whether the session now qualifies.
   *
   * @returns Whether this message completed a newly credited session.
   */
  record(message: SessionMessage): SessionEvaluation {
    if (message.peerDid === this.localDid) {
      return { credited: false, blockers: ['self-chat'] };
    }

    const state = this.stateFor(message.peerDid, message.timestamp);

    if (message.fromLocal) {
      state.localMessages++;
      if (message.proofValid) state.localProofSeen = true;
    } else {
      state.remoteMessages++;
      if (message.proofValid) state.remoteProofSeen = true;
    }

    state.epochs.add(message.epoch);
    state.firstTimestamp = Math.min(state.firstTimestamp, message.timestamp);
    state.lastTimestamp = Math.max(state.lastTimestamp, message.timestamp);

    return this.evaluate(message.peerDid, message.timestamp);
  }

  /**
   * Evaluate a peer's session without recording a new message.
   *
   * @param peerDid The counterparty.
   * @param now Unix seconds, for cooldown comparison.
   */
  evaluate(peerDid: string, now: number): SessionEvaluation {
    if (peerDid === this.localDid) {
      return { credited: false, blockers: ['self-chat'] };
    }

    const state = this.sessions.get(peerDid);
    if (!state) {
      return {
        credited: false,
        blockers: ['no-local-message', 'no-remote-message'],
      };
    }

    const blockers: SessionBlocker[] = [];

    if (state.localMessages === 0) blockers.push('no-local-message');
    if (state.remoteMessages === 0) blockers.push('no-remote-message');
    if (!state.localProofSeen) blockers.push('local-proof-missing');
    if (!state.remoteProofSeen) blockers.push('remote-proof-missing');
    if (state.epochs.size < this.minEpochs) blockers.push('insufficient-epochs');

    const elapsed = state.lastTimestamp - state.firstTimestamp;
    if (elapsed < this.minDurationS) blockers.push('insufficient-duration');

    if (
      state.lastCreditedAt !== undefined &&
      now - state.lastCreditedAt < this.cooldownS
    ) {
      blockers.push('cooldown-active');
    }

    if (blockers.length > 0) return { credited: false, blockers };

    // Credit exactly once, then start a fresh accumulator so the same
    // message history cannot be re-counted.
    state.lastCreditedAt = now;
    this.resetAccumulator(state, now);

    return { credited: true, blockers: [] };
  }

  /** Whether a peer is currently within its post-credit cooldown. */
  isInCooldown(peerDid: string, now: number): boolean {
    const last = this.sessions.get(peerDid)?.lastCreditedAt;
    return last !== undefined && now - last < this.cooldownS;
  }

  /** Distinct epochs observed so far for a peer. */
  epochSpan(peerDid: string): number {
    return this.sessions.get(peerDid)?.epochs.size ?? 0;
  }

  /** Forget a peer's session state entirely. */
  reset(peerDid: string): void {
    this.sessions.delete(peerDid);
  }

  /** Forget all session state. */
  clear(): void {
    this.sessions.clear();
  }

  private stateFor(peerDid: string, timestamp: number): SessionState {
    const existing = this.sessions.get(peerDid);
    if (existing) return existing;

    const created: SessionState = {
      localMessages: 0,
      remoteMessages: 0,
      localProofSeen: false,
      remoteProofSeen: false,
      epochs: new Set(),
      firstTimestamp: timestamp,
      lastTimestamp: timestamp,
    };

    this.sessions.set(peerDid, created);
    return created;
  }

  /** Clear message accumulation but preserve the cooldown marker. */
  private resetAccumulator(state: SessionState, now: number): void {
    state.localMessages = 0;
    state.remoteMessages = 0;
    state.localProofSeen = false;
    state.remoteProofSeen = false;
    state.epochs = new Set();
    state.firstTimestamp = now;
    state.lastTimestamp = now;
  }
}
