/**
 * @dicsussion/transport — NAT Traversal & DERP Relay Failover
 *
 * Implements the two-tier connection ladder from RFC 001 §4.2:
 *
 *   1. Attempt direct UDP hole-punching, bounded by a 3000ms deadline.
 *   2. On `HolePunchTimeout`, walk the ordered DERP relay chain, retrying
 *      each endpoint with exponential backoff.
 *   3. If every relay is unreachable, fail with `IrohDerpRelayUnavailable`.
 *
 * Relays are honest-but-curious: they forward end-to-end encrypted
 * streams only and never see plaintext.
 */

import {
  HOLE_PUNCH_TIMEOUT_MS,
  TransportError,
  TransportException,
} from './types.js';

/** How a connection was ultimately established. */
export type RouteKind = 'direct' | 'relay';

/** The negotiated transport route for a peer. */
export interface TransportRoute {
  readonly kind: RouteKind;
  /** Relay endpoint used, or null for a direct connection. */
  readonly endpoint: string | null;
  /** Index into the configured relay chain, or -1 for direct. */
  readonly relayIndex: number;
  /** Wall-clock milliseconds spent establishing the route. */
  readonly elapsedMs: number;
}

export interface RelayFailoverOptions {
  /** Ordered DERP relay endpoints, highest priority first. */
  readonly relayEndpoints?: readonly string[];
  /** Direct hole-punch deadline (default 3000ms per RFC 001 §4.2). */
  readonly holePunchTimeoutMs?: number;
  /** Attempts per relay endpoint before moving to the next. */
  readonly maxRetriesPerRelay?: number;
  /** Base delay for exponential backoff between retries. */
  readonly baseBackoffMs?: number;
  /** Upper bound on any single backoff delay. */
  readonly maxBackoffMs?: number;
  /** Injectable sleep, so tests need not wait in real time. */
  readonly sleep?: (ms: number) => Promise<void>;
}

/** Attempt a direct hole-punched connection. */
export type DirectAttempt = () => Promise<void>;

/** Attempt a connection through a specific relay endpoint. */
export type RelayAttempt = (endpoint: string) => Promise<void>;

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });

/** Outcome of the bounded direct-connection attempt. */
type DirectOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: 'timeout' | 'refused'; readonly error?: Error };

/**
 * Run the direct attempt under a deadline, never throwing.
 *
 * A refused hole-punch and an expired deadline are both just "the direct
 * path did not work" — each must hand off to the relay chain rather than
 * escaping to the caller. The abandoned promise's eventual rejection is
 * swallowed so it cannot surface as an unhandled rejection after the
 * race has already been decided.
 */
async function attemptDirectBounded(
  attemptDirect: DirectAttempt,
  timeoutMs: number,
): Promise<DirectOutcome> {
  let timer: NodeJS.Timeout | undefined;

  const attempt = attemptDirect().then(
    (): DirectOutcome => ({ ok: true }),
    (err: unknown): DirectOutcome => ({
      ok: false,
      reason: 'refused',
      error: err instanceof Error ? err : new Error(String(err)),
    }),
  );

  const deadline = new Promise<DirectOutcome>((resolve) => {
    timer = setTimeout(() => resolve({ ok: false, reason: 'timeout' }), timeoutMs);
    timer.unref?.();
  });

  try {
    return await Promise.race([attempt, deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Drives direct-then-relay connection establishment for a single peer.
 *
 * One manager instance tracks one peer's current route so callers can
 * inspect whether traffic is flowing directly or over a relay.
 */
export class RelayFailoverManager {
  private readonly relayEndpoints: readonly string[];
  private readonly holePunchTimeoutMs: number;
  private readonly maxRetriesPerRelay: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly sleep: (ms: number) => Promise<void>;

  private route: TransportRoute | null = null;

  constructor(options: RelayFailoverOptions = {}) {
    this.relayEndpoints = options.relayEndpoints ?? [];
    this.holePunchTimeoutMs = options.holePunchTimeoutMs ?? HOLE_PUNCH_TIMEOUT_MS;
    this.maxRetriesPerRelay = options.maxRetriesPerRelay ?? 2;
    this.baseBackoffMs = options.baseBackoffMs ?? 250;
    this.maxBackoffMs = options.maxBackoffMs ?? 4_000;
    this.sleep = options.sleep ?? defaultSleep;
  }

  /** The route established by the last successful `establish()` call. */
  get currentRoute(): TransportRoute | null {
    return this.route;
  }

  /** Configured relay chain, in priority order. */
  get relayChain(): readonly string[] {
    return this.relayEndpoints;
  }

  /**
   * Establish a connection, preferring a direct path and falling back
   * through the relay chain.
   *
   * @param attemptDirect Performs UDP hole-punching; resolves on success.
   * @param attemptRelay Connects via the given relay endpoint.
   * @returns The route that succeeded.
   * @throws TransportException `IrohDerpRelayUnavailable` if all paths fail.
   */
  async establish(
    attemptDirect: DirectAttempt,
    attemptRelay: RelayAttempt,
  ): Promise<TransportRoute> {
    const startedAt = Date.now();

    const direct = await attemptDirectBounded(attemptDirect, this.holePunchTimeoutMs);

    if (direct.ok) {
      this.route = {
        kind: 'direct',
        endpoint: null,
        relayIndex: -1,
        elapsedMs: Date.now() - startedAt,
      };
      return this.route;
    }

    // Direct path timed out or was refused — RFC 001 §7 `HolePunchTimeout`
    // requires a seamless transition to the next available relay.
    if (this.relayEndpoints.length === 0) {
      const detail =
        direct.reason === 'timeout'
          ? `did not resolve within ${this.holePunchTimeoutMs}ms`
          : `was refused: ${direct.error?.message ?? 'unknown error'}`;

      throw new TransportException(
        TransportError.HolePunchTimeout,
        `Direct hole-punch ${detail} and no DERP relays are configured`,
      );
    }

    const failures: string[] = [];

    for (let index = 0; index < this.relayEndpoints.length; index++) {
      const endpoint = this.relayEndpoints[index]!;
      const error = await this.tryRelayWithBackoff(endpoint, attemptRelay);

      if (error === null) {
        this.route = {
          kind: 'relay',
          endpoint,
          relayIndex: index,
          elapsedMs: Date.now() - startedAt,
        };
        return this.route;
      }

      failures.push(`${endpoint}: ${error.message}`);
    }

    throw new TransportException(
      TransportError.DerpRelayUnavailable,
      `All ${this.relayEndpoints.length} DERP relay(s) unreachable — ${failures.join('; ')}`,
    );
  }

  /** Forget the current route so the next call re-runs the full ladder. */
  reset(): void {
    this.route = null;
  }

  /**
   * Attempt one relay endpoint, retrying with exponential backoff.
   *
   * @returns `null` on success, otherwise the final error.
   */
  private async tryRelayWithBackoff(
    endpoint: string,
    attemptRelay: RelayAttempt,
  ): Promise<Error | null> {
    let lastError: Error = new Error('relay attempt never ran');

    for (let attempt = 0; attempt <= this.maxRetriesPerRelay; attempt++) {
      if (attempt > 0) {
        const delay = Math.min(
          this.baseBackoffMs * 2 ** (attempt - 1),
          this.maxBackoffMs,
        );
        await this.sleep(delay);
      }

      try {
        await attemptRelay(endpoint);
        return null;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    return lastError;
  }
}
