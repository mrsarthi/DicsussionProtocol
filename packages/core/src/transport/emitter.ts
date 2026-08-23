/**
 * @dicsussion/transport — Minimal event emitter
 *
 * Replaces `node:events` across the SDK. Node's `EventEmitter` is
 * bundler-polyfillable, but the polyfill is ~10 KB of machinery for the
 * three methods used here, and it makes every browser consumer configure
 * a shim before the package will build at all. A local implementation
 * removes that requirement rather than documenting it.
 *
 * Deliberately smaller than the Node API: no `once`, no `prependListener`,
 * no error-event special case. Anything needing those should say so
 * explicitly rather than inheriting behaviour nobody chose.
 */

/**
 * Erased listener shape.
 *
 * The map cannot be generic over each key's tuple at once, so listeners
 * are stored erased and re-cast on dispatch. The casts go through
 * `unknown` because the two signatures genuinely do not overlap — the
 * type safety lives at the `on`/`emit` boundary, which is where callers
 * actually touch it.
 */
type Listener = (...args: readonly unknown[]) => void;

/**
 * A synchronous, typed event emitter.
 *
 * `Events` maps an event name to its listener argument tuple, so
 * `emit('status', value)` is checked against the declared shape.
 */
export class Emitter<Events extends Record<string, unknown[]> = Record<string, unknown[]>> {
  private readonly listeners = new Map<keyof Events, Set<Listener>>();

  /** Subscribe to an event. */
  on<K extends keyof Events>(event: K, listener: (...args: Events[K]) => void): this {
    const set = this.listeners.get(event) ?? new Set<Listener>();
    set.add(listener as unknown as Listener);
    this.listeners.set(event, set);

    return this;
  }

  /** Unsubscribe a previously registered listener. */
  off<K extends keyof Events>(event: K, listener: (...args: Events[K]) => void): this {
    this.listeners.get(event)?.delete(listener as unknown as Listener);
    return this;
  }

  /**
   * Invoke every listener for an event.
   *
   * Iterates a copy, so a listener that unsubscribes itself — or another
   * listener — during dispatch cannot corrupt the walk. A throwing
   * listener still propagates: swallowing it here would hide real bugs
   * inside callbacks the caller owns.
   *
   * @returns True if any listener was registered.
   */
  emit<K extends keyof Events>(event: K, ...args: Events[K]): boolean {
    const set = this.listeners.get(event);
    if (!set || set.size === 0) return false;

    for (const listener of [...set]) {
      (listener as unknown as (...a: Events[K]) => void)(...args);
    }

    return true;
  }

  /** Drop every listener for one event, or for all events. */
  removeAllListeners<K extends keyof Events>(event?: K): this {
    if (event === undefined) this.listeners.clear();
    else this.listeners.delete(event);

    return this;
  }

  /** Listener count for an event. */
  listenerCount<K extends keyof Events>(event: K): number {
    return this.listeners.get(event)?.size ?? 0;
  }

  /**
   * Accepted for source compatibility with `node:events`.
   *
   * There is no listener ceiling here — the SDK enforces its own caps
   * where RFC 004 §7.5 requires them, which is the limit that actually
   * matters.
   */
  setMaxListeners(_count: number): this {
    return this;
  }
}
