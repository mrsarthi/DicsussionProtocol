/**
 * @dicsussion/zk — Persistent Proof Worker Pool
 *
 * Keeps proof generation off the calling thread, per RFC 004 §3 (60 FPS
 * UI) and §5 (persistent pool, timeout-safe, crash recovery).
 *
 * Proving takes ~1s and pins a core, so running it inline would freeze
 * the UI on every message. Workers are *persistent* because a cold
 * worker must re-read a ~5 MB proving key; recycling one per proof would
 * dominate the cost.
 *
 * Two failure modes are handled explicitly, because a hung prover must
 * never wedge the whole app:
 *   - **Timeout** — the worker is terminated and replaced. A wedged WASM
 *     instance cannot be interrupted any other way.
 *   - **Crash** — an exiting worker fails its in-flight job and is
 *     replaced, so the pool self-heals rather than silently shrinking.
 */

/** A unit of work handed to a worker. */
export interface ProofJob<TInput, TOutput> {
  readonly input: TInput;
  readonly resolve: (output: TOutput) => void;
  readonly reject: (error: Error) => void;
  /** Milliseconds before the worker is presumed wedged. */
  readonly timeoutMs: number;
}

/**
 * Executes one job. Implementations run inside a worker thread, or
 * in-process for tests and environments without threads.
 */
export type ProofExecutor<TInput, TOutput> = (
  input: TInput,
  signal: { aborted: boolean },
) => Promise<TOutput>;

export interface WorkerPoolOptions<TInput, TOutput> {
  /** Concurrent workers. Defaults to 2 — proving is CPU-bound. */
  readonly size?: number;
  /** Default per-job timeout. */
  readonly timeoutMs?: number;
  /** Builds a fresh executor, called again whenever a worker is replaced. */
  readonly createExecutor: () => ProofExecutor<TInput, TOutput>;
  /** Maximum queued jobs before submissions are rejected. */
  readonly maxQueueDepth?: number;
}

/** Snapshot of pool health. */
export interface PoolStats {
  readonly size: number;
  readonly busy: number;
  readonly queued: number;
  readonly completed: number;
  readonly failed: number;
  readonly timedOut: number;
  readonly restarts: number;
}

interface Worker<TInput, TOutput> {
  executor: ProofExecutor<TInput, TOutput>;
  busy: boolean;
  /** Flipped on timeout so a late result from a replaced worker is dropped. */
  signal: { aborted: boolean };
  /**
   * Job currently executing, tracked so `reset`/`dispose` can fail it.
   *
   * Without this an in-flight promise would never settle when the pool
   * is torn down, hanging any caller awaiting a proof.
   */
  currentJob?: ProofJob<TInput, TOutput>;
}

/** Default milliseconds before a proof job is abandoned. */
export const DEFAULT_PROOF_TIMEOUT_MS = 30_000;

/**
 * A persistent pool of proof executors with timeout recovery.
 */
export class ProofWorkerPool<TInput, TOutput> {
  private readonly workers: Worker<TInput, TOutput>[] = [];
  private readonly queue: ProofJob<TInput, TOutput>[] = [];
  private readonly createExecutor: () => ProofExecutor<TInput, TOutput>;
  private readonly defaultTimeoutMs: number;
  private readonly maxQueueDepth: number;

  private completed = 0;
  private failed = 0;
  private timedOut = 0;
  private restarts = 0;
  private disposed = false;

  constructor(options: WorkerPoolOptions<TInput, TOutput>) {
    this.createExecutor = options.createExecutor;
    this.defaultTimeoutMs = options.timeoutMs ?? DEFAULT_PROOF_TIMEOUT_MS;
    this.maxQueueDepth = options.maxQueueDepth ?? 128;

    const size = options.size ?? 2;
    for (let i = 0; i < size; i++) {
      this.workers.push(this.spawn());
    }
  }

  /** Current pool statistics. */
  get stats(): PoolStats {
    return {
      size: this.workers.length,
      busy: this.workers.filter((w) => w.busy).length,
      queued: this.queue.length,
      completed: this.completed,
      failed: this.failed,
      timedOut: this.timedOut,
      restarts: this.restarts,
    };
  }

  /** Whether the pool has workers and has not been disposed. */
  isHealthy(): boolean {
    return !this.disposed && this.workers.length > 0;
  }

  /**
   * Submit a job, resolving when a worker completes it.
   *
   * @param input Job input.
   * @param timeoutMs Override the pool default.
   * @throws If the pool is disposed or the queue is saturated.
   */
  async submit(input: TInput, timeoutMs?: number): Promise<TOutput> {
    if (this.disposed) {
      throw new Error('Proof worker pool has been disposed');
    }
    if (this.queue.length >= this.maxQueueDepth) {
      // Backpressure: silently growing the queue would turn a slow
      // prover into unbounded memory growth.
      throw new Error(
        `Proof queue is saturated (${this.maxQueueDepth}); refusing new work`,
      );
    }

    return new Promise<TOutput>((resolve, reject) => {
      this.queue.push({
        input,
        resolve,
        reject,
        timeoutMs: timeoutMs ?? this.defaultTimeoutMs,
      });
      this.pump();
    });
  }

  /**
   * Replace every worker, abandoning queued work.
   *
   * The RFC 004 §5.1 `reset()` hook, for recovering from a corrupted
   * proving environment.
   */
  async reset(): Promise<void> {
    const abandoned = this.queue.splice(0, this.queue.length);
    for (const job of abandoned) {
      job.reject(new Error('Proof worker pool was reset'));
    }

    const size = this.workers.length || 2;
    this.abortWorkers('Proof worker pool was reset');

    this.workers.length = 0;
    for (let i = 0; i < size; i++) {
      this.workers.push(this.spawn());
    }
  }

  /** Shut the pool down, failing anything outstanding. */
  async dispose(): Promise<void> {
    this.disposed = true;

    for (const job of this.queue.splice(0, this.queue.length)) {
      job.reject(new Error('Proof worker pool was disposed'));
    }

    this.abortWorkers('Proof worker pool was disposed');
    this.workers.length = 0;
  }

  /**
   * Abort every worker and fail whatever it was running.
   *
   * Aborting alone would leave in-flight promises unsettled, because the
   * completion path deliberately ignores results from aborted workers.
   */
  private abortWorkers(reason: string): void {
    for (const worker of this.workers) {
      worker.signal.aborted = true;

      const job = worker.currentJob;
      if (job) {
        worker.currentJob = undefined;
        this.failed++;
        job.reject(new Error(reason));
      }
    }
  }

  /** Hand queued work to any idle worker. */
  private pump(): void {
    if (this.disposed) return;

    for (const worker of this.workers) {
      if (worker.busy || this.queue.length === 0) continue;

      const job = this.queue.shift()!;
      void this.run(worker, job);
    }
  }

  private async run(
    worker: Worker<TInput, TOutput>,
    job: ProofJob<TInput, TOutput>,
  ): Promise<void> {
    worker.busy = true;
    worker.currentJob = job;

    const signal = worker.signal;
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      worker.currentJob = undefined;

      // A wedged WASM prover cannot be interrupted cooperatively, so the
      // worker is discarded and a fresh one takes its slot.
      signal.aborted = true;
      this.timedOut++;
      job.reject(
        new Error(`Proof generation timed out after ${job.timeoutMs}ms`),
      );
      this.replace(worker);
    }, job.timeoutMs);
    timer.unref?.();

    try {
      const output = await worker.executor(job.input, signal);

      if (settled || signal.aborted) return;
      settled = true;
      worker.currentJob = undefined;
      clearTimeout(timer);

      this.completed++;
      job.resolve(output);
      worker.busy = false;
      this.pump();
    } catch (error) {
      if (settled || signal.aborted) return;
      settled = true;
      worker.currentJob = undefined;
      clearTimeout(timer);

      this.failed++;
      job.reject(error instanceof Error ? error : new Error(String(error)));

      // A throwing executor may have left its environment unusable, so
      // the worker is replaced rather than reused.
      this.replace(worker);
    }
  }

  /** Swap a dead worker for a fresh one, keeping pool size constant. */
  private replace(worker: Worker<TInput, TOutput>): void {
    const index = this.workers.indexOf(worker);
    if (index < 0) return;

    this.restarts++;
    this.workers[index] = this.spawn();
    this.pump();
  }

  private spawn(): Worker<TInput, TOutput> {
    return {
      executor: this.createExecutor(),
      busy: false,
      signal: { aborted: false },
    };
  }
}
