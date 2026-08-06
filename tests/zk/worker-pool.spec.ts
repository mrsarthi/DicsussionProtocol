/**
 * Phase 3A — Proof worker pool (RFC 004 §5).
 *
 * Proving takes ~1s and pins a core, so it must never run on the UI
 * thread and a wedged prover must never take the app with it. These
 * tests drive the pool with synthetic executors so the recovery
 * behaviour is exercised in milliseconds rather than seconds.
 */

import { expect, test } from '@playwright/test';

import { ProofWorkerPool } from '../../packages/core/src/zk/worker-pool.js';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test.describe('ZK — Proof Worker Pool', () => {
  test('executes submitted jobs and reports completion', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 2,
      createExecutor: () => async (n) => n * 2,
    });

    try {
      expect(await pool.submit(21)).toBe(42);
      expect(pool.stats.completed).toBe(1);
      expect(pool.stats.failed).toBe(0);
    } finally {
      await pool.dispose();
    }
  });

  test('runs jobs concurrently up to the pool size', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 3,
      createExecutor: () => async (n) => {
        await sleep(60);
        return n;
      },
    });

    try {
      const started = Date.now();
      const results = await Promise.all([1, 2, 3].map((n) => pool.submit(n)));

      expect(results).toEqual([1, 2, 3]);
      // Three 60 ms jobs across three workers should overlap, not queue.
      expect(Date.now() - started).toBeLessThan(160);
    } finally {
      await pool.dispose();
    }
  });

  test('queues work beyond the pool size rather than dropping it', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      createExecutor: () => async (n) => {
        await sleep(20);
        return n;
      },
    });

    try {
      const results = await Promise.all([1, 2, 3, 4].map((n) => pool.submit(n)));

      expect(results.sort()).toEqual([1, 2, 3, 4]);
      expect(pool.stats.completed).toBe(4);
    } finally {
      await pool.dispose();
    }
  });

  test('a wedged worker times out and is replaced', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      timeoutMs: 40,
      createExecutor: () => async (n) => {
        // Simulates a hung WASM prover, which cannot be interrupted
        // cooperatively — the only recovery is to discard the worker.
        await sleep(5_000);
        return n;
      },
    });

    try {
      await expect(pool.submit(1)).rejects.toThrow(/timed out after 40ms/);

      expect(pool.stats.timedOut).toBe(1);
      expect(pool.stats.restarts).toBe(1);
      // Pool size is preserved so throughput does not silently degrade.
      expect(pool.stats.size).toBe(1);
      expect(pool.isHealthy()).toBe(true);
    } finally {
      await pool.dispose();
    }
  });

  test('the pool still works after a timeout', async () => {
    let hang = true;

    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      timeoutMs: 40,
      createExecutor: () => async (n) => {
        if (hang) {
          await sleep(5_000);
        }
        return n * 10;
      },
    });

    try {
      await expect(pool.submit(1)).rejects.toThrow(/timed out/);

      hang = false;
      // The replacement worker was built by a fresh createExecutor call.
      expect(await pool.submit(7)).toBe(70);
      expect(pool.stats.completed).toBe(1);
    } finally {
      await pool.dispose();
    }
  });

  test('a late result from a timed-out worker is discarded', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      timeoutMs: 30,
      createExecutor: () => async (n, signal) => {
        await sleep(80);
        // The pool marks the signal aborted on timeout; without that
        // check a stale result could resolve an already-rejected job.
        expect(signal.aborted).toBe(true);
        return n;
      },
    });

    try {
      await expect(pool.submit(1)).rejects.toThrow(/timed out/);
      await sleep(120);

      expect(pool.stats.completed).toBe(0);
    } finally {
      await pool.dispose();
    }
  });

  test('a throwing worker fails its job and is replaced', async () => {
    let shouldThrow = true;

    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      createExecutor: () => async (n) => {
        if (shouldThrow) throw new Error('witness generation failed');
        return n;
      },
    });

    try {
      await expect(pool.submit(1)).rejects.toThrow(/witness generation failed/);
      expect(pool.stats.failed).toBe(1);
      expect(pool.stats.restarts).toBe(1);

      shouldThrow = false;
      expect(await pool.submit(5)).toBe(5);
    } finally {
      await pool.dispose();
    }
  });

  test('a saturated queue applies backpressure instead of growing', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      maxQueueDepth: 2,
      createExecutor: () => async (n) => {
        await sleep(200);
        return n;
      },
    });

    try {
      const inflight = [pool.submit(1), pool.submit(2), pool.submit(3)];

      // Unbounded queueing would turn a slow prover into a memory leak.
      await expect(pool.submit(4)).rejects.toThrow(/saturated/);
      await Promise.allSettled(inflight);
    } finally {
      await pool.dispose();
    }
  });

  test('reset abandons queued work and rebuilds the pool', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      createExecutor: () => async (n) => {
        await sleep(100);
        return n;
      },
    });

    try {
      const running = pool.submit(1);
      const abandoned = pool.submit(2);

      await pool.reset();

      // Both the queued job and the one already executing must settle —
      // leaving either pending would hang a caller awaiting a proof.
      await expect(abandoned).rejects.toThrow(/was reset/);
      await expect(running).rejects.toThrow(/was reset/);
      expect(pool.isHealthy()).toBe(true);
    } finally {
      await pool.dispose();
    }
  });

  test('dispose fails outstanding work and refuses new submissions', async () => {
    const pool = new ProofWorkerPool<number, number>({
      size: 1,
      createExecutor: () => async (n) => {
        await sleep(100);
        return n;
      },
    });

    const running = pool.submit(1);
    const queued = pool.submit(2);

    await pool.dispose();

    await expect(queued).rejects.toThrow(/disposed/);
    await expect(running).rejects.toThrow(/disposed/);
    await expect(pool.submit(3)).rejects.toThrow(/disposed/);
    expect(pool.isHealthy()).toBe(false);
  });
});
