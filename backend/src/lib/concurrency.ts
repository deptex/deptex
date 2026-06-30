/**
 * Process-wide concurrency primitives.
 *
 * A per-request `pLimit(N)` only bounds work WITHIN one request — it does nothing
 * about 10 users each fanning a 30-project team at once (10×N reads hitting the DB
 * pool). A single MODULE-LEVEL Semaphore instance bounds total in-flight work across
 * ALL concurrent requests: callers queue on one shared budget, so the pool sees a
 * fixed ceiling no matter how many requests pile up.
 */

export class Semaphore {
  private active = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  private acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active++;
      return Promise.resolve();
    }
    // Busy: park. The waiter INHERITS a slot from whoever releases (no double-count).
    return new Promise<void>((resolve) => this.queue.push(resolve));
  }

  private release(): void {
    const next = this.queue.shift();
    if (next) {
      next(); // hand our slot directly to the next waiter — active stays the same
    } else {
      this.active--;
    }
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

/**
 * Reject with `Error('timeout')` if `p` doesn't settle within `ms`. The underlying
 * promise keeps running (and is ignored) — the point is to free the caller (and any
 * Semaphore slot it holds) so one hung unit can't stall a fan-in.
 */
export function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}
