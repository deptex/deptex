// POSTs a worker_minutes meter event to the backend after each fix task
// completes. Idempotency key namespaced to fix-worker so depscanner +
// fix-worker can't collide.

const BACKEND_URL = process.env.DEPTEX_BACKEND_URL || 'http://localhost:3001';
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;
const MACHINE_SIZE = process.env.FLY_VM_SIZE_NAME || process.env.FLY_MACHINE_SIZE || 'performance-2x';

export interface FixTaskTiming {
  taskId: string;
  orgId: string;
  startedAtMs: number;
  endedAtMs?: number;
}

export async function postFixTaskMeterEvent(timing: FixTaskTiming): Promise<void> {
  if (!INTERNAL_API_KEY) {
    console.warn('[fix-worker.meter-event] INTERNAL_API_KEY not set; skipping');
    return;
  }
  const endedAt = timing.endedAtMs ?? Date.now();
  const seconds = Math.max(1, Math.round((endedAt - timing.startedAtMs) / 1000));
  if (!Number.isFinite(seconds) || seconds <= 0) return;

  const body = {
    organization_id: timing.orgId,
    event_type: 'worker_minutes',
    provider: 'fly',
    feature: 'fix-worker.task',
    quantity: seconds,
    unit: 'seconds',
    machine_size: MACHINE_SIZE,
    attribution: {
      resource_type: 'fix_task',
      resource_id: timing.taskId,
    },
    idempotency_key: `fix-worker:${timing.taskId}:final`,
  };

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(`${BACKEND_URL}/api/internal/billing/meter-event`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-internal-api-key': INTERNAL_API_KEY,
        },
        body: JSON.stringify(body),
      });
      if (res.ok) return;
      if (res.status >= 400 && res.status < 500) {
        const text = await res.text().catch(() => '');
        console.error(`[fix-worker.meter-event] 4xx ${res.status} dropping: ${text}`);
        return;
      }
    } catch (err) {
      console.warn(`[fix-worker.meter-event] attempt ${attempt} threw`, err);
    }
    await new Promise((r) => setTimeout(r, 500 * 2 ** (attempt - 1)));
  }
  console.error('[fix-worker.meter-event] all retries exhausted for task', timing.taskId);
}
