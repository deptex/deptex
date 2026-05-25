// POSTs a worker_minutes meter event to the backend after each scan job
// completes. Idempotency key namespaces by source so a depscanner restart
// + replay can't double-bill.

const BACKEND_URL = process.env.DEPTEX_BACKEND_URL || 'http://localhost:3001';
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;
const MACHINE_SIZE = process.env.FLY_VM_SIZE_NAME || process.env.FLY_MACHINE_SIZE || 'performance-2x';

export type WorkerJobFeature =
  | 'depscanner.scan'
  | 'depscanner.dast'
  | 'depscanner.dast_zap_dry_run';

export interface PostWorkerMinutesInput {
  orgId: string;
  projectId?: string;
  scanJobId: string;
  feature: WorkerJobFeature;
  seconds: number;
}

export async function postWorkerMinutesEvent(input: PostWorkerMinutesInput): Promise<void> {
  if (!INTERNAL_API_KEY) {
    console.warn('[meter-event] INTERNAL_API_KEY not set; skipping');
    return;
  }
  if (!Number.isFinite(input.seconds) || input.seconds <= 0) return;

  const body: Record<string, unknown> = {
    organization_id: input.orgId,
    event_type: 'worker_minutes',
    provider: 'fly',
    feature: input.feature,
    quantity: Math.round(input.seconds),
    unit: 'seconds',
    machine_size: MACHINE_SIZE,
    attribution: {
      resource_type: 'scan_job',
      resource_id: input.scanJobId,
    },
    idempotency_key: `depscanner:${input.scanJobId}:final`,
  };
  if (input.projectId) body.project_id = input.projectId;

  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
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
        console.error(`[meter-event] 4xx ${res.status} — dropping: ${text}`);
        return;
      }
      console.warn(`[meter-event] attempt ${attempt} got ${res.status}; retrying`);
    } catch (err) {
      console.warn(`[meter-event] attempt ${attempt} threw`, err);
    }
    await new Promise((r) => setTimeout(r, 500 * 2 ** (attempt - 1)));
  }
  console.error('[meter-event] all retries exhausted for scan_job', input.scanJobId);
}

function featureForScanType(type: string): WorkerJobFeature {
  if (type.startsWith('dast_zap_dry_run')) return 'depscanner.dast_zap_dry_run';
  if (type.startsWith('dast')) return 'depscanner.dast';
  return 'depscanner.scan';
}

export interface JobTiming {
  jobId: string;
  orgId: string;
  projectId?: string;
  type: string;
  startedAtMs: number;
  endedAtMs?: number;
}

export async function postScanJobMeterEvent(timing: JobTiming): Promise<void> {
  const endedAt = timing.endedAtMs ?? Date.now();
  const seconds = Math.max(1, Math.round((endedAt - timing.startedAtMs) / 1000));
  await postWorkerMinutesEvent({
    orgId: timing.orgId,
    projectId: timing.projectId,
    scanJobId: timing.jobId,
    feature: featureForScanType(timing.type),
    seconds,
  });
}
