/**
 * In-process cron driver for self-hosted deploys.
 *
 * Cloud deploys rely on Upstash QStash schedules to POST the five
 * /api/internal/cron/* dispatcher endpoints. Self-hosts have no such
 * external scheduler, so we schedule setInterval calls to the same
 * endpoints with the INTERNAL_API_KEY header.
 *
 * Opt in by setting DEPTEX_RUN_CRONS=1. Automatic when the selected job
 * backend is bullmq (see startSelfHostCrons below).
 *
 * Intervals are rate-based (not clock-aligned). "Daily" fires 24h after
 * startup, then every 24h. That's accurate enough for background maintenance
 * — if a precise clock alignment is needed later, swap to node-cron.
 */

import { captureInfraError, captureInfraMessage } from './observability/capture';

const MIN = 60 * 1000;
const HOUR = 60 * MIN;

type Tick = { path: string; intervalMs: number; label: string };

const TICKS: Tick[] = [
  { path: '/api/internal/cron/every-5-min', intervalMs: 5 * MIN, label: 'every-5-min' },
  { path: '/api/internal/cron/every-15-min', intervalMs: 15 * MIN, label: 'every-15-min' },
  { path: '/api/internal/cron/hourly', intervalMs: HOUR, label: 'hourly' },
  { path: '/api/internal/cron/every-6h', intervalMs: 6 * HOUR, label: 'every-6h' },
  { path: '/api/internal/cron/daily', intervalMs: 24 * HOUR, label: 'daily' },
];

const handles: NodeJS.Timeout[] = [];

function backendUrl(): string {
  const raw = (process.env.BACKEND_URL || process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`).trim().replace(/\/$/, '');
  if (/^https?:\/\//i.test(raw)) return raw;
  return `http://${raw}`;
}

async function fire(tick: Tick) {
  const key = process.env.INTERNAL_API_KEY;
  if (!key) {
    console.warn(`[self-host-cron] ${tick.label}: INTERNAL_API_KEY not set, skipping`);
    return;
  }
  const url = `${backendUrl()}${tick.path}`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Api-Key': key },
      body: '{}',
    });
    if (!res.ok) {
      console.error(`[self-host-cron] ${tick.label} -> ${res.status}`);
      captureInfraMessage(`self-host-cron ${tick.label} -> ${res.status}`, 'self-host-cron', { tick: tick.label, status: res.status });
    }
  } catch (e: any) {
    console.error(`[self-host-cron] ${tick.label} failed:`, e?.message || e);
    captureInfraError(e, 'self-host-cron', { tick: tick.label });
  }
}

/**
 * Start the cron driver. Safe to call from backend startup; does nothing
 * unless DEPTEX_RUN_CRONS=1 (or JOB_QUEUE_BACKEND=bullmq, which implies it).
 */
export function startSelfHostCrons() {
  const enabled =
    process.env.DEPTEX_RUN_CRONS === '1' ||
    (process.env.JOB_QUEUE_BACKEND || '').toLowerCase() === 'bullmq';
  if (!enabled) return;
  if (handles.length > 0) return; // already started

  console.log('[self-host-cron] starting in-process cron driver');
  for (const tick of TICKS) {
    // Stagger initial fires so we don't slam the backend on boot.
    const jitter = Math.floor(Math.random() * 30_000);
    const h = setTimeout(() => {
      fire(tick);
      const interval = setInterval(() => fire(tick), tick.intervalMs);
      handles.push(interval);
    }, jitter);
    handles.push(h);
  }
}

/** For tests / graceful shutdown. */
export function stopSelfHostCrons() {
  for (const h of handles) clearInterval(h as any);
  handles.length = 0;
}
