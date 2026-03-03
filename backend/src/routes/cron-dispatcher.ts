/**
 * Consolidated QStash cron dispatcher (CE route).
 *
 * Reduces the number of QStash schedules by grouping jobs by frequency into
 * a few dispatcher endpoints. Configure only these in QStash; they fan out
 * to the real handlers internally (1 QStash message per run).
 *
 * Auth: QStash signature or X-Internal-Api-Key (same as other internal crons).
 */

import express from 'express';

const router = express.Router();

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();
const BACKEND_URL = (process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001').replace(/\/$/, '');

async function verifyInternalAuth(req: express.Request): Promise<boolean> {
  if (INTERNAL_API_KEY && req.headers['x-internal-api-key'] === INTERNAL_API_KEY) return true;
  if (INTERNAL_API_KEY && (req.headers.authorization === `Bearer ${INTERNAL_API_KEY}`)) return true;
  try {
    const signature = req.headers['upstash-signature'] as string;
    if (!signature || !process.env.QSTASH_CURRENT_SIGNING_KEY) return false;
    const { Receiver } = await import('@upstash/qstash');
    const receiver = new Receiver({
      currentSigningKey: process.env.QSTASH_CURRENT_SIGNING_KEY,
      nextSigningKey: process.env.QSTASH_NEXT_SIGNING_KEY || '',
    });
    const rawBody = (req as any).rawBody || JSON.stringify(req.body || {});
    await receiver.verify({ signature, body: rawBody });
    return true;
  } catch {
    return false;
  }
}

type JobResult = { path: string; status: number; ok: boolean; error?: string };

async function callInternal(path: string, method: 'POST' = 'POST', body?: object): Promise<JobResult> {
  const url = `${BACKEND_URL}${path}`;
  try {
    const res = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Api-Key': INTERNAL_API_KEY || '',
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const ok = res.ok || res.status === 404; // 404 = EE route not mounted in CE
    return { path, status: res.status, ok, error: ok ? undefined : `${res.status} ${res.statusText}` };
  } catch (e: any) {
    return { path, status: 0, ok: false, error: e?.message || 'fetch failed' };
  }
}

/**
 * POST /api/internal/cron/every-5-min
 * Run every 5 minutes (cron: 5-min interval).
 * Jobs: extraction recovery, fix recovery, watchtower recovery, Aegis due automations.
 */
router.post('/every-5-min', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const jobs = [
    '/api/internal/recovery/extraction-jobs',
    '/api/internal/recovery/fix-jobs',
    '/api/internal/recovery/watchtower-jobs',
    '/api/internal/aegis/check-due-automations',
  ];
  const results: JobResult[] = [];
  for (const path of jobs) {
    const r = await callInternal(path);
    results.push(r);
    if (!r.ok && r.status !== 404) {
      console.error(`[cron-dispatcher] every-5-min ${path}:`, r.error);
    }
  }
  res.json({ success: true, jobs: results });
});

/**
 * POST /api/internal/cron/every-15-min
 * Run every 15 minutes (cron: 15-min interval).
 * Jobs: reconcile stuck notifications, SLA check (EE).
 */
router.post('/every-15-min', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const jobs = [
    '/api/workers/reconcile-stuck-notifications',
    '/api/internal/sla-check',
  ];
  const results: JobResult[] = [];
  for (const path of jobs) {
    const r = await callInternal(path);
    results.push(r);
    if (!r.ok && r.status !== 404) {
      console.error(`[cron-dispatcher] every-15-min ${path}:`, r.error);
    }
  }
  res.json({ success: true, jobs: results });
});

/**
 * POST /api/internal/cron/hourly
 * Run at minute 0 every hour: 0 * * * *
 * Jobs: vuln-check, reset-sync-counters, learning feedback prompts, digest-check (EE).
 */
router.post('/hourly', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const jobs = [
    '/api/internal/vuln-check',
    '/api/workers/reset-sync-counters',
    '/api/internal/learning/check-feedback-prompts',
    '/api/workers/digest-check',
  ];
  const results: JobResult[] = [];
  for (const path of jobs) {
    const r = await callInternal(path);
    results.push(r);
    if (!r.ok && r.status !== 404) {
      console.error(`[cron-dispatcher] hourly ${path}:`, r.error);
    }
  }
  res.json({ success: true, jobs: results });
});

/**
 * POST /api/internal/cron/daily
 * Run once per day at 4 AM UTC: 0 4 * * *
 * Jobs: Aegis debt snapshot, learning recompute-patterns, notification cleanup (EE), watchtower daily poll.
 */
router.post('/daily', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const jobs = [
    '/api/internal/aegis/snapshot-debt',
    '/api/internal/learning/recompute-patterns',
    '/api/workers/notification-cleanup',
    '/api/workers/watchtower-daily-poll',
  ];
  const results: JobResult[] = [];
  for (const path of jobs) {
    const r = await callInternal(path);
    results.push(r);
    if (!r.ok && r.status !== 404) {
      console.error(`[cron-dispatcher] daily ${path}:`, r.error);
    }
  }
  res.json({ success: true, jobs: results });
});

/**
 * POST /api/internal/cron/every-6h
 * Run every 6 hours (cron: 0 past every 6th hour).
 * Jobs: scheduled extraction (daily/weekly sync_frequency projects).
 */
router.post('/every-6h', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const r = await callInternal('/api/workers/scheduled-extraction');
  if (!r.ok) {
    console.error('[cron-dispatcher] every-6h scheduled-extraction:', r.error);
  }
  res.json({ success: r.ok, job: r });
});

export default router;
