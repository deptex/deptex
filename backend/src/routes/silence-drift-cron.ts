/**
 * Silence Drift Cron — runs silence_cross_run_drift() across all projects with a
 * prior extraction run and reports run-over-run promotions of previously-silenced
 * findings (workstream M / M2).
 *
 * North-star: the reachability silence score. The worst failure is a silence
 * FALSE-NEGATIVE — a vuln auto-ignored (unreachable, depscore ~0) that is
 * actually reachable. The cheapest ground-truth signal is a run-over-run diff:
 * a finding silenced last run that gets PROMOTED (level goes UP) this run. The
 * differ buckets those by the prior verdict; the dangerous bucket is
 * silence_fn_count (prior tier SILENCED — unreachable|module — now VISIBLE:
 * function|data_flow|confirmed). unreachable->module stays silenced (healthy
 * R1 floor correction, not counted); module->function IS a silence-FN.
 *
 * Scheduled via the consolidated daily QStash dispatcher (cron-dispatcher.ts),
 * NOT its own schedule. The RPC is a PURE SELECT — read-only, no writes. This
 * cron LOGS ONLY (no email, no new env var); it never changes any finding's
 * visibility.
 *
 * Endpoint: POST /api/internal/silence/check-cross-run-drift
 * Auth: INTERNAL_API_KEY (single shared secret) OR QStash signature.
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { isValidInternalKey } from '../middleware/internal-key';

const router = express.Router();

// Copied verbatim from billing-drift-cron.ts: INTERNAL_API_KEY header OR QStash
// signature. Same posture as every other internal cron route.
async function verifyAuth(req: express.Request): Promise<boolean> {
  const headerKey = req.headers['x-internal-api-key'];
  if (typeof headerKey === 'string' && isValidInternalKey(headerKey)) return true;

  try {
    const currentSigningKey = process.env.QSTASH_CURRENT_SIGNING_KEY;
    const nextSigningKey = process.env.QSTASH_NEXT_SIGNING_KEY;
    if (!currentSigningKey) return false;
    const signature = req.headers['upstash-signature'] as string | undefined;
    if (!signature) return false;
    const { Receiver } = await import('@upstash/qstash');
    const receiver = new Receiver({ currentSigningKey, nextSigningKey } as any);
    const rawBody = (req as any).rawBody || JSON.stringify(req.body);
    await receiver.verify({ signature, body: rawBody });
    return true;
  } catch {
    return false;
  }
}

interface DriftRow {
  project_id: string;
  prior_verdict: string;
  upgraded_count: number | string;
  silence_fn_count: number | string;
  to_levels: string[] | null;
}

router.post('/check-cross-run-drift', async (req, res) => {
  if (!(await verifyAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { data, error } = await supabase.rpc('silence_cross_run_drift');
    if (error) {
      console.error('[silence-drift] RPC failed', error);
      return res.status(500).json({ error: 'RPC failed' });
    }

    const rows = (data ?? []) as DriftRow[];

    // projects_checked = distinct projects that surfaced at least one promotion.
    // (The differ only returns drifted projects, so this is "projects with
    // run-over-run promotions", not the full prior-run population.)
    const projectsWithDrift = new Set(rows.map((r) => r.project_id));

    let totalUpgraded = 0;
    let totalSilenceFn = 0;
    const byVerdict: Record<string, { upgraded: number; silence_fn: number }> = {};

    for (const r of rows) {
      const upgraded = Number(r.upgraded_count) || 0;
      const silenceFn = Number(r.silence_fn_count) || 0;
      totalUpgraded += upgraded;
      totalSilenceFn += silenceFn;
      const verdict = r.prior_verdict || 'unknown';
      const bucket = byVerdict[verdict] ?? (byVerdict[verdict] = { upgraded: 0, silence_fn: 0 });
      bucket.upgraded += upgraded;
      bucket.silence_fn += silenceFn;
    }

    const summary = {
      projects_checked: projectsWithDrift.size,
      total_upgraded: totalUpgraded,
      total_silence_fn: totalSilenceFn,
      by_verdict: byVerdict,
    };

    if (totalSilenceFn > 0) {
      // The dangerous case: a previously-silenced-to-depscore-0 finding is now
      // reachable. Log loudly with the per-verdict breakdown + the offending
      // projects so on-call can investigate which silence heuristic regressed.
      const fnProjects = rows
        .filter((r) => Number(r.silence_fn_count) > 0)
        .map((r) => ({ project_id: r.project_id, prior_verdict: r.prior_verdict, silence_fn: Number(r.silence_fn_count) }));
      console.error('[silence-drift] SILENCE FALSE-NEGATIVES DETECTED', {
        ...summary,
        fn_projects: fnProjects.slice(0, 25),
      });
    } else if (totalUpgraded > 0) {
      // Promotions but no FN (e.g. unreachable→module — a healthy R1 floor).
      console.warn('[silence-drift] promotions detected (no silence-FN)', summary);
    } else {
      console.info('[silence-drift] ok', summary);
    }

    return res.json({ ok: totalSilenceFn === 0, ...summary });
  } catch (err: any) {
    console.error('[silence-drift] threw', err?.message ?? err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
