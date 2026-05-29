import express from 'express';
import { supabase as getSupabaseClient } from '../lib/supabase';

const router = express.Router();

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw =
    (req.headers['x-internal-api-key'] as string) ||
    (req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined);
  const key = raw?.trim();
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

router.use(requireInternalKey);

/**
 * POST /api/internal/recovery/extraction-jobs
 * Called by QStash cron every 5 minutes.
 * Requeues stuck jobs, fails exhausted jobs, starts machines for orphaned queued jobs.
 */
router.post('/extraction-jobs', async (_req, res) => {
  try {
    const supabase = getSupabaseClient;

    const { data: requeued, error: requeueError } = await supabase.rpc('recover_stuck_scan_jobs');
    if (requeueError) {
      console.error('[RECOVERY] Failed to recover stuck jobs:', requeueError.message);
    }

    const { data: failed, error: failError } = await supabase.rpc('fail_exhausted_scan_jobs');
    if (failError) {
      console.error('[RECOVERY] Failed to fail exhausted jobs:', failError.message);
    }

    const requeuedCount = Array.isArray(requeued) ? requeued.length : 0;
    const failedCount = Array.isArray(failed) ? failed.length : 0;

    // Resolve fly-machines lazily so the recovery cron still runs in CE/local
    // mode where Fly is not configured.
    let stopFlyMachine: ((app: string, machineId: string) => Promise<void>) | null = null;
    let dastApp: string | null = null;
    try {
      const flyMachines = require('../lib/fly-machines');
      stopFlyMachine = flyMachines.stopFlyMachine;
      dastApp = flyMachines.DAST_CONFIG?.app ?? null;
    } catch {
      // fly-machines not available
    }

    // Log recovery actions to extraction_logs (extraction-only — DAST has no
    // log stream in v1; the failure surfaces on scan_jobs.error directly).
    if (Array.isArray(requeued)) {
      for (const job of requeued) {
        if (job.type !== 'extraction') continue;
        await supabase.from('extraction_logs').insert({
          project_id: job.project_id,
          run_id: job.run_id,
          step: 'complete',
          level: 'warning',
          message: `Extraction attempt ${job.attempts} failed (machine unresponsive) — automatically retrying...`,
        }).then(() => {});
      }
    }

    if (Array.isArray(failed)) {
      for (const job of failed) {
        if (job.type === 'extraction') {
          await supabase.from('extraction_logs').insert({
            project_id: job.project_id,
            run_id: job.run_id,
            step: 'complete',
            level: 'error',
            message: `Extraction failed after ${job.attempts} attempts — machine crashed or timed out. Try re-syncing from project settings.`,
          }).then(() => {});

          await supabase
            .from('project_repositories')
            .update({
              status: 'error',
              extraction_error: `Extraction failed after ${job.attempts} attempts`,
              extraction_step: null,
              updated_at: new Date().toISOString(),
            })
            .eq('project_id', job.project_id);
        }

        // Best-effort Fly machine stop. DAST scans burn billable seconds
        // until the host machine stops — extraction does too, but the
        // existing pool reuse path keeps cost bounded. This belt-and-braces
        // call is logged but never fails the recovery iteration.
        if (stopFlyMachine && dastApp && job.machine_id) {
          try {
            await stopFlyMachine(dastApp, job.machine_id);
          } catch (e: any) {
            console.warn(`[RECOVERY] Failed to stop Fly machine ${job.machine_id} for ${job.type} job ${job.id}: ${e?.message ?? e}`);
          }
        }
      }
    }

    // Provisioning is owned by the fleet dispatcher (single-flight, hard-capped
    // at FLY_MAX_FLEET). Trigger one tick in-process so requeued jobs get a
    // machine immediately; the every-minute cron is the standing safety net.
    // Redundant fallback: if the dispatcher is wedged and extraction work is
    // queued with nothing running, directly start one machine so the queue
    // never wedges on a single broken code path.
    let machinesStarted = 0;
    let zombiesReaped = 0;

    // Direct fallback: if the dispatcher can't provision and there's queued
    // extraction work with nothing processing, start one machine directly so the
    // queue never wedges on a single broken path. Returns machines started.
    const directProvisionFallback = async (): Promise<number> => {
      try {
        const { data: queued } = await supabase
          .from('scan_jobs')
          .select('id')
          .eq('type', 'extraction')
          .eq('status', 'queued')
          .limit(1);
        const { data: processing } = await supabase
          .from('scan_jobs')
          .select('id')
          .eq('type', 'extraction')
          .eq('status', 'processing')
          .limit(1);
        if (queued?.length && !processing?.length) {
          const { createDepscannerBurst } = require('../lib/fly-machines');
          await createDepscannerBurst();
          return 1;
        }
      } catch (e2: any) {
        console.error('[RECOVERY] direct fallback failed:', e2?.message ?? e2);
      }
      return 0;
    };

    try {
      const { dispatchFleet, reapZombieMachines } = require('../lib/fleet-dispatcher');
      const tick = await dispatchFleet('extraction');
      machinesStarted = tick?.started ?? 0;
      // The dispatcher FAILS CLOSED — on a Redis outage / snapshot failure / lock
      // contention it returns {error, started:0} WITHOUT throwing. Don't let that
      // silently wedge the queue: when it provisioned nothing because of an error,
      // run the direct fallback ourselves. (The catch below only covers an
      // import-time / synchronous throw, which is the rare case.)
      if (tick?.error && (tick?.started ?? 0) === 0) {
        console.warn(`[RECOVERY] dispatcher returned '${tick.error}' — trying direct fallback`);
        machinesStarted += await directProvisionFallback();
      }
      // Stop hung/zombie machines (started, no job, no heartbeat) to cap cost.
      try {
        const reap = await reapZombieMachines('extraction');
        zombiesReaped = reap?.stopped ?? 0;
      } catch (re: any) {
        console.warn('[RECOVERY] reapZombieMachines failed:', re?.message ?? re);
      }
    } catch (e: any) {
      console.error('[RECOVERY] dispatchFleet threw; attempting direct fallback:', e?.message ?? e);
      machinesStarted += await directProvisionFallback();
    }

    // Reap orphaned extractions (rows tagged with run_ids from failed/cancelled
    // jobs > 24h old that never went through finalize_extraction's inline reap).
    let orphanReap: {
      runs_reaped: number;
      orphan_runs: Array<{ project_id: string; run_id: string }>;
    } | null = null;
    let bucketFilesRemoved = 0;
    try {
      const { data: reapResult, error: reapError } = await supabase.rpc(
        'reap_orphaned_extractions',
        { p_older_than_hours: 24 }
      );
      if (reapError) {
        console.error('[RECOVERY] Orphan reap RPC failed:', reapError.message);
      } else if (reapResult) {
        orphanReap = reapResult as typeof orphanReap;

        // Clean up Supabase Storage bucket files for reaped runs.
        // Pipeline writes SBOM, dep-scan, semgrep, trufflehog outputs under
        // project-imports/${projectId}/${runId}/ — list + remove.
        for (const { project_id, run_id } of orphanReap?.orphan_runs ?? []) {
          try {
            const prefix = `${project_id}/${run_id}`;
            const { data: files } = await supabase.storage
              .from('project-imports')
              .list(prefix);
            if (files?.length) {
              const paths = files.map((f) => `${prefix}/${f.name}`);
              const { error: removeErr } = await supabase.storage
                .from('project-imports')
                .remove(paths);
              if (!removeErr) {
                bucketFilesRemoved += paths.length;
              }
            }
          } catch {
            // non-fatal — continue with next run
          }
        }
      }
    } catch (err: any) {
      console.error('[RECOVERY] Orphan reap error:', err?.message ?? err);
    }

    console.log(
      `[RECOVERY] Requeued ${requeuedCount} stuck jobs, failed ${failedCount} exhausted jobs, dispatcher started ${machinesStarted} machines, reaped ${zombiesReaped} zombie machines, reaped ${orphanReap?.runs_reaped ?? 0} orphan runs (${bucketFilesRemoved} bucket files)`
    );

    res.json({
      requeued: requeuedCount,
      failed: failedCount,
      machines_started: machinesStarted,
      zombies_reaped: zombiesReaped,
      orphan_runs_reaped: orphanReap?.runs_reaped ?? 0,
      orphan_bucket_files_removed: bucketFilesRemoved,
    });
  } catch (error: any) {
    console.error('[RECOVERY] Error:', error);
    res.status(500).json({ error: error.message || 'Recovery failed' });
  }
});

export default router;
