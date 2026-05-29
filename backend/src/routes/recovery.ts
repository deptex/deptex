import express from 'express';
import { supabase as getSupabaseClient } from '../lib/supabase';
import { isValidInternalKey } from '../middleware/internal-key';

const router = express.Router();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw =
    (req.headers['x-internal-api-key'] as string) ||
    (req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined);
  const key = raw?.trim();
  if (!isValidInternalKey(key)) {
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

    // Start machines for orphaned queued jobs
    let machinesStarted = 0;
    const { data: orphanedJobs } = await supabase
      .from('scan_jobs')
      .select('id')
      .eq('type', 'extraction')
      .eq('status', 'queued')
      .order('created_at', { ascending: true })
      .limit(5);

    if (orphanedJobs?.length) {
      let startExtractionMachine: (() => Promise<string | null>) | null = null;
      try {
        const flyMachines = require('../lib/fly-machines');
        startExtractionMachine = flyMachines.startExtractionMachine;
      } catch {
        // fly-machines not available (CE mode or not configured)
      }

      if (startExtractionMachine) {
        for (const _job of orphanedJobs) {
          try {
            await startExtractionMachine();
            machinesStarted++;
          } catch {
            // logged inside startExtractionMachine
          }
        }
      }
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
      `[RECOVERY] Requeued ${requeuedCount} stuck jobs, failed ${failedCount} exhausted jobs, started ${machinesStarted} machines for ${orphanedJobs?.length ?? 0} orphaned jobs, reaped ${orphanReap?.runs_reaped ?? 0} orphan runs (${bucketFilesRemoved} bucket files)`
    );

    res.json({
      requeued: requeuedCount,
      failed: failedCount,
      orphaned_jobs_found: orphanedJobs?.length ?? 0,
      machines_started: machinesStarted,
      orphan_runs_reaped: orphanReap?.runs_reaped ?? 0,
      orphan_bucket_files_removed: bucketFilesRemoved,
    });
  } catch (error: any) {
    console.error('[RECOVERY] Error:', error);
    res.status(500).json({ error: error.message || 'Recovery failed' });
  }
});

export default router;
