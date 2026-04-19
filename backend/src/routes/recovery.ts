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

    const { data: requeued, error: requeueError } = await supabase.rpc('recover_stuck_extraction_jobs');
    if (requeueError) {
      console.error('[RECOVERY] Failed to recover stuck jobs:', requeueError.message);
    }

    const { data: failed, error: failError } = await supabase.rpc('fail_exhausted_extraction_jobs');
    if (failError) {
      console.error('[RECOVERY] Failed to fail exhausted jobs:', failError.message);
    }

    const requeuedCount = Array.isArray(requeued) ? requeued.length : 0;
    const failedCount = Array.isArray(failed) ? failed.length : 0;

    // Log recovery actions to extraction_logs
    if (Array.isArray(requeued)) {
      for (const job of requeued) {
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
    }

    // Start machines for orphaned queued jobs
    let machinesStarted = 0;
    const { data: orphanedJobs } = await supabase
      .from('extraction_jobs')
      .select('id')
      .eq('status', 'queued')
      .order('created_at', { ascending: true })
      .limit(5);

    if (orphanedJobs?.length) {
      let startExtractionMachine: (() => Promise<string | null>) | null = null;
      try {
        const flyMachines = require('../../../ee/backend/lib/fly-machines');
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

    console.log(
      `[RECOVERY] Requeued ${requeuedCount} stuck jobs, failed ${failedCount} exhausted jobs, started ${machinesStarted} machines for ${orphanedJobs?.length ?? 0} orphaned jobs`
    );

    res.json({
      requeued: requeuedCount,
      failed: failedCount,
      orphaned_jobs_found: orphanedJobs?.length ?? 0,
      machines_started: machinesStarted,
    });
  } catch (error: any) {
    console.error('[RECOVERY] Error:', error);
    res.status(500).json({ error: error.message || 'Recovery failed' });
  }
});

export default router;
