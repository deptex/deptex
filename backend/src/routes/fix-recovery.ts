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
 * POST /api/internal/recovery/fix-jobs
 * Called by QStash cron every 5 minutes.
 * Requeues stuck fix jobs, fails exhausted jobs, starts machines for orphans.
 */
router.post('/fix-jobs', async (_req, res) => {
  try {
    const supabase = getSupabaseClient;

    const { data: requeued, error: requeueError } = await supabase.rpc('recover_stuck_fix_jobs');
    if (requeueError) {
      console.error('[FIX-RECOVERY] Failed to recover stuck jobs:', requeueError.message);
    }

    const { data: failed, error: failError } = await supabase.rpc('fail_exhausted_fix_jobs');
    if (failError) {
      console.error('[FIX-RECOVERY] Failed to fail exhausted jobs:', failError.message);
    }

    const requeuedCount = Array.isArray(requeued) ? requeued.length : 0;
    const failedCount = Array.isArray(failed) ? failed.length : 0;

    if (Array.isArray(requeued)) {
      for (const job of requeued) {
        await supabase.from('extraction_logs').insert({
          project_id: job.project_id,
          run_id: job.run_id,
          step: 'complete',
          level: 'warning',
          message: `Fix attempt ${job.attempts} failed (machine unresponsive) — automatically retrying...`,
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
          message: `Fix failed after ${job.attempts} attempts — machine crashed or timed out.`,
        }).then(() => {});
      }
    }

    // Start machines for orphaned queued jobs (up to 3)
    let machinesStarted = 0;
    const { data: orphanedJobs } = await supabase
      .from('project_security_fixes')
      .select('id')
      .eq('status', 'queued')
      .order('created_at', { ascending: true })
      .limit(3);

    if (orphanedJobs?.length) {
      let startAiderMachine: (() => Promise<string | null>) | null = null;
      try {
        const flyMachines = require('../lib/fly-machines');
        startAiderMachine = flyMachines.startAiderMachine;
      } catch {
        // fly-machines not available
      }

      if (startAiderMachine) {
        for (const _job of orphanedJobs) {
          try {
            await startAiderMachine();
            machinesStarted++;
          } catch {
            // logged inside startAiderMachine
          }
        }
      }
    }

    console.log(
      `[FIX-RECOVERY] Requeued ${requeuedCount}, failed ${failedCount}, started ${machinesStarted} machines for ${orphanedJobs?.length ?? 0} orphaned jobs`
    );

    res.json({
      requeued: requeuedCount,
      failed: failedCount,
      orphaned_jobs_found: orphanedJobs?.length ?? 0,
      machines_started: machinesStarted,
    });
  } catch (error: any) {
    console.error('[FIX-RECOVERY] Error:', error);
    res.status(500).json({ error: error.message || 'Recovery failed' });
  }
});

export default router;
