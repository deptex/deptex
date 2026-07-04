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

    // Crash-wake: closes the only path where a user follow-up was silently
    // stranded — a machine crash DURING a run that had a queued message (the
    // worker's end-of-run drain never got to run). For each just-failed agent
    // row whose task thread has a user message newer than the run, re-queue it
    // via wake_agent_fix. Woken rows land 'approved', so the orphaned-approved
    // sweep below boots a machine for them in this same cron pass.
    let crashWakes = 0;
    if (Array.isArray(failed)) {
      for (const job of failed) {
        try {
          if (job.strategy !== 'agent' || !job.thread_id || !job.task_id) continue;
          // v1 guard (mirrors the worker's end-of-run drain): single-target
          // tasks only — a multi-row task's rows share one thread, so a wake
          // here could re-run the wrong target.
          const { data: siblings } = await supabase
            .from('project_security_fixes')
            .select('id')
            .eq('task_id', job.task_id)
            .eq('strategy', 'agent')
            .limit(2);
          if ((siblings?.length ?? 0) > 1) continue;
          const runStart = job.started_at ?? job.approved_at;
          if (!runStart) continue;
          const { data: pendingMsgs } = await supabase
            .from('aegis_chat_messages')
            .select('id')
            .eq('thread_id', job.thread_id)
            .eq('role', 'user')
            .gt('created_at', runStart)
            .limit(1);
          if (!pendingMsgs?.length) continue;
          const { data: wokeId } = await supabase.rpc('wake_agent_fix', { p_fix_id: job.id });
          if (!wokeId) continue;
          crashWakes++;
          await supabase.from('extraction_logs').insert({
            project_id: job.project_id,
            run_id: job.run_id,
            step: 'complete',
            level: 'warning',
            message: 'Fix machine crashed mid-run with a pending follow-up — re-queued to resume.',
          }).then(() => {});
        } catch (e: any) {
          console.error('[FIX-RECOVERY] crash-wake check failed for fix', job?.id, e?.message ?? e);
        }
      }
    }

    // Start fix-worker machines for orphaned approved jobs (up to 3).
    // The new flow uses status='approved' rather than the legacy 'queued'.
    let machinesStarted = 0;
    const { data: orphanedJobs } = await supabase
      .from('project_security_fixes')
      .select('id')
      .eq('status', 'approved')
      .order('approved_at', { ascending: true })
      .limit(3);

    if (orphanedJobs?.length) {
      let startFixMachine: (() => Promise<string | null>) | null = null;
      try {
        const flyMachines = require('../lib/fly-machines');
        startFixMachine = flyMachines.startFixMachine;
      } catch {
        // fly-machines not available
      }

      if (startFixMachine) {
        for (const _job of orphanedJobs) {
          try {
            await startFixMachine();
            machinesStarted++;
          } catch {
            // logged inside startFixMachine
          }
        }
      }
    }

    console.log(
      `[FIX-RECOVERY] Requeued ${requeuedCount}, failed ${failedCount}, crash-woke ${crashWakes}, started ${machinesStarted} machines for ${orphanedJobs?.length ?? 0} orphaned jobs`
    );

    res.json({
      requeued: requeuedCount,
      failed: failedCount,
      crash_wakes: crashWakes,
      orphaned_jobs_found: orphanedJobs?.length ?? 0,
      machines_started: machinesStarted,
    });
  } catch (error: any) {
    console.error('[FIX-RECOVERY] Error:', error);
    res.status(500).json({ error: error.message || 'Recovery failed' });
  }
});

export default router;
