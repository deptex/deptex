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
 * POST /api/internal/recovery/watchtower-jobs
 * Called by QStash cron every 5 minutes.
 * Requeues stuck jobs, fails exhausted, starts machines for orphaned queued jobs.
 */
router.post('/watchtower-jobs', async (_req, res) => {
  try {
    const supabase = getSupabaseClient;

    const { data: recovered, error: recoverError } = await supabase.rpc('recover_stuck_watchtower_jobs');
    if (recoverError) {
      console.error('[WATCHTOWER-RECOVERY] Failed to recover stuck jobs:', recoverError.message);
    }

    const recoveredCount = typeof recovered === 'number' ? recovered : 0;

    let machinesStarted = 0;
    const { data: orphanedJobs } = await supabase
      .from('watchtower_jobs')
      .select('id')
      .eq('status', 'queued')
      .order('created_at', { ascending: true })
      .limit(1);

    if (orphanedJobs?.length) {
      let startWatchtowerMachine: (() => Promise<string | null>) | null = null;
      try {
        const flyMachines = require('../lib/fly-machines');
        startWatchtowerMachine = flyMachines.startWatchtowerMachine;
      } catch {
        // fly-machines not available in CE mode
      }

      if (startWatchtowerMachine) {
        try {
          await startWatchtowerMachine();
          machinesStarted++;
        } catch {
          // logged inside startWatchtowerMachine
        }
      }
    }

    console.log(
      `[WATCHTOWER-RECOVERY] Recovered ${recoveredCount} stuck jobs, started ${machinesStarted} machines for ${orphanedJobs?.length ?? 0} orphaned jobs`
    );

    res.json({
      recovered: recoveredCount,
      orphaned_jobs_found: orphanedJobs?.length ?? 0,
      machines_started: machinesStarted,
    });
  } catch (error: any) {
    console.error('[WATCHTOWER-RECOVERY] Error:', error);
    res.status(500).json({ error: error.message || 'Recovery failed' });
  }
});

export default router;
