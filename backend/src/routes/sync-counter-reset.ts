import { Router, Request, Response } from 'express';

const router = Router();

/**
 * POST /api/workers/reset-sync-counters
 * QStash cron (hourly) or manual trigger via X-Internal-Api-Key.
 * Resets syncs_used for orgs whose billing period has ended.
 */
router.post('/reset-sync-counters', async (req: Request, res: Response) => {
  const internalKey = process.env.INTERNAL_API_KEY;
  const providedKey = req.headers['x-internal-api-key'] as string;
  const rawBody = (req as any).rawBody;

  let authorized = false;

  // QStash signature verification
  if (rawBody && process.env.QSTASH_CURRENT_SIGNING_KEY) {
    try {
      const { Receiver } = require('@upstash/qstash');
      const receiver = new Receiver({
        currentSigningKey: process.env.QSTASH_CURRENT_SIGNING_KEY,
        nextSigningKey: process.env.QSTASH_NEXT_SIGNING_KEY || '',
      });
      await receiver.verify({
        signature: req.headers['upstash-signature'] as string,
        body: rawBody,
      });
      authorized = true;
    } catch { /* not from QStash */ }
  }

  if (!authorized && internalKey && providedKey === internalKey) {
    authorized = true;
  }

  if (!authorized) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    let resetCount = 0;
    try {
      const { resetDueSyncCounters } = require('../../../ee/backend/lib/stripe');
      resetCount = await resetDueSyncCounters();
    } catch {
      return res.status(503).json({ error: 'Billing module not available' });
    }

    res.json({ ok: true, reset_count: resetCount });
  } catch (err: any) {
    console.error('[SyncCounterReset] Error:', err.message);
    res.status(500).json({ error: 'Failed to reset sync counters' });
  }
});

export default router;
