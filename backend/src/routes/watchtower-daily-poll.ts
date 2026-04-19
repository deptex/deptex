/**
 * 8O: Watchtower Daily Poll (QStash cron endpoint)
 * Mounted at /api/workers (see backend/src/index.ts).
 * Schedule: 0 4 * * * (daily at 4 AM UTC)
 */

import express from 'express';
import {
  runDependencyRefresh,
  runPollSweep,
  runWebhookHealthCheck,
  cleanupOldWebhookDeliveries,
} from '../lib/watchtower-poll';

const router = express.Router();

async function verifyInternalAuth(req: express.Request): Promise<boolean> {
  const internalKey = process.env.INTERNAL_API_KEY;
  if (internalKey && req.headers['x-internal-api-key'] === internalKey) return true;

  try {
    const qstashKeys = {
      currentSigningKey: process.env.QSTASH_CURRENT_SIGNING_KEY,
      nextSigningKey: process.env.QSTASH_NEXT_SIGNING_KEY,
    };
    if (!qstashKeys.currentSigningKey) return false;
    const signature = req.headers['upstash-signature'] as string;
    if (!signature) return false;
    const { Receiver } = await import('@upstash/qstash');
    const receiver = new Receiver(qstashKeys as any);
    const rawBody = (req as any).rawBody || JSON.stringify(req.body);
    await receiver.verify({ signature, body: rawBody });
    return true;
  } catch {
    return false;
  }
}

router.post('/watchtower-daily-poll', async (req, res) => {
  if (!(await verifyInternalAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const startTime = Date.now();

  try {
    const refreshResult = await runDependencyRefresh();
    const sweepResult = await runPollSweep();
    const healthResult = await runWebhookHealthCheck();
    const cleanupResult = await cleanupOldWebhookDeliveries();

    const elapsed = Date.now() - startTime;
    console.log(`[watchtower-daily-poll] Complete in ${elapsed}ms`);

    res.json({
      deps_refreshed: refreshResult.processed,
      vulns_updated: refreshResult.vulnsUpdated,
      packages_polled: sweepResult.packagesPolled,
      webhooks_marked_inactive: healthResult.markedInactive,
      deliveries_cleaned: cleanupResult.deleted,
      elapsed_ms: elapsed,
    });
  } catch (error: any) {
    console.error('[watchtower-daily-poll] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
