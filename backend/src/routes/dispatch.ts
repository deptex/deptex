import express from 'express';
import { dispatchFleet, getFleetMetrics } from '../lib/fleet-dispatcher';

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
 * POST /api/internal/dispatch/extraction
 * Run one fleet-dispatcher tick for extraction. Idempotent + single-flight
 * (Redis lock). Called by the enqueue nudge and the every-minute cron.
 */
router.post('/extraction', async (_req, res) => {
  try {
    const result = await dispatchFleet('extraction');
    res.json(result);
  } catch (e: any) {
    console.error('[dispatch] extraction tick failed:', e?.message ?? e);
    res.status(500).json({ error: 'dispatch failed' });
  }
});

/**
 * GET /api/internal/dispatch/metrics?type=extraction
 * Live fleet metrics for the admin panel (queue depth, fleet size, throughput,
 * queue-wait percentiles, spend).
 */
router.get('/metrics', async (req, res) => {
  try {
    const type = typeof req.query.type === 'string' ? req.query.type : 'extraction';
    const metrics = await getFleetMetrics(type);
    res.json(metrics);
  } catch (e: any) {
    console.error('[dispatch] metrics failed:', e?.message ?? e);
    res.status(500).json({ error: 'metrics failed' });
  }
});

export default router;
