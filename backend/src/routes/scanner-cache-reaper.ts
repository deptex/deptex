import { Router, Request, Response } from 'express';
import { supabase } from '../lib/supabase';

const router = Router();

/**
 * POST /api/workers/scanner-cache-reap
 *
 * Daily QStash cron (03:00 UTC) — drops container_image_scan_cache rows older
 * than the retention window via the `cleanup_container_image_scan_cache(N)`
 * plpgsql function shipped in phase27b. Without this, the cache grows
 * unbounded at ~3 GB / month for a healthy customer scanning 100 unique
 * digests/day.
 *
 * Auth: QStash signature OR X-Internal-Api-Key header. Pattern mirrors
 * sync-counter-reset.ts.
 *
 * Operator setup (one-time): create the schedule via the Upstash dashboard or
 *   curl -X POST https://qstash.upstash.io/v2/schedules/<destination>/0%203%20*%20*%20* \
 *     -H "Authorization: Bearer $QSTASH_TOKEN" \
 *     -d '{"destination": "https://api.deptex.dev/api/workers/scanner-cache-reap"}'
 */
router.post('/scanner-cache-reap', async (req: Request, res: Response) => {
  const internalKey = process.env.INTERNAL_API_KEY;
  const providedKey = req.headers['x-internal-api-key'] as string | undefined;
  const rawBody = (req as any).rawBody;

  let authorized = false;

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
    } catch {
      /* not from QStash */
    }
  }

  if (!authorized && internalKey && providedKey === internalKey) {
    authorized = true;
  }

  if (!authorized) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // 30-day retention default; matches the migration's reaper signature.
  const retentionDays = Number(req.body?.retention_days ?? 30);
  if (!Number.isFinite(retentionDays) || retentionDays < 1 || retentionDays > 365) {
    return res.status(400).json({ error: 'retention_days must be between 1 and 365' });
  }

  try {
    const { data, error } = await supabase.rpc('cleanup_container_image_scan_cache', {
      retention_days: retentionDays,
    });
    if (error) throw error;
    const rowsDeleted = typeof data === 'number' ? data : Number(data) || 0;
    res.json({ ok: true, rows_deleted: rowsDeleted, retention_days: retentionDays });
  } catch (err: any) {
    console.error('[ScannerCacheReaper] Error:', err.message);
    res.status(500).json({ error: 'Failed to reap scanner cache' });
  }
});

export default router;
