import { Router, Request, Response } from 'express';
import { supabase } from '../lib/supabase';
import { isValidInternalKey } from '../middleware/internal-key';

const router = Router();

/**
 * POST /api/workers/scanner-cache-reap
 *
 * Daily QStash cron (03:00 UTC) — runs two container-scan maintenance reaps,
 * sharing one retention window:
 *
 *   1. `cleanup_container_image_scan_cache(N)` — drops global digest-keyed
 *      cache rows older than retention. Without this, the cache grows at
 *      ~3 GB / month for a healthy customer scanning 100 unique digests/day.
 *   2. `cleanup_dismissed_base_image_recommendations(N)` — drops dismissed
 *      base-image recommendation rows older than retention. Without this,
 *      dismissed rows accumulate forever.
 *
 * Both reaps are RETURNS INTEGER, so the row counts in the response are real.
 *
 * Retention windows differ on purpose: the cache reaper uses `retention_days`
 * (default 30) — global per-digest data that is cheap to regenerate. The
 * recommendation reaper uses `recommendation_retention_days` (default 90,
 * matching cleanup_dismissed_base_image_recommendations' RPC default) because
 * a dismissed recommendation is user-actioned state that operators should be
 * able to review for a longer window before it is purged.
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

  if (!authorized && isValidInternalKey(providedKey)) {
    authorized = true;
  }

  if (!authorized) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // 30-day retention default for the global cache (matches phase27b's reaper
  // signature). 90-day default for dismissed recommendations (matches
  // cleanup_dismissed_base_image_recommendations' own DEFAULT 90) — operators
  // expect user-actioned state to outlive ephemeral cache rows.
  const retentionDays = Number(req.body?.retention_days ?? 30);
  if (!Number.isFinite(retentionDays) || retentionDays < 1 || retentionDays > 365) {
    return res.status(400).json({ error: 'retention_days must be between 1 and 365' });
  }
  const recommendationRetentionDays = Number(
    req.body?.recommendation_retention_days ?? 90
  );
  if (
    !Number.isFinite(recommendationRetentionDays) ||
    recommendationRetentionDays < 1 ||
    recommendationRetentionDays > 365
  ) {
    return res.status(400).json({ error: 'recommendation_retention_days must be between 1 and 365' });
  }

  try {
    const { data: cacheData, error: cacheError } = await supabase.rpc(
      'cleanup_container_image_scan_cache',
      { retention_days: retentionDays }
    );
    if (cacheError) throw cacheError;
    const cacheRowsDeleted =
      typeof cacheData === 'number' ? cacheData : Number(cacheData) || 0;

    const { data: recData, error: recError } = await supabase.rpc(
      'cleanup_dismissed_base_image_recommendations',
      { retention_days: recommendationRetentionDays }
    );
    if (recError) throw recError;
    const recommendationRowsDeleted =
      typeof recData === 'number' ? recData : Number(recData) || 0;

    res.json({
      ok: true,
      cache_rows_deleted: cacheRowsDeleted,
      recommendation_rows_deleted: recommendationRowsDeleted,
      retention_days: retentionDays,
      recommendation_retention_days: recommendationRetentionDays,
    });
  } catch (err: any) {
    console.error('[ScannerCacheReaper] Error:', err.message);
    res.status(500).json({ error: 'Failed to reap scanner cache' });
  }
});

export default router;
