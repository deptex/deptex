/**
 * Retention pruner for the malicious-packages-v2 cache tables.
 *
 *   POST /api/internal/malicious/retention-prune
 *
 * Auth: INTERNAL_API_KEY only (called by the daily cron dispatcher).
 *
 * Deletes rows older than N days from:
 *   - package_capabilities (last `scanned_at` is the freshness column)
 *   - package_security_cache (last `created_at` is the freshness column;
 *     the GuardDog cache is what consumes the bulk of storage)
 *   - package_maintainer_snapshots (M1c historical baseline; `observed_at`
 *     is the freshness column; trimmed at MIN(retention_days, 90) so the
 *     30d-diff lookup always has a baseline window without unbounded growth)
 *
 * Threshold defaults to 180 days. Override via env var
 * `MALICIOUS_CACHE_RETENTION_DAYS` (integer; clamped to ≥ 7 days so a
 * misconfigured deploy can't accidentally wipe the cache to nothing).
 *
 * Per the brief: caches are GLOBAL — retention does NOT need to consider
 * org membership or any per-tenant policy. Stale rows just get re-scanned
 * lazily on the next extraction that touches the (package, version, eco).
 */
import express from 'express';
import { supabase } from '../lib/supabase';
import { isValidInternalKey } from '../middleware/internal-key';

const router = express.Router();

function verifyInternal(req: express.Request): boolean {
  const h = req.headers['x-internal-api-key'];
  if (typeof h === 'string' && isValidInternalKey(h)) return true;
  const auth = req.headers.authorization;
  if (typeof auth === 'string' && auth.startsWith('Bearer ') && isValidInternalKey(auth.slice(7))) return true;
  return false;
}

function retentionDays(): number {
  const raw = process.env.MALICIOUS_CACHE_RETENTION_DAYS;
  if (!raw) return 180;
  const parsed = parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 7) return 180;
  return parsed;
}

// Maintainer snapshots get a tighter window — 90d max — so the M1c 30d-diff
// baseline lookup always finds a reasonable predecessor without the table
// growing unbounded for popular packages that snapshot daily.
const MAINTAINER_SNAPSHOT_MAX_DAYS = 90;

router.post('/retention-prune', async (req, res) => {
  if (!verifyInternal(req)) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const days = retentionDays();
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

    const snapshotDays = Math.min(days, MAINTAINER_SNAPSHOT_MAX_DAYS);
    const snapshotCutoff = new Date(Date.now() - snapshotDays * 24 * 60 * 60 * 1000).toISOString();

    // package_capabilities — `scanned_at` is the freshness column. Use
    // `select('id', { count: 'exact' })` so we get a row count back.
    const capabilitiesResult = await supabase
      .from('package_capabilities')
      .delete({ count: 'exact' })
      .lt('scanned_at', cutoff);

    // package_security_cache — `created_at` is the freshness column.
    const cacheResult = await supabase
      .from('package_security_cache')
      .delete({ count: 'exact' })
      .lt('created_at', cutoff);

    // package_maintainer_snapshots — `observed_at` is the freshness column.
    const snapshotsResult = await supabase
      .from('package_maintainer_snapshots')
      .delete({ count: 'exact' })
      .lt('observed_at', snapshotCutoff);

    const result = {
      success: true,
      retention_days: days,
      maintainer_snapshot_days: snapshotDays,
      cutoff,
      maintainer_snapshot_cutoff: snapshotCutoff,
      deleted_capabilities: capabilitiesResult.count ?? 0,
      deleted_security_cache: cacheResult.count ?? 0,
      deleted_maintainer_snapshots: snapshotsResult.count ?? 0,
      capabilities_error: capabilitiesResult.error?.message ?? null,
      security_cache_error: cacheResult.error?.message ?? null,
      maintainer_snapshots_error: snapshotsResult.error?.message ?? null,
    };

    if (capabilitiesResult.error || cacheResult.error || snapshotsResult.error) {
      console.error('[malicious retention-prune] partial failure:', result);
    } else {
      console.log(
        `[malicious retention-prune] deleted ${result.deleted_capabilities} capability + ${result.deleted_security_cache} security_cache + ${result.deleted_maintainer_snapshots} maintainer-snapshot rows`,
      );
    }

    res.json(result);
  } catch (error: any) {
    console.error('[malicious retention-prune] failed:', error);
    res.status(500).json({ error: error?.message ?? 'retention-prune failed' });
  }
});

export default router;
