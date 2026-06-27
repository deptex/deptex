/**
 * Security-summary self-heal cron + backfill endpoint.
 *
 * The org overview reads denormalized project_security_summaries rows that are
 * recomputed at scan-finalize and on every finding-state mutation (see
 * lib/security-summary.ts + the hook list in the overview-instant-load plan). This
 * endpoint is the safety net: it re-runs recompute_all_project_summaries so any row a
 * hook missed (or a future unhooked mutation path) self-corrects, bounding drift to
 * the cron interval.
 *
 * Two modes via the JSON body:
 *   { "stale_before": "<ISO ts>" }  → recompute only rows older than that (the daily
 *                                     reconciliation) plus any project with no row yet.
 *   {}  /  { "stale_before": null } → recompute EVERY project (the one-time post-deploy
 *                                     backfill). Run this once after deploy.
 *
 * Endpoint: POST /api/internal/security-summary/refresh
 * Auth: INTERNAL_API_KEY (x-internal-api-key header) OR QStash signature.
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { isValidInternalKey } from '../middleware/internal-key';

const router = express.Router();

async function verifyAuth(req: express.Request): Promise<boolean> {
  const headerKey = req.headers['x-internal-api-key'];
  if (typeof headerKey === 'string' && isValidInternalKey(headerKey)) return true;

  try {
    const currentSigningKey = process.env.QSTASH_CURRENT_SIGNING_KEY;
    const nextSigningKey = process.env.QSTASH_NEXT_SIGNING_KEY;
    if (!currentSigningKey) return false;
    const signature = req.headers['upstash-signature'] as string | undefined;
    if (!signature) return false;
    const { Receiver } = await import('@upstash/qstash');
    const receiver = new Receiver({ currentSigningKey, nextSigningKey } as any);
    const rawBody = (req as any).rawBody || JSON.stringify(req.body);
    await receiver.verify({ signature, body: rawBody });
    return true;
  } catch {
    return false;
  }
}

router.post('/refresh', async (req, res) => {
  if (!(await verifyAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // staleBefore null/absent = full backfill; a timestamp = only rows older than it
  // (plus projects with no row yet). Reject a malformed timestamp rather than silently
  // treating it as a full backfill.
  const raw = (req.body ?? {}).stale_before;
  let staleBefore: string | null = null;
  if (raw != null) {
    if (typeof raw !== 'string' || Number.isNaN(Date.parse(raw))) {
      return res.status(400).json({ error: 'stale_before must be an ISO timestamp or null' });
    }
    staleBefore = new Date(raw).toISOString();
  }

  try {
    const { data, error } = await supabase.rpc('recompute_all_project_summaries', {
      p_stale_before: staleBefore,
    });
    if (error) {
      console.error('[security-summary] refresh RPC failed', error);
      return res.status(500).json({ error: 'RPC failed' });
    }
    const recomputed = typeof data === 'number' ? data : 0;
    console.info(`[security-summary] refresh ok — recomputed ${recomputed} project(s) (stale_before=${staleBefore ?? 'ALL'})`);
    return res.json({ ok: true, recomputed, stale_before: staleBefore });
  } catch (err: any) {
    console.error('[security-summary] refresh threw', err?.message ?? err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
