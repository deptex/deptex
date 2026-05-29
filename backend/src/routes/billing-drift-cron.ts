/**
 * Billing Drift Cron — runs assert_balance_matches_ledger() across all orgs and alerts
 * if any org's balance_cents disagrees with sum(billing_transactions.amount_cents).
 *
 * Scheduled via QStash daily. The RPC returns one row per drifted org; an empty result
 * is the invariant-holds case. On drift, every billing_recipient gets an email so ops
 * can investigate before the gap grows.
 *
 * Endpoint: POST /api/internal/billing/check-ledger-drift
 * Auth: INTERNAL_API_KEY (single shared secret) OR QStash signature.
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { sendEmail } from '../lib/email';
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

interface DriftRow {
  organization_id: string;
  balance_cents: number;
  ledger_sum: number;
  drift_cents: number;
}

router.post('/check-ledger-drift', async (req, res) => {
  if (!(await verifyAuth(req))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { data, error } = await supabase.rpc('assert_balance_matches_ledger');
    if (error) {
      console.error('[billing] drift-cron RPC failed', error);
      return res.status(500).json({ error: 'RPC failed' });
    }

    const drifted = (data ?? []) as DriftRow[];
    if (drifted.length === 0) {
      console.info('[billing] drift-cron ok — no drift detected');
      return res.json({ ok: true, drifted: 0 });
    }

    // Drift is a financial-integrity incident: log loudly + email ops. We don't try to
    // auto-reconcile (could mask a real bug). The reconciliation playbook is in
    // docs/runbooks/billing-drift.md (to be authored).
    console.error('[billing] drift-cron DRIFT DETECTED', {
      count: drifted.length,
      rows: drifted.slice(0, 25),
    });

    const opsEmail = process.env.BILLING_OPS_ALERT_EMAIL?.trim();
    if (opsEmail) {
      const summary = drifted
        .slice(0, 25)
        .map(
          (r) =>
            `  org=${r.organization_id} balance=${r.balance_cents} ledger_sum=${r.ledger_sum} drift=${r.drift_cents}`,
        )
        .join('\n');
      await sendEmail({
        to: [opsEmail],
        subject: `Deptex billing — ledger drift detected (${drifted.length} org${drifted.length === 1 ? '' : 's'})`,
        text:
          `assert_balance_matches_ledger() returned ${drifted.length} drifted org${drifted.length === 1 ? '' : 's'}.\n\n` +
          `${summary}\n\n` +
          `Investigate before the gap grows. Do NOT auto-reconcile — find the root cause first.`,
      }).catch((err) => console.error('[billing] drift-cron alert email failed', err));
    } else {
      console.warn('[billing] drift-cron BILLING_OPS_ALERT_EMAIL not set; drift not emailed');
    }

    return res.json({ ok: false, drifted: drifted.length });
  } catch (err: any) {
    console.error('[billing] drift-cron threw', err?.message ?? err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

export default router;
