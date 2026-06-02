import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';

const router = express.Router();

/**
 * Local admin gate. Reads ADMIN_EMAIL from env (comma-separated list).
 * Fails closed: if ADMIN_EMAIL is empty/unset, all requests 403.
 */
function requireAdmin(req: AuthRequest, res: express.Response, next: express.NextFunction) {
  const raw = process.env.ADMIN_EMAIL || '';
  const allowlist = raw
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.length > 0);

  if (allowlist.length === 0) {
    res.status(403).json({ error: 'Admin access is not configured' });
    return;
  }

  const email = req.user?.email?.trim().toLowerCase();
  if (!email || !allowlist.includes(email)) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }

  next();
}

// All admin routes require authenticated user AND the admin gate.
router.use(authenticateUser);
router.use(requireAdmin);

/**
 * GET /api/admin/ping
 * Used by the frontend AdminGate to verify access before rendering the page.
 */
router.get('/ping', (req: AuthRequest, res) => {
  res.json({ ok: true, email: req.user?.email || '' });
});

/**
 * GET /api/admin/fleet-metrics?type=extraction
 * Live fleet-dispatcher metrics for the admin panel: queue depth, running /
 * starting / inflight machine counts vs MAX_FLEET, hourly spend vs cap, and
 * queue-wait percentiles + throughput over the last hour.
 */
router.get('/fleet-metrics', async (req: AuthRequest, res) => {
  try {
    const type = typeof req.query.type === 'string' ? req.query.type : 'extraction';
    const { getFleetMetrics } = require('../lib/fleet-dispatcher');
    const metrics = await getFleetMetrics(type);
    res.json(metrics);
  } catch (e: any) {
    console.error('[admin/fleet-metrics] error:', e?.message ?? e);
    res.status(500).json({ error: 'Failed to load fleet metrics' });
  }
});

/**
 * GET /api/admin/extraction-failures
 * Paginated list of Phase 19 extraction_step_errors rows, with project names joined.
 *
 * Query params:
 *   page (default 1), per_page (default 50, max 200)
 *   step, code, severity ('warn'|'error'), project_id, since (ISO timestamp)
 */
router.get('/extraction-failures', async (req: AuthRequest, res) => {
  try {
    const pageRaw = parseInt(String(req.query.page ?? '1'), 10);
    const perPageRaw = parseInt(String(req.query.per_page ?? '50'), 10);
    const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
    const perPage = Math.min(
      Math.max(Number.isFinite(perPageRaw) && perPageRaw > 0 ? perPageRaw : 50, 1),
      200,
    );

    const step = typeof req.query.step === 'string' && req.query.step.trim() ? req.query.step.trim() : undefined;
    const code = typeof req.query.code === 'string' && req.query.code.trim() ? req.query.code.trim() : undefined;
    const severityRaw = typeof req.query.severity === 'string' ? req.query.severity.trim() : undefined;
    const severity = severityRaw === 'warn' || severityRaw === 'error' ? severityRaw : undefined;
    const projectId = typeof req.query.project_id === 'string' && req.query.project_id.trim() ? req.query.project_id.trim() : undefined;
    const since = typeof req.query.since === 'string' && req.query.since.trim() ? req.query.since.trim() : undefined;

    const from = (page - 1) * perPage;
    const to = from + perPage - 1;

    let query = supabase
      .from('extraction_step_errors')
      .select(
        'id, extraction_job_id, project_id, step, code, severity, message, stack, machine_id, duration_ms, created_at',
        { count: 'exact' },
      )
      .order('created_at', { ascending: false })
      .range(from, to);

    if (step) query = query.eq('step', step);
    if (code) query = query.eq('code', code);
    if (severity) query = query.eq('severity', severity);
    if (projectId) query = query.eq('project_id', projectId);
    if (since) query = query.gte('created_at', since);

    const { data, error, count } = await query;
    if (error) {
      console.error('[admin/extraction-failures] query error:', error);
      res.status(500).json({ error: error.message || 'Failed to list extraction failures' });
      return;
    }

    const rows = data ?? [];
    const projectIds = Array.from(new Set(rows.map((r) => r.project_id).filter(Boolean)));
    const nameById: Record<string, string> = {};
    if (projectIds.length > 0) {
      const { data: projects, error: projErr } = await supabase
        .from('projects')
        .select('id, name')
        .in('id', projectIds);
      if (projErr) {
        console.error('[admin/extraction-failures] project lookup error:', projErr);
        // Don't fail the whole request — just return rows without names.
      } else {
        for (const p of projects ?? []) {
          if (p?.id) nameById[p.id] = p.name ?? '';
        }
      }
    }

    const withNames = rows.map((r) => ({
      ...r,
      project_name: nameById[r.project_id] ?? null,
    }));

    res.json({
      data: withNames,
      total: count ?? withNames.length,
      page,
      per_page: perPage,
    });
  } catch (error: any) {
    console.error('[admin/extraction-failures] unexpected error:', error);
    res.status(500).json({ error: error?.message || 'Unexpected error' });
  }
});

/**
 * GET /api/admin/overview
 * Platform-wide health snapshot for the Deptex-staff admin console. Read-only
 * counts + billing rollups aggregated from existing tables (no dedicated events
 * table). Counts run DB-side (head:true); the two sums fetch a single column and
 * reduce in-process — trivial at current org/transaction scale. If org or
 * transaction volume grows large, move the sums into a SQL RPC.
 *
 * Sign convention (phase37): usage_deduction rows are negative; topup /
 * auto_recharge_topup / signup_grant are positive. Revenue counts only real
 * money in (topup + auto_recharge_topup), excluding the signup_grant free credit.
 *
 * Note: billing_stripe_webhook_events has no organization_id, so failed-payment
 * counts are an aggregate metric only — not attributable per-org in the feed.
 * The activity feed sources from billing_transactions (which carries org_id).
 */
router.get('/overview', async (_req: AuthRequest, res) => {
  try {
    const now = Date.now();
    const since30d = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
    const since7d = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    const FAILED_PAYMENT_EVENTS = ['payment_intent.payment_failed', 'invoice.payment_failed'];
    const ACTIVITY_KINDS = ['topup', 'auto_recharge_topup', 'refund', 'adjustment', 'signup_grant'];

    const [
      orgCount,
      projectCount,
      memberRows,
      scanCount,
      balanceRows,
      revenueRows,
      autoRechargeCount,
      zeroBalanceCount,
      failedPaymentCount,
      activityRows,
    ] = await Promise.all([
      supabase.from('organizations').select('*', { count: 'exact', head: true }),
      supabase.from('projects').select('*', { count: 'exact', head: true }),
      supabase.from('organization_members').select('user_id'),
      supabase.from('scan_jobs').select('*', { count: 'exact', head: true }).gte('created_at', since30d),
      supabase.from('organization_billing').select('balance_cents'),
      supabase
        .from('billing_transactions')
        .select('amount_cents')
        .in('kind', ['topup', 'auto_recharge_topup'])
        .gte('created_at', since30d),
      supabase
        .from('organization_billing')
        .select('*', { count: 'exact', head: true })
        .eq('auto_recharge_enabled', true),
      supabase
        .from('organization_billing')
        .select('*', { count: 'exact', head: true })
        .eq('balance_cents', 0),
      supabase
        .from('billing_stripe_webhook_events')
        .select('*', { count: 'exact', head: true })
        .in('event_type', FAILED_PAYMENT_EVENTS)
        .gte('processed_at', since7d),
      supabase
        .from('billing_transactions')
        .select('id, organization_id, kind, amount_cents, description, created_at')
        .in('kind', ACTIVITY_KINDS)
        .order('created_at', { ascending: false })
        .limit(20),
    ]);

    // Surface the first hard error rather than returning a half-populated payload.
    const firstError =
      orgCount.error ||
      projectCount.error ||
      memberRows.error ||
      scanCount.error ||
      balanceRows.error ||
      revenueRows.error ||
      autoRechargeCount.error ||
      zeroBalanceCount.error ||
      failedPaymentCount.error ||
      activityRows.error;
    if (firstError) {
      console.error('[admin/overview] query error:', firstError);
      res.status(500).json({ error: firstError.message || 'Failed to load overview' });
      return;
    }

    const distinctUsers = new Set(
      (memberRows.data ?? []).map((r: any) => r.user_id).filter(Boolean),
    ).size;
    const totalBalanceCents = (balanceRows.data ?? []).reduce(
      (s: number, r: any) => s + (r.balance_cents ?? 0),
      0,
    );
    const revenue30dCents = (revenueRows.data ?? []).reduce(
      (s: number, r: any) => s + (r.amount_cents ?? 0),
      0,
    );

    // Join org names onto the activity rows (non-fatal if the lookup fails).
    const activity = activityRows.data ?? [];
    const orgIds = Array.from(new Set(activity.map((r: any) => r.organization_id).filter(Boolean)));
    const nameById: Record<string, string> = {};
    if (orgIds.length > 0) {
      const { data: orgs, error: orgErr } = await supabase
        .from('organizations')
        .select('id, name')
        .in('id', orgIds);
      if (orgErr) {
        console.error('[admin/overview] org name lookup error:', orgErr);
      } else {
        for (const o of orgs ?? []) {
          if (o?.id) nameById[o.id] = o.name ?? '';
        }
      }
    }

    res.json({
      totals: {
        organizations: orgCount.count ?? 0,
        projects: projectCount.count ?? 0,
        users: distinctUsers,
        scans30d: scanCount.count ?? 0,
      },
      billing: {
        totalBalanceCents,
        revenue30dCents,
        autoRechargeOn: autoRechargeCount.count ?? 0,
        zeroBalanceOrgs: zeroBalanceCount.count ?? 0,
        failedPayments7d: failedPaymentCount.count ?? 0,
      },
      recentActivity: activity.map((r: any) => ({
        id: r.id,
        kind: r.kind,
        amount_cents: r.amount_cents,
        description: r.description ?? null,
        organization_id: r.organization_id,
        organization_name: nameById[r.organization_id] ?? null,
        created_at: r.created_at,
      })),
    });
  } catch (error: any) {
    console.error('[admin/overview] unexpected error:', error);
    res.status(500).json({ error: error?.message || 'Unexpected error' });
  }
});

export default router;
