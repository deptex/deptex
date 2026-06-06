import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { fail } from '../lib/responders';
import { computeAdminBillingFinancials } from '../lib/billing/admin-financials';

const router = express.Router();

const DAY_MS = 24 * 60 * 60 * 1000;

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
    fail(res, e, 'Failed to load fleet metrics');
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
      fail(res, error, 'Failed to list extraction failures');
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
    fail(res, error, 'Failed to list extraction failures');
  }
});

/**
 * Page through a select() 1000 rows at a time (PostgREST's hard cap), ordered by
 * `orderCol` for stable paging. Capped at MAX_ROWS so a pathological table can't
 * hang the admin page; returns { rows, truncated } where truncated=true means the
 * cap was hit and the aggregate is a floor, not exact. `build` must return a fresh
 * query each call. Throws on the first DB error.
 */
async function paginateAll(
  build: () => any,
  orderCol = 'id',
): Promise<{ rows: any[]; truncated: boolean }> {
  const PAGE = 1000;
  const MAX_ROWS = 100_000;
  const rows: any[] = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const { data, error } = await build()
      .order(orderCol, { ascending: true })
      .range(from, from + PAGE - 1);
    if (error) throw error;
    const batch = data ?? [];
    rows.push(...batch);
    if (batch.length < PAGE) return { rows, truncated: false };
  }
  return { rows, truncated: true };
}

/**
 * Cumulative count per day over the last 365 days for the Overview growth chart.
 * Each day's value is how many items existed on or before that point in time.
 */
export function cumulativeGrowth(
  now: number,
  series: { orgs: number[]; projects: number[]; users: number[] },
): Array<{ date: string; orgs: number; projects: number; users: number }> {
  const so = series.orgs.slice().sort((a, b) => a - b);
  const sp = series.projects.slice().sort((a, b) => a - b);
  const su = series.users.slice().sort((a, b) => a - b);
  const countLE = (arr: number[], ms: number) => {
    let lo = 0;
    let hi = arr.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (arr[mid] <= ms) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  const out: Array<{ date: string; orgs: number; projects: number; users: number }> = [];
  for (let i = 364; i >= 0; i--) {
    const ms = now - i * DAY_MS;
    out.push({
      date: new Date(ms).toISOString().slice(0, 10),
      orgs: countLE(so, ms),
      projects: countLE(sp, ms),
      users: countLE(su, ms),
    });
  }
  return out;
}

/**
 * GET /api/admin/overview
 * Platform scale for the Deptex-staff admin console: current counts plus a
 * 365-day cumulative growth series (orgs / projects / distinct users). No billing
 * aggregation here — that lives on /api/admin/billing so this tab stays cheap.
 */
router.get('/overview', async (_req: AuthRequest, res) => {
  try {
    const now = Date.now();
    const since30d = new Date(now - 30 * DAY_MS).toISOString();

    const [orgCount, projectCount, memberRows, scanCount, orgDates, projectDates, memberDates] =
      await Promise.all([
        supabase.from('organizations').select('*', { count: 'exact', head: true }),
        supabase.from('projects').select('*', { count: 'exact', head: true }),
        supabase.from('organization_members').select('user_id'),
        supabase.from('scan_jobs').select('*', { count: 'exact', head: true }).gte('created_at', since30d),
        paginateAll(() => supabase.from('organizations').select('created_at'), 'created_at'),
        paginateAll(() => supabase.from('projects').select('created_at'), 'created_at'),
        paginateAll(() => supabase.from('organization_members').select('user_id, created_at'), 'created_at'),
      ]);

    const countError = orgCount.error || projectCount.error || memberRows.error || scanCount.error;
    if (countError) {
      fail(res, countError, 'Failed to load overview');
      return;
    }

    const distinctUsers = new Set(
      (memberRows.data ?? []).map((r: any) => r.user_id).filter(Boolean),
    ).size;

    // First-seen timestamp per user, so growth counts distinct users not memberships.
    const userFirst = new Map<string, number>();
    for (const r of memberDates.rows) {
      if (!r.user_id || !r.created_at) continue;
      const t = new Date(r.created_at).getTime();
      const prev = userFirst.get(r.user_id);
      if (prev === undefined || t < prev) userFirst.set(r.user_id, t);
    }
    const toTimes = (rows: any[]) =>
      rows
        .map((r) => (r.created_at ? new Date(r.created_at).getTime() : NaN))
        .filter((t) => !Number.isNaN(t));

    const growthSeries = cumulativeGrowth(now, {
      orgs: toTimes(orgDates.rows),
      projects: toTimes(projectDates.rows),
      users: Array.from(userFirst.values()),
    });

    res.json({
      totals: {
        organizations: orgCount.count ?? 0,
        projects: projectCount.count ?? 0,
        users: distinctUsers,
        scans30d: scanCount.count ?? 0,
      },
      growthSeries,
    });
  } catch (error: any) {
    fail(res, error, 'Failed to load overview');
  }
});

/**
 * GET /api/admin/billing
 * Financial snapshot for the Deptex-staff admin console. Pages through the ledger
 * (billing_transactions) and reduces in-process — fine at current scale; move to a
 * SQL function if the usage table grows large (a `truncated` flag is returned when
 * the row cap is hit so the numbers are never silently undercounted).
 *
 * Money model (phase37 sign convention — usage_deduction is negative, the rest positive):
 *   - Deposits     = (topup + auto_recharge_topup) − refunds   → real cash collected
 *   - Gross margin = Σ over usage of (charged − cost_cents_cog) → markup we earned
 *   - Free credit  = signup_grant; "burned" = the prorated COGS of usage covered
 *                    by grants, assuming FREE CREDIT IS SPENT FIRST (an estimate —
 *                    the ledger keeps a single balance). `estimated: true` flags this.
 *   - Real balance = current balance MINUS unspent free credit (paid cash, not promo).
 * The activity feed shows real money events only (signup_grant excluded).
 */
router.get('/billing', async (_req: AuthRequest, res) => {
  try {
    const now = Date.now();
    const ACTIVITY_KINDS = ['topup', 'auto_recharge_topup', 'refund', 'adjustment'];

    const activityRows = await supabase
      .from('billing_transactions')
      .select('id, organization_id, kind, amount_cents, description, created_at')
      .in('kind', ACTIVITY_KINDS)
      .order('created_at', { ascending: false })
      .limit(20);
    if (activityRows.error) {
      fail(res, activityRows.error, 'Failed to load billing');
      return;
    }

    // Ledger aggregation (paged).
    const [balance, grants, deposits, refunds, usage] = await Promise.all([
      paginateAll(
        () => supabase.from('organization_billing').select('organization_id, balance_cents'),
        'organization_id',
      ),
      paginateAll(() =>
        supabase.from('billing_transactions').select('organization_id, amount_cents').eq('kind', 'signup_grant'),
      ),
      paginateAll(() =>
        supabase
          .from('billing_transactions')
          .select('amount_cents, created_at')
          .in('kind', ['topup', 'auto_recharge_topup']),
      ),
      paginateAll(() =>
        supabase.from('billing_transactions').select('amount_cents').eq('kind', 'refund'),
      ),
      paginateAll(() =>
        supabase
          .from('billing_transactions')
          .select('organization_id, amount_cents, cost_cents_cog')
          .eq('kind', 'usage_deduction'),
      ),
    ]);

    const truncated =
      balance.truncated || grants.truncated || deposits.truncated || refunds.truncated || usage.truncated;

    const { financials, revenueSeries } = computeAdminBillingFinancials({
      now,
      balanceRows: balance.rows,
      grantRows: grants.rows,
      depositRows: deposits.rows,
      refundRows: refunds.rows,
      usageRows: usage.rows,
    });

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
        console.error('[admin/billing] org name lookup error:', orgErr);
      } else {
        for (const o of orgs ?? []) {
          if (o?.id) nameById[o.id] = o.name ?? '';
        }
      }
    }

    res.json({
      financials: {
        ...financials,
        estimated: true,
        truncated,
      },
      revenueSeries,
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
    fail(res, error, 'Failed to load billing');
  }
});

/**
 * GET /api/admin/extraction-trend
 * Daily extraction-failure counts (errors vs warns) over the last 365 days for the
 * Extraction tab chart. Bounded to the window so the fetch stays cheap; returns a
 * `truncated` flag if the row cap is hit.
 */
router.get('/extraction-trend', async (_req: AuthRequest, res) => {
  try {
    const now = Date.now();
    const since365 = new Date(now - 365 * DAY_MS).toISOString();
    const { rows, truncated } = await paginateAll(() =>
      supabase.from('extraction_step_errors').select('created_at, severity').gte('created_at', since365),
    );

    const utcDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);
    const map = new Map<string, { errors: number; warns: number }>();
    for (let i = 364; i >= 0; i--) map.set(utcDay(now - i * DAY_MS), { errors: 0, warns: 0 });
    for (const r of rows) {
      if (!r.created_at) continue;
      const bucket = map.get(new Date(r.created_at).toISOString().slice(0, 10));
      if (!bucket) continue;
      if (r.severity === 'error') bucket.errors += 1;
      else bucket.warns += 1;
    }
    const series = Array.from(map, ([date, v]) => ({ date, errors: v.errors, warns: v.warns }));
    res.json({ series, truncated });
  } catch (error: any) {
    fail(res, error, 'Failed to load extraction trend');
  }
});

export default router;
