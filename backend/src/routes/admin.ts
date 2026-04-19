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

export default router;
