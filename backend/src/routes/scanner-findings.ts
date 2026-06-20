/**
 * IaC + container findings endpoints.
 *
 * URL convention follows the existing security-tab pattern:
 *   /api/organizations/:id/projects/:projectId/<resource>
 *
 * 7 endpoints total:
 *   - GET    /iac-findings
 *   - PATCH  /iac-findings/:findingId/ignore
 *   - PATCH  /iac-findings/:findingId/risk-accept
 *   - GET    /container-findings
 *   - PATCH  /container-findings/:findingId/ignore
 *   - PATCH  /container-findings/:findingId/risk-accept
 *   - GET    /scanner-summary
 *
 * All endpoints scope by (project_id, organization_id) AND require
 * checkProjectAccess. Mutation endpoints additionally require
 * checkProjectManagePermission.
 */

import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { checkProjectAccess, checkProjectManagePermission, checkOrgManageFindingsPermission } from '../lib/project-access';
import { getActiveExtractionId } from '../lib/active-extraction';

// Mirror of `IAC_FRAMEWORKS` in `depscanner/src/scanners/types.ts`.
// Backend's tsconfig rootDir is ./src so cross-package import isn't possible;
// kept in sync manually with the depscanner canonical export and the
// `project_iac_findings.framework` CHECK constraint (phase27a migration).
const RISK_ACCEPTED_REASON_MAX_LEN = 4096;

const IAC_FRAMEWORKS = [
  'terraform',
  'kubernetes',
  'dockerfile',
  'helm',
  'cloudformation',
  'arm',
  'bicep',
  'serverless',
  'github_actions',
] as const;

const router = express.Router();
router.use(authenticateUser);

// ============================================================
// Shared helpers
// ============================================================

function parsePagination(req: AuthRequest): { page: number; perPage: number; offset: number } {
  const page = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
  const perPage = Math.min(200, Math.max(1, parseInt(String(req.query.per_page ?? '50'), 10) || 50));
  return { page, perPage, offset: (page - 1) * perPage };
}

// ============================================================
// IaC findings
// ============================================================

router.get('/:id/projects/:projectId/iac-findings', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }

    const { page, perPage, offset } = parsePagination(req);
    const activeRunId = await getActiveExtractionId(supabase, projectId);
    if (!activeRunId) {
      return res.json({ data: [], total: 0, page, per_page: perPage });
    }

    const severityFilter = String(req.query.severity ?? '').trim().toUpperCase();
    const statusFilter = String(req.query.status ?? '').trim().toLowerCase();
    const frameworkFilter = String(req.query.framework ?? '').trim().toLowerCase();
    const depscoreMin = parseInt(String(req.query.depscore_min ?? ''), 10);

    let countQuery = supabase
      .from('project_iac_findings')
      .select('id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .eq('extraction_run_id', activeRunId);
    let dataQuery = supabase
      .from('project_iac_findings')
      .select('*')
      .eq('project_id', projectId)
      .eq('extraction_run_id', activeRunId);

    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severityFilter)) {
      countQuery = countQuery.eq('severity', severityFilter);
      dataQuery = dataQuery.eq('severity', severityFilter);
    }
    if (statusFilter === 'open' || statusFilter === 'ignored') {
      countQuery = countQuery.eq('status', statusFilter);
      dataQuery = dataQuery.eq('status', statusFilter);
    }
    if ((IAC_FRAMEWORKS as readonly string[]).includes(frameworkFilter)) {
      countQuery = countQuery.eq('framework', frameworkFilter);
      dataQuery = dataQuery.eq('framework', frameworkFilter);
    }
    if (Number.isFinite(depscoreMin)) {
      countQuery = countQuery.gte('depscore', depscoreMin);
      dataQuery = dataQuery.gte('depscore', depscoreMin);
    }

    const { count } = await countQuery;
    const { data, error } = await dataQuery
      .order('depscore', { ascending: false, nullsFirst: false })
      .order('severity', { ascending: true })
      .order('created_at', { ascending: false })
      .range(offset, offset + perPage - 1);

    if (error) throw error;
    res.json({ data: data ?? [], total: count ?? 0, page, per_page: perPage });
  } catch (error: any) {
    console.error('[scanner-findings] iac list error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch IaC findings' });
  }
});

router.patch('/:id/projects/:projectId/iac-findings/:findingId/ignore', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }
    if (!(await checkProjectManagePermission(userId, id, projectId))) {
      return res.status(403).json({ error: 'No permission to manage findings' });
    }

    const { ignored } = req.body ?? {};
    const newStatus = ignored === false ? 'open' : 'ignored';
    const { error, count } = await supabase
      .from('project_iac_findings')
      .update({ status: newStatus }, { count: 'exact' })
      .eq('id', findingId)
      .eq('project_id', projectId);
    if (error) throw error;
    if ((count ?? 0) === 0) {
      return res.status(404).json({ error: 'Finding not found' });
    }
    res.json({ success: true, status: newStatus });
  } catch (error: any) {
    console.error('[scanner-findings] iac ignore error:', error);
    res.status(500).json({ error: error.message || 'Failed to update IaC finding' });
  }
});

router.patch('/:id/projects/:projectId/iac-findings/:findingId/risk-accept', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }
    if (!(await checkProjectManagePermission(userId, id, projectId))) {
      return res.status(403).json({ error: 'No permission to manage findings' });
    }

    const { reason, accepted } = req.body ?? {};
    const now = new Date().toISOString();
    const trimmedReason =
      typeof reason === 'string' ? reason.trim().slice(0, RISK_ACCEPTED_REASON_MAX_LEN) : null;
    if (typeof reason === 'string' && reason.length > RISK_ACCEPTED_REASON_MAX_LEN) {
      return res.status(400).json({ error: 'reason too long' });
    }
    const update =
      accepted === false
        ? {
            risk_accepted: false,
            risk_accepted_by: null,
            risk_accepted_at: null,
            risk_accepted_reason: null,
          }
        : {
            risk_accepted: true,
            risk_accepted_by: userId,
            risk_accepted_at: now,
            risk_accepted_reason: trimmedReason || null,
          };
    const { error, count } = await supabase
      .from('project_iac_findings')
      .update(update, { count: 'exact' })
      .eq('id', findingId)
      .eq('project_id', projectId);
    if (error) throw error;
    if ((count ?? 0) === 0) {
      return res.status(404).json({ error: 'Finding not found' });
    }
    res.json({ success: true });
  } catch (error: any) {
    console.error('[scanner-findings] iac risk-accept error:', error);
    res.status(500).json({ error: error.message || 'Failed to update IaC finding' });
  }
});

// ============================================================
// Container findings
// ============================================================

router.get('/:id/projects/:projectId/container-findings', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }

    const { page, perPage, offset } = parsePagination(req);
    const activeRunId = await getActiveExtractionId(supabase, projectId);
    if (!activeRunId) {
      return res.json({ data: [], total: 0, page, per_page: perPage });
    }

    const severityFilter = String(req.query.severity ?? '').trim().toUpperCase();
    const statusFilter = String(req.query.status ?? '').trim().toLowerCase();

    let countQuery = supabase
      .from('project_container_findings')
      .select('id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .eq('extraction_run_id', activeRunId);
    let dataQuery = supabase
      .from('project_container_findings')
      .select('*')
      .eq('project_id', projectId)
      .eq('extraction_run_id', activeRunId);

    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severityFilter)) {
      countQuery = countQuery.eq('severity', severityFilter);
      dataQuery = dataQuery.eq('severity', severityFilter);
    }
    if (statusFilter === 'open' || statusFilter === 'ignored') {
      countQuery = countQuery.eq('status', statusFilter);
      dataQuery = dataQuery.eq('status', statusFilter);
    }

    const { count } = await countQuery;
    const { data, error } = await dataQuery
      .order('depscore', { ascending: false, nullsFirst: false })
      .order('severity', { ascending: true })
      .order('created_at', { ascending: false })
      .range(offset, offset + perPage - 1);

    if (error) throw error;
    res.json({ data: data ?? [], total: count ?? 0, page, per_page: perPage });
  } catch (error: any) {
    console.error('[scanner-findings] container list error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch container findings' });
  }
});

router.patch('/:id/projects/:projectId/container-findings/:findingId/ignore', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }
    if (!(await checkProjectManagePermission(userId, id, projectId))) {
      return res.status(403).json({ error: 'No permission to manage findings' });
    }

    const { ignored } = req.body ?? {};
    const newStatus = ignored === false ? 'open' : 'ignored';
    const { error, count } = await supabase
      .from('project_container_findings')
      .update({ status: newStatus }, { count: 'exact' })
      .eq('id', findingId)
      .eq('project_id', projectId);
    if (error) throw error;
    if ((count ?? 0) === 0) {
      return res.status(404).json({ error: 'Finding not found' });
    }
    res.json({ success: true, status: newStatus });
  } catch (error: any) {
    console.error('[scanner-findings] container ignore error:', error);
    res.status(500).json({ error: error.message || 'Failed to update container finding' });
  }
});

router.patch('/:id/projects/:projectId/container-findings/:findingId/risk-accept', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }
    if (!(await checkProjectManagePermission(userId, id, projectId))) {
      return res.status(403).json({ error: 'No permission to manage findings' });
    }

    const { reason, accepted } = req.body ?? {};
    const now = new Date().toISOString();
    const trimmedReason =
      typeof reason === 'string' ? reason.trim().slice(0, RISK_ACCEPTED_REASON_MAX_LEN) : null;
    if (typeof reason === 'string' && reason.length > RISK_ACCEPTED_REASON_MAX_LEN) {
      return res.status(400).json({ error: 'reason too long' });
    }
    const update =
      accepted === false
        ? {
            risk_accepted: false,
            risk_accepted_by: null,
            risk_accepted_at: null,
            risk_accepted_reason: null,
          }
        : {
            risk_accepted: true,
            risk_accepted_by: userId,
            risk_accepted_at: now,
            risk_accepted_reason: trimmedReason || null,
          };
    const { error, count } = await supabase
      .from('project_container_findings')
      .update(update, { count: 'exact' })
      .eq('id', findingId)
      .eq('project_id', projectId);
    if (error) throw error;
    if ((count ?? 0) === 0) {
      return res.status(404).json({ error: 'Finding not found' });
    }
    res.json({ success: true });
  } catch (error: any) {
    console.error('[scanner-findings] container risk-accept error:', error);
    res.status(500).json({ error: error.message || 'Failed to update container finding' });
  }
});

// ============================================================
// Scanner summary (rollup tile)
// ============================================================

interface SeverityRollup {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  ignored: number;
}

function emptyRollup(): SeverityRollup {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, ignored: 0 };
}

function rollup(rows: Array<{ severity: string | null; status: string }>): SeverityRollup {
  const out = emptyRollup();
  for (const r of rows) {
    if (r.status === 'ignored') {
      out.ignored += 1;
      continue;
    }
    const sev = (r.severity ?? '').toUpperCase();
    if (sev === 'CRITICAL') out.critical += 1;
    else if (sev === 'HIGH') out.high += 1;
    else if (sev === 'MEDIUM') out.medium += 1;
    else if (sev === 'LOW') out.low += 1;
    else if (sev === 'INFO') out.info += 1;
  }
  return out;
}

interface ReachabilityRollup {
  module: number;
  unreachable: number;
  unclassified: number;
}

/** Roll container findings up by Phase 2 reachability verdict. A null level
 *  ('unclassified') is a language package or an image the classifier could
 *  not analyze — distinct from 'unreachable', which is a positive verdict. */
function reachabilityRollup(
  rows: Array<{ reachability_level: string | null }>
): ReachabilityRollup {
  const out: ReachabilityRollup = { module: 0, unreachable: 0, unclassified: 0 };
  for (const r of rows) {
    if (r.reachability_level === 'module') out.module += 1;
    else if (r.reachability_level === 'unreachable') out.unreachable += 1;
    else out.unclassified += 1;
  }
  return out;
}

router.get('/:id/projects/:projectId/scanner-summary', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }

    const { data: projRow, error: projErr } = await supabase
      .from('projects')
      .select('infra_types, active_extraction_run_id')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();
    if (projErr) throw projErr;
    if (!projRow) {
      return res.status(404).json({ error: 'Project not found' });
    }
    const activeRunId = (projRow as any).active_extraction_run_id ?? null;
    const infraTypes = (projRow as any).infra_types ?? [];

    // Last scan time = most recent completed extraction job for this project.
    const { data: lastJob } = await supabase
      .from('scan_jobs')
      .select('completed_at')
      .eq('project_id', projectId)
      .eq('type', 'extraction')
      .eq('status', 'completed')
      .order('completed_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    const lastScanAt = (lastJob as { completed_at?: string | null } | null)?.completed_at ?? null;

    if (!activeRunId) {
      return res.json({
        iac: emptyRollup(),
        container: emptyRollup(),
        container_reachability: { module: 0, unreachable: 0, unclassified: 0 },
        infra_types: infraTypes,
        last_scan_at: lastScanAt,
        skipped_images: [],
      });
    }

    const [iacRes, containerRes] = await Promise.all([
      supabase
        .from('project_iac_findings')
        .select('severity, status')
        .eq('project_id', projectId)
        .eq('extraction_run_id', activeRunId),
      supabase
        .from('project_container_findings')
        .select('severity, status, reachability_level')
        .eq('project_id', projectId)
        .eq('extraction_run_id', activeRunId),
    ]);
    if (iacRes.error) throw iacRes.error;
    if (containerRes.error) throw containerRes.error;

    res.json({
      iac: rollup((iacRes.data ?? []) as any),
      container: rollup((containerRes.data ?? []) as any),
      container_reachability: reachabilityRollup((containerRes.data ?? []) as any),
      infra_types: infraTypes,
      last_scan_at: lastScanAt,
      // skipped_images: deferred to v1.5 — needs to be persisted by the
      // worker before it can surface here. For v1 the field exists in the
      // contract but is always empty.
      skipped_images: [],
    });
  } catch (error: any) {
    console.error('[scanner-findings] summary error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch scanner summary' });
  }
});

// ============================================================
// Unified finding status (ignore / un-ignore across finding types)
// ============================================================

/** Finding types whose status the unified endpoint can set, with how to resolve
 *  their active-run rows and whether they carry the legacy suppressed/risk_accepted
 *  columns. `malicious` lacks carry-forward (PR-B) and `taint_flow` uses its own
 *  flow-suppression model, so both are intentionally excluded. */
const STATUS_FINDING_TYPES = {
  vulnerability: { table: 'project_dependency_vulnerabilities', run: 'extraction', legacy: true },
  secret: { table: 'project_secret_findings', run: 'extraction', legacy: false },
  semgrep: { table: 'project_semgrep_findings', run: 'extraction', legacy: false },
  iac: { table: 'project_iac_findings', run: 'extraction', legacy: true },
  container: { table: 'project_container_findings', run: 'extraction', legacy: true },
  dast: { table: 'project_dast_findings', run: 'dast', legacy: false },
  // Malicious carries no carry-forward yet (PR-B), so a manual ignore resets on
  // the next scan. Status-only (NOT the legacy suppressed path) to avoid the
  // is_malicious recompute / allowlist desync.
  malicious: { table: 'project_malicious_findings', run: 'extraction', legacy: false },
} as const;
type StatusFindingType = keyof typeof STATUS_FINDING_TYPES;
const IGNORE_REASONS = ['false_positive', 'wont_fix', 'accepted_risk'] as const;

router.patch('/:id/projects/:projectId/findings/:type/:findingKey/status', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, type, findingKey } = req.params;
    const cfg = STATUS_FINDING_TYPES[type as StatusFindingType];
    if (!cfg) {
      return res.status(400).json({ error: `Unsupported finding type: ${type}` });
    }

    const { status, reason, note } = req.body ?? {};
    if (status !== 'open' && status !== 'ignored') {
      return res.status(400).json({ error: 'status must be "open" or "ignored"' });
    }
    if (status === 'ignored' && reason !== undefined && reason !== null && !IGNORE_REASONS.includes(reason)) {
      return res.status(400).json({ error: `reason must be one of: ${IGNORE_REASONS.join(', ')}` });
    }
    const trimmedNote = typeof note === 'string' ? note.trim().slice(0, RISK_ACCEPTED_REASON_MAX_LEN) || null : null;

    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) {
      return res.status(access.error!.status).json({ error: access.error!.message });
    }
    if (!(await checkOrgManageFindingsPermission(userId, id))) {
      return res.status(403).json({ error: 'Requires manage_findings permission' });
    }

    const now = new Date().toISOString();
    const ignoring = status === 'ignored';
    const acceptedRisk = ignoring && reason === 'accepted_risk';

    // Unified status + ignore_* columns, mirrored onto the legacy
    // suppressed/risk_accepted columns so every reader (the count RPC, the legacy
    // detail panels) stays consistent until the legacy columns are retired.
    const update: Record<string, unknown> = {
      status,
      ignore_reason: ignoring ? reason ?? null : null,
      ignore_note: ignoring ? trimmedNote : null,
      ignored_by: ignoring ? userId : null,
      ignored_at: ignoring ? now : null,
    };
    if (cfg.legacy) {
      update.suppressed = ignoring && !acceptedRisk;
      update.suppressed_by = ignoring && !acceptedRisk ? userId : null;
      update.suppressed_at = ignoring && !acceptedRisk ? now : null;
      update.risk_accepted = acceptedRisk;
      update.risk_accepted_by = acceptedRisk ? userId : null;
      update.risk_accepted_at = acceptedRisk ? now : null;
      update.risk_accepted_reason = acceptedRisk ? trimmedNote : null;
    } else if (type === 'dast') {
      update.risk_accepted_by = acceptedRisk ? userId : null;
      update.risk_accepted_at = acceptedRisk ? now : null;
      update.risk_accepted_reason = acceptedRisk ? trimmedNote : null;
    }

    let query = supabase
      .from(cfg.table)
      .update(update, { count: 'exact' })
      .eq('project_id', projectId)
      .eq('finding_key', findingKey);
    if (cfg.run === 'extraction') {
      const activeRun = await getActiveExtractionId(supabase, projectId);
      if (!activeRun) return res.status(404).json({ error: 'No active scan for this project' });
      query = query.eq('extraction_run_id', activeRun);
    } else {
      const { data: targets } = await supabase
        .from('project_dast_targets')
        .select('active_dast_run_id')
        .eq('project_id', projectId);
      const runs = (targets ?? []).map((t: any) => t.active_dast_run_id).filter(Boolean);
      if (runs.length === 0) return res.status(404).json({ error: 'No active DAST run for this project' });
      query = query.in('dast_run_id', runs);
    }

    const { data: updated, error, count } = await query.select('id');
    if (error) throw error;
    if ((count ?? 0) === 0) {
      return res.status(404).json({ error: 'Finding not found in the active scan' });
    }

    // Best-effort audit log (write-only in PR-A; postgrest builders have no
    // .catch, so use .then(ok, err) for fire-and-forget — see memory).
    await supabase
      .from('project_finding_status_events')
      .insert(
        (updated ?? []).map((row: any) => ({
          organization_id: id,
          project_id: projectId,
          finding_type: type,
          finding_key: findingKey,
          finding_id: row.id,
          to_status: status,
          reason: ignoring ? reason ?? null : null,
          note: ignoring ? trimmedNote : null,
          actor_user_id: userId,
        })),
      )
      .then(undefined, (e: any) => console.error('[finding-status] event log failed:', e?.message));

    res.json({ success: true, status, updated: count });
  } catch (error: any) {
    console.error('[scanner-findings] finding status error:', error);
    res.status(500).json({ error: error.message || 'Failed to update finding status' });
  }
});

export default router;
