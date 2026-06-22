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
import {
  getConnectedProviders,
  listJiraProjects,
  listLinearTeams,
  createJiraIssue,
  createLinearIssue,
  createGithubIssue,
  TrackerError,
  type TrackerProvider,
  type TrackerResult,
} from '../lib/trackers';

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
  // Malicious is status-only (NOT the legacy suppressed path) to keep the manual
  // ignore layer orthogonal to the allowlist auto-suppression. A status change
  // triggers a recompute of dependencies.is_malicious below (phase56), and the
  // ignore now carries across scans via insert_malicious_findings_with_recompute.
  malicious: { table: 'project_malicious_findings', run: 'extraction', legacy: false },
} as const;
type StatusFindingType = keyof typeof STATUS_FINDING_TYPES;
const IGNORE_REASONS = ['false_positive', 'wont_fix', 'accepted_risk'] as const;

/** Synthetic "collapsed" rows with no backing finding store of their own — the
 *  out-of-date base-image group and the container/k8s hardening group. Their
 *  Ignore lives in project_finding_group_suppressions, keyed by the stable
 *  synthetic group key (`cig:…` / `iacg:…`) the UI already uses. */
const GROUP_FINDING_TYPES = new Set<string>(['container_group', 'iac_group']);

router.patch('/:id/projects/:projectId/findings/:type/:findingKey/status', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, type, findingKey } = req.params;
    const isGroup = GROUP_FINDING_TYPES.has(type);
    const cfg = STATUS_FINDING_TYPES[type as StatusFindingType];
    if (!isGroup && !cfg) {
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

    // Group rows (container_group / iac_group) have no backing finding store, so
    // their Ignore disposition is a row in project_finding_group_suppressions
    // keyed by the synthetic group key. Ignoring sets it aside; opening removes it.
    if (isGroup) {
      if (status === 'ignored') {
        const { error } = await supabase
          .from('project_finding_group_suppressions')
          .upsert(
            {
              organization_id: id,
              project_id: projectId,
              group_type: type,
              group_key: findingKey,
              ignore_reason: reason ?? null,
              ignore_note: trimmedNote,
              ignored_by: userId,
              ignored_at: new Date().toISOString(),
            },
            { onConflict: 'project_id,group_type,group_key' },
          );
        if (error) throw error;
      } else {
        const { error } = await supabase
          .from('project_finding_group_suppressions')
          .delete()
          .eq('project_id', projectId)
          .eq('group_type', type)
          .eq('group_key', findingKey);
        if (error) throw error;
      }
      return res.json({ success: true, status, updated: 1 });
    }
    if (!cfg) return res.status(400).json({ error: `Unsupported finding type: ${type}` });

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

    const { data: updated, error, count } = await query.select(
      type === 'malicious' ? 'id, dependency_id' : 'id',
    );
    if (error) throw error;
    if ((count ?? 0) === 0) {
      return res.status(404).json({ error: 'Finding not found in the active scan' });
    }

    // A malicious status change flips dependencies.is_malicious (phase56): an
    // ignored/resolved finding no longer counts as active malicious.
    if (type === 'malicious') {
      const depIds = Array.from(
        new Set((updated ?? []).map((row: any) => row.dependency_id).filter(Boolean)),
      );
      if (depIds.length > 0) {
        await supabase
          .rpc('recompute_dependency_is_malicious', { p_dependency_ids: depIds })
          .then(undefined, (e: any) =>
            console.error('[finding-status] is_malicious recompute failed:', e?.message),
          );
      }
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

// ============================================================
// Finding -> external tracker links (Jira / Linear / GitHub)
// ============================================================

/** Finding types that can be filed to a tracker: the unified status types, plus
 *  data-flow (taint_flow, resolves by flow_signature_hash) and the two collapsed
 *  group rows (one ticket upgrades the whole base image / hardens the manifest). */
const TRACKER_FINDING_TYPES = new Set<string>([
  ...Object.keys(STATUS_FINDING_TYPES),
  'taint_flow',
  ...GROUP_FINDING_TYPES,
]);

/** Does the (finding_key) resolve to a row in the active run for its type?
 *  taint_flow resolves by flow_signature_hash against project_reachable_flows. */
async function findingExistsInActiveRun(
  projectId: string,
  type: string,
  findingKey: string,
): Promise<boolean> {
  if (type === 'taint_flow') {
    const activeRun = await getActiveExtractionId(supabase, projectId);
    if (!activeRun) return false;
    const { count } = await supabase
      .from('project_reachable_flows')
      .select('project_id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .eq('flow_signature_hash', findingKey)
      .eq('extraction_run_id', activeRun);
    return (count ?? 0) > 0;
  }
  // Collapsed group rows have no per-row store — validate the project actually
  // has findings of that family in the active run (enough to block phantom keys).
  if (type === 'container_group' || type === 'iac_group') {
    const activeRun = await getActiveExtractionId(supabase, projectId);
    if (!activeRun) return false;
    const table = type === 'container_group' ? 'project_container_findings' : 'project_iac_findings';
    const { count } = await supabase
      .from(table)
      .select('id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .eq('extraction_run_id', activeRun);
    return (count ?? 0) > 0;
  }
  const cfg = STATUS_FINDING_TYPES[type as StatusFindingType];
  if (!cfg) return false;
  let q = supabase
    .from(cfg.table)
    .select('id', { count: 'exact', head: true })
    .eq('project_id', projectId)
    .eq('finding_key', findingKey);
  if (cfg.run === 'extraction') {
    const activeRun = await getActiveExtractionId(supabase, projectId);
    if (!activeRun) return false;
    q = q.eq('extraction_run_id', activeRun);
  } else {
    const { data: targets } = await supabase
      .from('project_dast_targets')
      .select('active_dast_run_id')
      .eq('project_id', projectId);
    const runs = (targets ?? []).map((t: any) => t.active_dast_run_id).filter(Boolean);
    if (runs.length === 0) return false;
    q = q.in('dast_run_id', runs);
  }
  const { count } = await q;
  return (count ?? 0) > 0;
}

const TITLE_MAX = 255;
const DESC_MAX = 16384;

// Which providers are connected for this project (drives the picker).
router.get('/:id/projects/:projectId/tracker-providers', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) return res.status(access.error!.status).json({ error: access.error!.message });
    const providers = await getConnectedProviders(id, projectId);
    res.json({ providers });
  } catch (error: any) {
    console.error('[scanner-findings] tracker-providers error:', error);
    res.status(500).json({ error: error.message || 'Failed to list tracker providers' });
  }
});

// Destinations within a provider (Jira projects / Linear teams). GitHub files to
// the project's connected repo, so it has a single implicit destination.
router.get('/:id/projects/:projectId/tracker-destinations/:provider', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, provider } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) return res.status(access.error!.status).json({ error: access.error!.message });
    if (!(await checkOrgManageFindingsPermission(userId, id))) {
      return res.status(403).json({ error: 'Requires manage_findings permission' });
    }
    let destinations: Array<{ id: string; name: string }> = [];
    if (provider === 'jira') {
      destinations = (await listJiraProjects(id)).map((p) => ({ id: p.key, name: `${p.key} — ${p.name}` }));
    } else if (provider === 'linear') {
      destinations = await listLinearTeams(id);
    } else if (provider === 'github') {
      destinations = []; // implicit: the project's repo
    } else {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }
    res.json({ destinations });
  } catch (error: any) {
    if (error instanceof TrackerError) return res.status(error.connected ? 502 : 409).json({ error: error.message });
    console.error('[scanner-findings] tracker-destinations error:', error);
    res.status(500).json({ error: error.message || 'Failed to list destinations' });
  }
});

// All tracker links for the project's findings (the row chips read this once).
router.get('/:id/projects/:projectId/tracker-links', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) return res.status(access.error!.status).json({ error: access.error!.message });
    const { data, error } = await supabase
      .from('finding_tracker_links')
      .select('id, finding_type, finding_key, provider, external_key, external_url, title, external_state, created_at')
      .eq('project_id', projectId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ links: data ?? [] });
  } catch (error: any) {
    console.error('[scanner-findings] tracker-links error:', error);
    res.status(500).json({ error: error.message || 'Failed to list tracker links' });
  }
});

// All tracker links across the org's projects (the org-wide findings table maps
// chips by project_id + finding_type + finding_key in a single call).
router.get('/:id/tracker-links', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { data: membership } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .maybeSingle();
    if (!membership) return res.status(403).json({ error: 'Not a member of this organization' });
    const { data, error } = await supabase
      .from('finding_tracker_links')
      .select('id, project_id, finding_type, finding_key, provider, external_key, external_url, title, external_state, created_at')
      .eq('organization_id', id)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ links: data ?? [] });
  } catch (error: any) {
    console.error('[scanner-findings] org tracker-links error:', error);
    res.status(500).json({ error: error.message || 'Failed to list tracker links' });
  }
});

// Group-level Ignore for the collapsed rows (container_group / iac_group). The
// findings table reads these once and stamps the matching group row as ignored.
router.get('/:id/projects/:projectId/group-suppressions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) return res.status(access.error!.status).json({ error: access.error!.message });
    const { data, error } = await supabase
      .from('project_finding_group_suppressions')
      .select('project_id, group_type, group_key, ignore_reason, ignore_note')
      .eq('project_id', projectId);
    if (error) throw error;
    res.json({ suppressions: data ?? [] });
  } catch (error: any) {
    console.error('[scanner-findings] group-suppressions error:', error);
    res.status(500).json({ error: error.message || 'Failed to list group suppressions' });
  }
});

// All group suppressions across the org's projects (org-wide findings table).
router.get('/:id/group-suppressions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { data: membership } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .maybeSingle();
    if (!membership) return res.status(403).json({ error: 'Not a member of this organization' });
    const { data, error } = await supabase
      .from('project_finding_group_suppressions')
      .select('project_id, group_type, group_key, ignore_reason, ignore_note')
      .eq('organization_id', id);
    if (error) throw error;
    res.json({ suppressions: data ?? [] });
  } catch (error: any) {
    console.error('[scanner-findings] org group-suppressions error:', error);
    res.status(500).json({ error: error.message || 'Failed to list group suppressions' });
  }
});

// Create a ticket for a finding and store the link.
router.post('/:id/projects/:projectId/findings/:type/:findingKey/tracker', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, type, findingKey } = req.params;
    if (!TRACKER_FINDING_TYPES.has(type)) {
      return res.status(400).json({ error: `Unsupported finding type: ${type}` });
    }
    const provider = String(req.body?.provider ?? '') as TrackerProvider;
    if (!['jira', 'linear', 'github'].includes(provider)) {
      return res.status(400).json({ error: 'provider must be jira, linear, or github' });
    }
    const title = String(req.body?.title ?? '').trim().slice(0, TITLE_MAX);
    const description = String(req.body?.description ?? '').trim().slice(0, DESC_MAX);
    if (!title) return res.status(400).json({ error: 'title is required' });

    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) return res.status(access.error!.status).json({ error: access.error!.message });
    if (!(await checkOrgManageFindingsPermission(userId, id))) {
      return res.status(403).json({ error: 'Requires manage_findings permission' });
    }

    if (!(await findingExistsInActiveRun(projectId, type, findingKey))) {
      return res.status(404).json({ error: 'Finding not found in the active scan' });
    }

    // One link per (finding, provider) — block a duplicate ticket up-front.
    const { data: existing } = await supabase
      .from('finding_tracker_links')
      .select('id, provider, external_key, external_url')
      .eq('project_id', projectId)
      .eq('finding_type', type)
      .eq('finding_key', findingKey)
      .eq('provider', provider)
      .maybeSingle();
    if (existing) {
      return res.status(409).json({ error: `Already linked to ${provider}`, link: existing });
    }

    let result: TrackerResult;
    if (provider === 'jira') {
      const projectKey = String(req.body?.projectKey ?? '').trim();
      if (!projectKey) return res.status(400).json({ error: 'projectKey is required for Jira' });
      result = await createJiraIssue(id, {
        projectKey,
        summary: title,
        description,
        issueType: req.body?.issueType ? String(req.body.issueType) : undefined,
      });
    } else if (provider === 'linear') {
      const teamId = String(req.body?.teamId ?? '').trim();
      if (!teamId) return res.status(400).json({ error: 'teamId is required for Linear' });
      result = await createLinearIssue(id, { teamId, title, description });
    } else {
      result = await createGithubIssue(projectId, { title, body: description });
    }

    const { data: link, error: insErr } = await supabase
      .from('finding_tracker_links')
      .insert({
        organization_id: id,
        project_id: projectId,
        finding_type: type,
        finding_key: findingKey,
        provider,
        external_id: result.externalId,
        external_key: result.externalKey,
        external_url: result.externalUrl,
        title,
        created_by: userId,
        external_state: 'open', // a freshly-filed ticket is open; GitHub keeps it fresh via webhook
        external_state_synced_at: new Date().toISOString(),
      })
      .select('id, finding_type, finding_key, provider, external_key, external_url, title, external_state, created_at')
      .single();
    if (insErr) {
      // The ticket exists even if we couldn't store the link (e.g. a race on the
      // unique index). Surface the created ticket so the user isn't left guessing.
      console.error('[scanner-findings] tracker link insert failed:', insErr.message);
      return res.status(201).json({ success: true, link: { provider, external_key: result.externalKey, external_url: result.externalUrl, title }, persisted: false });
    }
    res.status(201).json({ success: true, link, persisted: true });
  } catch (error: any) {
    if (error instanceof TrackerError) return res.status(error.connected ? 502 : 409).json({ error: error.message });
    console.error('[scanner-findings] create tracker error:', error);
    res.status(500).json({ error: error.message || 'Failed to create ticket' });
  }
});

// Remove a tracker link (does NOT close the external ticket).
router.delete('/:id/projects/:projectId/findings/:type/:findingKey/tracker/:linkId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, linkId } = req.params;
    const access = await checkProjectAccess(userId, id, projectId);
    if (!access.hasAccess) return res.status(access.error!.status).json({ error: access.error!.message });
    if (!(await checkOrgManageFindingsPermission(userId, id))) {
      return res.status(403).json({ error: 'Requires manage_findings permission' });
    }
    const { error, count } = await supabase
      .from('finding_tracker_links')
      .delete({ count: 'exact' })
      .eq('id', linkId)
      .eq('project_id', projectId);
    if (error) throw error;
    if ((count ?? 0) === 0) return res.status(404).json({ error: 'Link not found' });
    res.json({ success: true });
  } catch (error: any) {
    console.error('[scanner-findings] delete tracker error:', error);
    res.status(500).json({ error: error.message || 'Failed to remove link' });
  }
});

export default router;
