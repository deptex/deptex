import express from 'express';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { validateExternalUrl } from '../lib/url-guard';
import { startDastMachine } from '../lib/fly-machines';
import { checkProjectAccess, checkProjectManagePermission } from './projects';
import type {
  DastConfigDTO,
  DastFindingDTO,
  DastJobDTO,
  DastScanProfile,
} from '../types/dast';

const router = express.Router();
router.use(authenticateUser);

const VALID_SCAN_PROFILES: ReadonlySet<DastScanProfile> = new Set([
  'auto',
  'quick',
  'full',
  'api',
]);
const TIMEOUT_MIN = 5;
const TIMEOUT_MAX = 60;

/**
 * Resolve a project to its organization and validate the user has at least
 * read access. DAST routes are mounted at /api/projects/... (not nested under
 * organizations) so we look up org_id here rather than reading it from the
 * URL.
 *
 * Returns the org id on success, or `{ deny: { status, message } }` on failure
 * so route handlers can do `if (resolved.deny) return res.status(...)`.
 */
type AccessResolved = { organizationId: string; deny?: undefined };
type AccessDenied = { organizationId?: undefined; deny: { status: number; message: string } };

async function resolveProjectAccess(
  userId: string,
  projectId: string,
): Promise<AccessResolved | AccessDenied> {
  const { data: project, error } = await supabase
    .from('projects')
    .select('organization_id')
    .eq('id', projectId)
    .single();

  if (error || !project) {
    return { deny: { status: 404, message: 'Project not found' } };
  }

  const access = await checkProjectAccess(userId, project.organization_id, projectId);
  if (!access.hasAccess) {
    return {
      deny: {
        status: access.error?.status ?? 403,
        message: access.error?.message ?? 'Access denied',
      },
    };
  }

  return { organizationId: project.organization_id };
}

// ---------------------------------------------------------------------------
// GET /api/projects/:projectId/dast/config
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/config', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    const { data, error } = await supabase
      .from('project_dast_config')
      .select('enabled, target_url, scan_profile, scan_timeout_minutes')
      .eq('project_id', projectId)
      .maybeSingle();

    if (error) {
      console.error('[dast] GET config error:', error.message);
      return res.status(500).json({ error: 'Failed to load DAST config' });
    }

    const config: DastConfigDTO = data
      ? {
          enabled: data.enabled,
          target_url: data.target_url,
          scan_profile: data.scan_profile,
          scan_timeout_minutes: data.scan_timeout_minutes,
        }
      : {
          enabled: false,
          target_url: null,
          scan_profile: 'auto',
          scan_timeout_minutes: 30,
        };

    return res.json(config);
  } catch (e: any) {
    console.error('[dast] GET config exception:', e);
    return res.status(500).json({ error: e.message ?? 'Failed to load DAST config' });
  }
});

// ---------------------------------------------------------------------------
// PUT /api/projects/:projectId/dast/config
// Upsert. RBAC: manage_projects. SSRF guard runs on target_url.
// ---------------------------------------------------------------------------
router.put('/:projectId/dast/config', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    if (!(await checkProjectManagePermission(userId, access.organizationId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage this project' });
    }

    const body = req.body ?? {};
    const enabled = typeof body.enabled === 'boolean' ? body.enabled : false;
    const targetUrl: string | null =
      typeof body.target_url === 'string' && body.target_url.length > 0
        ? body.target_url
        : null;
    const scanProfile: DastScanProfile = VALID_SCAN_PROFILES.has(body.scan_profile)
      ? body.scan_profile
      : 'auto';
    const scanTimeoutMinutes = Math.max(
      TIMEOUT_MIN,
      Math.min(TIMEOUT_MAX, Number(body.scan_timeout_minutes) || 30),
    );

    if (targetUrl) {
      const guard = await validateExternalUrl(targetUrl);
      if (guard.valid === false) {
        return res
          .status(422)
          .json({ error: 'invalid_target_url', detail: guard.reason });
      }
    } else if (enabled) {
      return res
        .status(422)
        .json({ error: 'invalid_target_url', detail: 'target_url is required when DAST is enabled' });
    }

    const { error } = await supabase.from('project_dast_config').upsert(
      {
        project_id: projectId,
        organization_id: access.organizationId,
        enabled,
        target_url: targetUrl,
        scan_profile: scanProfile,
        scan_timeout_minutes: scanTimeoutMinutes,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'project_id' },
    );

    if (error) {
      console.error('[dast] PUT config error:', error.message);
      return res.status(500).json({ error: 'Failed to save DAST config' });
    }

    const config: DastConfigDTO = {
      enabled,
      target_url: targetUrl,
      scan_profile: scanProfile,
      scan_timeout_minutes: scanTimeoutMinutes,
    };
    return res.json(config);
  } catch (e: any) {
    console.error('[dast] PUT config exception:', e);
    return res.status(500).json({ error: e.message ?? 'Failed to save DAST config' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/projects/:projectId/dast/scan
// Trigger a manual scan. Validates URL → queues row via queue_scan_job
// (which enforces concurrency caps) → boots a Fly machine.
// ---------------------------------------------------------------------------
router.post('/:projectId/dast/scan', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    if (!(await checkProjectManagePermission(userId, access.organizationId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage this project' });
    }

    // Read the saved config — manual scans use whatever the project last saved.
    const { data: config, error: configError } = await supabase
      .from('project_dast_config')
      .select('enabled, target_url, scan_profile, scan_timeout_minutes')
      .eq('project_id', projectId)
      .maybeSingle();

    if (configError || !config) {
      return res.status(409).json({
        error: 'dast_not_configured',
        detail: 'Configure a target URL on the Scanning tab before triggering a scan.',
      });
    }
    if (!config.enabled || !config.target_url) {
      return res.status(409).json({
        error: 'dast_not_configured',
        detail: 'DAST is disabled or missing a target URL.',
      });
    }

    // SSRF check at the route layer; queue_scan_job re-checks at the DB layer
    // (defense-in-depth) and the depscanner pipeline re-checks pre-flight to
    // defeat DNS-rebind between save and execution.
    const guard = await validateExternalUrl(config.target_url);
    if (guard.valid === false) {
      return res
        .status(422)
        .json({ error: 'invalid_target_url', detail: guard.reason });
    }

    const { data: queued, error: queueError } = await supabase.rpc('queue_scan_job', {
      p_project_id: projectId,
      p_organization_id: access.organizationId,
      p_type: 'dast',
      p_payload: { source: 'manual_dast_scan' },
      p_target_url: config.target_url,
      p_scan_profile: config.scan_profile,
      p_timeout_minutes: config.scan_timeout_minutes,
      p_trigger_source: 'manual',
      p_triggered_by: userId,
    });

    if (queueError) {
      const detail = queueError.message ?? 'Failed to queue scan';
      // queue_scan_job RAISEs P0001 with a stable error tag in the message.
      if (detail.includes('project_concurrent_dast_blocked')) {
        return res.status(409).json({ error: 'project_concurrent_dast_blocked', detail });
      }
      if (detail.includes('org_concurrent_dast_cap')) {
        return res.status(409).json({ error: 'org_concurrent_dast_cap', detail });
      }
      if (detail.includes('rejected (private/loopback/internal)') || detail.includes('must be http(s)')) {
        return res.status(422).json({ error: 'invalid_target_url', detail });
      }
      console.error('[dast] queue_scan_job error:', detail);
      return res.status(500).json({ error: detail });
    }

    const job = Array.isArray(queued) ? queued[0] : queued;
    if (!job?.id) {
      console.error('[dast] queue_scan_job returned no row');
      return res.status(500).json({ error: 'Failed to queue scan' });
    }

    // Start a Fly machine. Best-effort — the recovery cron will pick up
    // orphaned queued rows if this fails.
    try {
      await startDastMachine();
    } catch (e: any) {
      console.warn(`[dast] startDastMachine failed (job stays queued): ${e?.message ?? e}`);
    }

    return res.status(202).json({
      jobId: job.id,
      status: job.status,
      target_url: job.target_url,
      scan_profile: job.scan_profile,
      created_at: job.created_at,
    });
  } catch (e: any) {
    console.error('[dast] POST scan exception:', e);
    return res.status(500).json({ error: e.message ?? 'Failed to trigger scan' });
  }
});

// ---------------------------------------------------------------------------
// GET /api/projects/:projectId/dast/jobs?limit=20
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/jobs', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;
    const limit = Math.max(1, Math.min(100, Number(req.query.limit) || 20));

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    const { data, error } = await supabase
      .from('scan_jobs')
      .select(
        'id, status, trigger_source, target_url, scan_profile, findings_count, duration_seconds, started_at, completed_at, error, error_category, attempts, created_at',
      )
      .eq('project_id', projectId)
      .eq('type', 'dast')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('[dast] GET jobs error:', error.message);
      return res.status(500).json({ error: 'Failed to load DAST jobs' });
    }

    const jobs: DastJobDTO[] = (data ?? []).map((row: any) => ({
      id: row.id,
      status: row.status,
      trigger_source: row.trigger_source,
      target_url: row.target_url,
      scan_profile: row.scan_profile,
      findings_count: row.findings_count,
      duration_seconds: row.duration_seconds,
      started_at: row.started_at,
      completed_at: row.completed_at,
      error: row.error,
      error_category: row.error_category,
      attempts: row.attempts ?? 0,
      created_at: row.created_at,
    }));

    return res.json(jobs);
  } catch (e: any) {
    console.error('[dast] GET jobs exception:', e);
    return res.status(500).json({ error: e.message ?? 'Failed to load DAST jobs' });
  }
});

// ---------------------------------------------------------------------------
// GET /api/projects/:projectId/dast/findings
// Returns active findings (gated by projects.active_dast_run_id) with the
// computed confirmed_exploitable boolean derived from linked_sca_osv_id.
// ---------------------------------------------------------------------------
router.get('/:projectId/dast/findings', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { projectId } = req.params;
    const limit = Math.max(1, Math.min(500, Number(req.query.limit) || 100));

    const access = await resolveProjectAccess(userId, projectId);
    if (access.deny) {
      return res.status(access.deny.status).json({ error: access.deny.message });
    }

    const { data: project } = await supabase
      .from('projects')
      .select('active_dast_run_id')
      .eq('id', projectId)
      .single();

    const activeRunId = project?.active_dast_run_id;
    if (!activeRunId) {
      return res.json([]);
    }

    const { data, error } = await supabase
      .from('project_dast_findings')
      .select(
        'id, endpoint_url, http_method, vulnerability_type, severity, cwe_id, owasp_top10_ref, rule_id, message, payload_redacted, response_evidence_redacted, confidence, handler_file_path, handler_function_name, handler_line, linked_sca_osv_id, linked_sca_project_dependency_id, status, risk_accepted_reason, created_at',
      )
      .eq('project_id', projectId)
      .eq('dast_run_id', activeRunId)
      .order('severity', { ascending: true })
      .limit(limit);

    if (error) {
      console.error('[dast] GET findings error:', error.message);
      return res.status(500).json({ error: 'Failed to load DAST findings' });
    }

    const findings: DastFindingDTO[] = (data ?? []).map((row: any) => ({
      id: row.id,
      endpoint_url: row.endpoint_url,
      http_method: row.http_method,
      vulnerability_type: row.vulnerability_type,
      severity: row.severity,
      cwe_id: row.cwe_id,
      owasp_top10_ref: row.owasp_top10_ref,
      rule_id: row.rule_id,
      message: row.message,
      payload_redacted: row.payload_redacted,
      response_evidence_redacted: row.response_evidence_redacted,
      confidence: row.confidence,
      handler_file_path: row.handler_file_path,
      handler_function_name: row.handler_function_name,
      handler_line: row.handler_line,
      linked_sca_osv_id: row.linked_sca_osv_id,
      linked_sca_project_dependency_id: row.linked_sca_project_dependency_id,
      confirmed_exploitable: row.linked_sca_osv_id != null,
      status: row.status,
      risk_accepted_reason: row.risk_accepted_reason,
      created_at: row.created_at,
    }));

    return res.json(findings);
  } catch (e: any) {
    console.error('[dast] GET findings exception:', e);
    return res.status(500).json({ error: e.message ?? 'Failed to load DAST findings' });
  }
});

export default router;
