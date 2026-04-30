// @ts-nocheck
/**
 * Malicious-package finding routes.
 *
 * Public routes mount under `/api/organizations` and follow the canonical
 * `/api/organizations/:id/projects/:projectId/...` shape used by every other
 * project-scoped finding endpoint (semgrep, secrets, vulnerabilities). Reads
 * gate on `checkProjectAccess`; mutations gate on `checkProjectManagePermission`.
 *
 * Internal routes mount under `/api/internal/malicious` for QStash to drive
 * feed-sync + staleness-watchdog. They auth on `INTERNAL_API_KEY` only.
 *
 * Tenant invariant: `organization_id` is taken from the URL param ONLY, never
 * from the request body. The PMF `enforce_pmf_org_consistency` trigger is the
 * defence-in-depth backstop.
 */
import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { getActiveExtractionId } from '../lib/active-extraction';
import { checkProjectAccess, checkProjectManagePermission } from './project-access';

const router = express.Router();
router.use(authenticateUser);

function verifyInternal(req: express.Request): boolean {
  const internalKey = process.env.INTERNAL_API_KEY?.trim();
  if (!internalKey) return false;
  const h = req.headers['x-internal-api-key'];
  if (h && h === internalKey) return true;
  const auth = req.headers.authorization;
  return Boolean(auth && auth === `Bearer ${internalKey}`);
}

// ---------------------------------------------------------------------------
// GET .../malicious-findings
// ---------------------------------------------------------------------------

router.get('/:id/projects/:projectId/malicious-findings', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const page = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
    const perPage = Math.min(200, Math.max(1, parseInt(String(req.query.per_page ?? '50'), 10) || 50));
    const offset = (page - 1) * perPage;

    const activeExtractionId = await getActiveExtractionId(supabase, projectId);

    const { count } = await supabase
      .from('project_malicious_findings')
      .select('id', { count: 'exact', head: true })
      .eq('project_id', projectId)
      .eq('organization_id', id)
      .eq('extraction_run_id', activeExtractionId ?? '__no_active_run__');

    const { data, error } = await supabase
      .from('project_malicious_findings')
      .select('*')
      .eq('project_id', projectId)
      .eq('organization_id', id)
      .eq('extraction_run_id', activeExtractionId ?? '__no_active_run__')
      .order('severity', { ascending: true })
      .order('created_at', { ascending: false })
      .range(offset, offset + perPage - 1);

    if (error) throw error;

    const findings = data ?? [];
    if (findings.length === 0) {
      return res.json({ data: [], total: count ?? 0, page, per_page: perPage });
    }

    // Hydrate with package_name + ecosystem + version from project_dependencies + dependencies join
    const pdIds = [...new Set(findings.map((f: any) => f.project_dependency_id))];
    const { data: pds } = await supabase
      .from('project_dependencies')
      .select('id, version, dependency_id')
      .in('id', pdIds);

    const depIds = [...new Set((pds ?? []).map((pd: any) => pd.dependency_id).filter(Boolean))];
    const { data: deps } = depIds.length > 0
      ? await supabase.from('dependencies').select('id, name, ecosystem').in('id', depIds)
      : { data: [] as any[] };

    const pdById = new Map((pds ?? []).map((pd: any) => [pd.id, pd]));
    const depById = new Map((deps ?? []).map((d: any) => [d.id, d]));

    const enriched = findings.map((f: any) => {
      const pd = pdById.get(f.project_dependency_id);
      const dep = pd ? depById.get(pd.dependency_id) : null;
      return {
        ...f,
        package_name: dep?.name ?? null,
        ecosystem: dep?.ecosystem ?? null,
        package_version: pd?.version ?? null,
      };
    });

    res.json({ data: enriched, total: count ?? 0, page, per_page: perPage });
  } catch (error: any) {
    console.error('Error fetching malicious findings:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch malicious findings' });
  }
});

// ---------------------------------------------------------------------------
// GET .../malicious-findings/:findingId
// ---------------------------------------------------------------------------

router.get('/:id/projects/:projectId/malicious-findings/:findingId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: finding, error } = await supabase
      .from('project_malicious_findings')
      .select('*')
      .eq('id', findingId)
      .eq('project_id', projectId)
      .eq('organization_id', id)
      .maybeSingle();

    if (error) throw error;
    if (!finding) return res.status(404).json({ error: 'Finding not found' });

    // Hydrate package + cache evidence
    const { data: pd } = await supabase
      .from('project_dependencies')
      .select('id, version, dependency_id')
      .eq('id', finding.project_dependency_id)
      .single();

    const { data: dep } = pd?.dependency_id
      ? await supabase.from('dependencies').select('id, name, ecosystem').eq('id', pd.dependency_id).single()
      : { data: null as any };

    let evidence: any[] = [];
    let aiNarrative: string | null = null;
    let aiNarrativeCachedAt: string | null = null;

    if (dep) {
      // GuardDog evidence
      if (finding.scanner === 'guarddog') {
        const { data: cache } = await supabase
          .from('package_security_cache')
          .select('findings, scanner_version, scanned_at')
          .eq('package_name', dep.name)
          .eq('version', pd.version)
          .eq('ecosystem', dep.ecosystem)
          .eq('scanner', 'guarddog')
          .maybeSingle();
        const cached = cache?.findings ?? [];
        const matching = cached.find((c: any) => c.rule_id === finding.rule_id);
        if (matching?.evidence) evidence = matching.evidence;
      }
      // AI narrative
      const { data: aiCache } = await supabase
        .from('package_security_cache')
        .select('ai_narrative, scanned_at')
        .eq('package_name', dep.name)
        .eq('version', pd.version)
        .eq('ecosystem', dep.ecosystem)
        .eq('scanner', 'ai_review')
        .maybeSingle();
      if (aiCache) {
        aiNarrative = aiCache.ai_narrative ?? null;
        aiNarrativeCachedAt = aiCache.scanned_at ?? null;
      }
    }

    res.json({
      ...finding,
      package_name: dep?.name ?? null,
      ecosystem: dep?.ecosystem ?? null,
      package_version: pd?.version ?? null,
      evidence,
      ai_narrative: aiNarrative,
      ai_narrative_cached_at: aiNarrativeCachedAt,
    });
  } catch (error: any) {
    console.error('Error fetching malicious finding:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch malicious finding' });
  }
});

// ---------------------------------------------------------------------------
// PATCH .../malicious-findings/:findingId
//
// Body: { suppressed?: boolean, suppressed_reason?: string,
//         risk_accepted?: boolean, risk_accepted_reason?: string }
// ---------------------------------------------------------------------------

router.patch('/:id/projects/:projectId/malicious-findings/:findingId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const canManage = await checkProjectManagePermission(userId, id, projectId);
    if (!canManage) {
      return res.status(403).json({ error: 'Requires manage_projects or manage_teams_and_projects permission' });
    }

    // Defence-in-depth: verify finding belongs to (orgId, projectId) before update
    const { data: finding } = await supabase
      .from('project_malicious_findings')
      .select('id, project_id, organization_id')
      .eq('id', findingId)
      .maybeSingle();
    if (!finding || finding.project_id !== projectId || finding.organization_id !== id) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    const body = req.body ?? {};
    const update: Record<string, any> = {};
    const now = new Date().toISOString();

    if (body.suppressed === true) {
      update.suppressed = true;
      update.suppressed_by = userId;
      update.suppressed_at = now;
      update.suppressed_reason = body.suppressed_reason ?? null;
    } else if (body.suppressed === false) {
      update.suppressed = false;
      update.suppressed_by = null;
      update.suppressed_at = null;
      update.suppressed_reason = null;
    }

    if (body.risk_accepted === true) {
      update.risk_accepted = true;
      update.risk_accepted_by = userId;
      update.risk_accepted_at = now;
      update.risk_accepted_reason = body.risk_accepted_reason ?? null;
    } else if (body.risk_accepted === false) {
      update.risk_accepted = false;
      update.risk_accepted_by = null;
      update.risk_accepted_at = null;
      update.risk_accepted_reason = null;
    }

    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: 'No updatable fields supplied' });
    }

    const { error } = await supabase
      .from('project_malicious_findings')
      .update(update)
      .eq('id', findingId)
      .eq('project_id', projectId)
      .eq('organization_id', id);

    if (error) throw error;

    // Recompute is_malicious denorm flag for the underlying dependency
    const { data: pmf } = await supabase
      .from('project_malicious_findings')
      .select('dependency_id')
      .eq('id', findingId)
      .single();
    if (pmf?.dependency_id) {
      await supabase.rpc('recompute_dependency_is_malicious', { p_dependency_ids: [pmf.dependency_id] });
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error('Error updating malicious finding:', error);
    res.status(500).json({ error: error.message || 'Failed to update malicious finding' });
  }
});

// ---------------------------------------------------------------------------
// POST .../malicious-findings/:findingId/explain
// ---------------------------------------------------------------------------

router.post('/:id/projects/:projectId/malicious-findings/:findingId/explain', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, findingId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Pull finding + package + cached evidence so explain.ts has snippets.
    const { data: finding } = await supabase
      .from('project_malicious_findings')
      .select('id, project_dependency_id, dependency_id, scanner, rule_id, message, project_id, organization_id')
      .eq('id', findingId)
      .maybeSingle();
    if (!finding || finding.project_id !== projectId || finding.organization_id !== id) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    const { data: pd } = await supabase
      .from('project_dependencies')
      .select('id, version, dependency_id')
      .eq('id', finding.project_dependency_id)
      .single();
    if (!pd || !pd.dependency_id || !pd.version) {
      return res.status(404).json({ error: 'Project dependency not found' });
    }

    const { data: dep } = await supabase
      .from('dependencies')
      .select('name, ecosystem')
      .eq('id', pd.dependency_id)
      .single();
    if (!dep) return res.status(404).json({ error: 'Dependency not found' });

    let snippets: Array<{ file_path: string; snippet: string }> = [];
    if (finding.scanner === 'guarddog') {
      const { data: cache } = await supabase
        .from('package_security_cache')
        .select('findings')
        .eq('package_name', dep.name)
        .eq('version', pd.version)
        .eq('ecosystem', dep.ecosystem)
        .eq('scanner', 'guarddog')
        .maybeSingle();
      const cachedRules = (cache as any)?.findings ?? [];
      const matching = Array.isArray(cachedRules)
        ? cachedRules.find((c: any) => c.rule_id === finding.rule_id || finding.rule_id.endsWith(c.rule_id))
        : null;
      if (matching?.evidence) {
        snippets = (matching.evidence as Array<{ file_path: string; snippet: string }>).slice(0, 4);
      }
    }

    const { explainMaliciousFinding } = await import('../lib/malicious/explain');
    const outcome = await explainMaliciousFinding({
      organizationId: id,
      userId,
      projectId,
      findingId,
      packageName: dep.name,
      packageVersion: pd.version,
      ecosystem: dep.ecosystem,
      scanner: finding.scanner,
      ruleId: finding.rule_id,
      ruleMessage: finding.message,
      rawSourceSnippets: snippets,
    });

    if (!outcome.ok) {
      return res.status(outcome.status).json({ error: outcome.reason });
    }
    res.json(outcome.result);
  } catch (error: any) {
    console.error('Error explaining malicious finding:', error);
    res.status(500).json({ error: error.message || 'Failed to explain malicious finding' });
  }
});

// ---------------------------------------------------------------------------
// Internal routes (INTERNAL_API_KEY only)
// ---------------------------------------------------------------------------

const internalRouter = express.Router();

internalRouter.post('/feed-sync/:source', async (req, res) => {
  if (!verifyInternal(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { source } = req.params;
  if (source !== 'osv' && source !== 'ghsa') {
    return res.status(400).json({ error: `Unknown feed source: ${source}` });
  }
  try {
    const { runMaliciousFeedSync } = await import('../lib/malicious/feed-sync');
    const result = await runMaliciousFeedSync(source as 'osv' | 'ghsa');
    res.json(result);
  } catch (error: any) {
    console.error(`[malicious feed-sync ${source}] failed:`, error);
    res.status(500).json({ error: error?.message ?? 'feed-sync failed' });
  }
});

internalRouter.post('/staleness-watchdog', async (req, res) => {
  if (!verifyInternal(req)) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { runStalenessWatchdog } = await import('../lib/malicious/staleness-watchdog');
    const result = await runStalenessWatchdog();
    res.json(result);
  } catch (error: any) {
    console.error('[malicious staleness-watchdog] failed:', error);
    res.status(500).json({ error: error?.message ?? 'watchdog failed' });
  }
});

export { internalRouter as maliciousInternalRouter };
export default router;
