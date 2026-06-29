// ⚠️ ACCESS-FREE. CALLER MUST gate with checkProjectAccess first. Project-scoped finding tables filter by project_id/extraction_run_id only (NOT organization_id) → an ungated caller is a cross-tenant IDOR. Only the findings-bundle route (and its tests) may call these.
/**
 * project-findings.ts — one access-free builder per findings slice.
 *
 * Each builder is the EXACT query + shaping the matching standalone endpoint
 * runs in its `res.json(...)`, with the access/permission check stripped out.
 * The findings-bundle route gates ONCE (checkProjectAccess) and then runs every
 * builder concurrently; the standalone endpoints keep their own gate and
 * delegate the query to the same builder, so the bundle and the legacy
 * endpoints can never drift on shaping, ordering, or null-run handling.
 *
 * Builders take `(orgId, projectId, activeExtractionId, opts?)` (org-wide
 * builders take just `orgId`) and return the standalone endpoint's payload.
 */
import { supabase } from '../lib/supabase';
import { toDataFlowFinding } from '../lib/code-flow-findings';
import { RECOMMENDATION_COLUMNS } from '../routes/base-image-recommendations';
import { IAC_FRAMEWORKS } from '../routes/scanner-findings';
import { loadDastFindings } from '../lib/dast-findings';
import type { DastFindingDTO } from '../types/dast';

const NO_ACTIVE_RUN = '__no_active_run__';

// ---------------------------------------------------------------------------
// 1. Dependency (SCA) vulnerabilities
//    Source: projects.ts GET .../vulnerabilities
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildProjectVulnerabilitiesUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
): Promise<any[]> {
  // No finalized run → nothing valid to show (orphaned partial-run rows would
  // 404 on expand). Mirrors the endpoint's early `res.json([])`.
  if (!activeExtractionId) return [];

  // Prefer project_dependency_vulnerabilities (reachable vulns from extraction
  // worker) when this run has any. A single-row existence probe answers the
  // branch question in one indexed lookup (vs a count over thousands of CVEs).
  const { data: pdvProbe } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('id')
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN)
    .limit(1);

  const usePdv = (pdvProbe?.length ?? 0) > 0;
  const rpcName = usePdv ? 'get_project_vulnerabilities_from_pdv' : 'get_project_vulnerabilities';
  const { data: rows, error: rpcError } = await supabase.rpc(rpcName, {
    p_project_id: projectId,
  });

  if (rpcError) {
    // Fallback if RPC not yet deployed: two queries (no per-dep batching).
    const { data: projectDeps, error: depsError } = await supabase
      .from('project_dependencies')
      .select('dependency_id, name, version')
      .eq('project_id', projectId)
      .is('removed_at', null);

    if (depsError) throw depsError;

    const dependencyIds = (projectDeps || [])
      .map((pd: any) => pd.dependency_id)
      .filter(Boolean);

    if (dependencyIds.length === 0) return [];

    const depInfoMap = new Map<string, { name: string; version: string }>();
    (projectDeps || []).forEach((pd: any) => {
      if (pd.dependency_id) depInfoMap.set(pd.dependency_id, { name: pd.name, version: pd.version });
    });

    const VULN_BATCH = 1000;
    const allVulnerabilities: any[] = [];
    for (let i = 0; i < dependencyIds.length; i += VULN_BATCH) {
      const batch = dependencyIds.slice(i, i + VULN_BATCH);
      const { data: vulns, error: vulnsError } = await supabase
        .from('dependency_vulnerabilities')
        .select('id, dependency_id, osv_id, severity, summary, details, aliases, fixed_versions, published_at, modified_at, created_at')
        .in('dependency_id', batch)
        .order('severity', { ascending: true })
        .order('published_at', { ascending: false, nullsFirst: false });
      if (vulnsError) throw vulnsError;
      if (vulns) allVulnerabilities.push(...vulns);
    }

    const enrichedVulnerabilities = allVulnerabilities.map((vuln: any) => {
      const depInfo = depInfoMap.get(vuln.dependency_id);
      return {
        id: vuln.id,
        osv_id: vuln.osv_id,
        severity: vuln.severity,
        summary: vuln.summary,
        details: vuln.details,
        aliases: vuln.aliases || [],
        fixed_versions: vuln.fixed_versions || [],
        published_at: vuln.published_at,
        modified_at: vuln.modified_at,
        dependency_id: vuln.dependency_id,
        dependency_name: depInfo?.name || 'Unknown',
        dependency_version: depInfo?.version || 'Unknown',
      };
    });

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    enrichedVulnerabilities.sort((a, b) => {
      const severityDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
      if (severityDiff !== 0) return severityDiff;
      return new Date(b.published_at || 0).getTime() - new Date(a.published_at || 0).getTime();
    });
    return enrichedVulnerabilities;
  }

  const enrichedVulnerabilities = (rows || []).map((vuln: any) => ({
    id: vuln.id,
    osv_id: vuln.osv_id,
    severity: vuln.severity,
    summary: vuln.summary,
    details: vuln.details ?? null,
    aliases: vuln.aliases || [],
    fixed_versions: vuln.fixed_versions || [],
    published_at: vuln.published_at,
    modified_at: vuln.modified_at,
    dependency_id: vuln.dependency_id,
    dependency_name: vuln.dependency_name ?? 'Unknown',
    sla_status: vuln.sla_status ?? null,
    sla_deadline_at: vuln.sla_deadline_at ?? null,
    dependency_version: vuln.dependency_version ?? 'Unknown',
    ...(usePdv && {
      is_reachable: vuln.is_reachable ?? true,
      reachability_level: vuln.reachability_level ?? null,
      runtime_confirmed_at: vuln.runtime_confirmed_at ?? null,
      epss_score: vuln.epss_score,
      cvss_score: vuln.cvss_score ?? null,
      cisa_kev: vuln.cisa_kev ?? false,
      depscore: vuln.depscore ?? null,
      contextual_depscore: vuln.contextual_depscore ?? null,
      entry_point_classification: vuln.entry_point_classification ?? null,
      epd_status: vuln.epd_status ?? null,
      finding_key: vuln.finding_key ?? null,
      status: vuln.status ?? null,
      auto_ignored: vuln.auto_ignored ?? false,
      auto_ignore_reason: vuln.auto_ignore_reason ?? null,
      ignore_reason: vuln.ignore_reason ?? null,
      ignore_note: vuln.ignore_note ?? null,
      suppressed: vuln.suppressed ?? false,
      risk_accepted: vuln.risk_accepted ?? false,
    }),
  }));

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  enrichedVulnerabilities.sort((a: any, b: any) => {
    const rank = (x: any) => {
      const c = x.contextual_depscore;
      const d = x.depscore;
      if (c != null && Number.isFinite(Number(c))) return Number(c);
      if (d != null && Number.isFinite(Number(d))) return Number(d);
      return -1;
    };
    const aScore = rank(a);
    const bScore = rank(b);
    if (aScore !== bScore) return bScore - aScore;
    const severityDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
    if (severityDiff !== 0) return severityDiff;
    return new Date(b.published_at || 0).getTime() - new Date(a.published_at || 0).getTime();
  });

  return enrichedVulnerabilities;
}

// ---------------------------------------------------------------------------
// 2. Secret findings
//    Source: projects.ts GET .../secret-findings
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildSecretFindingsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
  opts: { page: number; perPage: number; skipCount?: boolean },
): Promise<{ data: any[]; total: number; page: number; per_page: number }> {
  const { page, perPage } = opts;
  const offset = (page - 1) * perPage;

  const { data, error } = await supabase
    .from('project_secret_findings')
    .select('*')
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN)
    .order('is_verified', { ascending: false })
    .order('created_at', { ascending: false })
    .range(offset, offset + perPage - 1);
  if (error) throw error;
  const rows = data ?? [];

  // The bundle feeds only `.data` into the table and never reads `total`, so it
  // passes skipCount to drop the exact count(*) — which scans every matching row
  // and is the slowest part of the bundle on large finding tables. Standalone
  // endpoints omit skipCount and still get the exact total.
  if (opts.skipCount) return { data: rows, total: rows.length, page, per_page: perPage };

  const { count } = await supabase
    .from('project_secret_findings')
    .select('id', { count: 'exact', head: true })
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN);
  return { data: rows, total: count ?? 0, page, per_page: perPage };
}

// ---------------------------------------------------------------------------
// 3. Semgrep (SAST) findings
//    Source: projects.ts GET .../semgrep-findings
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildSemgrepFindingsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
  opts: { page: number; perPage: number; skipCount?: boolean },
): Promise<{ data: any[]; total: number; page: number; per_page: number }> {
  const { page, perPage } = opts;
  const offset = (page - 1) * perPage;

  const { data, error } = await supabase
    .from('project_semgrep_findings')
    .select('*')
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN)
    .order('severity', { ascending: true })
    .order('created_at', { ascending: false })
    .range(offset, offset + perPage - 1);
  if (error) throw error;
  const rows = data ?? [];

  // See buildSecretFindingsUnchecked — bundle passes skipCount to drop the count(*).
  if (opts.skipCount) return { data: rows, total: rows.length, page, per_page: perPage };

  const { count } = await supabase
    .from('project_semgrep_findings')
    .select('id', { count: 'exact', head: true })
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN);
  return { data: rows, total: count ?? 0, page, per_page: perPage };
}

// ---------------------------------------------------------------------------
// 4. IaC findings
//    Source: scanner-findings.ts GET .../iac-findings
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildIacFindingsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
  opts: {
    page: number;
    perPage: number;
    status?: unknown;
    severity?: unknown;
    framework?: unknown;
    depscoreMin?: unknown;
    skipCount?: boolean;
  },
): Promise<{ data: any[]; total: number; page: number; per_page: number }> {
  const { page, perPage } = opts;
  const offset = (page - 1) * perPage;
  if (!activeExtractionId) {
    return { data: [], total: 0, page, per_page: perPage };
  }

  const severityFilter = String(opts.severity ?? '').trim().toUpperCase();
  const statusFilter = String(opts.status ?? '').trim().toLowerCase();
  const frameworkFilter = String(opts.framework ?? '').trim().toLowerCase();
  const depscoreMin = parseInt(String(opts.depscoreMin ?? ''), 10);

  let countQuery = supabase
    .from('project_iac_findings')
    .select('id', { count: 'exact', head: true })
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId);
  let dataQuery = supabase
    .from('project_iac_findings')
    .select('*')
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId);

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

  const { data, error } = await dataQuery
    .order('depscore', { ascending: false, nullsFirst: false })
    .order('severity', { ascending: true })
    .order('created_at', { ascending: false })
    .range(offset, offset + perPage - 1);
  if (error) throw error;
  const rows = data ?? [];

  // See buildSecretFindingsUnchecked — bundle passes skipCount to drop the count(*).
  if (opts.skipCount) return { data: rows, total: rows.length, page, per_page: perPage };

  const { count } = await countQuery;
  return { data: rows, total: count ?? 0, page, per_page: perPage };
}

// ---------------------------------------------------------------------------
// 5. Container findings
//    Source: scanner-findings.ts GET .../container-findings
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildContainerFindingsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
  opts: { page: number; perPage: number; status?: unknown; severity?: unknown; skipCount?: boolean },
): Promise<{ data: any[]; total: number; page: number; per_page: number }> {
  const { page, perPage } = opts;
  const offset = (page - 1) * perPage;
  if (!activeExtractionId) {
    return { data: [], total: 0, page, per_page: perPage };
  }

  const severityFilter = String(opts.severity ?? '').trim().toUpperCase();
  const statusFilter = String(opts.status ?? '').trim().toLowerCase();

  let countQuery = supabase
    .from('project_container_findings')
    .select('id', { count: 'exact', head: true })
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId);
  let dataQuery = supabase
    .from('project_container_findings')
    .select('*')
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId);

  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severityFilter)) {
    countQuery = countQuery.eq('severity', severityFilter);
    dataQuery = dataQuery.eq('severity', severityFilter);
  }
  if (statusFilter === 'open' || statusFilter === 'ignored') {
    countQuery = countQuery.eq('status', statusFilter);
    dataQuery = dataQuery.eq('status', statusFilter);
  }

  const { data, error } = await dataQuery
    .order('depscore', { ascending: false, nullsFirst: false })
    .order('severity', { ascending: true })
    .order('created_at', { ascending: false })
    .range(offset, offset + perPage - 1);
  if (error) throw error;
  const rows = data ?? [];

  // See buildSecretFindingsUnchecked — bundle passes skipCount to drop the count(*).
  if (opts.skipCount) return { data: rows, total: rows.length, page, per_page: perPage };

  const { count } = await countQuery;
  return { data: rows, total: count ?? 0, page, per_page: perPage };
}

// ---------------------------------------------------------------------------
// 6. Malicious-package findings
//    Source: malicious.ts GET .../malicious-findings
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildMaliciousFindingsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
  opts: {
    page: number;
    perPage: number;
    reachabilityLevels?: string[];
    includeUnknown?: boolean;
    skipCount?: boolean;
  },
): Promise<{ data: any[]; total: number; page: number; per_page: number }> {
  const { page, perPage } = opts;
  const offset = (page - 1) * perPage;

  const reachabilityLevels = opts.reachabilityLevels ?? [];
  const includeUnknown = opts.includeUnknown ?? false;
  const hasReachabilityFilter = reachabilityLevels.length > 0 || includeUnknown;

  const applyReachabilityFilter = <T extends { or: any; in: any; is: any }>(q: T): T => {
    if (!hasReachabilityFilter) return q;
    if (reachabilityLevels.length > 0 && includeUnknown) {
      const inList = reachabilityLevels.map((l) => `"${l}"`).join(',');
      return q.or(`reachability_level.in.(${inList}),reachability_level.is.null`);
    }
    if (reachabilityLevels.length > 0) {
      return q.in('reachability_level', reachabilityLevels);
    }
    return q.is('reachability_level', null);
  };

  const { data, error } = await applyReachabilityFilter(
    supabase
      .from('project_malicious_findings')
      .select('*')
      .eq('project_id', projectId)
      .eq('organization_id', orgId)
      .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN)
      .order('severity', { ascending: true })
      .order('created_at', { ascending: false })
      .range(offset, offset + perPage - 1),
  );

  if (error) throw error;

  const findings = data ?? [];

  // See buildSecretFindingsUnchecked — bundle passes skipCount to drop the count(*).
  const total = opts.skipCount
    ? findings.length
    : (
        await applyReachabilityFilter(
          supabase
            .from('project_malicious_findings')
            .select('id', { count: 'exact', head: true })
            .eq('project_id', projectId)
            .eq('organization_id', orgId)
            .eq('extraction_run_id', activeExtractionId ?? NO_ACTIVE_RUN),
        )
      ).count ?? 0;

  if (findings.length === 0) {
    return { data: [], total, page, per_page: perPage };
  }

  // Hydrate with package_name + ecosystem + version from project_dependencies +
  // dependencies join.
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

  return { data: enriched, total, page, per_page: perPage };
}

// ---------------------------------------------------------------------------
// 7. First-party data-flow (code-flow) findings
//    Source: projects.ts GET .../code-flow-findings
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildCodeFlowFindingsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
): Promise<{ data: any[]; total: number }> {
  if (!activeExtractionId) {
    return { data: [], total: 0 };
  }

  const [flowsRes, supRes] = await Promise.all([
    supabase
      .from('project_reachable_flows')
      .select(
        'id, project_id, extraction_run_id, vuln_class, entry_point_file, entry_point_line, entry_point_method, entry_point_tag, entry_point_code, sink_file, sink_line, sink_method, sink_code, flow_length, flow_nodes, flow_signature_hash, created_at',
      )
      .eq('project_id', projectId)
      .eq('extraction_run_id', activeExtractionId)
      .eq('reachability_source', 'taint_engine')
      .is('osv_id', null)
      .order('created_at', { ascending: false }),
    supabase
      .from('project_reachable_flow_suppressions')
      .select('flow_signature_hash')
      .eq('project_id', projectId),
  ]);

  if (flowsRes.error) throw flowsRes.error;
  const suppressed = new Set(
    (supRes.data ?? []).map((r: any) => r.flow_signature_hash).filter(Boolean),
  );

  const data = (flowsRes.data ?? []).map((row: any) => ({
    ...toDataFlowFinding(row),
    flow_suppressed: Boolean(row.flow_signature_hash && suppressed.has(row.flow_signature_hash)),
  }));

  return { data, total: data.length };
}

// ---------------------------------------------------------------------------
// 8. Base-image recommendations
//    Source: base-image-recommendations.ts GET .../base-image-recommendations
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildBaseImageRecommendationsUnchecked(
  orgId: string,
  projectId: string,
  activeExtractionId: string | null,
): Promise<{ recommendations: any[] }> {
  if (!activeExtractionId) {
    return { recommendations: [] };
  }

  const { data, error } = await supabase
    .from('project_base_image_recommendations')
    .select(RECOMMENDATION_COLUMNS)
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeExtractionId)
    .eq('is_dismissed', false)
    .order('cve_delta', { ascending: false, nullsFirst: false })
    .order('dockerfile_path', { ascending: true });
  if (error) throw error;

  return { recommendations: (data ?? []) as any[] };
}

// ---------------------------------------------------------------------------
// 9. DAST findings
//    Source: dast.ts GET /:projectId/dast/findings?resolve_target=latest
// ---------------------------------------------------------------------------

/**
 * ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first.
 *
 * No orgId param: the bundle has already verified access to `projectId`. The
 * tenant guard inside loadDastFindings still needs the project's org, so we read
 * it off the project row (the same org the resolved target must belong to).
 */
export async function buildDastFindingsForProjectUnchecked(
  projectId: string,
  opts: { limit: number },
): Promise<DastFindingDTO[]> {
  const { data: proj } = await supabase
    .from('projects')
    .select('organization_id')
    .eq('id', projectId)
    .single();
  const organizationId = (proj as any)?.organization_id;
  if (!organizationId) return [];

  const result = await loadDastFindings(supabase, {
    projectId,
    organizationId,
    limit: opts.limit,
    filterTargetId: null,
    resolveLatestTarget: true,
  });
  // A deny (target tenant-guard miss / query error) degrades the slice to []
  // rather than failing the whole bundle.
  return result.findings;
}

// ---------------------------------------------------------------------------
// 10-12. Org-wide chip/disposition maps (the org-wide findings table reads
//        these once and maps by project_id + finding_type + finding_key).
//        Source: scanner-findings.ts GET /:id/tracker-links,
//        /:id/group-suppressions, /:id/acknowledgements.
// ---------------------------------------------------------------------------

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildOrgTrackerLinksUnchecked(orgId: string): Promise<any[]> {
  const { data, error } = await supabase
    .from('finding_tracker_links')
    .select('id, project_id, finding_type, finding_key, provider, external_key, external_url, title, external_state, created_at')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data ?? [];
}

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildOrgGroupSuppressionsUnchecked(orgId: string): Promise<any[]> {
  const { data, error } = await supabase
    .from('project_finding_group_suppressions')
    .select('project_id, group_type, group_key, ignore_reason, ignore_note')
    .eq('organization_id', orgId);
  if (error) throw error;
  return data ?? [];
}

/** ⚠️ ACCESS-FREE — see file banner. Gate with checkProjectAccess first. */
export async function buildOrgAcknowledgementsUnchecked(orgId: string): Promise<any[]> {
  const { data, error } = await supabase
    .from('project_finding_acknowledgements')
    .select('project_id, finding_type, finding_key')
    .eq('organization_id', orgId);
  if (error) throw error;
  return data ?? [];
}
