// ⚠️ ACCESS-FREE orchestration. CALLERS MUST gate first (checkTeamAccess for team,
// getAccessibleProjectIdsInOrganization for org) and pass an ALREADY-VALIDATED,
// org-scoped `projects` array. This module fans the per-project findings engine in,
// stamps + merges, and reads the org-wide chip maps once — it does NO access logic.
//
// One shared engine for the team (#112) and org findings bundles, so the fan-in /
// stamp / merge / degrade / log behavior can't drift between scopes.
import { captureInfraError } from './observability/capture';
import { Semaphore, withTimeout } from './concurrency';
import { supabase } from './supabase';
import {
  buildProjectFindingsCoreUnchecked,
  buildOrgTrackerLinksUnchecked,
  buildOrgGroupSuppressionsUnchecked,
  buildOrgAcknowledgementsUnchecked,
} from './project-findings';

// Worst-first caps applied PER PROJECT in the fan-in (the underlying builders order
// by depscore/severity desc, so these keep the most important rows).
export const SCA_CAP_PER_PROJECT = 100;
export const CODEFLOW_CAP_PER_PROJECT = 100;
// One slow/hung project degrades to empty rather than stalling the whole bundle.
export const PROJECT_TIMEOUT_MS = 8000;
// Process-wide: total per-project bundles in flight across ALL findings-bundle
// requests (team AND org). A fixed ceiling independent of how many users open
// findings surfaces at once. (Org fans the largest project set, so it's the heaviest
// consumer — acceptable: with SCA read in bulk, each project's fan-in is light, so
// slots free quickly.)
const findingsLimiter = new Semaphore(8);

export const FINDING_SLICES = [
  'vulnerabilities', 'secrets', 'semgrep', 'iac', 'container',
  'malicious', 'codeFlows', 'dast', 'baseImageRecs',
] as const;

export interface FindingsBundle {
  vulnerabilities: any[];
  secrets: any[];
  semgrep: any[];
  iac: any[];
  container: any[];
  malicious: any[];
  codeFlows: any[];
  dast: any[];
  baseImageRecs: any[];
  trackerLinks: any[];
  groupSuppressions: any[];
  acknowledgements: any[];
  projectIds: string[];
  degradedSlices: string[];
}

export function emptyFindingsBundle(): FindingsBundle {
  return {
    vulnerabilities: [], secrets: [], semgrep: [], iac: [], container: [],
    malicious: [], codeFlows: [], dast: [], baseImageRecs: [],
    trackerLinks: [], groupSuppressions: [], acknowledgements: [],
    projectIds: [], degradedSlices: [],
  };
}

export interface BundleProject {
  id: string;
  name?: string | null;
  framework?: string | null;
  active_extraction_run_id?: string | null;
}

/**
 * Fan the per-project findings engine across an already-validated project set,
 * stamp every row with project_id/name/framework, merge per-type, read the 3
 * org-wide chip maps once, and return one bundle. Slices/projects run concurrently
 * under a process-wide semaphore; a project that throws or times out degrades to
 * empty + a `${pid}:…` marker without blanking the bundle.
 *
 * `skipVulns` (org) nulls the per-project SCA slice — the org route reads SCA as ONE
 * bounded cross-project query instead of N unbounded per-project RPCs.
 */
export async function assembleFindingsBundle(
  orgId: string,
  projects: BundleProject[],
  opts: {
    scope: 'team' | 'org';
    logContext?: Record<string, string>;
    skipVulns?: boolean;
    vulnLimit?: number;
    codeFlowLimit?: number;
  },
): Promise<FindingsBundle> {
  if (projects.length === 0) return emptyFindingsBundle();

  const nameById = new Map<string, string>();
  const frameworkById = new Map<string, string | null>();
  for (const p of projects) {
    nameById.set(p.id, p.name ?? 'Unknown');
    frameworkById.set(p.id, p.framework ?? null);
  }

  const degradedSlices: string[] = [];
  const projectMs: Array<{ project_id: string; ms: number }> = [];
  const merged: Record<string, any[]> = {};
  for (const s of FINDING_SLICES) merged[s] = [];

  // Org-wide chip maps only need the org id — fire them NOW so their round-trips
  // OVERLAP the per-project fan-in instead of trailing it.
  const chipMapsPromise = Promise.all([
    buildOrgTrackerLinksUnchecked(orgId).catch(() => [] as any[]),
    buildOrgGroupSuppressionsUnchecked(orgId).catch(() => [] as any[]),
    buildOrgAcknowledgementsUnchecked(orgId).catch(() => [] as any[]),
  ]);

  await Promise.all(projects.map((p) => findingsLimiter.run(async () => {
    const pid = p.id;
    const projectName = nameById.get(pid);
    const projectFramework = frameworkById.get(pid) ?? null;
    const started = Date.now();
    try {
      const core = await withTimeout(
        buildProjectFindingsCoreUnchecked(orgId, pid, p.active_extraction_run_id ?? null, {
          vulnLimit: opts.vulnLimit ?? SCA_CAP_PER_PROJECT,
          codeFlowLimit: opts.codeFlowLimit ?? CODEFLOW_CAP_PER_PROJECT,
          organizationId: orgId,
          skipVulns: opts.skipVulns,
        }),
        PROJECT_TIMEOUT_MS,
      );
      for (const s of FINDING_SLICES) {
        for (const row of (core as any)[s] as any[]) {
          // Stamp project_id + project_name + project_framework on EVERY row. The SCA
          // RPC omits project_id (the cross-project dedup key would collapse),
          // project_name is on no finding table, and the org Findings table shows a
          // per-row framework icon. NOTE: the key is `project_framework`, NEVER
          // `framework` — IaC rows carry their own `framework` (the rule framework,
          // e.g. terraform/k8s) and stamping `framework` would clobber IaC grouping.
          merged[s].push({ ...row, project_id: pid, project_name: projectName, project_framework: projectFramework });
        }
      }
      for (const ds of core.degradedSlices) degradedSlices.push(`${pid}:${ds}`);
    } catch (err: any) {
      degradedSlices.push(`${pid}:${err?.message === 'timeout' ? 'timeout' : 'project'}`);
      captureInfraError(err, 'findings-bundle:project', { project_id: pid, organization_id: orgId, ...(opts.logContext ?? {}) });
    } finally {
      projectMs.push({ project_id: pid, ms: Date.now() - started });
    }
  })));

  const [trackerLinks, groupSuppressions, acknowledgements] = await chipMapsPromise;

  // Wall-time is set by the slowest project holding a slot, so log the top-3 slowest
  // PROJECTS by id — a slow bundle then names the culprit even at org scale.
  const slowestProjects = [...projectMs].sort((a, b) => b.ms - a.ms).slice(0, 3).map((x) => `${x.project_id}:${x.ms}ms`);
  console.log('[findings-bundle]', JSON.stringify({
    scope: opts.scope, ...(opts.logContext ?? {}), projects: projects.length, slowestProjects, degraded: degradedSlices.length,
  }));

  return {
    vulnerabilities: merged.vulnerabilities,
    secrets: merged.secrets,
    semgrep: merged.semgrep,
    iac: merged.iac,
    container: merged.container,
    malicious: merged.malicious,
    codeFlows: merged.codeFlows,
    dast: merged.dast,
    baseImageRecs: merged.baseImageRecs,
    trackerLinks,
    groupSuppressions,
    acknowledgements,
    projectIds: projects.map((p) => p.id),
    degradedSlices,
  };
}

/**
 * ⚠️ ACCESS-FREE. Caller passes ALREADY-VALIDATED project ids + their active run ids.
 *
 * The org Findings page's SCA slice as ONE bounded cross-project query — the same
 * shape the standalone org `/vulnerabilities` read uses, but `skipCount` + a
 * worst-first LIMIT (no exact count). Includes the disposition columns the row kebab
 * needs (finding_key/status/…), which the standalone read selects but drops. Does NOT
 * stamp project_name/framework — the caller does that from its validated projects.
 */
export async function buildOrgVulnerabilitiesUnchecked(
  projectIds: string[],
  activeRunIds: string[],
  opts: { limit: number },
): Promise<any[]> {
  if (projectIds.length === 0 || activeRunIds.length === 0) return [];

  const { data: rows, error } = await supabase
    .from('project_dependency_findings')
    .select(
      'id, project_id, project_dependency_id, osv_id, severity, summary, aliases, fixed_versions, published_at, is_reachable, epss_score, cvss_score, cisa_kev, depscore, contextual_depscore, entry_point_classification, epd_status, sla_status, sla_deadline_at, reachability_level, runtime_confirmed_at, runtime_confirmed_dast_finding_id, runtime_confirmed_prior_level, status, finding_key, auto_ignored, auto_ignore_reason, suppressed, risk_accepted',
    )
    .in('project_id', projectIds)
    .in('extraction_run_id', activeRunIds)
    .neq('status', 'resolved')
    .order('contextual_depscore', { ascending: false, nullsFirst: false })
    .order('depscore', { ascending: false, nullsFirst: false })
    .limit(opts.limit);
  if (error) throw error;

  const list = rows ?? [];
  const pdIds = [...new Set(list.map((r: any) => r.project_dependency_id).filter(Boolean))];
  const depMap = new Map<string, { name: string; version: string; dependency_id: string }>();
  if (pdIds.length > 0) {
    const { data: deps, error: depErr } = await supabase
      .from('project_dependencies')
      .select('id, name, version, dependency_id')
      .in('id', pdIds)
      .is('removed_at', null);
    if (depErr) throw depErr;
    for (const d of deps || []) {
      depMap.set((d as any).id, {
        name: (d as any).name ?? 'Unknown',
        version: (d as any).version ?? 'Unknown',
        dependency_id: (d as any).dependency_id ?? '',
      });
    }
  }

  return list.map((r: any) => {
    const dep = r.project_dependency_id ? depMap.get(r.project_dependency_id) : undefined;
    return {
      id: r.id,
      osv_id: r.osv_id,
      severity: r.severity,
      summary: r.summary ?? null,
      details: null,
      aliases: r.aliases || [],
      fixed_versions: r.fixed_versions || [],
      published_at: r.published_at ?? null,
      modified_at: null,
      dependency_id: dep?.dependency_id ?? '',
      dependency_name: dep?.name ?? 'Unknown',
      dependency_version: dep?.version ?? 'Unknown',
      is_reachable: r.is_reachable ?? undefined,
      epss_score: r.epss_score,
      cvss_score: r.cvss_score ?? null,
      cisa_kev: r.cisa_kev ?? false,
      depscore: r.depscore ?? null,
      contextual_depscore: r.contextual_depscore ?? null,
      entry_point_classification: r.entry_point_classification ?? null,
      epd_status: r.epd_status ?? null,
      sla_status: r.sla_status ?? null,
      sla_deadline_at: r.sla_deadline_at ?? null,
      reachability_level: r.reachability_level ?? null,
      runtime_confirmed_at: r.runtime_confirmed_at ?? null,
      runtime_confirmed_dast_finding_id: r.runtime_confirmed_dast_finding_id ?? null,
      runtime_confirmed_prior_level: r.runtime_confirmed_prior_level ?? null,
      project_id: r.project_id,
      // Disposition fields the row kebab needs (the standalone read drops these).
      finding_key: r.finding_key ?? null,
      status: r.status ?? null,
      auto_ignored: r.auto_ignored ?? false,
      auto_ignore_reason: r.auto_ignore_reason ?? null,
      suppressed: r.suppressed ?? false,
      risk_accepted: r.risk_accepted ?? false,
    };
  });
}
