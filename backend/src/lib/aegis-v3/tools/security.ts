import { jsonSchema } from 'ai';
import { resolveProject, resolveProjectVulnerability } from './resolvers';
import type { AegisToolEntry } from '../tool-types';

const getProjectVulnerabilities: AegisToolEntry<{
  projectName: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  reachableOnly?: boolean;
  limit?: number;
}> = {
  name: 'get_project_vulnerabilities',
  description:
    'Vulnerabilities for a project. Each row includes OSV id, CVE aliases, severity, CVSS, EPSS, KEV flag, reachability level, depscore, the affected dependency@version, and fixed versions. Pass the project name exactly as the user said it.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
      reachableOnly: { type: 'boolean' },
      limit: { type: 'integer', minimum: 1, maximum: 500 },
    },
    required: ['projectName'],
    additionalProperties: false,
  }),
  execute: async ({ projectName, severity, reachableOnly, limit }, ctx) => {
    const resolved = await resolveProject(projectName, ctx.orgId, ctx.supabase);
    if ('error' in resolved) return resolved;

    let query = ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select(
        'osv_id, severity, summary, aliases, fixed_versions, is_reachable, reachability_level, epss_score, cvss_score, cisa_kev, depscore, published_at, project_dependency_id',
      )
      .eq('project_id', resolved.id)
      .order('depscore', { ascending: false, nullsFirst: false })
      .limit(limit ?? 200);

    if (severity) query = query.eq('severity', severity);
    if (reachableOnly) query = query.eq('is_reachable', true);

    const { data: vulns, error } = await query;
    if (error) return { error: error.message };
    if (!vulns || vulns.length === 0) {
      return { project: resolved.name, vulnerabilities: [], totalReturned: 0 };
    }

    const pdIds = Array.from(new Set(vulns.map((v: any) => v.project_dependency_id)));
    const { data: pds } = await ctx.supabase
      .from('project_dependencies')
      .select('id, name, version')
      .in('id', pdIds);
    const pdById = new Map<string, any>();
    for (const pd of pds ?? []) pdById.set(pd.id, pd);

    return {
      project: resolved.name,
      vulnerabilities: vulns.map((v: any) => {
        const pd = pdById.get(v.project_dependency_id);
        return {
          osvId: v.osv_id,
          cveAliases: (v.aliases ?? []).filter((a: string) => a.startsWith('CVE-')),
          aliases: v.aliases ?? [],
          severity: v.severity,
          cvssScore: v.cvss_score,
          epssScore: v.epss_score,
          isKev: !!v.cisa_kev,
          isReachable: !!v.is_reachable,
          reachabilityLevel: v.reachability_level,
          depscore: v.depscore,
          publishedAt: v.published_at,
          summary: v.summary,
          fixedVersions: v.fixed_versions ?? [],
          dependency: pd ? { name: pd.name, version: pd.version } : null,
        };
      }),
      totalReturned: vulns.length,
    };
  },
};

const getSecurityPosture: AegisToolEntry<Record<string, never>> = {
  name: 'get_security_posture',
  description:
    'Org-wide aggregate. Returns project count, vulnerability totals by severity (incl. reachable and KEV), average health score, and a count of projects in violation. Takes no arguments.',
  danger: 'safe',
  inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
  execute: async (_input, ctx) => {
    const { data: projects, error } = await ctx.supabase
      .from('projects')
      .select('id, health_score, status_violations, status_id')
      .eq('organization_id', ctx.orgId);
    if (error) return { error: error.message };
    if (!projects || projects.length === 0) return { projectCount: 0, vulnCounts: null };

    const projectIds = projects.map((p: any) => p.id);
    const { data: vulns } = await ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select('severity, is_reachable, cisa_kev, depscore')
      .in('project_id', projectIds);

    const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    let reachable = 0;
    let kev = 0;
    let critReachable = 0;
    let highestDepscore = 0;
    for (const v of vulns ?? []) {
      const sev = (v.severity ?? 'low').toLowerCase();
      if (sev in vulnCounts) (vulnCounts as any)[sev]++;
      if (v.is_reachable) reachable++;
      if (v.cisa_kev) kev++;
      if (v.is_reachable && sev === 'critical') critReachable++;
      if (typeof v.depscore === 'number' && v.depscore > highestDepscore) highestDepscore = v.depscore;
    }

    let healthSum = 0;
    let healthCount = 0;
    let projectsInViolation = 0;
    for (const p of projects) {
      if (typeof p.health_score === 'number') {
        healthSum += p.health_score;
        healthCount++;
      }
      if (Array.isArray(p.status_violations) && p.status_violations.length > 0) {
        projectsInViolation++;
      }
    }

    return {
      projectCount: projects.length,
      vulnCounts,
      reachableVulnCount: reachable,
      kevVulnCount: kev,
      criticalReachableCount: critReachable,
      highestDepscore,
      averageHealthScore: healthCount > 0 ? Math.round(healthSum / healthCount) : null,
      projectsInViolation,
    };
  },
};

const getVulnerabilityDetail: AegisToolEntry<{
  cveOrOsvId: string;
}> = {
  name: 'get_vulnerability_detail',
  description:
    'Full detail for a vulnerability across the whole org. Lookup by CVE id (e.g. CVE-2024-1234) or OSV id (e.g. GHSA-xxxx). Returns severity, CVSS, EPSS, KEV, published date, fixed versions, and every project + dependency it affects.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      cveOrOsvId: {
        type: 'string',
        minLength: 1,
        description: 'CVE id (CVE-YYYY-NNNN) or OSV id (GHSA-xxxx).',
      },
    },
    required: ['cveOrOsvId'],
    additionalProperties: false,
  }),
  execute: async ({ cveOrOsvId }, ctx) => {
    const trimmed = (cveOrOsvId ?? '').trim();
    if (!trimmed) return { error: 'cveOrOsvId is required.' };

    const { data: orgProjects } = await ctx.supabase
      .from('projects')
      .select('id, name')
      .eq('organization_id', ctx.orgId);
    const orgProjectIds = (orgProjects ?? []).map((p: any) => p.id);
    const projectNameById = new Map<string, string>();
    for (const p of orgProjects ?? []) projectNameById.set(p.id, p.name);

    let query = ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select(
        'project_id, project_dependency_id, osv_id, severity, summary, aliases, fixed_versions, is_reachable, reachability_level, epss_score, cvss_score, cisa_kev, depscore, published_at',
      )
      .in('project_id', orgProjectIds);

    if (trimmed.toUpperCase().startsWith('CVE-')) {
      query = (query as any).contains('aliases', [trimmed.toUpperCase()]);
    } else {
      query = query.eq('osv_id', trimmed);
    }

    const { data: rows, error } = await query.limit(50);
    if (error) return { error: error.message };
    if (!rows || rows.length === 0) {
      return { error: `Vulnerability "${trimmed}" not found in this organization.` };
    }

    const first = rows[0] as any;
    const pdIds = Array.from(new Set(rows.map((r: any) => r.project_dependency_id)));
    const { data: pds } = await ctx.supabase
      .from('project_dependencies')
      .select('id, name, version')
      .in('id', pdIds);
    const pdById = new Map<string, any>();
    for (const pd of pds ?? []) pdById.set(pd.id, pd);

    return {
      osvId: first.osv_id,
      cveAliases: (first.aliases ?? []).filter((a: string) => a.startsWith('CVE-')),
      aliases: first.aliases ?? [],
      severity: first.severity,
      cvssScore: first.cvss_score,
      epssScore: first.epss_score,
      isKev: !!first.cisa_kev,
      publishedAt: first.published_at,
      summary: first.summary,
      fixedVersions: first.fixed_versions ?? [],
      affectedProjects: rows.map((r: any) => {
        const pd = pdById.get(r.project_dependency_id);
        return {
          projectName: projectNameById.get(r.project_id) ?? null,
          dependency: pd ? { name: pd.name, version: pd.version } : null,
          isReachable: !!r.is_reachable,
          reachabilityLevel: r.reachability_level,
          depscore: r.depscore,
        };
      }),
      affectedProjectCount: new Set(rows.map((r: any) => r.project_id)).size,
    };
  },
};

const getReachabilityFlows: AegisToolEntry<{
  projectName: string;
  cveOrOsvId: string;
}> = {
  name: 'get_reachability_flows',
  description:
    'Reachability flow paths (entry point → sink) for a vulnerability inside a specific project. Returns each flow with entry-point file/method/line, sink file/method/line, and the chain of nodes between them.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
      cveOrOsvId: {
        type: 'string',
        minLength: 1,
        description: 'CVE id (CVE-YYYY-NNNN) or OSV id (GHSA-xxxx) — from get_project_vulnerabilities.',
      },
    },
    required: ['projectName', 'cveOrOsvId'],
    additionalProperties: false,
  }),
  execute: async ({ projectName, cveOrOsvId }, ctx) => {
    const ref = await resolveProjectVulnerability(projectName, cveOrOsvId, ctx.orgId, ctx.supabase);
    if ('error' in ref) return ref;

    const { data: vuln } = await ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select('id, project_id, osv_id, reachability_level, reachability_details, project_dependency_id')
      .eq('id', ref.vulnerabilityId)
      .single();
    if (!vuln) return { error: 'Vulnerability not found' };

    const { data: pd } = await ctx.supabase
      .from('project_dependencies')
      .select('name, version')
      .eq('id', vuln.project_dependency_id)
      .single();

    const { data: flows } = await ctx.supabase
      .from('project_reachable_flows')
      .select(
        'id, purl, entry_point_file, entry_point_method, entry_point_line, sink_file, sink_method, sink_line, flow_length, flow_nodes',
      )
      .eq('project_id', vuln.project_id)
      .limit(10);

    const packageMatch = pd?.name
      ? (flows ?? []).filter((f: any) => f.purl && f.purl.includes(pd.name))
      : flows ?? [];

    return {
      project: ref.projectName,
      osvId: vuln.osv_id,
      reachabilityLevel: vuln.reachability_level,
      reachabilityDetails: vuln.reachability_details ?? null,
      dependency: pd ? { name: pd.name, version: pd.version } : null,
      flows: packageMatch.map((f: any) => ({
        purl: f.purl,
        entryPoint: {
          file: f.entry_point_file,
          method: f.entry_point_method,
          line: f.entry_point_line,
        },
        sink: { file: f.sink_file, method: f.sink_method, line: f.sink_line },
        flowLength: f.flow_length,
        flowNodes: f.flow_nodes,
      })),
      flowCount: packageMatch.length,
    };
  },
};

export const securityTools: AegisToolEntry[] = [
  getProjectVulnerabilities,
  getSecurityPosture,
  getVulnerabilityDetail,
  getReachabilityFlows,
];
