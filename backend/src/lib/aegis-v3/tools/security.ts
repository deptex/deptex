import { jsonSchema } from 'ai';
import type { AegisToolEntry } from '../tool-types';

const getProjectVulnerabilities: AegisToolEntry<{
  projectId: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  reachableOnly?: boolean;
  limit?: number;
}> = {
  name: 'get_project_vulnerabilities',
  description:
    'List vulnerabilities for a project. Each row includes OSV id, CVE aliases, severity, CVSS, EPSS, KEV flag, reachability level, depscore, the affected dependency@version, and fixed versions. Optional filters: severity and reachableOnly.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectId: { type: 'string', format: 'uuid' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
      reachableOnly: { type: 'boolean' },
      limit: { type: 'integer', minimum: 1, maximum: 500 },
    },
    required: ['projectId'],
    additionalProperties: false,
  }),
  execute: async ({ projectId, severity, reachableOnly, limit }, ctx) => {
    const { data: project } = await ctx.supabase
      .from('projects')
      .select('id, organization_id')
      .eq('id', projectId)
      .single();
    if (!project) return { error: 'Project not found' };
    if (project.organization_id !== ctx.orgId) return { error: 'Project not in current organization' };

    let query = ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select(
        'id, osv_id, severity, summary, aliases, fixed_versions, is_reachable, reachability_level, epss_score, cvss_score, cisa_kev, depscore, published_at, project_dependency_id',
      )
      .eq('project_id', projectId)
      .order('depscore', { ascending: false, nullsFirst: false })
      .limit(limit ?? 200);

    if (severity) query = query.eq('severity', severity);
    if (reachableOnly) query = query.eq('is_reachable', true);

    const { data: vulns, error } = await query;
    if (error) return { error: error.message };
    if (!vulns || vulns.length === 0) return { vulnerabilities: [], totalReturned: 0 };

    const pdIds = Array.from(new Set(vulns.map((v: any) => v.project_dependency_id)));
    const { data: pds } = await ctx.supabase
      .from('project_dependencies')
      .select('id, name, version')
      .in('id', pdIds);
    const pdById = new Map<string, any>();
    for (const pd of pds ?? []) pdById.set(pd.id, pd);

    return {
      vulnerabilities: vulns.map((v: any) => {
        const pd = pdById.get(v.project_dependency_id);
        return {
          id: v.id,
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
          dependency: pd ? { id: pd.id, name: pd.name, version: pd.version } : null,
        };
      }),
      totalReturned: vulns.length,
    };
  },
};

const getSecurityPosture: AegisToolEntry<Record<string, never>> = {
  name: 'get_security_posture',
  description:
    'Org-wide aggregate. Returns project count, vulnerability totals by severity (incl. reachable and KEV), average health score, and a count of projects in violation.',
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
  cveId?: string;
  osvId?: string;
  vulnerabilityId?: string;
}> = {
  name: 'get_vulnerability_detail',
  description:
    'Full detail for a vulnerability. Lookup by CVE id (e.g. CVE-2024-1234), OSV id (e.g. GHSA-xxxx), or project_dependency_vulnerabilities.id. Returns severity, CVSS, EPSS, KEV, published date, affected dependencies across the org, and fixed versions.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      cveId: { type: 'string', description: 'CVE id like CVE-2024-1234.' },
      osvId: { type: 'string', description: 'OSV id like GHSA-xxxx-xxxx.' },
      vulnerabilityId: {
        type: 'string',
        format: 'uuid',
        description: 'A project_dependency_vulnerabilities.id.',
      },
    },
    additionalProperties: false,
  }),
  execute: async ({ cveId, osvId, vulnerabilityId }, ctx) => {
    if (!cveId && !osvId && !vulnerabilityId) {
      return { error: 'Provide cveId, osvId, or vulnerabilityId.' };
    }

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
        'id, project_id, project_dependency_id, osv_id, severity, summary, aliases, fixed_versions, is_reachable, reachability_level, epss_score, cvss_score, cisa_kev, depscore, published_at',
      )
      .in('project_id', orgProjectIds);

    if (vulnerabilityId) query = query.eq('id', vulnerabilityId);
    else if (osvId) query = query.eq('osv_id', osvId);
    else if (cveId) query = (query as any).contains('aliases', [cveId]);

    const { data: rows, error } = await query.limit(50);
    if (error) return { error: error.message };
    if (!rows || rows.length === 0) return { error: 'Vulnerability not found in this organization' };

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
          vulnerabilityId: r.id,
          projectId: r.project_id,
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

const getReachabilityFlows: AegisToolEntry<{ vulnerabilityId: string }> = {
  name: 'get_reachability_flows',
  description:
    'Return reachability flow paths (entry point → sink) for a vulnerability. Input is a project_dependency_vulnerabilities.id. Each flow has an entry point file/method/line, a sink file/method/line, and a chain of nodes.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      vulnerabilityId: {
        type: 'string',
        format: 'uuid',
        description: 'project_dependency_vulnerabilities.id (from get_project_vulnerabilities).',
      },
    },
    required: ['vulnerabilityId'],
    additionalProperties: false,
  }),
  execute: async ({ vulnerabilityId }, ctx) => {
    const { data: vuln } = await ctx.supabase
      .from('project_dependency_vulnerabilities')
      .select('id, project_id, osv_id, reachability_level, reachability_details, project_dependency_id')
      .eq('id', vulnerabilityId)
      .single();
    if (!vuln) return { error: 'Vulnerability not found' };

    const { data: project } = await ctx.supabase
      .from('projects')
      .select('id, organization_id')
      .eq('id', vuln.project_id)
      .single();
    if (!project || project.organization_id !== ctx.orgId) {
      return { error: 'Project not in current organization' };
    }

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
      vulnerabilityId: vuln.id,
      osvId: vuln.osv_id,
      reachabilityLevel: vuln.reachability_level,
      reachabilityDetails: vuln.reachability_details ?? null,
      dependency: pd ? { name: pd.name, version: pd.version } : null,
      flows: packageMatch.map((f: any) => ({
        id: f.id,
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
