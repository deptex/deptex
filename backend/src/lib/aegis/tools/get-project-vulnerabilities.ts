import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function getProjectVulnerabilitiesTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'List vulnerabilities for a project. Each row includes OSV id, CVE aliases, severity, CVSS, EPSS, KEV flag, reachability level, depscore, the affected dependency@version, and fixed versions. Optional filters: severity and reachableOnly.',
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
    execute: async (input) => {
      const { projectId, severity, reachableOnly, limit } = input as {
        projectId: string;
        severity?: 'critical' | 'high' | 'medium' | 'low';
        reachableOnly?: boolean;
        limit?: number;
      };

      const { data: project } = await supabase
        .from('projects')
        .select('id, organization_id')
        .eq('id', projectId)
        .single();
      if (!project) return { error: 'Project not found' };
      if (project.organization_id !== ctx.organizationId) return { error: 'Project not in current organization' };

      let query = supabase
        .from('project_dependency_findings')
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
      const { data: pds } = await supabase
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
  });
}
