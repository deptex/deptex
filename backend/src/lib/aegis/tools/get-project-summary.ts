import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function getProjectSummaryTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'Get summary for a single project: metadata, asset tier, current status, dependency counts (direct vs transitive), vulnerability counts by severity, semgrep and secret finding counts.',
    inputSchema: jsonSchema({
      type: 'object',
      properties: {
        projectId: { type: 'string', format: 'uuid', description: 'The project id (UUID).' },
      },
      required: ['projectId'],
      additionalProperties: false,
    }),
    execute: async (input) => {
      const { projectId } = input as { projectId: string };

      const { data: project, error } = await supabase
        .from('projects')
        .select('id, name, organization_id, health_score, asset_tier, asset_tier_id, status_id, status_violations, updated_at')
        .eq('id', projectId)
        .single();

      if (error || !project) return { error: 'Project not found' };
      if (project.organization_id !== ctx.organizationId) {
        return { error: 'Project not in current organization' };
      }

      const [repoRes, directDepRes, totalDepRes, vulnsRes, semgrepRes, secretsRes, tierRes, statusRes] = await Promise.all([
        supabase
          .from('project_repositories')
          .select('repo_full_name, ecosystem, default_branch, last_extracted_at, status')
          .eq('project_id', projectId)
          .single(),
        supabase
          .from('project_dependencies')
          .select('id', { count: 'exact', head: true })
          .eq('project_id', projectId)
          .eq('is_direct', true),
        supabase
          .from('project_dependencies')
          .select('id', { count: 'exact', head: true })
          .eq('project_id', projectId),
        supabase
          .from('project_dependency_vulnerabilities')
          .select('severity, is_reachable, cisa_kev')
          .eq('project_id', projectId),
        supabase
          .from('project_semgrep_findings')
          .select('id', { count: 'exact', head: true })
          .eq('project_id', projectId),
        supabase
          .from('project_secret_findings')
          .select('id', { count: 'exact', head: true })
          .eq('project_id', projectId)
          .eq('is_current', true),
        project.asset_tier_id
          ? supabase.from('organization_asset_tiers').select('name').eq('id', project.asset_tier_id).single()
          : Promise.resolve({ data: null, error: null } as any),
        project.status_id
          ? supabase.from('organization_statuses').select('name, is_passing').eq('id', project.status_id).single()
          : Promise.resolve({ data: null, error: null } as any),
      ]);

      const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0, reachable: 0, kev: 0 };
      for (const v of vulnsRes.data ?? []) {
        const sev = (v.severity ?? 'low').toLowerCase();
        if (sev in vulnCounts) (vulnCounts as any)[sev]++;
        if (v.is_reachable) vulnCounts.reachable++;
        if (v.cisa_kev) vulnCounts.kev++;
      }

      const totalDeps = totalDepRes.count ?? 0;
      const directDeps = directDepRes.count ?? 0;
      return {
        id: project.id,
        name: project.name,
        healthScore: project.health_score,
        assetTier: tierRes.data?.name ?? project.asset_tier,
        status: statusRes.data?.name ?? null,
        statusPassing: statusRes.data?.is_passing ?? null,
        statusViolations: project.status_violations ?? [],
        repoFullName: repoRes.data?.repo_full_name ?? null,
        ecosystem: repoRes.data?.ecosystem ?? null,
        defaultBranch: repoRes.data?.default_branch ?? null,
        lastExtractedAt: repoRes.data?.last_extracted_at ?? null,
        extractionStatus: repoRes.data?.status ?? null,
        dependencyCount: { direct: directDeps, transitive: Math.max(0, totalDeps - directDeps), total: totalDeps },
        vulnCounts,
        semgrepFindingCount: semgrepRes.count ?? 0,
        secretFindingCount: secretsRes.count ?? 0,
      };
    },
  });
}
