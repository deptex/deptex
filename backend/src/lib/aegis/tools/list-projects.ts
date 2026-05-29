import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function listProjectsTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      "List all projects in the current organization with health score, importance (depscore multiplier), ecosystem, and dependency/vulnerability counts.",
    inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
    execute: async () => {
      const { data: projects, error } = await supabase
        .from('projects')
        .select(
          'id, name, health_score, importance, status_id, updated_at',
        )
        .eq('organization_id', ctx.organizationId)
        .order('name', { ascending: true });

      if (error) return { error: error.message };
      if (!projects || projects.length === 0) return { projects: [] };

      const projectIds = projects.map((p: any) => p.id);

      const [repoRes, depCountRes, vulnCountRes, statusesRes] = await Promise.all([
        supabase
          .from('project_repositories')
          .select('project_id, repo_full_name, ecosystem, default_branch, last_extracted_at, status')
          .in('project_id', projectIds),
        supabase
          .from('project_dependencies')
          .select('project_id', { count: 'exact' })
          .in('project_id', projectIds),
        supabase
          .from('project_dependency_vulnerabilities')
          .select('project_id, severity')
          .in('project_id', projectIds),
        supabase
          .from('organization_statuses')
          .select('id, name, is_passing')
          .eq('organization_id', ctx.organizationId),
      ]);

      const repoByProject = new Map<string, any>();
      for (const r of repoRes.data ?? []) repoByProject.set(r.project_id, r);

      const depCounts = new Map<string, number>();
      for (const row of depCountRes.data ?? []) {
        depCounts.set(row.project_id, (depCounts.get(row.project_id) ?? 0) + 1);
      }

      const vulnCounts = new Map<string, Record<string, number>>();
      for (const row of vulnCountRes.data ?? []) {
        const existing = vulnCounts.get(row.project_id) ?? { critical: 0, high: 0, medium: 0, low: 0 };
        const sev = (row.severity ?? 'low').toLowerCase();
        if (sev in existing) existing[sev]++;
        vulnCounts.set(row.project_id, existing);
      }

      const statusById = new Map<string, { name: string; isPassing: boolean }>();
      for (const s of statusesRes.data ?? []) statusById.set(s.id, { name: s.name, isPassing: !!s.is_passing });

      const result = projects.map((p: any) => {
        const repo = repoByProject.get(p.id);
        const vulns = vulnCounts.get(p.id) ?? { critical: 0, high: 0, medium: 0, low: 0 };
        return {
          id: p.id,
          name: p.name,
          healthScore: p.health_score,
          healthGrade: healthGrade(p.health_score),
          importance: typeof p.importance === 'number' ? p.importance : 1.0,
          status: p.status_id ? statusById.get(p.status_id)?.name ?? null : null,
          repoFullName: repo?.repo_full_name ?? null,
          ecosystem: repo?.ecosystem ?? null,
          defaultBranch: repo?.default_branch ?? null,
          lastExtractedAt: repo?.last_extracted_at ?? null,
          extractionStatus: repo?.status ?? null,
          dependencyCount: depCounts.get(p.id) ?? 0,
          vulnCounts: vulns,
        };
      });

      return { projects: result };
    },
  });
}

function healthGrade(score: number | null | undefined): string | null {
  if (score == null) return null;
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
