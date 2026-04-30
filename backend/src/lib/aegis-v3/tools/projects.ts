import { jsonSchema } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { getActiveExtractionId, NO_ACTIVE_RUN } from '../../active-extraction';
import type { AegisToolEntry } from '../tool-types';

const listProjects: AegisToolEntry<{ teamId?: string }> = {
  name: 'list_projects',
  description:
    'List all projects in the organization with basic stats (health_score, status, framework). Optionally filter by team.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      teamId: { type: 'string', format: 'uuid' },
    },
    additionalProperties: false,
  }),
  execute: async ({ teamId }, ctx) => {
    let query = ctx.supabase
      .from('projects')
      .select(
        `id, name, health_score, status_id, framework,
         organization_statuses(name),
         project_repositories(status, repo_full_name)`,
      )
      .eq('organization_id', ctx.orgId);

    if (teamId) {
      const { data: pt } = await ctx.supabase
        .from('project_teams')
        .select('project_id')
        .eq('team_id', teamId);
      const projectIds = (pt ?? []).map((r: { project_id: string }) => r.project_id);
      if (projectIds.length === 0) return { projects: [] };
      query = query.in('id', projectIds);
    }

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return { error: error.message };

    const projects = (data ?? []).map((p: any) => ({
      id: p.id,
      name: p.name,
      health_score: p.health_score,
      status: p.organization_statuses?.name ?? null,
      framework: p.framework,
      repo_status: p.project_repositories?.[0]?.status ?? null,
      repo_full_name: p.project_repositories?.[0]?.repo_full_name ?? null,
    }));
    return { projects };
  },
};

const getProjectSummary: AegisToolEntry<{ projectId: string }> = {
  name: 'get_project_summary',
  description:
    'Get detailed project info including dep count, vuln count, semgrep findings.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectId: { type: 'string', format: 'uuid' },
    },
    required: ['projectId'],
    additionalProperties: false,
  }),
  execute: async ({ projectId }, ctx) => {
    const { data: project, error: projError } = await ctx.supabase
      .from('projects')
      .select(
        `id, name, organization_id, health_score, status_id, framework,
         organization_statuses(name),
         project_repositories(status, repo_full_name, default_branch, ecosystem)`,
      )
      .eq('id', projectId)
      .single();

    if (projError || !project) {
      return { error: projError?.message ?? 'Project not found' };
    }
    if (project.organization_id !== ctx.orgId) {
      return { error: 'Project not in current organization' };
    }

    const activeRunId =
      (await getActiveExtractionId(ctx.supabase as SupabaseClient, projectId)) ?? NO_ACTIVE_RUN;
    const [{ count: depCount }, { count: vulnCount }, { count: semgrepCount }] = await Promise.all([
      ctx.supabase
        .from('project_dependencies')
        .select('id', { count: 'exact', head: true })
        .eq('project_id', projectId)
        .is('removed_at', null),
      ctx.supabase
        .from('project_dependency_vulnerabilities')
        .select('id', { count: 'exact', head: true })
        .eq('project_id', projectId)
        .eq('extraction_run_id', activeRunId)
        .eq('suppressed', false),
      ctx.supabase
        .from('project_semgrep_findings')
        .select('id', { count: 'exact', head: true })
        .eq('project_id', projectId)
        .eq('extraction_run_id', activeRunId),
    ]);

    return {
      id: project.id,
      name: project.name,
      health_score: project.health_score,
      status: (project as any).organization_statuses?.name ?? null,
      framework: project.framework,
      repository: (project as any).project_repositories?.[0]
        ? {
            status: (project as any).project_repositories[0].status,
            repo_full_name: (project as any).project_repositories[0].repo_full_name,
            default_branch: (project as any).project_repositories[0].default_branch,
            ecosystem: (project as any).project_repositories[0].ecosystem,
          }
        : null,
      counts: {
        dependencies: depCount ?? 0,
        vulnerabilities: vulnCount ?? 0,
        semgrep_findings: semgrepCount ?? 0,
      },
    };
  },
};

const listProjectDependencies: AegisToolEntry<{
  projectId: string;
  directOnly?: boolean;
  limit?: number;
}> = {
  name: 'list_project_dependencies',
  description:
    'List dependencies for a project with version, direct/transitive flag, outdated status, and reputation fields (openssf score, is_malicious, latest_version).',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectId: { type: 'string', format: 'uuid' },
      directOnly: { type: 'boolean', description: 'When true, only return direct dependencies.' },
      limit: { type: 'integer', minimum: 1, maximum: 500, description: 'Max rows to return (default 100).' },
    },
    required: ['projectId'],
    additionalProperties: false,
  }),
  execute: async ({ projectId, directOnly, limit }, ctx) => {
    const { data: project } = await ctx.supabase
      .from('projects')
      .select('id, organization_id')
      .eq('id', projectId)
      .single();
    if (!project) return { error: 'Project not found' };
    if (project.organization_id !== ctx.orgId) return { error: 'Project not in current organization' };

    let query = ctx.supabase
      .from('project_dependencies')
      .select('id, name, version, license, is_direct, source, is_outdated, versions_behind')
      .eq('project_id', projectId)
      .order('is_direct', { ascending: false })
      .order('name', { ascending: true })
      .limit(limit ?? 100);
    if (directOnly) query = query.eq('is_direct', true);

    const { data: deps, error } = await query;
    if (error) return { error: error.message };
    if (!deps || deps.length === 0) return { dependencies: [], totalReturned: 0 };

    const names = Array.from(new Set(deps.map((d: any) => d.name)));
    const { data: pkgRows } = await ctx.supabase
      .from('dependencies')
      .select('name, openssf_score, score, is_malicious, latest_version, weekly_downloads')
      .in('name', names);
    const pkgByName = new Map<string, any>();
    for (const p of pkgRows ?? []) pkgByName.set(p.name, p);

    return {
      dependencies: deps.map((d: any) => {
        const pkg = pkgByName.get(d.name);
        return {
          id: d.id,
          name: d.name,
          version: d.version,
          license: d.license,
          isDirect: d.is_direct,
          source: d.source,
          isOutdated: d.is_outdated,
          versionsBehind: d.versions_behind,
          latestVersion: pkg?.latest_version ?? null,
          openssfScore: pkg?.openssf_score ?? null,
          reputationScore: pkg?.score ?? null,
          isMalicious: pkg?.is_malicious ?? false,
          weeklyDownloads: pkg?.weekly_downloads ?? null,
        };
      }),
      totalReturned: deps.length,
    };
  },
};

export const projectsTools: AegisToolEntry[] = [
  listProjects,
  getProjectSummary,
  listProjectDependencies,
];
