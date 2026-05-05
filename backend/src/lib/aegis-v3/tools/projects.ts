import { jsonSchema } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { getActiveExtractionId, NO_ACTIVE_RUN } from '../../active-extraction';
import { resolveProject, resolveTeam } from './resolvers';
import type { AegisToolEntry } from '../tool-types';

const listProjects: AegisToolEntry<{ teamName?: string }> = {
  name: 'list_projects',
  description:
    'List every project in the organization: each row includes `id` (required for chat embeds), `name`, health_score, status, framework, and repo info. In your follow-up message to the user, embed each project inline as `<project>UUID</project>` using those ids. Pass `teamName` ONLY when the user explicitly named a team — otherwise leave unset to list all projects.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      teamName: {
        type: 'string',
        description:
          'Filter to projects on a specific team. Pass the team name as the user said it. Leave unset to list every project in the org.',
      },
    },
    additionalProperties: false,
  }),
  execute: async ({ teamName }, ctx) => {
    let teamProjectIds: string[] | null = null;
    let resolvedTeamName: string | null = null;
    if (teamName) {
      const team = await resolveTeam(teamName, ctx.orgId, ctx.supabase);
      if ('error' in team) return team;
      resolvedTeamName = team.name;
      const { data: pt } = await ctx.supabase
        .from('project_teams')
        .select('project_id')
        .eq('team_id', team.id);
      teamProjectIds = (pt ?? []).map((r: { project_id: string }) => r.project_id);
      if (teamProjectIds.length === 0) {
        return { team: team.name, projects: [] };
      }
    }

    let query = ctx.supabase
      .from('projects')
      .select(
        `id, name, health_score, status_id, framework,
         organization_statuses(name, is_passing),
         project_repositories(status, repo_full_name, provider)`,
      )
      .eq('organization_id', ctx.orgId);

    if (teamProjectIds) query = query.in('id', teamProjectIds);

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return { error: error.message };

    const projects = (data ?? []).map((p: any) => ({
      id: p.id,
      name: p.name,
      health_score: p.health_score,
      status: p.organization_statuses?.name ?? null,
      status_is_passing:
        typeof p.organization_statuses?.is_passing === 'boolean'
          ? p.organization_statuses.is_passing
          : null,
      framework: p.framework,
      repo_status: p.project_repositories?.[0]?.status ?? null,
      repo_full_name: p.project_repositories?.[0]?.repo_full_name ?? null,
      provider: (p.project_repositories?.[0]?.provider as string | undefined) ?? null,
    }));
    return resolvedTeamName ? { team: resolvedTeamName, projects } : { projects };
  },
};

const getProjectSummary: AegisToolEntry<{ projectName: string }> = {
  name: 'get_project_summary',
  description:
    'Detailed project info: dependency count, vulnerability count, semgrep findings, framework, status, repo. Pass the project name exactly as the user said it (e.g. "deptex-test-npm").',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
    },
    required: ['projectName'],
    additionalProperties: false,
  }),
  execute: async ({ projectName }, ctx) => {
    const resolved = await resolveProject(projectName, ctx.orgId, ctx.supabase);
    if ('error' in resolved) return resolved;

    const { data: project, error: projError } = await ctx.supabase
      .from('projects')
      .select(
        `id, name, organization_id, health_score, status_id, framework,
         organization_statuses(name),
         project_repositories(status, repo_full_name, default_branch, ecosystem)`,
      )
      .eq('id', resolved.id)
      .single();

    if (projError || !project) {
      return { error: projError?.message ?? 'Project not found' };
    }

    const activeRunId =
      (await getActiveExtractionId(ctx.supabase as SupabaseClient, resolved.id)) ?? NO_ACTIVE_RUN;
    const [{ count: depCount }, { count: vulnCount }, { count: semgrepCount }] = await Promise.all([
      ctx.supabase
        .from('project_dependencies')
        .select('id', { count: 'exact', head: true })
        .eq('project_id', resolved.id)
        .is('removed_at', null),
      ctx.supabase
        .from('project_dependency_vulnerabilities')
        .select('id', { count: 'exact', head: true })
        .eq('project_id', resolved.id)
        .eq('extraction_run_id', activeRunId)
        .eq('suppressed', false),
      ctx.supabase
        .from('project_semgrep_findings')
        .select('id', { count: 'exact', head: true })
        .eq('project_id', resolved.id)
        .eq('extraction_run_id', activeRunId),
    ]);

    return {
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
  projectName: string;
  directOnly?: boolean;
  limit?: number;
}> = {
  name: 'list_project_dependencies',
  description:
    'Dependencies for a project with version, direct/transitive flag, outdated status, and reputation fields (openssf score, is_malicious, latest_version). Pass the project name exactly as the user said it.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
      directOnly: { type: 'boolean', description: 'When true, only return direct dependencies.' },
      limit: { type: 'integer', minimum: 1, maximum: 500, description: 'Max rows to return (default 100).' },
    },
    required: ['projectName'],
    additionalProperties: false,
  }),
  execute: async ({ projectName, directOnly, limit }, ctx) => {
    const resolved = await resolveProject(projectName, ctx.orgId, ctx.supabase);
    if ('error' in resolved) return resolved;

    let query = ctx.supabase
      .from('project_dependencies')
      .select('name, version, license, is_direct, source, is_outdated, versions_behind')
      .eq('project_id', resolved.id)
      .order('is_direct', { ascending: false })
      .order('name', { ascending: true })
      .limit(limit ?? 100);
    if (directOnly) query = query.eq('is_direct', true);

    const { data: deps, error } = await query;
    if (error) return { error: error.message };
    if (!deps || deps.length === 0) {
      return { project: resolved.name, dependencies: [], totalReturned: 0 };
    }

    const names = Array.from(new Set(deps.map((d: any) => d.name)));
    const { data: pkgRows } = await ctx.supabase
      .from('dependencies')
      .select('name, openssf_score, score, is_malicious, latest_version, weekly_downloads')
      .in('name', names);
    const pkgByName = new Map<string, any>();
    for (const p of pkgRows ?? []) pkgByName.set(p.name, p);

    return {
      project: resolved.name,
      dependencies: deps.map((d: any) => {
        const pkg = pkgByName.get(d.name);
        return {
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
