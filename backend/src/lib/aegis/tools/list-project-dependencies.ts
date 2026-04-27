import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function listProjectDependenciesTool(ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'List dependencies for a project with version, direct/transitive flag, outdated status, and reputation fields (openssf score, is_malicious, latest_version).',
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
    execute: async (input) => {
      const { projectId, directOnly, limit } = input as {
        projectId: string;
        directOnly?: boolean;
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
      const { data: pkgRows } = await supabase
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
  });
}
