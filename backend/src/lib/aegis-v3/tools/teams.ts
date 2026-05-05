import { jsonSchema } from 'ai';
import type { AegisToolEntry } from '../tool-types';

const listTeams: AegisToolEntry<Record<string, never>> = {
  name: 'list_teams',
  description:
    'List every team in the organization: each row includes `id` (required for chat embeds), `name`, member_count, and project_count. In your follow-up message to the user, embed each team inline as `<team>UUID</team>` using those ids. Do not restate member_count or project_count in prose — the user can ask for those if they want a breakdown.',
  danger: 'safe',
  inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
  execute: async (_input, ctx) => {
    const { data: teamsRows, error: teamsError } = await ctx.supabase
      .from('teams')
      .select('id, name, description')
      .eq('organization_id', ctx.orgId)
      .order('created_at', { ascending: false });

    if (teamsError) return { error: teamsError.message };
    const teamsRowsSafe = teamsRows ?? [];
    if (teamsRowsSafe.length === 0) return { team_count: 0, teams: [] };

    const ids = teamsRowsSafe.map((t: { id: string }) => t.id);

    const { data: memberRows } = await ctx.supabase
      .from('team_members')
      .select('team_id')
      .in('team_id', ids);
    const { data: projectTeamRows } = await ctx.supabase
      .from('project_teams')
      .select('team_id')
      .in('team_id', ids);

    const memberCount = new Map<string, number>();
    const projectCount = new Map<string, number>();
    for (const id of ids) {
      memberCount.set(id, 0);
      projectCount.set(id, 0);
    }
    for (const r of memberRows ?? []) {
      const id = (r as { team_id: string }).team_id;
      memberCount.set(id, (memberCount.get(id) ?? 0) + 1);
    }
    for (const r of projectTeamRows ?? []) {
      const id = (r as { team_id: string }).team_id;
      projectCount.set(id, (projectCount.get(id) ?? 0) + 1);
    }

    const teams = teamsRowsSafe.map((t: any) => ({
      id: t.id,
      name: t.name,
      description: typeof t.description === 'string' ? t.description : null,
      member_count: memberCount.get(t.id) ?? 0,
      project_count: projectCount.get(t.id) ?? 0,
    }));

    return {
      team_count: teams.length,
      teams,
    };
  },
};

export const teamsTools: AegisToolEntry[] = [listTeams];
