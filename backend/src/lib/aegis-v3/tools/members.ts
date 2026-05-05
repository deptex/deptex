import { jsonSchema } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { resolveTeam } from './resolvers';
import type { AegisToolEntry } from '../tool-types';

interface MemberRow {
  user_id: string;
  name: string;
  email: string;
  avatar_url: string | null;
}

async function fetchUsersByIds(
  supabase: SupabaseClient,
  userIds: string[],
): Promise<Map<string, MemberRow>> {
  const out = new Map<string, MemberRow>();
  if (userIds.length === 0) return out;

  const { data: profiles } = await supabase
    .from('user_profiles')
    .select('user_id, full_name, avatar_url')
    .in('user_id', userIds);
  const profileById = new Map<string, { full_name: string | null; avatar_url: string | null }>();
  for (const p of profiles ?? []) {
    profileById.set(
      (p as { user_id: string }).user_id,
      {
        full_name: (p as { full_name: string | null }).full_name ?? null,
        avatar_url: (p as { avatar_url: string | null }).avatar_url ?? null,
      },
    );
  }

  await Promise.all(
    userIds.map(async (userId) => {
      try {
        const { data } = await supabase.auth.admin.getUserById(userId);
        const user = data?.user;
        const profile = profileById.get(userId);
        const fullName = profile?.full_name || (user?.user_metadata as any)?.full_name || null;
        const email = user?.email || '';
        const avatar =
          profile?.avatar_url ||
          (user?.user_metadata as any)?.picture ||
          (user?.user_metadata as any)?.avatar_url ||
          null;
        out.set(userId, {
          user_id: userId,
          name: fullName || (email ? email.split('@')[0] : userId),
          email,
          avatar_url: avatar,
        });
      } catch {
        out.set(userId, { user_id: userId, name: userId, email: '', avatar_url: null });
      }
    }),
  );
  return out;
}

const listOrganizationMembers: AegisToolEntry<Record<string, never>> = {
  name: 'list_organization_members',
  description:
    'List every member of the organization: each row includes `user_id` (required for chat embeds), `name`, `email`, `role` (the org role name), `role_display_name`, `role_color`, and `team_count`. In your follow-up message to the user, embed each member inline as `<member>USER_ID</member>` using those `user_id`s. Do not restate emails or team_count in prose — the user can ask for a breakdown.',
  danger: 'safe',
  inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
  execute: async (_input, ctx) => {
    const { data: members, error: membersError } = await ctx.supabase
      .from('organization_members')
      .select('user_id, role, created_at')
      .eq('organization_id', ctx.orgId)
      .order('created_at', { ascending: true });
    if (membersError) return { error: membersError.message };
    const memberRows = members ?? [];
    if (memberRows.length === 0) return { member_count: 0, members: [] };

    const userIds = memberRows.map((m: { user_id: string }) => m.user_id);

    const [{ data: orgRoles }, { data: teamMemberRows }, userMap] = await Promise.all([
      ctx.supabase
        .from('organization_roles')
        .select('name, display_name, color')
        .eq('organization_id', ctx.orgId),
      ctx.supabase.from('team_members').select('user_id, team_id').in('user_id', userIds),
      fetchUsersByIds(ctx.supabase, userIds),
    ]);

    const roleByName = new Map<string, { display_name: string | null; color: string | null }>();
    for (const r of orgRoles ?? []) {
      roleByName.set(
        (r as { name: string }).name,
        {
          display_name: (r as { display_name: string | null }).display_name ?? null,
          color: (r as { color: string | null }).color ?? null,
        },
      );
    }

    const teamCountByUser = new Map<string, number>();
    for (const tm of teamMemberRows ?? []) {
      const uid = (tm as { user_id: string }).user_id;
      teamCountByUser.set(uid, (teamCountByUser.get(uid) ?? 0) + 1);
    }

    const result = memberRows.map((m: { user_id: string; role: string }) => {
      const user = userMap.get(m.user_id);
      const role = roleByName.get(m.role);
      return {
        user_id: m.user_id,
        name: user?.name ?? m.user_id,
        email: user?.email ?? '',
        role: m.role,
        role_display_name: role?.display_name ?? null,
        role_color: role?.color ?? null,
        team_count: teamCountByUser.get(m.user_id) ?? 0,
      };
    });

    return { member_count: result.length, members: result };
  },
};

const listTeamMembers: AegisToolEntry<{ teamName: string }> = {
  name: 'list_team_members',
  description:
    'List members of a SPECIFIC team. Use this — NOT `list_organization_members` — whenever the user asks who is on a team ("who is on the X team?", "show me the Y team\'s members"). Pass `teamName` exactly as the user said it; the resolver fuzzy-matches. Each row includes `user_id` (required for chat embeds), `name`, `email`, `team_role` (the role on this team), `role_display_name`, `role_color`. Embed each member inline as `<member>USER_ID</member>`. The org-wide member list does NOT contain team membership — never infer team rosters from it.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      teamName: { type: 'string', minLength: 1, description: 'Team name as the user said it.' },
    },
    required: ['teamName'],
    additionalProperties: false,
  }),
  execute: async ({ teamName }, ctx) => {
    const team = await resolveTeam(teamName, ctx.orgId, ctx.supabase);
    if ('error' in team) return team;

    const { data: rows, error } = await ctx.supabase
      .from('team_members')
      .select('user_id, role_id, created_at')
      .eq('team_id', team.id)
      .order('created_at', { ascending: true });
    if (error) return { error: error.message };
    const teamMemberRows = rows ?? [];
    if (teamMemberRows.length === 0) return { team: team.name, member_count: 0, members: [] };

    const userIds = teamMemberRows.map((r: { user_id: string }) => r.user_id);
    const roleIds = Array.from(
      new Set(
        teamMemberRows
          .map((r: { role_id: string | null }) => r.role_id)
          .filter((id: string | null): id is string => Boolean(id)),
      ),
    );

    const [{ data: teamRoles }, userMap] = await Promise.all([
      roleIds.length
        ? ctx.supabase
            .from('team_roles')
            .select('id, name, display_name, color')
            .in('id', roleIds)
        : Promise.resolve({ data: [] as Array<{ id: string; name: string; display_name: string | null; color: string | null }> }),
      fetchUsersByIds(ctx.supabase, userIds),
    ]);

    const roleById = new Map<
      string,
      { name: string; display_name: string | null; color: string | null }
    >();
    for (const r of teamRoles ?? []) {
      roleById.set((r as { id: string }).id, {
        name: (r as { name: string }).name,
        display_name: (r as { display_name: string | null }).display_name ?? null,
        color: (r as { color: string | null }).color ?? null,
      });
    }

    const result = teamMemberRows.map(
      (m: { user_id: string; role_id: string | null }) => {
        const user = userMap.get(m.user_id);
        const role = m.role_id ? roleById.get(m.role_id) : undefined;
        return {
          user_id: m.user_id,
          name: user?.name ?? m.user_id,
          email: user?.email ?? '',
          team_role: role?.name ?? null,
          role_display_name: role?.display_name ?? null,
          role_color: role?.color ?? null,
        };
      },
    );

    return { team: team.name, member_count: result.length, members: result };
  },
};

export const membersTools: AegisToolEntry[] = [listOrganizationMembers, listTeamMembers];
