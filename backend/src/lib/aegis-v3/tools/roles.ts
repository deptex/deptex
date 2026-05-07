import { jsonSchema } from 'ai';
import { resolveTeam } from './resolvers';
import type { AegisToolEntry } from '../tool-types';

function summarizePermissions(raw: unknown): {
  granted: string[];
  denied: string[];
} {
  const granted: string[] = [];
  const denied: string[] = [];
  if (raw && typeof raw === 'object') {
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (value === true) granted.push(key);
      else if (value === false) denied.push(key);
    }
  }
  granted.sort();
  denied.sort();
  return { granted, denied };
}

const listOrganizationRoles: AegisToolEntry<Record<string, never>> = {
  name: 'list_organization_roles',
  description:
    'List every organization role and the permissions each one grants. Each row includes `name`, `display_name`, `color`, `is_default`, `member_count`, and `permissions` split into `granted` (true) and `denied` (false) keys. Use this when the user asks who can do what at the org level. When narrating, lead with the role name and only list `granted` permissions; mention `denied` only if the user explicitly asks.',
  danger: 'safe',
  inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
  execute: async (_input, ctx) => {
    const [{ data: roles, error: rolesError }, { data: members }] = await Promise.all([
      ctx.supabase
        .from('organization_roles')
        .select('name, display_name, color, is_default, display_order, permissions')
        .eq('organization_id', ctx.orgId)
        .order('display_order', { ascending: true }),
      ctx.supabase
        .from('organization_members')
        .select('role')
        .eq('organization_id', ctx.orgId),
    ]);
    if (rolesError) return { error: rolesError.message };
    const roleRows = roles ?? [];
    if (roleRows.length === 0) return { role_count: 0, roles: [] };

    const memberCountByRole = new Map<string, number>();
    for (const m of members ?? []) {
      const r = (m as { role: string }).role;
      memberCountByRole.set(r, (memberCountByRole.get(r) ?? 0) + 1);
    }

    const out = roleRows.map((r: any) => {
      const perms = summarizePermissions(r.permissions);
      return {
        name: r.name as string,
        display_name: (r.display_name as string | null) ?? null,
        color: (r.color as string | null) ?? null,
        is_default: Boolean(r.is_default),
        member_count: memberCountByRole.get(r.name as string) ?? 0,
        permissions: perms,
      };
    });

    return { role_count: out.length, roles: out };
  },
};

const listTeamRoles: AegisToolEntry<{ teamName: string }> = {
  name: 'list_team_roles',
  description:
    'List the roles configured on a team and the permissions each one grants. Each row includes `name`, `display_name`, `color`, `is_default`, `member_count`, and `permissions` (`granted` / `denied`). Pass `teamName` exactly as the user said it. Lead with the role name; only list `granted` permissions unless the user asks otherwise.',
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

    const [{ data: roles, error: rolesError }, { data: members }] = await Promise.all([
      ctx.supabase
        .from('team_roles')
        .select('id, name, display_name, color, is_default, display_order, permissions')
        .eq('team_id', team.id)
        .order('display_order', { ascending: true }),
      ctx.supabase.from('team_members').select('role_id').eq('team_id', team.id),
    ]);
    if (rolesError) return { error: rolesError.message };
    const roleRows = roles ?? [];
    if (roleRows.length === 0) return { team: team.name, role_count: 0, roles: [] };

    const memberCountByRoleId = new Map<string, number>();
    for (const m of members ?? []) {
      const rid = (m as { role_id: string | null }).role_id;
      if (rid) memberCountByRoleId.set(rid, (memberCountByRoleId.get(rid) ?? 0) + 1);
    }

    const out = roleRows.map((r: any) => {
      const perms = summarizePermissions(r.permissions);
      return {
        name: r.name as string,
        display_name: (r.display_name as string | null) ?? null,
        color: (r.color as string | null) ?? null,
        is_default: Boolean(r.is_default),
        member_count: memberCountByRoleId.get(r.id as string) ?? 0,
        permissions: perms,
      };
    });

    return { team: team.name, role_count: out.length, roles: out };
  },
};

export const rolesTools: AegisToolEntry[] = [listOrganizationRoles, listTeamRoles];
