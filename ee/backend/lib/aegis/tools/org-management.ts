import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';

// 1. listTeams
registerAegisTool(
  'listTeams',
  {
    category: 'org_management',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'List all teams in the organization with project and member counts',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
    }),
    execute: async ({ organizationId }) => {
      const { data: teams, error: teamsError } = await supabase
        .from('teams')
        .select('id, name, description, created_at, updated_at')
        .eq('organization_id', organizationId)
        .order('name');

      if (teamsError) {
        return JSON.stringify({ error: teamsError.message });
      }

      const teamIds = (teams || []).map((t) => t.id);

      const [projectCountRes, memberCountRes] = await Promise.all([
        teamIds.length > 0
          ? supabase
              .from('project_teams')
              .select('team_id')
              .in('team_id', teamIds)
          : { data: [] as { team_id: string }[] },
        teamIds.length > 0
          ? supabase
              .from('team_members')
              .select('team_id')
              .in('team_id', teamIds)
          : { data: [] as { team_id: string }[] },
      ]);

      const projectCountByTeam = new Map<string, number>();
      const memberCountByTeam = new Map<string, number>();

      ;(projectCountRes.data || []).forEach((r) => {
        projectCountByTeam.set(r.team_id, (projectCountByTeam.get(r.team_id) || 0) + 1);
      });
      ;(memberCountRes.data || []).forEach((r) => {
        memberCountByTeam.set(r.team_id, (memberCountByTeam.get(r.team_id) || 0) + 1);
      });

      const result = (teams || []).map((t) => ({
        id: t.id,
        name: t.name,
        description: t.description,
        project_count: projectCountByTeam.get(t.id) || 0,
        member_count: memberCountByTeam.get(t.id) || 0,
        created_at: t.created_at,
      }));

      return JSON.stringify(result);
    },
  }),
);

// 2. createTeam
registerAegisTool(
  'createTeam',
  {
    category: 'org_management',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['manage_teams_and_projects'],
  },
  tool({
    description: 'Create a new team. Default owner and member roles are auto-created. Pass createdBy to add the creator as team owner.',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      name: z.string().min(1),
      description: z.string().optional(),
      createdBy: z.string().uuid().optional(),
    }),
    execute: async ({ organizationId, name, description, createdBy }) => {
      const { data: team, error: insertError } = await supabase
        .from('teams')
        .insert({
          organization_id: organizationId,
          name,
          description: description || null,
        })
        .select('id, name, description, created_at')
        .single();

      if (insertError) {
        return JSON.stringify({ error: insertError.message });
      }

      if (createdBy) {
        const { data: ownerRole } = await supabase
          .from('team_roles')
          .select('id')
          .eq('team_id', team.id)
          .eq('name', 'owner')
          .single();

        if (ownerRole) {
          await supabase
            .from('team_members')
            .upsert(
              { team_id: team.id, user_id: createdBy, role_id: ownerRole.id },
              { onConflict: 'team_id,user_id' },
            );
        }
      }

      return JSON.stringify(team);
    },
  }),
);

// 3. updateTeam
registerAegisTool(
  'updateTeam',
  {
    category: 'org_management',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['manage_teams_and_projects'],
  },
  tool({
    description: 'Update a team name and/or description',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      teamId: z.string().uuid(),
      name: z.string().min(1).optional(),
      description: z.string().optional(),
    }),
    execute: async ({ organizationId, teamId, name, description }) => {
      const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
      if (name !== undefined) updates.name = name;
      if (description !== undefined) updates.description = description;

      const { data, error } = await supabase
        .from('teams')
        .update(updates)
        .eq('id', teamId)
        .eq('organization_id', organizationId)
        .select('id, name, description, updated_at')
        .single();

      if (error) {
        return JSON.stringify({ error: error.message });
      }
      return JSON.stringify(data);
    },
  }),
);

// 4. deleteTeam
registerAegisTool(
  'deleteTeam',
  {
    category: 'org_management',
    permissionLevel: 'dangerous',
    requiredRbacPermissions: ['manage_teams_and_projects'],
  },
  tool({
    description: 'Delete a team by ID. Projects with this team as primary team are moved to org-level (team_id set to null).',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      teamId: z.string().uuid(),
    }),
    execute: async ({ organizationId, teamId }) => {
      const { data: team } = await supabase
        .from('teams')
        .select('id, name')
        .eq('id', teamId)
        .eq('organization_id', organizationId)
        .single();

      if (!team) {
        return JSON.stringify({ error: 'Team not found or does not belong to this organization' });
      }

      await supabase
        .from('projects')
        .update({ team_id: null })
        .eq('team_id', teamId)
        .eq('organization_id', organizationId);

      const { error } = await supabase.from('teams').delete().eq('id', teamId).eq('organization_id', organizationId);

      if (error) {
        return JSON.stringify({ error: error.message });
      }
      return JSON.stringify({ deleted: true, team_id: teamId, team_name: team.name });
    },
  }),
);

// 5. listMembers
registerAegisTool(
  'listMembers',
  {
    category: 'org_management',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'List all organization members with role info and user profile (name, avatar)',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
    }),
    execute: async ({ organizationId }) => {
      const { data: members, error: membersError } = await supabase
        .from('organization_members')
        .select('id, user_id, role, created_at')
        .eq('organization_id', organizationId);

      if (membersError) {
        return JSON.stringify({ error: membersError.message });
      }

      const userIds = [...new Set((members || []).map((m) => m.user_id))];
      const profileMap = new Map<string, { full_name: string | null; avatar_url: string | null }>();

      if (userIds.length > 0) {
        const { data: profiles } = await supabase
          .from('user_profiles')
          .select('user_id, full_name, avatar_url')
          .in('user_id', userIds);
        (profiles || []).forEach((p) => profileMap.set(p.user_id, { full_name: p.full_name, avatar_url: p.avatar_url }));
      }

      const { data: roles } = await supabase
        .from('organization_roles')
        .select('id, name, display_name, display_order')
        .eq('organization_id', organizationId);

      const roleMap = new Map((roles || []).map((r) => [r.name, r]));

      const result = (members || []).map((m) => {
        const profile = profileMap.get(m.user_id);
        const roleInfo = roleMap.get(m.role);
        return {
          id: m.id,
          user_id: m.user_id,
          role: m.role,
          role_display_name: roleInfo?.display_name ?? m.role,
          full_name: profile?.full_name ?? null,
          avatar_url: profile?.avatar_url ?? null,
          created_at: m.created_at,
        };
      });

      return JSON.stringify(result);
    },
  }),
);

// 6. inviteMember
registerAegisTool(
  'inviteMember',
  {
    category: 'org_management',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['add_members'],
  },
  tool({
    description: 'Create an invitation for a new member to join the organization. Use invitedBy as the current acting user ID.',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      email: z.string().email(),
      role: z.enum(['owner', 'admin', 'member']).default('member'),
      invitedBy: z.string().uuid(),
    }),
    execute: async ({ organizationId, email, role, invitedBy }) => {
      const { data: existing } = await supabase
        .from('organization_invitations')
        .select('id, status')
        .eq('organization_id', organizationId)
        .eq('email', email.toLowerCase())
        .eq('status', 'pending')
        .single();

      if (existing) {
        return JSON.stringify({ error: 'A pending invitation already exists for this email' });
      }

      const { data: invitation, error } = await supabase
        .from('organization_invitations')
        .insert({
          organization_id: organizationId,
          email: email.toLowerCase(),
          role,
          invited_by: invitedBy,
          status: 'pending',
        })
        .select('id, email, role, status, created_at, expires_at')
        .single();

      if (error) {
        return JSON.stringify({ error: error.message });
      }
      return JSON.stringify(invitation);
    },
  }),
);

// 7. removeMember
registerAegisTool(
  'removeMember',
  {
    category: 'org_management',
    permissionLevel: 'dangerous',
    requiredRbacPermissions: ['kick_members'],
  },
  tool({
    description: 'Remove a member from the organization',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      userId: z.string().uuid(),
    }),
    execute: async ({ organizationId, userId }) => {
      const { data: membership } = await supabase
        .from('organization_members')
        .select('id, role')
        .eq('organization_id', organizationId)
        .eq('user_id', userId)
        .single();

      if (!membership) {
        return JSON.stringify({ error: 'Member not found in this organization' });
      }

      const { error } = await supabase.from('organization_members').delete().eq('id', membership.id);

      if (error) {
        return JSON.stringify({ error: error.message });
      }
      return JSON.stringify({ removed: true, user_id: userId });
    },
  }),
);

// 8. updateMemberRole
registerAegisTool(
  'updateMemberRole',
  {
    category: 'org_management',
    permissionLevel: 'moderate',
    requiredRbacPermissions: ['edit_roles'],
  },
  tool({
    description: 'Update a member\'s organization role (owner, admin, or member)',
    inputSchema: z.object({
      organizationId: z.string().uuid(),
      userId: z.string().uuid(),
      role: z.enum(['owner', 'admin', 'member']),
    }),
    execute: async ({ organizationId, userId, role }) => {
      const { data, error } = await supabase
        .from('organization_members')
        .update({ role })
        .eq('organization_id', organizationId)
        .eq('user_id', userId)
        .select('id, user_id, role')
        .single();

      if (error) {
        return JSON.stringify({ error: error.message });
      }
      return JSON.stringify(data);
    },
  }),
);
