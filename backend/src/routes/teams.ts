import express from 'express';
import { supabase } from '../lib/supabase';
import { AuthRequest } from '../middleware/auth';
import { createActivity } from '../lib/activities';

const router = express.Router();

// Helper function to check if user has access to a team
// Access is granted if user is a team member OR has org-level permissions
async function checkTeamAccess(userId: string, organizationId: string, teamId: string): Promise<{
  hasAccess: boolean;
  orgMembership: { role: string } | null;
  teamMembership: { role_id: string | null } | null;
  orgRole: { permissions: any; display_order: number } | null;
  error?: { status: number; message: string };
}> {
  // Check if user is a member of the organization
  const { data: orgMembership, error: orgMembershipError } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (orgMembershipError || !orgMembership) {
    return {
      hasAccess: false,
      orgMembership: null,
      teamMembership: null,
      orgRole: null,
      error: { status: 404, message: 'Organization not found or access denied' }
    };
  }

  // Get user's team membership
  const { data: teamMembership } = await supabase
    .from('team_members')
    .select('role_id')
    .eq('team_id', teamId)
    .eq('user_id', userId)
    .single();

  // Get user's org role permissions
  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions, display_order')
    .eq('organization_id', organizationId)
    .eq('name', orgMembership.role)
    .single();

  // Check if user has access:
  // 1. Is a team member, OR
  // 2. Is org owner/admin, OR
  // 3. Has view_all_teams_and_projects or manage_teams_and_projects permission
  const isTeamMember = !!teamMembership;
  const isOrgAdminOrOwner = orgMembership.role === 'owner' || orgMembership.role === 'admin';
  const hasOrgPermission = 
    orgRole?.permissions?.view_all_teams_and_projects === true ||
    orgRole?.permissions?.manage_teams_and_projects === true;

  const hasAccess = isTeamMember || isOrgAdminOrOwner || hasOrgPermission;

  if (!hasAccess) {
    return {
      hasAccess: false,
      orgMembership,
      teamMembership,
      orgRole,
      error: { status: 403, message: 'You do not have access to this team' }
    };
  }

  return {
    hasAccess: true,
    orgMembership,
    teamMembership,
    orgRole
  };
}

// GET /api/organizations/:id/teams - Get all teams for an organization
router.get('/:id/teams', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Check if user is a member
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Get user's organization role permissions
    const { data: orgRole } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    const canViewAllTeams = membership.role === 'owner' || orgRole?.permissions?.manage_teams_and_projects === true;

    // Get teams - either all or just ones user is a member of
    let teams;
    if (canViewAllTeams) {
      // User can view all teams
      const { data, error: teamsError } = await supabase
        .from('teams')
        .select('*')
        .eq('organization_id', id)
        .order('created_at', { ascending: false });

      if (teamsError) throw teamsError;
      teams = data;
    } else {
      // User can only view teams they're a member of
      const { data: userTeamIds } = await supabase
        .from('team_members')
        .select('team_id')
        .eq('user_id', userId);

      const teamIds = (userTeamIds || []).map((t: any) => t.team_id);

      if (teamIds.length === 0) {
        return res.json([]);
      }

      const { data, error: teamsError } = await supabase
        .from('teams')
        .select('*')
        .eq('organization_id', id)
        .in('id', teamIds)
        .order('created_at', { ascending: false });

      if (teamsError) throw teamsError;
      teams = data;
    }

    // Get member counts, project counts, and user roles for each team
    const teamsWithCounts = await Promise.all(
      (teams || []).map(async (team) => {
        const { count: memberCount } = await supabase
          .from('team_members')
          .select('*', { count: 'exact', head: true })
          .eq('team_id', team.id);

        const { count: projectCount } = await supabase
          .from('project_teams')
          .select('*', { count: 'exact', head: true })
          .eq('team_id', team.id);

        // Get user's team membership with role
        const { data: teamMembership } = await supabase
          .from('team_members')
          .select('role_id')
          .eq('team_id', team.id)
          .eq('user_id', userId)
          .single();

        let userRole = 'member';
        let userRoleDisplayName = 'Member';
        let userRoleColor = null;
        let userRank: number | null = null;
        let userPermissions = {
          view_overview: true,
          resolve_alerts: false,
          manage_projects: false,
          manage_members: false,
          view_settings: false,
          view_roles: false,
          edit_roles: false,
          manage_notification_settings: false,
        };

        // If user has a team membership with a role, get role details
        if (teamMembership?.role_id) {
          const { data: role } = await supabase
            .from('team_roles')
            .select('name, display_name, color, permissions, display_order')
            .eq('id', teamMembership.role_id)
            .single();

          if (role) {
            userRole = role.name;
            userRoleDisplayName = role.display_name || role.name.charAt(0).toUpperCase() + role.name.slice(1);
            userRoleColor = role.color;
            userRank = role.display_order;
            // Merge permissions but always ensure view_overview is true (everyone can view overview)
            userPermissions = {
              ...userPermissions,
              ...(role.permissions || {}),
              view_overview: true, // Always allow viewing overview
            };
          }
        } else if (teamMembership) {
          // User is a team member but without role_id, look up the member role for this team
          const { data: memberRole } = await supabase
            .from('team_roles')
            .select('name, display_name, color, permissions, display_order')
            .eq('team_id', team.id)
            .eq('name', 'member')
            .single();

          if (memberRole) {
            userRole = memberRole.name;
            userRoleDisplayName = memberRole.display_name || 'Member';
            userRoleColor = memberRole.color;
            userRank = memberRole.display_order;
            // Merge permissions but always ensure view_overview is true
            userPermissions = {
              ...userPermissions,
              ...(memberRole.permissions || {}),
              view_overview: true,
            };
          }
        }

        // Org admins/owners OR users with manage_teams_and_projects permission get all permissions on teams
        if (membership.role === 'owner' || membership.role === 'admin' || canViewAllTeams) {
          userPermissions = {
            view_overview: true,
            resolve_alerts: true,
            manage_projects: true,
            manage_members: true,
            view_settings: true,
            view_roles: true,
            edit_roles: true,
          };
          // Org admins/owners have effective rank of 0 (highest) for team role management
          userRank = 0;
          // If user is NOT a team member but has org-level access, don't show a role badge
          // But if they ARE a team member, preserve their team role badge
          if (!teamMembership?.role_id) {
            userRole = null as any;
            userRoleDisplayName = null as any;
            userRoleColor = null;
          }
        }

        return {
          ...team,
          member_count: memberCount || 0,
          project_count: projectCount || 0,
          role: userRole,
          role_display_name: userRoleDisplayName,
          role_color: userRoleColor,
          user_rank: userRank,
          permissions: userPermissions,
        };
      })
    );

    res.json(teamsWithCounts);
  } catch (error: any) {
    console.error('Error fetching teams:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch teams' });
  }
});

// POST /api/organizations/:id/teams - Create a new team
router.post('/:id/teams', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { name } = req.body;

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'Team name is required' });
    }

    // Check if user is a member of the organization
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Check if user has permission to create teams
    // Owners always have permission
    if (membership.role !== 'owner') {
      // For non-owners, check the role permissions
      const { data: roleData } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      const hasPermission = roleData?.permissions?.manage_teams_and_projects === true;

      if (!hasPermission) {
        return res.status(403).json({ error: 'You do not have permission to create teams' });
      }
    }

    // Create team
    const { data: team, error: teamError } = await supabase
      .from('teams')
      .insert({
        organization_id: id,
        name: name.trim(),
      })
      .select()
      .single();

    if (teamError) {
      if (teamError.code === '23505' || teamError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'A team with this name already exists' });
      }
      throw teamError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'team_created',
      description: `created team "${name.trim()}"`,
      metadata: { team_name: name.trim(), team_id: team.id },
    });

    // Team creator gets full permissions but no team role badge
    // (they have access via org-level permissions, not as a team member)
    res.status(201).json({
      ...team,
      member_count: 0,
      project_count: 0,
      role: null,
      role_display_name: null,
      role_color: null,
      permissions: {
        view_overview: true,
        resolve_alerts: true,
        manage_projects: true,
        manage_members: true,
        view_settings: true,
        view_roles: true,
        edit_roles: true,
      },
    });
  } catch (error: any) {
    console.error('Error creating team:', error);
    res.status(500).json({ error: error.message || 'Failed to create team' });
  }
});

// PUT /api/organizations/:id/teams/:teamId - Update a team
router.put('/:id/teams/:teamId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;
    const { name, avatar_url, description } = req.body;

    // Check if user has access to this team
    const accessCheck = await checkTeamAccess(userId, id, teamId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }
    const { orgMembership, teamMembership } = accessCheck;

    const isOrgAdmin = orgMembership!.role === 'owner' || orgMembership!.role === 'admin';

    if (!isOrgAdmin) {
      // Check if user has view_settings permission on team (which implies edit for now)
      if (teamMembership?.role_id) {
        const { data: role } = await supabase
          .from('team_roles')
          .select('permissions')
          .eq('id', teamMembership.role_id)
          .single();

        if (!role?.permissions?.view_settings) {
          return res.status(403).json({ error: 'Only team managers or org admins can update teams' });
        }
      } else {
        return res.status(403).json({ error: 'Only team managers or org admins can update teams' });
      }
    }

    // Get current team data for activity logs
    const { data: currentTeam } = await supabase
      .from('teams')
      .select('name, avatar_url, description')
      .eq('id', teamId)
      .eq('organization_id', id)
      .single();

    // Build update data
    const updateData: any = {
      updated_at: new Date().toISOString(),
    };
    if (name !== undefined) updateData.name = name.trim();
    if (avatar_url !== undefined) updateData.avatar_url = avatar_url;
    if (description !== undefined) updateData.description = description;

    const { data: team, error: teamError } = await supabase
      .from('teams')
      .update(updateData)
      .eq('id', teamId)
      .eq('organization_id', id)
      .select()
      .single();

    if (teamError) {
      if (teamError.code === '23505' || teamError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'A team with this name already exists' });
      }
      throw teamError;
    }

    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Create activity logs for changes
    if (name !== undefined && name.trim() !== currentTeam?.name) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'updated_team_name',
        description: `updated team name from "${currentTeam?.name}" to "${name.trim()}"`,
        metadata: {
          team_id: teamId,
          team_name: name.trim(),
          old_name: currentTeam?.name,
          new_name: name.trim()
        },
      });
    }

    if (description !== undefined && description !== currentTeam?.description) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'updated_team_description',
        description: `updated team "${team.name}" description`,
        metadata: {
          team_id: teamId,
          team_name: team.name,
        },
      });
    }

    if (avatar_url !== undefined && avatar_url !== currentTeam?.avatar_url) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'changed_team_avatar',
        description: `changed team "${team.name}" avatar`,
        metadata: {
          team_id: teamId,
          team_name: team.name,
        },
      });
    }

    res.json(team);
  } catch (error: any) {
    console.error('Error updating team:', error);
    res.status(500).json({ error: error.message || 'Failed to update team' });
  }
});

// DELETE /api/organizations/:id/teams/:teamId - Delete a team
router.delete('/:id/teams/:teamId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;

    // Check if user is a member of the organization
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Owners always have permission
    if (membership.role !== 'owner') {
      // Check if user has manage_teams_and_projects permission
      const { data: roleData } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      const hasPermission = roleData?.permissions?.manage_teams_and_projects === true;

      if (!hasPermission) {
        return res.status(403).json({ error: 'You do not have permission to delete teams' });
      }
    }

    // Get team name for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .eq('organization_id', id)
      .single();

    // Delete team (cascade will delete team_members)
    const { error: deleteError } = await supabase
      .from('teams')
      .delete()
      .eq('id', teamId)
      .eq('organization_id', id);

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'deleted_team',
      description: `deleted team "${team?.name || teamId}"`,
      metadata: {
        team_id: teamId,
        team_name: team?.name,
      },
    });

    res.json({ message: 'Team deleted' });
  } catch (error: any) {
    console.error('Error deleting team:', error);
    res.status(500).json({ error: error.message || 'Failed to delete team' });
  }
});

// GET /api/organizations/:id/teams/:teamId - Get single team with user's role and permissions
router.get('/:id/teams/:teamId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;

    // Check if user has access to this team
    const accessCheck = await checkTeamAccess(userId, id, teamId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }
    const { orgMembership, teamMembership } = accessCheck;

    // Get team data
    const { data: team, error: teamError } = await supabase
      .from('teams')
      .select('*')
      .eq('id', teamId)
      .eq('organization_id', id)
      .single();

    if (teamError || !team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Get member and project counts
    const { count: memberCount } = await supabase
      .from('team_members')
      .select('*', { count: 'exact', head: true })
      .eq('team_id', teamId);

    const { count: projectCount } = await supabase
      .from('project_teams')
      .select('*', { count: 'exact', head: true })
      .eq('team_id', teamId);

    // teamMembership already obtained from checkTeamAccess

    let userRole = 'member';
    let userRoleDisplayName = 'Member';
    let userRoleColor = null;
    let userPermissions = {
      view_overview: true,
      resolve_alerts: false,
      manage_projects: false,
      manage_members: false,
      view_settings: false,
      view_roles: false,
      edit_roles: false,
      manage_notification_settings: false,
    };

    let userRank: number | null = null;

    // If user has a team membership with a role, get role details
    if (teamMembership?.role_id) {
      const { data: role } = await supabase
        .from('team_roles')
        .select('name, display_name, color, permissions, display_order')
        .eq('id', teamMembership.role_id)
        .single();

      if (role) {
        userRole = role.name;
        userRoleDisplayName = role.display_name || role.name.charAt(0).toUpperCase() + role.name.slice(1);
        userRoleColor = role.color;
        userRank = role.display_order;
        // Merge permissions but always ensure view_overview is true (everyone can view overview)
        userPermissions = {
          ...userPermissions,
          ...(role.permissions || {}),
          view_overview: true, // Always allow viewing overview
        };
      }
    } else if (teamMembership) {
      // User is a team member but without role_id, get the member role
      const { data: memberRole } = await supabase
        .from('team_roles')
        .select('name, display_name, color, permissions, display_order')
        .eq('team_id', teamId)
        .eq('name', 'member')
        .single();

      if (memberRole) {
        userRole = memberRole.name;
        userRoleDisplayName = memberRole.display_name || 'Member';
        userRoleColor = memberRole.color;
        userRank = memberRole.display_order;
        // Merge permissions but always ensure view_overview is true (everyone can view overview)
        userPermissions = {
          ...userPermissions,
          ...(memberRole.permissions || {}),
          view_overview: true, // Always allow viewing overview
        };
      }
    }

    // Org admins/owners OR users with view_all_teams_and_projects/manage_teams_and_projects permission get all permissions on teams
    // We need to check org role permissions for this
    const { data: orgRole } = await supabase
      .from('organization_roles')
      .select('permissions, display_order')
      .eq('organization_id', id)
      .eq('name', orgMembership.role)
      .single();

    // Get the current user's org rank for hierarchy checks
    const userOrgRank = orgRole?.display_order ?? 999;

    const canViewAllTeamsAndProjects = orgRole?.permissions?.view_all_teams_and_projects === true;
    const canManageTeamsAndProjects = orgRole?.permissions?.manage_teams_and_projects === true;

    if (orgMembership.role === 'owner' || orgMembership.role === 'admin' || canViewAllTeamsAndProjects || canManageTeamsAndProjects) {
      userPermissions = {
        view_overview: true,
        resolve_alerts: true,
        manage_projects: true,
        manage_members: true,
        view_settings: true,
        view_roles: true,
        edit_roles: true,
      };
      // Org admins/owners have effective rank of 0 (highest) for team role management
      userRank = 0;
      // Don't set role if not a team member
      if (!teamMembership) {
        userRole = null as any;
        userRoleDisplayName = null as any;
        userRoleColor = null;
      }
    }

    res.json({
      ...team,
      member_count: memberCount || 0,
      project_count: projectCount || 0,
      role: userRole,
      role_display_name: userRoleDisplayName,
      role_color: userRoleColor,
      user_rank: userRank,
      user_org_rank: userOrgRank, // Added: current user's org rank for hierarchy checks
      permissions: userPermissions,
    });
  } catch (error: any) {
    console.error('Error fetching team:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch team' });
  }
});

// GET /api/organizations/:id/teams/:teamId/roles - Get team roles
router.get('/:id/teams/:teamId/roles', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;

    // Check if user has access to this team
    const accessCheck = await checkTeamAccess(userId, id, teamId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get team roles
    const { data: roles, error: rolesError } = await supabase
      .from('team_roles')
      .select('*')
      .eq('team_id', teamId)
      .order('display_order', { ascending: true });

    if (rolesError) {
      throw rolesError;
    }

    res.json(roles || []);
  } catch (error: any) {
    console.error('Error fetching team roles:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch team roles' });
  }
});

// POST /api/organizations/:id/teams/:teamId/roles - Create team role
router.post('/:id/teams/:teamId/roles', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;
    const { name, display_name, permissions, color } = req.body;

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'Role name is required' });
    }

    // Validate color hex code if provided
    if (color && !/^#([0-9A-F]{3}){1,2}$/i.test(color)) {
      return res.status(400).json({ error: 'Invalid color format. Must be a hex code (e.g. #FF0000)' });
    }

    // Check if user has access to this team
    const accessCheck = await checkTeamAccess(userId, id, teamId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }
    const { orgMembership, teamMembership } = accessCheck;

    const isOrgAdmin = orgMembership!.role === 'owner' || orgMembership!.role === 'admin';
    let userPermissions: any = null;

    if (!isOrgAdmin) {
      // Check if user has edit_roles permission on team
      if (teamMembership?.role_id) {
        const { data: role } = await supabase
          .from('team_roles')
          .select('name, permissions, display_order')
          .eq('id', teamMembership.role_id)
          .single();

        // Check if user has edit_roles permission or is top ranked role (display_order 0)
        const hasEditRoles = role?.permissions?.edit_roles === true;
        const isTopRankedRole = role?.display_order === 0;

        if (!role || (!hasEditRoles && !isTopRankedRole)) {
          return res.status(403).json({ error: 'Only team admins or org admins can create roles' });
        }
        userPermissions = role.permissions;
      } else {
        return res.status(403).json({ error: 'Only team admins or org admins can create roles' });
      }
    }

    // Check if user is trying to grant permissions they don't have
    if (permissions && userPermissions) {
      const permissionKeys = Object.keys(permissions) as Array<keyof typeof permissions>;
      for (const key of permissionKeys) {
        // If trying to set a permission to true that the user doesn't have
        if (permissions[key] === true && !userPermissions[key]) {
          return res.status(403).json({ error: `You cannot grant the '${key}' permission because you don't have it` });
        }
      }
    }

    // Get max display_order
    const { data: maxOrderResult } = await supabase
      .from('team_roles')
      .select('display_order')
      .eq('team_id', teamId)
      .order('display_order', { ascending: false })
      .limit(1)
      .single();

    const displayOrder = (maxOrderResult?.display_order || 0) + 1;

    // Create role
    const { data: role, error: roleError } = await supabase
      .from('team_roles')
      .insert({
        team_id: teamId,
        name: name.trim().toLowerCase(),
        display_name: display_name || name.trim(),
        display_order: displayOrder,
        color: color || null,
        permissions: permissions || {
          view_overview: true,
          resolve_alerts: false,
          manage_projects: false,
          manage_members: false,
          view_settings: false,
          view_roles: false,
          edit_roles: false,
          manage_notification_settings: false,
        },
      })
      .select()
      .single();

    if (roleError) {
      if (roleError.code === '23505' || roleError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'A role with this name already exists' });
      }
      throw roleError;
    }

    // Get team name for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'created_team_role',
      description: `created role "${display_name || name.trim()}" in team "${team?.name || teamId}"`,
      metadata: {
        team_id: teamId,
        team_name: team?.name,
        role_name: display_name || name.trim(),
        role_id: role.id,
      },
    });

    res.status(201).json(role);
  } catch (error: any) {
    console.error('Error creating team role:', error);
    res.status(500).json({ error: error.message || 'Failed to create team role' });
  }
});

// PUT /api/organizations/:id/teams/:teamId/roles/:roleId - Update team role
router.put('/:id/teams/:teamId/roles/:roleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId, roleId } = req.params;
    const { name, display_name, display_order, permissions, color } = req.body;

    // Check if user has access to this team
    const accessCheck = await checkTeamAccess(userId, id, teamId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }
    const { orgMembership, teamMembership } = accessCheck;

    const isOrgAdmin = orgMembership!.role === 'owner' || orgMembership!.role === 'admin';
    let userRank = 0; // Org admins have rank 0 (highest)
    let userPermissions: any = null; // For checking permission granting

    if (!isOrgAdmin) {
      if (teamMembership?.role_id) {
        const { data: userRole } = await supabase
          .from('team_roles')
          .select('name, display_order, permissions')
          .eq('id', teamMembership.role_id)
          .single();

        // Check if user has edit_roles permission
        if (!userRole || !userRole.permissions?.edit_roles) {
          return res.status(403).json({ error: 'You do not have permission to update roles' });
        }
        userRank = userRole.display_order;
        userPermissions = userRole.permissions;
      } else {
        return res.status(403).json({ error: 'Only users with edit_roles permission can update roles' });
      }
    }

    // Get the target role to check rank
    const { data: targetRole } = await supabase
      .from('team_roles')
      .select('display_order, name, is_default')
      .eq('id', roleId)
      .eq('team_id', teamId)
      .single();

    if (!targetRole) {
      return res.status(404).json({ error: 'Role not found' });
    }

    // Check rank hierarchy for non-admin users: can only edit roles below your rank
    // Note: For display_order changes, we allow it (for reordering member role), but name/permission changes require lower rank
    const isReorderOnly = display_order !== undefined &&
      name === undefined &&
      display_name === undefined &&
      permissions === undefined &&
      color === undefined;

    // Special case: If user is the TOP ranked role (display_order 0) and editing their OWN role (name/color only, not permissions)
    // This allows the top role to edit their own name/color without needing org-level permissions
    const isEditingOwnTopRole = userRank === 0 && targetRole.display_order === 0 && !permissions;

    if (!isOrgAdmin && !isReorderOnly && !isEditingOwnTopRole && targetRole.display_order <= userRank) {
      return res.status(403).json({ error: 'You cannot edit roles at or above your rank' });
    }

    // For reorder operations, check that the new position isn't above user's rank
    if (!isOrgAdmin && isReorderOnly && display_order !== undefined) {
      // Can't move a role to a position above user's rank (lower number)
      if (display_order < userRank) {
        return res.status(403).json({ error: 'You cannot reorder a role to be above your rank' });
      }
    }

    // Check if user is trying to grant permissions they don't have
    if (permissions && userPermissions) {
      const permissionKeys = Object.keys(permissions) as Array<keyof typeof permissions>;
      for (const key of permissionKeys) {
        // If trying to set a permission to true that the user doesn't have
        if (permissions[key] === true && !userPermissions[key]) {
          return res.status(403).json({ error: `You cannot grant the '${key}' permission because you don't have it` });
        }
      }
    }

    // Build update data
    const updateData: any = {
      updated_at: new Date().toISOString(),
    };
    if (name !== undefined) updateData.name = name.trim().toLowerCase();
    if (display_name !== undefined) updateData.display_name = display_name;
    if (display_order !== undefined) updateData.display_order = display_order;
    if (permissions !== undefined) updateData.permissions = permissions;
    if (color !== undefined) {
      // Validate color hex code if provided
      if (color && !/^#([0-9A-F]{3}){1,2}$/i.test(color)) {
        return res.status(400).json({ error: 'Invalid color format. Must be a hex code (e.g. #FF0000)' });
      }
      updateData.color = color;
    }

    // Update role
    const { data: role, error: roleError } = await supabase
      .from('team_roles')
      .update(updateData)
      .eq('id', roleId)
      .eq('team_id', teamId)
      .select()
      .single();

    if (roleError) {
      if (roleError.code === '23505' || roleError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'A role with this name already exists' });
      }
      throw roleError;
    }

    if (!role) {
      return res.status(404).json({ error: 'Role not found' });
    }

    // Get team name for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    // Create activity logs for different types of changes
    const roleDisplayName = role.display_name || role.name;

    // Check if this is a rank change only
    if (display_order !== undefined && display_order !== targetRole.display_order) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'changed_team_role_rank',
        description: `changed rank of role "${roleDisplayName}" in team "${team?.name || teamId}"`,
        metadata: {
          team_id: teamId,
          team_name: team?.name,
          role_name: roleDisplayName,
          role_id: roleId,
          old_rank: targetRole.display_order,
          new_rank: display_order,
        },
      });
    }

    // Check for name or permission changes
    const hasNameChange = name !== undefined || display_name !== undefined;
    const hasPermissionChange = permissions !== undefined;

    if (hasNameChange || hasPermissionChange || (color !== undefined && !isReorderOnly)) {
      const changes: string[] = [];
      const metadata: any = {
        team_id: teamId,
        team_name: team?.name,
        role_id: roleId,
      };

      if (hasNameChange) {
        changes.push('name');
        metadata.old_name = targetRole.name;
        metadata.new_name = name || targetRole.name;
      }

      if (hasPermissionChange) {
        changes.push('permissions');
        metadata.permissions_changed = true;
      }

      if (color !== undefined && color !== targetRole.color) {
        changes.push('color');
      }

      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'updated_team_role',
        description: `updated role "${roleDisplayName}" in team "${team?.name || teamId}"`,
        metadata,
      });
    }

    res.json(role);
  } catch (error: any) {
    console.error('Error updating team role:', error);
    res.status(500).json({ error: error.message || 'Failed to update team role' });
  }
});

// DELETE /api/organizations/:id/teams/:teamId/roles/:roleId - Delete team role
router.delete('/:id/teams/:teamId/roles/:roleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId, roleId } = req.params;

    // Check if user is org admin/owner or has manage_teams_and_projects permission
    const { data: orgMembership, error: orgMembershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (orgMembershipError || !orgMembership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const isOrgAdmin = orgMembership.role === 'owner' || orgMembership.role === 'admin';
    let userRank = 0; // Org admins have rank 0 (highest)
    let hasOrgManagePermission = false;

    if (!isOrgAdmin) {
      // Check if user's org role has manage_teams_and_projects permission
      const { data: orgRoleData } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', orgMembership.role)
        .single();

      hasOrgManagePermission = orgRoleData?.permissions?.manage_teams_and_projects === true;

      if (!hasOrgManagePermission) {
        const { data: teamMembership } = await supabase
          .from('team_members')
          .select('role_id')
          .eq('team_id', teamId)
          .eq('user_id', userId)
          .single();

        if (teamMembership?.role_id) {
          const { data: userRole } = await supabase
            .from('team_roles')
            .select('name, display_order, permissions')
            .eq('id', teamMembership.role_id)
            .single();

          // Check if user has edit_roles permission
          if (!userRole || !userRole.permissions?.edit_roles) {
            return res.status(403).json({ error: 'You do not have permission to delete roles' });
          }
          userRank = userRole.display_order;
        } else {
          return res.status(403).json({ error: 'Only users with edit_roles permission can delete roles' });
        }
      }
    }

    // Check if role exists and get its details
    const { data: roleToDelete } = await supabase
      .from('team_roles')
      .select('is_default, name, display_order')
      .eq('id', roleId)
      .eq('team_id', teamId)
      .single();

    if (!roleToDelete) {
      return res.status(404).json({ error: 'Role not found' });
    }

    // Only the top ranked role (display_order 0) cannot be deleted - it's always required
    // Member role CAN be deleted
    if (roleToDelete.display_order === 0) {
      return res.status(400).json({ error: 'Cannot delete the top ranked role' });
    }

    // Check rank hierarchy: can only delete roles below your rank (higher display_order number)
    // Skip this check for org admins or users with org-level manage_teams_and_projects permission
    if (!isOrgAdmin && !hasOrgManagePermission && roleToDelete.display_order <= userRank) {
      return res.status(403).json({ error: 'You cannot delete roles at or above your rank' });
    }

    // Check if any members have this role
    const { data: membersWithRole, error: membersError } = await supabase
      .from('team_members')
      .select('user_id')
      .eq('team_id', teamId)
      .eq('role_id', roleId);

    if (membersError) {
      throw membersError;
    }

    if (membersWithRole && membersWithRole.length > 0) {
      return res.status(400).json({
        error: `Cannot delete this role because ${membersWithRole.length} member(s) have this role. Please reassign them first.`
      });
    }

    // Get team info for activity log before deletion
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    // Delete role
    const { error: deleteError } = await supabase
      .from('team_roles')
      .delete()
      .eq('id', roleId)
      .eq('team_id', teamId);

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    const roleDisplayName = roleToDelete?.display_name || roleToDelete?.name || 'Unknown';
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'deleted_team_role',
      description: `deleted role "${roleDisplayName}" from team "${team?.name || teamId}"`,
      metadata: {
        team_id: teamId,
        team_name: team?.name,
        role_name: roleDisplayName,
      },
    });

    res.json({ message: 'Role deleted successfully' });
  } catch (error: any) {
    console.error('Error deleting team role:', error);
    res.status(500).json({ error: error.message || 'Failed to delete team role' });
  }
});

// GET /api/organizations/:id/teams/:teamId/members - Get team members
router.get('/:id/teams/:teamId/members', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;

    // Check if user has access to this team
    const accessCheck = await checkTeamAccess(userId, id, teamId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get team members with role_id
    const { data: teamMembers, error: teamMembersError } = await supabase
      .from('team_members')
      .select('user_id, role_id, created_at')
      .eq('team_id', teamId);

    if (teamMembersError) {
      throw teamMembersError;
    }

    // Get all team roles for lookup
    const { data: teamRoles } = await supabase
      .from('team_roles')
      .select('id, name, display_name, display_order, permissions, color')
      .eq('team_id', teamId);

    const rolesMap = new Map((teamRoles || []).map(r => [r.id, r]));

    // Get user details for each member
    const membersWithDetails = await Promise.all(
      (teamMembers || []).map(async (tm) => {
        const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(tm.user_id);
        if (userError || !user) return null;

        // Get user profile for full name
        const { data: userProfile } = await supabase
          .from('user_profiles')
          .select('full_name, avatar_url')
          .eq('user_id', tm.user_id)
          .single();

        // Get organization membership for org_rank
        const { data: orgMembership } = await supabase
          .from('organization_members')
          .select('role')
          .eq('organization_id', id)
          .eq('user_id', tm.user_id)
          .single();

        // Get organization role for rank by role name
        let orgRank = 999; // Default to lowest rank
        if (orgMembership?.role) {
          const { data: orgRole } = await supabase
            .from('organization_roles')
            .select('display_order')
            .eq('organization_id', id)
            .eq('name', orgMembership.role)
            .single();

          if (orgRole) {
            orgRank = orgRole.display_order;
          }
        }

        const role = tm.role_id ? rolesMap.get(tm.role_id) : null;

        return {
          user_id: user.id,
          email: user.email,
          full_name: userProfile?.full_name || user.user_metadata?.full_name || null,
          avatar_url: userProfile?.avatar_url || user.user_metadata?.avatar_url || null,
          role: role?.name || 'member',
          role_display_name: role?.display_name || 'Member',
          role_color: role?.color || null,
          rank: role?.display_order ?? 999,
          org_rank: orgRank, // Organization-level rank
          permissions: role?.permissions || {
            view_overview: true,
            resolve_alerts: false,
            manage_projects: false,
            view_settings: false,
            view_members: false,
            add_members: false,
            kick_members: false,
            view_roles: false,
            edit_roles: false,
          },
          created_at: tm.created_at,
        };
      })
    );

    res.json(membersWithDetails.filter(Boolean));
  } catch (error: any) {
    console.error('Error fetching team members:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch team members' });
  }
});

// POST /api/organizations/:id/teams/:teamId/members - Add member to team
router.post('/:id/teams/:teamId/members', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;
    const { user_id, role_id } = req.body;

    if (!user_id) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // Check if user is admin or owner of org, or has add_members permission on team
    const { data: orgMembership, error: orgMembershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (orgMembershipError || !orgMembership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const isOrgAdmin = orgMembership.role === 'owner' || orgMembership.role === 'admin';

    // Check if user's org role has manage_teams_and_projects permission
    let hasOrgManagePermission = false;
    if (!isOrgAdmin) {
      const { data: orgRoleData } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', orgMembership.role)
        .single();

      hasOrgManagePermission = orgRoleData?.permissions?.manage_teams_and_projects === true;
    }

    if (!isOrgAdmin && !hasOrgManagePermission) {
      // Check if user has add_members permission on team
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role_id')
        .eq('team_id', teamId)
        .eq('user_id', userId)
        .single();

      if (teamMembership?.role_id) {
        const { data: role } = await supabase
          .from('team_roles')
          .select('permissions')
          .eq('id', teamMembership.role_id)
          .single();

        if (!role?.permissions?.add_members) {
          return res.status(403).json({ error: 'You do not have permission to add team members' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to add team members' });
      }
    }

    // Verify the user is a member of the organization
    const { data: orgMember } = await supabase
      .from('organization_members')
      .select('id')
      .eq('organization_id', id)
      .eq('user_id', user_id)
      .single();

    if (!orgMember) {
      return res.status(400).json({ error: 'User is not a member of this organization' });
    }

    // Get the role_id to assign (default to member role if not specified)
    let assignRoleId = role_id;
    if (!assignRoleId) {
      const { data: memberRole } = await supabase
        .from('team_roles')
        .select('id')
        .eq('team_id', teamId)
        .eq('name', 'member')
        .single();
      assignRoleId = memberRole?.id;
    }

    // Add member to team
    const { data: teamMember, error: teamMemberError } = await supabase
      .from('team_members')
      .insert({
        team_id: teamId,
        user_id: user_id,
        role_id: assignRoleId,
      })
      .select()
      .single();

    if (teamMemberError) {
      if (teamMemberError.code === '23505' || teamMemberError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'User is already a member of this team' });
      }
      throw teamMemberError;
    }

    // Get team and user info for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    const { data: { user: addedUser } } = await supabase.auth.admin.getUserById(user_id);

    // Get user profile for full name
    const { data: addedUserProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', user_id)
      .single();

    const addedUserName = addedUserProfile?.full_name || addedUser?.user_metadata?.full_name || addedUser?.email || user_id;

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'added_member_to_team',
      description: `added ${addedUserName} to team "${team?.name || teamId}"`,
      metadata: {
        team_id: teamId,
        team_name: team?.name,
        added_user_id: user_id,
        added_user_email: addedUser?.email,
        added_user_name: addedUserName,
      },
    });

    res.status(201).json(teamMember);
  } catch (error: any) {
    console.error('Error adding team member:', error);
    res.status(500).json({ error: error.message || 'Failed to add team member' });
  }
});

// PUT /api/organizations/:id/teams/:teamId/members/:memberId/role - Update team member role
router.put('/:id/teams/:teamId/members/:memberId/role', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId, memberId } = req.params;
    const { role_id } = req.body;

    if (!role_id) {
      return res.status(400).json({ error: 'Role ID is required' });
    }

    // Check if user is admin or owner of org, or has edit_roles permission on team
    const { data: orgMembership, error: orgMembershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (orgMembershipError || !orgMembership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const isOrgAdmin = orgMembership.role === 'owner' || orgMembership.role === 'admin';

    // Check if user's org role has manage_teams_and_projects permission
    let hasOrgManagePermission = false;
    if (!isOrgAdmin) {
      const { data: orgRoleData } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', orgMembership.role)
        .single();

      hasOrgManagePermission = orgRoleData?.permissions?.manage_teams_and_projects === true;
    }

    if (!isOrgAdmin && !hasOrgManagePermission) {
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role_id')
        .eq('team_id', teamId)
        .eq('user_id', userId)
        .single();

      if (teamMembership?.role_id) {
        const { data: role } = await supabase
          .from('team_roles')
          .select('permissions')
          .eq('id', teamMembership.role_id)
          .single();

        if (!role?.permissions?.edit_roles) {
          return res.status(403).json({ error: 'You do not have permission to update team member roles' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to update team member roles' });
      }
    }

    // Verify the role exists for this team
    const { data: roleExists } = await supabase
      .from('team_roles')
      .select('id')
      .eq('id', role_id)
      .eq('team_id', teamId)
      .single();

    if (!roleExists) {
      return res.status(400).json({ error: 'Invalid role for this team' });
    }

    // If user has org-level manage_teams_and_projects permission and is changing someone else's role
    // Check org rank hierarchy (skip if changing own role)
    const isChangingOwnRole = userId === memberId;
    if (hasOrgManagePermission && !isOrgAdmin && !isChangingOwnRole) {
      // Get actor's org rank
      const { data: actorOrgRole } = await supabase
        .from('organization_roles')
        .select('display_order')
        .eq('organization_id', id)
        .eq('name', orgMembership.role)
        .single();

      // Get target member's org role
      const { data: targetOrgMembership } = await supabase
        .from('organization_members')
        .select('role')
        .eq('organization_id', id)
        .eq('user_id', memberId)
        .single();

      if (targetOrgMembership) {
        const { data: targetOrgRole } = await supabase
          .from('organization_roles')
          .select('display_order')
          .eq('organization_id', id)
          .eq('name', targetOrgMembership.role)
          .single();

        const actorRank = actorOrgRole?.display_order ?? 999;
        const targetRank = targetOrgRole?.display_order ?? 999;

        // Can only change roles for members with lower org rank (higher display_order number)
        if (targetRank <= actorRank) {
          return res.status(403).json({ error: 'You can only change roles for members ranked below you in the organization' });
        }
      }
    }

    // Get current member role for activity log
    const { data: currentMember } = await supabase
      .from('team_members')
      .select('role_id')
      .eq('team_id', teamId)
      .eq('user_id', memberId)
      .single();

    let oldRoleName = 'member';
    if (currentMember?.role_id) {
      const { data: oldRole } = await supabase
        .from('team_roles')
        .select('name, display_name')
        .eq('id', currentMember.role_id)
        .single();
      oldRoleName = oldRole?.display_name || oldRole?.name || 'member';
    }

    // Get new role name
    const { data: newRole } = await supabase
      .from('team_roles')
      .select('name, display_name')
      .eq('id', role_id)
      .single();
    const newRoleName = newRole?.display_name || newRole?.name || 'member';

    // Update member role
    const { data: updatedMember, error: updateError } = await supabase
      .from('team_members')
      .update({ role_id })
      .eq('team_id', teamId)
      .eq('user_id', memberId)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }

    if (!updatedMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    // Get team and user info for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    const { data: { user: targetUser } } = await supabase.auth.admin.getUserById(memberId);
    const { data: targetProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', memberId)
      .single();

    const targetUserName = targetProfile?.full_name || targetUser?.user_metadata?.full_name || targetUser?.email || memberId;

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'changed_team_member_role',
      description: `changed ${targetUserName}'s role from ${oldRoleName} to ${newRoleName} in team "${team?.name || teamId}"`,
      metadata: {
        team_id: teamId,
        team_name: team?.name,
        target_user_id: memberId,
        target_user_email: targetUser?.email,
        target_user_name: targetUserName,
        old_role: oldRoleName,
        new_role: newRoleName,
      },
    });

    res.json(updatedMember);
  } catch (error: any) {
    console.error('Error updating team member role:', error);
    res.status(500).json({ error: error.message || 'Failed to update team member role' });
  }
});

// DELETE /api/organizations/:id/teams/:teamId/members/:memberId - Remove member from team
router.delete('/:id/teams/:teamId/members/:memberId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId, memberId } = req.params;

    // Allow users to leave a team (remove themselves) without needing kick_members permission
    const isLeavingTeam = userId === memberId;

    // Check if user is admin or owner of org, or has kick_members permission on team
    const { data: orgMembership, error: orgMembershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (orgMembershipError || !orgMembership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const isOrgAdmin = orgMembership.role === 'owner' || orgMembership.role === 'admin';

    // Check if user's org role has manage_teams_and_projects permission
    let hasOrgManagePermission = false;
    if (!isOrgAdmin) {
      const { data: orgRoleData } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', orgMembership.role)
        .single();

      hasOrgManagePermission = orgRoleData?.permissions?.manage_teams_and_projects === true;
    }

    // Skip permission check if user is leaving the team themselves
    if (!isOrgAdmin && !hasOrgManagePermission && !isLeavingTeam) {
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role_id')
        .eq('team_id', teamId)
        .eq('user_id', userId)
        .single();

      if (teamMembership?.role_id) {
        const { data: role } = await supabase
          .from('team_roles')
          .select('permissions')
          .eq('id', teamMembership.role_id)
          .single();

        if (!role?.permissions?.kick_members) {
          return res.status(403).json({ error: 'You do not have permission to remove team members' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to remove team members' });
      }
    }

    // If user has org-level manage_teams_and_projects permission, check org rank hierarchy
    if (hasOrgManagePermission && !isOrgAdmin && !isLeavingTeam) {
      // Get actor's org rank
      const { data: actorOrgRole } = await supabase
        .from('organization_roles')
        .select('display_order')
        .eq('organization_id', id)
        .eq('name', orgMembership.role)
        .single();

      // Get target member's org role
      const { data: targetOrgMembership } = await supabase
        .from('organization_members')
        .select('role')
        .eq('organization_id', id)
        .eq('user_id', memberId)
        .single();

      if (targetOrgMembership) {
        const { data: targetOrgRole } = await supabase
          .from('organization_roles')
          .select('display_order')
          .eq('organization_id', id)
          .eq('name', targetOrgMembership.role)
          .single();

        const actorRank = actorOrgRole?.display_order ?? 999;
        const targetRank = targetOrgRole?.display_order ?? 999;

        // Can only kick members with lower org rank (higher display_order number)
        if (targetRank <= actorRank) {
          return res.status(403).json({ error: 'You can only remove members ranked below you in the organization' });
        }
      }
    }

    // Get team and user info for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    const { data: { user: targetUser } } = await supabase.auth.admin.getUserById(memberId);
    const { data: targetProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', memberId)
      .single();

    const targetUserName = targetProfile?.full_name || targetUser?.user_metadata?.full_name || targetUser?.email || memberId;

    // Remove member from team
    const { error: deleteError } = await supabase
      .from('team_members')
      .delete()
      .eq('team_id', teamId)
      .eq('user_id', memberId);

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    if (isLeavingTeam) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'left_team',
        description: `left team "${team?.name || teamId}"`,
        metadata: {
          team_id: teamId,
          team_name: team?.name,
          user_email: targetUser?.email,
        },
      });
    } else {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'removed_member_from_team',
        description: `removed ${targetUserName} from team "${team?.name || teamId}"`,
        metadata: {
          team_id: teamId,
          team_name: team?.name,
          removed_user_id: memberId,
          removed_user_email: targetUser?.email,
          removed_user_name: targetUserName,
        },
      });
    }

    res.json({ message: 'Team member removed' });
  } catch (error: any) {
    console.error('Error removing team member:', error);
    res.status(500).json({ error: error.message || 'Failed to remove team member' });
  }
});

// POST /api/organizations/:id/teams/:teamId/transfer-ownership - Transfer team ownership
router.post('/:id/teams/:teamId/transfer-ownership', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;
    const { user_id: newOwnerId, new_role: newRole = 'member' } = req.body;

    if (!newOwnerId) {
      return res.status(400).json({ error: 'New owner user ID is required' });
    }

    // Check if user is org admin/owner or current team owner
    const { data: orgMembership, error: orgMembershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (orgMembershipError || !orgMembership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const isOrgAdmin = orgMembership.role === 'owner' || orgMembership.role === 'admin';

    // Check if current user is team owner
    const { data: currentUserMembership } = await supabase
      .from('team_members')
      .select('role_id')
      .eq('team_id', teamId)
      .eq('user_id', userId)
      .single();

    let isTeamOwner = false;
    if (currentUserMembership?.role_id) {
      const { data: currentRole } = await supabase
        .from('team_roles')
        .select('name')
        .eq('id', currentUserMembership.role_id)
        .single();

      isTeamOwner = currentRole?.name === 'owner';
    }

    if (!isOrgAdmin && !isTeamOwner) {
      return res.status(403).json({ error: 'Only team owners or org admins can transfer ownership' });
    }

    // Verify new owner is a team member
    const { data: newOwnerMembership } = await supabase
      .from('team_members')
      .select('role_id')
      .eq('team_id', teamId)
      .eq('user_id', newOwnerId)
      .single();

    if (!newOwnerMembership) {
      return res.status(400).json({ error: 'New owner must be a team member' });
    }

    // Get owner role
    const { data: ownerRole } = await supabase
      .from('team_roles')
      .select('id')
      .eq('team_id', teamId)
      .eq('name', 'owner')
      .single();

    if (!ownerRole) {
      return res.status(500).json({ error: 'Owner role not found' });
    }

    // Get new role for current owner
    const { data: newRoleData } = await supabase
      .from('team_roles')
      .select('id')
      .eq('team_id', teamId)
      .eq('name', newRole)
      .single();

    if (!newRoleData) {
      return res.status(400).json({ error: `Role "${newRole}" not found` });
    }

    // Update new owner's role to owner
    const { error: updateNewOwnerError } = await supabase
      .from('team_members')
      .update({ role_id: ownerRole.id })
      .eq('team_id', teamId)
      .eq('user_id', newOwnerId);

    if (updateNewOwnerError) {
      throw updateNewOwnerError;
    }

    // Update current owner's role to new role
    const { error: updateCurrentOwnerError } = await supabase
      .from('team_members')
      .update({ role_id: newRoleData.id })
      .eq('team_id', teamId)
      .eq('user_id', userId);

    if (updateCurrentOwnerError) {
      throw updateCurrentOwnerError;
    }

    // Get new owner details for activity log
    const { data: { user: newOwnerUser } } = await supabase.auth.admin.getUserById(newOwnerId);
    const { data: newOwnerProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', newOwnerId)
      .single();

    const newOwnerName = newOwnerProfile?.full_name || newOwnerUser?.email || 'Unknown';

    // Get team name for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'team_ownership_transferred',
      description: `transferred ownership of team "${team?.name || 'Unknown'}" to ${newOwnerName}`,
      metadata: {
        team_id: teamId,
        team_name: team?.name,
        new_owner_id: newOwnerId,
        new_owner_name: newOwnerName,
        previous_owner_new_role: newRole
      },
    });

    res.json({ message: 'Team ownership transferred successfully' });
  } catch (error: any) {
    console.error('Error transferring team ownership:', error);
    res.status(500).json({ error: error.message || 'Failed to transfer team ownership' });
  }
});

export default router;

