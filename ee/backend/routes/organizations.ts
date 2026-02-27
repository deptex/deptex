import express from 'express';
import * as crypto from 'crypto';
import { authenticateUser, AuthRequest } from '../../../backend/src/middleware/auth';
import { supabase } from '../../../backend/src/lib/supabase';
import { sendInvitationEmail } from '../lib/email';
import { createActivity } from '../lib/activities';
import { getOpenAIClient } from '../lib/openai';
import { updateAllProjectsCompliance } from './projects';
import { invalidateAllProjectCachesInOrg, invalidateProjectCachesForTeam } from '../lib/cache';

const router = express.Router();

// All routes require authentication
router.use(authenticateUser);

// Helper function to get a user's rank (display_order) in an organization
// Lower numbers = higher rank (owner is 0)
async function getUserRank(organizationId: string, userId: string): Promise<{ rank: number; roleName: string } | null> {
  // First get the user's role name
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (!membership) return null;

  // Then get the role's display_order (rank)
  const { data: role } = await supabase
    .from('organization_roles')
    .select('display_order, name')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();

  if (!role) return null;

  return { rank: role.display_order, roleName: role.name };
}

// Helper function to get a role's rank by name
async function getRoleRank(organizationId: string, roleName: string): Promise<number | null> {
  const { data: role } = await supabase
    .from('organization_roles')
    .select('display_order')
    .eq('organization_id', organizationId)
    .eq('name', roleName)
    .single();

  return role?.display_order ?? null;
}

// GET /api/organizations - List user's organizations
router.get('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;

    // Get organizations with user's role in a single query using join
    const { data: memberships, error: membershipError } = await supabase
      .from('organization_members')
      .select(`
        organization_id,
        role,
        organizations!inner (
          id,
          name,
          plan,
          avatar_url,
          created_at,
          updated_at
        )
      `)
      .eq('user_id', userId);

    if (membershipError) {
      throw membershipError;
    }

    if (!memberships || memberships.length === 0) {
      return res.json([]);
    }

    const organizationIds = memberships.map(m => m.organization_id);

    // Get member counts for all organizations in parallel using count queries
    const memberCountPromises = organizationIds.map(async (orgId) => {
      const { count, error } = await supabase
        .from('organization_members')
        .select('*', { count: 'exact', head: true })
        .eq('organization_id', orgId);

      if (error) {
        console.error(`Error counting members for org ${orgId}:`, error);
        return { orgId, count: 0 };
      }
      return { orgId, count: count || 0 };
    });

    const memberCountResults = await Promise.all(memberCountPromises);
    const memberCountMap = new Map<string, number>();
    memberCountResults.forEach(({ orgId, count }) => {
      memberCountMap.set(orgId, count);
    });

    // Fetch custom role display names and permissions for these organizations
    const { data: orgRoles } = await supabase
      .from('organization_roles')
      .select('organization_id, name, display_name, color, permissions')
      .in('organization_id', organizationIds);

    // Create a map for quick lookup: orgId:roleName -> { displayName, color, permissions }
    const roleMap = new Map<string, { displayName?: string, color?: string, permissions?: any }>();
    if (orgRoles) {
      orgRoles.forEach((role) => {
        roleMap.set(`${role.organization_id}:${role.name}`, {
          displayName: role.display_name,
          color: role.color,
          permissions: role.permissions // Include permissions
        });
      });
    }

    // Combine data
    const organizationsWithRole = memberships
      .map(m => {
        const org = Array.isArray(m.organizations) ? m.organizations[0] : m.organizations;
        if (!org) return null;
        const roleData = roleMap.get(`${m.organization_id}:${m.role || 'member'}`);

        return {
          ...org,
          role: m.role || 'member',
          role_display_name: roleData?.displayName || null,
          role_color: roleData?.color || null,
          permissions: roleData?.permissions || null, // Return permissions
          member_count: memberCountMap.get(m.organization_id) || 0,
        };
      })
      .filter((org): org is NonNullable<typeof org> => org !== null)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    res.json(organizationsWithRole);
  } catch (error: any) {
    console.error('Error fetching organizations:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch organizations' });
  }
});

// POST /api/organizations - Create new organization
router.post('/', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { name } = req.body;

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'Organization name is required' });
    }

    // Create organization
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .insert({
        name: name.trim(),
        plan: 'free',
      })
      .select()
      .single();

    if (orgError) {
      throw orgError;
    }

    // Add creator as owner
    const { error: memberError } = await supabase
      .from('organization_members')
      .insert({
        organization_id: organization.id,
        user_id: userId,
        role: 'owner',
      });

    if (memberError) {
      // Rollback organization creation
      await supabase.from('organizations').delete().eq('id', organization.id);
      throw memberError;
    }

    // Create default roles (owner and member)
    const { error: rolesError } = await supabase
      .from('organization_roles')
      .insert([
        {
          organization_id: organization.id,
          name: 'owner',
          display_name: 'Owner',
          display_order: 0,
          is_default: true,
          color: '#f59e0b', // Amber/orange color
          permissions: {
            view_settings: true,
            manage_billing: true,
            manage_security: true,
            view_activity: true,
            manage_compliance: true,
            interact_with_security_agent: true,
            manage_aegis: true,
            view_members: true,
            add_members: true,
            edit_roles: true,
            edit_permissions: true,
            kick_members: true,
            manage_teams_and_projects: true,
            manage_integrations: true,
            manage_notifications: true,
          },
        },
        {
          organization_id: organization.id,
          name: 'member',
          display_name: 'Member',
          display_order: 2,
          is_default: true,
          permissions: {
            view_settings: true,
            manage_billing: true,
            manage_security: true,
            view_activity: true,
            manage_compliance: true,
            interact_with_security_agent: true,
            manage_aegis: true,
            view_members: true,
            add_members: true,
            edit_roles: true,
            edit_permissions: true,
            kick_members: true,
            manage_teams_and_projects: true,
            manage_integrations: true,
            manage_notifications: true,
          },
        },
      ]);

    if (rolesError) {
      // Rollback organization and member creation
      await supabase.from('organization_members').delete().eq('organization_id', organization.id);
      await supabase.from('organizations').delete().eq('id', organization.id);
      throw rolesError;
    }

    // Create activity log
    await createActivity({
      organization_id: organization.id,
      user_id: userId,
      activity_type: 'created_org',
      description: `created organization "${organization.name}"`,
      metadata: { organization_name: organization.name },
    });

    res.status(201).json({
      ...organization,
      role: 'owner',
    });
  } catch (error: any) {
    console.error('Error creating organization:', error);
    res.status(500).json({ error: error.message || 'Failed to create organization' });
  }
});

// GET /api/organizations/:id - Get organization details
router.get('/:id', async (req: AuthRequest, res) => {
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

    // Get organization details
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .select('*')
      .eq('id', id)
      .single();

    if (orgError || !organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Get role display name, color, and rank (display_order)
    const { data: roleData } = await supabase
      .from('organization_roles')
      .select('display_name, color, display_order, permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    res.json({
      ...organization,
      role: membership.role,
      role_display_name: roleData?.display_name || null,
      role_color: roleData?.color || null,
      user_rank: roleData?.display_order ?? null,
      permissions: roleData?.permissions || null,
    });
  } catch (error: any) {
    console.error('Error fetching organization:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch organization' });
  }
});

// GET /api/organizations/:id/members - Get organization members
router.get('/:id/members', async (req: AuthRequest, res) => {
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

    // Get all members
    const { data: members, error: membersError } = await supabase
      .from('organization_members')
      .select('user_id, role, created_at')
      .eq('organization_id', id)
      .order('created_at', { ascending: false });

    if (membersError) {
      throw membersError;
    }

    if (!members || members.length === 0) {
      return res.json([]);
    }

    // Get all teams for this organization
    const { data: orgTeams } = await supabase
      .from('teams')
      .select('id, name')
      .eq('organization_id', id);

    // Get all team memberships for this organization
    const teamIds = (orgTeams || []).map(t => t.id);
    const { data: allTeamMembers } = teamIds.length > 0 ? await supabase
      .from('team_members')
      .select('user_id, team_id, teams!inner(id, name)')
      .in('team_id', teamIds) : { data: [] };

    // Create a map of user_id -> teams
    const userTeamsMap = new Map<string, Array<{ id: string; name: string }>>();
    (allTeamMembers || []).forEach((tm: any) => {
      if (!userTeamsMap.has(tm.user_id)) {
        userTeamsMap.set(tm.user_id, []);
      }
      userTeamsMap.get(tm.user_id)!.push({
        id: tm.teams.id,
        name: tm.teams.name,
      });
    });

    // Get all roles for this organization to map role name -> rank
    const { data: orgRoles } = await supabase
      .from('organization_roles')
      .select('name, display_order, display_name, color')
      .eq('organization_id', id);

    const roleRankMap = new Map<string, { rank: number; displayName?: string; color?: string }>();
    (orgRoles || []).forEach((role: any) => {
      roleRankMap.set(role.name, {
        rank: role.display_order,
        displayName: role.display_name,
        color: role.color,
      });
    });

    // Get user data for each member using admin API
    const formattedMembers = await Promise.all(
      members.map(async (m: any) => {
        try {
          // Use admin client to get user data
          const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(m.user_id);

          const teams = userTeamsMap.get(m.user_id) || [];
          const roleInfo = roleRankMap.get(m.role);

          if (userError || !user) {
            return {
              user_id: m.user_id,
              role: m.role,
              role_display_name: roleInfo?.displayName || null,
              role_color: roleInfo?.color || null,
              rank: roleInfo?.rank ?? null,
              created_at: m.created_at,
              email: '',
              full_name: '',
              avatar_url: null,
              teams: teams,
            };
          }

          // Get user profile from user_profiles table
          const { data: profile } = await supabase
            .from('user_profiles')
            .select('avatar_url, full_name')
            .eq('user_id', m.user_id)
            .single();

          // Get avatar URL with priority:
          // 1. Database profile (user_profiles table)
          // 2. OAuth metadata picture (from raw_user_meta_data.picture)
          // 3. OAuth metadata avatar_url (from raw_user_meta_data.avatar_url)
          const avatarUrl = profile?.avatar_url
            || user.user_metadata?.picture
            || user.user_metadata?.avatar_url
            || null;
          const fullName = profile?.full_name || user.user_metadata?.full_name || null;

          return {
            user_id: m.user_id,
            role: m.role,
            role_display_name: roleInfo?.displayName || null,
            role_color: roleInfo?.color || null,
            rank: roleInfo?.rank ?? null,
            created_at: m.created_at,
            email: user.email || '',
            full_name: fullName,
            avatar_url: avatarUrl,
            teams: teams,
          };
        } catch (error) {
          console.error(`Error fetching user ${m.user_id}:`, error);
          const roleInfo = roleRankMap.get(m.role);
          return {
            user_id: m.user_id,
            role: m.role,
            role_display_name: roleInfo?.displayName || null,
            role_color: roleInfo?.color || null,
            rank: roleInfo?.rank ?? null,
            created_at: m.created_at,
            email: '',
            full_name: '',
            avatar_url: null,
            teams: [],
          };
        }
      })
    );

    res.json(formattedMembers);
  } catch (error: any) {
    console.error('Error fetching members:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch members' });
  }
});

// GET /api/organizations/:id/invitations - Get organization invitations
router.get('/:id/invitations', async (req: AuthRequest, res) => {
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

    // Get pending invitations
    const { data: invitations, error: invitationsError } = await supabase
      .from('organization_invitations')
      .select('*')
      .eq('organization_id', id)
      .eq('status', 'pending')
      .order('created_at', { ascending: false });

    if (invitationsError) {
      throw invitationsError;
    }

    // Get teams from junction table for each invitation
    const invitationsWithTeams = await Promise.all(
      (invitations || []).map(async (invitation: any) => {
        // Get teams from junction table
        const { data: invitationTeams } = await supabase
          .from('invitation_teams')
          .select('team_id, teams(name)')
          .eq('invitation_id', invitation.id);

        const teamIds: string[] = [];
        const teamNames: string[] = [];

        if (invitationTeams && invitationTeams.length > 0) {
          invitationTeams.forEach((it: any) => {
            teamIds.push(it.team_id);
            if (it.teams?.name) {
              teamNames.push(it.teams.name);
            }
          });
        } else if (invitation.team_id) {
          // Fallback to team_id for backward compatibility
          const { data: team } = await supabase
            .from('teams')
            .select('name')
            .eq('id', invitation.team_id)
            .single();

          if (team) {
            teamIds.push(invitation.team_id);
            teamNames.push(team.name);
          }
        }

        return {
          ...invitation,
          team_ids: teamIds,
          team_names: teamNames,
          team_name: teamNames.length === 1 ? teamNames[0] : (teamNames.length > 1 ? teamNames.join(', ') : null), // Keep for backward compatibility
        };
      })
    );

    res.json(invitationsWithTeams);
  } catch (error: any) {
    console.error('Error fetching invitations:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch invitations' });
  }
});

// POST /api/organizations/:id/invitations - Create invitation
router.post('/:id/invitations', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { email, role, team_id, team_ids } = req.body;

    // Support both old team_id (single) and new team_ids (array) for backward compatibility
    const teamIdsArray = team_ids && Array.isArray(team_ids) ? team_ids : (team_id ? [team_id] : []);

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can invite members' });
    }

    // Get organization name and inviter info
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .select('name')
      .eq('id', id)
      .single();

    if (orgError || !organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Get inviter info
    const { data: { user: inviter }, error: inviterError } = await supabase.auth.admin.getUserById(userId);
    const inviterName = inviter?.user_metadata?.full_name || inviter?.email || 'Someone';

    // Check if invitation already exists
    const { data: existingInvitation } = await supabase
      .from('organization_invitations')
      .select('id')
      .eq('organization_id', id)
      .eq('email', email.trim().toLowerCase())
      .eq('status', 'pending')
      .single();

    if (existingInvitation) {
      return res.status(400).json({ error: 'Already invited this person' });
    }

    // Validate team_ids if provided and get team names
    const teamNames: string[] = [];
    if (teamIdsArray.length > 0) {
      const { data: teams, error: teamsError } = await supabase
        .from('teams')
        .select('id, name')
        .eq('organization_id', id)
        .in('id', teamIdsArray);

      if (teamsError || !teams || teams.length !== teamIdsArray.length) {
        return res.status(400).json({ error: 'Invalid team(s) selected' });
      }
      teamNames.push(...teams.map(t => t.name));
    }

    // Validate role (default or custom)
    const defaultRoles = ['owner', 'admin', 'member'];
    const roleToUse = (role || 'member').toLowerCase();
    const isValidDefault = defaultRoles.includes(roleToUse);

    if (!isValidDefault) {
      // Check if it's a custom role
      const { data: customRole } = await supabase
        .from('organization_roles')
        .select('id')
        .eq('organization_id', id)
        .eq('name', roleToUse)
        .single();

      if (!customRole) {
        return res.status(400).json({ error: 'Invalid role. Role must be owner, admin, member, or a custom role defined for this organization' });
      }
    }

    // Create invitation (keep team_id for backward compatibility, but prefer junction table)
    const { data: invitation, error: invitationError } = await supabase
      .from('organization_invitations')
      .insert({
        organization_id: id,
        email: email.trim().toLowerCase(),
        role: roleToUse,
        team_id: teamIdsArray.length === 1 ? teamIdsArray[0] : null, // Keep for backward compatibility
        invited_by: userId,
        status: 'pending',
      })
      .select()
      .single();

    if (invitationError) {
      // Check if it's a duplicate key error
      if (invitationError.code === '23505' || invitationError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'Already invited this person' });
      }
      throw invitationError;
    }

    // Add teams to junction table if any
    if (teamIdsArray.length > 0) {
      const { error: junctionError } = await supabase
        .from('invitation_teams')
        .insert(teamIdsArray.map(teamId => ({
          invitation_id: invitation.id,
          team_id: teamId,
        })));

      if (junctionError) {
        // Rollback invitation if junction insert fails
        await supabase
          .from('organization_invitations')
          .delete()
          .eq('id', invitation.id);
        throw junctionError;
      }
    }

    // Send invitation email
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const inviteLink = `${frontendUrl}/invite/${invitation.id}`;

    const teamNamesText = teamNames.length > 0
      ? teamNames.length === 1
        ? ` (team: ${teamNames[0]})`
        : ` (teams: ${teamNames.join(', ')})`
      : '';

    console.log(`Creating invitation for ${email} to join ${organization.name}${teamNamesText}`);
    try {
      await sendInvitationEmail(
        email.trim().toLowerCase(),
        organization.name,
        inviterName,
        inviteLink,
        role || 'member',
        teamNames.length === 1 ? teamNames[0] : (teamNames.length > 1 ? teamNames.join(', ') : undefined)
      );
      console.log('✅ Email sent successfully');
    } catch (emailError: any) {
      console.error('❌ Failed to send invitation email:', emailError);
      console.error('Email error details:', emailError?.message || emailError);
      // Don't fail the request if email fails - invitation is still created
      // But log the invite link for manual testing
      console.log('📧 Invite link (for manual testing):', inviteLink);
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'invited_member',
      description: `invited ${email.trim().toLowerCase()} to join as ${roleToUse}${teamNamesText}`,
      metadata: {
        invited_email: email.trim().toLowerCase(),
        role: roleToUse,
        team_ids: teamIdsArray,
        team_names: teamNames,
      },
    });

    // Return invitation with team information included
    const invitationWithTeams = {
      ...invitation,
      team_ids: teamIdsArray,
      team_names: teamNames,
      team_name: teamNames.length === 1 ? teamNames[0] : (teamNames.length > 1 ? teamNames.join(', ') : null), // For backward compatibility
    };

    res.status(201).json(invitationWithTeams);
  } catch (error: any) {
    console.error('Error creating invitation:', error);
    res.status(500).json({ error: error.message || 'Failed to create invitation' });
  }
});

// POST /api/organizations/:id/invitations/:invitationId/accept - Accept invitation
router.post('/:id/invitations/:invitationId/accept', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, invitationId } = req.params;

    // Get user's email from admin API
    const { data: { user }, error: userError } = await supabase.auth.admin.getUserById(userId);
    if (userError || !user?.email) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Get invitation
    const { data: invitation, error: invitationError } = await supabase
      .from('organization_invitations')
      .select('*')
      .eq('id', invitationId)
      .eq('organization_id', id)
      .eq('email', user.email.toLowerCase())
      .eq('status', 'pending')
      .single();

    if (invitationError || !invitation) {
      return res.status(404).json({ error: 'Invitation not found or already used' });
    }

    // Check if invitation is expired
    if (new Date(invitation.expires_at) < new Date()) {
      // Update status to expired
      await supabase
        .from('organization_invitations')
        .update({ status: 'expired' })
        .eq('id', invitationId);
      return res.status(400).json({ error: 'Invitation has expired' });
    }

    // Check if user is already a member
    const { data: existingMember } = await supabase
      .from('organization_members')
      .select('id')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (existingMember) {
      // User is already a member, just delete the invitation
      const { error: deleteError } = await supabase
        .from('organization_invitations')
        .delete()
        .eq('id', invitationId);

      if (deleteError) {
        console.error('Error deleting invitation for existing member:', deleteError);
      } else {
        console.log(`✅ Invitation ${invitationId} deleted for existing member`);
      }

      return res.json({ message: 'Already a member', organization_id: id });
    }

    // Validate that the role still exists in organization_roles
    // If the role was deleted after the invitation was sent, fallback to 'member'
    let roleToAssign = invitation.role;
    const { data: roleExists } = await supabase
      .from('organization_roles')
      .select('name')
      .eq('organization_id', id)
      .eq('name', invitation.role)
      .single();

    if (!roleExists) {
      console.warn(`⚠️ Role "${invitation.role}" no longer exists for organization ${id}. Falling back to 'member' role.`);
      roleToAssign = 'member';
    }

    // Add user as member
    const { error: memberError } = await supabase
      .from('organization_members')
      .insert({
        organization_id: id,
        user_id: userId,
        role: roleToAssign,
      });

    if (memberError) {
      throw memberError;
    }

    // Add user to teams from junction table (or fallback to team_id for backward compatibility)
    const { data: invitationTeams } = await supabase
      .from('invitation_teams')
      .select('team_id')
      .eq('invitation_id', invitationId);

    const teamIdsToAdd = invitationTeams && invitationTeams.length > 0
      ? invitationTeams.map(it => it.team_id)
      : (invitation.team_id ? [invitation.team_id] : []);

    if (teamIdsToAdd.length > 0) {
      for (const teamId of teamIdsToAdd) {
        const { error: teamMemberError } = await supabase
          .from('team_members')
          .insert({
            team_id: teamId,
            user_id: userId,
          });

        // Don't fail if user is already in team (duplicate key)
        if (teamMemberError && teamMemberError.code !== '23505') {
          console.error(`Error adding user to team ${teamId}:`, teamMemberError);
          // Continue anyway - user is added to org, just not to this team
        }
      }
    }

    // Delete the invitation after successful acceptance
    // This is cleaner than updating status and avoids RLS issues
    const { error: deleteError, data: deleteData } = await supabase
      .from('organization_invitations')
      .delete()
      .eq('id', invitationId)
      .select();

    if (deleteError) {
      console.error('Error deleting invitation:', deleteError);
      console.error('Delete error details:', JSON.stringify(deleteError, null, 2));
      // Don't fail the request - user is already added as member
      // But log it so we can debug
    } else {
      console.log(`✅ Invitation ${invitationId} deleted successfully`);
      if (deleteData && deleteData.length === 0) {
        console.warn(`⚠️ Invitation ${invitationId} was not found to delete (may have already been deleted)`);
      }
    }

    // Create activity log
    const { data: { user: newUser } } = await supabase.auth.admin.getUserById(userId);
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'new_member_joined',
      description: `${newUser?.email || userId} joined the organization${invitation.team_id ? ' and joined a team' : ''}`,
      metadata: {
        user_email: newUser?.email,
        role: invitation.role,
        team_id: invitation.team_id || null,
      },
    });

    res.json({ message: 'Invitation accepted', organization_id: id });
  } catch (error: any) {
    console.error('Error accepting invitation:', error);
    res.status(500).json({ error: error.message || 'Failed to accept invitation' });
  }
});

// DELETE /api/organizations/:id/invitations/:invitationId - Cancel invitation
router.delete('/:id/invitations/:invitationId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, invitationId } = req.params;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can cancel invitations' });
    }

    // Get invitation info for activity log
    const { data: invitation } = await supabase
      .from('organization_invitations')
      .select('email, role, team_id')
      .eq('id', invitationId)
      .single();

    // Delete invitation
    const { error: deleteError } = await supabase
      .from('organization_invitations')
      .delete()
      .eq('id', invitationId)
      .eq('organization_id', id)
      .eq('status', 'pending');

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    if (invitation) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'cancelled_invite',
        description: `cancelled invitation for ${invitation.email}`,
        metadata: {
          invited_email: invitation.email,
          role: invitation.role,
          team_id: invitation.team_id || null,
        },
      });
    }

    res.json({ message: 'Invitation cancelled' });
  } catch (error: any) {
    console.error('Error cancelling invitation:', error);
    res.status(500).json({ error: error.message || 'Failed to cancel invitation' });
  }
});

// POST /api/organizations/:id/invitations/:invitationId/resend - Resend invitation
router.post('/:id/invitations/:invitationId/resend', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, invitationId } = req.params;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can resend invitations' });
    }

    // Get invitation
    const { data: invitation, error: invitationError } = await supabase
      .from('organization_invitations')
      .select('*')
      .eq('id', invitationId)
      .eq('organization_id', id)
      .eq('status', 'pending')
      .single();

    if (invitationError || !invitation) {
      return res.status(404).json({ error: 'Invitation not found or already used' });
    }

    // Get organization name
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .select('name')
      .eq('id', id)
      .single();

    if (orgError || !organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Get team name if invitation has a team_id
    let teamName: string | undefined;
    if (invitation.team_id) {
      const { data: team } = await supabase
        .from('teams')
        .select('name')
        .eq('id', invitation.team_id)
        .single();
      teamName = team?.name;
    }

    // Get inviter info
    const { data: { user: inviter }, error: inviterError } = await supabase.auth.admin.getUserById(userId);
    const inviterName = inviter?.user_metadata?.full_name || inviter?.email || 'Someone';

    // Send invitation email
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const inviteLink = `${frontendUrl}/invite/${invitation.id}`;

    console.log(`Resending invitation for ${invitation.email} to join ${organization.name}${teamName ? ` (team: ${teamName})` : ''}`);
    try {
      await sendInvitationEmail(
        invitation.email,
        organization.name,
        inviterName,
        inviteLink,
        invitation.role,
        teamName
      );
      console.log('✅ Resend email sent successfully');
    } catch (emailError: any) {
      console.error('❌ Failed to resend invitation email:', emailError);
      console.error('Email error details:', emailError?.message || emailError);
      // Don't fail the request if email fails
      console.log('📧 Invite link (for manual testing):', inviteLink);
    }

    res.json({ message: 'Invitation resent', invitation });
  } catch (error: any) {
    console.error('Error resending invitation:', error);
    res.status(500).json({ error: error.message || 'Failed to resend invitation' });
  }
});

// POST /api/organizations/:id/join - Join organization via share link
router.post('/:id/join', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const teamId = req.query.team as string | undefined;

    // Get organization
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .select('id, name')
      .eq('id', id)
      .single();

    if (orgError || !organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Check if user is already a member
    const { data: existingMember } = await supabase
      .from('organization_members')
      .select('id')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    let isNewMember = false;
    if (!existingMember) {
      // Add user as member with default role 'member'
      const { error: memberError } = await supabase
        .from('organization_members')
        .insert({
          organization_id: id,
          user_id: userId,
          role: 'member',
        });

      if (memberError) {
        throw memberError;
      }
      isNewMember = true;
    }

    // If team_id is provided and user is a new member (or already a member), add to team
    if (teamId) {
      // Verify the team exists and belongs to this organization
      const { data: team, error: teamError } = await supabase
        .from('teams')
        .select('id, organization_id')
        .eq('id', teamId)
        .eq('organization_id', id)
        .single();

      if (!teamError && team) {
        // Check if user is already in the team
        const { data: existingTeamMember } = await supabase
          .from('team_members')
          .select('id')
          .eq('team_id', teamId)
          .eq('user_id', userId)
          .single();

        if (!existingTeamMember) {
          // Add user to team
          const { error: teamMemberError } = await supabase
            .from('team_members')
            .insert({
              team_id: teamId,
              user_id: userId,
            });

          if (teamMemberError) {
            console.error('Error adding user to team:', teamMemberError);
            // Don't fail the whole request if team addition fails
          }
        }
      }
    }

    res.json({
      message: isNewMember ? 'Successfully joined organization' : 'Already a member',
      organization_id: id
    });
  } catch (error: any) {
    console.error('Error joining organization:', error);
    res.status(500).json({ error: error.message || 'Failed to join organization' });
  }
});

// GET /api/organizations/invitations/:invitationId - Get invitation details (for public invite page)
router.get('/invitations/:invitationId', async (req, res) => {
  try {
    const { invitationId } = req.params;

    // Get invitation
    const { data: invitation, error: invitationError } = await supabase
      .from('organization_invitations')
      .select('*')
      .eq('id', invitationId)
      .eq('status', 'pending')
      .single();

    if (invitationError || !invitation) {
      return res.status(404).json({ error: 'Invitation not found or already used' });
    }

    // Check if expired
    if (new Date(invitation.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invitation has expired' });
    }

    // Get organization name
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .select('id, name')
      .eq('id', invitation.organization_id)
      .single();

    // Get teams from junction table
    const { data: invitationTeams } = await supabase
      .from('invitation_teams')
      .select('team_id, teams(name)')
      .eq('invitation_id', invitationId);

    const teamIds: string[] = [];
    const teamNames: string[] = [];

    if (invitationTeams && invitationTeams.length > 0) {
      invitationTeams.forEach((it: any) => {
        teamIds.push(it.team_id);
        if (it.teams?.name) {
          teamNames.push(it.teams.name);
        }
      });
    } else if (invitation.team_id) {
      // Fallback to team_id for backward compatibility
      const { data: team } = await supabase
        .from('teams')
        .select('name')
        .eq('id', invitation.team_id)
        .single();

      if (team) {
        teamIds.push(invitation.team_id);
        teamNames.push(team.name);
      }
    }

    res.json({
      id: invitation.id,
      email: invitation.email,
      role: invitation.role,
      organization_id: invitation.organization_id,
      organization_name: organization?.name || 'Organization',
      expires_at: invitation.expires_at,
      team_ids: teamIds,
      team_names: teamNames,
    });
  } catch (error: any) {
    console.error('Error fetching invitation:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch invitation' });
  }
});

// PUT /api/organizations/:id/members/:userId/role - Update member role
router.put('/:id/members/:userId/role', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, userId: targetUserId } = req.params;
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ error: 'Role is required' });
    }

    // Check if role is valid (default or custom)
    const defaultRoles = ['owner', 'admin', 'member'];
    const isValidDefault = defaultRoles.includes(role.toLowerCase());

    if (!isValidDefault) {
      // Check if it's a custom role
      const { data: customRole } = await supabase
        .from('organization_roles')
        .select('id')
        .eq('organization_id', id)
        .eq('name', role.toLowerCase())
        .single();

      if (!customRole) {
        return res.status(400).json({ error: 'Invalid role. Role must be owner, admin, member, or a custom role defined for this organization' });
      }
    }

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Get the acting user's rank
    const actorRank = await getUserRank(id, userId);
    if (!actorRank) {
      return res.status(403).json({ error: 'Could not determine your role rank' });
    }

    // Get the target user's rank
    const targetRank = await getUserRank(id, targetUserId);
    if (!targetRank) {
      return res.status(404).json({ error: 'Target user not found in organization' });
    }

    // Get the new role's rank
    const newRoleRank = await getRoleRank(id, role);
    if (newRoleRank === null) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Hierarchy check: Can only change role of members with rank > yours (higher number = lower rank)
    if (targetRank.rank <= actorRank.rank && userId !== targetUserId) {
      return res.status(403).json({ error: 'You can only change roles of members ranked below you' });
    }

    // Hierarchy check: Can only assign roles with rank >= yours
    if (newRoleRank < actorRank.rank) {
      return res.status(403).json({ error: 'You cannot assign a role higher than your own rank' });
    }

    // Prevent changing the last owner's role
    if (role !== 'owner') {
      const { data: owners } = await supabase
        .from('organization_members')
        .select('user_id')
        .eq('organization_id', id)
        .eq('role', 'owner');

      if (owners && owners.length === 1 && owners[0].user_id === targetUserId) {
        return res.status(400).json({ error: 'Cannot change the last owner\'s role' });
      }
    }

    // Get current role and user info
    const { data: currentMember } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', targetUserId)
      .single();

    const { data: { user: targetUser } } = await supabase.auth.admin.getUserById(targetUserId);

    // Get user profile for full name
    const { data: targetProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', targetUserId)
      .single();

    const targetDisplayName = targetProfile?.full_name || targetUser?.user_metadata?.full_name || targetUser?.email || targetUserId;

    // Update member role
    const { error: updateError } = await supabase
      .from('organization_members')
      .update({ role })
      .eq('organization_id', id)
      .eq('user_id', targetUserId);

    if (updateError) {
      throw updateError;
    }

    // Create activity log
    if (currentMember && currentMember.role !== role) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'changed_member_role',
        description: `changed ${targetDisplayName}'s role from ${currentMember.role} to ${role}`,
        metadata: {
          target_user_id: targetUserId,
          target_user_email: targetUser?.email,
          old_role: currentMember.role,
          new_role: role,
        },
      });
    }

    res.json({ message: 'Member role updated successfully' });
  } catch (error: any) {
    console.error('Error updating member role:', error);
    res.status(500).json({ error: error.message || 'Failed to update member role' });
  }
});

// DELETE /api/organizations/:id/members/:userId - Remove member from organization
router.delete('/:id/members/:userId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, userId: targetUserId } = req.params;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // If removing yourself, allow it (leave organization)
    if (userId === targetUserId) {
      // Prevent leaving if you're the last owner
      const { data: owners } = await supabase
        .from('organization_members')
        .select('user_id')
        .eq('organization_id', id)
        .eq('role', 'owner');

      if (owners && owners.length === 1 && owners[0].user_id === userId) {
        return res.status(400).json({ error: 'Please promote someone else to owner first before leaving' });
      }
    } else {
      // Get the acting user's rank
      const actorRank = await getUserRank(id, userId);
      if (!actorRank) {
        return res.status(403).json({ error: 'Could not determine your role rank' });
      }

      // Get the target user's rank
      const targetRank = await getUserRank(id, targetUserId);
      if (!targetRank) {
        return res.status(404).json({ error: 'Target user not found in organization' });
      }

      // Hierarchy check: Can only kick members with rank > yours (higher number = lower rank)
      if (targetRank.rank <= actorRank.rank) {
        return res.status(403).json({ error: 'You can only remove members ranked below you' });
      }

      // Prevent removing the last owner
      const { data: owners } = await supabase
        .from('organization_members')
        .select('user_id')
        .eq('organization_id', id)
        .eq('role', 'owner');

      if (owners && owners.length === 1 && owners[0].user_id === targetUserId) {
        return res.status(400).json({ error: 'Cannot remove the last owner' });
      }
    }

    // Remove member from all teams first
    const { data: teams } = await supabase
      .from('teams')
      .select('id')
      .eq('organization_id', id);

    if (teams && teams.length > 0) {
      const teamIds = teams.map(t => t.id);
      await supabase
        .from('team_members')
        .delete()
        .eq('user_id', targetUserId)
        .in('team_id', teamIds);
    }

    // Get user info for activity log
    const { data: { user: targetUser } } = await supabase.auth.admin.getUserById(targetUserId);

    // Get user profile for full name
    const { data: targetProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', targetUserId)
      .single();

    const targetDisplayName = targetProfile?.full_name || targetUser?.user_metadata?.full_name || targetUser?.email || targetUserId;

    // Delete all dependency notes authored by this user in this organization's projects
    const { data: orgProjects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', id);

    if (orgProjects && orgProjects.length > 0) {
      const projectIds = orgProjects.map(p => p.id);

      // Get all project_dependency_ids for these projects
      const { data: projectDeps } = await supabase
        .from('project_dependencies')
        .select('id')
        .in('project_id', projectIds);

      if (projectDeps && projectDeps.length > 0) {
        const projectDepIds = projectDeps.map(pd => pd.id);

        // Delete all notes by this user in these projects
        await supabase
          .from('dependency_notes')
          .delete()
          .eq('author_id', targetUserId)
          .in('project_dependency_id', projectDepIds);
      }
    }

    // Remove member from organization
    const { error: deleteError } = await supabase
      .from('organization_members')
      .delete()
      .eq('organization_id', id)
      .eq('user_id', targetUserId);

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    if (userId === targetUserId) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'left_org',
        description: `left the organization`,
        metadata: { user_email: targetUser?.email },
      });
    } else {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'removed_member',
        description: `removed ${targetDisplayName} from the organization`,
        metadata: {
          removed_user_id: targetUserId,
          removed_user_email: targetUser?.email,
        },
      });
    }

    res.json({ message: userId === targetUserId ? 'Left organization successfully' : 'Member removed successfully' });
  } catch (error: any) {
    console.error('Error removing member:', error);
    res.status(500).json({ error: error.message || 'Failed to remove member' });
  }
});

// PUT /api/organizations/:id - Update organization
router.put('/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { name, avatar_url } = req.body;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins and owners can update organization' });
    }

    // Get current organization data for activity logs
    const { data: currentOrg } = await supabase
      .from('organizations')
      .select('name')
      .eq('id', id)
      .single();

    const updateData: any = {};
    if (name !== undefined) updateData.name = name;
    if (avatar_url !== undefined) updateData.avatar_url = avatar_url;
    updateData.updated_at = new Date().toISOString();

    const { data: organization, error: updateError } = await supabase
      .from('organizations')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }

    // Create activity logs
    if (name !== undefined && name !== currentOrg?.name) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'updated_org_name',
        description: `updated organization name from "${currentOrg?.name}" to "${name}"`,
        metadata: { old_name: currentOrg?.name, new_name: name },
      });
    }

    if (avatar_url !== undefined) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'changed_org_profile_image',
        description: `changed organization profile image`,
        metadata: { organization_name: organization.name },
      });
    }

    res.json(organization);
  } catch (error: any) {
    console.error('Error updating organization:', error);
    res.status(500).json({ error: error.message || 'Failed to update organization' });
  }
});

// DELETE /api/organizations/:id - Delete organization
router.delete('/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Check if user is owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner') {
      return res.status(403).json({ error: 'Only owners can delete organization' });
    }

    // Delete organization (cascade will handle members, teams, etc.)
    const { error: deleteError } = await supabase
      .from('organizations')
      .delete()
      .eq('id', id);

    if (deleteError) {
      throw deleteError;
    }

    res.json({ message: 'Organization deleted successfully' });
  } catch (error: any) {
    console.error('Error deleting organization:', error);
    res.status(500).json({ error: error.message || 'Failed to delete organization' });
  }
});

// POST /api/organizations/:id/transfer-ownership - Transfer ownership
router.post('/:id/transfer-ownership', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { user_id: targetUserId, new_role = 'admin' } = req.body;

    if (!targetUserId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // Validate new_role
    if (new_role === 'owner') {
      return res.status(400).json({ error: 'Cannot set new role to owner' });
    }

    // Check if role is valid (default or custom)
    const defaultRoles = ['admin', 'member'];
    const isValidDefault = defaultRoles.includes(new_role.toLowerCase());

    if (!isValidDefault) {
      // Check if it's a custom role
      const { data: customRole } = await supabase
        .from('organization_roles')
        .select('id')
        .eq('organization_id', id)
        .eq('name', new_role.toLowerCase())
        .single();

      if (!customRole) {
        return res.status(400).json({ error: 'Invalid role. Role must be admin, member, or a custom role defined for this organization' });
      }
    }

    // Check if user is owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership || membership.role !== 'owner') {
      return res.status(403).json({ error: 'Only owners can transfer ownership' });
    }

    // Prevent transferring to self
    if (targetUserId === userId) {
      return res.status(400).json({ error: 'Cannot transfer ownership to yourself' });
    }

    // Check if target user is a member
    const { data: targetMembership, error: targetError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', targetUserId)
      .single();

    if (targetError || !targetMembership) {
      return res.status(404).json({ error: 'User is not a member of this organization' });
    }

    // Get target user info for activity
    const { data: { user: targetUser } } = await supabase.auth.admin.getUserById(targetUserId);

    // Get user profile for full name
    const { data: targetProfile } = await supabase
      .from('user_profiles')
      .select('full_name')
      .eq('user_id', targetUserId)
      .single();

    const targetDisplayName = targetProfile?.full_name || targetUser?.user_metadata?.full_name || targetUser?.email || targetUserId;

    // Transfer ownership: make current owner the specified new role, make target user owner
    await supabase
      .from('organization_members')
      .update({ role: new_role.toLowerCase() })
      .eq('organization_id', id)
      .eq('user_id', userId);

    await supabase
      .from('organization_members')
      .update({ role: 'owner' })
      .eq('organization_id', id)
      .eq('user_id', targetUserId);

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'transferred_ownership',
      description: `transferred ownership to ${targetDisplayName}`,
      metadata: {
        target_user_id: targetUserId,
        target_user_email: targetUser?.email,
        new_role: new_role.toLowerCase(),
      },
    });

    res.json({ message: 'Ownership transferred successfully' });
  } catch (error: any) {
    console.error('Error transferring ownership:', error);
    res.status(500).json({ error: error.message || 'Failed to transfer ownership' });
  }
});

// GET /api/organizations/:id/roles - Get all roles (default and custom)
router.get('/:id/roles', async (req: AuthRequest, res) => {
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

    // Get all roles (default and custom) from database
    const { data: roles, error: rolesError } = await supabase
      .from('organization_roles')
      .select('*')
      .eq('organization_id', id)
      .order('display_order', { ascending: true });

    if (rolesError) {
      throw rolesError;
    }

    // If no roles exist, ensure default roles are created
    if (!roles || roles.length === 0) {
      // This should be handled by the migration, but as a fallback:
      // Return empty array - the frontend can handle this
      res.json([]);
      return;
    }

    res.json(roles);
  } catch (error: any) {
    console.error('Error fetching roles:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch roles' });
  }
});

// POST /api/organizations/:id/roles - Create custom role
router.post('/:id/roles', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { name, display_name, display_order, permissions, color } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Role name is required' });
    }

    // Validate color hex code if provided
    if (color && !/^#([0-9A-F]{3}){1,2}$/i.test(color)) {
      return res.status(400).json({ error: 'Invalid color format. Must be a hex code (e.g. #FF0000)' });
    }

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Get the acting user's rank
    const actorRank = await getUserRank(id, userId);
    if (!actorRank) {
      return res.status(403).json({ error: 'Could not determine your role rank' });
    }

    // Check if role already exists
    const { data: existingRole } = await supabase
      .from('organization_roles')
      .select('id')
      .eq('organization_id', id)
      .eq('name', name.toLowerCase())
      .single();

    if (existingRole) {
      return res.status(400).json({ error: 'Role with this name already exists' });
    }

    // Default permissions: all false for custom roles
    const defaultPermissions = {
      view_settings: false,
      view_activity: false,
      manage_compliance: false,
      interact_with_security_agent: false,
      view_members: false,
      add_members: false,
      edit_roles: false,
      kick_members: false,
      manage_teams_and_projects: false,
    };

    // Use provided permissions or default to all false
    const rolePermissions = permissions || defaultPermissions;

    // Get current max display_order to place new role at the end
    const { data: existingRoles } = await supabase
      .from('organization_roles')
      .select('display_order')
      .eq('organization_id', id)
      .order('display_order', { ascending: false })
      .limit(1);

    let newDisplayOrder = display_order !== undefined
      ? display_order
      : (existingRoles && existingRoles.length > 0 ? existingRoles[0].display_order + 1 : 1);

    // Hierarchy check: Cannot create role with rank 0 (reserved for owner)
    if (newDisplayOrder === 0) {
      return res.status(400).json({ error: 'Rank 0 is reserved for the owner role' });
    }

    // Hierarchy check: Cannot create role with rank higher than yours (lower number)
    if (newDisplayOrder < actorRank.rank) {
      return res.status(403).json({ error: 'You cannot create a role ranked higher than yourself' });
    }

    const { data: role, error: createError } = await supabase
      .from('organization_roles')
      .insert({
        organization_id: id,
        name: name.toLowerCase(),
        display_name: display_name || name,
        display_order: newDisplayOrder,
        permissions: rolePermissions,
        color,
        is_default: false,
      })
      .select()
      .single();

    if (createError) {
      throw createError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'created_role',
      description: `created role "${display_name || name}"`,
      metadata: { role_name: display_name || name, role_id: role.id },
    });

    res.json(role);
  } catch (error: any) {
    console.error('Error creating role:', error);
    res.status(500).json({ error: error.message || 'Failed to create role' });
  }
});

// PUT /api/organizations/:id/roles/:roleId - Update role (name, display_name, permissions)
router.put('/:id/roles/:roleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, roleId } = req.params;
    const { name, display_name, permissions, display_order, color } = req.body;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Get the acting user's rank
    const actorRank = await getUserRank(id, userId);
    if (!actorRank) {
      return res.status(403).json({ error: 'Could not determine your role rank' });
    }

    // Check if role exists
    const { data: existingRole, error: roleError } = await supabase
      .from('organization_roles')
      .select('*')
      .eq('id', roleId)
      .eq('organization_id', id)
      .single();

    if (roleError || !existingRole) {
      return res.status(404).json({ error: 'Role not found' });
    }

    // Special handling for owner role - only allow color and display_name changes
    if (existingRole.name === 'owner') {
      if (permissions !== undefined || name !== undefined || display_order !== undefined) {
        return res.status(403).json({ error: 'Only color and display name can be modified for the owner role' });
      }
    } else {
      // Hierarchy check: Can only edit roles with rank >= yours (higher number = lower rank)
      if (existingRole.display_order < actorRank.rank) {
        return res.status(403).json({ error: 'You can only edit roles ranked at or below your level' });
      }
    }

    // If updating display_order (rank), validate the new rank
    if (display_order !== undefined) {
      // Cannot set rank to 0 (owner rank is reserved)
      if (display_order === 0) {
        return res.status(400).json({ error: 'Rank 0 is reserved for the owner role' });
      }
      // Cannot set rank higher than your own (lower number)
      if (display_order < actorRank.rank) {
        return res.status(403).json({ error: 'You cannot promote a role above your own rank' });
      }
    }

    // If updating name, check for conflicts (but allow same name)
    if (name && name.toLowerCase() !== existingRole.name) {
      const { data: conflictingRole } = await supabase
        .from('organization_roles')
        .select('id')
        .eq('organization_id', id)
        .eq('name', name.toLowerCase())
        .neq('id', roleId)
        .single();

      if (conflictingRole) {
        return res.status(400).json({ error: 'Role with this name already exists' });
      }
    }

    // Special check for default roles
    if (existingRole.is_default) {
      // Prevent changing name of default roles
      if (name && name.toLowerCase() !== existingRole.name) {
        return res.status(400).json({ error: 'Cannot change name of default roles' });
      }
    }

    // Build update object
    const updateData: any = {
      updated_at: new Date().toISOString(),
    };

    if (name !== undefined) {
      updateData.name = name.toLowerCase();
    }
    if (display_name !== undefined) {
      updateData.display_name = display_name;
    }
    if (permissions !== undefined) {
      updateData.permissions = permissions;
    }
    if (display_order !== undefined) {
      updateData.display_order = display_order;
    }
    if (color !== undefined) {
      // Validate color hex code if provided
      if (color && !/^#([0-9A-F]{3}){1,2}$/i.test(color)) {
        return res.status(400).json({ error: 'Invalid color format. Must be a hex code (e.g. #FF0000)' });
      }
      updateData.color = color;
    }

    // Update the role
    const { data: updatedRole, error: updateError } = await supabase
      .from('organization_roles')
      .update(updateData)
      .eq('id', roleId)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }

    // Calculate detailed changes for activity log
    const metadata: any = {
      role_name: updatedRole.display_name || updatedRole.name,
      role_id: updatedRole.id,
    };

    // Track name changes
    if (display_name !== undefined && display_name !== existingRole.display_name) {
      metadata.name_changed = true;
      metadata.old_name = existingRole.display_name || existingRole.name;
      metadata.new_name = display_name;
    }

    // Track color changes
    if (color !== undefined && color !== existingRole.color) {
      metadata.color_changed = true;
      metadata.old_color = existingRole.color;
      metadata.new_color = color;
    }

    // Track permission changes
    if (permissions !== undefined) {
      const oldPerms = existingRole.permissions || {};
      const newPerms = permissions;
      const addedPermissions: string[] = [];
      const removedPermissions: string[] = [];

      // Check all permission keys
      const allPermissionKeys = [
        'view_settings', 'manage_billing', 'manage_security', 'view_activity', 'manage_compliance', 'interact_with_security_agent',
        'view_members', 'add_members', 'edit_roles', 'edit_permissions',
        'kick_members', 'manage_teams_and_projects', 'manage_integrations', 'manage_notifications', 'view_overview'
      ];

      for (const key of allPermissionKeys) {
        const oldValue = oldPerms[key] || false;
        const newValue = newPerms[key] || false;
        if (!oldValue && newValue) {
          addedPermissions.push(key);
        } else if (oldValue && !newValue) {
          removedPermissions.push(key);
        }
      }

      if (addedPermissions.length > 0 || removedPermissions.length > 0) {
        metadata.permissions_changed = true;
        if (addedPermissions.length > 0) {
          metadata.added_permissions = addedPermissions;
        }
        if (removedPermissions.length > 0) {
          metadata.removed_permissions = removedPermissions;
        }
      }
    }

    // Track rank changes separately
    if (display_order !== undefined && display_order !== existingRole.display_order) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'changed_role_rank',
        description: `changed rank of role "${updatedRole.display_name || updatedRole.name}"`,
        metadata: {
          role_name: updatedRole.display_name || updatedRole.name,
          role_id: updatedRole.id,
          old_rank: existingRole.display_order,
          new_rank: display_order,
        },
      });
    }

    // Create activity log for other changes (if any)
    if (metadata.name_changed || metadata.color_changed || metadata.permissions_changed) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'changed_role_settings',
        description: `changed settings for role "${updatedRole.display_name || updatedRole.name}"`,
        metadata,
      });
    }

    res.json(updatedRole);
  } catch (error: any) {
    console.error('Error updating role:', error);
    res.status(500).json({ error: error.message || 'Failed to update role' });
  }
});

// DELETE /api/organizations/:id/roles/:roleId - Delete custom role
router.delete('/:id/roles/:roleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, roleId } = req.params;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Get the acting user's rank
    const actorRank = await getUserRank(id, userId);
    if (!actorRank) {
      return res.status(403).json({ error: 'Could not determine your role rank' });
    }

    // Check if role exists and is not a default role
    const { data: role, error: roleError } = await supabase
      .from('organization_roles')
      .select('*')
      .eq('id', roleId)
      .eq('organization_id', id)
      .single();

    if (roleError || !role) {
      return res.status(404).json({ error: 'Role not found' });
    }

    if (role.is_default) {
      return res.status(400).json({ error: 'Cannot delete default roles' });
    }

    // Hierarchy check: Can only delete roles with rank > yours (strictly lower rank)
    if (role.display_order <= actorRank.rank) {
      return res.status(403).json({ error: 'You can only delete roles ranked below your level' });
    }

    // Check if any members have this role
    const { data: membersWithRole } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', id)
      .eq('role', role.name)
      .limit(1);

    if (membersWithRole && membersWithRole.length > 0) {
      return res.status(400).json({ error: 'Cannot delete role that is assigned to members' });
    }

    // Check if any pending invitations have this role
    const { data: invitationsWithRole } = await supabase
      .from('organization_invitations')
      .select('id')
      .eq('organization_id', id)
      .eq('role', role.name)
      .eq('status', 'pending')
      .limit(1);

    if (invitationsWithRole && invitationsWithRole.length > 0) {
      return res.status(400).json({ error: 'Cannot delete role that has pending invitations. Please cancel those invitations first.' });
    }

    // Store role name before deletion for activity log
    const roleName = role.display_name || role.name;

    const { error: deleteError } = await supabase
      .from('organization_roles')
      .delete()
      .eq('id', roleId);

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'deleted_role',
      description: `deleted role "${roleName}"`,
      metadata: {
        role_name: roleName,
        role_id: roleId,
      },
    });

    res.json({ message: 'Role deleted successfully' });
  } catch (error: any) {
    console.error('Error deleting role:', error);
    res.status(500).json({ error: error.message || 'Failed to delete role' });
  }
});

// GET /api/organizations/:id/policies - Get organization policies (policy as code + backward-compat shape)
router.get('/:id/policies', async (req: AuthRequest, res) => {
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

    // Get policies (policy_code only)
    const { data: policies, error: policiesError } = await supabase
      .from('organization_policies')
      .select('policy_code')
      .eq('organization_id', id)
      .single();

    if (policiesError) {
      // If no policies exist, return default structure
      if (policiesError.code === 'PGRST116') {
        return res.json({
          policy_code: '',
          accepted_licenses: [],
          rejected_licenses: [],
          slsa_enforcement: 'none',
          slsa_level: null,
        });
      }
      throw policiesError;
    }

    const policyCode = policies?.policy_code ?? '';

    res.json({
      policy_code: policyCode,
      accepted_licenses: [],
      rejected_licenses: [],
      slsa_enforcement: 'none',
      slsa_level: null,
    });
  } catch (error: any) {
    console.error('Error fetching policies:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch policies' });
  }
});

// PUT /api/organizations/:id/policies - Update organization policies (policy as code)
router.put('/:id/policies', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { policy_code: policyCode } = req.body;

    // Check if user is admin or owner
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      const { data: roles } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      if (!roles?.permissions?.manage_compliance) {
        return res.status(403).json({ error: 'Only admins and owners can update policies' });
      }
    }

    // Validate policy_code
    const code = typeof policyCode === 'string' ? policyCode : '';
    const MAX_POLICY_CODE_LENGTH = 100_000;
    if (code.length > MAX_POLICY_CODE_LENGTH) {
      return res.status(400).json({ error: `policy_code must be at most ${MAX_POLICY_CODE_LENGTH} characters` });
    }

    // Check if policies exist for activity log
    const { data: existingPolicies } = await supabase
      .from('organization_policies')
      .select('id, policy_code')
      .eq('organization_id', id)
      .single();

    const policiesData: Record<string, unknown> = {
      organization_id: id,
      policy_code: code,
      updated_at: new Date().toISOString(),
    };

    let result: { policy_code?: string };
    if (existingPolicies) {
      const { data: updated, error: updateError } = await supabase
        .from('organization_policies')
        .update(policiesData)
        .eq('organization_id', id)
        .select('policy_code')
        .single();

      if (updateError) throw updateError;
      result = updated;
    } else {
      const { data: created, error: createError } = await supabase
        .from('organization_policies')
        .insert(policiesData)
        .select('policy_code')
        .single();

      if (createError) throw createError;
      result = created;
    }

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'updated_policy',
      description: 'updated organization policies',
      metadata: {
        policy_code_length: (result?.policy_code ?? code).length,
      },
    });

    updateAllProjectsCompliance(id).catch((err) => {
      console.error('Error updating projects compliance after policy change:', err);
    });

    await invalidateAllProjectCachesInOrg(id, { policiesOnly: true }).catch(() => {});

    const savedCode = result?.policy_code ?? code;
    res.json({
      policy_code: savedCode,
      accepted_licenses: [],
      rejected_licenses: [],
      slsa_enforcement: 'none',
      slsa_level: null,
    });
  } catch (error: any) {
    console.error('Error updating policies:', error);
    res.status(500).json({ error: error.message || 'Failed to update policies' });
  }
});

// Helper to check manage_integrations (owner/admin or custom role with permission)
async function canManageNotificationRules(organizationId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (!membership) return false;
  if (membership.role === 'owner' || membership.role === 'admin') return true;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();

  const perms = role?.permissions as Record<string, boolean> | undefined;
  return !!(perms?.manage_integrations || perms?.manage_notifications);
}

// GET /api/organizations/:id/notification-rules - List notification rules
router.get('/:id/notification-rules', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: rules, error } = await supabase
      .from('organization_notification_rules')
      .select('*')
      .eq('organization_id', id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const mapped = (rules ?? []).map((r: Record<string, unknown>) => ({
      id: r.id,
      name: r.name,
      triggerType: r.trigger_type,
      minDepscoreThreshold: r.min_depscore_threshold ?? undefined,
      customCode: r.custom_code ?? undefined,
      destinations: r.destinations ?? [],
      active: r.active ?? true,
      createdByUserId: r.created_by_user_id ?? undefined,
      createdByName: r.created_by_name ?? undefined,
    }));

    res.json(mapped);
  } catch (error: any) {
    console.error('Error fetching notification rules:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch notification rules' });
  }
});

// POST /api/organizations/:id/notification-rules - Create notification rule
router.post('/:id/notification-rules', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { name, triggerType, minDepscoreThreshold, customCode, destinations, createdByName } = req.body;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'name is required' });
    }
    const validTriggers = ['weekly_digest', 'vulnerability_discovered', 'custom_code_pipeline'];
    if (!triggerType || !validTriggers.includes(triggerType)) {
      return res.status(400).json({ error: 'triggerType must be one of: weekly_digest, vulnerability_discovered, custom_code_pipeline' });
    }

    const dests = Array.isArray(destinations) ? destinations : [];
    const insertData: Record<string, unknown> = {
      organization_id: id,
      name: name.trim(),
      trigger_type: triggerType,
      destinations: dests,
      active: true,
      created_by_user_id: userId,
      created_by_name: typeof createdByName === 'string' ? createdByName : null,
    };
    if (triggerType === 'vulnerability_discovered' && typeof minDepscoreThreshold === 'number') {
      insertData.min_depscore_threshold = minDepscoreThreshold;
    }
    if (triggerType === 'custom_code_pipeline' && typeof customCode === 'string') {
      insertData.custom_code = customCode;
    }

    const { data: created, error } = await supabase
      .from('organization_notification_rules')
      .insert(insertData)
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      id: created.id,
      name: created.name,
      triggerType: created.trigger_type,
      minDepscoreThreshold: created.min_depscore_threshold ?? undefined,
      customCode: created.custom_code ?? undefined,
      destinations: created.destinations ?? [],
      active: created.active ?? true,
      createdByUserId: created.created_by_user_id ?? undefined,
      createdByName: created.created_by_name ?? undefined,
    });
  } catch (error: any) {
    console.error('Error creating notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to create notification rule' });
  }
});

// PUT /api/organizations/:id/notification-rules/:ruleId - Update notification rule
router.put('/:id/notification-rules/:ruleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, ruleId } = req.params;
    const { name, triggerType, minDepscoreThreshold, customCode, destinations } = req.body;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    const validTriggers = ['weekly_digest', 'vulnerability_discovered', 'custom_code_pipeline'];
    const updateData: Record<string, unknown> = {};
    if (typeof name === 'string') updateData.name = name.trim();
    if (triggerType && validTriggers.includes(triggerType)) updateData.trigger_type = triggerType;
    if (triggerType === 'vulnerability_discovered') {
      updateData.min_depscore_threshold = typeof minDepscoreThreshold === 'number' ? minDepscoreThreshold : null;
    } else {
      updateData.min_depscore_threshold = null;
    }
    if (triggerType === 'custom_code_pipeline') {
      updateData.custom_code = typeof customCode === 'string' ? customCode : null;
    } else {
      updateData.custom_code = null;
    }
    if (Array.isArray(destinations)) updateData.destinations = destinations;

    const { data: updated, error } = await supabase
      .from('organization_notification_rules')
      .update(updateData)
      .eq('id', ruleId)
      .eq('organization_id', id)
      .select()
      .single();

    if (error) throw error;
    if (!updated) return res.status(404).json({ error: 'Notification rule not found' });

    res.json({
      id: updated.id,
      name: updated.name,
      triggerType: updated.trigger_type,
      minDepscoreThreshold: updated.min_depscore_threshold ?? undefined,
      customCode: updated.custom_code ?? undefined,
      destinations: updated.destinations ?? [],
      active: updated.active ?? true,
      createdByUserId: updated.created_by_user_id ?? undefined,
      createdByName: updated.created_by_name ?? undefined,
    });
  } catch (error: any) {
    console.error('Error updating notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to update notification rule' });
  }
});

// DELETE /api/organizations/:id/notification-rules/:ruleId - Delete notification rule
router.delete('/:id/notification-rules/:ruleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, ruleId } = req.params;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    const { error } = await supabase
      .from('organization_notification_rules')
      .delete()
      .eq('id', ruleId)
      .eq('organization_id', id);

    if (error) throw error;
    res.json({ message: 'Notification rule deleted' });
  } catch (error: any) {
    console.error('Error deleting notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to delete notification rule' });
  }
});

// POST /api/organizations/:id/notifications/ai-assist - AI assistant for notification rule trigger code (SSE streaming)
router.post('/:id/notifications/ai-assist', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { message, currentCode, conversationHistory } = req.body;

    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message is required' });
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const NOTIFICATION_TYPEDEFS = `
type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';
type AnalysisStatus = 'pass' | 'warning' | 'fail';

interface NotificationEvent {
  type: 'vulnerability_discovered' | 'dependency_added' | 'dependency_updated'
      | 'dependency_removed' | 'compliance_violation' | 'risk_score_changed'
      | 'license_violation' | 'supply_chain_anomaly' | 'new_version_available'
      | 'security_analysis_failure';
}

interface Vulnerability {
  osv_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score: number;       // 0.0 - 10.0
  epss_score: number;       // 0.0 - 1.0
  depscore: number;         // 0 - 100, composite risk score
  is_reachable: boolean;
  cisa_kev: boolean;
  fixed_versions: string[];
  summary: string;
}

interface Dependency {
  name: string;
  version: string;
  license: string;          // SPDX identifier e.g. "MIT"
  is_direct: boolean;
  environment: string;      // "production" or "development"
  score: number;            // Deptex reputation 0-100
  openssf_score: number;    // OpenSSF Scorecard 0.0-10.0
  weekly_downloads: number;
  registry_integrity_status: AnalysisStatus;
  install_scripts_status: AnalysisStatus;
  entropy_analysis_status: AnalysisStatus;
  vulnerabilities: Vulnerability[];
}

interface Project {
  name: string;
  asset_tier: AssetTier;
  health_score: number;     // 0-100
  is_compliant: boolean;
  dependencies_count: number;
}

interface PreviousState {
  health_score?: number;
  is_compliant?: boolean;
}

interface NotificationContext {
  event: NotificationEvent;
  project: Project;
  dependency: Dependency | null;
  vulnerability: Vulnerability | null;
  previous: PreviousState | null;
}`;

    const NOTIFICATION_EXAMPLES = `
EXAMPLE 1 - High Depscore vulnerability alert:
\`\`\`
if (context.event.type !== 'vulnerability_discovered') return false;
if (!context.vulnerability) return false;
return context.vulnerability.depscore > 75;
\`\`\`

EXAMPLE 2 - Critical reachable vulnerabilities only:
\`\`\`
if (context.event.type !== 'vulnerability_discovered') return false;
if (!context.vulnerability) return false;
return context.vulnerability.severity === 'critical' && context.vulnerability.is_reachable;
\`\`\`

EXAMPLE 3 - New dependencies with low OpenSSF score:
\`\`\`
if (context.event.type !== 'dependency_added') return false;
if (!context.dependency) return false;
return context.dependency.is_direct && context.dependency.openssf_score < 3;
\`\`\`

EXAMPLE 4 - Supply chain security failures:
\`\`\`
if (!context.dependency) return false;
var types = ['dependency_added', 'dependency_updated', 'security_analysis_failure'];
if (types.indexOf(context.event.type) === -1) return false;
return context.dependency.registry_integrity_status === 'fail'
    || context.dependency.install_scripts_status === 'fail'
    || context.dependency.entropy_analysis_status === 'fail';
\`\`\`

EXAMPLE 5 - Crown Jewel projects — any vulnerability:
\`\`\`
if (context.event.type !== 'vulnerability_discovered') return false;
return context.project.asset_tier === 'CROWN_JEWELS';
\`\`\`

EXAMPLE 6 - License violation for banned licenses:
\`\`\`
if (context.event.type !== 'license_violation') return false;
if (!context.dependency) return false;
var BANNED = ['AGPL-3.0', 'GPL-3.0', 'SSPL-1.0'];
return BANNED.some(function(b) { return (context.dependency.license || '').indexOf(b) !== -1; });
\`\`\``;

    const systemPrompt = `You are an expert AI assistant that helps users write Deptex notification rule trigger functions. You write JavaScript function bodies that decide whether to send a notification.

## Trigger Event Types
- vulnerability_discovered: New vulnerability found in a dependency
- dependency_added: New dependency added to a project
- dependency_updated: Dependency version changed
- dependency_removed: Dependency removed from a project
- compliance_violation: Project compliance check failed
- risk_score_changed: Project health score crossed a threshold
- license_violation: Dependency with banned/unapproved license detected
- supply_chain_anomaly: Suspicious commit or anomaly detected
- new_version_available: Newer version of a dependency published
- security_analysis_failure: Registry integrity, install scripts, or entropy check failed

## Type Definitions
${NOTIFICATION_TYPEDEFS}

## Example Trigger Functions
${NOTIFICATION_EXAMPLES}

## Your Task
The user is editing the body of a trigger function that receives \`context: NotificationContext\`. You write ONLY the function body — do NOT include the function declaration or wrapping braces. The variable \`context\` is available.

The function must return \`true\` to trigger the notification, or \`false\` to skip it. Use plain JavaScript (no TypeScript, no ES module syntax). You may use var instead of const/let for compatibility.

## Current Code State
Current trigger function body:
\`\`\`
${typeof currentCode === 'string' ? currentCode : '// Return true to trigger notification, false to skip\nreturn false;'}
\`\`\`

## Response Format
Respond with a JSON object. ONLY output valid JSON, nothing else:
{
  "message": "Brief explanation of what the code does",
  "code": "the complete function body as a string, or null if just answering a question"
}

If the user is asking a question (not requesting code), set "code" to null and answer in "message".
When providing code, always provide the COMPLETE function body, not a partial diff.`;

    const messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }> = [
      { role: 'system', content: systemPrompt },
    ];

    if (Array.isArray(conversationHistory)) {
      for (const msg of conversationHistory) {
        if (msg.role === 'user' || msg.role === 'assistant') {
          messages.push({ role: msg.role, content: msg.content });
        }
      }
    }

    messages.push({ role: 'user', content: message });

    const openai = getOpenAIClient();
    const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';

    const stream = await openai.chat.completions.create({
      model,
      messages,
      stream: true,
    });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    let fullContent = '';

    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content;
      if (delta) {
        fullContent += delta;
        res.write(`data: ${JSON.stringify({ type: 'chunk', content: delta })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ type: 'done', fullContent })}\n\n`);
    res.end();
  } catch (error: any) {
    console.error('Error in notification AI assist:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: error.message || 'Failed to generate notification trigger code' });
    } else {
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message || 'Failed to generate notification trigger code' })}\n\n`);
      res.end();
    }
  }
});

// POST /api/organizations/:id/policies/recommend - Recommend policies based on description
router.post('/:id/policies/recommend', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { description } = req.body;

    if (!description || typeof description !== 'string') {
      return res.status(400).json({ error: 'Description is required' });
    }

    // Check if user is a member
    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Check permissions (owner, admin, or has manage_compliance)
    // First check role directly
    let hasPermission = membership.role === 'owner' || membership.role === 'admin';

    if (!hasPermission) {
      // Check custom role permissions
      const { data: role } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      if (role?.permissions?.manage_compliance) {
        hasPermission = true;
      }
    }

    if (!hasPermission) {
      return res.status(403).json({ error: 'You do not have permission to configure policies' });
    }

    const AVAILABLE_LICENSES = [
      'Apache License 2.0',
      'GNU General Public License v3.0',
      'MIT License',
      'MIT No Attribution (MIT-0)',
      'ISC License',
      'BSD Zero Clause License (0BSD)',
      'BSD 2-Clause "Simplified" License',
      'BSD 3-Clause "New" or "Revised" License',
      'Blue Oak Model License 1.0.0',
      'Boost Software License 1.0',
      'Creative Commons Zero v1.0 Universal',
      'Creative Commons Attribution 4.0',
      'Eclipse Public License 2.0',
      'GNU Affero General Public License v3.0',
      'GNU General Public License v2.0',
      'GNU Lesser General Public License v2.1',
      'Mozilla Public License 2.0',
      'Python License 2.0',
      'The Unlicense',
    ];

    const openai = getOpenAIClient();
    const systemPrompt = `You are a legal expert on open source software licensing and compliance.
Your task is to recommend a list of **ALLOWED third-party licenses** that this project should accept for its dependencies.
The user will describe their project, and you must determine which licenses are safe for them to use/import based on their project type.

The ONLY licenses you can recommend to be in the allowed list are:
${JSON.stringify(AVAILABLE_LICENSES, null, 2)}

Analyze the user's project description and select the most appropriate licenses to ALLOW from the list above.

Guidelines:
1. **Proprietary / SaaS / Commercial Projects**: 
   - You MUST recommend ALLOWING permissive licenses (MIT, Apache 2.0, BSD, Unlicense, ISC).
   - You should typically EXCLUDE strong copyleft licenses (GPL, AGPL) unless the user implies they are fine with open sourcing their code.
   
2. **Open Source Projects (Permissive)**:
   - Recommend ALLOWING permissive licenses.
   
3. **Open Source Projects (Copyleft)**:
   - Recommend ALLOWING both permissive AND copyleft licenses (GPL, MPL, etc).

4. **Specific Constraints**:
   - If the user mentions "Proprietary", "Commercial", "SaaS", or "Private", ensure you include standard permissive licenses (MIT, Apache) and exclude viral ones.
   
Return a JSON object with a single key "recommended_licenses" containing an array of strings of the licenses to ALLOW.`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4-turbo-preview",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: description }
      ],
      response_format: { type: "json_object" },
    });

    const content = completion.choices[0].message.content;
    if (!content) {
      throw new Error('Failed to generate recommendations');
    }

    const result = JSON.parse(content);

    // Filter to ensure only valid licenses are returned
    const validRecommendations = (result.recommended_licenses || []).filter((l: string) =>
      AVAILABLE_LICENSES.includes(l)
    );

    res.json({ recommended_licenses: validRecommendations });
  } catch (error: any) {
    console.error('Error recommending policies:', error);
    res.status(500).json({ error: error.message || 'Failed to generate recommendations' });
  }
});

// POST /api/organizations/:id/policies/ai-assist - AI assistant for writing policy code (SSE streaming)
router.post('/:id/policies/ai-assist', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { message, targetEditor, currentComplianceCode, currentPullRequestCode, conversationHistory } = req.body;

    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message is required' });
    }
    if (!targetEditor || (targetEditor !== 'compliance' && targetEditor !== 'pullRequest')) {
      return res.status(400).json({ error: 'targetEditor must be "compliance" or "pullRequest"' });
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const POLICY_TYPEDEFS = `
type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';
type AnalysisStatus = 'pass' | 'warning' | 'fail';

interface Vulnerability {
  osv_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score: number;       // 0.0 - 10.0
  epss_score: number;       // 0.0 - 1.0, higher = more likely exploited
  depscore: number;         // 0 - 100, composite risk score
  is_reachable: boolean;
  cisa_kev: boolean;
  fixed_versions: string[];
  aliases: string[];
  summary: string;
  published_at: string;
}

interface Dependency {
  name: string;
  version: string;
  license: string;          // SPDX identifier e.g. "MIT"
  is_direct: boolean;
  environment: string;      // "production", "development", etc.
  score: number;            // Deptex reputation 0-100
  openssf_score: number;    // OpenSSF Scorecard 0.0-10.0
  weekly_downloads: number;
  last_published_at: string;
  releases_last_12_months: number;
  files_importing_count: number;
  registry_integrity_status: AnalysisStatus;
  install_scripts_status: AnalysisStatus;
  entropy_analysis_status: AnalysisStatus;
  vulnerabilities: Vulnerability[];
}

interface UpdatedDependency extends Dependency {
  from_version: string;
  to_version: string;
}

interface RemovedDependency {
  name: string;
  version: string;
}

interface Project {
  name: string;
  asset_tier: AssetTier;
}

// pullRequestCheck receives:
interface PullRequestCheckContext {
  project: Project;
  added: Dependency[];
  updated: UpdatedDependency[];
  removed: RemovedDependency[];
}

// projectCompliance receives:
interface ProjectComplianceContext {
  project: Project;
  dependencies: Dependency[];
}

// pullRequestCheck must return:
interface PullRequestCheckResult { passed: boolean; violations: string[]; }

// projectCompliance must return:
interface ComplianceResult { compliant: boolean; violations: string[]; }`;

    const EXAMPLE_POLICIES = `
EXAMPLE 1 - License Allowlist (projectCompliance body):
\`\`\`
const ALLOWED = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"];
const violations = [];
for (const dep of context.dependencies) {
  const lic = dep.license || "UNKNOWN";
  if (!ALLOWED.some(a => lic.includes(a))) {
    violations.push(\`License \${lic} not allowed on \${dep.name}@\${dep.version}\`);
  }
}
return { compliant: violations.length === 0, violations };
\`\`\`

EXAMPLE 2 - Block critical reachable vulns (pullRequestCheck body):
\`\`\`
const violations = [];
for (const pkg of [...context.added, ...context.updated]) {
  for (const v of pkg.vulnerabilities) {
    if (v.severity === "critical" && v.is_reachable) {
      violations.push(\`\${v.osv_id} (depscore \${v.depscore}) in \${pkg.name}@\${pkg.version}\`);
    }
    if (v.cisa_kev) {
      violations.push(\`CISA KEV: \${v.osv_id} in \${pkg.name}@\${pkg.version}\`);
    }
  }
}
return { passed: violations.length === 0, violations };
\`\`\`

EXAMPLE 3 - Minimum OpenSSF score for new production deps (pullRequestCheck body):
\`\`\`
const violations = [];
for (const pkg of context.added) {
  if (pkg.is_direct && pkg.environment === "production" && pkg.openssf_score < 3) {
    violations.push(\`\${pkg.name} has OpenSSF score \${pkg.openssf_score} (min 3 for direct prod deps)\`);
  }
}
return { passed: violations.length === 0, violations };
\`\`\`

EXAMPLE 4 - Supply chain integrity (pullRequestCheck body):
\`\`\`
const violations = [];
for (const pkg of [...context.added, ...context.updated]) {
  if (pkg.registry_integrity_status === "fail")
    violations.push(\`Registry integrity failure: \${pkg.name}@\${pkg.version}\`);
  if (pkg.install_scripts_status === "fail")
    violations.push(\`Suspicious install scripts: \${pkg.name}@\${pkg.version}\`);
  if (pkg.entropy_analysis_status === "fail")
    violations.push(\`High entropy (obfuscation): \${pkg.name}@\${pkg.version}\`);
}
return { passed: violations.length === 0, violations };
\`\`\``;

    const targetFnName = targetEditor === 'compliance' ? 'projectCompliance' : 'pullRequestCheck';
    const targetReturnType = targetEditor === 'compliance'
      ? '{ compliant: boolean, violations: string[] }'
      : '{ passed: boolean, violations: string[] }';
    const targetContextType = targetEditor === 'compliance' ? 'ProjectComplianceContext' : 'PullRequestCheckContext';

    const systemPrompt = `You are an expert AI assistant that helps users write Deptex policy-as-code. You write JavaScript function bodies for dependency security policies.

## Type Definitions
${POLICY_TYPEDEFS}

## Example Policies
${EXAMPLE_POLICIES}

## Your Task
The user is editing the body of \`function ${targetFnName}(context: ${targetContextType})\`. You write ONLY the function body — do NOT include the function declaration or wrapping braces. The variable \`context\` is available.

The function must return ${targetReturnType}.

## Current Code State
Current ${targetEditor === 'compliance' ? 'Project Compliance' : 'Pull Request Check'} body:
\`\`\`
${targetEditor === 'compliance' ? (currentComplianceCode || 'return { compliant: true };') : (currentPullRequestCode || 'return { passed: true };')}
\`\`\`

${targetEditor === 'compliance' && currentPullRequestCode ? `Current Pull Request Check body (for reference):\n\`\`\`\n${currentPullRequestCode}\n\`\`\`` : ''}
${targetEditor === 'pullRequest' && currentComplianceCode ? `Current Project Compliance body (for reference):\n\`\`\`\n${currentComplianceCode}\n\`\`\`` : ''}

## Response Format
Respond with a JSON object. ONLY output valid JSON, nothing else:
{
  "message": "Brief explanation of what the code does",
  "code": "the complete function body as a string, or null if just answering a question"
}

If the user is asking a question (not requesting code), set "code" to null and answer in "message".
When providing code, always provide the COMPLETE function body, not a partial diff. Use plain JavaScript (no TypeScript syntax).`;

    const messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }> = [
      { role: 'system', content: systemPrompt },
    ];

    if (Array.isArray(conversationHistory)) {
      for (const msg of conversationHistory) {
        if (msg.role === 'user' || msg.role === 'assistant') {
          messages.push({ role: msg.role, content: msg.content });
        }
      }
    }

    messages.push({ role: 'user', content: message });

    const openai = getOpenAIClient();
    const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';

    const stream = await openai.chat.completions.create({
      model,
      messages,
      stream: true,
    });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    let fullContent = '';

    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content;
      if (delta) {
        fullContent += delta;
        res.write(`data: ${JSON.stringify({ type: 'chunk', content: delta })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ type: 'done', fullContent })}\n\n`);
    res.end();
  } catch (error: any) {
    console.error('Error in policy AI assist:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: error.message || 'Failed to generate policy code' });
    } else {
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message || 'Failed to generate policy code' })}\n\n`);
      res.end();
    }
  }
});

// POST /api/organizations/:id/deprecations - Deprecate a dependency org-wide (dependency_id required)
router.post('/:id/deprecations', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { dependency_id, recommended_alternative } = req.body;

    if (!recommended_alternative) {
      return res.status(400).json({ error: 'recommended_alternative is required' });
    }
    const resolvedDependencyId = dependency_id ?? null;
    if (!resolvedDependencyId) {
      return res.status(400).json({ error: 'dependency_id is required' });
    }

    // Check membership
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    // Check manage_teams_and_projects permission
    const isOwner = membership.role === 'owner';
    if (!isOwner) {
      const { data: orgRole } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      if (!orgRole?.permissions?.manage_teams_and_projects) {
        return res.status(403).json({ error: 'You do not have permission to manage deprecations' });
      }
    }

    const { data, error } = await supabase
      .from('organization_deprecations')
      .upsert(
        {
          organization_id: id,
          dependency_id: resolvedDependencyId,
          recommended_alternative: String(recommended_alternative).trim(),
          deprecated_by: userId,
          created_at: new Date().toISOString(),
        },
        { onConflict: 'organization_id,dependency_id' }
      )
      .select()
      .single();

    if (error) throw error;

    await invalidateAllProjectCachesInOrg(id, { depsOnly: true }).catch(() => {});
    res.json(data);
  } catch (error: any) {
    console.error('Error creating deprecation:', error);
    res.status(500).json({ error: error.message || 'Failed to create deprecation' });
  }
});

// DELETE /api/organizations/:id/deprecations/:dependencyId - Remove deprecation (dependencyId = UUID)
router.delete('/:id/deprecations/:dependencyId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, dependencyId } = req.params;

    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const isOwner = membership.role === 'owner';
    if (!isOwner) {
      const { data: orgRole } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      if (!orgRole?.permissions?.manage_teams_and_projects) {
        return res.status(403).json({ error: 'Cannot remove org level deprecations' });
      }
    }

    const { error } = await supabase
      .from('organization_deprecations')
      .delete()
      .eq('organization_id', id)
      .eq('dependency_id', dependencyId);

    if (error) throw error;

    await invalidateAllProjectCachesInOrg(id, { depsOnly: true }).catch(() => {});
    res.json({ success: true });
  } catch (error: any) {
    console.error('Error removing deprecation:', error);
    res.status(500).json({ error: error.message || 'Failed to remove deprecation' });
  }
});

// POST /api/organizations/:id/teams/:teamId/deprecations - Deprecate a dependency at team level (dependency_id required)
router.post('/:id/teams/:teamId/deprecations', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId } = req.params;
    const { dependency_id, recommended_alternative } = req.body;

    if (!recommended_alternative) {
      return res.status(400).json({ error: 'recommended_alternative is required' });
    }
    const resolvedDependencyId = dependency_id ?? null;
    if (!resolvedDependencyId) {
      return res.status(400).json({ error: 'dependency_id is required' });
    }

    const { data: team } = await supabase
      .from('teams')
      .select('id, organization_id')
      .eq('id', teamId)
      .eq('organization_id', id)
      .single();
    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    const { data: teamMembership } = await supabase
      .from('team_members')
      .select('role_id')
      .eq('team_id', teamId)
      .eq('user_id', userId)
      .single();
    if (!teamMembership?.role_id) {
      return res.status(403).json({ error: 'You are not a member of this team' });
    }
    const { data: teamRole } = await supabase
      .from('team_roles')
      .select('permissions')
      .eq('id', teamMembership.role_id)
      .single();
    if (!teamRole?.permissions?.manage_projects) {
      return res.status(403).json({ error: 'You need manage_projects permission in this team to deprecate dependencies' });
    }

    const { data, error } = await supabase
      .from('team_deprecations')
      .upsert(
        {
          team_id: teamId,
          dependency_id: resolvedDependencyId,
          recommended_alternative: String(recommended_alternative).trim(),
          deprecated_by: userId,
          created_at: new Date().toISOString(),
        },
        { onConflict: 'team_id,dependency_id' }
      )
      .select()
      .single();

    if (error) throw error;
    await invalidateProjectCachesForTeam(id, teamId).catch(() => {});
    res.json(data);
  } catch (error: any) {
    console.error('Error creating team deprecation:', error);
    res.status(500).json({ error: error.message || 'Failed to create deprecation' });
  }
});

// DELETE /api/organizations/:id/teams/:teamId/deprecations/:dependencyId - Remove team deprecation (dependencyId = UUID)
// Org manage can remove any team deprecation; team manage can only remove for their team.
router.delete('/:id/teams/:teamId/deprecations/:dependencyId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, teamId, dependencyId } = req.params;

    const { data: team } = await supabase
      .from('teams')
      .select('id, organization_id')
      .eq('id', teamId)
      .eq('organization_id', id)
      .single();
    if (!team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();
    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }
    const isOwner = membership.role === 'owner';
    let hasOrgManage = isOwner;
    if (!hasOrgManage) {
      const { data: orgRole } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();
      hasOrgManage = orgRole?.permissions?.manage_teams_and_projects === true;
    }

    if (!hasOrgManage) {
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role_id')
        .eq('team_id', teamId)
        .eq('user_id', userId)
        .single();
      if (!teamMembership?.role_id) {
        return res.status(403).json({ error: 'You are not a member of this team' });
      }
      const { data: teamRole } = await supabase
        .from('team_roles')
        .select('permissions')
        .eq('id', teamMembership.role_id)
        .single();
      if (!teamRole?.permissions?.manage_projects) {
        return res.status(403).json({ error: 'You need manage_projects permission to remove team deprecations' });
      }
    }

    const { error } = await supabase
      .from('team_deprecations')
      .delete()
      .eq('team_id', teamId)
      .eq('dependency_id', dependencyId);

    if (error) throw error;
    await invalidateProjectCachesForTeam(id, teamId).catch(() => {});
    res.json({ success: true });
  } catch (error: any) {
    console.error('Error removing team deprecation:', error);
    res.status(500).json({ error: error.message || 'Failed to remove deprecation' });
  }
});

// Dismiss the "Get Started" onboarding card for the entire organization.
// Any member can call this; it flips the org-level flag so everyone stops seeing the card.
router.post('/:id/dismiss-get-started', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    // Verify the caller is a member of this organization
    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { error: updateError } = await supabase
      .from('organizations')
      .update({ get_started_dismissed: true, updated_at: new Date().toISOString() })
      .eq('id', id);

    if (updateError) throw updateError;

    res.json({ success: true });
  } catch (error: any) {
    console.error('Error dismissing get started:', error);
    res.status(500).json({ error: error.message || 'Failed to dismiss get started' });
  }
});

// ---------------------------------------------------------------------------
// Team Notification / Integration routes
// ---------------------------------------------------------------------------

async function canManageTeamNotifications(orgId: string, teamId: string, userId: string): Promise<boolean> {
  // Org-level owner/admin can always manage
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;
  if (membership.role === 'owner' || membership.role === 'admin') return true;

  // Check org custom role permissions
  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();
  const orgPerms = orgRole?.permissions as Record<string, boolean> | undefined;
  if (orgPerms?.manage_notifications || orgPerms?.manage_integrations) return true;

  // Check team-level permission
  const { data: teamMembership } = await supabase
    .from('team_members')
    .select('role_id')
    .eq('team_id', teamId)
    .eq('user_id', userId)
    .single();
  if (!teamMembership?.role_id) return false;
  const { data: teamRole } = await supabase
    .from('team_roles')
    .select('permissions')
    .eq('id', teamMembership.role_id)
    .single();
  const teamPerms = teamRole?.permissions as Record<string, boolean> | undefined;
  return !!(teamPerms?.manage_notification_settings);
}

// GET /api/organizations/:id/teams/:teamId/connections
router.get('/:id/teams/:teamId/connections', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId } = req.params;

    const { data: team } = await supabase
      .from('teams')
      .select('id, organization_id')
      .eq('id', teamId)
      .eq('organization_id', orgId)
      .single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(403).json({ error: 'Access denied' });

    const NOTIFICATION_PROVIDERS = ['slack', 'discord', 'jira', 'linear', 'asana', 'custom_notification', 'custom_ticketing', 'email'];

    const [{ data: orgConns }, { data: teamConns }] = await Promise.all([
      supabase
        .from('organization_integrations')
        .select('id, organization_id, provider, installation_id, display_name, metadata, status, connected_at, created_at, updated_at')
        .eq('organization_id', orgId)
        .eq('status', 'connected')
        .in('provider', NOTIFICATION_PROVIDERS)
        .order('created_at', { ascending: true }),
      supabase
        .from('team_integrations')
        .select('id, team_id, provider, installation_id, display_name, metadata, status, connected_at, created_at, updated_at')
        .eq('team_id', teamId)
        .eq('status', 'connected')
        .in('provider', NOTIFICATION_PROVIDERS)
        .order('created_at', { ascending: true }),
    ]);

    const inherited = (orgConns || []).map((c: any) => ({ ...c, source: 'organization' }));
    const teamSpecific = (teamConns || []).map((c: any) => ({ ...c, source: 'team' }));
    res.json({ inherited, team: teamSpecific });
  } catch (error: any) {
    console.error('Error fetching team connections:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch connections' });
  }
});

// DELETE /api/organizations/:id/teams/:teamId/connections/:connectionId
router.delete('/:id/teams/:teamId/connections/:connectionId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId, connectionId } = req.params;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage team integrations' });
    }

    const { data: connection } = await supabase
      .from('team_integrations')
      .select('*')
      .eq('id', connectionId)
      .eq('team_id', teamId)
      .single();
    if (!connection) return res.status(404).json({ error: 'Connection not found' });

    const { error: deleteError } = await supabase
      .from('team_integrations')
      .delete()
      .eq('id', connectionId)
      .eq('team_id', teamId);
    if (deleteError) throw deleteError;

    res.json({ success: true, message: 'Connection removed' });
  } catch (error: any) {
    console.error('Error deleting team connection:', error);
    res.status(500).json({ error: error.message || 'Failed to delete connection' });
  }
});

// POST /api/organizations/:id/teams/:teamId/email-notifications
router.post('/:id/teams/:teamId/email-notifications', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId } = req.params;
    const { email } = req.body;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage team integrations' });
    }

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'email is required' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail) return res.status(400).json({ error: 'email is required' });
    const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!EMAIL_REGEX.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    const { data: team } = await supabase
      .from('teams')
      .select('id')
      .eq('id', teamId)
      .eq('organization_id', orgId)
      .single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data, error: dbError } = await supabase
      .from('team_integrations')
      .insert({
        team_id: teamId,
        provider: 'email',
        installation_id: crypto.randomUUID(),
        display_name: normalizedEmail,
        status: 'connected',
        metadata: { email: normalizedEmail },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any)
      .select('id')
      .single();

    if (dbError) {
      console.error('Team email notification DB error:', dbError);
      return res.status(500).json({ error: 'Failed to add email notification' });
    }

    res.json({ success: true, id: data?.id });
  } catch (error: any) {
    console.error('Add team email notification error:', error);
    res.status(500).json({ error: error.message || 'Failed to add email' });
  }
});

// POST /api/organizations/:id/teams/:teamId/custom-integrations
router.post('/:id/teams/:teamId/custom-integrations', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId } = req.params;
    const { name, type, webhook_url, icon_url } = req.body;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage team integrations' });
    }

    if (!name || !type || !webhook_url) {
      return res.status(400).json({ error: 'name, type (notification|ticketing), and webhook_url are required' });
    }
    const trimmedUrl = String(webhook_url).trim();
    if (!/^https:\/\/[^\s]+$/i.test(trimmedUrl)) {
      return res.status(400).json({ error: 'webhook_url must start with https://' });
    }
    if (type !== 'notification' && type !== 'ticketing') {
      return res.status(400).json({ error: 'type must be "notification" or "ticketing"' });
    }

    const secret = `whsec_${crypto.randomBytes(32).toString('hex')}`;
    const provider = type === 'notification' ? 'custom_notification' : 'custom_ticketing';

    const { data: team } = await supabase
      .from('teams')
      .select('id')
      .eq('id', teamId)
      .eq('organization_id', orgId)
      .single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data, error: dbError } = await supabase
      .from('team_integrations')
      .insert({
        team_id: teamId,
        provider,
        installation_id: crypto.randomUUID() as string,
        display_name: name,
        access_token: secret,
        status: 'connected',
        metadata: {
          webhook_url: trimmedUrl,
          icon_url: icon_url || null,
          custom_name: name,
          type,
        },
        connected_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      } as any)
      .select('id')
      .single();

    if (dbError) {
      console.error('Team custom integration DB error:', dbError);
      return res.status(500).json({ error: 'Failed to create custom integration' });
    }

    res.json({ success: true, id: data?.id, secret });
  } catch (error: any) {
    console.error('Create team custom integration error:', error);
    res.status(500).json({ error: error.message || 'Failed to create custom integration' });
  }
});

// GET /api/organizations/:id/teams/:teamId/notification-rules
router.get('/:id/teams/:teamId/notification-rules', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId } = req.params;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(404).json({ error: 'Organization not found or access denied' });

    const { data: team } = await supabase
      .from('teams')
      .select('id')
      .eq('id', teamId)
      .eq('organization_id', orgId)
      .single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const { data: rules, error } = await supabase
      .from('team_notification_rules')
      .select('*')
      .eq('team_id', teamId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const mapped = (rules ?? []).map((r: any) => ({
      id: r.id,
      name: r.name,
      triggerType: r.trigger_type,
      minDepscoreThreshold: r.min_depscore_threshold ?? undefined,
      customCode: r.custom_code ?? undefined,
      destinations: r.destinations ?? [],
      active: r.active ?? true,
      createdByUserId: r.created_by_user_id ?? undefined,
      createdByName: r.created_by_name ?? undefined,
    }));

    res.json(mapped);
  } catch (error: any) {
    console.error('Error fetching team notification rules:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch notification rules' });
  }
});

// POST /api/organizations/:id/teams/:teamId/notification-rules
router.post('/:id/teams/:teamId/notification-rules', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId } = req.params;
    const { name, triggerType, minDepscoreThreshold, customCode, destinations, createdByName } = req.body;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'name is required' });
    }
    const validTriggers = ['weekly_digest', 'vulnerability_discovered', 'custom_code_pipeline'];
    if (!triggerType || !validTriggers.includes(triggerType)) {
      return res.status(400).json({ error: 'triggerType must be one of: weekly_digest, vulnerability_discovered, custom_code_pipeline' });
    }

    const { data: team } = await supabase
      .from('teams')
      .select('id')
      .eq('id', teamId)
      .eq('organization_id', orgId)
      .single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    const dests = Array.isArray(destinations) ? destinations : [];
    const insertData: Record<string, unknown> = {
      team_id: teamId,
      name: name.trim(),
      trigger_type: triggerType,
      destinations: dests,
      active: true,
      created_by_user_id: userId,
      created_by_name: typeof createdByName === 'string' ? createdByName : null,
    };
    if (triggerType === 'vulnerability_discovered' && typeof minDepscoreThreshold === 'number') {
      insertData.min_depscore_threshold = minDepscoreThreshold;
    }
    if (triggerType === 'custom_code_pipeline' && typeof customCode === 'string') {
      insertData.custom_code = customCode;
    }

    const { data: created, error } = await supabase
      .from('team_notification_rules')
      .insert(insertData)
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      id: created.id,
      name: created.name,
      triggerType: created.trigger_type,
      minDepscoreThreshold: created.min_depscore_threshold ?? undefined,
      customCode: created.custom_code ?? undefined,
      destinations: created.destinations ?? [],
      active: created.active ?? true,
      createdByUserId: created.created_by_user_id ?? undefined,
      createdByName: created.created_by_name ?? undefined,
    });
  } catch (error: any) {
    console.error('Error creating team notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to create notification rule' });
  }
});

// PUT /api/organizations/:id/teams/:teamId/notification-rules/:ruleId
router.put('/:id/teams/:teamId/notification-rules/:ruleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId, ruleId } = req.params;
    const { name, triggerType, minDepscoreThreshold, customCode, destinations } = req.body;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    const validTriggers = ['weekly_digest', 'vulnerability_discovered', 'custom_code_pipeline'];
    const updateData: Record<string, unknown> = {};
    if (typeof name === 'string') updateData.name = name.trim();
    if (triggerType && validTriggers.includes(triggerType)) updateData.trigger_type = triggerType;
    if (triggerType === 'vulnerability_discovered') {
      updateData.min_depscore_threshold = typeof minDepscoreThreshold === 'number' ? minDepscoreThreshold : null;
    } else {
      updateData.min_depscore_threshold = null;
    }
    if (triggerType === 'custom_code_pipeline') {
      updateData.custom_code = typeof customCode === 'string' ? customCode : null;
    } else {
      updateData.custom_code = null;
    }
    if (Array.isArray(destinations)) updateData.destinations = destinations;

    const { data: updated, error } = await supabase
      .from('team_notification_rules')
      .update(updateData)
      .eq('id', ruleId)
      .eq('team_id', teamId)
      .select()
      .single();

    if (error) throw error;
    if (!updated) return res.status(404).json({ error: 'Notification rule not found' });

    res.json({
      id: updated.id,
      name: updated.name,
      triggerType: updated.trigger_type,
      minDepscoreThreshold: updated.min_depscore_threshold ?? undefined,
      customCode: updated.custom_code ?? undefined,
      destinations: updated.destinations ?? [],
      active: updated.active ?? true,
      createdByUserId: updated.created_by_user_id ?? undefined,
      createdByName: updated.created_by_name ?? undefined,
    });
  } catch (error: any) {
    console.error('Error updating team notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to update notification rule' });
  }
});

// DELETE /api/organizations/:id/teams/:teamId/notification-rules/:ruleId
router.delete('/:id/teams/:teamId/notification-rules/:ruleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId, ruleId } = req.params;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    const { error } = await supabase
      .from('team_notification_rules')
      .delete()
      .eq('id', ruleId)
      .eq('team_id', teamId);

    if (error) throw error;
    res.json({ message: 'Notification rule deleted' });
  } catch (error: any) {
    console.error('Error deleting team notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to delete notification rule' });
  }
});

export default router;

