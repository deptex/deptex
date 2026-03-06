// @ts-nocheck
import express from 'express';
import * as crypto from 'crypto';
import { authenticateUser, AuthRequest, checkMFACompliance } from '../middleware/auth';
import { createIPAllowlistMiddleware } from '../middleware/ip-allowlist';
import { supabase } from '../lib/supabase';
import { sendInvitationEmail } from '../lib/email';
import { createActivity } from '../lib/activities';
import { getOpenAIClient } from '../lib/openai';
import { getPlatformProvider } from '../lib/ai/provider';
import { updateAllProjectsCompliance } from './projects';
import { invalidateAllProjectCachesInOrg, invalidateProjectCachesForTeam, getCached, setCached } from '../lib/cache';
import { seedOrganizationPolicyDefaults } from '../lib/policy-seed';
import { emitEvent } from '../lib/event-bus';

const router = express.Router();

import {
  DEFAULT_STATUSES,
  DEFAULT_ASSET_TIERS,
  DEFAULT_PACKAGE_POLICY_CODE,
  DEFAULT_PROJECT_STATUS_CODE,
  DEFAULT_PR_CHECK_CODE,
} from '../lib/policy-defaults';

// All routes require authentication
router.use(authenticateUser);

// Phase 14: IP allowlist and MFA enforcement for org-scoped routes (/:id/...)
router.use('/:id', createIPAllowlistMiddleware());
router.use('/:id', async (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
  const orgId = req.params.id;
  if (!orgId) return next();
  const mfa = await checkMFACompliance(req, orgId);
  if (!mfa.ok) return res.status(403).json({ error: mfa.error, grace_period_expired: true });
  next();
});

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

    // Get organizations with user's role in a single query using join (plan comes from organization_plans)
    const { data: memberships, error: membershipError } = await supabase
      .from('organization_members')
      .select(`
        organization_id,
        role,
        organizations!inner (
          id,
          name,
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

    // Plan tier from organization_plans (single source of truth)
    const { data: planRows } = await supabase
      .from('organization_plans')
      .select('organization_id, plan_tier')
      .in('organization_id', organizationIds);
    const planByOrgId = new Map<string, string>();
    (planRows || []).forEach((row: { organization_id: string; plan_tier: string }) => {
      planByOrgId.set(row.organization_id, row.plan_tier ?? 'free');
    });

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
          plan: planByOrgId.get(m.organization_id) ?? 'free',
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

    // Create organization (plan tier lives in organization_plans only)
    const { data: organization, error: orgError } = await supabase
      .from('organizations')
      .insert({ name: name.trim() })
      .select()
      .single();

    if (orgError) {
      throw orgError;
    }

    // Create organization_plans row (single source of truth for plan tier and billing)
    const { error: planError } = await supabase
      .from('organization_plans')
      .insert({ organization_id: organization.id, plan_tier: 'free' });

    if (planError) {
      await supabase.from('organizations').delete().eq('id', organization.id);
      throw planError;
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
            manage_statuses: true,
            interact_with_aegis: true,
            trigger_fix: true,
            manage_aegis: true,
            view_ai_spending: true,
            manage_incidents: true,
            manage_watchtower: true,
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
            manage_statuses: true,
            interact_with_aegis: true,
            trigger_fix: true,
            manage_aegis: true,
            view_ai_spending: true,
            manage_incidents: true,
            manage_watchtower: true,
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

    // Seed default statuses
    await supabase.from('organization_statuses').insert(
      DEFAULT_STATUSES.map(s => ({ ...s, organization_id: organization.id }))
    );

    // Seed default asset tiers
    await supabase.from('organization_asset_tiers').insert(
      DEFAULT_ASSET_TIERS.map(t => ({ ...t, organization_id: organization.id }))
    );

    // Seed default policy code tables
    await Promise.all([
      supabase.from('organization_package_policies').insert({
        organization_id: organization.id,
        package_policy_code: DEFAULT_PACKAGE_POLICY_CODE,
        updated_by_id: userId,
      }),
      supabase.from('organization_status_codes').insert({
        organization_id: organization.id,
        project_status_code: DEFAULT_PROJECT_STATUS_CODE,
        updated_by_id: userId,
      }),
      supabase.from('organization_pr_checks').insert({
        organization_id: organization.id,
        pr_check_code: DEFAULT_PR_CHECK_CODE,
        updated_by_id: userId,
      }),
    ]);

    // Seed default statuses, asset tiers, and policy templates
    await seedOrganizationPolicyDefaults(organization.id);

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
      plan: 'free',
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

    // Plan tier comes from organization_plans (single source of truth)
    const { data: planRow } = await supabase
      .from('organization_plans')
      .select('plan_tier')
      .eq('organization_id', id)
      .single();

    // Get role display name, color, and rank (display_order)
    const { data: roleData } = await supabase
      .from('organization_roles')
      .select('display_name, color, display_order, permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    res.json({
      ...organization,
      plan: planRow?.plan_tier ?? 'free',
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

    // Plan limit check: members
    try {
      const { checkPlanLimit, TIER_DISPLAY_NAMES } = require('../lib/plan-limits');
      const planCheck = await checkPlanLimit(id, 'members');
      if (!planCheck.allowed) {
        return res.status(403).json({
          error: 'PLAN_LIMIT',
          message: `Your ${TIER_DISPLAY_NAMES[planCheck.tier]} plan supports up to ${planCheck.limit} members.`,
          resource: 'members', current: planCheck.current, limit: planCheck.limit,
          tier: planCheck.tier, upgradeTier: planCheck.upgradeTier,
        });
      }
    } catch (e) { /* fail open */ }

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

    try {
      await emitEvent({ type: 'member_invited', organizationId: id, payload: { email: email.trim().toLowerCase(), role: roleToUse, teamIds: teamIdsArray }, source: 'system', priority: 'normal' });
    } catch (e) {}

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

    try {
      await emitEvent({ type: 'member_removed', organizationId: id, payload: { removedUserId: targetUserId, removedEmail: targetUser?.email, selfRemoval: userId === targetUserId }, source: 'system', priority: 'normal' });
    } catch (e) {}

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

    const { data: planRow } = await supabase
      .from('organization_plans')
      .select('plan_tier')
      .eq('organization_id', id)
      .single();

    res.json({ ...organization, plan: planRow?.plan_tier ?? 'free' });
  } catch (error: any) {
    console.error('Error updating organization:', error);
    res.status(500).json({ error: error.message || 'Failed to update organization' });
  }
});

// PATCH /api/organizations/:id - Partial update (e.g. notifications_paused_until)
router.patch('/:id', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { notifications_paused_until } = req.body;

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

    const updateData: any = { updated_at: new Date().toISOString() };
    if (notifications_paused_until !== undefined) {
      updateData.notifications_paused_until = notifications_paused_until;
    }

    const { data: organization, error: updateError } = await supabase
      .from('organizations')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) throw updateError;

    const { data: planRow } = await supabase
      .from('organization_plans')
      .select('plan_tier')
      .eq('organization_id', id)
      .single();

    res.json({ ...organization, plan: planRow?.plan_tier ?? 'free' });
  } catch (error: any) {
    console.error('Error patching organization:', error);
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
      manage_statuses: false,
      interact_with_aegis: false,
      trigger_fix: false,
      manage_aegis: false,
      view_ai_spending: false,
      manage_incidents: false,
      manage_watchtower: false,
      view_members: false,
      add_members: false,
      edit_roles: false,
      kick_members: false,
      manage_teams_and_projects: false,
      manage_integrations: false,
      manage_notifications: false,
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
        'view_settings', 'manage_billing', 'manage_security', 'view_activity', 'manage_compliance', 'manage_statuses',
        'interact_with_aegis', 'trigger_fix', 'manage_aegis', 'view_ai_spending', 'manage_incidents', 'manage_watchtower',
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

// ───── Phase 4: Organization Statuses CRUD ─────

async function canManageStatuses(organizationId: string, userId: string): Promise<boolean> {
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
  return !!(perms?.manage_statuses || perms?.manage_compliance);
}

// GET /api/organizations/:id/statuses
router.get('/:id/statuses', async (req: AuthRequest, res) => {
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

    const { data: statuses, error } = await supabase
      .from('organization_statuses')
      .select('*')
      .eq('organization_id', id)
      .order('rank', { ascending: true });

    if (error) throw error;
    res.json(statuses ?? []);
  } catch (error: any) {
    console.error('Error fetching statuses:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch statuses' });
  }
});

// POST /api/organizations/:id/statuses
router.post('/:id/statuses', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const { name, color, description, is_passing, rank } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ error: 'Status name is required' });
    }

    const colorVal = (color != null && String(color).trim() !== '') ? String(color).trim() : null;
    const { data: status, error } = await supabase
      .from('organization_statuses')
      .insert({
        organization_id: id,
        name: name.trim(),
        color: colorVal,
        description: description || null,
        is_passing: is_passing ?? false,
        rank: rank ?? 50,
        is_system: false,
      })
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'A status with this name already exists' });
      }
      throw error;
    }

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'created_status',
      description: `created status "${name.trim()}"`,
      metadata: { status_name: name.trim() },
    });

    res.status(201).json(status);
  } catch (error: any) {
    console.error('Error creating status:', error);
    res.status(500).json({ error: error.message || 'Failed to create status' });
  }
});

// PUT /api/organizations/:id/statuses/reorder - Bulk reorder (must be before /:statusId so "reorder" is not matched as id)
router.put('/:id/statuses/reorder', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const { order } = req.body;
    if (!Array.isArray(order)) {
      return res.status(400).json({ error: 'order must be an array of { id, rank }' });
    }

    for (const item of order) {
      const { error } = await supabase
        .from('organization_statuses')
        .update({ rank: item.rank })
        .eq('id', item.id)
        .eq('organization_id', id);
      if (error) throw error;
    }

    const { data: statuses, error: fetchError } = await supabase
      .from('organization_statuses')
      .select('*')
      .eq('organization_id', id)
      .order('rank', { ascending: true });

    if (fetchError) throw fetchError;
    res.json({ statuses: statuses ?? [] });
  } catch (error: any) {
    console.error('Error reordering statuses:', error);
    res.status(500).json({ error: error.message || 'Failed to reorder statuses' });
  }
});

// PUT /api/organizations/:id/statuses/:statusId
router.put('/:id/statuses/:statusId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, statusId } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const updates: Record<string, unknown> = {};
    if (req.body.name !== undefined) updates.name = req.body.name;
    if (req.body.color !== undefined) {
      const v = req.body.color;
      updates.color = (v != null && String(v).trim() !== '') ? String(v).trim() : null;
    }
    if (req.body.description !== undefined) updates.description = req.body.description;
    if (req.body.is_passing !== undefined) updates.is_passing = req.body.is_passing;
    if (req.body.rank !== undefined) updates.rank = req.body.rank;

    const { data: status, error } = await supabase
      .from('organization_statuses')
      .update(updates)
      .eq('id', statusId)
      .eq('organization_id', id)
      .select()
      .single();

    if (error) throw error;
    if (!status) return res.status(404).json({ error: 'Status not found' });

    res.json(status);
  } catch (error: any) {
    console.error('Error updating status:', error);
    res.status(500).json({ error: error.message || 'Failed to update status' });
  }
});

// DELETE /api/organizations/:id/statuses/:statusId
router.delete('/:id/statuses/:statusId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, statusId } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const { data: status } = await supabase
      .from('organization_statuses')
      .select('is_system, name')
      .eq('id', statusId)
      .eq('organization_id', id)
      .single();

    if (!status) return res.status(404).json({ error: 'Status not found' });
    if (status.is_system) return res.status(400).json({ error: 'Cannot delete system statuses. You can rename or recolor them.' });

    const { data: projectsUsingStatus } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', id)
      .eq('status_id', statusId);

    if (projectsUsingStatus && projectsUsingStatus.length > 0) {
      return res.status(400).json({
        error: `Cannot delete status "${status.name}" because ${projectsUsingStatus.length} project(s) are using it. Reassign them first.`,
        projects_count: projectsUsingStatus.length,
      });
    }

    const { error } = await supabase
      .from('organization_statuses')
      .delete()
      .eq('id', statusId)
      .eq('organization_id', id);

    if (error) throw error;

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'deleted_status',
      description: `deleted status "${status.name}"`,
      metadata: { status_name: status.name },
    });

    res.json({ message: 'Status deleted' });
  } catch (error: any) {
    console.error('Error deleting status:', error);
    res.status(500).json({ error: error.message || 'Failed to delete status' });
  }
});

// ───── Phase 4: Organization Asset Tiers CRUD ─────

// GET /api/organizations/:id/asset-tiers
router.get('/:id/asset-tiers', async (req: AuthRequest, res) => {
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

    const { data: tiers, error } = await supabase
      .from('organization_asset_tiers')
      .select('*')
      .eq('organization_id', id)
      .order('rank', { ascending: true });

    if (error) throw error;
    res.json(tiers ?? []);
  } catch (error: any) {
    console.error('Error fetching asset tiers:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch asset tiers' });
  }
});

// POST /api/organizations/:id/asset-tiers
router.post('/:id/asset-tiers', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const { name, color, description, environmental_multiplier, rank } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ error: 'Tier name is required' });
    }

    const multiplier = typeof environmental_multiplier === 'number' ? environmental_multiplier : 1.0;

    const { data: tier, error } = await supabase
      .from('organization_asset_tiers')
      .insert({
        organization_id: id,
        name: name.trim(),
        color: color || '#6b7280',
        description: description || null,
        environmental_multiplier: multiplier,
        rank: rank ?? 50,
        is_system: false,
      })
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'A tier with this name already exists' });
      }
      throw error;
    }

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'created_asset_tier',
      description: `created asset tier "${name.trim()}"`,
      metadata: { tier_name: name.trim() },
    });

    res.status(201).json(tier);
  } catch (error: any) {
    console.error('Error creating asset tier:', error);
    res.status(500).json({ error: error.message || 'Failed to create asset tier' });
  }
});

// PUT /api/organizations/:id/asset-tiers/:tierId
router.put('/:id/asset-tiers/:tierId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, tierId } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const updates: Record<string, unknown> = {};
    if (req.body.name !== undefined) updates.name = req.body.name;
    if (req.body.color !== undefined) updates.color = req.body.color;
    if (req.body.description !== undefined) updates.description = req.body.description;
    if (req.body.environmental_multiplier !== undefined) updates.environmental_multiplier = req.body.environmental_multiplier;
    if (req.body.rank !== undefined) updates.rank = req.body.rank;

    const { data: tier, error } = await supabase
      .from('organization_asset_tiers')
      .update(updates)
      .eq('id', tierId)
      .eq('organization_id', id)
      .select()
      .single();

    if (error) throw error;
    if (!tier) return res.status(404).json({ error: 'Tier not found' });

    res.json(tier);
  } catch (error: any) {
    console.error('Error updating asset tier:', error);
    res.status(500).json({ error: error.message || 'Failed to update asset tier' });
  }
});

// PUT /api/organizations/:id/asset-tiers/reorder
router.put('/:id/asset-tiers/reorder', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const { order } = req.body;
    if (!Array.isArray(order)) {
      return res.status(400).json({ error: 'order must be an array of { id, rank }' });
    }

    for (const item of order) {
      await supabase
        .from('organization_asset_tiers')
        .update({ rank: item.rank })
        .eq('id', item.id)
        .eq('organization_id', id);
    }

    const { data: tiers } = await supabase
      .from('organization_asset_tiers')
      .select('*')
      .eq('organization_id', id)
      .order('rank', { ascending: true });

    res.json(tiers ?? []);
  } catch (error: any) {
    console.error('Error reordering asset tiers:', error);
    res.status(500).json({ error: error.message || 'Failed to reorder asset tiers' });
  }
});

// DELETE /api/organizations/:id/asset-tiers/:tierId
router.delete('/:id/asset-tiers/:tierId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, tierId } = req.params;

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    const { data: tier } = await supabase
      .from('organization_asset_tiers')
      .select('is_system, name')
      .eq('id', tierId)
      .eq('organization_id', id)
      .single();

    if (!tier) return res.status(404).json({ error: 'Tier not found' });
    if (tier.is_system) return res.status(400).json({ error: 'Cannot delete system tiers' });

    const reassignTo = req.body?.reassign_to_id;
    if (reassignTo) {
      await supabase
        .from('projects')
        .update({ asset_tier_id: reassignTo })
        .eq('organization_id', id)
        .eq('asset_tier_id', tierId);
    }

    const { error } = await supabase
      .from('organization_asset_tiers')
      .delete()
      .eq('id', tierId)
      .eq('organization_id', id);

    if (error) throw error;

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'deleted_asset_tier',
      description: `deleted asset tier "${tier.name}"`,
      metadata: { tier_name: tier.name },
    });

    res.json({ message: 'Tier deleted' });
  } catch (error: any) {
    console.error('Error deleting asset tier:', error);
    res.status(500).json({ error: error.message || 'Failed to delete asset tier' });
  }
});

// ───── Phase 15: Security SLA Management ─────

const SLA_DEFAULT_HOURS: Record<string, number> = {
  critical: 48,
  high: 168,   // 7d
  medium: 720, // 30d
  low: 2160,   // 90d
};

// GET /api/organizations/:id/sla-policies
router.get('/:id/sla-policies', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied. Requires manage compliance or statuses.' });
    }

    const { data: policies, error } = await supabase
      .from('organization_sla_policies')
      .select('*')
      .eq('organization_id', id)
      .order('severity', { ascending: true });

    if (error) throw error;

    const { data: org } = await supabase
      .from('organizations')
      .select('sla_paused_at')
      .eq('id', id)
      .single();

    res.json({
      policies: policies ?? [],
      sla_paused_at: (org as any)?.sla_paused_at ?? null,
    });
  } catch (error: any) {
    console.error('Error fetching SLA policies:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch SLA policies' });
  }
});

// PUT /api/organizations/:id/sla-policies
router.put('/:id/sla-policies', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    const { policies: policiesPayload } = req.body as { policies?: Array<{ id?: string; severity: string; asset_tier_id?: string | null; max_hours: number; warning_threshold_percent?: number; enabled?: boolean }> };
    if (!Array.isArray(policiesPayload)) {
      return res.status(400).json({ error: 'policies array is required' });
    }

    const severities = ['critical', 'high', 'medium', 'low'];
    const { data: existing } = await supabase
      .from('organization_sla_policies')
      .select('*')
      .eq('organization_id', id);

    const existingMap = new Map<string, any>();
    for (const p of existing ?? []) {
      const key = `${p.severity}:${p.asset_tier_id ?? 'default'}`;
      existingMap.set(key, p);
    }

    for (const row of policiesPayload) {
      if (!row.severity || !severities.includes(row.severity)) continue;
      const maxHours = typeof row.max_hours === 'number' && row.max_hours > 0 ? row.max_hours : SLA_DEFAULT_HOURS[row.severity];
      const warningPct = typeof row.warning_threshold_percent === 'number' ? Math.min(99, Math.max(1, row.warning_threshold_percent)) : 75;
      const enabled = row.enabled !== false;
      const assetTierId = row.asset_tier_id === undefined || row.asset_tier_id === '' ? null : row.asset_tier_id;
      const key = `${row.severity}:${assetTierId ?? 'default'}`;
      const existingRow = existingMap.get(key);

      if (existingRow) {
        const prev = { max_hours: existingRow.max_hours, warning_threshold_percent: existingRow.warning_threshold_percent, enabled: existingRow.enabled };
        const { error: updateErr } = await supabase
          .from('organization_sla_policies')
          .update({ max_hours: maxHours, warning_threshold_percent: warningPct, enabled, updated_at: new Date().toISOString() })
          .eq('id', existingRow.id);
        if (updateErr) throw updateErr;
        await supabase.from('sla_policy_changes').insert({
          organization_id: id,
          changed_by: userId,
          change_type: 'updated',
          previous_values: prev,
          new_values: { max_hours: maxHours, warning_threshold_percent: warningPct, enabled },
        });
      } else {
        const { error: insertErr } = await supabase
          .from('organization_sla_policies')
          .insert({
            organization_id: id,
            severity: row.severity,
            asset_tier_id: assetTierId,
            max_hours: maxHours,
            warning_threshold_percent: warningPct,
            enabled,
          });
        if (insertErr) throw insertErr;
        await supabase.from('sla_policy_changes').insert({
          organization_id: id,
          changed_by: userId,
          change_type: 'created',
          new_values: { severity: row.severity, asset_tier_id: assetTierId, max_hours: maxHours, warning_threshold_percent: warningPct, enabled },
        });
      }
    }

    const { data: updated } = await supabase
      .from('organization_sla_policies')
      .select('*')
      .eq('organization_id', id)
      .order('severity', { ascending: true });

    res.json({ policies: updated ?? [] });
  } catch (error: any) {
    console.error('Error updating SLA policies:', error);
    res.status(500).json({ error: error.message || 'Failed to update SLA policies' });
  }
});

// POST /api/organizations/:id/sla-policies/enable
router.post('/:id/sla-policies/enable', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    const { data: existing } = await supabase
      .from('organization_sla_policies')
      .select('id')
      .eq('organization_id', id)
      .limit(1);

    if (existing && existing.length > 0) {
      return res.status(400).json({ error: 'SLA policies already enabled for this organization' });
    }

    for (const severity of ['critical', 'high', 'medium', 'low']) {
      const { error: insertErr } = await supabase
        .from('organization_sla_policies')
        .insert({
          organization_id: id,
          severity,
          asset_tier_id: null,
          max_hours: SLA_DEFAULT_HOURS[severity],
          warning_threshold_percent: 75,
          enabled: true,
        });
      if (insertErr) throw insertErr;
    }

    await supabase.from('sla_policy_changes').insert({
      organization_id: id,
      changed_by: userId,
      change_type: 'created',
      new_values: { action: 'enable_defaults', severities: ['critical', 'high', 'medium', 'low'] },
    });

    const { data: rpcResult, error: rpcError } = await supabase.rpc('backfill_sla_for_organization', { p_organization_id: id });
    if (rpcError) {
      console.error('SLA backfill RPC error:', rpcError);
      // still return success; policies are created
    }

    const { data: policies } = await supabase
      .from('organization_sla_policies')
      .select('*')
      .eq('organization_id', id)
      .order('severity', { ascending: true });

    res.status(201).json({
      policies: policies ?? [],
      backfill_updated: (rpcResult as number) ?? 0,
    });
  } catch (error: any) {
    console.error('Error enabling SLA policies:', error);
    res.status(500).json({ error: error.message || 'Failed to enable SLA policies' });
  }
});

// POST /api/organizations/:id/sla-policies/pause
router.post('/:id/sla-policies/pause', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    const now = new Date().toISOString();
    const { error } = await supabase
      .from('organizations')
      .update({ sla_paused_at: now })
      .eq('id', id);

    if (error) throw error;

    await supabase.from('sla_policy_changes').insert({
      organization_id: id,
      changed_by: userId,
      change_type: 'paused',
      new_values: { sla_paused_at: now },
    });

    res.json({ sla_paused_at: now });
  } catch (error: any) {
    console.error('Error pausing SLA:', error);
    res.status(500).json({ error: error.message || 'Failed to pause SLA' });
  }
});

// POST /api/organizations/:id/sla-policies/resume
router.post('/:id/sla-policies/resume', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    const { data: org } = await supabase
      .from('organizations')
      .select('sla_paused_at')
      .eq('id', id)
      .single();

    const pausedAt = (org as any)?.sla_paused_at;
    if (!pausedAt) {
      return res.json({ sla_paused_at: null, message: 'SLAs were not paused' });
    }

    const pauseDurationMs = Date.now() - new Date(pausedAt).getTime();
    const pauseDurationSeconds = Math.round(pauseDurationMs / 1000);
    const pauseDurationHours = pauseDurationMs / (1000 * 60 * 60);

    const { error: rpcErr } = await supabase.rpc('resume_sla_shift_deadlines', {
      p_organization_id: id,
      p_pause_duration_seconds: pauseDurationSeconds,
    });
    if (rpcErr) {
      console.error('resume_sla_shift_deadlines RPC error:', rpcErr);
    }

    const { error: updateErr } = await supabase
      .from('organizations')
      .update({ sla_paused_at: null })
      .eq('id', id);

    if (updateErr) throw updateErr;

    await supabase.from('sla_policy_changes').insert({
      organization_id: id,
      changed_by: userId,
      change_type: 'resumed',
      previous_values: { sla_paused_at: pausedAt },
      new_values: { pause_duration_hours: pauseDurationHours },
    });

    res.json({ sla_paused_at: null });
  } catch (error: any) {
    console.error('Error resuming SLA:', error);
    res.status(500).json({ error: error.message || 'Failed to resume SLA' });
  }
});

// POST /api/organizations/:id/sla-policies/disable
router.post('/:id/sla-policies/disable', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    const { data: projectIds } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', id);

    const ids = (projectIds ?? []).map((p: { id: string }) => p.id);
    if (ids.length > 0) {
      const { error: clearErr } = await supabase
        .from('project_dependency_vulnerabilities')
        .update({
          detected_at: null,
          sla_deadline_at: null,
          sla_warning_at: null,
          sla_status: null,
          sla_breached_at: null,
          sla_met_at: null,
          sla_exempt_reason: null,
          sla_warning_notified_at: null,
          sla_breach_notified_at: null,
        })
        .in('project_id', ids);
      if (clearErr) throw clearErr;
    }

    const { error: deleteErr } = await supabase
      .from('organization_sla_policies')
      .delete()
      .eq('organization_id', id);
    if (deleteErr) throw deleteErr;

    await supabase.from('organizations').update({ sla_paused_at: null }).eq('id', id);

    await supabase.from('sla_policy_changes').insert({
      organization_id: id,
      changed_by: userId,
      change_type: 'disabled',
      new_values: { action: 'disable' },
    });

    res.status(200).json({ ok: true });
  } catch (error: any) {
    console.error('Error disabling SLA policies:', error);
    res.status(500).json({ error: error.message || 'Failed to disable SLA policies' });
  }
});

// GET /api/organizations/:id/sla-compliance
router.get('/:id/sla-compliance', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId } = req.params;
    const timeRange = (req.query.timeRange as string) || '90d';

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: projects } = await supabase.from('projects').select('id, name, asset_tier_id, team_id').eq('organization_id', orgId);
    const projectList = projects ?? [];
    const projectIds = projectList.map((p: any) => p.id);
    const projectNameMap = new Map(projectList.map((p: any) => [p.id, p.name]));

    if (projectIds.length === 0) {
      return res.json({
        overall_compliance_percent: 100,
        current_breaches: 0,
        average_mttr_by_severity: {},
        adherence_by_month: [],
        violations: [],
        team_breakdown: [],
      });
    }

    const pdvSelect = 'id, project_id, severity, sla_status, sla_deadline_at, sla_met_at, sla_breached_at, detected_at, osv_id, created_at';
    const { data: allPdv } = await supabase
      .from('project_dependency_vulnerabilities')
      .select(pdvSelect)
      .in('project_id', projectIds);

    const pdvList = allPdv ?? [];
    const met = pdvList.filter((p: any) => p.sla_status === 'met').length;
    const resolvedLate = pdvList.filter((p: any) => p.sla_status === 'resolved_late').length;
    const breached = pdvList.filter((p: any) => p.sla_status === 'breached').length;
    const onTrack = pdvList.filter((p: any) => p.sla_status === 'on_track').length;
    const warning = pdvList.filter((p: any) => p.sla_status === 'warning').length;
    const exempt = pdvList.filter((p: any) => p.sla_status === 'exempt').length;
    const totalResolved = met + resolvedLate;
    const overallCompliancePercent = totalResolved > 0 ? Math.round((met / totalResolved) * 100) : 100;

    const violations = pdvList
      .filter((p: any) => p.sla_status === 'breached' || p.sla_status === 'warning')
      .map((p: any) => ({
        id: p.id,
        project_id: p.project_id,
        project_name: projectNameMap.get(p.project_id) ?? '',
        osv_id: p.osv_id,
        severity: p.severity,
        detected_at: p.detected_at ?? p.created_at,
        deadline: p.sla_deadline_at,
        sla_status: p.sla_status,
      }))
      .sort((a: any, b: any) => {
        const aDeadline = a.deadline ? new Date(a.deadline).getTime() : 0;
        const bDeadline = b.deadline ? new Date(b.deadline).getTime() : 0;
        return aDeadline - bDeadline;
      });

    const severityKeys = ['critical', 'high', 'medium', 'low'];
    const mttrBySeverity: Record<string, number> = {};
    for (const sev of severityKeys) {
      const resolved = pdvList.filter((p: any) => p.severity === sev && (p.sla_status === 'met' || p.sla_status === 'resolved_late') && p.sla_met_at);
      if (resolved.length === 0) continue;
      let totalHours = 0;
      for (const p of resolved) {
        const detected = p.detected_at ?? p.created_at;
        if (detected && p.sla_met_at) {
          totalHours += (new Date(p.sla_met_at).getTime() - new Date(detected).getTime()) / (1000 * 60 * 60);
        }
      }
      mttrBySeverity[sev] = Math.round((totalHours / resolved.length) * 10) / 10;
    }

    const monthsBack = timeRange === '30d' ? 1 : timeRange === '90d' ? 3 : timeRange === '6m' ? 6 : 12;
    const adherenceByMonth: Array<{ month: string; met: number; met_late: number; breached: number; exempt: number }> = [];
    const now = new Date();
    for (let i = monthsBack - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      const monthStart = new Date(d.getFullYear(), d.getMonth(), 1).toISOString();
      const monthEnd = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59).toISOString();
      const inMonth = pdvList.filter((p: any) => {
        const metAt = p.sla_met_at;
        const breachedAt = p.sla_breached_at;
        const created = p.created_at;
        if (metAt && metAt >= monthStart && metAt <= monthEnd) return true;
        if (breachedAt && breachedAt >= monthStart && breachedAt <= monthEnd) return true;
        if (p.sla_status === 'exempt' && created >= monthStart && created <= monthEnd) return true;
        return false;
      });
      const metCount = inMonth.filter((p: any) => p.sla_status === 'met').length;
      const metLateCount = inMonth.filter((p: any) => p.sla_status === 'resolved_late').length;
      const breachedCount = inMonth.filter((p: any) => p.sla_status === 'breached').length;
      const exemptCount = inMonth.filter((p: any) => p.sla_status === 'exempt').length;
      adherenceByMonth.push({ month: monthKey, met: metCount, met_late: metLateCount, breached: breachedCount, exempt: exemptCount });
    }

    const teamIds = [...new Set(projectList.map((p: any) => p.team_id).filter(Boolean))];
    const teamBreakdown: Array<{ team_id: string; team_name: string; total: number; on_track_pct: number; warning: number; breached: number; avg_mttr: number }> = [];
    if (teamIds.length > 0) {
      const { data: teams } = await supabase.from('teams').select('id, name').in('id', teamIds);
      const teamNameMap = new Map((teams ?? []).map((t: any) => [t.id, t.name]));
      for (const tid of teamIds) {
        const teamProjectIds = projectList.filter((p: any) => p.team_id === tid).map((p: any) => p.id);
        const teamPdv = pdvList.filter((p: any) => teamProjectIds.includes(p.project_id));
        const total = teamPdv.length;
        const onTrackCount = teamPdv.filter((p: any) => p.sla_status === 'on_track').length;
        const warningCount = teamPdv.filter((p: any) => p.sla_status === 'warning').length;
        const breachedCount = teamPdv.filter((p: any) => p.sla_status === 'breached').length;
        const resolvedTeam = teamPdv.filter((p: any) => (p.sla_status === 'met' || p.sla_status === 'resolved_late') && p.sla_met_at);
        let avgMttr = 0;
        if (resolvedTeam.length > 0) {
          const totalH = resolvedTeam.reduce((acc: number, p: any) => {
            const det = p.detected_at ?? p.created_at;
            return acc + (det && p.sla_met_at ? (new Date(p.sla_met_at).getTime() - new Date(det).getTime()) / (1000 * 60 * 60) : 0);
          }, 0);
          avgMttr = Math.round((totalH / resolvedTeam.length) * 10) / 10;
        }
        teamBreakdown.push({
          team_id: tid,
          team_name: teamNameMap.get(tid) ?? 'Unknown',
          total,
          on_track_pct: total > 0 ? Math.round((onTrackCount / total) * 100) : 100,
          warning: warningCount,
          breached: breachedCount,
          avg_mttr: avgMttr,
        });
      }
    }

    res.json({
      overall_compliance_percent: overallCompliancePercent,
      current_breaches: breached,
      on_track: onTrack,
      warning,
      exempt,
      met,
      resolved_late: resolvedLate,
      average_mttr_by_severity: mttrBySeverity,
      adherence_by_month: adherenceByMonth,
      violations,
      team_breakdown: teamBreakdown,
    });
  } catch (error: any) {
    console.error('Error fetching SLA compliance:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch SLA compliance' });
  }
});

// GET /api/organizations/:id/sla-compliance/export
router.get('/:id/sla-compliance/export', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId } = req.params;
    const timeRange = (req.query.timeRange as string) || '90d';

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: projects } = await supabase.from('projects').select('id, name').eq('organization_id', orgId);
    const projectList = projects ?? [];
    const projectIds = projectList.map((p: any) => p.id);
    const projectNameMap = new Map(projectList.map((p: any) => [p.id, p.name]));

    if (projectIds.length === 0) {
      return res.json({ rows: [], summary: {} });
    }

    const { data: allPdv } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('id, project_id, osv_id, severity, sla_status, detected_at, sla_deadline_at, sla_met_at, sla_breached_at, created_at')
      .in('project_id', projectIds);

    const rows = (allPdv ?? []).map((p: any) => ({
      project_name: projectNameMap.get(p.project_id) ?? '',
      project_id: p.project_id,
      osv_id: p.osv_id,
      severity: p.severity,
      sla_status: p.sla_status,
      detected_at: p.detected_at ?? p.created_at,
      deadline: p.sla_deadline_at,
      met_at: p.sla_met_at,
      breached_at: p.sla_breached_at,
    }));

    const pdvList = allPdv ?? [];
    const met = pdvList.filter((p: any) => p.sla_status === 'met').length;
    const totalResolved = met + pdvList.filter((p: any) => p.sla_status === 'resolved_late').length;
    const summary = {
      time_range: timeRange,
      total_vulnerabilities: pdvList.length,
      met_within_sla: met,
      resolved_late: pdvList.filter((p: any) => p.sla_status === 'resolved_late').length,
      current_breaches: pdvList.filter((p: any) => p.sla_status === 'breached').length,
      compliance_percent: totalResolved > 0 ? Math.round((met / totalResolved) * 100) : 100,
    };

    res.json({ rows, summary });
  } catch (error: any) {
    console.error('Error exporting SLA compliance:', error);
    res.status(500).json({ error: error.message || 'Failed to export SLA compliance' });
  }
});

// GET /api/organizations/:id/sla-policy-changes
router.get('/:id/sla-policy-changes', async (req: AuthRequest, res) => {
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

    if (!(await canManageStatuses(id, userId))) {
      return res.status(403).json({ error: 'Permission denied.' });
    }

    const { data: changes, error } = await supabase
      .from('sla_policy_changes')
      .select('*')
      .eq('organization_id', id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    const rows = changes ?? [];
    const userIds = [...new Set(rows.map((r: any) => r.changed_by).filter(Boolean))];
    const profiles: Record<string, { full_name: string | null }> = {};
    if (userIds.length > 0) {
      const { data: profileRows } = await supabase
        .from('user_profiles')
        .select('user_id, full_name')
        .in('user_id', userIds);
      for (const p of profileRows ?? []) {
        profiles[p.user_id] = { full_name: p.full_name ?? null };
      }
    }

    const withUser = rows.map((r: any) => ({
      ...r,
      changed_by_user: profiles[r.changed_by] ?? { full_name: null },
    }));
    res.json(withUser);
  } catch (error: any) {
    console.error('Error fetching SLA policy changes:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch SLA policy changes' });
  }
});

// ───── Phase 4: Split Policy Code CRUD ─────

// GET /api/organizations/:id/policy-code
router.get('/:id/policy-code', async (req: AuthRequest, res) => {
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

    const [pkgResult, statusResult, prResult] = await Promise.all([
      supabase.from('organization_package_policies').select('*').eq('organization_id', id).single(),
      supabase.from('organization_status_codes').select('*').eq('organization_id', id).single(),
      supabase.from('organization_pr_checks').select('*').eq('organization_id', id).single(),
    ]);

    res.json({
      package_policy: pkgResult.data ?? { package_policy_code: null },
      status_code: statusResult.data ?? { project_status_code: null },
      pr_check: prResult.data ?? { pr_check_code: null },
    });
  } catch (error: any) {
    console.error('Error fetching policy code:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch policy code' });
  }
});

// PUT /api/organizations/:id/policy-code/:codeType
router.put('/:id/policy-code/:codeType', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, codeType } = req.params;
    const { code, message } = req.body;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      const { data: role } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      if (!(role?.permissions as Record<string, boolean>)?.manage_compliance) {
        return res.status(403).json({ error: 'Permission denied' });
      }
    }

    if (typeof code !== 'string') {
      return res.status(400).json({ error: 'code is required' });
    }

    const MAX_CODE_SIZE = 50_000;
    if (code.length > MAX_CODE_SIZE) {
      return res.status(400).json({ error: 'Policy code exceeds 50KB limit' });
    }

    let tableName: string;
    let columnName: string;
    switch (codeType) {
      case 'package_policy':
        tableName = 'organization_package_policies';
        columnName = 'package_policy_code';
        break;
      case 'project_status':
        tableName = 'organization_status_codes';
        columnName = 'project_status_code';
        break;
      case 'pr_check':
        tableName = 'organization_pr_checks';
        columnName = 'pr_check_code';
        break;
      default:
        return res.status(400).json({ error: 'Invalid code type. Must be package_policy, project_status, or pr_check' });
    }

    const { data: existing } = await supabase
      .from(tableName)
      .select('*')
      .eq('organization_id', id)
      .single();

    const previousCode = existing ? (existing as Record<string, unknown>)[columnName] as string : null;

    if (existing) {
      const { error: updateError } = await supabase
        .from(tableName)
        .update({ [columnName]: code, updated_at: new Date().toISOString(), updated_by_id: userId })
        .eq('organization_id', id);

      if (updateError) throw updateError;
    } else {
      const { error: insertError } = await supabase
        .from(tableName)
        .insert({ organization_id: id, [columnName]: code, updated_by_id: userId });

      if (insertError) throw insertError;
    }

    await supabase.from('organization_policy_changes').insert({
      organization_id: id,
      code_type: codeType,
      author_id: userId,
      previous_code: previousCode || '',
      new_code: code,
      message: message || `Updated ${codeType.replace('_', ' ')}`,
    });

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'updated_policy_code',
      description: `updated ${codeType.replace('_', ' ')} policy code`,
      metadata: { code_type: codeType },
    });

    try {
      await emitEvent({ type: 'policy_code_updated', organizationId: id, payload: { codeType, updatedBy: userId }, source: 'system', priority: 'normal' });
    } catch (e) {}

    res.json({ success: true, code_type: codeType });
  } catch (error: any) {
    console.error('Error updating policy code:', error);
    res.status(500).json({ error: error.message || 'Failed to update policy code' });
  }
});

// GET /api/organizations/:id/policy-changes - Org-level policy change history
router.get('/:id/policy-changes', async (req: AuthRequest, res) => {
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

    const codeTypeFilter = req.query.code_type as string | undefined;
    let query = supabase
      .from('organization_policy_changes')
      .select('*')
      .eq('organization_id', id)
      .order('created_at', { ascending: false })
      .limit(100);

    if (codeTypeFilter) {
      query = query.eq('code_type', codeTypeFilter);
    }

    const { data: changes, error } = await query;
    if (error) throw error;

    const list = changes ?? [];
    const authorIds = [...new Set(list.map((c: any) => c.author_id).filter(Boolean))];
    let profiles: Record<string, { full_name: string | null; avatar_url: string | null }> = {};
    if (authorIds.length > 0) {
      const { data: profileRows } = await supabase
        .from('user_profiles')
        .select('user_id, full_name, avatar_url')
        .in('user_id', authorIds);
      for (const p of profileRows ?? []) {
        profiles[p.user_id] = { full_name: p.full_name ?? null, avatar_url: p.avatar_url ?? null };
      }
      // Fallback: where full_name is missing, use Auth user metadata (OAuth often has name/email)
      for (const uid of authorIds) {
        if (!profiles[uid]?.full_name?.trim()) {
          const { data: { user: authUser } } = await supabase.auth.admin.getUserById(uid);
          const fallbackName = authUser?.user_metadata?.full_name
            || authUser?.user_metadata?.name
            || authUser?.email
            || null;
          if (fallbackName) {
            if (!profiles[uid]) profiles[uid] = { full_name: null, avatar_url: null };
            profiles[uid].full_name = fallbackName;
          }
          if (profiles[uid] && !profiles[uid].avatar_url && authUser?.user_metadata?.picture) {
            profiles[uid].avatar_url = authUser.user_metadata.picture;
          }
          if (profiles[uid] && !profiles[uid].avatar_url && authUser?.user_metadata?.avatar_url) {
            profiles[uid].avatar_url = authUser.user_metadata.avatar_url;
          }
        }
      }
    }

    const enriched = list.map((c: any) => ({
      ...c,
      author_display_name: profiles[c.author_id]?.full_name ?? null,
      author_avatar_url: profiles[c.author_id]?.avatar_url ?? null,
    }));

    res.json(enriched);
  } catch (error: any) {
    console.error('Error fetching policy changes:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch policy changes' });
  }
});

// GET /api/organizations/:id/policy-change-requests - Pending project policy change requests (for org Policies UI)
router.get('/:id/policy-change-requests', async (req: AuthRequest, res) => {
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

    const { data: changes, error } = await supabase
      .from('project_policy_changes')
      .select('*')
      .eq('organization_id', id)
      .eq('status', 'pending')
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) throw error;
    const list = changes ?? [];

    const projectIds = [...new Set(list.map((c: any) => c.project_id))];
    const authorIds = [...new Set(list.map((c: any) => c.author_id).filter(Boolean))];

    let projectNames: Record<string, string> = {};
    if (projectIds.length > 0) {
      const { data: projects } = await supabase
        .from('projects')
        .select('id, name')
        .in('id', projectIds);
      for (const p of projects ?? []) {
        projectNames[p.id] = p.name ?? 'Unknown project';
      }
    }

    let profiles: Record<string, { full_name: string | null; avatar_url: string | null }> = {};
    if (authorIds.length > 0) {
      const { data: profileRows } = await supabase
        .from('user_profiles')
        .select('user_id, full_name, avatar_url')
        .in('user_id', authorIds);
      for (const p of profileRows ?? []) {
        profiles[p.user_id] = { full_name: p.full_name ?? null, avatar_url: p.avatar_url ?? null };
      }
      for (const uid of authorIds) {
        if (!profiles[uid]?.full_name?.trim()) {
          const { data: { user: authUser } } = await supabase.auth.admin.getUserById(uid);
          const fallbackName = authUser?.user_metadata?.full_name
            || authUser?.user_metadata?.name
            || authUser?.email
            || null;
          if (fallbackName) {
            if (!profiles[uid]) profiles[uid] = { full_name: null, avatar_url: null };
            profiles[uid].full_name = fallbackName;
          }
          if (profiles[uid] && !profiles[uid].avatar_url && authUser?.user_metadata?.picture) {
            profiles[uid].avatar_url = authUser.user_metadata.picture;
          }
          if (profiles[uid] && !profiles[uid].avatar_url && authUser?.user_metadata?.avatar_url) {
            profiles[uid].avatar_url = authUser.user_metadata.avatar_url;
          }
        }
      }
    }

    const enriched = list.map((c: any) => ({
      ...c,
      project_name: projectNames[c.project_id] ?? 'Unknown project',
      author_display_name: profiles[c.author_id]?.full_name ?? null,
      author_avatar_url: profiles[c.author_id]?.avatar_url ?? null,
    }));

    res.json(enriched);
  } catch (error: any) {
    console.error('Error fetching policy change requests:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch policy change requests' });
  }
});

// POST /api/organizations/:id/policy-code/:codeType/revert
router.post('/:id/policy-code/:codeType/revert', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, codeType } = req.params;
    const { change_id } = req.body;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    if (membership.role !== 'owner' && membership.role !== 'admin') {
      const { data: role } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      if (!(role?.permissions as Record<string, boolean>)?.manage_compliance) {
        return res.status(403).json({ error: 'Permission denied' });
      }
    }

    let revertToCode: string;
    if (change_id) {
      const { data: change } = await supabase
        .from('organization_policy_changes')
        .select('new_code')
        .eq('id', change_id)
        .eq('organization_id', id)
        .single();

      if (!change) return res.status(404).json({ error: 'Change not found' });
      revertToCode = change.new_code;
    } else {
      const defaults: Record<string, string> = {
        package_policy: (await import('../lib/policy-defaults')).DEFAULT_PACKAGE_POLICY_CODE,
        project_status: (await import('../lib/policy-defaults')).DEFAULT_PROJECT_STATUS_CODE,
        pr_check: (await import('../lib/policy-defaults')).DEFAULT_PR_CHECK_CODE,
      };
      revertToCode = defaults[codeType] || '';
    }

    let tableName: string;
    let columnName: string;
    switch (codeType) {
      case 'package_policy':
        tableName = 'organization_package_policies';
        columnName = 'package_policy_code';
        break;
      case 'project_status':
        tableName = 'organization_status_codes';
        columnName = 'project_status_code';
        break;
      case 'pr_check':
        tableName = 'organization_pr_checks';
        columnName = 'pr_check_code';
        break;
      default:
        return res.status(400).json({ error: 'Invalid code type' });
    }

    const { data: existing } = await supabase
      .from(tableName)
      .select('*')
      .eq('organization_id', id)
      .single();

    const previousCode = existing ? (existing as Record<string, unknown>)[columnName] as string : '';

    await supabase
      .from(tableName)
      .update({ [columnName]: revertToCode, updated_at: new Date().toISOString(), updated_by_id: userId })
      .eq('organization_id', id);

    await supabase.from('organization_policy_changes').insert({
      organization_id: id,
      code_type: codeType,
      author_id: userId,
      previous_code: previousCode,
      new_code: revertToCode,
      message: change_id ? `Reverted to previous version` : 'Reverted to default template',
    });

    res.json({ success: true });
  } catch (error: any) {
    console.error('Error reverting policy code:', error);
    res.status(500).json({ error: error.message || 'Failed to revert policy code' });
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
      snoozedUntil: (r.snoozed_until as string) ?? undefined,
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

    // Plan limit check: notification rules
    try {
      const { checkPlanLimit, TIER_DISPLAY_NAMES } = require('../lib/plan-limits');
      const planCheck = await checkPlanLimit(id, 'notification_rules');
      if (!planCheck.allowed) {
        return res.status(403).json({
          error: 'PLAN_LIMIT',
          message: `Your ${TIER_DISPLAY_NAMES[planCheck.tier]} plan supports up to ${planCheck.limit} notification rules.`,
          resource: 'notification_rules', current: planCheck.current, limit: planCheck.limit,
          tier: planCheck.tier, upgradeTier: planCheck.upgradeTier,
        });
      }
    } catch (e) { /* fail open */ }

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
      const { validateNotificationTriggerCode } = require('../lib/notification-validator');
      if (customCode.trim()) {
        const validation = await validateNotificationTriggerCode(customCode);
        if (!validation.passed) {
          return res.status(422).json({ error: 'Validation failed', checks: validation.checks });
        }
      }
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

    const validTriggers = ['weekly_digest', 'custom_code_pipeline'];
    const updateData: Record<string, unknown> = {};
    if (typeof name === 'string') updateData.name = name.trim();
    if (triggerType && validTriggers.includes(triggerType)) updateData.trigger_type = triggerType;
    if (typeof minDepscoreThreshold === 'number') {
      updateData.min_depscore_threshold = minDepscoreThreshold;
    }
    if (triggerType === 'custom_code_pipeline' && typeof customCode === 'string') {
      const { validateNotificationTriggerCode } = require('../lib/notification-validator');
      if (customCode.trim()) {
        const validation = await validateNotificationTriggerCode(customCode);
        if (!validation.passed) {
          return res.status(422).json({ error: 'Validation failed', checks: validation.checks });
        }
      }
      updateData.custom_code = customCode;
    }
    if (Array.isArray(destinations)) updateData.destinations = destinations;
    if (typeof req.body.dryRun === 'boolean') updateData.dry_run = req.body.dryRun;
    if (typeof req.body.scheduleConfig === 'object') updateData.schedule_config = req.body.scheduleConfig;

    const { data: existing } = await supabase
      .from('organization_notification_rules')
      .select('custom_code, destinations')
      .eq('id', ruleId)
      .eq('organization_id', id)
      .single();

    const { data: updated, error } = await supabase
      .from('organization_notification_rules')
      .update(updateData)
      .eq('id', ruleId)
      .eq('organization_id', id)
      .select()
      .single();

    if (!error && updated && existing) {
      const { data: profile } = await supabase.from('user_profiles').select('full_name').eq('id', userId).single();
      await supabase.from('notification_rule_changes').insert({
        rule_id: ruleId,
        rule_scope: 'organization',
        organization_id: id,
        previous_code: existing.custom_code,
        new_code: updated.custom_code,
        previous_destinations: existing.destinations,
        new_destinations: updated.destinations,
        changed_by_user_id: userId,
        changed_by_name: profile?.full_name || req.user!.email,
      }).then(() => {}).catch(() => {});
    }

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

// POST /api/organizations/:id/validate-notification-rule - Validate trigger code
router.post('/:id/validate-notification-rule', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { code } = req.body;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'code is required' });
    }

    const { validateNotificationTriggerCode } = require('../lib/notification-validator');
    const result = await validateNotificationTriggerCode(code);
    res.json(result);
  } catch (error: any) {
    console.error('Validate notification rule error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/organizations/:id/test-notification-rule - Test trigger code against sample events
router.post('/:id/test-notification-rule', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { code, eventType } = req.body;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'code is required' });
    }

    const { executeNotificationTrigger } = require('../lib/notification-validator');
    const { buildDefaultMessage } = require('../lib/destination-dispatchers');

    const testEventTypes = eventType ? [eventType] : ['vulnerability_discovered', 'dependency_added', 'status_changed'];

    const SAMPLE_CONTEXTS: Record<string, any> = {
      vulnerability_discovered: {
        event: { type: 'vulnerability_discovered', timestamp: new Date().toISOString(), source: 'vuln_monitor' },
        project: { id: 'test-id', name: 'api-service', asset_tier: 'Crown Jewels', asset_tier_rank: 1, health_score: 72, status: 'Compliant', status_is_passing: true, dependencies_count: 145, team_name: 'Platform' },
        dependency: { name: 'lodash', version: '4.17.20', license: 'MIT', is_direct: true, is_dev_dependency: false, environment: 'production', score: 82, dependency_score: 82, openssf_score: 7.2, weekly_downloads: 45000000, malicious_indicator: null, slsa_level: 0, vulnerabilities: [] },
        vulnerability: { osv_id: 'GHSA-test-0000-0000', severity: 'critical', cvss_score: 9.8, epss_score: 0.45, depscore: 88, is_reachable: true, cisa_kev: false, fixed_versions: ['4.17.21'], summary: 'Prototype Pollution in lodash' },
        pr: null, previous: null, batch: null,
      },
      dependency_added: {
        event: { type: 'dependency_added', timestamp: new Date().toISOString(), source: 'extraction' },
        project: { id: 'test-id', name: 'web-app', asset_tier: 'External', asset_tier_rank: 2, health_score: 85, status: 'Compliant', status_is_passing: true, dependencies_count: 200, team_name: 'Frontend' },
        dependency: { name: 'new-pkg', version: '1.0.0', license: 'MIT', is_direct: true, is_dev_dependency: false, environment: 'production', score: 45, dependency_score: 45, openssf_score: 3.1, weekly_downloads: 1200, malicious_indicator: null, slsa_level: 0, vulnerabilities: [] },
        vulnerability: null, pr: null, previous: null, batch: null,
      },
      status_changed: {
        event: { type: 'status_changed', timestamp: new Date().toISOString(), source: 'policy_eval' },
        project: { id: 'test-id', name: 'api-service', asset_tier: 'Crown Jewels', asset_tier_rank: 1, health_score: 45, status: 'Blocked', status_is_passing: false, dependencies_count: 145, team_name: 'Platform' },
        dependency: null, vulnerability: null, pr: null,
        previous: { status: 'Compliant', status_is_passing: true, health_score: 72 }, batch: null,
      },
    };

    const results = [];
    for (const et of testEventTypes) {
      const sampleContext = SAMPLE_CONTEXTS[et] || SAMPLE_CONTEXTS.vulnerability_discovered;
      sampleContext.event.type = et;
      const start = Date.now();
      try {
        const triggerResult = await executeNotificationTrigger(code, sampleContext, id);
        const message = triggerResult.notify ? buildDefaultMessage(
          { id: 'test', event_type: et, organization_id: id, payload: sampleContext },
          sampleContext,
        ) : undefined;
        results.push({
          eventType: et, sampleContext, returnValue: triggerResult, wouldNotify: triggerResult.notify,
          message: message ? { title: message.title, body: message.body, severity: message.severity } : undefined,
          executionTimeMs: Date.now() - start,
        });
      } catch (err: any) {
        results.push({ eventType: et, sampleContext, wouldNotify: false, error: err.message, executionTimeMs: Date.now() - start });
      }
    }
    res.json({ results });
  } catch (error: any) {
    console.error('Test notification rule error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/organizations/:id/notification-history - Paginated delivery history
router.get('/:id/notification-history', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { event_type, destination_type, destination_id, status, timeframe, page: pageStr, per_page: perPageStr } = req.query;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    const page = parseInt(pageStr as string) || 1;
    const perPage = Math.min(parseInt(perPageStr as string) || 20, 50);
    const offset = (page - 1) * perPage;

    let query = supabase
      .from('notification_deliveries')
      .select('*, notification_events!inner(event_type, payload, priority, created_at)', { count: 'exact' })
      .eq('organization_id', id)
      .order('created_at', { ascending: false })
      .range(offset, offset + perPage - 1);

    if (event_type) query = query.eq('notification_events.event_type', event_type as string);
    if (destination_type) query = query.eq('destination_type', destination_type as string);
    if (destination_id) query = query.eq('destination_id', destination_id as string);
    if (status && status !== 'all') query = query.eq('status', status as string);
    if (timeframe) {
      const hours = timeframe === '24h' ? 24 : timeframe === '7d' ? 168 : timeframe === '30d' ? 720 : 168;
      query = query.gte('created_at', new Date(Date.now() - hours * 3600000).toISOString());
    }

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ deliveries: data || [], total: count || 0, page, perPage });
  } catch (error: any) {
    console.error('Notification history error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/organizations/:id/notification-history/:deliveryId/retry - Retry failed delivery
router.post('/:id/notification-history/:deliveryId/retry', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, deliveryId } = req.params;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { data: delivery } = await supabase
      .from('notification_deliveries')
      .select('event_id, status')
      .eq('id', deliveryId)
      .eq('organization_id', id)
      .single();

    if (!delivery) return res.status(404).json({ error: 'Delivery not found' });
    if (delivery.status !== 'failed') return res.status(400).json({ error: 'Only failed deliveries can be retried' });

    await supabase.from('notification_deliveries').update({ status: 'pending', attempts: 0 }).eq('id', deliveryId);

    const token = process.env.QSTASH_TOKEN;
    if (token) {
      const apiBaseUrl = process.env.API_BASE_URL || process.env.BACKEND_URL || 'http://localhost:3001';
      await fetch('https://qstash.upstash.io/v2/publish/' + encodeURIComponent(`${apiBaseUrl}/api/workers/dispatch-notification`), {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Upstash-Method': 'POST', 'Upstash-Retries': '5', 'Upstash-Forward-Content-Type': 'application/json' },
        body: JSON.stringify({ eventId: delivery.event_id }),
      });
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error('Retry delivery error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/organizations/:id/notification-stats - Aggregate notification stats
router.get('/:id/notification-stats', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;

    const { data: membership } = await supabase.from('organization_members').select('role').eq('organization_id', id).eq('user_id', userId).single();
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    const oneDayAgo = new Date(Date.now() - 24 * 3600000).toISOString();
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 3600000).toISOString();

    const [deliveries24h, deliveries7d, events7d, recentFailures] = await Promise.all([
      supabase.from('notification_deliveries').select('status', { count: 'exact' }).eq('organization_id', id).gte('created_at', oneDayAgo),
      supabase.from('notification_deliveries').select('status', { count: 'exact' }).eq('organization_id', id).gte('created_at', sevenDaysAgo),
      supabase.from('notification_events').select('event_type, created_at', { count: 'exact' }).eq('organization_id', id).gte('created_at', sevenDaysAgo),
      supabase.from('notification_deliveries').select('*').eq('organization_id', id).eq('status', 'failed').order('created_at', { ascending: false }).limit(5),
    ]);

    const delivered24h = (deliveries24h.data || []).filter((d: any) => d.status === 'delivered').length;
    const total24h = deliveries24h.count || 0;

    res.json({
      delivery_success_rate_24h: total24h > 0 ? Math.round((delivered24h / total24h) * 100) : 100,
      total_deliveries_24h: total24h,
      total_deliveries_7d: deliveries7d.count || 0,
      total_events_7d: events7d.count || 0,
      recent_failures: recentFailures.data || [],
    });
  } catch (error: any) {
    console.error('Notification stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/organizations/:id/notification-rules/:ruleId/history - Rule change history
router.get('/:id/notification-rules/:ruleId/history', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, ruleId } = req.params;

    const { data: membership } = await supabase.from('organization_members').select('role').eq('organization_id', id).eq('user_id', userId).single();
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    const { data, error } = await supabase
      .from('notification_rule_changes')
      .select('*')
      .eq('rule_id', ruleId)
      .eq('organization_id', id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    res.json(data || []);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/organizations/:id/notification-rules/:ruleId/revert/:changeId - Revert rule to previous version
router.post('/:id/notification-rules/:ruleId/revert/:changeId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, ruleId, changeId } = req.params;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { data: change } = await supabase
      .from('notification_rule_changes')
      .select('previous_code, previous_destinations')
      .eq('id', changeId)
      .eq('rule_id', ruleId)
      .single();

    if (!change) return res.status(404).json({ error: 'Change not found' });

    const updateData: Record<string, any> = {};
    if (change.previous_code !== null) updateData.custom_code = change.previous_code;
    if (change.previous_destinations !== null) updateData.destinations = change.previous_destinations;

    const { data: updated, error } = await supabase
      .from('organization_notification_rules')
      .update(updateData)
      .eq('id', ruleId)
      .eq('organization_id', id)
      .select()
      .single();

    if (error) throw error;
    res.json(updated);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/integrations/organizations/:orgId/pagerduty/connect - PagerDuty connect
router.post('/:id/pagerduty/connect', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { routingKey, serviceName } = req.body;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (!routingKey || routingKey.length < 20) {
      return res.status(400).json({ error: 'Invalid PagerDuty routing key' });
    }

    const testResponse = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: 'trigger',
        dedup_key: `deptex-test-${Date.now()}`,
        payload: { summary: 'Deptex connection test - you can resolve this incident', source: 'Deptex', severity: 'info' },
      }),
    });

    if (!testResponse.ok) {
      return res.status(400).json({ error: 'PagerDuty rejected the routing key' });
    }

    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ routing_key: routingKey, event_action: 'resolve', dedup_key: `deptex-test-${Date.now()}` }),
    }).catch(() => {});

    await supabase.from('organization_integrations').upsert({
      organization_id: id,
      provider: 'pagerduty',
      access_token: routingKey,
      display_name: serviceName || 'PagerDuty',
      metadata: { service_name: serviceName },
      status: 'active',
    }, { onConflict: 'organization_id,provider' });

    res.json({ success: true });
  } catch (error: any) {
    console.error('PagerDuty connect error:', error);
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/organizations/:id/notification-rules/:ruleId/snooze - Snooze a rule
router.patch('/:id/notification-rules/:ruleId/snooze', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, ruleId } = req.params;
    const { snoozedUntil } = req.body;

    if (!(await canManageNotificationRules(id, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { data, error } = await supabase
      .from('organization_notification_rules')
      .update({ snoozed_until: snoozedUntil || null })
      .eq('id', ruleId)
      .eq('organization_id', id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/organizations/:id/notification-rule-templates - Get rule templates
router.get('/:id/notification-rule-templates', async (req: AuthRequest, res) => {
  const RULE_TEMPLATES = [
    { id: 'critical-vuln-alert', name: 'Critical Vulnerability Alert', description: 'Notify immediately when a critical or high-severity vulnerability is discovered', code: "if (context.event.type !== 'vulnerability_discovered') return false;\nif (!context.vulnerability) return false;\nreturn context.vulnerability.severity === 'critical' || context.vulnerability.severity === 'high';", suggestedDestinations: ['slack', 'email', 'pagerduty'] },
    { id: 'malicious-package', name: 'Malicious Package Detection', description: 'Immediate alert when a dependency is flagged as malicious', code: "return context.event.type === 'malicious_package_detected';", suggestedDestinations: ['slack', 'pagerduty', 'email'] },
    { id: 'weekly-digest', name: 'Weekly Security Digest', description: 'Weekly summary of all security events across projects', triggerType: 'weekly_digest', suggestedDestinations: ['email', 'slack'] },
    { id: 'policy-violation', name: 'Policy Violation Alert', description: 'Alert when a dependency violates package policy', code: "return context.event.type === 'policy_violation' || context.event.type === 'license_violation';", suggestedDestinations: ['slack', 'jira'] },
    { id: 'extraction-failure', name: 'Extraction Failure Alert', description: 'Alert when dependency extraction fails', code: "return context.event.type === 'extraction_failed';", suggestedDestinations: ['slack', 'email'] },
    { id: 'pr-check-failure', name: 'PR Check Failure', description: 'Alert when a PR fails dependency policy checks', code: "if (context.event.type !== 'pr_check_completed') return false;\nreturn context.pr && context.pr.check_result === 'failed';", suggestedDestinations: ['slack', 'discord'] },
    { id: 'crown-jewels-any-change', name: 'Crown Jewels - Any Change', description: 'Alert on any event affecting Crown Jewels projects', code: "return context.project.asset_tier === 'Crown Jewels';", suggestedDestinations: ['slack', 'pagerduty'] },
    { id: 'new-dep-low-score', name: 'New Dependency with Low Score', description: 'Alert when a new dependency is added with a low reputation score', code: "if (context.event.type !== 'dependency_added') return false;\nreturn context.dependency && context.dependency.score < 50;", suggestedDestinations: ['slack', 'jira'] },
    { id: 'watchtower-alerts', name: 'Watchtower Alerts', description: 'Alert on supply chain security check failures, high-anomaly commits, and new version availability', code: "const watchEvents = [\n  'security_analysis_failure',\n  'supply_chain_anomaly',\n  'new_version_available'\n];\nif (!watchEvents.includes(context.event.type)) return false;\nreturn true;", suggestedDestinations: ['slack', 'email'] },
  ];
  res.json(RULE_TEMPLATES);
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

    const systemPrompt = `You are an expert AI assistant that helps users write Deptex policy-as-code. You can chat normally or suggest JavaScript function bodies for dependency security policies.

## When to respond with code vs chat only

- **Chat only (code must be null):** Greetings ("hello", "hi"), small talk, "what can you do?", "explain X", any question that is not explicitly asking you to change or write policy code. Reply briefly and helpfully in "message"; set "code" to null.
- **Provide code only when:** The user clearly asks you to implement, change, or add a policy rule (e.g. "only allow MIT license", "block critical vulns in PRs", "require OpenSSF score >= 3"). Then set both "message" (short explanation) and "code" (the full function body).

Do NOT suggest or rewrite code when the user is just saying hello, asking what you do, or having a general conversation. When in doubt, respond with chat only and set "code" to null.

## Type Definitions
${POLICY_TYPEDEFS}

## Example Policies
${EXAMPLE_POLICIES}

## Your Task (when the user asks for a code change)
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
  "message": "Brief reply or explanation",
  "code": null
}
or when the user explicitly asked for a code change:
{
  "message": "Brief explanation of what the code does",
  "code": "the complete function body as a string"
}

- For greetings, questions, or non-code requests: always use "code": null and answer in "message" only.
- When providing code, always provide the COMPLETE function body, not a partial diff. Use plain JavaScript (no TypeScript syntax).`;

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

    const provider = getPlatformProvider();

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    let fullContent = '';
    let usage: { inputTokens: number; outputTokens: number } | undefined;

    for await (const chunk of provider.streamChat(messages, { model: 'gemini-2.5-flash' })) {
      if (chunk.type === 'text' && chunk.content) {
        fullContent += chunk.content;
        res.write(`data: ${JSON.stringify({ type: 'chunk', content: chunk.content })}\n\n`);
      } else if (chunk.type === 'done') {
        if (chunk.usage) usage = chunk.usage;
        break;
      }
    }

    res.write(`data: ${JSON.stringify({ type: 'done', fullContent, usage })}\n\n`);
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

    const NOTIFICATION_PROVIDERS = ['slack', 'discord', 'jira', 'linear', 'asana', 'pagerduty', 'custom_notification', 'custom_ticketing', 'email'];

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

// POST /api/organizations/:id/teams/:teamId/pagerduty/connect - PagerDuty connect at team level
router.post('/:id/teams/:teamId/pagerduty/connect', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId } = req.params;
    const { routingKey, serviceName } = req.body;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (!routingKey || routingKey.length < 20) {
      return res.status(400).json({ error: 'Invalid PagerDuty routing key' });
    }

    const testResponse = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: 'trigger',
        dedup_key: `deptex-test-${Date.now()}`,
        payload: { summary: 'Deptex connection test - you can resolve this incident', source: 'Deptex', severity: 'info' },
      }),
    });

    if (!testResponse.ok) {
      return res.status(400).json({ error: 'PagerDuty rejected the routing key' });
    }

    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ routing_key: routingKey, event_action: 'resolve', dedup_key: `deptex-test-${Date.now()}` }),
    }).catch(() => {});

    const { data: team } = await supabase
      .from('teams')
      .select('id')
      .eq('id', teamId)
      .eq('organization_id', orgId)
      .single();
    if (!team) return res.status(404).json({ error: 'Team not found' });

    await supabase.from('team_integrations').insert({
      team_id: teamId,
      provider: 'pagerduty',
      access_token: routingKey,
      display_name: serviceName || 'PagerDuty',
      metadata: { service_name: serviceName },
      status: 'connected',
    });

    res.json({ success: true });
  } catch (error: any) {
    console.error('Team PagerDuty connect error:', error);
    res.status(500).json({ error: error.message });
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
      snoozedUntil: r.snoozed_until ?? undefined,
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
      const { validateNotificationTriggerCode } = require('../lib/notification-validator');
      if (customCode.trim()) {
        const validation = await validateNotificationTriggerCode(customCode);
        if (!validation.passed) {
          return res.status(422).json({ error: 'Validation failed', checks: validation.checks });
        }
      }
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
    if (triggerType === 'custom_code_pipeline' && typeof customCode === 'string') {
      const { validateNotificationTriggerCode } = require('../lib/notification-validator');
      if (customCode.trim()) {
        const validation = await validateNotificationTriggerCode(customCode);
        if (!validation.passed) {
          return res.status(422).json({ error: 'Validation failed', checks: validation.checks });
        }
      }
      updateData.custom_code = customCode;
    } else if (triggerType === 'custom_code_pipeline') {
      updateData.custom_code = null;
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

// PATCH /api/organizations/:id/teams/:teamId/notification-rules/:ruleId/snooze - Snooze a team rule
router.patch('/:id/teams/:teamId/notification-rules/:ruleId/snooze', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, teamId, ruleId } = req.params;
    const { snoozedUntil } = req.body;

    if (!(await canManageTeamNotifications(orgId, teamId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    const { data, error } = await supabase
      .from('team_notification_rules')
      .update({ snoozed_until: snoozedUntil || null })
      .eq('id', ruleId)
      .eq('team_id', teamId)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error: any) {
    console.error('Error snoozing team notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to snooze' });
  }
});

// ============================================================
// AI Provider Management (BYOK)
// ============================================================

async function hasManageIntegrations(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.manage_integrations === true;
}

// POST /api/organizations/:id/ai-providers -- add or update provider
router.post('/:id/ai-providers', async (req: AuthRequest, res) => {
  try {
    const { encryptApiKey, isEncryptionConfigured } = await import('../lib/ai/encryption');
    if (!isEncryptionConfigured()) {
      return res.status(503).json({ error: 'AI encryption not configured. Contact your administrator.' });
    }

    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { provider, api_key, model_preference, monthly_cost_cap, display_name, api_base_url } = req.body;
    if (!provider || !api_key) {
      return res.status(400).json({ error: 'provider and api_key are required' });
    }
    if (!['openai', 'anthropic', 'google', 'custom'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider. Must be openai, anthropic, google, or custom' });
    }
    if (provider === 'custom' && (!display_name || typeof display_name !== 'string' || !display_name.trim())) {
      return res.status(400).json({ error: 'display_name is required for custom provider' });
    }
    if (provider === 'custom' && (!api_base_url || typeof api_base_url !== 'string' || !api_base_url.trim())) {
      return res.status(400).json({ error: 'api_base_url is required for custom provider' });
    }

    const { encrypted, version } = encryptApiKey(api_key);

    const { data: existing } = await supabase
      .from('organization_ai_providers')
      .select('id')
      .eq('organization_id', orgId);

    const isOnlyProvider = !existing || existing.length === 0;

    if (provider === 'custom') {
      const { data, error } = await supabase
        .from('organization_ai_providers')
        .insert({
          organization_id: orgId,
          provider: 'custom',
          encrypted_api_key: encrypted,
          encryption_key_version: version,
          display_name: (display_name || '').trim(),
          api_base_url: (api_base_url || '').trim().replace(/\/$/, ''),
          model_preference: model_preference || null,
          monthly_cost_cap: monthly_cost_cap ?? 100,
          is_default: isOnlyProvider,
          updated_at: new Date().toISOString(),
        })
        .select('id, provider, model_preference, is_default, monthly_cost_cap, display_name, api_base_url, created_at, updated_at')
        .single();
      if (error) throw error;
      return res.json({ ...data, connected: true });
    }

    const { data, error } = await supabase
      .from('organization_ai_providers')
      .upsert({
        organization_id: orgId,
        provider,
        encrypted_api_key: encrypted,
        encryption_key_version: version,
        model_preference: model_preference || null,
        monthly_cost_cap: monthly_cost_cap ?? 100,
        is_default: isOnlyProvider ? true : undefined,
        updated_at: new Date().toISOString(),
      }, { onConflict: 'organization_id,provider' })
      .select('id, provider, model_preference, is_default, monthly_cost_cap, display_name, api_base_url, created_at, updated_at')
      .single();

    if (error) throw error;
    res.json({ ...data, connected: true });
  } catch (error: any) {
    console.error('Error adding AI provider:', error);
    res.status(500).json({ error: error.message || 'Failed to add AI provider' });
  }
});

// GET /api/organizations/:id/ai-providers -- list providers (no keys)
router.get('/:id/ai-providers', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { data, error } = await supabase
      .from('organization_ai_providers')
      .select('id, provider, model_preference, is_default, monthly_cost_cap, display_name, api_base_url, created_at, updated_at')
      .eq('organization_id', orgId);

    if (error) throw error;
    res.json((data || []).map((p: any) => ({ ...p, connected: true })));
  } catch (error: any) {
    console.error('Error listing AI providers:', error);
    res.status(500).json({ error: error.message || 'Failed to list AI providers' });
  }
});

// DELETE /api/organizations/:id/ai-providers/:providerId
router.delete('/:id/ai-providers/:providerId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { providerId } = req.params;

    const { data: activeThreads } = await supabase
      .from('aegis_chat_threads')
      .select('id')
      .eq('organization_id', orgId)
      .gte('updated_at', new Date(Date.now() - 5 * 60 * 1000).toISOString())
      .limit(1);

    let warning: string | undefined;
    if (activeThreads?.length) {
      warning = 'There are active Aegis conversations using this provider. They may be affected.';
    }

    const { error } = await supabase
      .from('organization_ai_providers')
      .delete()
      .eq('id', providerId)
      .eq('organization_id', orgId);

    if (error) throw error;
    res.json({ message: 'Provider deleted', ...(warning ? { warning } : {}) });
  } catch (error: any) {
    console.error('Error deleting AI provider:', error);
    res.status(500).json({ error: error.message || 'Failed to delete AI provider' });
  }
});

// POST /api/organizations/:id/ai-providers/test -- test connection (dry-run)
router.post('/:id/ai-providers/test', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;

    const { checkRateLimit } = await import('../lib/rate-limit');
    const rl = await checkRateLimit(`ai:test:${userId}`, 5, 60);
    if (!rl.allowed) {
      return res.status(429).json({ error: 'Too many test requests. Try again in a minute.' });
    }

    const { provider, api_key, model, api_base_url } = req.body;
    if (!provider || !api_key) {
      return res.status(400).json({ error: 'provider and api_key are required' });
    }

    const { createProviderFromKey } = await import('../lib/ai/provider');
    const baseURL = provider === 'custom' ? (api_base_url || '').trim().replace(/\/$/, '') : undefined;
    const aiProvider = createProviderFromKey(provider, api_key, model, baseURL);

    const result = await aiProvider.chat([
      { role: 'user', content: 'Say hello in exactly one word.' }
    ], { maxTokens: 10 });

    res.json({ success: true, model: result.model, response: result.content.slice(0, 100) });
  } catch (error: any) {
    const { AIProviderError } = await import('../lib/ai/types');
    if (error instanceof AIProviderError) {
      return res.json({ success: false, error: error.message, code: error.code });
    }
    res.json({ success: false, error: error.message || 'Connection test failed' });
  }
});

// PATCH /api/organizations/:id/ai-providers/:providerId -- update model_preference, or (custom) display_name, api_base_url
router.patch('/:id/ai-providers/:providerId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    const providerId = req.params.providerId;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { model_preference, display_name, api_base_url } = req.body;
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (model_preference !== undefined) updates.model_preference = model_preference === '' ? null : model_preference;
    if (display_name !== undefined) updates.display_name = display_name === '' ? null : (display_name || '').trim();
    if (api_base_url !== undefined) updates.api_base_url = api_base_url === '' ? null : (api_base_url || '').trim().replace(/\/$/, '');

    const { data, error } = await supabase
      .from('organization_ai_providers')
      .update(updates)
      .eq('id', providerId)
      .eq('organization_id', orgId)
      .select('id, provider, model_preference, is_default, monthly_cost_cap, display_name, api_base_url, updated_at')
      .single();

    if (error) throw error;
    res.json({ ...data, connected: true });
  } catch (error: any) {
    console.error('Error updating AI provider:', error);
    res.status(500).json({ error: error.message || 'Failed to update provider' });
  }
});

// PATCH /api/organizations/:id/ai-providers/:providerId/default
router.patch('/:id/ai-providers/:providerId/default', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const { providerId } = req.params;

    await supabase
      .from('organization_ai_providers')
      .update({ is_default: false, updated_at: new Date().toISOString() })
      .eq('organization_id', orgId);

    const { error } = await supabase
      .from('organization_ai_providers')
      .update({ is_default: true, updated_at: new Date().toISOString() })
      .eq('id', providerId)
      .eq('organization_id', orgId);

    if (error) throw error;
    res.json({ message: 'Default provider updated' });
  } catch (error: any) {
    console.error('Error setting default AI provider:', error);
    res.status(500).json({ error: error.message || 'Failed to set default provider' });
  }
});

// ============================================================
// AI Usage Dashboard
// ============================================================

// GET /api/organizations/:id/ai-usage
router.get('/:id/ai-usage', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to view AI usage' });
    }

    const period = req.query.period === '7d' ? 7 : req.query.period === '90d' ? 90 : 30;
    const { getAIUsageSummary } = await import('../lib/ai/logging');
    const summary = await getAIUsageSummary(orgId, period);
    res.json(summary);
  } catch (error: any) {
    console.error('Error fetching AI usage:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch AI usage' });
  }
});

// GET /api/organizations/:id/ai-usage/logs
router.get('/:id/ai-usage/logs', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to view AI usage logs' });
    }

    const page = parseInt(req.query.page as string) || 1;
    const perPage = Math.min(parseInt(req.query.per_page as string) || 50, 100);
    const { getAIUsageLogs } = await import('../lib/ai/logging');
    const result = await getAIUsageLogs(orgId, page, perPage);
    res.json(result);
  } catch (error: any) {
    console.error('Error fetching AI usage logs:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch AI usage logs' });
  }
});

// ============================================================
// Webhook Deliveries
// ============================================================

// GET /api/organizations/:id/webhook-deliveries
router.get('/:id/webhook-deliveries', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const provider = (req.query.provider as string) || 'ALL';
    const status = (req.query.status as string) || 'ALL';
    const eventType = (req.query.event_type as string) || 'ALL';
    const repo = req.query.repo as string | undefined;
    const timeframe = (req.query.timeframe as string) || '30D';
    const page = parseInt(req.query.page as string) || 1;
    const perPage = Math.min(parseInt(req.query.per_page as string) || 50, 100);

    const { data: projects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', orgId);

    if (!projects || projects.length === 0) {
      return res.json({ deliveries: [], total: 0, page, per_page: perPage });
    }

    const projectIds = projects.map((p: any) => p.id);
    const { data: repos } = await supabase
      .from('project_repositories')
      .select('repo_full_name')
      .in('project_id', projectIds);

    const repoNames = (repos || []).map((r: any) => r.repo_full_name).filter(Boolean);
    if (repoNames.length === 0) {
      return res.json({ deliveries: [], total: 0, page, per_page: perPage });
    }

    const timeframeMs: Record<string, number> = {
      '1H': 60 * 60 * 1000,
      '24H': 24 * 60 * 60 * 1000,
      '7D': 7 * 24 * 60 * 60 * 1000,
      '30D': 30 * 24 * 60 * 60 * 1000,
    };
    const cutoff = new Date(Date.now() - (timeframeMs[timeframe] || timeframeMs['30D'])).toISOString();

    let query = supabase
      .from('webhook_deliveries')
      .select('*', { count: 'exact' })
      .in('repo_full_name', repoNames)
      .gte('created_at', cutoff);

    // Exclude check_suite and check_run (recorded for audit but not actionable in UI)
    query = query.not('event_type', 'in', '("check_suite","check_run")');

    if (provider !== 'ALL') query = query.eq('provider', provider);
    if (status !== 'ALL') query = query.eq('processing_status', status);
    if (eventType !== 'ALL') query = query.eq('event_type', eventType);
    if (repo) query = query.eq('repo_full_name', repo);

    query = query.order('created_at', { ascending: false });

    const offset = (page - 1) * perPage;
    query = query.range(offset, offset + perPage - 1);

    const { data: deliveries, count, error } = await query;
    if (error) throw error;

    res.json({ deliveries: deliveries || [], total: count || 0, page, per_page: perPage });
  } catch (error: any) {
    console.error('Error fetching webhook deliveries:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch webhook deliveries' });
  }
});

// GET /api/organizations/:id/webhook-deliveries/stats
router.get('/:id/webhook-deliveries/stats', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;
    if (!(await hasManageIntegrations(orgId, userId))) {
      return res.status(403).json({ error: 'You do not have permission to manage integrations' });
    }

    const timeframe = (req.query.timeframe as string) || '30D';

    const { data: projects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', orgId);

    if (!projects || projects.length === 0) {
      return res.json({ total: 0, processed: 0, errors: 0, skipped: 0 });
    }

    const projectIds = projects.map((p: any) => p.id);
    const { data: repos } = await supabase
      .from('project_repositories')
      .select('repo_full_name')
      .in('project_id', projectIds);

    const repoNames = (repos || []).map((r: any) => r.repo_full_name).filter(Boolean);
    if (repoNames.length === 0) {
      return res.json({ total: 0, processed: 0, errors: 0, skipped: 0 });
    }

    const timeframeMs: Record<string, number> = {
      '1H': 60 * 60 * 1000,
      '24H': 24 * 60 * 60 * 1000,
      '7D': 7 * 24 * 60 * 60 * 1000,
      '30D': 30 * 24 * 60 * 60 * 1000,
    };
    const cutoff = new Date(Date.now() - (timeframeMs[timeframe] || timeframeMs['30D'])).toISOString();

    const { data: deliveries, error } = await supabase
      .from('webhook_deliveries')
      .select('processing_status')
      .in('repo_full_name', repoNames)
      .gte('created_at', cutoff)
      .not('event_type', 'in', '("check_suite","check_run")');

    if (error) throw error;

    const all = deliveries || [];
    res.json({
      total: all.length,
      processed: all.filter((d: any) => d.processing_status === 'processed').length,
      errors: all.filter((d: any) => d.processing_status === 'error').length,
      skipped: all.filter((d: any) => d.processing_status === 'skipped').length,
    });
  } catch (error: any) {
    console.error('Error fetching webhook delivery stats:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch webhook delivery stats' });
  }
});

// ============================================================================
// Phase 10: Organization Stats endpoint
// ============================================================================

// GET /api/organizations/:id/stats
router.get('/:id/stats', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId } = req.params;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const cacheKey = `org-stats:${orgId}`;
    const cached = await getCached<any>(cacheKey);
    if (cached) return res.json(cached);

    const [
      projectsResult,
      syncingResult,
      membersResult,
      statusesResult,
    ] = await Promise.all([
      supabase.from('projects').select('id, name, health_score, status_id').eq('organization_id', orgId),
      supabase.from('extraction_jobs').select('id', { count: 'exact', head: true }).eq('organization_id', orgId).in('status', ['queued', 'processing']),
      supabase.from('organization_members').select('id', { count: 'exact', head: true }).eq('organization_id', orgId),
      supabase.from('organization_statuses').select('id, name, color, is_passing').eq('organization_id', orgId),
    ]);

    const projects = projectsResult.data ?? [];
    const projectIds = projects.map((p: any) => p.id);

    // Health bands
    const healthy = projects.filter((p: any) => (p.health_score ?? 0) >= 80).length;
    const atRisk = projects.filter((p: any) => (p.health_score ?? 0) >= 50 && (p.health_score ?? 0) < 80).length;
    const critical = projects.filter((p: any) => (p.health_score ?? 0) < 50).length;

    // Vulns across all org projects
    let vulnTotals = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    let topVulns: any[] = [];
    if (projectIds.length > 0) {
      const { data: vulns } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('severity, depscore, project_id, project_dependency_id')
        .in('project_id', projectIds)
        .eq('suppressed', false);

      for (const v of vulns ?? []) {
        vulnTotals.total++;
        if (v.severity === 'critical') vulnTotals.critical++;
        else if (v.severity === 'high') vulnTotals.high++;
        else if (v.severity === 'medium') vulnTotals.medium++;
        else if (v.severity === 'low') vulnTotals.low++;
      }

      // Top 5 critical/high vulns by depscore
      const { data: topVulnRows } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('osv_id, severity, depscore, project_id')
        .in('project_id', projectIds)
        .eq('suppressed', false)
        .in('severity', ['critical', 'high'])
        .order('depscore', { ascending: false })
        .limit(20);

      const osvIdSet = new Set<string>();
      const topRaw: any[] = [];
      for (const r of topVulnRows ?? []) {
        if (!r.osv_id || osvIdSet.has(r.osv_id)) continue;
        osvIdSet.add(r.osv_id);
        topRaw.push(r);
        if (topRaw.length >= 5) break;
      }

      if (topRaw.length > 0) {
        const { data: vulnDetails } = await supabase
          .from('dependency_vulnerabilities')
          .select('osv_id, summary, severity')
          .in('osv_id', topRaw.map((r: any) => r.osv_id));
        const detailMap = new Map((vulnDetails ?? []).map((d: any) => [d.osv_id, d]));

        // Count affected projects per osv_id
        const affectedCounts = new Map<string, Set<string>>();
        for (const v of topVulnRows ?? []) {
          if (!v.osv_id) continue;
          if (!affectedCounts.has(v.osv_id)) affectedCounts.set(v.osv_id, new Set());
          affectedCounts.get(v.osv_id)!.add(v.project_id);
        }

        const projectNameMap = new Map(projects.map((p: any) => [p.id, p.name]));

        topVulns = topRaw.map((r: any) => {
          const detail = detailMap.get(r.osv_id);
          return {
            osv_id: r.osv_id,
            summary: detail?.summary ?? '',
            severity: detail?.severity ?? r.severity,
            depscore: r.depscore ?? 0,
            affected_project_count: affectedCounts.get(r.osv_id)?.size ?? 1,
            worst_project: { id: r.project_id, name: projectNameMap.get(r.project_id) ?? 'Unknown' },
          };
        });
      }
    }

    // Code findings
    let semgrepTotal = 0;
    let secretTotal = 0;
    if (projectIds.length > 0) {
      const [sr, scr] = await Promise.all([
        supabase.from('project_semgrep_findings').select('id', { count: 'exact', head: true }).in('project_id', projectIds),
        supabase.from('project_secret_findings').select('id', { count: 'exact', head: true }).in('project_id', projectIds),
      ]);
      semgrepTotal = sr.count ?? 0;
      secretTotal = scr.count ?? 0;
    }

    // Status distribution
    const statuses = statusesResult.data ?? [];
    const statusDist = statuses.map((s: any) => ({
      status_id: s.id, name: s.name, color: s.color, is_passing: s.is_passing,
      count: projects.filter((p: any) => p.status_id === s.id).length,
    }));
    const passingProjects = projects.filter((p: any) => {
      const st = statuses.find((s: any) => s.id === p.status_id);
      return st?.is_passing === true;
    }).length;
    const compliancePercent = projects.length > 0 ? Math.round((passingProjects / projects.length) * 100) : 100;

    // Dependencies total
    let depsTotalCount = 0;
    if (projectIds.length > 0) {
      const { count } = await supabase.from('project_dependencies').select('id', { count: 'exact', head: true }).in('project_id', projectIds);
      depsTotalCount = count ?? 0;
    }

    // Phase 15: SLA aggregates (org-wide)
    let slaAgg = { compliance_percent: 100, on_track: 0, warning: 0, breached: 0, exempt: 0, met: 0, resolved_late: 0 };
    if (projectIds.length > 0) {
      const { data: pdvSla } = await supabase
        .from('project_dependency_vulnerabilities')
        .select('sla_status')
        .in('project_id', projectIds);
      const list = pdvSla ?? [];
      const met = list.filter((p: any) => p.sla_status === 'met').length;
      const resolvedLate = list.filter((p: any) => p.sla_status === 'resolved_late').length;
      const totalResolved = met + resolvedLate;
      slaAgg = {
        compliance_percent: totalResolved > 0 ? Math.round((met / totalResolved) * 100) : 100,
        on_track: list.filter((p: any) => p.sla_status === 'on_track').length,
        warning: list.filter((p: any) => p.sla_status === 'warning').length,
        breached: list.filter((p: any) => p.sla_status === 'breached').length,
        exempt: list.filter((p: any) => p.sla_status === 'exempt').length,
        met,
        resolved_late: resolvedLate,
      };
    }

    const result = {
      projects: { total: projects.length, healthy, at_risk: atRisk, critical, syncing_count: syncingResult.count ?? 0 },
      vulnerabilities: vulnTotals,
      code_findings: { semgrep_total: semgrepTotal, secret_total: secretTotal },
      compliance: { percent: compliancePercent, status_distribution: statusDist },
      top_vulnerabilities: topVulns,
      dependencies_total: depsTotalCount,
      members_count: membersResult.count ?? 0,
      sla: slaAgg,
    };

    await setCached(cacheKey, result, 60);
    res.json(result);
  } catch (error: any) {
    console.error('Error fetching org stats:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch organization stats' });
  }
});

// ===== ORG WATCHTOWER ENDPOINTS (Phase 10B) =====

router.get('/:id/watchtower/overview', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      res.status(403).json({ error: 'Not a member' });
      return;
    }

    const cacheKey = `watchtower-org-stats:${orgId}`;
    const cached = await getCached(cacheKey);
    if (cached) { res.json(cached); return; }

    const { data: projects } = await supabase
      .from('projects')
      .select('id, name, watchtower_enabled, watchtower_enabled_at, asset_tier_id, health_score')
      .eq('organization_id', orgId);

    const allProjects = projects || [];
    const enabledProjects = allProjects.filter((p: any) => p.watchtower_enabled);

    const { data: watchlistEntries } = await supabase
      .from('organization_watchlist')
      .select('id, dependency_id')
      .eq('organization_id', orgId);

    const depIds = (watchlistEntries || []).map((w: any) => w.dependency_id);
    let depNames: string[] = [];
    if (depIds.length > 0) {
      const { data: deps } = await supabase
        .from('dependencies')
        .select('id, name')
        .in('id', depIds);
      depNames = (deps || []).map((d: any) => d.name);
    }

    let totalAlerts = 0;
    let totalBlocked = 0;
    if (depNames.length > 0) {
      const { data: pkgs } = await supabase
        .from('watched_packages')
        .select('id, name, status, analysis_data')
        .in('name', depNames);

      for (const pkg of pkgs || []) {
        const ad = pkg.analysis_data as any;
        if (ad?.registryIntegrityStatus === 'fail' || ad?.installScriptsStatus === 'fail' || ad?.entropyAnalysisStatus === 'fail') {
          totalAlerts++;
        }
      }
    }

    const { data: tiers } = await supabase
      .from('organization_asset_tiers')
      .select('id, name')
      .eq('organization_id', orgId);

    const tierMap = new Map((tiers || []).map((t: any) => [t.id, t.name]));

    const projectsSummary = allProjects.map((p: any) => ({
      id: p.id,
      name: p.name,
      tier: tierMap.get(p.asset_tier_id) || null,
      watchtower_enabled: p.watchtower_enabled,
      enabled_at: p.watchtower_enabled_at,
    }));

    const result = {
      projects_enabled: enabledProjects.length,
      projects_total: allProjects.length,
      packages_monitored: depNames.length,
      total_alerts: totalAlerts,
      total_blocked: totalBlocked,
      projects: projectsSummary,
    };

    await setCached(cacheKey, result, 60);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch overview' });
  }
});

router.get('/:id/watchtower/projects', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      res.status(403).json({ error: 'Not a member' });
      return;
    }

    const { data: projects } = await supabase
      .from('projects')
      .select('id, name, watchtower_enabled, watchtower_enabled_at, asset_tier_id')
      .eq('organization_id', orgId);

    const { data: tiers } = await supabase
      .from('organization_asset_tiers')
      .select('id, name')
      .eq('organization_id', orgId);

    const tierMap = new Map((tiers || []).map((t: any) => [t.id, t.name]));

    const result = (projects || []).map((p: any) => ({
      id: p.id,
      name: p.name,
      tier: tierMap.get(p.asset_tier_id) || null,
      watchtower_enabled: p.watchtower_enabled,
      enabled_at: p.watchtower_enabled_at,
    }));

    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch projects' });
  }
});

router.get('/:id/watchtower/package-usage', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const orgId = req.params.id;

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) {
      res.status(403).json({ error: 'Not a member' });
      return;
    }

    const { data: orgProjects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', orgId);

    const projectIds = (orgProjects || []).map((p: any) => p.id);
    if (projectIds.length === 0) {
      res.json([]);
      return;
    }

    const { data: deps } = await supabase
      .from('project_dependencies')
      .select('dependency_id, name, project_id')
      .in('project_id', projectIds)
      .eq('is_direct', true);

    const usageMap = new Map<string, { name: string; dependency_id: string; project_count: number; project_ids: string[] }>();
    for (const dep of deps || []) {
      const existing = usageMap.get(dep.name);
      if (existing) {
        existing.project_count++;
        existing.project_ids.push(dep.project_id);
      } else {
        usageMap.set(dep.name, { name: dep.name, dependency_id: dep.dependency_id, project_count: 1, project_ids: [dep.project_id] });
      }
    }

    const { data: watchlistEntries } = await supabase
      .from('organization_watchlist')
      .select('dependency_id')
      .eq('organization_id', orgId);

    const watchedDepIds = new Set((watchlistEntries || []).map((w: any) => w.dependency_id));

    const result = Array.from(usageMap.values())
      .map((u) => ({ ...u, watched: watchedDepIds.has(u.dependency_id) }))
      .sort((a, b) => b.project_count - a.project_count)
      .slice(0, 50);

    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch package usage' });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// PHASE 13: BILLING ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════

// GET /:id/billing/plan -- plan details (any member)
router.get('/:id/billing/plan', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { data: membership } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', orgId)
      .eq('user_id', userId)
      .single();

    if (!membership) return res.status(403).json({ error: 'Not a member of this organization' });

    const { getUsageSummary } = require('../lib/plan-limits');
    const summary = await getUsageSummary(orgId);

    const { data: planRow } = await supabase
      .from('organization_plans')
      .select('billing_cycle, cancel_at_period_end, cancel_at, payment_method_brand, payment_method_last4, billing_email, subscription_status')
      .eq('organization_id', orgId)
      .single();

    res.json({
      ...summary,
      billing_cycle: planRow?.billing_cycle || 'monthly',
      cancel_at_period_end: planRow?.cancel_at_period_end || false,
      cancel_at: planRow?.cancel_at || null,
      payment_method_brand: planRow?.payment_method_brand || null,
      payment_method_last4: planRow?.payment_method_last4 || null,
      billing_email: planRow?.billing_email || null,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch plan' });
  }
});

// GET /:id/billing/usage -- usage vs limits (manage_billing)
router.get('/:id/billing/usage', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkBillingPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { getUsageSummary } = require('../lib/plan-limits');
    const summary = await getUsageSummary(orgId);
    res.json(summary);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch usage' });
  }
});

// POST /:id/billing/checkout -- create Stripe Checkout session (manage_billing)
router.post('/:id/billing/checkout', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkBillingPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { priceId, billingEmail } = req.body;
    if (!priceId) return res.status(400).json({ error: 'priceId is required' });

    // If downgrading, check usage fits target tier
    const { checkDowngradeAllowed } = require('../lib/plan-limits');
    const { tierFromPriceId: _tierCheck } = require('../lib/stripe');

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const successUrl = `${frontendUrl}/organizations/${orgId}/settings/plan?billing=success`;
    const cancelUrl = `${frontendUrl}/organizations/${orgId}/settings/plan?billing=cancelled`;

    const { createCheckoutSession } = require('../lib/stripe');
    const url = await createCheckoutSession(orgId, priceId, successUrl, cancelUrl, billingEmail);

    if (!url) return res.status(500).json({ error: 'Failed to create checkout session' });
    res.json({ url });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to create checkout session' });
  }
});

// POST /:id/billing/portal -- create Stripe Customer Portal session (manage_billing)
router.post('/:id/billing/portal', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkBillingPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const returnUrl = `${frontendUrl}/organizations/${orgId}/settings/plan`;

    const { createPortalSession } = require('../lib/stripe');
    const url = await createPortalSession(orgId, returnUrl);
    res.json({ url });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to create portal session' });
  }
});

// GET /:id/billing/invoices -- paginated invoice list (manage_billing)
router.get('/:id/billing/invoices', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkBillingPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const limit = Math.min(parseInt(req.query.limit as string) || 10, 50);
    const startingAfter = req.query.starting_after as string | undefined;

    const { getInvoices } = require('../lib/stripe');
    const result = await getInvoices(orgId, limit, startingAfter);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch invoices' });
  }
});

// POST /:id/billing/check-downgrade -- check if downgrade is possible (manage_billing)
router.post('/:id/billing/check-downgrade', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkBillingPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { targetTier } = req.body;
    if (!targetTier) return res.status(400).json({ error: 'targetTier is required' });

    const { checkDowngradeAllowed } = require('../lib/plan-limits');
    const result = await checkDowngradeAllowed(orgId, targetTier);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to check downgrade' });
  }
});

async function checkBillingPermission(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();

  if (!membership) return false;
  if (membership.role === 'owner' || membership.role === 'admin') return true;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.manage_billing === true;
}

async function checkSecurityPermission(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();

  if (!membership) return false;
  if (membership.role === 'owner' || membership.role === 'admin') return true;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.manage_security === true;
}

// ============================================================
// Phase 14: Enterprise Security Endpoints
// ============================================================

// --- 14A: Security Audit Log ---

router.get('/:id/security/audit-log', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const offset = (page - 1) * limit;
    const action = req.query.action as string;
    const actorId = req.query.actor_id as string;
    const severity = req.query.severity as string;
    const from = req.query.from as string;
    const to = req.query.to as string;

    let query = supabase
      .from('security_audit_logs')
      .select('*', { count: 'exact' })
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (action) query = query.eq('action', action);
    if (actorId) query = query.eq('actor_id', actorId);
    if (severity) query = query.eq('severity', severity);
    if (from) query = query.gte('created_at', from);
    if (to) query = query.lte('created_at', to);

    const { data: logs, count, error } = await query;

    if (error) return res.status(500).json({ error: 'Failed to fetch audit logs' });

    res.json({ logs: logs || [], total: count || 0, page, limit });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch audit logs' });
  }
});

router.get('/:id/security/audit-log/export', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const from = req.query.from as string;
    const to = req.query.to as string;

    let query = supabase
      .from('security_audit_logs')
      .select('*')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false })
      .limit(10000);

    if (from) query = query.gte('created_at', from);
    if (to) query = query.lte('created_at', to);

    const { data: logs, error } = await query;
    if (error) return res.status(500).json({ error: 'Failed to export audit logs' });

    const rows = (logs || []).map((l: any) => ({
      timestamp: l.created_at,
      action: l.action,
      actor_id: l.actor_id || '',
      target_type: l.target_type || '',
      target_id: l.target_id || '',
      ip_address: l.ip_address || '',
      severity: l.severity,
      metadata: JSON.stringify(l.metadata || {}),
    }));

    const header = 'timestamp,action,actor_id,target_type,target_id,ip_address,severity,metadata\n';
    const csvRows = rows.map((r: any) =>
      [r.timestamp, r.action, r.actor_id, r.target_type, r.target_id, r.ip_address, r.severity, `"${r.metadata.replace(/"/g, '""')}"`].join(',')
    );

    res.set('Content-Type', 'text/csv');
    res.set('Content-Disposition', `attachment; filename="audit-log-${orgId}-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(header + csvRows.join('\n'));
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to export audit logs' });
  }
});

// --- 14B: MFA Enforcement ---

router.get('/:id/security/mfa-status', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: org } = await supabase
      .from('organizations')
      .select('mfa_enforced, mfa_grace_period_days, mfa_enforcement_started_at')
      .eq('id', orgId)
      .single();

    const { data: members } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', orgId);

    const userIds = (members || []).map((m: any) => m.user_id);

    const { data: factors } = await supabase
      .from('auth.mfa_factors' as any)
      .select('user_id, status')
      .in('user_id', userIds);

    const verifiedFactors = new Set(
      (factors || []).filter((f: any) => f.status === 'verified').map((f: any) => f.user_id)
    );

    const { data: exemptions } = await supabase
      .from('organization_mfa_exemptions')
      .select('user_id, reason, expires_at')
      .eq('organization_id', orgId)
      .gt('expires_at', new Date().toISOString());

    const exemptionMap = new Map((exemptions || []).map((e: any) => [e.user_id, e]));

    const memberStatuses = userIds.map((uid: string) => ({
      user_id: uid,
      has_mfa: verifiedFactors.has(uid),
      is_exempt: exemptionMap.has(uid),
      exemption: exemptionMap.get(uid) || null,
    }));

    res.json({
      enforcement: {
        enabled: org?.mfa_enforced || false,
        grace_period_days: org?.mfa_grace_period_days || 7,
        started_at: org?.mfa_enforcement_started_at || null,
      },
      members: memberStatuses,
      summary: {
        total: userIds.length,
        enrolled: memberStatuses.filter((m: any) => m.has_mfa).length,
        not_enrolled: memberStatuses.filter((m: any) => !m.has_mfa && !m.is_exempt).length,
        exempt: memberStatuses.filter((m: any) => m.is_exempt).length,
      },
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch MFA status' });
  }
});

router.patch('/:id/security/mfa-enforcement', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { enabled, grace_period_days } = req.body;

    const updates: Record<string, unknown> = {};
    if (typeof enabled === 'boolean') {
      updates.mfa_enforced = enabled;
      if (enabled) {
        updates.mfa_enforcement_started_at = new Date().toISOString();
      }
    }
    if (typeof grace_period_days === 'number') {
      updates.mfa_grace_period_days = Math.max(1, Math.min(90, grace_period_days));
    }

    const { error } = await supabase
      .from('organizations')
      .update(updates)
      .eq('id', orgId);

    if (error) return res.status(500).json({ error: 'Failed to update MFA enforcement' });

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'mfa_enforcement_changed',
      req,
      metadata: updates,
    });

    res.json({ success: true, ...updates });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to update MFA enforcement' });
  }
});

router.post('/:id/security/mfa-exemptions', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { target_user_id, reason, expires_in_days } = req.body;
    if (!target_user_id || !reason) {
      return res.status(400).json({ error: 'target_user_id and reason are required' });
    }

    const expiresAt = new Date(Date.now() + (expires_in_days || 30) * 86400000).toISOString();

    const { data, error } = await supabase
      .from('organization_mfa_exemptions')
      .upsert({
        organization_id: orgId,
        user_id: target_user_id,
        exempted_by: userId,
        reason,
        expires_at: expiresAt,
      }, { onConflict: 'organization_id,user_id' })
      .select()
      .single();

    if (error) return res.status(500).json({ error: 'Failed to create exemption' });

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'mfa_exemption_created',
      targetType: 'user',
      targetId: target_user_id,
      req,
      metadata: { reason, expires_at: expiresAt },
    });

    res.status(201).json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to create exemption' });
  }
});

router.delete('/:id/security/mfa-exemptions/:userId', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { error } = await supabase
      .from('organization_mfa_exemptions')
      .delete()
      .eq('organization_id', orgId)
      .eq('user_id', req.params.userId);

    if (error) return res.status(500).json({ error: 'Failed to remove exemption' });

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'mfa_exemption_removed',
      targetType: 'user',
      targetId: req.params.userId,
      req,
    });

    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to remove exemption' });
  }
});

router.post('/:id/security/force-logout/:targetUserId', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const targetUserId = req.params.targetUserId;

    const { data: member } = await supabase
      .from('organization_members')
      .select('id')
      .eq('organization_id', orgId)
      .eq('user_id', targetUserId)
      .single();

    if (!member) return res.status(404).json({ error: 'User is not a member of this organization' });

    await supabase.from('user_sessions').delete().eq('user_id', targetUserId);

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'force_logout',
      targetType: 'user',
      targetId: targetUserId,
      req,
      severity: 'warning',
    });

    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to force logout' });
  }
});

// --- 14D: SSO/SAML ---

router.get('/:id/security/sso', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: sso } = await supabase
      .from('organization_sso_providers')
      .select('id, provider_type, display_name, domain, domain_verified, enforce_sso, allow_oauth_fallback, jit_provisioning, default_role_id, group_role_mapping, is_active, created_at, updated_at')
      .eq('organization_id', orgId)
      .single();

    res.json({ sso: sso || null });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch SSO config' });
  }
});

router.post('/:id/security/sso', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { provider_type, display_name, entity_id, sso_url, certificate, domain, metadata_url, metadata_xml, default_role_id, group_role_mapping, jit_provisioning } = req.body;

    if (!provider_type || !entity_id || !sso_url || !certificate || !domain) {
      return res.status(400).json({ error: 'provider_type, entity_id, sso_url, certificate, and domain are required' });
    }

    const { generateDomainVerificationToken } = require('../lib/saml');
    const verificationToken = generateDomainVerificationToken();

    const { data, error } = await supabase
      .from('organization_sso_providers')
      .insert({
        organization_id: orgId,
        provider_type,
        display_name: display_name || null,
        entity_id,
        sso_url,
        certificate,
        domain: domain.toLowerCase(),
        domain_verification_token: verificationToken,
        metadata_url: metadata_url || null,
        metadata_xml: metadata_xml || null,
        default_role_id: default_role_id || null,
        group_role_mapping: group_role_mapping || {},
        jit_provisioning: jit_provisioning !== false,
      })
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'SSO already configured for this organization or domain is in use' });
      }
      return res.status(500).json({ error: 'Failed to create SSO config' });
    }

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'sso_configured',
      req,
      metadata: { provider_type, domain },
    });

    res.status(201).json({
      ...data,
      domain_verification_record: `deptex-domain-verify=${verificationToken}`,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to create SSO config' });
  }
});

router.put('/:id/security/sso', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const allowed = ['display_name', 'entity_id', 'sso_url', 'certificate', 'metadata_url', 'metadata_xml', 'enforce_sso', 'allow_oauth_fallback', 'jit_provisioning', 'default_role_id', 'group_role_mapping', 'is_active'];
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };

    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }

    const { error } = await supabase
      .from('organization_sso_providers')
      .update(updates)
      .eq('organization_id', orgId);

    if (error) return res.status(500).json({ error: 'Failed to update SSO config' });

    if (updates.enforce_sso !== undefined) {
      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: orgId,
        actorId: userId,
        action: 'sso_enforcement_changed',
        req,
        metadata: { enforce_sso: updates.enforce_sso },
      });
    }

    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to update SSO config' });
  }
});

router.delete('/:id/security/sso', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { error } = await supabase
      .from('organization_sso_providers')
      .delete()
      .eq('organization_id', orgId);

    if (error) return res.status(500).json({ error: 'Failed to remove SSO config' });

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'sso_removed',
      req,
      severity: 'warning',
    });

    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to remove SSO config' });
  }
});

router.post('/:id/security/sso/verify-domain', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: sso } = await supabase
      .from('organization_sso_providers')
      .select('domain, domain_verification_token')
      .eq('organization_id', orgId)
      .single();

    if (!sso) return res.status(404).json({ error: 'No SSO config found' });

    const { verifyDomain } = require('../lib/saml');
    const verified = await verifyDomain(sso.domain, sso.domain_verification_token);

    if (verified) {
      await supabase
        .from('organization_sso_providers')
        .update({ domain_verified: true, updated_at: new Date().toISOString() })
        .eq('organization_id', orgId);

      const { logSecurityEvent } = require('../lib/security-audit');
      await logSecurityEvent({
        organizationId: orgId,
        actorId: userId,
        action: 'sso_domain_verified',
        req,
        metadata: { domain: sso.domain },
      });
    }

    res.json({ verified, domain: sso.domain });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to verify domain' });
  }
});

router.post('/:id/security/sso/test', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: sso } = await supabase
      .from('organization_sso_providers')
      .select('*')
      .eq('organization_id', orgId)
      .single();

    if (!sso) return res.status(404).json({ error: 'No SSO config found' });

    try {
      const { createSAMLInstance, generateAuthRequest } = require('../lib/saml');
      const saml = createSAMLInstance(sso);
      const url = await generateAuthRequest(saml);
      res.json({ success: true, test_url: url });
    } catch (err: any) {
      res.json({ success: false, error: err.message });
    }
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to test SSO' });
  }
});

router.post('/:id/security/sso/bypass-token', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { generateBypassToken } = require('../lib/saml');
    const { raw, hash } = generateBypassToken();

    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    const { error } = await supabase
      .from('organization_sso_bypass_tokens')
      .insert({
        organization_id: orgId,
        token_hash: hash,
        created_by: userId,
        expires_at: expiresAt,
      });

    if (error) return res.status(500).json({ error: 'Failed to create bypass token' });

    res.status(201).json({ token: raw, expires_at: expiresAt });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to create bypass token' });
  }
});

router.get('/:id/security/sso/bypass-tokens', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: tokens } = await supabase
      .from('organization_sso_bypass_tokens')
      .select('id, created_by, used_at, expires_at, created_at')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false })
      .limit(20);

    res.json({ tokens: tokens || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch bypass tokens' });
  }
});

// --- 14E: IP Allowlisting ---

router.get('/:id/security/ip-allowlist', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: org } = await supabase
      .from('organizations')
      .select('ip_allowlist_enabled')
      .eq('id', orgId)
      .single();

    const { data: entries } = await supabase
      .from('organization_ip_allowlist')
      .select('id, cidr, label, created_by, created_at')
      .eq('organization_id', orgId)
      .order('created_at', { ascending: false });

    res.json({
      enabled: org?.ip_allowlist_enabled || false,
      entries: entries || [],
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch IP allowlist' });
  }
});

router.post('/:id/security/ip-allowlist', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { cidr, label } = req.body;
    if (!cidr) return res.status(400).json({ error: 'cidr is required' });

    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-fA-F:]+\/\d{1,3}$/;
    if (!cidrPattern.test(cidr)) {
      return res.status(400).json({ error: 'Invalid CIDR format' });
    }

    const { data, error } = await supabase
      .from('organization_ip_allowlist')
      .insert({
        organization_id: orgId,
        cidr,
        label: label || null,
        created_by: userId,
      })
      .select()
      .single();

    if (error) return res.status(500).json({ error: 'Failed to add IP entry' });

    try {
      const { invalidateIPAllowlistCache } = require('../middleware/ip-allowlist');
      invalidateIPAllowlistCache(orgId);
    } catch {}

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'ip_allowlist_entry_added',
      req,
      metadata: { cidr, label },
    });

    res.status(201).json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to add IP entry' });
  }
});

router.delete('/:id/security/ip-allowlist/:entryId', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: entry } = await supabase
      .from('organization_ip_allowlist')
      .select('id, cidr')
      .eq('id', req.params.entryId)
      .eq('organization_id', orgId)
      .single();

    if (!entry) return res.status(404).json({ error: 'Entry not found' });

    await supabase.from('organization_ip_allowlist').delete().eq('id', entry.id);

    try {
      const { invalidateIPAllowlistCache } = require('../middleware/ip-allowlist');
      invalidateIPAllowlistCache(orgId);
    } catch {}

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'ip_allowlist_entry_removed',
      req,
      metadata: { cidr: entry.cidr },
    });

    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to remove IP entry' });
  }
});

router.patch('/:id/security/ip-allowlist-enabled', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { enabled } = req.body;
    if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be a boolean' });

    if (enabled) {
      const { data: entries } = await supabase
        .from('organization_ip_allowlist')
        .select('id')
        .eq('organization_id', orgId)
        .limit(1);

      if (!entries || entries.length === 0) {
        return res.status(400).json({ error: 'Cannot enable IP allowlist with no entries. Add at least one IP range first.' });
      }
    }

    const { error } = await supabase
      .from('organizations')
      .update({ ip_allowlist_enabled: enabled })
      .eq('id', orgId);

    if (error) return res.status(500).json({ error: 'Failed to toggle IP allowlist' });

    try {
      const { invalidateIPAllowlistCache } = require('../middleware/ip-allowlist');
      invalidateIPAllowlistCache(orgId);
    } catch {}

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'ip_allowlist_toggled',
      req,
      metadata: { enabled },
    });

    res.json({ success: true, enabled });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to toggle IP allowlist' });
  }
});

// --- 14F: API Tokens (org admin view) ---

router.get('/:id/security/api-tokens', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: tokens } = await supabase
      .from('api_tokens')
      .select('id, user_id, name, token_prefix, scopes, last_used_at, last_used_ip, expires_at, created_at')
      .eq('organization_id', orgId)
      .is('revoked_at', null)
      .order('created_at', { ascending: false });

    res.json({ tokens: tokens || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch tokens' });
  }
});

router.delete('/:id/security/api-tokens/:tokenId', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: tokenRow } = await supabase
      .from('api_tokens')
      .select('id, name, user_id')
      .eq('id', req.params.tokenId)
      .eq('organization_id', orgId)
      .is('revoked_at', null)
      .single();

    if (!tokenRow) return res.status(404).json({ error: 'Token not found' });

    await supabase
      .from('api_tokens')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', tokenRow.id);

    const { logSecurityEvent } = require('../lib/security-audit');
    await logSecurityEvent({
      organizationId: orgId,
      actorId: userId,
      action: 'api_token_revoked',
      targetType: 'api_token',
      targetId: tokenRow.id,
      req,
      metadata: { name: tokenRow.name, token_owner: tokenRow.user_id },
      severity: 'warning',
    });

    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to revoke token' });
  }
});

// --- 14G: SCIM Config ---

router.get('/:id/security/scim', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { data: config } = await supabase
      .from('organization_scim_configs')
      .select('id, scim_token_prefix, is_active, last_sync_at, created_at')
      .eq('organization_id', orgId)
      .single();

    const baseUrl = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`;

    res.json({
      config: config || null,
      endpoint_url: `${baseUrl}/api/scim/v2`,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to fetch SCIM config' });
  }
});

router.post('/:id/security/scim', async (req: AuthRequest, res) => {
  try {
    const orgId = req.params.id;
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const hasAccess = await checkSecurityPermission(orgId, userId);
    if (!hasAccess) return res.status(403).json({ error: 'Insufficient permissions' });

    const { generateSCIMToken } = require('../lib/saml');
    const { raw, prefix, hash } = generateSCIMToken();

    const { data, error } = await supabase
      .from('organization_scim_configs')
      .upsert({
        organization_id: orgId,
        scim_token_hash: hash,
        scim_token_prefix: prefix,
        is_active: true,
        updated_at: new Date().toISOString(),
      }, { onConflict: 'organization_id' })
      .select('id, scim_token_prefix, is_active, created_at')
      .single();

    if (error) return res.status(500).json({ error: 'Failed to create SCIM config' });

    const baseUrl = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`;

    res.status(201).json({
      ...data,
      token: raw,
      endpoint_url: `${baseUrl}/api/scim/v2`,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Failed to create SCIM config' });
  }
});

export default router;
