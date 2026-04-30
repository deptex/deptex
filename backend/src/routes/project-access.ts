/**
 * Project-access + project-manage permission helpers.
 *
 * Extracted from `backend/src/routes/projects.ts` so non-projects routes
 * (e.g. malicious-package findings) can gate access without copy-pasting the
 * RBAC logic. The originals in `projects.ts` remain identical until they get
 * collapsed onto these in a follow-up sweep.
 */
import { supabase } from '../lib/supabase';

export interface ProjectAccessResult {
  hasAccess: boolean;
  orgMembership: { role: string } | null;
  projectMembership: { role_id: string } | null;
  orgRole: { permissions: any; display_order: number } | null;
  isInProjectTeam: boolean;
  error?: { status: number; message: string };
}

/**
 * Read-side gate. Access is granted if the user is org owner, has
 * manage_teams_and_projects, is a direct project member, or is in a team
 * assigned to the project.
 */
export async function checkProjectAccess(
  userId: string,
  organizationId: string,
  projectId: string
): Promise<ProjectAccessResult> {
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
      projectMembership: null,
      orgRole: null,
      isInProjectTeam: false,
      error: { status: 404, message: 'Organization not found or access denied' },
    };
  }

  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions, display_order')
    .eq('organization_id', organizationId)
    .eq('name', orgMembership.role)
    .single();

  const isOrgOwner = orgMembership.role === 'owner';
  const hasOrgPermission = orgRole?.permissions?.manage_teams_and_projects === true;

  if (isOrgOwner || hasOrgPermission) {
    return { hasAccess: true, orgMembership, projectMembership: null, orgRole, isInProjectTeam: false };
  }

  const { data: projectMembership } = await supabase
    .from('project_members')
    .select('role_id')
    .eq('project_id', projectId)
    .eq('user_id', userId)
    .single();

  if (projectMembership) {
    return { hasAccess: true, orgMembership, projectMembership, orgRole, isInProjectTeam: false };
  }

  const { data: userTeams } = await supabase
    .from('team_members')
    .select('team_id')
    .eq('user_id', userId);
  const userTeamIds = (userTeams ?? []).map((t: any) => t.team_id);

  if (userTeamIds.length > 0) {
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('team_id')
      .eq('project_id', projectId)
      .in('team_id', userTeamIds);
    if (projectTeams && projectTeams.length > 0) {
      return { hasAccess: true, orgMembership, projectMembership: null, orgRole, isInProjectTeam: true };
    }
  }

  return {
    hasAccess: false,
    orgMembership,
    projectMembership: null,
    orgRole,
    isInProjectTeam: false,
    error: { status: 403, message: 'You do not have access to this project' },
  };
}

/**
 * Mutation-side gate. Returns true when the user is org owner/admin, has
 * `manage_teams_and_projects` at the org level, or is in the project's owner
 * team with `manage_projects` at the team level.
 */
export async function checkProjectManagePermission(
  userId: string,
  organizationId: string,
  projectId: string
): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  if (membership.role === 'owner' || membership.role === 'admin') return true;

  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();
  if (orgRole?.permissions?.manage_teams_and_projects === true) return true;

  const { data: projectTeams } = await supabase
    .from('project_teams')
    .select('is_owner, team_id')
    .eq('project_id', projectId);

  const ownerEntry = projectTeams?.find((pt: any) => pt.is_owner);
  const ownerTeamId = ownerEntry?.team_id;
  if (!ownerTeamId) return false;

  const { data: ownerTeamMembership } = await supabase
    .from('team_members')
    .select('role')
    .eq('team_id', ownerTeamId)
    .eq('user_id', userId)
    .single();
  if (!ownerTeamMembership) return false;

  const { data: teamRole } = await supabase
    .from('team_roles')
    .select('permissions')
    .eq('team_id', ownerTeamId)
    .eq('name', ownerTeamMembership.role)
    .single();

  return teamRole?.permissions?.manage_projects === true;
}
