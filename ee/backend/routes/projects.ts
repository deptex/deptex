import express from 'express';
import * as crypto from 'crypto';
import semver from 'semver';
import { supabase } from '../../../backend/src/lib/supabase';
import { authenticateUser, AuthRequest } from '../../../backend/src/middleware/auth';
import { createActivity } from '../lib/activities';
import {
  createInstallationToken,
  listInstallationRepositories,
  getRepositoryFileContent,
  getRepositoryFileWithSha,
  getBranchSha,
  createBranch,
  createOrUpdateFileOnBranch,
  createPullRequest,
  getPullRequest,
  closePullRequest,
} from '../lib/github';
import { detectMonorepo } from '../../../backend/src/lib/detect-monorepo';
import { createProvider, GitHubProvider, type GitProvider, type OrgIntegration } from '../lib/git-provider';
import { queueExtractionJob } from '../lib/redis';
import { MANIFEST_FILES, detectFrameworkForEcosystem, ECOSYSTEM_DEFAULTS } from '../../../backend/src/lib/ecosystems';
import { queueWatchtowerJob } from '../lib/watchtower-queue';
import { createBumpPrForProject } from '../lib/create-bump-pr';
import { createRemovePrForProject } from '../lib/create-remove-pr';
import { isVersionAffected, isVersionFixed } from '../../../backend/src/lib/semver-affected';
import { fetchGhsaVulnerabilitiesBatch, filterGhsaVulnsByVersion, ghsaSeverityToLevel } from '../../../backend/src/lib/ghsa';
import { getVulnCountsBatch, getVulnCountsForVersion, getVulnCountsForVersionsBatch, VulnCounts } from '../../../backend/src/lib/vuln-counts';
import { getEffectivePolicies, isLicenseAllowed } from '../lib/project-policies';
import pacote from 'pacote';
import { calculateLatestSafeVersion, type LatestSafeVersionResponse } from '../lib/latest-safe-version';
import {
  getCached,
  setCached,
  getDependenciesCacheKey,
  getDependencyVersionsCacheKey,
  getDependencyNotesCacheKey,
  registerDependencyNotesCacheKey,
  invalidateDependenciesCache,
  invalidateDependencyNotesCache,
  invalidateDependencyVersionsCacheByDependencyId,
  invalidateLatestSafeVersionCacheByDependencyId,
  invalidateWatchtowerSummaryCache,
  invalidateAllProjectCachesInOrg,
  invalidateProjectCachesForTeam,
  CACHE_TTL_SECONDS,
} from '../lib/cache';

/** True if version is a stable release (no canary/experimental/alpha/beta/rc). */
function isStableVersion(version: string): boolean {
  if (!semver.valid(version)) return false;
  return !semver.prerelease(version);
}

/** Batched ancestor paths: one edge query for project subgraph, then BFS in memory. */
async function getAncestorPathsBatched(
  client: import('../../../backend/src/lib/supabase').SupabaseClientAny,
  projectId: string,
  dependencyVersionId: string,
  parentName: string,
  parentVersion: string,
  isDirect: boolean
): Promise<Array<Array<{ name: string; version: string; dependency_version_id: string; is_direct: boolean }>>> {
  if (isDirect) return [];

  const MAX_DEPTH = 10;
  const MAX_PATHS = 5;

  const { data: projectDeps, error: projectDepsError } = await client
    .from('project_dependencies')
    .select('dependency_version_id, name, version, is_direct')
    .eq('project_id', projectId);

  if (projectDepsError || !projectDeps?.length) return [];

  const projectVersionIds = projectDeps
    .map((p: any) => (p as any).dependency_version_id)
    .filter(Boolean) as string[];
  const projectVersionIdToInfo = new Map<string, { name: string; version: string; is_direct: boolean }>();
  for (const p of projectDeps) {
    const vid = (p as any).dependency_version_id;
    if (vid) {
      projectVersionIdToInfo.set(vid, {
        name: (p as any).name,
        version: (p as any).version,
        is_direct: (p as any).is_direct,
      });
    }
  }

  const { data: edges, error: edgesError } = await client
    .from('dependency_version_edges')
    .select('parent_version_id, child_version_id')
    .in('parent_version_id', projectVersionIds)
    .in('child_version_id', projectVersionIds);

  if (edgesError || !edges?.length) return [];

  const childToParents = new Map<string, string[]>();
  for (const e of edges as any[]) {
    const cid = e.child_version_id;
    const pid = e.parent_version_id;
    if (!childToParents.has(cid)) childToParents.set(cid, []);
    childToParents.get(cid)!.push(pid);
  }

  type PathNode = { versionId: string; name: string; version: string; is_direct: boolean };
  const queue: Array<{ versionId: string; path: PathNode[] }> = [
    { versionId: dependencyVersionId, path: [{ versionId: dependencyVersionId, name: parentName, version: parentVersion, is_direct: isDirect }] },
  ];
  const foundPaths: PathNode[][] = [];

  while (queue.length > 0 && foundPaths.length < MAX_PATHS) {
    const current = queue.shift()!;
    if (current.path.length > MAX_DEPTH) continue;

    const parentIds = childToParents.get(current.versionId) ?? [];
    for (const pvId of parentIds) {
      if (current.path.some((n) => n.versionId === pvId)) continue;
      const info = projectVersionIdToInfo.get(pvId);
      if (!info) continue;

      const node: PathNode = {
        versionId: pvId,
        name: info.name,
        version: info.version,
        is_direct: info.is_direct,
      };
      const newPath = [...current.path, node];

      if (info.is_direct) {
        foundPaths.push([...newPath].reverse());
        if (foundPaths.length >= MAX_PATHS) break;
      } else {
        queue.push({ versionId: pvId, path: newPath });
      }
    }
  }

  return foundPaths.map((path) =>
    path.map((node) => ({
      name: node.name,
      version: node.version,
      dependency_version_id: node.versionId,
      is_direct: node.is_direct,
    }))
  );
}

/** Fetch latest version and release date from npm registry (public, no API key). */
async function fetchLatestNpmVersion(packageName: string): Promise<{ latest_version: string | null; latest_release_date: string | null }> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return { latest_version: null, latest_release_date: null };
    const data = (await res.json()) as Record<string, unknown>;
    const latest = (data['dist-tags'] as Record<string, string> | undefined)?.latest;
    if (!latest) return { latest_version: null, latest_release_date: null };
    const time = (data.time as Record<string, string> | undefined)?.[latest]; // ISO string or undefined
    return {
      latest_version: latest,
      latest_release_date: time ? new Date(time).toISOString() : null,
    };
  } catch {
    return { latest_version: null, latest_release_date: null };
  }
}

/**
 * Detect framework for a repository by trying each registered manifest file.
 * Accepts a GitProvider so it works for GitHub, GitLab, and Bitbucket.
 */
async function detectRepoFramework(
  provider: GitProvider,
  repoFullName: string,
  defaultBranch: string
): Promise<{ framework: string; ecosystem: string }> {
  for (const [fileName, ecosystem] of Object.entries(MANIFEST_FILES)) {
    try {
      const content = await provider.getFileContent(repoFullName, fileName, defaultBranch);
      const framework = detectFrameworkForEcosystem(ecosystem, content);
      return { framework, ecosystem };
    } catch {
      continue;
    }
  }
  return { framework: 'unknown', ecosystem: 'unknown' };
}

async function getOrgIntegrations(orgId: string): Promise<OrgIntegration[]> {
  const { data } = await supabase
    .from('organization_integrations')
    .select('id, provider, installation_id, access_token, refresh_token, metadata, status')
    .eq('organization_id', orgId)
    .in('provider', ['github', 'gitlab', 'bitbucket'])
    .eq('status', 'connected');
  return (data || []) as OrgIntegration[];
}

async function getIntegrationById(orgId: string, integrationId: string): Promise<OrgIntegration | null> {
  const { data } = await supabase
    .from('organization_integrations')
    .select('id, provider, installation_id, access_token, refresh_token, metadata, status')
    .eq('id', integrationId)
    .eq('organization_id', orgId)
    .eq('status', 'connected')
    .single();
  return data as OrgIntegration | null;
}

// Calculate whether a project is compliant based on its dependencies and policies
async function calculateProjectCompliance(organizationId: string, projectId: string): Promise<boolean> {
  // Get effective policies
  const { acceptedLicenses } = await getEffectivePolicies(organizationId, projectId);

  // If no policies defined, project is considered compliant
  if (acceptedLicenses.length === 0) {
    return true;
  }

  // Get project dependencies
  const { data: projectDeps } = await supabase
    .from('project_dependencies')
    .select('dependency_id')
    .eq('project_id', projectId);

  if (!projectDeps || projectDeps.length === 0) {
    return true; // No dependencies = compliant
  }

  // Get licenses for all dependencies
  const dependencyIds = projectDeps.map((pd: any) => pd.dependency_id).filter(Boolean);

  if (dependencyIds.length === 0) {
    return true;
  }

  // Query dependencies in batches
  const BATCH_SIZE = 100;
  for (let i = 0; i < dependencyIds.length; i += BATCH_SIZE) {
    const batch = dependencyIds.slice(i, i + BATCH_SIZE);
    const { data: deps } = await supabase
      .from('dependencies')
      .select('license')
      .in('id', batch);

    if (deps) {
      for (const dep of deps) {
        const allowed = isLicenseAllowed(dep.license, acceptedLicenses);
        // If a license is explicitly not allowed (false), project is not compliant
        // Unknown licenses (null) are not considered violations
        if (allowed === false) {
          return false;
        }
      }
    }
  }

  return true;
}

// Update the is_compliant field for a project
async function updateProjectCompliance(organizationId: string, projectId: string): Promise<boolean> {
  const isCompliant = await calculateProjectCompliance(organizationId, projectId);

  await supabase
    .from('projects')
    .update({ is_compliant: isCompliant })
    .eq('id', projectId)
    .eq('organization_id', organizationId);

  return isCompliant;
}

// Update compliance for all projects in an organization
async function updateAllProjectsCompliance(organizationId: string): Promise<void> {
  const { data: projects } = await supabase
    .from('projects')
    .select('id')
    .eq('organization_id', organizationId);

  if (projects) {
    for (const project of projects) {
      await updateProjectCompliance(organizationId, project.id);
    }
  }
}

const router = express.Router();
router.use(authenticateUser);

// Helper function to check if user has access to a project
// Access is granted if user is org owner, has manage_teams_and_projects permission,
// is a direct project member, or is in a team assigned to the project
async function checkProjectAccess(userId: string, organizationId: string, projectId: string): Promise<{
  hasAccess: boolean;
  orgMembership: { role: string } | null;
  projectMembership: { role_id: string } | null;
  orgRole: { permissions: any; display_order: number } | null;
  isInProjectTeam: boolean;
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
      projectMembership: null,
      orgRole: null,
      isInProjectTeam: false,
      error: { status: 404, message: 'Organization not found or access denied' }
    };
  }

  // Get user's org role permissions
  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions, display_order')
    .eq('organization_id', organizationId)
    .eq('name', orgMembership.role)
    .single();

  // Check if user is org owner or has manage_teams_and_projects permission
  const isOrgOwner = orgMembership.role === 'owner';
  const hasOrgPermission = orgRole?.permissions?.manage_teams_and_projects === true;

  // If org owner or has permission, grant access immediately
  if (isOrgOwner || hasOrgPermission) {
    return {
      hasAccess: true,
      orgMembership,
      projectMembership: null,
      orgRole,
      isInProjectTeam: false
    };
  }

  // Check if user is a direct project member
  const { data: projectMembership } = await supabase
    .from('project_members')
    .select('role_id')
    .eq('project_id', projectId)
    .eq('user_id', userId)
    .single();

  if (projectMembership) {
    return {
      hasAccess: true,
      orgMembership,
      projectMembership,
      orgRole,
      isInProjectTeam: false
    };
  }

  // Check if user is in a team assigned to this project
  // First get user's teams
  const { data: userTeams } = await supabase
    .from('team_members')
    .select('team_id')
    .eq('user_id', userId);

  const userTeamIds = (userTeams || []).map((t: any) => t.team_id);

  if (userTeamIds.length > 0) {
    // Check if any of user's teams are assigned to this project
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('team_id')
      .eq('project_id', projectId)
      .in('team_id', userTeamIds);

    if (projectTeams && projectTeams.length > 0) {
      return {
        hasAccess: true,
        orgMembership,
        projectMembership: null,
        orgRole,
        isInProjectTeam: true
      };
    }
  }

  // User has no access
  return {
    hasAccess: false,
    orgMembership,
    projectMembership: null,
    orgRole,
    isInProjectTeam: false,
    error: { status: 403, message: 'You do not have access to this project' }
  };
}

/** Check if user can manage watchtower (enable/disable, clear commits, quarantine).
 * Requires org-level manage_teams_and_projects OR team-level manage_projects (owner team). */
async function checkWatchtowerManagePermission(userId: string, organizationId: string, projectId: string): Promise<boolean> {
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

// GET /api/organizations/:id/projects - Get all projects for an organization
router.get('/:id/projects', async (req: AuthRequest, res) => {
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

    const canViewAllProjects = membership.role === 'owner' || orgRole?.permissions?.manage_teams_and_projects === true;

    // Get projects - either all or just ones user has access to
    let projects;
    let accessibleProjectIds: string[] = [];

    if (canViewAllProjects) {
      // User can view all projects
      const { data, error: projectsError } = await supabase
        .from('projects')
        .select('*')
        .eq('organization_id', id)
        .order('created_at', { ascending: false });

      if (projectsError) throw projectsError;
      projects = data;
    } else {
      // User can only view projects they have access to (direct member or via team)

      // Get projects user is a direct member of
      const { data: directProjects } = await supabase
        .from('project_members')
        .select('project_id')
        .eq('user_id', userId);

      const directProjectIds = (directProjects || []).map((p: any) => p.project_id);

      // Get user's teams
      const { data: userTeams } = await supabase
        .from('team_members')
        .select('team_id')
        .eq('user_id', userId);

      const userTeamIds = (userTeams || []).map((t: any) => t.team_id);

      // Get projects associated with user's teams
      let teamProjectIds: string[] = [];
      if (userTeamIds.length > 0) {
        const { data: teamProjects } = await supabase
          .from('project_teams')
          .select('project_id')
          .in('team_id', userTeamIds);

        teamProjectIds = (teamProjects || []).map((tp: any) => tp.project_id);
      }

      // Combine and deduplicate project IDs
      accessibleProjectIds = [...new Set([...directProjectIds, ...teamProjectIds])];

      if (accessibleProjectIds.length === 0) {
        return res.json([]);
      }

      const { data, error: projectsError } = await supabase
        .from('projects')
        .select('*')
        .eq('organization_id', id)
        .in('id', accessibleProjectIds)
        .order('created_at', { ascending: false });

      if (projectsError) throw projectsError;
      projects = data;
    }

    // Get team associations for all projects
    const projectIds = (projects || []).map((p: any) => p.id);

    if (projectIds.length === 0) {
      return res.json([]);
    }

    const { data: projectTeams, error: projectTeamsError } = await supabase
      .from('project_teams')
      .select(`
        project_id,
        is_owner,
        teams:team_id (
          id,
          name
        )
      `)
      .in('project_id', projectIds);

    if (projectTeamsError) {
      throw projectTeamsError;
    }

    // Group teams by project_id and track owner team
    const teamsByProject: Record<string, Array<{ id: string; name: string }>> = {};
    const ownerTeamByProject: Record<string, { id: string; name: string } | null> = {};
    (projectTeams || []).forEach((pt: any) => {
      if (pt.teams) {
        if (!teamsByProject[pt.project_id]) {
          teamsByProject[pt.project_id] = [];
        }
        teamsByProject[pt.project_id].push({
          id: pt.teams.id,
          name: pt.teams.name,
        });
        // Track owner team
        if (pt.is_owner) {
          ownerTeamByProject[pt.project_id] = {
            id: pt.teams.id,
            name: pt.teams.name,
          };
        }
      }
    });

    // Determine user's role for each project
    // Org owners get 'owner', org admins get 'editor'
    // For regular members, check project_members and team memberships
    let projectRoles: Record<string, string> = {};

    if (membership.role === 'owner') {
      // Org owners are owners of all projects
      projectIds.forEach((pid: string) => {
        projectRoles[pid] = 'owner';
      });
    } else if (membership.role === 'admin') {
      // Org admins are editors of all projects
      projectIds.forEach((pid: string) => {
        projectRoles[pid] = 'editor';
      });
    } else if (projectIds.length > 0) {
      // For regular members, check project memberships
      const { data: directMemberships } = await supabase
        .from('project_members')
        .select('project_id, role')
        .eq('user_id', userId)
        .in('project_id', projectIds);

      // Store direct membership roles
      (directMemberships || []).forEach((pm: any) => {
        projectRoles[pm.project_id] = pm.role;
      });

      // For projects without direct membership, check team access
      const projectsWithoutRole = projectIds.filter((pid: string) => !projectRoles[pid]);
      if (projectsWithoutRole.length > 0) {
        // Get user's teams
        const { data: userTeams } = await supabase
          .from('team_members')
          .select('team_id')
          .eq('user_id', userId);

        const userTeamIds = (userTeams || []).map((t: any) => t.team_id);

        if (userTeamIds.length > 0) {
          // Check which projects have teams the user is in
          const { data: teamProjects } = await supabase
            .from('project_teams')
            .select('project_id')
            .in('project_id', projectsWithoutRole)
            .in('team_id', userTeamIds);

          // Team members get 'viewer' role by default
          (teamProjects || []).forEach((tp: any) => {
            if (!projectRoles[tp.project_id]) {
              projectRoles[tp.project_id] = 'viewer';
            }
          });
        }
      }

      // Projects without any role get 'viewer' as default (they have org access)
      projectIds.forEach((pid: string) => {
        if (!projectRoles[pid]) {
          projectRoles[pid] = 'viewer';
        }
      });
    }

    // Determine permissions for each project
    // For efficiency, we compute base permissions from org role and check owner team permissions in batch
    const hasOrgManagePermission = orgRole?.permissions?.manage_teams_and_projects === true;

    // Get user's team memberships and their permissions for owner team checks
    let userTeamPermissions: Record<string, any> = {};
    if (membership.role !== 'owner' && membership.role !== 'admin' && !hasOrgManagePermission) {
      // Get all teams user is a member of with their roles
      const { data: userTeamMemberships } = await supabase
        .from('team_members')
        .select('team_id, role')
        .eq('user_id', userId);

      if (userTeamMemberships && userTeamMemberships.length > 0) {
        // Get all owner team IDs from projects
        const ownerTeamIds = Object.values(ownerTeamByProject)
          .filter(Boolean)
          .map((t: any) => t.id);

        // Check if user is in any owner teams
        const userOwnerTeamMemberships = userTeamMemberships.filter(
          (tm: any) => ownerTeamIds.includes(tm.team_id)
        );

        if (userOwnerTeamMemberships.length > 0) {
          // Get team roles for these memberships to check manage_projects permission
          for (const teamMembership of userOwnerTeamMemberships) {
            const { data: teamRole } = await supabase
              .from('team_roles')
              .select('permissions')
              .eq('team_id', teamMembership.team_id)
              .eq('name', teamMembership.role)
              .single();

            if (teamRole?.permissions?.manage_projects) {
              userTeamPermissions[teamMembership.team_id] = true;
            }
          }
        }
      }
    }

    // Fetch repository statuses for all projects in one query
    const repoStatusByProject: Record<string, { status: string; extraction_step: string | null; extraction_error: string | null }> = {};
    if (projectIds.length > 0) {
      const { data: repoStatuses } = await supabase
        .from('project_repositories')
        .select('project_id, status, extraction_step, extraction_error')
        .in('project_id', projectIds);
      if (repoStatuses) {
        for (const rs of repoStatuses) {
          repoStatusByProject[rs.project_id] = {
            status: rs.status,
            extraction_step: (rs as any).extraction_step ?? null,
            extraction_error: (rs as any).extraction_error ?? null,
          };
        }
      }
    }

    // Format projects with team_ids, team_names, owner_team, role, and permissions
    const formattedProjects = (projects || []).map((project: any) => {
      const role = projectRoles[project.id] || 'viewer';
      const ownerTeamId = ownerTeamByProject[project.id]?.id || null;

      // Determine permissions
      let permissions;
      if (membership.role === 'owner') {
        permissions = {
          view_overview: true,
          view_dependencies: true,
          view_watchlist: true,
          view_members: true,
          manage_members: true,
          view_settings: true,
          edit_settings: true,
        };
      } else if (membership.role === 'admin' || hasOrgManagePermission) {
        permissions = {
          view_overview: true,
          view_dependencies: true,
          view_watchlist: true,
          view_members: true,
          manage_members: hasOrgManagePermission,
          view_settings: true,
          edit_settings: hasOrgManagePermission,
        };
      } else if (ownerTeamId && userTeamPermissions[ownerTeamId]) {
        // User is in owner team with manage_projects permission
        permissions = {
          view_overview: true,
          view_dependencies: true,
          view_watchlist: true,
          view_members: true,
          manage_members: true,
          view_settings: true,
          edit_settings: true,
        };
      } else {
        // Default viewer permissions
        permissions = {
          view_overview: true,
          view_dependencies: true,
          view_watchlist: true,
          view_members: false,
          manage_members: false,
          view_settings: false,
          edit_settings: false,
        };
      }

      const repoStatus = repoStatusByProject[project.id] ?? null;
      return {
        id: project.id,
        organization_id: project.organization_id,
        name: project.name,
        team_ids: teamsByProject[project.id]?.map((t: any) => t.id) || [],
        health_score: project.health_score || 0,
        status: project.status || 'compliant',
        is_compliant: project.is_compliant !== false,
        created_at: project.created_at,
        updated_at: project.updated_at,
        team_names: teamsByProject[project.id]?.map((t: any) => t.name) || [],
        owner_team_id: ownerTeamId,
        owner_team_name: ownerTeamByProject[project.id]?.name || null,
        dependencies_count: project.dependencies_count || 0,
        framework: project.framework || null,
        alerts_count: project.alerts_count || 0,
        repo_status: repoStatus?.status ?? null,
        extraction_step: repoStatus?.extraction_step ?? null,
        extraction_error: repoStatus?.extraction_error ?? null,
        role,
        permissions,
      };
    });

    res.json(formattedProjects);
  } catch (error: any) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch projects' });
  }
});

// GET /api/organizations/:id/repositories/scan - Preview scan repo for subprojects (no project required; for create-project sidebar)
router.get('/:id/repositories/scan', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { repo_full_name, default_branch, integration_id } = req.query as { repo_full_name?: string; default_branch?: string; integration_id?: string };

    if (!repo_full_name || !default_branch || !integration_id) {
      return res.status(400).json({ error: 'repo_full_name, default_branch, and integration_id query params are required' });
    }

    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const integ = await getIntegrationById(id, integration_id);
    if (!integ) {
      return res.status(400).json({ error: 'Integration not found or not connected' });
    }

    const provider = createProvider(integ);
    const result = await detectMonorepo(provider, repo_full_name, default_branch);

    const withLinkStatus = await Promise.all(
      result.potentialProjects.map(async (p) => {
        const { data: existing } = await supabase
          .from('project_repositories')
          .select('project_id')
          .eq('repo_full_name', repo_full_name)
          .eq('package_json_path', p.path)
          .maybeSingle();

        const linkedByProjectId = existing?.project_id ?? null;
        return {
          name: p.name,
          path: p.path,
          ecosystem: p.ecosystem,
          isLinked: !!linkedByProjectId,
          linkedByProjectId: linkedByProjectId ?? undefined,
          linkedByProjectName: undefined as string | undefined,
        };
      })
    );

    const linkedIds = [...new Set(withLinkStatus.filter((p) => p.linkedByProjectId).map((p) => p.linkedByProjectId!))];
    let projectNames: Record<string, string> = {};
    if (linkedIds.length > 0) {
      const { data: projects } = await supabase.from('projects').select('id, name').in('id', linkedIds);
      if (projects) for (const proj of projects) projectNames[proj.id] = proj.name ?? '';
    }
    const withLinkStatusAndNames = withLinkStatus.map((p) => ({
      ...p,
      linkedByProjectName: p.linkedByProjectId ? projectNames[p.linkedByProjectId] : undefined,
    }));

    res.json({
      isMonorepo: result.isMonorepo,
      confidence: result.confidence ?? undefined,
      potentialProjects: withLinkStatusAndNames,
    });
  } catch (error: any) {
    console.error('Error scanning repository (org-level):', error);
    res.status(500).json({ error: error.message || 'Failed to scan repository' });
  }
});

// GET /api/organizations/:id/repositories - List repos from all connected providers (or a specific integration_id)
router.get('/:id/repositories', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { integration_id } = req.query as { integration_id?: string };

    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const GIT_PROVIDERS = ['github', 'gitlab', 'bitbucket'] as const;
    let integrations: OrgIntegration[];
    if (integration_id) {
      const single = await getIntegrationById(id, integration_id);
      integrations = single && GIT_PROVIDERS.includes(single.provider as any) ? [single] : [];
    } else {
      integrations = await getOrgIntegrations(id);
    }

    if (integrations.length === 0) {
      return res.status(400).json({ error: 'No source code integrations connected for this organization' });
    }

    const allRepos: Array<{
      id: number;
      full_name: string;
      default_branch: string;
      private: boolean;
      framework: string;
      ecosystem: string;
      provider: string;
      integration_id: string;
      display_name: string;
    }> = [];

    for (const integ of integrations) {
      try {
        const provider = createProvider(integ);
        const repos = await provider.listRepositories();
        const reposWithFrameworks = await Promise.all(
          repos.map(async (repo) => {
            const detected = await detectRepoFramework(provider, repo.full_name, repo.default_branch);
            return {
              id: repo.id,
              full_name: repo.full_name,
              default_branch: repo.default_branch,
              private: repo.private,
              framework: detected.framework,
              ecosystem: detected.ecosystem,
              provider: integ.provider,
              integration_id: integ.id,
              display_name: (integ as any).display_name || integ.provider,
            };
          })
        );
        allRepos.push(...reposWithFrameworks);
      } catch (err: any) {
        console.warn(`Failed to list repos from ${integ.provider} integration ${integ.id}:`, err.message);
      }
    }

    res.json({ repositories: allRepos });
  } catch (error: any) {
    console.error('Error fetching organization repositories:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch repositories' });
  }
});

// POST /api/organizations/:id/projects - Create a new project
router.post('/:id/projects', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const { name, team_ids, asset_tier: assetTierRaw } = req.body;

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'Project name is required' });
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

    // Check if user is admin, owner, or has manage_teams_and_projects permission
    const { data: orgRole } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    const canCreateProjects =
      membership.role === 'owner' ||
      membership.role === 'admin' ||
      orgRole?.permissions?.manage_teams_and_projects === true;

    if (!canCreateProjects) {
      return res.status(403).json({ error: 'You do not have permission to create projects' });
    }

    // Validate team_ids if provided
    const teamIdsArray = Array.isArray(team_ids) ? team_ids.filter((tid: any) => tid && typeof tid === 'string') : [];
    if (teamIdsArray.length > 0) {
      const { data: teams, error: teamsError } = await supabase
        .from('teams')
        .select('id')
        .eq('organization_id', id)
        .in('id', teamIdsArray);

      if (teamsError || !teams || teams.length !== teamIdsArray.length) {
        return res.status(400).json({ error: 'One or more teams not found or do not belong to this organization' });
      }
    }

    const VALID_ASSET_TIERS = ['CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION'];
    const assetTier =
      typeof assetTierRaw === 'string' && VALID_ASSET_TIERS.includes(assetTierRaw)
        ? assetTierRaw
        : 'EXTERNAL';

    // Create project
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .insert({
        organization_id: id,
        name: name.trim(),
        health_score: 0,
        status: 'compliant',
        asset_tier: assetTier,
      })
      .select('*')
      .single();

    if (projectError) {
      if (projectError.code === '23505' || projectError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'A project with this name already exists' });
      }
      throw projectError;
    }

    // Create project-team associations
    // First team in the array is the owner, rest are contributors
    if (teamIdsArray.length > 0) {
      const projectTeamInserts = teamIdsArray.map((teamId: string, index: number) => ({
        project_id: project.id,
        team_id: teamId,
        is_owner: index === 0, // First team is the owner
      }));

      const { error: projectTeamsError } = await supabase
        .from('project_teams')
        .insert(projectTeamInserts);

      if (projectTeamsError) {
        // Rollback project creation
        await supabase.from('projects').delete().eq('id', project.id);
        throw projectTeamsError;
      }
    }

    // Get team names for response
    const teamNames: string[] = [];
    if (teamIdsArray.length > 0) {
      const { data: teams } = await supabase
        .from('teams')
        .select('name')
        .in('id', teamIdsArray);
      if (teams) {
        teamNames.push(...teams.map((t: any) => t.name));
      }
    }

    const formattedProject = {
      id: project.id,
      organization_id: project.organization_id,
      name: project.name,
      team_ids: teamIdsArray,
      health_score: project.health_score || 0,
      status: project.status || 'compliant',
      is_compliant: project.is_compliant !== false,
      created_at: project.created_at,
      updated_at: project.updated_at,
      team_names: teamNames,
      dependencies_count: project.dependencies_count || 0,
      framework: project.framework || null,
      alerts_count: project.alerts_count || 0,
    };

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'project_created',
      description: `created project "${name.trim()}"`,
      metadata: {
        project_name: name.trim(),
        project_id: project.id,
        team_ids: teamIdsArray,
        team_names: teamNames,
      },
    });

    res.status(201).json(formattedProject);
  } catch (error: any) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: error.message || 'Failed to create project' });
  }
});

// PUT /api/organizations/:id/projects/:projectId - Update a project
router.put('/:id/projects/:projectId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { name, team_ids, auto_bump: autoBump, asset_tier: assetTierRaw } = req.body;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Org owners or users with manage_teams_and_projects can update any project fields.
    // When updating only auto_bump, also allow users with project-level edit_settings.
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;
    const onlyAutoBump = name === undefined && team_ids === undefined && assetTierRaw === undefined && autoBump !== undefined;
    const onlyAssetTier = name === undefined && team_ids === undefined && autoBump === undefined && assetTierRaw !== undefined;
    const onlyNonStructuralUpdate = onlyAutoBump || onlyAssetTier;

    if (!isOrgOwner && !hasOrgPermission) {
      if (!onlyNonStructuralUpdate) {
        return res.status(403).json({ error: 'Only org owners or users with manage_teams_and_projects permission can update projects' });
      }
      // Check project-level edit_settings for auto_bump- or asset_tier-only update
      const { data: projectTeams } = await supabase
        .from('project_teams')
        .select('team_id, is_owner')
        .eq('project_id', projectId);
      const ownerEntry = projectTeams?.find((pt: any) => pt.is_owner);
      const ownerTeamId = ownerEntry?.team_id;

      let hasEditSettings = false;
      if (accessCheck.projectMembership) {
        const { data: projectRole } = await supabase
          .from('project_roles')
          .select('permissions')
          .eq('id', accessCheck.projectMembership.role_id)
          .single();
        hasEditSettings = (projectRole?.permissions as any)?.edit_settings === true;
      }
      if (!hasEditSettings && accessCheck.isInProjectTeam && ownerTeamId) {
        const { data: ownerTeamMembership } = await supabase
          .from('team_members')
          .select('role')
          .eq('team_id', ownerTeamId)
          .eq('user_id', userId)
          .single();
        if (ownerTeamMembership) {
          const { data: teamRole } = await supabase
            .from('team_roles')
            .select('permissions')
            .eq('team_id', ownerTeamId)
            .eq('name', ownerTeamMembership.role)
            .single();
          hasEditSettings = (teamRole?.permissions as any)?.manage_projects === true;
        }
      }
      if (!hasEditSettings) {
        return res.status(403).json({ error: 'You do not have permission to update project settings' });
      }
    }

    // Get current project data before updating (for activity log)
    const { data: currentProject } = await supabase
      .from('projects')
      .select('name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    // Update project name if provided
    const updateData: any = {
      updated_at: new Date().toISOString(),
    };

    if (name !== undefined) {
      updateData.name = name.trim();
    }

    if (autoBump !== undefined) {
      if (typeof autoBump !== 'boolean') {
        return res.status(400).json({ error: 'auto_bump must be a boolean' });
      }
      updateData.auto_bump = autoBump;
    }

    const VALID_ASSET_TIERS = ['CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION'];
    if (assetTierRaw !== undefined) {
      if (typeof assetTierRaw !== 'string' || !VALID_ASSET_TIERS.includes(assetTierRaw)) {
        return res.status(400).json({ error: 'asset_tier must be one of: CROWN_JEWELS, EXTERNAL, INTERNAL, NON_PRODUCTION' });
      }
      updateData.asset_tier = assetTierRaw;
    }

    const { data: project, error: projectError } = await supabase
      .from('projects')
      .update(updateData)
      .eq('id', projectId)
      .eq('organization_id', id)
      .select('*')
      .single();

    if (projectError) {
      if (projectError.code === '23505' || projectError.message?.includes('duplicate key')) {
        return res.status(400).json({ error: 'A project with this name already exists' });
      }
      throw projectError;
    }

    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Update team associations if team_ids is provided
    if (team_ids !== undefined) {
      const teamIdsArray = Array.isArray(team_ids) ? team_ids.filter((tid: any) => tid && typeof tid === 'string') : [];

      // Validate team_ids if provided
      if (teamIdsArray.length > 0) {
        const { data: teams, error: teamsError } = await supabase
          .from('teams')
          .select('id')
          .eq('organization_id', id)
          .in('id', teamIdsArray);

        if (teamsError || !teams || teams.length !== teamIdsArray.length) {
          return res.status(400).json({ error: 'One or more teams not found or do not belong to this organization' });
        }
      }

      // Delete existing associations
      const { error: deleteError } = await supabase
        .from('project_teams')
        .delete()
        .eq('project_id', projectId);

      if (deleteError) {
        throw deleteError;
      }

      // Create new associations
      if (teamIdsArray.length > 0) {
        const projectTeamInserts = teamIdsArray.map((teamId: string) => ({
          project_id: projectId,
          team_id: teamId,
        }));

        const { error: insertError } = await supabase
          .from('project_teams')
          .insert(projectTeamInserts);

        if (insertError) {
          throw insertError;
        }
      }
    }

    // Get team names and IDs for response
    let teamIds: string[] = [];
    let teamNames: string[] = [];

    if (team_ids !== undefined) {
      // Use the provided team_ids
      teamIds = Array.isArray(team_ids) ? team_ids.filter((tid: any) => tid && typeof tid === 'string') : [];

      if (teamIds.length > 0) {
        const { data: teams } = await supabase
          .from('teams')
          .select('id, name')
          .in('id', teamIds);
        if (teams) {
          teamNames = teams.map((t: any) => t.name);
        }
      }
    } else {
      // Fetch current teams if team_ids wasn't updated
      const { data: projectTeams } = await supabase
        .from('project_teams')
        .select(`
          teams:team_id (
            id,
            name
          )
        `)
        .eq('project_id', projectId);

      if (projectTeams) {
        teamIds = projectTeams
          .map((pt: any) => pt.teams?.id)
          .filter((id: string | undefined) => id) as string[];
        teamNames = projectTeams
          .map((pt: any) => pt.teams?.name)
          .filter((name: string | undefined) => name) as string[];
      }
    }

    const formattedProject = {
      id: project.id,
      organization_id: project.organization_id,
      name: project.name,
      team_ids: teamIds,
      health_score: project.health_score || 0,
      status: project.status || 'compliant',
      is_compliant: project.is_compliant !== false,
      created_at: project.created_at,
      updated_at: project.updated_at,
      team_names: teamNames,
      dependencies_count: project.dependencies_count || 0,
      framework: project.framework || null,
      alerts_count: project.alerts_count || 0,
      auto_bump: project.auto_bump !== false,
    };

    // Create activity log if name changed
    if (name !== undefined && currentProject && name.trim() !== currentProject.name) {
      await createActivity({
        organization_id: id,
        user_id: userId,
        activity_type: 'updated_project_name',
        description: `updated project name from "${currentProject.name}" to "${name.trim()}"`,
        metadata: {
          project_id: projectId,
          old_name: currentProject.name,
          new_name: name.trim(),
        },
      });
    }

    res.json(formattedProject);
  } catch (error: any) {
    console.error('Error updating project:', error);
    res.status(500).json({ error: error.message || 'Failed to update project' });
  }
});

// DELETE /api/organizations/:id/projects/:projectId - Delete a project
router.delete('/:id/projects/:projectId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Only org owners or users with manage_teams_and_projects permission can delete projects
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;
    if (!isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'Only org owners or users with manage_teams_and_projects permission can delete projects' });
    }

    // Delete project
    const { error: deleteError } = await supabase
      .from('projects')
      .delete()
      .eq('id', projectId)
      .eq('organization_id', id);

    if (deleteError) {
      throw deleteError;
    }

    res.json({ message: 'Project deleted' });
  } catch (error: any) {
    console.error('Error deleting project:', error);
    res.status(500).json({ error: error.message || 'Failed to delete project' });
  }
});

// GET /api/organizations/:id/projects/:projectId - Get single project with user's role
router.get('/:id/projects/:projectId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

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

    // Get the project
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('*')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Get team associations with owner flag
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select(`
        is_owner,
        teams:team_id (
          id,
          name
        )
      `)
      .eq('project_id', projectId);

    const teamIds = projectTeams?.map((pt: any) => pt.teams?.id).filter(Boolean) || [];
    const teamNames = projectTeams?.map((pt: any) => pt.teams?.name).filter(Boolean) || [];

    // Find owner team
    const ownerTeamEntry = projectTeams?.find((pt: any) => pt.is_owner);
    const team = Array.isArray(ownerTeamEntry?.teams) ? ownerTeamEntry?.teams?.[0] : ownerTeamEntry?.teams;
    const ownerTeamId = (team as { id?: string } | undefined)?.id ?? null;
    const ownerTeamName = (team as { name?: string } | undefined)?.name ?? null;

    // Get user's project role and permissions
    let userRole = null;
    let userPermissions = null;

    // First check if user is an org owner/admin (they get full access)
    if (membership.role === 'owner' || membership.role === 'admin') {
      userRole = membership.role === 'owner' ? 'owner' : 'editor';
      userPermissions = {
        view_overview: true,
        view_dependencies: true,
        view_watchlist: true,
        view_members: true,
        manage_members: membership.role === 'owner',
        view_settings: true,
        edit_settings: membership.role === 'owner',
        can_manage_watchtower: true,
      };
    } else {
      // Check org-level manage_teams_and_projects permission
      const { data: orgRole } = await supabase
        .from('organization_roles')
        .select('permissions')
        .eq('organization_id', id)
        .eq('name', membership.role)
        .single();

      const hasOrgManagePermission = orgRole?.permissions?.manage_teams_and_projects === true;

      // Check if user is in the owner team with manage_projects permission
      let hasOwnerTeamManageProjects = false;
      if (ownerTeamId) {
        // Check if user is a member of the owner team
        const { data: ownerTeamMembership } = await supabase
          .from('team_members')
          .select('role')
          .eq('team_id', ownerTeamId)
          .eq('user_id', userId)
          .single();

        if (ownerTeamMembership) {
          // Get the team role permissions
          const { data: teamRole } = await supabase
            .from('team_roles')
            .select('permissions')
            .eq('team_id', ownerTeamId)
            .eq('name', ownerTeamMembership.role)
            .single();

          hasOwnerTeamManageProjects = teamRole?.permissions?.manage_projects === true;
        }
      }

      // Check project_members for direct membership
      const { data: projectMember } = await supabase
        .from('project_members')
        .select(`
          role_id,
          project_roles!inner (
            name,
            display_name,
            permissions
          )
        `)
        .eq('project_id', projectId)
        .eq('user_id', userId)
        .single();

      if (projectMember) {
        const role = (projectMember as any).project_roles;
        userRole = role.name;
        userPermissions = { ...role.permissions };

        // Grant settings access if user has org-level or owner team manage permission
        if (hasOrgManagePermission || hasOwnerTeamManageProjects) {
          userPermissions.view_settings = true;
          userPermissions.edit_settings = true;
        }
        (userPermissions as any).can_manage_watchtower = hasOrgManagePermission || hasOwnerTeamManageProjects;
      } else {
        // Check if user is in a team assigned to this project
        const { data: teamMemberships } = await supabase
          .from('team_members')
          .select('team_id')
          .eq('user_id', userId);

        const userTeamIds = teamMemberships?.map((tm: any) => tm.team_id) || [];
        const isInProjectTeam = userTeamIds.some((tid: string) => teamIds.includes(tid));

        if (isInProjectTeam || hasOrgManagePermission) {
          // User has access via team membership or org permission
          userRole = hasOrgManagePermission || hasOwnerTeamManageProjects ? 'editor' : 'viewer';
          userPermissions = {
            view_overview: true,
            view_dependencies: true,
            view_watchlist: true,
            view_members: hasOrgManagePermission || hasOwnerTeamManageProjects,
            manage_members: hasOrgManagePermission || hasOwnerTeamManageProjects,
            view_settings: hasOrgManagePermission || hasOwnerTeamManageProjects,
            edit_settings: hasOrgManagePermission || hasOwnerTeamManageProjects,
            can_manage_watchtower: hasOrgManagePermission || hasOwnerTeamManageProjects,
          };
        }
      }
    }

    // If user has no access, return 403
    if (!userRole && !userPermissions) {
      return res.status(403).json({ error: 'Access denied to this project' });
    }

    const formattedProject = {
      id: project.id,
      organization_id: project.organization_id,
      name: project.name,
      team_ids: teamIds,
      health_score: project.health_score || 0,
      status: project.status || 'compliant',
      is_compliant: project.is_compliant !== false,
      created_at: project.created_at,
      updated_at: project.updated_at,
      team_names: teamNames,
      owner_team_id: ownerTeamId,
      owner_team_name: ownerTeamName,
      dependencies_count: project.dependencies_count || 0,
      framework: project.framework || null,
      alerts_count: project.alerts_count || 0,
      auto_bump: project.auto_bump !== false,
      role: userRole,
      permissions: userPermissions,
    };

    res.json(formattedProject);
  } catch (error: any) {
    console.error('Error fetching project:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project' });
  }
});

// GET /api/organizations/:id/projects/:projectId/connections - Merged org + team + project connections
router.get('/:id/projects/:projectId/connections', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, orgId, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: project } = await supabase
      .from('projects')
      .select('organization_id')
      .eq('id', projectId)
      .eq('organization_id', orgId)
      .single();

    if (!project) return res.status(404).json({ error: 'Project not found' });

    const NOTIFICATION_PROVIDERS = ['slack', 'discord', 'jira', 'linear', 'asana', 'custom_notification', 'custom_ticketing', 'email'];

    // Find the owner team for this project
    const { data: ownerEntry } = await supabase
      .from('project_teams')
      .select('team_id')
      .eq('project_id', projectId)
      .eq('is_owner', true)
      .single();
    const ownerTeamId = ownerEntry?.team_id || null;

    const queries: Promise<any>[] = [
      supabase
        .from('organization_integrations')
        .select('id, organization_id, provider, installation_id, display_name, metadata, status, connected_at, created_at, updated_at')
        .eq('organization_id', orgId)
        .eq('status', 'connected')
        .in('provider', NOTIFICATION_PROVIDERS)
        .order('created_at', { ascending: true }),
      supabase
        .from('project_integrations')
        .select('id, project_id, provider, installation_id, display_name, metadata, status, connected_at, created_at, updated_at')
        .eq('project_id', projectId)
        .eq('status', 'connected')
        .in('provider', NOTIFICATION_PROVIDERS)
        .order('created_at', { ascending: true }),
    ];

    if (ownerTeamId) {
      queries.push(
        supabase
          .from('team_integrations')
          .select('id, team_id, provider, installation_id, display_name, metadata, status, connected_at, created_at, updated_at')
          .eq('team_id', ownerTeamId)
          .eq('status', 'connected')
          .in('provider', NOTIFICATION_PROVIDERS)
          .order('created_at', { ascending: true })
      );
    }

    const results = await Promise.all(queries);
    const orgConns = results[0].data || [];
    const projConns = results[1].data || [];
    const teamConns = ownerTeamId ? (results[2]?.data || []) : [];

    const inherited = orgConns.map((c: any) => ({ ...c, source: 'organization' }));
    const teamSpecific = teamConns.map((c: any) => ({ ...c, source: 'team' }));
    const projectSpecific = projConns.map((c: any) => ({ ...c, source: 'project' }));
    res.json({ inherited, team: teamSpecific, project: projectSpecific });
  } catch (error: any) {
    console.error('Error fetching project connections:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch connections' });
  }
});

// DELETE /api/organizations/:id/projects/:projectId/connections/:connectionId - Delete project connection only
router.delete('/:id/projects/:projectId/connections/:connectionId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId, connectionId } = req.params;

    if (!(await checkWatchtowerManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage project integrations' });
    }

    const { data: connection } = await supabase
      .from('project_integrations')
      .select('*')
      .eq('id', connectionId)
      .eq('project_id', projectId)
      .single();

    if (!connection) return res.status(404).json({ error: 'Connection not found' });

    const { error: deleteError } = await supabase
      .from('project_integrations')
      .delete()
      .eq('id', connectionId)
      .eq('project_id', projectId);

    if (deleteError) throw deleteError;

    res.json({ success: true, message: 'Connection removed' });
  } catch (error: any) {
    console.error('Error deleting project connection:', error);
    res.status(500).json({ error: error.message || 'Failed to delete connection' });
  }
});

// GET /api/organizations/:id/projects/:projectId/notification-rules
router.get('/:id/projects/:projectId/notification-rules', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, orgId, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: rules, error } = await supabase
      .from('project_notification_rules')
      .select('*')
      .eq('project_id', projectId)
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
    console.error('Error fetching project notification rules:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch notification rules' });
  }
});

// POST /api/organizations/:id/projects/:projectId/notification-rules
router.post('/:id/projects/:projectId/notification-rules', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;
    const { name, triggerType, minDepscoreThreshold, customCode, destinations, createdByName } = req.body;

    if (!(await checkWatchtowerManagePermission(userId, orgId, projectId))) {
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
      project_id: projectId,
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
      .from('project_notification_rules')
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
    console.error('Error creating project notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to create notification rule' });
  }
});

// PUT /api/organizations/:id/projects/:projectId/notification-rules/:ruleId
router.put('/:id/projects/:projectId/notification-rules/:ruleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId, ruleId } = req.params;
    const { name, triggerType, minDepscoreThreshold, customCode, destinations } = req.body;

    if (!(await checkWatchtowerManagePermission(userId, orgId, projectId))) {
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
      .from('project_notification_rules')
      .update(updateData)
      .eq('id', ruleId)
      .eq('project_id', projectId)
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
    console.error('Error updating project notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to update notification rule' });
  }
});

// DELETE /api/organizations/:id/projects/:projectId/notification-rules/:ruleId
router.delete('/:id/projects/:projectId/notification-rules/:ruleId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId, ruleId } = req.params;

    if (!(await checkWatchtowerManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage notification rules' });
    }

    const { error } = await supabase
      .from('project_notification_rules')
      .delete()
      .eq('id', ruleId)
      .eq('project_id', projectId);

    if (error) throw error;
    res.json({ message: 'Notification rule deleted' });
  } catch (error: any) {
    console.error('Error deleting project notification rule:', error);
    res.status(500).json({ error: error.message || 'Failed to delete notification rule' });
  }
});

// POST /api/organizations/:id/projects/:projectId/email-notifications
router.post('/:id/projects/:projectId/email-notifications', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;
    const { email } = req.body;

    if (!(await checkWatchtowerManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage project integrations' });
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

    const { data: project } = await supabase
      .from('projects')
      .select('id')
      .eq('id', projectId)
      .eq('organization_id', orgId)
      .single();
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const { data, error: dbError } = await supabase
      .from('project_integrations')
      .insert({
        project_id: projectId,
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
      console.error('Project email notification DB error:', dbError);
      return res.status(500).json({ error: 'Failed to add email notification' });
    }

    res.json({ success: true, id: data?.id });
  } catch (error: any) {
    console.error('Add project email notification error:', error);
    res.status(500).json({ error: error.message || 'Failed to add email' });
  }
});

// POST /api/organizations/:id/projects/:projectId/custom-integrations
router.post('/:id/projects/:projectId/custom-integrations', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id: orgId, projectId } = req.params;
    const { name, type, webhook_url, icon_url } = req.body;

    if (!(await checkWatchtowerManagePermission(userId, orgId, projectId))) {
      return res.status(403).json({ error: 'You do not have permission to manage project integrations' });
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

    const { data, error: dbError } = await supabase
      .from('project_integrations')
      .insert({
        project_id: projectId,
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
      console.error('Project custom integration DB error:', dbError);
      return res.status(500).json({ error: 'Failed to create custom integration' });
    }

    res.json({ success: true, id: data?.id, secret });
  } catch (error: any) {
    console.error('Create project custom integration error:', error);
    res.status(500).json({ error: error.message || 'Failed to create custom integration' });
  }
});

// GET /api/organizations/:id/projects/:projectId/roles - Get project roles
router.get('/:id/projects/:projectId/roles', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get project roles
    const { data: roles, error: rolesError } = await supabase
      .from('project_roles')
      .select('*')
      .eq('project_id', projectId)
      .order('display_order', { ascending: true });

    if (rolesError) {
      throw rolesError;
    }

    res.json(roles || []);
  } catch (error: any) {
    console.error('Error fetching project roles:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project roles' });
  }
});

// GET /api/organizations/:id/projects/:projectId/members - Get project members (direct + team-based)
router.get('/:id/projects/:projectId/members', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get direct project members
    const { data: directMembers, error: directMembersError } = await supabase
      .from('project_members')
      .select(`
        id,
        user_id,
        role_id,
        created_at,
        project_roles!inner (
          name,
          display_name,
          permissions
        )
      `)
      .eq('project_id', projectId);

    if (directMembersError) {
      throw directMembersError;
    }

    // Get user profiles for direct members
    const directMemberIds = directMembers?.map((m: any) => m.user_id) || [];
    let directMemberProfiles: any[] = [];

    if (directMemberIds.length > 0) {
      const { data: profiles } = await supabase
        .from('user_profiles')
        .select('user_id, full_name, avatar_url')
        .in('user_id', directMemberIds);

      // Get emails and user_metadata from auth.users (requires service role)
      const { data: authUsers } = await supabase.auth.admin.listUsers();
      const authUserMap = new Map(authUsers?.users?.map((u: any) => [u.id, u]) || []);

      directMemberProfiles = (profiles || []).map(p => {
        const authUser = authUserMap.get(p.user_id);
        const avatarUrl = p.avatar_url
          || authUser?.user_metadata?.avatar_url
          || authUser?.user_metadata?.picture
          || null;
        const fullName = p.full_name
          || authUser?.user_metadata?.full_name
          || authUser?.user_metadata?.name
          || null;
        return {
          ...p,
          full_name: fullName,
          avatar_url: avatarUrl,
          email: authUser?.email || null,
        };
      });
    }

    // Get team-based members (from project_teams junction)
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('team_id')
      .eq('project_id', projectId);

    const teamIds = projectTeams?.map((pt: any) => pt.team_id) || [];
    let teamMembers: any[] = [];

    if (teamIds.length > 0) {
      const { data: teamMemberData } = await supabase
        .from('team_members')
        .select(`
          user_id,
          team_id,
          teams!inner (
            name
          )
        `)
        .in('team_id', teamIds);

      // Get user profiles for team members
      const teamMemberIds = teamMemberData?.map((tm: any) => tm.user_id) || [];
      const uniqueTeamMemberIds = [...new Set(teamMemberIds)];

      if (uniqueTeamMemberIds.length > 0) {
        const { data: teamProfiles } = await supabase
          .from('user_profiles')
          .select('user_id, full_name, avatar_url')
          .in('user_id', uniqueTeamMemberIds);

        // Get emails and user_metadata from auth.users
        const { data: authUsers } = await supabase.auth.admin.listUsers();
        const authUserMap = new Map(authUsers?.users?.map((u: any) => [u.id, u]) || []);

        // Group team names by user
        const teamsByUser = new Map<string, string[]>();
        teamMemberData?.forEach((tm: any) => {
          const teams = teamsByUser.get(tm.user_id) || [];
          teams.push((tm as any).teams?.name);
          teamsByUser.set(tm.user_id, teams);
        });

        teamMembers = (teamProfiles || []).map((p: any) => {
          const authUser = authUserMap.get(p.user_id);
          const avatarUrl = p.avatar_url
            || authUser?.user_metadata?.avatar_url
            || authUser?.user_metadata?.picture
            || null;
          const fullName = p.full_name
            || authUser?.user_metadata?.full_name
            || authUser?.user_metadata?.name
            || null;
          return {
            user_id: p.user_id,
            full_name: fullName,
            avatar_url: avatarUrl,
            email: authUser?.email || null,
            teams: teamsByUser.get(p.user_id) || [],
            membership_type: 'team',
          };
        });
      }
    }

    // Format direct members
    const formattedDirectMembers = (directMembers || []).map((m: any) => {
      const profile = directMemberProfiles.find(p => p.user_id === m.user_id);
      return {
        user_id: m.user_id,
        full_name: profile?.full_name || null,
        avatar_url: profile?.avatar_url || null,
        email: profile?.email || null,
        role: (m as any).project_roles?.name,
        role_display_name: (m as any).project_roles?.display_name,
        permissions: (m as any).project_roles?.permissions,
        membership_type: 'direct',
        created_at: m.created_at,
      };
    });

    // Combine and deduplicate (direct membership takes precedence)
    const directMemberUserIds = new Set(formattedDirectMembers.map(m => m.user_id));
    const filteredTeamMembers = teamMembers.filter(m => !directMemberUserIds.has(m.user_id));

    res.json({
      direct_members: formattedDirectMembers,
      team_members: filteredTeamMembers,
    });
  } catch (error: any) {
    console.error('Error fetching project members:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project members' });
  }
});

// POST /api/organizations/:id/projects/:projectId/members - Add a member to project
router.post('/:id/projects/:projectId/members', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { user_id: targetUserId, role_id } = req.body;

    if (!targetUserId) {
      return res.status(400).json({ error: 'user_id is required' });
    }

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if requesting user has permission to manage members
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      // Check project-level permission
      if (accessCheck.projectMembership?.role_id) {
        const { data: projectRole } = await supabase
          .from('project_roles')
          .select('permissions')
          .eq('id', accessCheck.projectMembership.role_id)
          .single();

        if (!projectRole?.permissions?.manage_members) {
          return res.status(403).json({ error: 'You do not have permission to manage project members' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to manage project members' });
      }
    }

    // Verify target user is in the organization
    const { data: targetMembership } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', id)
      .eq('user_id', targetUserId)
      .single();

    if (!targetMembership) {
      return res.status(400).json({ error: 'User must be a member of the organization' });
    }

    // Get role_id - use provided one or default to viewer
    let finalRoleId = role_id;
    if (!finalRoleId) {
      const { data: viewerRole } = await supabase
        .from('project_roles')
        .select('id')
        .eq('project_id', projectId)
        .eq('name', 'viewer')
        .single();
      finalRoleId = viewerRole?.id;
    }

    if (!finalRoleId) {
      return res.status(400).json({ error: 'Could not determine role for member' });
    }

    // Add member
    const { data: newMember, error: insertError } = await supabase
      .from('project_members')
      .insert({
        project_id: projectId,
        user_id: targetUserId,
        role_id: finalRoleId,
      })
      .select(`
        id,
        user_id,
        role_id,
        created_at,
        project_roles!inner (
          name,
          display_name,
          permissions
        )
      `)
      .single();

    if (insertError) {
      if (insertError.code === '23505') {
        return res.status(400).json({ error: 'User is already a member of this project' });
      }
      throw insertError;
    }

    // Get user profile
    const { data: profile } = await supabase
      .from('user_profiles')
      .select('full_name, avatar_url')
      .eq('user_id', targetUserId)
      .single();

    const { data: authUsers } = await supabase.auth.admin.listUsers();
    const targetUser = authUsers?.users?.find((u: any) => u.id === targetUserId);

    // Fall back to user_metadata for name and avatar
    const fullName = profile?.full_name
      || targetUser?.user_metadata?.full_name
      || targetUser?.user_metadata?.name
      || null;
    const avatarUrl = profile?.avatar_url
      || targetUser?.user_metadata?.avatar_url
      || targetUser?.user_metadata?.picture
      || null;

    res.status(201).json({
      user_id: newMember.user_id,
      full_name: fullName,
      avatar_url: avatarUrl,
      email: targetUser?.email || null,
      role: (newMember as any).project_roles?.name,
      role_display_name: (newMember as any).project_roles?.display_name,
      permissions: (newMember as any).project_roles?.permissions,
      membership_type: 'direct',
      created_at: newMember.created_at,
    });
  } catch (error: any) {
    console.error('Error adding project member:', error);
    res.status(500).json({ error: error.message || 'Failed to add project member' });
  }
});

// PUT /api/organizations/:id/projects/:projectId/members/:memberId/role - Update member role
router.put('/:id/projects/:projectId/members/:memberId/role', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, memberId } = req.params;
    const { role_id } = req.body;

    if (!role_id) {
      return res.status(400).json({ error: 'role_id is required' });
    }

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if requesting user has permission to manage members
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      if (accessCheck.projectMembership?.role_id) {
        const { data: projectRole } = await supabase
          .from('project_roles')
          .select('permissions')
          .eq('id', accessCheck.projectMembership.role_id)
          .single();

        if (!projectRole?.permissions?.manage_members) {
          return res.status(403).json({ error: 'You do not have permission to manage project members' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to manage project members' });
      }
    }

    // Verify the role exists for this project
    const { data: role } = await supabase
      .from('project_roles')
      .select('id')
      .eq('id', role_id)
      .eq('project_id', projectId)
      .single();

    if (!role) {
      return res.status(400).json({ error: 'Invalid role for this project' });
    }

    // Update the member's role
    const { data: updatedMember, error: updateError } = await supabase
      .from('project_members')
      .update({ role_id, updated_at: new Date().toISOString() })
      .eq('project_id', projectId)
      .eq('user_id', memberId)
      .select(`
        id,
        user_id,
        role_id,
        created_at,
        project_roles!inner (
          name,
          display_name,
          permissions
        )
      `)
      .single();

    if (updateError) {
      throw updateError;
    }

    if (!updatedMember) {
      return res.status(404).json({ error: 'Member not found' });
    }

    res.json({
      user_id: updatedMember.user_id,
      role: (updatedMember as any).project_roles?.name,
      role_display_name: (updatedMember as any).project_roles?.display_name,
      permissions: (updatedMember as any).project_roles?.permissions,
    });
  } catch (error: any) {
    console.error('Error updating project member role:', error);
    res.status(500).json({ error: error.message || 'Failed to update member role' });
  }
});

// DELETE /api/organizations/:id/projects/:projectId/members/:memberId - Remove member from project
router.delete('/:id/projects/:projectId/members/:memberId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, memberId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if requesting user has permission to manage members
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      if (accessCheck.projectMembership?.role_id) {
        const { data: projectRole } = await supabase
          .from('project_roles')
          .select('permissions')
          .eq('id', accessCheck.projectMembership.role_id)
          .single();

        if (!projectRole?.permissions?.manage_members) {
          return res.status(403).json({ error: 'You do not have permission to manage project members' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to manage project members' });
      }
    }

    // Cannot remove the last owner
    const { data: ownerRole } = await supabase
      .from('project_roles')
      .select('id')
      .eq('project_id', projectId)
      .eq('name', 'owner')
      .single();

    if (ownerRole) {
      const { data: owners } = await supabase
        .from('project_members')
        .select('user_id')
        .eq('project_id', projectId)
        .eq('role_id', ownerRole.id);

      if (owners?.length === 1 && owners[0].user_id === memberId) {
        return res.status(400).json({ error: 'Cannot remove the last owner of the project' });
      }
    }

    // Remove the member
    const { error: deleteError } = await supabase
      .from('project_members')
      .delete()
      .eq('project_id', projectId)
      .eq('user_id', memberId);

    if (deleteError) {
      throw deleteError;
    }

    res.json({ message: 'Member removed from project' });
  } catch (error: any) {
    console.error('Error removing project member:', error);
    res.status(500).json({ error: error.message || 'Failed to remove project member' });
  }
});

// GET /api/organizations/:id/projects/:projectId/policies - Get effective policies for a project
router.get('/:id/projects/:projectId/policies', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Get organization policy (policy as code)
    const { data: orgPolicies } = await supabase
      .from('organization_policies')
      .select('policy_code')
      .eq('organization_id', id)
      .single();

    const inheritedPolicyCode = (orgPolicies?.policy_code ?? '').trim() || '';

    // Get all exceptions for this project (accepted and pending)
    const { data: exceptions } = await supabase
      .from('project_policy_exceptions')
      .select('id, status, requested_policy_code, base_policy_code, reason, requested_by, policy_type, created_at, updated_at')
      .eq('organization_id', id)
      .eq('project_id', projectId)
      .order('created_at', { ascending: false });

    const acceptedList = (exceptions || []).filter((e: any) => e.status === 'accepted');
    const pendingList = (exceptions || []).filter((e: any) => e.status === 'pending');
    const revokedList = (exceptions || []).filter((e: any) => e.status === 'revoked');
    const latestAccepted = acceptedList[0] || null;
    const effectivePolicyCode = latestAccepted?.requested_policy_code != null && latestAccepted.requested_policy_code !== ''
      ? latestAccepted.requested_policy_code
      : inheritedPolicyCode;
    const pendingException = pendingList[0] || null;

    // Backward-compat shape for compliance UIs
    const inherited = {
      accepted_licenses: [] as string[],
      slsa_enforcement: 'none' as const,
      slsa_level: null as number | null,
    };
    const effective = {
      accepted_licenses: [] as string[],
      slsa_enforcement: 'none' as const,
      slsa_level: null as number | null,
    };
    const acceptedExceptionsLegacy = acceptedList.map((e: any) => ({
      id: e.id,
      project_id: projectId,
      organization_id: id,
      requested_by: e.requested_by,
      status: e.status,
      reason: e.reason,
      policy_type: e.policy_type ?? 'full',
      additional_licenses: [] as string[],
      requested_policy_code: e.requested_policy_code ?? null,
      base_policy_code: e.base_policy_code ?? null,
      created_at: e.created_at,
      updated_at: e.updated_at,
    }));
    const pendingExceptionsLegacy = pendingList.map((e: any) => ({
      id: e.id,
      project_id: projectId,
      organization_id: id,
      requested_by: e.requested_by,
      status: e.status,
      reason: e.reason,
      policy_type: e.policy_type ?? 'full',
      additional_licenses: [] as string[],
      requested_policy_code: e.requested_policy_code ?? null,
      base_policy_code: e.base_policy_code ?? null,
      created_at: e.created_at,
      updated_at: e.updated_at,
    }));
    const revokedExceptionsLegacy = revokedList.map((e: any) => ({
      id: e.id,
      project_id: projectId,
      organization_id: id,
      requested_by: e.requested_by,
      status: e.status,
      reason: e.reason,
      policy_type: e.policy_type ?? 'full',
      additional_licenses: [] as string[],
      requested_policy_code: e.requested_policy_code ?? null,
      base_policy_code: e.base_policy_code ?? null,
      created_at: e.created_at,
      updated_at: e.updated_at,
    }));

    res.json({
      inherited_policy_code: inheritedPolicyCode,
      effective_policy_code: effectivePolicyCode,
      pending_exception: pendingException
        ? {
            id: pendingException.id,
            policy_type: pendingException.policy_type ?? 'full',
            requested_policy_code: pendingException.requested_policy_code ?? '',
            base_policy_code: pendingException.base_policy_code ?? '',
            reason: pendingException.reason,
            requested_by: pendingException.requested_by,
            created_at: pendingException.created_at,
            updated_at: pendingException.updated_at,
          }
        : null,
      accepted_exceptions: acceptedExceptionsLegacy,
      inherited,
      effective,
      pending_exceptions: pendingExceptionsLegacy,
      revoked_exceptions: revokedExceptionsLegacy,
    });
  } catch (error: any) {
    console.error('Error fetching project policies:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project policies' });
  }
});

// POST /api/organizations/:id/projects/:projectId/policy-exceptions - Submit exception request
router.post('/:id/projects/:projectId/policy-exceptions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { reason, requested_policy_code, additional_licenses, slsa_enforcement, slsa_level, policy_type: policyTypeParam } = req.body;

    if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
      return res.status(400).json({ error: 'Reason is required for exception request' });
    }

    const requestedCode = typeof requested_policy_code === 'string' ? requested_policy_code : '';
    // Policy-as-code flow requires requested_policy_code
    if (requestedCode === '' && (!additional_licenses || additional_licenses.length === 0) && !slsa_enforcement && (slsa_level == null || slsa_level === undefined)) {
      return res.status(400).json({ error: 'requested_policy_code is required for policy exception request' });
    }

    const policyType = ['compliance', 'pull_request', 'full'].includes(policyTypeParam) ? policyTypeParam : 'full';

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // One pending per (project, policy_type): reject if already pending for this type
    // 'full' blocks both sections; compliance/pull_request block only their section
    const { data: allPending } = await supabase
      .from('project_policy_exceptions')
      .select('id, policy_type')
      .eq('organization_id', id)
      .eq('project_id', projectId)
      .eq('status', 'pending');

    const pendingList = (allPending || []) as Array<{ id: string; policy_type?: string }>;
    const hasFull = pendingList.some((p) => (p.policy_type ?? 'full') === 'full');
    const hasCompliance = pendingList.some((p) => (p.policy_type ?? 'full') === 'compliance');
    const hasPullRequest = pendingList.some((p) => (p.policy_type ?? 'full') === 'pull_request');

    if (policyType === 'full' && pendingList.length > 0) {
      return res.status(409).json({ error: 'Project already has a pending exception request. Cancel it before submitting a new one.' });
    }
    if (policyType === 'compliance' && (hasFull || hasCompliance)) {
      return res.status(409).json({ error: 'Compliance exception request already pending. Cancel it before submitting a new one.' });
    }
    if (policyType === 'pull_request' && (hasFull || hasPullRequest)) {
      return res.status(409).json({ error: 'Pull request exception request already pending. Cancel it before submitting a new one.' });
    }

    // Base = current effective (org or latest accepted exception's requested_policy_code)
    let basePolicyCode = '';
    const { data: orgPolicies } = await supabase
      .from('organization_policies')
      .select('policy_code')
      .eq('organization_id', id)
      .single();
    basePolicyCode = (orgPolicies?.policy_code ?? '').trim() || '';

    const { data: latestAccepted } = await supabase
      .from('project_policy_exceptions')
      .select('requested_policy_code')
      .eq('organization_id', id)
      .eq('project_id', projectId)
      .eq('status', 'accepted')
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (latestAccepted?.requested_policy_code != null && latestAccepted.requested_policy_code !== '') {
      basePolicyCode = latestAccepted.requested_policy_code;
    }

    // Validate SLSA enforcement if provided (legacy)
    if (slsa_enforcement) {
      const validSlsaEnforcement = ['none', 'recommended', 'require_provenance', 'require_attestations', 'require_signed'];
      if (!validSlsaEnforcement.includes(slsa_enforcement)) {
        return res.status(400).json({ error: 'Invalid slsa_enforcement value' });
      }
    }

    if (slsa_level !== null && slsa_level !== undefined) {
      if (!Number.isInteger(slsa_level) || slsa_level < 1 || slsa_level > 4) {
        return res.status(400).json({ error: 'slsa_level must be an integer between 1 and 4' });
      }
    }

    // Create exception request (policy-as-code and legacy fields)
    const { data: exception, error: createError } = await supabase
      .from('project_policy_exceptions')
      .insert({
        project_id: projectId,
        organization_id: id,
        requested_by: userId,
        reason: reason.trim(),
        requested_policy_code: requestedCode || null,
        base_policy_code: basePolicyCode || null,
        policy_type: policyType,
        additional_licenses: Array.isArray(additional_licenses) ? additional_licenses : [],
        slsa_enforcement: slsa_enforcement || null,
        slsa_level: slsa_level || null,
        status: 'pending',
      })
      .select()
      .single();

    if (createError) {
      throw createError;
    }

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'policy_exception_requested',
      description: `requested policy exception for project "${project.name}"`,
      metadata: {
        project_id: projectId,
        project_name: project.name,
        exception_id: exception.id,
        additional_licenses: additional_licenses || [],
        slsa_enforcement: slsa_enforcement || null,
      },
    });

    res.status(201).json(exception);
  } catch (error: any) {
    console.error('Error creating policy exception request:', error);
    res.status(500).json({ error: error.message || 'Failed to create exception request' });
  }
});

// GET /api/organizations/:id/policy-exceptions - List all exception requests for org
router.get('/:id/policy-exceptions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id } = req.params;
    const status = req.query.status as string | undefined;

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

    // Build query
    let query = supabase
      .from('project_policy_exceptions')
      .select('*')
      .eq('organization_id', id)
      .order('created_at', { ascending: false });

    if (status) {
      query = query.eq('status', status);
    }

    const { data: exceptions, error: exceptionsError } = await query;

    if (exceptionsError) {
      throw exceptionsError;
    }

    // Get project names and requester info
    const projectIds = [...new Set((exceptions || []).map((e: any) => e.project_id))];
    const userIds = [...new Set((exceptions || []).map((e: any) => e.requested_by))];

    let projectsMap: Record<string, { name: string; framework?: string | null }> = {};
    let usersMap: Record<string, { email: string; full_name: string | null; avatar_url?: string | null; role?: string; role_display_name?: string | null; role_color?: string | null }> = {};
    if (projectIds.length > 0) {
      const { data: projects } = await supabase
        .from('projects')
        .select('id, name, framework')
        .in('id', projectIds);

      projects?.forEach((p: any) => {
        projectsMap[p.id] = { name: p.name, framework: p.framework ?? null };
      });
    }

    if (userIds.length > 0) {
      // Get user profiles (including avatar for display)
      const { data: profiles } = await supabase
        .from('user_profiles')
        .select('user_id, full_name, avatar_url')
        .in('user_id', userIds);

      // Get auth user details (email, metadata) - fetch only requesters, not all users
      const authUserResults = await Promise.all(
        userIds.map((uid) => supabase.auth.admin.getUserById(uid))
      );
      const authUserMap = new Map(
        authUserResults
          .filter((r) => r.data?.user)
          .map((r) => [(r.data as any).user.id, (r.data as any).user])
      );

      // Get organization roles for requesters
      const { data: orgMembers } = await supabase
        .from('organization_members')
        .select('user_id, role')
        .eq('organization_id', id)
        .in('user_id', userIds);

      const uniqueRoles = [...new Set((orgMembers || []).map((m: any) => m.role).filter(Boolean))];
      let roleInfoMap: Record<string, { display_name: string | null; color: string | null }> = {};
      if (uniqueRoles.length > 0) {
        const { data: roles } = await supabase
          .from('organization_roles')
          .select('name, display_name, color')
          .eq('organization_id', id)
          .in('name', uniqueRoles);
        roles?.forEach((r: any) => {
          roleInfoMap[r.name] = { display_name: r.display_name ?? null, color: r.color ?? null };
        });
      }

      const memberRoleMap: Record<string, string> = {};
      orgMembers?.forEach((m: any) => {
        memberRoleMap[m.user_id] = m.role;
      });

      userIds.forEach(uid => {
        const profile = profiles?.find((p: any) => p.user_id === uid);
        const authUser = authUserMap.get(uid);
        const fullName = profile?.full_name
          || (authUser?.user_metadata as any)?.full_name
          || (authUser?.user_metadata as any)?.name
          || (authUser?.user_metadata as any)?.user_name
          || (authUser?.user_metadata as any)?.preferred_username
          || (authUser?.email ? authUser.email.split('@')[0] : null);
        const role = memberRoleMap[uid];
        const roleInfo = role ? roleInfoMap[role] : undefined;
        usersMap[uid] = {
          email: authUser?.email || '',
          full_name: fullName || null,
          avatar_url: profile?.avatar_url ?? (authUser?.user_metadata as any)?.avatar_url ?? (authUser?.user_metadata as any)?.picture ?? null,
          role: role || undefined,
          role_display_name: roleInfo?.display_name ?? null,
          role_color: roleInfo?.color ?? null,
        };
      });
    }

    // Enrich exceptions with project and user info
    const enrichedExceptions = (exceptions || []).map((exception: any) => {
      const proj = projectsMap[exception.project_id];
      const requesterData = usersMap[exception.requested_by];
      return {
        ...exception,
        project_name: proj?.name || 'Unknown Project',
        project_framework: proj?.framework ?? null,
        requester: requesterData || { email: '', full_name: null, avatar_url: null },
      };
    });

    res.json(enrichedExceptions);
  } catch (error: any) {
    console.error('Error fetching policy exceptions:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch policy exceptions' });
  }
});

// PUT /api/organizations/:id/policy-exceptions/:exceptionId - Accept/reject exception
router.put('/:id/policy-exceptions/:exceptionId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, exceptionId } = req.params;
    const { status } = req.body;

    if (!status || !['accepted', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Status must be "accepted" or "rejected"' });
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

    // Check for manage_compliance permission
    const { data: roleData } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    const canEditPolicies = membership.role === 'owner' ||
      membership.role === 'admin' ||
      roleData?.permissions?.manage_compliance === true;

    if (!canEditPolicies) {
      return res.status(403).json({ error: 'You do not have permission to review policy exceptions' });
    }

    // Get the exception
    const { data: exception, error: exceptionError } = await supabase
      .from('project_policy_exceptions')
      .select('*, projects!inner(name)')
      .eq('id', exceptionId)
      .eq('organization_id', id)
      .single();

    if (exceptionError || !exception) {
      return res.status(404).json({ error: 'Exception not found' });
    }

    if (exception.status !== 'pending') {
      return res.status(400).json({ error: 'Exception has already been reviewed' });
    }

    // Update exception status
    const { data: updatedException, error: updateError } = await supabase
      .from('project_policy_exceptions')
      .update({
        status,
        reviewed_by: userId,
        reviewed_at: new Date().toISOString(),
      })
      .eq('id', exceptionId)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: status === 'accepted' ? 'policy_exception_accepted' : 'policy_exception_rejected',
      description: `${status} policy exception for project "${(exception as any).projects?.name}"`,
      metadata: {
        project_id: exception.project_id,
        project_name: (exception as any).projects?.name,
        exception_id: exceptionId,
        additional_licenses: exception.additional_licenses || [],
      },
    });

    // Recalculate project compliance after exception status change
    await updateProjectCompliance(id, exception.project_id);

    res.json(updatedException);
  } catch (error: any) {
    console.error('Error updating policy exception:', error);
    res.status(500).json({ error: error.message || 'Failed to update policy exception' });
  }
});

// PUT /api/organizations/:id/policy-exceptions/:exceptionId/revoke - Revoke an accepted exception
router.put('/:id/policy-exceptions/:exceptionId/revoke', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, exceptionId } = req.params;

    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: roleData } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    const canEditPolicies = membership.role === 'owner' ||
      membership.role === 'admin' ||
      roleData?.permissions?.manage_compliance === true;

    if (!canEditPolicies) {
      return res.status(403).json({ error: 'You do not have permission to revoke policy exceptions' });
    }

    const { data: exception, error: exceptionError } = await supabase
      .from('project_policy_exceptions')
      .select('*, projects!inner(name)')
      .eq('id', exceptionId)
      .eq('organization_id', id)
      .single();

    if (exceptionError || !exception) {
      return res.status(404).json({ error: 'Exception not found' });
    }

    if (exception.status !== 'accepted') {
      return res.status(400).json({ error: 'Only accepted exceptions can be revoked' });
    }

    const { data: updatedException, error: updateError } = await supabase
      .from('project_policy_exceptions')
      .update({
        status: 'revoked',
        revoked_by: userId,
        revoked_at: new Date().toISOString(),
      })
      .eq('id', exceptionId)
      .select()
      .single();

    if (updateError) {
      throw updateError;
    }

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'policy_exception_revoked',
      description: `revoked policy exception for project "${(exception as any).projects?.name}"`,
      metadata: {
        project_id: exception.project_id,
        project_name: (exception as any).projects?.name,
        exception_id: exceptionId,
      },
    });

    await updateProjectCompliance(id, exception.project_id);

    res.json(updatedException);
  } catch (error: any) {
    console.error('Error revoking policy exception:', error);
    res.status(500).json({ error: error.message || 'Failed to revoke policy exception' });
  }
});

// DELETE /api/organizations/:id/policy-exceptions/:exceptionId - Cancel/remove exception (pending only)
router.delete('/:id/policy-exceptions/:exceptionId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, exceptionId } = req.params;

    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', id)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    const { data: roleData } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', id)
      .eq('name', membership.role)
      .single();

    const canEditPolicies = membership.role === 'owner' ||
      membership.role === 'admin' ||
      roleData?.permissions?.manage_compliance === true;

    const { data: exception } = await supabase
      .from('project_policy_exceptions')
      .select('*, projects!inner(name)')
      .eq('id', exceptionId)
      .eq('organization_id', id)
      .single();

    if (!exception) {
      return res.status(404).json({ error: 'Exception not found' });
    }

    // Only pending exceptions can be cancelled; requester or org admin/owner may delete
    if (exception.status !== 'pending') {
      return res.status(400).json({ error: 'Only pending exception requests can be cancelled' });
    }

    const isRequester = exception.requested_by === userId;
    if (!isRequester && !canEditPolicies) {
      return res.status(403).json({ error: 'You do not have permission to remove this policy exception' });
    }

    const { error: deleteError } = await supabase
      .from('project_policy_exceptions')
      .delete()
      .eq('id', exceptionId)
      .eq('organization_id', id);

    if (deleteError) {
      throw deleteError;
    }

    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'policy_exception_removed',
      description: `removed policy exception for project "${(exception as any).projects?.name}"`,
      metadata: {
        project_id: exception.project_id,
        project_name: (exception as any).projects?.name,
        exception_id: exceptionId,
      },
    });

    res.json({ message: 'Exception removed successfully' });
  } catch (error: any) {
    console.error('Error removing policy exception:', error);
    res.status(500).json({ error: error.message || 'Failed to remove policy exception' });
  }
});

// GET /api/organizations/:id/projects/:projectId/teams - Get owner team and contributing teams
router.get('/:id/projects/:projectId/teams', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Get all project teams with is_owner flag
    const { data: projectTeams, error: teamsError } = await supabase
      .from('project_teams')
      .select(`
        id,
        team_id,
        is_owner,
        created_at,
        teams:team_id (
          id,
          name,
          description,
          avatar_url
        )
      `)
      .eq('project_id', projectId);

    if (teamsError) {
      throw teamsError;
    }

    // Separate owner and contributing teams
    const ownerTeam = projectTeams?.find((pt: any) => pt.is_owner)?.teams || null;
    const contributingTeams = projectTeams
      ?.filter((pt: any) => !pt.is_owner)
      .map((pt: any) => ({
        ...pt.teams,
        added_at: pt.created_at,
      })) || [];

    res.json({
      owner_team: ownerTeam,
      contributing_teams: contributingTeams,
    });
  } catch (error: any) {
    console.error('Error fetching project teams:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project teams' });
  }
});

// POST /api/organizations/:id/projects/:projectId/contributing-teams - Add a contributing team
router.post('/:id/projects/:projectId/contributing-teams', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { team_id } = req.body;

    if (!team_id) {
      return res.status(400).json({ error: 'team_id is required' });
    }

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if user has permission to manage project teams
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'You do not have permission to manage project teams' });
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Verify team exists and belongs to org
    const { data: team, error: teamError } = await supabase
      .from('teams')
      .select('id, name, description, avatar_url')
      .eq('id', team_id)
      .eq('organization_id', id)
      .single();

    if (teamError || !team) {
      return res.status(404).json({ error: 'Team not found' });
    }

    // Check if team is already associated with the project
    const { data: existingAssoc } = await supabase
      .from('project_teams')
      .select('id, is_owner')
      .eq('project_id', projectId)
      .eq('team_id', team_id)
      .single();

    if (existingAssoc) {
      if (existingAssoc.is_owner) {
        return res.status(400).json({ error: 'This team is already the owner of this project' });
      }
      return res.status(400).json({ error: 'This team already has access to this project' });
    }

    // Add team as a contributing team (is_owner = false)
    const { data: newAssoc, error: insertError } = await supabase
      .from('project_teams')
      .insert({
        project_id: projectId,
        team_id: team_id,
        is_owner: false,
      })
      .select()
      .single();

    if (insertError) {
      throw insertError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'project_team_added',
      description: `added team "${team.name}" as contributor to project "${project.name}"`,
      metadata: {
        project_id: projectId,
        project_name: project.name,
        team_id: team_id,
        team_name: team.name,
      },
    });

    res.status(201).json({
      id: team.id,
      name: team.name,
      description: team.description,
      avatar_url: team.avatar_url,
      added_at: newAssoc.created_at,
    });
  } catch (error: any) {
    console.error('Error adding contributing team:', error);
    res.status(500).json({ error: error.message || 'Failed to add contributing team' });
  }
});

// POST /api/organizations/:id/projects/:projectId/transfer-ownership - Transfer project ownership to another team
router.post('/:id/projects/:projectId/transfer-ownership', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { new_owner_team_id } = req.body;

    if (!new_owner_team_id) {
      return res.status(400).json({ error: 'new_owner_team_id is required' });
    }

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if user has permission to transfer project ownership
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'You do not have permission to transfer project ownership' });
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Verify new owner team exists and belongs to org
    const { data: newOwnerTeam, error: teamError } = await supabase
      .from('teams')
      .select('id, name, description, avatar_url')
      .eq('id', new_owner_team_id)
      .eq('organization_id', id)
      .single();

    if (teamError || !newOwnerTeam) {
      return res.status(404).json({ error: 'New owner team not found' });
    }

    // Get current owner team
    const { data: currentOwnerAssoc } = await supabase
      .from('project_teams')
      .select('id, team_id')
      .eq('project_id', projectId)
      .eq('is_owner', true)
      .single();

    // Check if new owner is already the owner
    if (currentOwnerAssoc && currentOwnerAssoc.team_id === new_owner_team_id) {
      return res.status(400).json({ error: 'This team is already the owner of this project' });
    }

    // Get current owner team info for activity log
    let oldOwnerTeamName = 'Unknown';
    if (currentOwnerAssoc) {
      const { data: oldOwnerTeam } = await supabase
        .from('teams')
        .select('name')
        .eq('id', currentOwnerAssoc.team_id)
        .single();
      oldOwnerTeamName = oldOwnerTeam?.name || 'Unknown';
    }

    // Check if new owner team is already a contributor
    const { data: newOwnerExistingAssoc } = await supabase
      .from('project_teams')
      .select('id')
      .eq('project_id', projectId)
      .eq('team_id', new_owner_team_id)
      .single();

    // Transaction: Update ownership
    // 1. Demote current owner to contributor (set is_owner = false)
    if (currentOwnerAssoc) {
      const { error: demoteError } = await supabase
        .from('project_teams')
        .update({ is_owner: false })
        .eq('id', currentOwnerAssoc.id);

      if (demoteError) {
        throw demoteError;
      }
    }

    // 2. If new owner was already a contributor, update to owner; otherwise insert as owner
    if (newOwnerExistingAssoc) {
      const { error: promoteError } = await supabase
        .from('project_teams')
        .update({ is_owner: true })
        .eq('id', newOwnerExistingAssoc.id);

      if (promoteError) {
        throw promoteError;
      }
    } else {
      const { error: insertError } = await supabase
        .from('project_teams')
        .insert({
          project_id: projectId,
          team_id: new_owner_team_id,
          is_owner: true,
        });

      if (insertError) {
        throw insertError;
      }
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'project_ownership_transferred',
      description: `transferred project "${project.name}" ownership from "${oldOwnerTeamName}" to "${newOwnerTeam.name}"`,
      metadata: {
        project_id: projectId,
        project_name: project.name,
        old_owner_team_id: currentOwnerAssoc?.team_id,
        old_owner_team_name: oldOwnerTeamName,
        new_owner_team_id: new_owner_team_id,
        new_owner_team_name: newOwnerTeam.name,
      },
    });

    res.json({
      message: 'Project ownership transferred successfully',
      owner_team: {
        id: newOwnerTeam.id,
        name: newOwnerTeam.name,
        description: newOwnerTeam.description,
        avatar_url: newOwnerTeam.avatar_url,
      },
    });
  } catch (error: any) {
    console.error('Error transferring project ownership:', error);
    res.status(500).json({ error: error.message || 'Failed to transfer project ownership' });
  }
});

// DELETE /api/organizations/:id/projects/:projectId/contributing-teams/:teamId - Remove a contributing team
router.delete('/:id/projects/:projectId/contributing-teams/:teamId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, teamId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if user has permission to manage project teams
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'You do not have permission to manage project teams' });
    }

    // Verify project exists
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Check if team association exists and is not the owner
    const { data: assoc, error: assocError } = await supabase
      .from('project_teams')
      .select('id, is_owner')
      .eq('project_id', projectId)
      .eq('team_id', teamId)
      .single();

    if (assocError || !assoc) {
      return res.status(404).json({ error: 'Team is not associated with this project' });
    }

    if (assoc.is_owner) {
      return res.status(400).json({ error: 'Cannot remove the owner team. Use transfer ownership instead.' });
    }

    // Get team info for activity log
    const { data: team } = await supabase
      .from('teams')
      .select('name')
      .eq('id', teamId)
      .single();

    // Remove the association
    const { error: deleteError } = await supabase
      .from('project_teams')
      .delete()
      .eq('project_id', projectId)
      .eq('team_id', teamId);

    if (deleteError) {
      throw deleteError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'project_team_removed',
      description: `removed team "${team?.name || 'Unknown'}" from project "${project.name}"`,
      metadata: {
        project_id: projectId,
        project_name: project.name,
        team_id: teamId,
        team_name: team?.name,
      },
    });

    res.json({ message: 'Contributing team removed successfully' });
  } catch (error: any) {
    console.error('Error removing contributing team:', error);
    res.status(500).json({ error: error.message || 'Failed to remove contributing team' });
  }
});

// GET /api/organizations/:id/projects/:projectId/pr-guardrails - Get PR guardrails settings
router.get('/:id/projects/:projectId/pr-guardrails', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Get PR guardrails for this project
    const { data: guardrails, error: guardrailsError } = await supabase
      .from('project_pr_guardrails')
      .select('*')
      .eq('project_id', projectId)
      .single();

    if (guardrailsError && guardrailsError.code !== 'PGRST116') {
      // PGRST116 is "not found" which is fine - means no guardrails configured yet
      throw guardrailsError;
    }

    // Return default values if no guardrails exist
    if (!guardrails) {
      return res.json({
        project_id: projectId,
        block_critical_vulns: false,
        block_high_vulns: false,
        block_medium_vulns: false,
        block_low_vulns: false,
        block_policy_violations: false,
        block_transitive_vulns: false,
      });
    }

    res.json(guardrails);
  } catch (error: any) {
    console.error('Error fetching PR guardrails:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch PR guardrails' });
  }
});

// PUT /api/organizations/:id/projects/:projectId/pr-guardrails - Update PR guardrails settings
router.put('/:id/projects/:projectId/pr-guardrails', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const {
      block_critical_vulns,
      block_high_vulns,
      block_medium_vulns,
      block_low_vulns,
      block_policy_violations,
      block_transitive_vulns,
    } = req.body;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Check if user has permission to edit project settings
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;

    if (!isOrgOwner && !hasOrgPermission) {
      // Check project-level permission
      if (accessCheck.projectMembership?.role_id) {
        const { data: projectRole } = await supabase
          .from('project_roles')
          .select('permissions')
          .eq('id', accessCheck.projectMembership.role_id)
          .single();

        if (!projectRole?.permissions?.edit_settings) {
          return res.status(403).json({ error: 'You do not have permission to edit project settings' });
        }
      } else {
        return res.status(403).json({ error: 'You do not have permission to edit project settings' });
      }
    }

    // Verify project exists and belongs to org
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .select('id, name')
      .eq('id', projectId)
      .eq('organization_id', id)
      .single();

    if (projectError || !project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Prepare the update data
    const guardrailsData = {
      project_id: projectId,
      block_critical_vulns: block_critical_vulns ?? false,
      block_high_vulns: block_high_vulns ?? false,
      block_medium_vulns: block_medium_vulns ?? false,
      block_low_vulns: block_low_vulns ?? false,
      block_policy_violations: block_policy_violations ?? false,
      block_transitive_vulns: block_transitive_vulns ?? false,
    };

    // Upsert the guardrails
    const { data: guardrails, error: upsertError } = await supabase
      .from('project_pr_guardrails')
      .upsert(guardrailsData, {
        onConflict: 'project_id',
      })
      .select()
      .single();

    if (upsertError) {
      throw upsertError;
    }

    // Create activity log
    await createActivity({
      organization_id: id,
      user_id: userId,
      activity_type: 'pr_guardrails_updated',
      description: `updated PR guardrails for project "${project.name}"`,
      metadata: {
        project_id: projectId,
        project_name: project.name,
        guardrails: guardrailsData,
      },
    });

    res.json(guardrails);
  } catch (error: any) {
    console.error('Error updating PR guardrails:', error);
    res.status(500).json({ error: error.message || 'Failed to update PR guardrails' });
  }
});

// GET /api/organizations/:id/projects/:projectId/repositories - List repos from all connected providers + connected status
router.get('/:id/projects/:projectId/repositories', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { integration_id } = req.query as { integration_id?: string };

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: repoRecord } = await supabase
      .from('project_repositories')
      .select('*')
      .eq('project_id', projectId)
      .single();

    const GIT_PROVIDERS = ['github', 'gitlab', 'bitbucket'] as const;
    let integrations: OrgIntegration[];
    if (integration_id) {
      const single = await getIntegrationById(id, integration_id);
      integrations = single && GIT_PROVIDERS.includes(single.provider as any) ? [single] : [];
    } else {
      integrations = await getOrgIntegrations(id);
    }

    if (integrations.length === 0) {
      return res.status(400).json({ error: 'No source code integrations connected for this organization' });
    }

    const allRepos: Array<{
      id: number;
      full_name: string;
      default_branch: string;
      private: boolean;
      framework: string;
      ecosystem: string;
      provider: string;
      integration_id: string;
      display_name: string;
    }> = [];

    for (const integ of integrations) {
      try {
        const provider = createProvider(integ);
        const repos = await provider.listRepositories();
        const reposWithFrameworks = await Promise.all(
          repos.map(async (repo) => {
            const detected = await detectRepoFramework(provider, repo.full_name, repo.default_branch);
            return {
              id: repo.id,
              full_name: repo.full_name,
              default_branch: repo.default_branch,
              private: repo.private,
              framework: detected.framework,
              ecosystem: detected.ecosystem,
              provider: integ.provider,
              integration_id: integ.id,
              display_name: (integ as any).display_name || integ.provider,
            };
          })
        );
        allRepos.push(...reposWithFrameworks);
      } catch (err: any) {
        console.warn(`Failed to list repos from ${integ.provider} integration ${integ.id}:`, err.message);
      }
    }

    res.json({
      connectedRepository: repoRecord
        ? {
          repo_full_name: repoRecord.repo_full_name,
          default_branch: repoRecord.default_branch,
          status: repoRecord.status,
          package_json_path: (repoRecord as { package_json_path?: string }).package_json_path ?? '',
          extraction_step: (repoRecord as { extraction_step?: string }).extraction_step ?? null,
          extraction_error: (repoRecord as { extraction_error?: string }).extraction_error ?? null,
          provider: (repoRecord as any).provider ?? 'github',
          pull_request_comments_enabled: (repoRecord as { pull_request_comments_enabled?: boolean }).pull_request_comments_enabled !== false,
          connected_at: (repoRecord as { created_at?: string }).created_at ?? null,
        }
        : null,
      repositories: allRepos,
    });
  } catch (error: any) {
    console.error('Error fetching repositories:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch repositories' });
  }
});

// GET /api/organizations/:id/projects/:projectId/repositories/scan - Scan repo for monorepo / potential projects
router.get('/:id/projects/:projectId/repositories/scan', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { repo_full_name, default_branch, integration_id } = req.query as { repo_full_name?: string; default_branch?: string; integration_id?: string };

    if (!repo_full_name || !default_branch || !integration_id) {
      return res.status(400).json({ error: 'repo_full_name, default_branch, and integration_id query params are required' });
    }

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const integ = await getIntegrationById(id, integration_id);
    if (!integ) {
      return res.status(400).json({ error: 'Integration not found or not connected' });
    }

    const provider = createProvider(integ);
    const result = await detectMonorepo(provider, repo_full_name, default_branch);

    const withLinkStatus = await Promise.all(
      result.potentialProjects.map(async (p) => {
        const { data: existing } = await supabase
          .from('project_repositories')
          .select('project_id')
          .eq('repo_full_name', repo_full_name)
          .eq('package_json_path', p.path)
          .maybeSingle();

        const linkedByProjectId = existing?.project_id && existing.project_id !== projectId ? existing.project_id : null;
        return {
          name: p.name,
          path: p.path,
          ecosystem: p.ecosystem,
          isLinked: !!linkedByProjectId,
          linkedByProjectId: linkedByProjectId ?? undefined,
          linkedByProjectName: undefined as string | undefined,
        };
      })
    );

    const linkedIds = [...new Set(withLinkStatus.filter((p) => p.linkedByProjectId).map((p) => p.linkedByProjectId!))];
    let projectNames: Record<string, string> = {};
    if (linkedIds.length > 0) {
      const { data: projects } = await supabase.from('projects').select('id, name').in('id', linkedIds);
      if (projects) for (const proj of projects) projectNames[proj.id] = proj.name ?? '';
    }
    const withLinkStatusAndNames = withLinkStatus.map((p) => ({
      ...p,
      linkedByProjectName: p.linkedByProjectId ? projectNames[p.linkedByProjectId] : undefined,
    }));

    res.json({
      isMonorepo: result.isMonorepo,
      confidence: result.confidence ?? undefined,
      potentialProjects: withLinkStatusAndNames,
    });
  } catch (error: any) {
    console.error('Error scanning repository:', error);
    res.status(500).json({ error: error.message || 'Failed to scan repository' });
  }
});

// POST /api/organizations/:id/projects/:projectId/repositories/connect - Connect a repo (supports all providers)
router.post('/:id/projects/:projectId/repositories/connect', async (req: AuthRequest, res) => {
  const { id, projectId } = req.params;
  const package_json_path = typeof req.body?.package_json_path === 'string' ? req.body.package_json_path : '';
  console.log(`[EXTRACT] POST connect received: org=${id} project=${projectId} repo=${(req.body && req.body.repo_full_name) || '?'} path=${package_json_path || '(root)'}`);
  try {
    const userId = req.user!.id;
    const { repo_id, repo_full_name, default_branch, framework, ecosystem, provider: reqProvider, integration_id: reqIntegrationId } = req.body;

    if (!repo_id || !repo_full_name || !default_branch) {
      return res.status(400).json({ error: 'repo_id, repo_full_name, and default_branch are required' });
    }

    const resolvedEcosystem = ecosystem || 'npm';
    const resolvedProvider = reqProvider || 'github';

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;
    if (!isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'You do not have permission to connect repositories' });
    }

    let installationId: string;
    let integrationId: string | null = reqIntegrationId || null;

    if (reqIntegrationId) {
      const integ = await getIntegrationById(id, reqIntegrationId);
      if (!integ) {
        return res.status(400).json({ error: 'Integration not found or not connected' });
      }
      installationId = integ.installation_id || reqIntegrationId;
    } else {
      const { data: org, error: orgError } = await supabase
        .from('organizations')
        .select('github_installation_id')
        .eq('id', id)
        .single();
      if (orgError || !org?.github_installation_id) {
        return res.status(400).json({ error: 'No source code integration connected for this organization' });
      }
      installationId = org.github_installation_id;
    }

    const { data: existingLink } = await supabase
      .from('project_repositories')
      .select('project_id')
      .eq('repo_full_name', repo_full_name)
      .eq('package_json_path', package_json_path)
      .maybeSingle();

    if (existingLink && existingLink.project_id !== projectId) {
      return res.status(409).json({
        error: 'This repository and package path are already linked to another project. Each package in a repo can only be tracked by one project.',
      });
    }

    const { data: repoRecord, error: repoError } = await supabase
      .from('project_repositories')
      .upsert(
        {
          project_id: projectId,
          installation_id: installationId,
          repo_id: repo_id,
          repo_full_name: repo_full_name,
          default_branch: default_branch,
          package_json_path: package_json_path,
          ecosystem: resolvedEcosystem,
          provider: resolvedProvider,
          integration_id: integrationId,
          status: 'initializing',
          extraction_step: 'queued',
          extraction_error: null,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'project_id' }
      )
      .select('*')
      .single();

    if (repoError || !repoRecord) {
      throw repoError;
    }

    console.log(`[EXTRACT] Connect: queuing extraction job for project ${projectId}, repo ${repo_full_name} path=${package_json_path || '(root)'} ecosystem=${resolvedEcosystem} provider=${resolvedProvider}`);

    const queueResult = await queueExtractionJob(projectId, id, {
      repo_full_name: repo_full_name,
      installation_id: installationId,
      default_branch: default_branch,
      package_json_path: package_json_path,
      ecosystem: resolvedEcosystem,
      provider: resolvedProvider,
      integration_id: integrationId ?? undefined,
    });

    if (!queueResult.success) {
      await supabase
        .from('project_repositories')
        .update({
          status: 'error',
          extraction_error: queueResult.error ?? 'Failed to queue extraction job',
          updated_at: new Date().toISOString(),
        })
        .eq('project_id', projectId);
      return res.status(502).json({
        error: queueResult.error ?? 'Failed to queue extraction job. Set UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN, then run extraction-worker.',
      });
    }

    if (framework) {
      await supabase
        .from('projects')
        .update({ framework, updated_at: new Date().toISOString() })
        .eq('id', projectId)
        .eq('organization_id', id);
    }

    res.json({
      repo_full_name: repoRecord.repo_full_name,
      default_branch: repoRecord.default_branch,
      status: 'initializing',
      dependencies_count: 0,
      analyzing_count: 0,
    });
  } catch (error: any) {
    console.error('Error connecting repository:', error);
    res.status(500).json({ error: error.message || 'Failed to connect repository' });
  }
});

// PATCH /api/organizations/:id/projects/:projectId/repositories/settings - Update repository settings (e.g. pull request comments)
router.patch('/:id/projects/:projectId/repositories/settings', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const { pull_request_comments_enabled } = req.body || {};

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const hasEditSettings = accessCheck.projectPermissions?.edit_settings === true;
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;
    if (!hasEditSettings && !isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'You do not have permission to update repository settings' });
    }

    const { data: repoRecord, error: fetchError } = await supabase
      .from('project_repositories')
      .select('id')
      .eq('project_id', projectId)
      .single();

    if (fetchError || !repoRecord) {
      return res.status(404).json({ error: 'No repository connected to this project' });
    }

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (typeof pull_request_comments_enabled === 'boolean') {
      updates.pull_request_comments_enabled = pull_request_comments_enabled;
    }

    const { data: updated, error: updateError } = await supabase
      .from('project_repositories')
      .update(updates)
      .eq('project_id', projectId)
      .select('repo_full_name, default_branch, status, pull_request_comments_enabled')
      .single();

    if (updateError) {
      throw updateError;
    }

    res.json({
      repo_full_name: updated.repo_full_name,
      default_branch: updated.default_branch,
      status: updated.status,
      pull_request_comments_enabled: (updated as { pull_request_comments_enabled?: boolean }).pull_request_comments_enabled !== false,
    });
  } catch (error: any) {
    console.error('Error updating repository settings:', error);
    res.status(500).json({ error: error.message || 'Failed to update repository settings' });
  }
});

/** Fetches and enriches project dependencies from the DB. Used for cache refresh and when cache misses. */
async function fetchEnrichedDependenciesForProject(organizationId: string, projectId: string): Promise<any[]> {
  // Get project dependencies with joined dependency analysis data
    // Note: license column was removed from project_dependencies - it now comes from dependencies table
    // is_watching and watchtower_cleared_at come from organization_watchlist (org-level)
    const { data: projectDeps, error: depsError } = await supabase
      .from('project_dependencies')
      .select(`
        id,
        project_id,
        dependency_id,
        dependency_version_id,
        name,
        version,
        is_direct,
        source,
        environment,
        files_importing_count,
        created_at
      `)
      .eq('project_id', projectId)
      .order('name', { ascending: true });

    if (depsError) {
      throw depsError;
    }

    // Derive ids and helpers from projectDeps for parallel waves
    const dependencyIds = [...new Set((projectDeps || []).map((pd: any) => pd.dependency_id).filter(Boolean))];
    const dependencyVersionIds = [...new Set((projectDeps || [])
      .map((pd: any) => pd.dependency_version_id)
      .filter(Boolean))];
    const projectDepIds = (projectDeps || []).map((pd: any) => pd.id);
    const depIds = [...new Set((projectDeps || []).map((pd: any) => pd.dependency_id).filter(Boolean))];
    const namesNeedingFallback = [...new Set((projectDeps || []).map((pd: any) => pd.name).filter(Boolean))];
    const depIdKey = (id: string | null | undefined) => (id ? String(id).toLowerCase().replace(/-/g, '') : '');

    const BATCH_SIZE = 100;
    const EDGE_BATCH = 200;
    const NAME_BATCH_SIZE = 100;

    // Wave 1: run independent fetches in parallel
    const [
      watchlistResult,
      depsByIdBatches,
      dvBatches,
      edgesBatches,
      funcRowsResult,
      filePathRowsResult,
      depsByNameResult,
      projectTeamsResult,
    ] = await Promise.all([
      supabase.from('organization_watchlist').select('dependency_id, watchtower_cleared_at').eq('organization_id', organizationId),
      dependencyIds.length > 0
        ? Promise.all(
            Array.from({ length: Math.ceil(dependencyIds.length / BATCH_SIZE) }, (_, i) => {
              const batch = dependencyIds.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);
              return supabase.from('dependencies').select(`
                id, license, github_url, status, score, openssf_penalty, popularity_penalty, maintenance_penalty,
                openssf_score, openssf_data, weekly_downloads, last_published_at, releases_last_12_months, analyzed_at
              `).in('id', batch);
            })
          )
        : Promise.resolve([]),
      dependencyVersionIds.length > 0
        ? Promise.all(
            Array.from({ length: Math.ceil(dependencyVersionIds.length / BATCH_SIZE) }, (_, i) => {
              const batch = dependencyVersionIds.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);
              return supabase.from('dependency_versions').select('id, dependency_id, version, analyzed_at, dependencies(license)').in('id', batch);
            })
          )
        : Promise.resolve([]),
      dependencyVersionIds.length > 0
        ? Promise.all(
            Array.from({ length: Math.ceil(dependencyVersionIds.length / EDGE_BATCH) }, (_, i) => {
              const batch = dependencyVersionIds.slice(i * EDGE_BATCH, (i + 1) * EDGE_BATCH);
              return supabase.from('dependency_version_edges').select('parent_version_id, child_version_id').in('child_version_id', batch);
            })
          )
        : Promise.resolve([]),
      projectDepIds.length > 0
        ? supabase.from('project_dependency_functions').select('project_dependency_id, function_name').in('project_dependency_id', projectDepIds)
        : Promise.resolve({ data: null }),
      projectDepIds.length > 0
        ? supabase.from('project_dependency_files').select('project_dependency_id, file_path').in('project_dependency_id', projectDepIds).order('file_path')
        : Promise.resolve({ data: null }),
      namesNeedingFallback.length > 0
        ? supabase.from('dependencies').select('name, github_url, openssf_score, openssf_data, license, weekly_downloads, last_published_at, openssf_penalty, popularity_penalty, maintenance_penalty, releases_last_12_months, status, score, analyzed_at').in('name', namesNeedingFallback)
        : Promise.resolve({ data: null }),
      supabase.from('project_teams').select('team_id').eq('project_id', projectId),
    ]);

    const watchlistByDependencyId = new Map<string, { watchtower_cleared_at: string | null }>();
    if (watchlistResult.data) {
      watchlistResult.data.forEach((row: any) => {
        if (row.dependency_id) {
          watchlistByDependencyId.set(row.dependency_id, { watchtower_cleared_at: row.watchtower_cleared_at ?? null });
        }
      });
    }

    const analysisData = new Map<string, any>();
    for (const { data: deps } of depsByIdBatches as Array<{ data: any[] | null }>) {
      if (deps) {
        deps.forEach((d: any) => {
          const idVal = d.id != null ? String(d.id).trim() : '';
          if (!idVal) return;
          const k = depIdKey(idVal);
          analysisData.set(k, d);
          if (idVal !== k) analysisData.set(idVal, d);
        });
      }
    }

    const analysisDataByVersionId = new Map<string, any>();
    const allPairs: Array<{ dependencyId: string; version: string }> = [];
    for (const resp of dvBatches as Array<{ data: any[] | null; error: any }>) {
      if (!resp.error && resp.data) {
        resp.data.forEach((d: any) => analysisDataByVersionId.set(d.id, d));
        const pairs = (resp.data as any[]).map((d: any) => ({ dependencyId: d.dependency_id, version: d.version })).filter((p: any) => p.dependencyId && p.version);
        allPairs.push(...pairs);
      }
    }

    let vulnCountsByKey = new Map<string, VulnCounts>();
    if (allPairs.length > 0) {
      vulnCountsByKey = await getVulnCountsBatch(supabase, allPairs);
    }

    const projectVersionIdSet = new Set(dependencyVersionIds);
    const childToParentVersionId = new Map<string, string>();
    for (const resp of edgesBatches as Array<{ data: any[] | null; error: any }>) {
      if (!resp.error && resp.data?.length) {
        for (const e of resp.data as any[]) {
          const pid = e.parent_version_id;
          const cid = e.child_version_id;
          if (projectVersionIdSet.has(pid) && !childToParentVersionId.has(cid)) {
            childToParentVersionId.set(cid, pid);
          }
        }
      }
    }

    const importedFunctionsByDepId = new Map<string, string[]>();
    if (funcRowsResult.data) {
      funcRowsResult.data.forEach((row: any) => {
        const list = importedFunctionsByDepId.get(row.project_dependency_id) || [];
        list.push(row.function_name);
        importedFunctionsByDepId.set(row.project_dependency_id, list);
      });
    }

    const importedFilePathsByDepId = new Map<string, string[]>();
    if (filePathRowsResult.data) {
      filePathRowsResult.data.forEach((row: any) => {
        const list = importedFilePathsByDepId.get(row.project_dependency_id) || [];
        list.push(row.file_path);
        importedFilePathsByDepId.set(row.project_dependency_id, list);
      });
    }

    const githubUrlByName = new Map<string, string>();
    const dependencyByNameFallback = new Map<string, { openssf_score: number | null; openssf_data: any; github_url: string | null; license: string | null; weekly_downloads: number | null; last_published_at: string | null; openssf_penalty?: number; popularity_penalty?: number; maintenance_penalty?: number; releases_last_12_months?: number | null; status?: string; score?: number | null; analyzed_at?: string | null }>();
    if (depsByNameResult.data) {
      depsByNameResult.data.forEach((d: any) => {
        if (d.name) {
          if (d.github_url) githubUrlByName.set(d.name, d.github_url);
          dependencyByNameFallback.set(d.name, d);
          dependencyByNameFallback.set((d.name as string).toLowerCase(), d);
        }
      });
    }

    const teamIds = (projectTeamsResult.data ?? []).map((t: any) => t.team_id).filter(Boolean);

    const versionDependencyIds = [...new Set(
      (projectDeps || [])
        .map((pd: any) => (pd.dependency_version_id ? analysisDataByVersionId.get(pd.dependency_version_id)?.dependency_id : null))
        .filter((id: any) => id != null && String(id).trim() !== '')
    )];
    const namesMissingScore = [...new Set((projectDeps || []).filter((pd: any) => {
      const row = pd.dependency_id ? analysisData.get(depIdKey(pd.dependency_id)) : null;
      return pd.name && (!row || (row.openssf_score == null && row.weekly_downloads == null && row.last_published_at == null));
    }).map((pd: any) => pd.name))];

    const allNamesForScore = namesMissingScore.length > 0
      ? [...new Set([...namesMissingScore, ...namesMissingScore.filter((n: string) => n.startsWith('@')).map((n: string) => n.replace(/^@/, ''))])]
      : [];

    // Wave 2: score fallback, versionDependencyIds deps, deprecations, banned
    const [
      scoreFallbackBatches,
      versionDepsBatches,
      orgDepRowsResult,
      teamDepRowsResult,
      orgBansResult,
      teamBansResult,
    ] = await Promise.all([
      allNamesForScore.length > 0
        ? Promise.all(
            Array.from({ length: Math.ceil(allNamesForScore.length / NAME_BATCH_SIZE) }, (_, i) => {
              const batch = allNamesForScore.slice(i * NAME_BATCH_SIZE, (i + 1) * NAME_BATCH_SIZE);
              if (batch.length === 0) return Promise.resolve({ data: null });
              const orFilter = batch.map((n: string) => `name.ilike.${n.replace(/,/g, '\\,')}`).join(',');
              return supabase.from('dependencies').select('name, openssf_score, openssf_data, weekly_downloads, last_published_at, openssf_penalty, popularity_penalty, maintenance_penalty, releases_last_12_months, status, score, analyzed_at').or(orFilter);
            })
          )
        : Promise.resolve([]),
      versionDependencyIds.length > 0
        ? Promise.all(
            Array.from({ length: Math.ceil(versionDependencyIds.length / BATCH_SIZE) }, (_, i) => {
              const batch = versionDependencyIds.slice(i * BATCH_SIZE, (i + 1) * BATCH_SIZE);
              return supabase.from('dependencies').select(`
                id, license, github_url, status, score, openssf_penalty, popularity_penalty, maintenance_penalty,
                openssf_score, openssf_data, weekly_downloads, last_published_at, releases_last_12_months, analyzed_at
              `).in('id', batch);
            })
          )
        : Promise.resolve([]),
      depIds.length > 0 ? supabase.from('organization_deprecations').select('dependency_id, recommended_alternative, deprecated_by, created_at').eq('organization_id', organizationId).in('dependency_id', depIds) : Promise.resolve({ data: null }),
      depIds.length > 0 && teamIds.length > 0 ? supabase.from('team_deprecations').select('dependency_id, team_id, recommended_alternative, deprecated_by, created_at').in('team_id', teamIds).in('dependency_id', depIds) : Promise.resolve({ data: null }),
      depIds.length > 0 ? supabase.from('banned_versions').select('dependency_id, banned_version').eq('organization_id', organizationId).in('dependency_id', depIds) : Promise.resolve({ data: null }),
      depIds.length > 0 && teamIds.length > 0 ? supabase.from('team_banned_versions').select('dependency_id, banned_version').in('team_id', teamIds).in('dependency_id', depIds) : Promise.resolve({ data: null }),
    ]);

    const scoreFallbackByName = new Map<string, { openssf_score: number | null; openssf_data: any; weekly_downloads: number | null; last_published_at: string | null; openssf_penalty?: number; popularity_penalty?: number; maintenance_penalty?: number; releases_last_12_months?: number | null; status?: string; score?: number | null; analyzed_at?: string | null }>();
    for (const resp of scoreFallbackBatches as Array<{ data: any[] | null }>) {
      if (resp.data) {
        const withScore = resp.data.filter((r: any) => r.openssf_score != null || r.weekly_downloads != null || r.last_published_at != null);
        withScore.forEach((r: any) => {
          if (r.name) {
            if (!scoreFallbackByName.has(r.name)) scoreFallbackByName.set(r.name, r);
            const keyLower = r.name.toLowerCase();
            if (!scoreFallbackByName.has(keyLower)) scoreFallbackByName.set(keyLower, r);
          }
        });
      }
    }
    namesMissingScore.filter((n: string) => n.startsWith('@')).forEach((n: string) => {
      const unscoped = n.replace(/^@/, '');
      if (scoreFallbackByName.has(unscoped) && !scoreFallbackByName.has(n)) scoreFallbackByName.set(n, scoreFallbackByName.get(unscoped)!);
    });

    (versionDepsBatches as Array<{ data: any[] | null; error: any }>).forEach((resp, batchIndex) => {
      if (!resp.error && resp.data) {
        const deps = resp.data as any[];
        const batch = versionDependencyIds.slice(batchIndex * BATCH_SIZE, (batchIndex + 1) * BATCH_SIZE);
        for (const requestedId of batch) {
          const rid = String(requestedId).trim();
          const dep = deps.find((d: any) => {
            const did = d.id != null ? String(d.id).trim() : '';
            return did === rid || depIdKey(did) === depIdKey(rid);
          });
          if (dep) {
            analysisData.set(rid, dep);
            analysisData.set(depIdKey(rid), dep);
          }
        }
      }
    });

    const deprecationByDependencyId = new Map<string, { recommended_alternative: string; deprecated_by: string | null; created_at: string; scope: 'organization' | 'team'; team_id?: string }>();
    if (orgDepRowsResult.data) {
      orgDepRowsResult.data.forEach((row: any) => {
        if (row.dependency_id) {
          deprecationByDependencyId.set(row.dependency_id, {
            recommended_alternative: row.recommended_alternative ?? '',
            deprecated_by: row.deprecated_by ?? null,
            created_at: row.created_at,
            scope: 'organization',
          });
        }
      });
    }
    if (teamDepRowsResult.data) {
      teamDepRowsResult.data.forEach((row: any) => {
        if (row.dependency_id && !deprecationByDependencyId.has(row.dependency_id)) {
          deprecationByDependencyId.set(row.dependency_id, {
            recommended_alternative: row.recommended_alternative ?? '',
            deprecated_by: row.deprecated_by ?? null,
            created_at: row.created_at,
            scope: 'team',
            team_id: row.team_id,
          });
        }
      });
    }

    const bannedKeySet = new Set<string>();
    if (orgBansResult.data) {
      (orgBansResult.data as any[]).forEach((r: any) => {
        if (r.dependency_id && r.banned_version) bannedKeySet.add(`${r.dependency_id}|${r.banned_version}`);
      });
    }
    if (teamBansResult.data) {
      (teamBansResult.data as any[]).forEach((r: any) => {
        if (r.dependency_id && r.banned_version) bannedKeySet.add(`${r.dependency_id}|${r.banned_version}`);
      });
    }

    const versionIdToNameVersion = new Map<string, { name: string; version: string }>();
    (projectDeps || []).forEach((pd: any) => {
      if (pd.dependency_version_id && pd.name != null && pd.version != null) {
        versionIdToNameVersion.set(pd.dependency_version_id, { name: pd.name, version: pd.version });
      }
    });

    // Merge project dependencies with analysis data.
    // Score + status come from dependencies table (package-level reputation score).
    // Vuln counts come from dependency_versions (version-specific).
    // openssf_score/weekly_downloads/last_published: from dependencies; fallback by name.
    const enrichedDeps = (projectDeps || []).map((pd: any) => {
      const versionAnalysis = pd.dependency_version_id ? analysisDataByVersionId.get(pd.dependency_version_id) : null;
      const rawDepId = versionAnalysis?.dependency_id ?? (versionAnalysis as any)?.dependencyId;
      const depIdFromVersion = rawDepId != null ? String(rawDepId).trim() : null;
      const packageAnalysisFromVersion = depIdFromVersion
        ? (analysisData.get(depIdFromVersion) ?? analysisData.get(depIdKey(depIdFromVersion)) ?? null)
        : null;
      // License from joined dependencies row: dependency_versions JOIN dependencies on dependency_id
      const depRow = versionAnalysis?.dependencies;
      const licenseFromJoin = depRow != null ? (Array.isArray(depRow) ? depRow[0]?.license : depRow?.license) : null;
      const packageAnalysis = pd.dependency_id
        ? (analysisData.get(depIdKey(pd.dependency_id)) ?? analysisData.get(String(pd.dependency_id).trim()) ?? null)
        : null;
      // Prefer the dependency row that the version references
      const effectivePackageAnalysis = packageAnalysisFromVersion || packageAnalysis;
      const scoreFallback = scoreFallbackByName.get(pd.name) ?? scoreFallbackByName.get((pd.name || '').toLowerCase()) ?? null;
      const byNameRow = dependencyByNameFallback.get(pd.name) ?? dependencyByNameFallback.get((pd.name || '').toLowerCase()) ?? null;
      const githubFromAnalysis = effectivePackageAnalysis?.github_url || null;
      const githubFromFallback = githubUrlByName.get(pd.name) || null;
      const watchlistRow = pd.dependency_id ? watchlistByDependencyId.get(pd.dependency_id) : null;
      // Score and status come from dependencies (package-level), not dependency_versions
      const status = effectivePackageAnalysis?.status ?? byNameRow?.status ?? 'pending';
      const score = effectivePackageAnalysis?.score ?? byNameRow?.score ?? null;
      // Vuln counts derived from dependency_vulnerabilities (version-specific)
      const versionKey = (versionAnalysis?.dependency_id && versionAnalysis?.version) ? `${versionAnalysis.dependency_id}\t${versionAnalysis.version}` : '';
      const derivedCounts = versionKey ? (vulnCountsByKey.get(versionKey) ?? { critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0 }) : { critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0 };
      const critical_vulns = derivedCounts.critical_vulns;
      const high_vulns = derivedCounts.high_vulns;
      const medium_vulns = derivedCounts.medium_vulns;
      const low_vulns = derivedCounts.low_vulns;
      const analyzed_at = effectivePackageAnalysis?.analyzed_at ?? byNameRow?.analyzed_at ?? null;
      const sourceForScore = (effectivePackageAnalysis?.openssf_score != null || effectivePackageAnalysis?.weekly_downloads != null || effectivePackageAnalysis?.last_published_at != null) ? effectivePackageAnalysis : (scoreFallback?.openssf_score != null ? scoreFallback : byNameRow);
      const analysis = effectivePackageAnalysis || versionAnalysis || sourceForScore ? {
        status,
        score,
        score_breakdown: (effectivePackageAnalysis || scoreFallback || byNameRow) ? {
          openssf_penalty: (effectivePackageAnalysis || scoreFallback || byNameRow)?.openssf_penalty,
          popularity_penalty: (effectivePackageAnalysis || scoreFallback || byNameRow)?.popularity_penalty,
          maintenance_penalty: (effectivePackageAnalysis || scoreFallback || byNameRow)?.maintenance_penalty,
        } : undefined,
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
        openssf_score: (sourceForScore?.openssf_score ?? effectivePackageAnalysis?.openssf_score ?? byNameRow?.openssf_score) ?? null,
        openssf_data: sourceForScore?.openssf_data ?? effectivePackageAnalysis?.openssf_data ?? byNameRow?.openssf_data ?? null,
        weekly_downloads: (sourceForScore?.weekly_downloads ?? effectivePackageAnalysis?.weekly_downloads ?? byNameRow?.weekly_downloads) ?? null,
        last_published_at: (sourceForScore?.last_published_at ?? effectivePackageAnalysis?.last_published_at ?? byNameRow?.last_published_at) ?? null,
        releases_last_12_months: (sourceForScore?.releases_last_12_months ?? effectivePackageAnalysis?.releases_last_12_months ?? byNameRow?.releases_last_12_months) ?? null,
        analyzed_at,
      } : null;
      const parentVersionId = !pd.is_direct && pd.dependency_version_id
        ? childToParentVersionId.get(pd.dependency_version_id)
        : null;
      const parentInfo = parentVersionId ? versionIdToNameVersion.get(parentVersionId) : null;
      const parent_package = parentInfo ? `${parentInfo.name}@${parentInfo.version}` : null;

      const effectiveDepIdForBan = pd.dependency_id || depIdFromVersion;
      const isBannedComputed = !!(effectiveDepIdForBan && pd.version && bannedKeySet.has(`${effectiveDepIdForBan}|${pd.version}`));

      const out = {
        ...pd,
        is_watching: !!watchlistRow,
        watchtower_cleared_at: watchlistRow?.watchtower_cleared_at ?? null,
        license: licenseFromJoin ?? null,
        github_url: githubFromAnalysis || githubFromFallback || null,
        imported_functions: importedFunctionsByDepId.get(pd.id) || [],
        imported_file_paths: importedFilePathsByDepId.get(pd.id) ?? [],
        analysis,
        deprecation: (pd.dependency_id ? deprecationByDependencyId.get(pd.dependency_id) : null) ?? null,
        parent_package,
        is_current_version_banned: isBannedComputed,
      };
      return out;
    });

  return enrichedDeps;
}

// GET /api/organizations/:id/projects/:projectId/dependencies - List dependencies with analysis data
// Query: cached_only=true -> return only cached list (no DB); empty array if miss. Frontend uses this for fast first paint, then a second request (no param) gets fresh DB data and replaces.
router.get('/:id/projects/:projectId/dependencies', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const depsCacheKey = getDependenciesCacheKey(id, projectId);
    const cachedOnly = req.query.cached_only === 'true';

    if (cachedOnly) {
      const cachedDeps = await getCached<any[]>(depsCacheKey);
      return res.json(cachedDeps ?? []);
    }

    const bypassCache = req.query.refresh === 'true' || req.query.bypass_cache === 'true';
    if (bypassCache) {
      await invalidateDependenciesCache(id, projectId);
    }

    const enrichedDeps = await fetchEnrichedDependenciesForProject(id, projectId);
    await setCached(depsCacheKey, enrichedDeps, CACHE_TTL_SECONDS.DEPENDENCIES).catch((err: any) => {
      console.warn('[Cache] Failed to set dependencies cache:', err?.message);
    });
    res.json(enrichedDeps);
  } catch (error: any) {
    console.error('Error fetching project dependencies:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project dependencies' });
  }
});

// GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/overview - Get dependency name for overview (project_dependency -> dependency_version_id -> dependency_id -> dependencies.name)
router.get('/:id/projects/:projectId/dependencies/:projectDependencyId/overview', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: pd, error: pdError } = await supabase
      .from('project_dependencies')
      .select('dependency_version_id, files_importing_count, ai_usage_summary, ai_usage_analyzed_at')
      .eq('id', projectDependencyId)
      .eq('project_id', projectId)
      .single();

    if (pdError || !pd) {
      return res.status(404).json({ error: 'Project dependency not found' });
    }

    const dependencyVersionId = (pd as any).dependency_version_id;
    const filesImportingCount = (pd as any).files_importing_count ?? 0;
    const aiUsageSummary = (pd as any).ai_usage_summary ?? null;
    const aiUsageAnalyzedAt = (pd as any).ai_usage_analyzed_at ?? null;

    const [functionsResult, filesResult] = await Promise.all([
      supabase.from('project_dependency_functions').select('function_name').eq('project_dependency_id', projectDependencyId).order('function_name'),
      supabase.from('project_dependency_files').select('file_path').eq('project_dependency_id', projectDependencyId).order('file_path'),
    ]);
    const importedFunctions = ((functionsResult.data || []) as { function_name: string }[]).map((r) => r.function_name);
    const importedFilePaths = ((filesResult.data || []) as { file_path: string }[]).map((r) => r.file_path);

    if (!dependencyVersionId) {
      return res.status(404).json({ error: 'Project dependency has no dependency_version_id' });
    }

    const { data: dv, error: dvError } = await supabase
      .from('dependency_versions')
      .select('dependency_id, version')
      .eq('id', dependencyVersionId)
      .single();

    if (dvError || !dv) {
      return res.status(404).json({ error: 'Dependency version not found' });
    }

    const dependencyId = (dv as any).dependency_id;
    if (!dependencyId) {
      return res.status(404).json({ error: 'Dependency version has no dependency_id' });
    }

    const version = (dv as any).version ?? null;

    // Score now comes from dependencies (package-level reputation score)
    const { data: dep, error: depError } = await supabase
      .from('dependencies')
      .select('name, github_url, license, weekly_downloads, latest_release_date, latest_version, last_published_at, score, releases_last_12_months, description, openssf_score, openssf_penalty, popularity_penalty, maintenance_penalty')
      .eq('id', dependencyId)
      .single();

    if (depError || !dep) {
      return res.status(404).json({ error: 'Dependency not found' });
    }

    const d = dep as any;

    // Run independent queries in parallel
    const [
      vulnCounts,
      otherProjectRows,
      orgDepRow,
      removePrRow,
      projectTeamsData,
    ] = await Promise.all([
      getVulnCountsForVersion(supabase, dependencyId, version ?? ''),
      d.name
        ? supabase
            .from('project_dependencies')
            .select('project_id, projects!inner(id, name, organization_id)')
            .eq('name', d.name)
            .eq('projects.organization_id', id)
            .neq('project_id', projectId)
            .then((r) => r.data ?? [])
        : Promise.resolve([]),
      supabase
        .from('organization_deprecations')
        .select('recommended_alternative, deprecated_by, created_at')
        .eq('organization_id', id)
        .eq('dependency_id', dependencyId)
        .maybeSingle()
        .then((r) => r.data),
      supabase
        .from('dependency_prs')
        .select('pr_url, pr_number')
        .eq('project_id', projectId)
        .eq('dependency_id', dependencyId)
        .eq('type', 'remove')
        .maybeSingle()
        .then((r) => r.data),
      supabase.from('project_teams').select('team_id').eq('project_id', projectId).then((r) => r.data ?? []),
    ]);

    const critical_vulns = vulnCounts.critical_vulns;
    const high_vulns = vulnCounts.high_vulns;
    const medium_vulns = vulnCounts.medium_vulns;
    const low_vulns = vulnCounts.low_vulns;

    let otherProjectsUsingCount = 0;
    let otherProjectsUsingNames: string[] = [];
    if (Array.isArray(otherProjectRows) && otherProjectRows.length > 0) {
      const seen = new Set<string>();
      const uniqueProjects: { id: string; name: string }[] = [];
      for (const row of otherProjectRows) {
        const proj = (row as any).projects;
        if (proj && !seen.has(proj.id)) {
          seen.add(proj.id);
          uniqueProjects.push({ id: proj.id, name: proj.name });
        }
      }
      otherProjectsUsingCount = uniqueProjects.length;
      otherProjectsUsingNames = uniqueProjects.slice(0, 5).map((p) => p.name);
    }

    let deprecation: { recommended_alternative: string; deprecated_by: string | null; created_at: string; scope: 'organization' | 'team'; team_id?: string } | null = null;
    if (orgDepRow) {
      deprecation = {
        recommended_alternative: (orgDepRow as any).recommended_alternative,
        deprecated_by: (orgDepRow as any).deprecated_by ?? null,
        created_at: (orgDepRow as any).created_at,
        scope: 'organization',
      };
    } else {
      const teamIds = (projectTeamsData ?? []).map((t: any) => t.team_id);
      if (teamIds.length > 0) {
        const { data: teamDepRow } = await supabase
          .from('team_deprecations')
          .select('team_id, recommended_alternative, deprecated_by, created_at')
          .in('team_id', teamIds)
          .eq('dependency_id', dependencyId)
          .limit(1)
          .maybeSingle();
        if (teamDepRow) {
          deprecation = {
            recommended_alternative: (teamDepRow as any).recommended_alternative,
            deprecated_by: (teamDepRow as any).deprecated_by ?? null,
            created_at: (teamDepRow as any).created_at,
            scope: 'team',
            team_id: (teamDepRow as any).team_id,
          };
        }
      }
    }

    let remove_pr_url: string | null = null;
    let remove_pr_number: number | null = null;
    if (removePrRow) {
      remove_pr_url = (removePrRow as any).pr_url ?? null;
      remove_pr_number = (removePrRow as any).pr_number ?? null;
    }

    res.json({
      name: d.name ?? null,
      version,
      score: d.score ?? null,
      critical_vulns,
      high_vulns,
      medium_vulns,
      low_vulns,
      github_url: d.github_url ?? null,
      license: d.license ?? null,
      weekly_downloads: d.weekly_downloads ?? null,
      latest_release_date: d.latest_release_date ?? null,
      latest_version: d.latest_version ?? null,
      last_published_at: d.last_published_at ?? null,
      releases_last_12_months: d.releases_last_12_months ?? null,
      openssf_score: d.openssf_score != null ? Number(d.openssf_score) : null,
      openssf_penalty: d.openssf_penalty ?? null,
      popularity_penalty: d.popularity_penalty ?? null,
      maintenance_penalty: d.maintenance_penalty ?? null,
      dependency_id: dependencyId,
      dependency_version_id: dependencyVersionId,
      files_importing_count: filesImportingCount,
      imported_functions: importedFunctions,
      imported_file_paths: importedFilePaths,
      ai_usage_summary: aiUsageSummary,
      ai_usage_analyzed_at: aiUsageAnalyzedAt,
      other_projects_using_count: otherProjectsUsingCount,
      other_projects_using_names: otherProjectsUsingNames,
      description: d.description ?? null,
      deprecation,
      remove_pr_url,
      remove_pr_number,
    });
  } catch (error: any) {
    console.error('Error fetching dependency overview:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch dependency overview' });
  }
});

// POST /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/analyze-usage - AI usage analysis
router.post('/:id/projects/:projectId/dependencies/:projectDependencyId/analyze-usage', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // 1. Fetch dependency info
    const { data: pd, error: pdError } = await supabase
      .from('project_dependencies')
      .select('name, version, files_importing_count, is_direct')
      .eq('id', projectDependencyId)
      .eq('project_id', projectId)
      .single();

    if (pdError || !pd) {
      return res.status(404).json({ error: 'Project dependency not found' });
    }

    const depName = (pd as any).name;
    const depVersion = (pd as any).version;
    const filesImportingCount = (pd as any).files_importing_count ?? 0;
    const isDirect = (pd as any).is_direct;

    // 2. Fetch imported function names
    const { data: funcRows } = await supabase
      .from('project_dependency_functions')
      .select('function_name')
      .eq('project_dependency_id', projectDependencyId)
      .order('function_name');
    const importedFunctions = (funcRows || []).map((r: { function_name: string }) => r.function_name);

    // 3. Fetch file paths from project_dependency_files
    const { data: fileRows } = await supabase
      .from('project_dependency_files')
      .select('file_path')
      .eq('project_dependency_id', projectDependencyId)
      .order('file_path');
    const allFilePaths = (fileRows || []).map((r: { file_path: string }) => r.file_path);

    // 4. Fetch project framework
    const { data: projectData } = await supabase
      .from('projects')
      .select('framework')
      .eq('id', projectId)
      .single();
    const framework = (projectData as any)?.framework || null;

    // 5. Try to fetch real code snippets from GitHub
    let codeSnippets: Array<{ filePath: string; code: string }> = [];
    try {
      // Get repo info (include package_json_path so we fetch files from the right workspace root)
      const { data: repoRow } = await supabase
        .from('project_repositories')
        .select('repo_full_name, default_branch, installation_id, package_json_path')
        .eq('project_id', projectId)
        .maybeSingle();

      if (repoRow?.repo_full_name && repoRow?.installation_id) {
        const installationToken = await createInstallationToken(repoRow.installation_id);
        const packageJsonDir = (repoRow as { package_json_path?: string }).package_json_path ?? '';
        const prefixPath = packageJsonDir ? `${packageJsonDir}/` : '';

        // File selection: skip test files, sort by path length (shorter = simpler/more representative)
        const testPattern = /\/(test|spec|__test__|__tests__|__mock__|__mocks__|\.test\.|\.spec\.)/i;
        const candidateFiles = allFilePaths
          .filter((fp: string) => !testPattern.test('/' + fp))
          .sort((a: string, b: string) => a.length - b.length)
          .slice(0, 3);

        const MAX_CODE_CHARS = 8000; // ~2000 tokens
        let totalChars = 0;

        for (const filePath of candidateFiles) {
          if (totalChars >= MAX_CODE_CHARS) break;
          try {
            const fullPath = prefixPath + filePath;
            const content = await getRepositoryFileContent(
              installationToken,
              repoRow.repo_full_name,
              fullPath,
              repoRow.default_branch
            );

            const lines = content.split('\n');

            // If file is short enough, include it all
            if (lines.length <= 150) {
              const snippet = content.substring(0, MAX_CODE_CHARS - totalChars);
              codeSnippets.push({ filePath, code: snippet });
              totalChars += snippet.length;
            } else {
              // Extract import lines for this package + surrounding usage of imported functions
              const extractedLines: string[] = [];
              const importLineIndices: number[] = [];

              // Find import lines for this package
              for (let i = 0; i < lines.length; i++) {
                if (lines[i].includes(depName)) {
                  importLineIndices.push(i);
                }
              }

              // Add import lines with 2 lines of context
              for (const idx of importLineIndices) {
                const start = Math.max(0, idx - 1);
                const end = Math.min(lines.length - 1, idx + 1);
                for (let i = start; i <= end; i++) {
                  extractedLines.push(`${i + 1}: ${lines[i]}`);
                }
                extractedLines.push('...');
              }

              // Find usage of imported function names (up to 30 lines of context)
              const usageLines: string[] = [];
              for (const fn of importedFunctions.slice(0, 5)) {
                if (fn === 'default' || fn === '*') continue;
                for (let i = 0; i < lines.length; i++) {
                  if (importLineIndices.includes(i)) continue; // skip import lines already captured
                  if (lines[i].includes(fn)) {
                    const start = Math.max(0, i - 2);
                    const end = Math.min(lines.length - 1, i + 2);
                    for (let j = start; j <= end; j++) {
                      usageLines.push(`${j + 1}: ${lines[j]}`);
                    }
                    usageLines.push('...');
                    if (usageLines.length > 30) break;
                  }
                }
                if (usageLines.length > 30) break;
              }

              const combined = [...extractedLines, ...usageLines].join('\n');
              const snippet = combined.substring(0, MAX_CODE_CHARS - totalChars);
              if (snippet.length > 0) {
                codeSnippets.push({ filePath, code: snippet });
                totalChars += snippet.length;
              }
            }
          } catch (fileError) {
            console.warn(`Failed to fetch file ${filePath} from GitHub:`, fileError);
            // Continue with other files
          }
        }
      }
    } catch (githubError) {
      console.warn('Failed to fetch code from GitHub for AI analysis, proceeding with metadata only:', githubError);
    }

    // 6. Build the OpenAI prompt
    const systemPrompt = `You are a senior software architect reviewing how a dependency is used in a codebase. Provide:
(1) A 2-3 sentence summary of the dependency's role and criticality in this project.
(2) One representative code example from the provided files showing how it's used, formatted as a markdown code block with the file path as a comment above it.
Be concise, specific, and direct. Do not repeat the metadata back.`;

    let userPrompt = `Package: ${depName}@${depVersion}
Type: ${isDirect ? 'Direct dependency' : 'Transitive dependency'}
${framework ? `Project framework: ${framework}` : ''}
Imported in ${filesImportingCount} file(s)
Functions/exports used: ${importedFunctions.length > 0 ? importedFunctions.join(', ') : 'none detected'}

File paths importing this package:
${allFilePaths.length > 0 ? allFilePaths.map((fp: string) => `- ${fp}`).join('\n') : 'No file path data available'}`;

    if (codeSnippets.length > 0) {
      userPrompt += `\n\nCode from representative files:\n`;
      for (const snippet of codeSnippets) {
        userPrompt += `\n--- ${snippet.filePath} ---\n${snippet.code}\n`;
      }
    }

    // 7. Call OpenAI
    const { getOpenAIClient } = await import('../lib/openai');
    const openai = getOpenAIClient();

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.3,
      max_tokens: 500,
    });

    const aiSummary = completion.choices[0]?.message?.content || 'Analysis could not be generated.';
    const analyzedAt = new Date().toISOString();

    // 8. Store the result
    const { error: updateError } = await supabase
      .from('project_dependencies')
      .update({
        ai_usage_summary: aiSummary,
        ai_usage_analyzed_at: analyzedAt,
      })
      .eq('id', projectDependencyId);

    if (updateError) {
      console.error('Failed to store AI usage summary:', updateError);
    }

    res.json({
      ai_usage_summary: aiSummary,
      ai_usage_analyzed_at: analyzedAt,
    });
  } catch (error: any) {
    console.error('Error analyzing dependency usage:', error);
    res.status(500).json({ error: error.message || 'Failed to analyze dependency usage' });
  }
});

// GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/versions - List versions with vuln counts, CVE details, watchtower checks, and PRs
// Query: limit, offset (optional). When provided, returns only that page and a total count for faster initial load; omit for full list (e.g. VersionSidebar).
router.get('/:id/projects/:projectId/dependencies/:projectDependencyId/versions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;
    const limitParam = req.query.limit != null ? parseInt(String(req.query.limit), 10) : undefined;
    const offsetParam = req.query.offset != null ? parseInt(String(req.query.offset), 10) : undefined;
    const paginate = limitParam != null && limitParam > 0;
    const limit = paginate ? Math.min(limitParam!, 100) : undefined;
    const offset = paginate ? Math.max(0, offsetParam ?? 0) : undefined;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    if (!paginate) {
      const cacheKey = getDependencyVersionsCacheKey(id, projectId, projectDependencyId);
      const cached = await getCached<{ versions: any[]; currentVersion: string; latestVersion: string; prs: any[]; bannedVersions: string[] }>(cacheKey);
      if (cached) {
        return res.json(cached);
      }
    }

    const { data: pd, error: pdError } = await supabase
      .from('project_dependencies')
      .select('dependency_version_id')
      .eq('id', projectDependencyId)
      .eq('project_id', projectId)
      .single();

    if (pdError || !pd) {
      return res.status(404).json({ error: 'Project dependency not found' });
    }

    const dependencyVersionId = (pd as any).dependency_version_id;
    if (!dependencyVersionId) {
      return res.status(404).json({ error: 'Project dependency has no dependency_version_id' });
    }

    const { data: currentDv, error: dvError } = await supabase
      .from('dependency_versions')
      .select('dependency_id, version')
      .eq('id', dependencyVersionId)
      .single();

    if (dvError || !currentDv) {
      return res.status(404).json({ error: 'Dependency version not found' });
    }

    const dependencyId = (currentDv as any).dependency_id;
    const currentVersion = (currentDv as any).version ?? null;

    const { data: allVersions, error: listError } = await supabase
      .from('dependency_versions')
      .select(
        'id, version, registry_integrity_status, registry_integrity_reason, install_scripts_status, install_scripts_reason, entropy_analysis_status, entropy_analysis_reason'
      )
      .eq('dependency_id', dependencyId)
      .order('version', { ascending: false });

    if (listError) {
      throw listError;
    }

    const { data: vulnsRows, error: vulnsError } = await supabase
      .from('dependency_vulnerabilities')
      .select('id, osv_id, severity, summary, aliases, affected_versions, fixed_versions')
      .eq('dependency_id', dependencyId);

    if (vulnsError) {
      throw vulnsError;
    }
    const allVulns = (vulnsRows || []) as Array<{
      id: string;
      osv_id: string;
      severity: string | null;
      summary: string | null;
      aliases: string[] | null;
      affected_versions: unknown;
      fixed_versions: string[] | null;
    }>;

    const { data: dep, error: depErr } = await supabase
      .from('dependencies')
      .select('latest_version, name')
      .eq('id', dependencyId)
      .single();
    if (depErr || !dep) {
      return res.status(404).json({ error: 'Dependency not found' });
    }
    const packageName = (dep as any).name ?? null;
    const latestVersion = (dep as any).latest_version ?? (allVersions?.[0] as any)?.version ?? currentVersion;

    const organizationId = id;
    const { data: bannedRows } = await supabase
      .from('banned_versions')
      .select('banned_version')
      .eq('organization_id', organizationId)
      .eq('dependency_id', dependencyId);
    const bannedSet = new Set<string>((bannedRows || []).map((r: any) => r.banned_version as string));
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('team_id')
      .eq('project_id', projectId);
    const teamIds = (projectTeams ?? []).map((t: any) => t.team_id);
    if (teamIds.length > 0) {
      const { data: teamBans } = await supabase
        .from('team_banned_versions')
        .select('banned_version')
        .in('team_id', teamIds)
        .eq('dependency_id', dependencyId);
      (teamBans ?? []).forEach((r: any) => bannedSet.add(r.banned_version as string));
    }
    const bannedVersions = Array.from(bannedSet);

    const { data: prRows } = await supabase
      .from('dependency_prs')
      .select('target_version, pr_url, pr_number')
      .eq('project_id', projectId)
      .eq('dependency_id', dependencyId)
      .eq('type', 'bump');
    const allBumpPrs = (prRows || []).map((r: any) => ({
      target_version: r.target_version,
      pr_url: r.pr_url,
      pr_number: r.pr_number,
    }));
    // Only expose one bump PR (highest target_version) so the versions sidebar never shows multiple "View PR" links
    const prs = allBumpPrs.length <= 1 ? allBumpPrs : (() => {
      const sorted = [...allBumpPrs].sort((a, b) => {
        const va = semver.coerce(a.target_version);
        const vb = semver.coerce(b.target_version);
        if (!va || !vb) return 0;
        return semver.rcompare(va, vb);
      });
      return sorted.slice(0, 1);
    })();

    // Only show stable releases in the list (plus current version if it's prerelease)
    let versionList = (allVersions || []).filter(
      (v: any) => isStableVersion(v.version ?? '') || (v.version === currentVersion)
    );
    // Sort semver descending (4.17.23 before 4.17.4)
    versionList = versionList.sort((a: any, b: any) => {
      const va = semver.coerce(a.version ?? '');
      const vb = semver.coerce(b.version ?? '');
      if (!va || !vb) return 0;
      return semver.rcompare(va, vb);
    });
    const totalVersions = versionList.length;
    const latestVersionBySemver = versionList[0]?.version ?? latestVersion;
    if (paginate && limit != null && offset != null) {
      versionList = versionList.slice(offset, offset + limit);
    }
    const versionStrs = versionList.map((v: any) => v.version ?? '');
    const vulnCountsMap = await getVulnCountsForVersionsBatch(supabase, dependencyId, versionStrs);

    // Transitive vulnerabilities: for each parent version, get child versions via edges, then vulns affecting those children
    const parentDvIds = versionList.map((v: any) => v.id).filter(Boolean);
    const transitiveByParentId = new Map<string, Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[] }>>();
    if (parentDvIds.length > 0) {
      const BATCH = 100;
      const { data: edges } = await supabase
        .from('dependency_version_edges')
        .select('parent_version_id, child_version_id')
        .in('parent_version_id', parentDvIds);
      const parentToChildren = new Map<string, string[]>();
      for (const e of edges || []) {
        const pid = (e as any).parent_version_id;
        const cid = (e as any).child_version_id;
        if (!parentToChildren.has(pid)) parentToChildren.set(pid, []);
        parentToChildren.get(pid)!.push(cid);
      }
      const childVersionIds = [...new Set((edges || []).map((e: any) => e.child_version_id))];
      if (childVersionIds.length > 0) {
        const allChildVersions: any[] = [];
        for (let i = 0; i < childVersionIds.length; i += BATCH) {
          const batch = childVersionIds.slice(i, i + BATCH);
          const { data: dvRows } = await supabase
            .from('dependency_versions')
            .select('id, dependency_id, version')
            .in('id', batch);
          if (dvRows) allChildVersions.push(...dvRows);
        }
        const childDepIds = [...new Set(allChildVersions.map((dv: any) => dv.dependency_id).filter(Boolean))];
        const depIdToName = new Map<string, string>();
        for (let i = 0; i < childDepIds.length; i += BATCH) {
          const batch = childDepIds.slice(i, i + BATCH);
          const { data: depRows } = await supabase
            .from('dependencies')
            .select('id, name')
            .in('id', batch);
          if (depRows) {
            for (const row of depRows as any[]) {
              depIdToName.set(row.id, row.name ?? row.id);
            }
          }
        }
        const depIdToVulns = new Map<string, any[]>();
        for (let i = 0; i < childDepIds.length; i += BATCH) {
          const batch = childDepIds.slice(i, i + BATCH);
          const { data: vulnRows } = await supabase
            .from('dependency_vulnerabilities')
            .select('dependency_id, osv_id, severity, summary, aliases, affected_versions, fixed_versions')
            .in('dependency_id', batch);
          if (vulnRows) {
            for (const row of vulnRows) {
              if (!depIdToVulns.has(row.dependency_id)) depIdToVulns.set(row.dependency_id, []);
              depIdToVulns.get(row.dependency_id)!.push(row);
            }
          }
        }
        const childIdToInfo = new Map<string, { dependency_id: string; version: string }>();
        for (const dv of allChildVersions) {
          childIdToInfo.set(dv.id, { dependency_id: dv.dependency_id, version: dv.version });
        }
        for (const parentId of parentDvIds) {
          const childIds = parentToChildren.get(parentId) || [];
          const seenOsv = new Set<string>();
          const list: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[]; from_package: string }> = [];
          for (const cid of childIds) {
            const info = childIdToInfo.get(cid);
            if (!info) continue;
            const vulns = depIdToVulns.get(info.dependency_id) || [];
            const packageName = depIdToName.get(info.dependency_id) ?? info.dependency_id;
            for (const v of vulns) {
              if (!isVersionAffected(info.version, v.affected_versions) || isVersionFixed(info.version, v.fixed_versions ?? [])) continue;
              if (seenOsv.has(v.osv_id)) continue;
              seenOsv.add(v.osv_id);
              list.push({
                osv_id: v.osv_id,
                severity: v.severity ?? 'unknown',
                summary: v.summary ?? null,
                aliases: v.aliases ?? [],
                from_package: packageName,
              });
            }
          }
          transitiveByParentId.set(parentId, list);
        }
      }
    }

    const versions = versionList.map((v: any) => {
      const versionStr = v.version ?? '';
      const counts = vulnCountsMap.get(versionStr) ?? { critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0 };
      const vulnCount = counts.critical_vulns + counts.high_vulns + counts.medium_vulns + counts.low_vulns;
      const vulnerabilities = allVulns
        .filter((uv) => isVersionAffected(versionStr, uv.affected_versions))
        .map((uv) => ({
          osv_id: uv.osv_id,
          severity: uv.severity ?? 'unknown',
          summary: uv.summary ?? null,
          aliases: uv.aliases ?? [],
          fixed_versions: uv.fixed_versions ?? [],
        }));
      const transitiveVulnerabilities = transitiveByParentId.get(v.id) ?? [];
      const transitiveVulnCount = transitiveVulnerabilities.length;
      const totalVulnCount = vulnCount + transitiveVulnCount;
      return {
        version: versionStr,
        vulnCount,
        vulnerabilities,
        transitiveVulnCount,
        transitiveVulnerabilities,
        totalVulnCount,
        registry_integrity_status: v.registry_integrity_status ?? null,
        registry_integrity_reason: v.registry_integrity_reason ?? null,
        install_scripts_status: v.install_scripts_status ?? null,
        install_scripts_reason: v.install_scripts_reason ?? null,
        entropy_analysis_status: v.entropy_analysis_status ?? null,
        entropy_analysis_reason: v.entropy_analysis_reason ?? null,
      };
    });

    const response: {
      versions: typeof versions;
      currentVersion: string | null;
      latestVersion: string | null;
      prs: any[];
      bannedVersions: string[];
      total?: number;
    } = {
      versions,
      currentVersion,
      latestVersion: latestVersionBySemver,
      prs,
      bannedVersions,
    };
    if (paginate) {
      response.total = totalVersions;
    } else {
      await setCached(getDependencyVersionsCacheKey(id, projectId, projectDependencyId), response, CACHE_TTL_SECONDS.VERSIONS);
    }
    res.json(response);
  } catch (error: any) {
    console.error('Error fetching dependency versions:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch dependency versions' });
  }
});

/** Build supply chain children for one project dependency (for batch endpoint and reuse). Returns [] if not found. */
const BATCH_SIZE_SUPPLY_CHAIN = 100;
type SupplyChainChildRow = {
  name: string;
  version: string;
  dependency_version_id: string;
  score: number | null;
  license: string | null;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  vulnerabilities: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[] }>;
};

async function buildSupplyChainChildren(
  client: import('../../../backend/src/lib/supabase').SupabaseClientAny,
  projectId: string,
  projectDependencyId: string
): Promise<SupplyChainChildRow[]> {
  const { data: pd, error: pdError } = await client
    .from('project_dependencies')
    .select('dependency_version_id')
    .eq('id', projectDependencyId)
    .eq('project_id', projectId)
    .single();

  if (pdError || !pd) return [];
  const dependencyVersionId = (pd as any).dependency_version_id;
  if (!dependencyVersionId) return [];

  const { data: childEdges, error: childEdgesError } = await client
    .from('dependency_version_edges')
    .select('child_version_id')
    .eq('parent_version_id', dependencyVersionId);

  if (childEdgesError) return [];
  const childVersionIds = (childEdges || []).map((e: any) => e.child_version_id);
  if (childVersionIds.length === 0) return [];

  const allChildVersions: any[] = [];
  for (let i = 0; i < childVersionIds.length; i += BATCH_SIZE_SUPPLY_CHAIN) {
    const batch = childVersionIds.slice(i, i + BATCH_SIZE_SUPPLY_CHAIN);
    const { data: dvRows, error: dvError } = await client
      .from('dependency_versions')
      .select('id, dependency_id, version')
      .in('id', batch);
    if (dvError) return [];
    if (dvRows) allChildVersions.push(...dvRows);
  }

  const depIds = [...new Set(allChildVersions.map((dv: any) => dv.dependency_id).filter(Boolean))];
  const depIdToName = new Map<string, string>();
  const depIdToScore = new Map<string, number | null>();
  const depIdToLicense = new Map<string, string | null>();
  for (let i = 0; i < depIds.length; i += BATCH_SIZE_SUPPLY_CHAIN) {
    const batch = depIds.slice(i, i + BATCH_SIZE_SUPPLY_CHAIN);
    const { data: depRows, error: depError } = await client
      .from('dependencies')
      .select('id, name, score, license')
      .in('id', batch);
    if (depError) return [];
    if (depRows) for (const row of depRows) {
      depIdToName.set(row.id, row.name);
      depIdToScore.set(row.id, (row as any).score ?? null);
      depIdToLicense.set(row.id, (row as any).license ?? null);
    }
  }

  const depIdToVulns = new Map<string, any[]>();
  for (let i = 0; i < depIds.length; i += BATCH_SIZE_SUPPLY_CHAIN) {
    const batch = depIds.slice(i, i + BATCH_SIZE_SUPPLY_CHAIN);
    const { data: vulnRows, error: vulnError } = await client
      .from('dependency_vulnerabilities')
      .select('dependency_id, osv_id, severity, summary, aliases, affected_versions, fixed_versions')
      .in('dependency_id', batch);
    if (vulnError) return [];
    if (vulnRows) {
      for (const v of vulnRows) {
        if (!depIdToVulns.has(v.dependency_id)) depIdToVulns.set(v.dependency_id, []);
        depIdToVulns.get(v.dependency_id)!.push(v);
      }
    }
  }

  const result: SupplyChainChildRow[] = allChildVersions.map((dv: any) => {
    const name = depIdToName.get(dv.dependency_id) || 'unknown';
    const version = dv.version;
    const allVulns = depIdToVulns.get(dv.dependency_id) || [];
    const vulnerabilities = allVulns
      .filter((v: any) => isVersionAffected(version, v.affected_versions) && !isVersionFixed(version, v.fixed_versions ?? []))
      .map((v: any) => ({
        osv_id: v.osv_id,
        severity: v.severity ?? 'unknown',
        summary: v.summary ?? null,
        aliases: v.aliases ?? [],
      }));
    const critical_vulns = vulnerabilities.filter((v: any) => v.severity === 'critical').length;
    const high_vulns = vulnerabilities.filter((v: any) => v.severity === 'high').length;
    const medium_vulns = vulnerabilities.filter((v: any) => v.severity === 'medium').length;
    const low_vulns = vulnerabilities.filter((v: any) => v.severity === 'low').length;
    return {
      name,
      version,
      dependency_version_id: dv.id,
      score: depIdToScore.get(dv.dependency_id) ?? null,
      license: depIdToLicense.get(dv.dependency_id) ?? null,
      critical_vulns,
      high_vulns,
      medium_vulns,
      low_vulns,
      vulnerabilities,
    };
  });
  result.sort((a, b) => {
    const aVulns = a.vulnerabilities.length;
    const bVulns = b.vulnerabilities.length;
    if (aVulns !== bVulns) return bVulns - aVulns;
    return a.name.localeCompare(b.name);
  });
  return result;
}

// POST /api/organizations/:id/projects/:projectId/dependencies/supply-chains/batch - Batch supply chain children for vulnerabilities tab
router.post('/:id/projects/:projectId/dependencies/supply-chains/batch', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const body = req.body as { project_dependency_ids?: string[] };
    const projectDependencyIds = Array.isArray(body?.project_dependency_ids) ? body.project_dependency_ids : [];

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const results: Record<string, { children: SupplyChainChildRow[] }> = {};
    const childArrays = await Promise.all(
      projectDependencyIds.map((pid) => buildSupplyChainChildren(supabase, projectId, pid))
    );
    projectDependencyIds.forEach((pid, i) => {
      results[pid] = { children: childArrays[i] ?? [] };
    });

    res.json(results);
  } catch (error: any) {
    console.error('Error fetching batch supply chains:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch batch supply chains' });
  }
});

// GET /api/organizations/:id/projects/:projectId/dependencies/supply-chains/latest-safe-versions - Batch latest safe version for vulnerabilities tab
router.get('/:id/projects/:projectId/dependencies/supply-chains/latest-safe-versions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;
    const idsParam = (req.query.project_dependency_ids as string) || '';
    const projectDependencyIds = idsParam ? idsParam.split(',').map((s) => s.trim()).filter(Boolean) : [];
    const severityParam = ((req.query.severity as string) || 'high').toLowerCase() as 'critical' | 'high' | 'medium' | 'low';
    const excludeBanned = req.query.exclude_banned !== 'false';

    const validSeverities = ['critical', 'high', 'medium', 'low'];
    if (!validSeverities.includes(severityParam)) {
      return res.status(400).json({ error: 'severity must be one of: critical, high, medium, low' });
    }

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const results: Record<string, LatestSafeVersionResponse> = {};
    const settled = await Promise.allSettled(
      projectDependencyIds.map((projectDependencyId) =>
        calculateLatestSafeVersion({
          organizationId: id,
          projectId,
          projectDependencyId,
          severity: severityParam,
          excludeBanned,
          skipCache: false,
        })
      )
    );
    settled.forEach((outcome, i) => {
      const pid = projectDependencyIds[i];
      if (!pid) return;
      if (outcome.status === 'fulfilled') {
        results[pid] = outcome.value;
      }
    });

    res.json(results);
  } catch (error: any) {
    console.error('Error fetching batch latest safe versions:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch batch latest safe versions' });
  }
});

// GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/supply-chain - Get supply chain data for a dependency
router.get('/:id/projects/:projectId/dependencies/:projectDependencyId/supply-chain', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // 1. Get the project_dependency row to find dependency_version_id, dependency_id, name, version, is_direct, source, files_importing_count
    const { data: pd, error: pdError } = await supabase
      .from('project_dependencies')
      .select('dependency_version_id, dependency_id, name, version, is_direct, source, files_importing_count')
      .eq('id', projectDependencyId)
      .eq('project_id', projectId)
      .single();

    if (pdError || !pd) {
      return res.status(404).json({ error: 'Project dependency not found' });
    }

    const dependencyVersionId = (pd as any).dependency_version_id;
    if (!dependencyVersionId) {
      return res.status(404).json({ error: 'Project dependency has no dependency_version_id' });
    }

    const isDirect = (pd as any).is_direct;
    const parentName = (pd as any).name;
    const parentVersion = (pd as any).version;

    // 2. Get children: query dependency_version_edges where parent_version_id = this version
    const { data: childEdges, error: childEdgesError } = await supabase
      .from('dependency_version_edges')
      .select('child_version_id')
      .eq('parent_version_id', dependencyVersionId);

    if (childEdgesError) {
      throw childEdgesError;
    }

    const childVersionIds = (childEdges || []).map((e: any) => e.child_version_id);

    const BATCH_SIZE = 100;
    type ChildRow = {
      name: string;
      version: string;
      dependency_version_id: string;
      score: number | null;
      license: string | null;
      critical_vulns: number;
      high_vulns: number;
      medium_vulns: number;
      low_vulns: number;
      vulnerabilities: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[] }>;
    };

    async function buildChildren(): Promise<ChildRow[]> {
      const children: ChildRow[] = [];
      if (childVersionIds.length === 0) return children;
      const allChildVersions: any[] = [];
      for (let i = 0; i < childVersionIds.length; i += BATCH_SIZE) {
        const batch = childVersionIds.slice(i, i + BATCH_SIZE);
        const { data: dvRows, error: dvError } = await supabase
          .from('dependency_versions')
          .select('id, dependency_id, version')
          .in('id', batch);
        if (dvError) throw dvError;
        if (dvRows) allChildVersions.push(...dvRows);
      }
      const depIds = [...new Set(allChildVersions.map((dv: any) => dv.dependency_id).filter(Boolean))];
      const depIdToName = new Map<string, string>();
      const depIdToScore = new Map<string, number | null>();
      const depIdToLicense = new Map<string, string | null>();
      for (let i = 0; i < depIds.length; i += BATCH_SIZE) {
        const batch = depIds.slice(i, i + BATCH_SIZE);
        const { data: depRows, error: depError } = await supabase
          .from('dependencies')
          .select('id, name, score, license')
          .in('id', batch);
        if (depError) throw depError;
        if (depRows) for (const row of depRows) {
          depIdToName.set(row.id, row.name);
          depIdToScore.set(row.id, (row as any).score ?? null);
          depIdToLicense.set(row.id, (row as any).license ?? null);
        }
      }
      const depIdToVulns = new Map<string, any[]>();
      for (let i = 0; i < depIds.length; i += BATCH_SIZE) {
        const batch = depIds.slice(i, i + BATCH_SIZE);
        const { data: vulnRows, error: vulnError } = await supabase
          .from('dependency_vulnerabilities')
          .select('dependency_id, osv_id, severity, summary, aliases, affected_versions, fixed_versions')
          .in('dependency_id', batch);
        if (vulnError) throw vulnError;
        if (vulnRows) {
          for (const v of vulnRows) {
            if (!depIdToVulns.has(v.dependency_id)) depIdToVulns.set(v.dependency_id, []);
            depIdToVulns.get(v.dependency_id)!.push(v);
          }
        }
      }
      const result = allChildVersions.map((dv: any) => {
        const name = depIdToName.get(dv.dependency_id) || 'unknown';
        const version = dv.version;
        const allVulns = depIdToVulns.get(dv.dependency_id) || [];
        const vulnerabilities = allVulns
          .filter((v: any) => isVersionAffected(version, v.affected_versions) && !isVersionFixed(version, v.fixed_versions ?? []))
          .map((v: any) => ({
            osv_id: v.osv_id,
            severity: v.severity ?? 'unknown',
            summary: v.summary ?? null,
            aliases: v.aliases ?? [],
          }));
        const critical_vulns = vulnerabilities.filter((v: any) => v.severity === 'critical').length;
        const high_vulns = vulnerabilities.filter((v: any) => v.severity === 'high').length;
        const medium_vulns = vulnerabilities.filter((v: any) => v.severity === 'medium').length;
        const low_vulns = vulnerabilities.filter((v: any) => v.severity === 'low').length;
        return {
          name,
          version,
          dependency_version_id: dv.id,
          score: depIdToScore.get(dv.dependency_id) ?? null,
          license: depIdToLicense.get(dv.dependency_id) ?? null,
          critical_vulns,
          high_vulns,
          medium_vulns,
          low_vulns,
          vulnerabilities,
        };
      });
      result.sort((a, b) => {
        const aVulns = a.vulnerabilities.length;
        const bVulns = b.vulnerabilities.length;
        if (aVulns !== bVulns) return bVulns - aVulns;
        return a.name.localeCompare(b.name);
      });
      return result;
    }

    async function getCurrentDvAndAvailableVersions(): Promise<{
      currentDvRow: any;
      availableVersions: Array<{ dependency_version_id: string; version: string }>;
    }> {
      const { data: currentDvRow, error: dvError } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', dependencyVersionId)
        .single();
      if (dvError || !currentDvRow) {
        return { currentDvRow: null, availableVersions: [] };
      }
      const { data: allVersionRows } = await supabase
        .from('dependency_versions')
        .select('id, version')
        .eq('dependency_id', (currentDvRow as any).dependency_id)
        .order('version', { ascending: false });
      let availableVersions: Array<{ dependency_version_id: string; version: string }> = [];
      if (allVersionRows?.length) {
        const filtered = allVersionRows.filter(
          (v: any) => isStableVersion(v.version ?? '') || v.version === parentVersion
        );
        filtered.sort((a: any, b: any) => {
          const va = semver.coerce(a.version);
          const vb = semver.coerce(b.version);
          if (!va || !vb) return 0;
          return semver.rcompare(va, vb);
        });
        availableVersions = filtered.map((v: any) => ({
          dependency_version_id: v.id,
          version: v.version,
        }));
      }
      return { currentDvRow, availableVersions };
    }

    const [children, dvAndVersions, ancestors] = await Promise.all([
      buildChildren(),
      getCurrentDvAndAvailableVersions(),
      getAncestorPathsBatched(supabase, projectId, dependencyVersionId, parentName, parentVersion, isDirect),
    ]);

    const { currentDvRow, availableVersions } = dvAndVersions;
    const parentDepId = (currentDvRow as any)?.dependency_id ?? null;

    // Parallel 2: parent license, parent vulns, bump PRs, remove PR, watchtower, banned versions
    const parentDepIdForRemove = (pd as any).dependency_id ?? null;
    const [parentLicenseResult, parentVulnRows, bumpPrRows, removePrRow, versionSecurityData, bannedVersionsResult] = await Promise.all([
      parentDepId != null
        ? supabase.from('dependencies').select('license').eq('id', parentDepId).single().then(({ data }) => (data as any)?.license ?? null)
        : Promise.resolve(null as string | null),
      parentDepId != null
        ? supabase
            .from('dependency_vulnerabilities')
            .select('osv_id, severity, summary, aliases, affected_versions, fixed_versions')
            .eq('dependency_id', parentDepId)
            .then(({ data }) =>
              (data || []).map((v: any) => ({
                osv_id: v.osv_id,
                severity: v.severity ?? 'unknown',
                summary: v.summary ?? null,
                aliases: v.aliases ?? [],
                affected_versions: v.affected_versions ?? null,
                fixed_versions: v.fixed_versions ?? [],
              }))
            )
        : Promise.resolve([] as any[]),
      parentDepId != null
        ? supabase
            .from('dependency_prs')
            .select('target_version, pr_url, pr_number')
            .eq('project_id', projectId)
            .eq('dependency_id', parentDepId)
            .eq('type', 'bump')
            .then(({ data }) => (data || []).map((r: any) => ({ target_version: r.target_version, pr_url: r.pr_url, pr_number: r.pr_number })))
        : Promise.resolve([] as any[]),
      parentDepIdForRemove != null
        ? supabase
            .from('dependency_prs')
            .select('pr_url, pr_number')
            .eq('project_id', projectId)
            .eq('dependency_id', parentDepIdForRemove)
            .eq('type', 'remove')
            .maybeSingle()
            .then((r) => r.data)
        : Promise.resolve(null),
      (async () => {
        const out: {
          onWatchtower: boolean;
          quarantinedVersions: string[];
          securityChecks: Record<string, { registry_integrity_status: string | null; install_scripts_status: string | null; entropy_analysis_status: string | null }>;
        } = { onWatchtower: false, quarantinedVersions: [], securityChecks: {} };
        if (parentDepId == null) return out;
        const { data: wlRow } = await supabase
          .from('organization_watchlist')
          .select('quarantine_until, is_current_version_quarantined')
          .eq('organization_id', id)
          .eq('dependency_id', parentDepId)
          .maybeSingle();
        if (!wlRow) return out;
        out.onWatchtower = true;
        const wl = wlRow as any;
        if (wl.is_current_version_quarantined && wl.quarantine_until && new Date(wl.quarantine_until) > new Date()) {
          const { data: depRow } = await supabase.from('dependencies').select('latest_version').eq('id', parentDepId).single();
          if (depRow && (depRow as any).latest_version) {
            out.quarantinedVersions = [(depRow as any).latest_version];
          }
        }
        if (availableVersions.length > 0) {
          const { data: secRows } = await supabase
            .from('dependency_versions')
            .select('version, registry_integrity_status, install_scripts_status, entropy_analysis_status')
            .eq('dependency_id', parentDepId)
            .in('version', availableVersions.map((v: any) => v.version));
          if (secRows) {
            for (const row of secRows as any[]) {
              out.securityChecks[row.version] = {
                registry_integrity_status: row.registry_integrity_status ?? null,
                install_scripts_status: row.install_scripts_status ?? null,
                entropy_analysis_status: row.entropy_analysis_status ?? null,
              };
            }
          }
        }
        return out;
      })(),
      (async () => {
        if (parentDepId == null) return [] as Array<{ id: string; dependency_id: string; banned_version: string; bump_to_version: string; banned_by: string; created_at: string; source: 'org' | 'team'; team_id?: string }>;
        const { data: orgBans } = await supabase
          .from('banned_versions')
          .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at')
          .eq('organization_id', id)
          .eq('dependency_id', parentDepId)
          .order('created_at', { ascending: false });
        const result: Array<{ id: string; dependency_id: string; banned_version: string; bump_to_version: string; banned_by: string; created_at: string; source: 'org' | 'team'; team_id?: string }> = (orgBans ?? []).map((b: any) => ({ ...b, source: 'org' as const }));
        const { data: projectTeams } = await supabase.from('project_teams').select('team_id').eq('project_id', projectId);
        const teamIds = (projectTeams ?? []).map((t: any) => t.team_id);
        if (teamIds.length > 0) {
          const { data: teamBans } = await supabase
            .from('team_banned_versions')
            .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at, team_id')
            .in('team_id', teamIds)
            .eq('dependency_id', parentDepId)
            .order('created_at', { ascending: false });
          for (const b of teamBans ?? []) {
            result.push({
              id: (b as any).id,
              dependency_id: (b as any).dependency_id,
              banned_version: (b as any).banned_version,
              bump_to_version: (b as any).bump_to_version,
              banned_by: (b as any).banned_by,
              created_at: (b as any).created_at,
              source: 'team',
              team_id: (b as any).team_id,
            });
          }
        }
        return result;
      })(),
    ]);

    const parentLicense = parentLicenseResult;
    const parentVulnerabilities = parentVulnRows;
    const bumpPrs = bumpPrRows;

    let parentVulnerabilitiesAffectingCurrent: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[]; affected_versions: unknown; fixed_versions: string[] }> = [];
    if (parentVulnerabilities.length > 0) {
      parentVulnerabilitiesAffectingCurrent = parentVulnerabilities.filter(
        (v) => isVersionAffected(parentVersion, v.affected_versions) && !isVersionFixed(parentVersion, v.fixed_versions)
      );
    }

    // 12. Per-version vulnerability flags for center node dropdown (direct: from parent vulns; transitive: from children)
    const versionVulnerabilitySummary: Record<string, { hasDirect: boolean; hasTransitive: boolean }> = {};
    for (const av of availableVersions) {
      const ver = av.version;
      const hasDirect =
        parentVulnerabilities.some(
          (v) => isVersionAffected(ver, v.affected_versions) && !isVersionFixed(ver, v.fixed_versions)
        );
      versionVulnerabilitySummary[ver] = { hasDirect, hasTransitive: false };
    }
    // Transitive: one query for all edges from available versions, then resolve child vulns
    const availableVersionIds = availableVersions.map((v: any) => v.dependency_version_id);
    if (availableVersionIds.length > 0 && parentDepId) {
      const BATCH = 100;
      const { data: edges } = await supabase
        .from('dependency_version_edges')
        .select('parent_version_id, child_version_id')
        .in('parent_version_id', availableVersionIds);
      const parentToChildren = new Map<string, string[]>();
      for (const e of edges || []) {
        const pid = (e as any).parent_version_id;
        const cid = (e as any).child_version_id;
        if (!parentToChildren.has(pid)) parentToChildren.set(pid, []);
        parentToChildren.get(pid)!.push(cid);
      }
      const childVersionIds = [...new Set((edges || []).map((e: any) => (e as any).child_version_id))];
      if (childVersionIds.length > 0) {
        const allChildVersions: any[] = [];
        for (let i = 0; i < childVersionIds.length; i += BATCH) {
          const batch = childVersionIds.slice(i, i + BATCH);
          const { data: dvRows } = await supabase
            .from('dependency_versions')
            .select('id, dependency_id, version')
            .in('id', batch);
          if (dvRows) allChildVersions.push(...dvRows);
        }
        const childDepIds = [...new Set(allChildVersions.map((dv: any) => dv.dependency_id).filter(Boolean))];
        const depIdToVulns = new Map<string, any[]>();
        for (let i = 0; i < childDepIds.length; i += BATCH) {
          const batch = childDepIds.slice(i, i + BATCH);
          const { data: vulnRows } = await supabase
            .from('dependency_vulnerabilities')
            .select('dependency_id, osv_id, severity, summary, aliases, affected_versions, fixed_versions')
            .in('dependency_id', batch);
          if (vulnRows) {
            for (const row of vulnRows as any[]) {
              if (!depIdToVulns.has(row.dependency_id)) depIdToVulns.set(row.dependency_id, []);
              depIdToVulns.get(row.dependency_id)!.push(row);
            }
          }
        }
        for (const av of availableVersions) {
          const parentId = (av as any).dependency_version_id;
          const childIds = parentToChildren.get(parentId) || [];
          let hasTransitive = false;
          for (const cid of childIds) {
            const childDv = allChildVersions.find((d: any) => d.id === cid);
            if (!childDv) continue;
            const vulns = depIdToVulns.get(childDv.dependency_id) || [];
            for (const v of vulns) {
              if (isVersionAffected(childDv.version, v.affected_versions) && !isVersionFixed(childDv.version, v.fixed_versions ?? [])) {
                hasTransitive = true;
                break;
              }
            }
            if (hasTransitive) break;
          }
          if (versionVulnerabilitySummary[av.version]) {
            versionVulnerabilitySummary[av.version].hasTransitive = hasTransitive;
          }
        }
      }
    }

    const parentDependencyId = (pd as any).dependency_id ?? null;
    const removePr = removePrRow as { pr_url?: string; pr_number?: number } | null;
    res.json({
      parent: {
        name: parentName,
        version: parentVersion,
        dependency_id: parentDependencyId,
        dependency_version_id: dependencyVersionId,
        is_direct: isDirect,
        license: parentLicense,
        vulnerabilities: parentVulnerabilities,
        /** For the graph only: vulns that affect the current version (so graph shows only those). */
        vulnerabilities_affecting_current_version: parentVulnerabilitiesAffectingCurrent,
        files_importing_count: (pd as any).files_importing_count ?? 0,
        remove_pr_url: removePr?.pr_url ?? null,
        remove_pr_number: removePr?.pr_number ?? null,
      },
      children,
      ancestors,
      availableVersions,
      bumpPrs,
      versionSecurityData,
      versionVulnerabilitySummary,
      banned_versions: bannedVersionsResult,
    });
  } catch (error: any) {
    console.error('Error fetching supply chain data:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch supply chain data' });
  }
});

// GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/supply-chain/version/:dependencyVersionId - Get supply chain for a specific version
router.get('/:id/projects/:projectId/dependencies/:projectDependencyId/supply-chain/version/:dependencyVersionId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId, dependencyVersionId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Verify the project dependency exists
    const { data: pd, error: pdError } = await supabase
      .from('project_dependencies')
      .select('id')
      .eq('id', projectDependencyId)
      .eq('project_id', projectId)
      .single();

    if (pdError || !pd) {
      return res.status(404).json({ error: 'Project dependency not found' });
    }

    // 1. Look up the dependency_version to get the package name and version string
    const { data: dv, error: dvError } = await supabase
      .from('dependency_versions')
      .select('id, dependency_id, version')
      .eq('id', dependencyVersionId)
      .single();

    if (dvError || !dv) {
      return res.status(404).json({ error: 'Dependency version not found' });
    }

    const dvDependencyId = (dv as any).dependency_id;
    const dvVersion = (dv as any).version;

    // Get the package name from the dependencies table
    const { data: dep, error: depError } = await supabase
      .from('dependencies')
      .select('name')
      .eq('id', dvDependencyId)
      .single();

    if (depError || !dep) {
      return res.status(404).json({ error: 'Dependency not found' });
    }
    const packageName = (dep as any).name;

    // 2. Check if edges already exist for this version
    const { data: existingEdges, error: edgesError } = await supabase
      .from('dependency_version_edges')
      .select('child_version_id')
      .eq('parent_version_id', dependencyVersionId);

    if (edgesError) throw edgesError;

    let childVersionIds: string[] = (existingEdges || []).map((e: any) => e.child_version_id);

    // 3. If no edges exist, use pacote to resolve dependencies from the npm registry
    if (childVersionIds.length === 0) {
      try {
        const manifest = await pacote.manifest(`${packageName}@${dvVersion}`, {
          fullMetadata: false,
        });

        const deps = manifest.dependencies || {};
        const depEntries = Object.entries(deps);

        if (depEntries.length > 0) {
          // For each dependency, upsert into dependencies and dependency_versions, then create edges
          const edgesToInsert: Array<{ parent_version_id: string; child_version_id: string }> = [];

          for (const [childName, childRange] of depEntries) {
            // Resolve the actual version from the registry for this range
            let resolvedVersion: string;
            try {
              const childManifest = await pacote.manifest(`${childName}@${childRange}`, {
                fullMetadata: false,
              });
              resolvedVersion = childManifest.version;
            } catch {
              // If we can't resolve, skip this dependency
              continue;
            }

            // Upsert the child dependency
            const { data: childDep } = await supabase
              .from('dependencies')
              .upsert({ name: childName }, { onConflict: 'name', ignoreDuplicates: true })
              .select('id')
              .single();

            if (!childDep) {
              // If upsert returned nothing, fetch it
              const { data: existingDep } = await supabase
                .from('dependencies')
                .select('id')
                .eq('name', childName)
                .single();
              if (!existingDep) continue;

              // Upsert the child dependency version
              const { data: childDv } = await supabase
                .from('dependency_versions')
                .upsert(
                  { dependency_id: (existingDep as any).id, version: resolvedVersion },
                  { onConflict: 'dependency_id,version', ignoreDuplicates: true }
                )
                .select('id')
                .single();

              if (!childDv) {
                const { data: existingDv } = await supabase
                  .from('dependency_versions')
                  .select('id')
                  .eq('dependency_id', (existingDep as any).id)
                  .eq('version', resolvedVersion)
                  .single();
                if (existingDv) {
                  edgesToInsert.push({ parent_version_id: dependencyVersionId, child_version_id: (existingDv as any).id });
                }
              } else {
                edgesToInsert.push({ parent_version_id: dependencyVersionId, child_version_id: (childDv as any).id });
              }
            } else {
              // Upsert the child dependency version
              const { data: childDv } = await supabase
                .from('dependency_versions')
                .upsert(
                  { dependency_id: (childDep as any).id, version: resolvedVersion },
                  { onConflict: 'dependency_id,version', ignoreDuplicates: true }
                )
                .select('id')
                .single();

              if (!childDv) {
                const { data: existingDv } = await supabase
                  .from('dependency_versions')
                  .select('id')
                  .eq('dependency_id', (childDep as any).id)
                  .eq('version', resolvedVersion)
                  .single();
                if (existingDv) {
                  edgesToInsert.push({ parent_version_id: dependencyVersionId, child_version_id: (existingDv as any).id });
                }
              } else {
                edgesToInsert.push({ parent_version_id: dependencyVersionId, child_version_id: (childDv as any).id });
              }
            }
          }

          // Bulk upsert edges
          if (edgesToInsert.length > 0) {
            await supabase
              .from('dependency_version_edges')
              .upsert(edgesToInsert, { onConflict: 'parent_version_id,child_version_id', ignoreDuplicates: true });
          }

          // Re-fetch edges now that they've been inserted
          const { data: newEdges } = await supabase
            .from('dependency_version_edges')
            .select('child_version_id')
            .eq('parent_version_id', dependencyVersionId);

          childVersionIds = (newEdges || []).map((e: any) => e.child_version_id);
        }
      } catch (pacoteError: any) {
        console.error(`Pacote error resolving ${packageName}@${dvVersion}:`, pacoteError.message);
        // Continue with empty children rather than failing the entire request
      }
    }

    // 4. Build the children array (same logic as the main supply chain endpoint)
    let children: Array<{
      name: string;
      version: string;
      dependency_version_id: string;
      score: number | null;
      license: string | null;
      critical_vulns: number;
      high_vulns: number;
      medium_vulns: number;
      low_vulns: number;
      vulnerabilities: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[] }>;
    }> = [];

    if (childVersionIds.length > 0) {
      const BATCH_SIZE = 100;
      const allChildVersions: any[] = [];
      for (let i = 0; i < childVersionIds.length; i += BATCH_SIZE) {
        const batch = childVersionIds.slice(i, i + BATCH_SIZE);
        const { data: dvRows, error: dvBatchError } = await supabase
          .from('dependency_versions')
          .select('id, dependency_id, version')
          .in('id', batch);
        if (dvBatchError) throw dvBatchError;
        if (dvRows) allChildVersions.push(...dvRows);
      }

      const depIds = [...new Set(allChildVersions.map((d: any) => d.dependency_id).filter(Boolean))];
      const depIdToName = new Map<string, string>();
      const depIdToScore2 = new Map<string, number | null>();
      const depIdToLicense2 = new Map<string, string | null>();
      for (let i = 0; i < depIds.length; i += BATCH_SIZE) {
        const batch = depIds.slice(i, i + BATCH_SIZE);
        const { data: depRows, error: depBatchError } = await supabase
          .from('dependencies')
          .select('id, name, score, license')
          .in('id', batch);
        if (depBatchError) throw depBatchError;
        if (depRows) for (const row of depRows) {
          depIdToName.set(row.id, row.name);
          depIdToScore2.set(row.id, (row as any).score ?? null);
          depIdToLicense2.set(row.id, (row as any).license ?? null);
        }
      }

      const depIdToVulns = new Map<string, any[]>();
      for (let i = 0; i < depIds.length; i += BATCH_SIZE) {
        const batch = depIds.slice(i, i + BATCH_SIZE);
        const { data: vulnRows, error: vulnBatchError } = await supabase
          .from('dependency_vulnerabilities')
          .select('dependency_id, osv_id, severity, summary, aliases, affected_versions, fixed_versions')
          .in('dependency_id', batch);
        if (vulnBatchError) throw vulnBatchError;
        if (vulnRows) {
          for (const v of vulnRows) {
            if (!depIdToVulns.has(v.dependency_id)) depIdToVulns.set(v.dependency_id, []);
            depIdToVulns.get(v.dependency_id)!.push(v);
          }
        }
      }

      children = allChildVersions.map((d: any) => {
        const name = depIdToName.get(d.dependency_id) || 'unknown';
        const version = d.version;
        const allVulns = depIdToVulns.get(d.dependency_id) || [];
        const vulnerabilities = allVulns
          .filter((v: any) => isVersionAffected(version, v.affected_versions) && !isVersionFixed(version, v.fixed_versions ?? []))
          .map((v: any) => ({
            osv_id: v.osv_id,
            severity: v.severity ?? 'unknown',
            summary: v.summary ?? null,
            aliases: v.aliases ?? [],
          }));

        const critical_vulns = vulnerabilities.filter((v: any) => v.severity === 'critical').length;
        const high_vulns = vulnerabilities.filter((v: any) => v.severity === 'high').length;
        const medium_vulns = vulnerabilities.filter((v: any) => v.severity === 'medium').length;
        const low_vulns = vulnerabilities.filter((v: any) => v.severity === 'low').length;

        return {
          name,
          version,
          dependency_version_id: d.id,
          score: depIdToScore2.get(d.dependency_id) ?? null,
          license: depIdToLicense2.get(d.dependency_id) ?? null,
          critical_vulns,
          high_vulns,
          medium_vulns,
          low_vulns,
          vulnerabilities,
        };
      });

      children.sort((a, b) => {
        const aVulns = a.vulnerabilities.length;
        const bVulns = b.vulnerabilities.length;
        if (aVulns !== bVulns) return bVulns - aVulns;
        return a.name.localeCompare(b.name);
      });
    }

    // Parent vulnerabilities for this specific version (only those that affect dvVersion)
    let parentVulnerabilities: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[]; affected_versions: unknown; fixed_versions: string[] }> = [];
    const { data: parentVulnRows } = await supabase
      .from('dependency_vulnerabilities')
      .select('osv_id, severity, summary, aliases, affected_versions, fixed_versions')
      .eq('dependency_id', dvDependencyId);
    if (parentVulnRows) {
      const mapped = parentVulnRows.map((v: any) => ({
        osv_id: v.osv_id,
        severity: v.severity ?? 'unknown',
        summary: v.summary ?? null,
        aliases: v.aliases ?? [],
        affected_versions: v.affected_versions ?? null,
        fixed_versions: v.fixed_versions ?? [],
      }));
      parentVulnerabilities = mapped.filter(
        (v) => isVersionAffected(dvVersion, v.affected_versions) && !isVersionFixed(dvVersion, v.fixed_versions)
      );
    }

    res.json({
      version: dvVersion,
      children,
      vulnerabilities: parentVulnerabilities,
    });
  } catch (error: any) {
    console.error('Error fetching supply chain for version:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch supply chain for version' });
  }
});

// ============================================================================
// GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/supply-chain/latest-safe-version
// Calculate the latest safe version for a dependency by checking vulnerabilities
// across versions and their transitive dependencies.
// ============================================================================
router.get('/:id/projects/:projectId/dependencies/:projectDependencyId/supply-chain/latest-safe-version', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;
    const severityParam = (req.query.severity as string || 'high').toLowerCase() as 'critical' | 'high' | 'medium' | 'low';
    const excludeBanned = req.query.exclude_banned === 'true';
    const skipCache = req.query.refresh === 'true';

    // Validate severity param
    const validSeverities = ['critical', 'high', 'medium', 'low'];
    if (!validSeverities.includes(severityParam)) {
      return res.status(400).json({ error: 'severity must be one of: critical, high, medium, low' });
    }

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const result = await calculateLatestSafeVersion({
      organizationId: id,
      projectId,
      projectDependencyId,
      severity: severityParam,
      excludeBanned,
      skipCache,
    });

    res.json(result);
  } catch (error: any) {
    console.error('Error calculating latest safe version:', error);
    if (error.message === 'Project dependency not found' || error.message === 'Dependency version not found' || error.message === 'Dependency not found') {
      return res.status(404).json({ error: error.message });
    }
    if (error.message === 'severity must be one of: critical, high, medium, low') {
      return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: error.message || 'Failed to calculate latest safe version' });
  }
});

// PATCH /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/watching - Toggle watchtower watching for a dependency (org-level)
router.patch('/:id/projects/:projectId/dependencies/:dependencyId/watching', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;
    const { is_watching } = req.body;

    if (typeof is_watching !== 'boolean') {
      return res.status(400).json({ error: 'is_watching must be a boolean' });
    }

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const canManage = await checkWatchtowerManagePermission(userId, id, projectId);
    if (!canManage) {
      return res.status(403).json({ error: 'You do not have permission to manage Watchtower. Org-level manage teams & projects or team-level manage projects is required.' });
    }

    // Get dependency details (project_dependency row: need name, version; resolve package dependency_id for watchlist)
    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, version, dependency_version_id')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError) {
      if (detailsError.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    // Invalidate watchtower summary cache first so the next summary fetch is never stale (fixes re-enable showing old "ready" from cache)
    await invalidateWatchtowerSummaryCache(depDetails.name, dependencyId).catch((err: any) => {
      console.warn('[Cache] Failed to invalidate watchtower summary on watching toggle:', err?.message);
    });

    // Resolve package dependency_id (dependencies.id) for organization_watchlist
    let packageDependencyId: string | null = null;
    if (depDetails.dependency_version_id) {
      const { data: dv } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', depDetails.dependency_version_id)
        .single();
      if (dv) packageDependencyId = (dv as any).dependency_id;
    }
    if (!packageDependencyId) {
      const { data: depByName } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', depDetails.name)
        .limit(1)
        .single();
      if (depByName) packageDependencyId = (depByName as any).id;
    }

    // Update organization_watchlist (org-level watching, by dependency_id)
    if (is_watching) {
      if (!packageDependencyId) {
        return res.status(400).json({ error: 'Could not resolve package for watchlist' });
      }
      const npmLatest = await fetchLatestNpmVersion(depDetails.name);
      const latestAllowedVersion = npmLatest.latest_version ?? depDetails.version;
      const { error: insertError } = await supabase
        .from('organization_watchlist')
        .insert({
          organization_id: organizationId,
          dependency_id: packageDependencyId,
          watchtower_cleared_at: null,
          latest_allowed_version: latestAllowedVersion,
        });
      if (insertError && insertError.code !== '23505') throw insertError; // 23505 = unique violation, row exists
    } else {
      let clearedCommitDepId: string | null = packageDependencyId;
      if (packageDependencyId) {
        const { error: deleteError } = await supabase
          .from('organization_watchlist')
          .delete()
          .eq('organization_id', organizationId)
          .eq('dependency_id', packageDependencyId);
        if (deleteError) throw deleteError;
      } else {
        const { data: depByName } = await supabase
          .from('dependencies')
          .select('id')
          .eq('name', depDetails.name)
          .limit(1)
          .single();
        if (depByName) {
          clearedCommitDepId = (depByName as any).id;
          await supabase
            .from('organization_watchlist')
            .delete()
            .eq('organization_id', organizationId)
            .eq('dependency_id', (depByName as any).id);
        }
      }
      if (clearedCommitDepId) {
        await supabase
          .from('organization_watchlist_cleared_commits')
          .delete()
          .eq('organization_id', organizationId)
          .eq('dependency_id', clearedCommitDepId);
      }
    }

    // If enabling watching, upsert into watched_packages and queue worker job
    if (is_watching && depDetails) {
      // 1. Resolve dependency_id from dependencies table (or insert if missing)
      // We need to ensure the package exists in the central 'dependencies' table first
      let dependencyIdForWatch: string | null = null;

      const { data: existingDep, error: depError } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', depDetails.name)
        .eq('version', depDetails.version)
        .single();

      if (existingDep) {
        dependencyIdForWatch = existingDep.id;
      } else {
        // Try getting just by name (any version) as fallback if exact version missing
        const { data: anyDep } = await supabase
          .from('dependencies')
          .select('id')
          .eq('name', depDetails.name)
          .limit(1)
          .single();

        if (anyDep) {
          dependencyIdForWatch = anyDep.id;
        } else {
          // Insert new dependency entry
          const { data: newDep, error: insertDepError } = await supabase
            .from('dependencies')
            .insert({
              name: depDetails.name,
              license: (depDetails as { license?: string }).license ?? null,
            })
            .select('id')
            .single();

          if (newDep) {
            dependencyIdForWatch = newDep.id;
          } else if (insertDepError) {
            console.error('Failed to create dependency entry for watch:', insertDepError);
          }
        }
      }

      if (dependencyIdForWatch) {
        // 2. Upsert into watched_packages using dependency_id
        const { data: existingPkg, error: checkError } = await supabase
          .from('watched_packages')
          .select('id, status')
          .eq('dependency_id', dependencyIdForWatch)
          .single();

        let watchedPkgId: string | null = null;
        let shouldQueueJob = false;

        if ((checkError && checkError.code === 'PGRST116') || !existingPkg) {
          // Package doesn't exist: fetch latest from npm, update dependencies by name, then insert watched_package
          const npmLatest = await fetchLatestNpmVersion(depDetails.name);
          await supabase
            .from('dependencies')
            .update({
              ...(npmLatest.latest_version && { latest_version: npmLatest.latest_version }),
              ...(npmLatest.latest_release_date && { latest_release_date: npmLatest.latest_release_date }),
            })
            .eq('name', depDetails.name);
          const { data: newPkg, error: insertError } = await supabase
            .from('watched_packages')
            .insert({
              dependency_id: dependencyIdForWatch,
              status: 'pending',
              updated_at: new Date().toISOString(),
            })
            .select('id')
            .single();

          if (insertError) {
            console.error('Failed to insert watched_packages:', insertError);
          } else if (newPkg) {
            watchedPkgId = newPkg.id;
            shouldQueueJob = true; // First project to watch this package
            console.log(`First project to watch ${depDetails.name}, will queue analysis job`);
          }
        } else if (existingPkg) {
          // Package already exists
          watchedPkgId = existingPkg.id;

          // Only queue job if status is 'error' (retry) - don't queue if already 'analyzing' or 'ready'
          if (existingPkg.status === 'error') {
            // Reset to pending and retry
            await supabase
              .from('watched_packages')
              .update({ status: 'pending', error_message: null, updated_at: new Date().toISOString() })
              .eq('id', existingPkg.id);
            shouldQueueJob = true;
            console.log(`Retrying analysis for ${depDetails.name} (was in error state)`);
          } else {
            console.log(`Package ${depDetails.name} already watched with status '${existingPkg.status}', skipping job queue`);
          }
        }

        // Queue watchtower job via Redis only if this is a new package or needs retry
        if (watchedPkgId && shouldQueueJob) {
          const queueResult = await queueWatchtowerJob({
            packageName: depDetails.name,
            watchedPackageId: watchedPkgId,
            projectDependencyId: dependencyId,
            currentVersion: depDetails.version,
          });
          if (!queueResult.success) {
            console.warn(`Failed to queue Watchtower job for ${depDetails.name}: ${queueResult.error}`);
          }
        }
      } else {
        console.error(`Could not resolve dependency_id for ${depDetails.name}, skipping watch setup`);
      }
    }

    // If disabling watching, check if any other orgs are still watching this package (by dependency_id)
    if (!is_watching && depDetails && packageDependencyId) {
      const { count, error: countError } = await supabase
        .from('organization_watchlist')
        .select('id', { count: 'exact', head: true })
        .eq('dependency_id', packageDependencyId);

      if (countError) {
        console.error('Failed to count orgs watching package:', countError);
      } else if (count === 0) {
        const { error: deleteError } = await supabase
          .from('watched_packages')
          .delete()
          .eq('dependency_id', packageDependencyId);

        if (deleteError) {
          console.error('Failed to delete from watched_packages:', deleteError);
        } else {
          console.log(`Removed ${depDetails.name} from watched_packages (no longer watched by any org)`);
        }
      }
    }

    await invalidateDependenciesCache(id, projectId).catch((err: any) => {
      console.warn('[Cache] Failed to invalidate dependencies cache on watching toggle:', err?.message);
    });
    res.json({ id: dependencyId, is_watching });
  } catch (error: any) {
    console.error('Error updating dependency watching status:', error);
    res.status(500).json({ error: error.message || 'Failed to update watching status' });
  }
});

// PATCH /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/clear-commits - Clear watchtower commits for a dependency (org-level)
router.patch('/:id/projects/:projectId/dependencies/:dependencyId/clear-commits', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const canManage = await checkWatchtowerManagePermission(userId, id, projectId);
    if (!canManage) {
      return res.status(403).json({ error: 'You do not have permission to clear commits. Org-level manage teams & projects or team-level manage projects is required.' });
    }

    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, dependency_version_id')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError || !depDetails) {
      if (detailsError?.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    let packageDependencyId: string | null = null;
    if ((depDetails as any).dependency_version_id) {
      const { data: dv } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', (depDetails as any).dependency_version_id)
        .single();
      if (dv) packageDependencyId = (dv as any).dependency_id;
    }
    if (!packageDependencyId) {
      const { data: d } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', depDetails.name)
        .limit(1)
        .single();
      if (d) packageDependencyId = (d as any).id;
    }
    if (!packageDependencyId) {
      return res.status(400).json({ error: 'Could not resolve package for watchlist' });
    }

    const clearedAt = new Date().toISOString();
    const { error: upsertError } = await supabase
      .from('organization_watchlist')
      .upsert(
        { organization_id: organizationId, dependency_id: packageDependencyId, watchtower_cleared_at: clearedAt },
        { onConflict: 'organization_id,dependency_id' }
      );

    if (upsertError) throw upsertError;

    await supabase
      .from('organization_watchlist_cleared_commits')
      .delete()
      .eq('organization_id', organizationId)
      .eq('dependency_id', packageDependencyId);

    await invalidateDependenciesCache(id, projectId).catch((err: any) => {
      console.warn('[Cache] Failed to invalidate dependencies cache on clear-commits:', err?.message);
    });
    res.json({ id: dependencyId, watchtower_cleared_at: clearedAt });
  } catch (error: any) {
    console.error('Error clearing watchtower commits:', error);
    res.status(500).json({ error: error.message || 'Failed to clear commits' });
  }
});

// POST /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/cleared-commits - Mark a single commit as cleared (acknowledged)
router.post('/:id/projects/:projectId/dependencies/:dependencyId/cleared-commits', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;
    const { commit_sha } = req.body as { commit_sha?: string };

    if (!commit_sha || typeof commit_sha !== 'string' || !commit_sha.trim()) {
      return res.status(400).json({ error: 'commit_sha is required' });
    }

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const canManage = await checkWatchtowerManagePermission(userId, id, projectId);
    if (!canManage) {
      return res.status(403).json({ error: 'You do not have permission to acknowledge commits. Org-level manage teams & projects or team-level manage projects is required.' });
    }

    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, dependency_id, dependency_version_id')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError || !depDetails) {
      if (detailsError?.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    let packageDependencyId: string | null = (depDetails as any).dependency_id ?? null;
    if (!packageDependencyId) {
      const { data: dv } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', (depDetails as any).dependency_version_id)
        .single();
      if (dv) packageDependencyId = (dv as any).dependency_id;
    }
    if (!packageDependencyId) {
      const { data: d } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', (depDetails as any).name)
        .limit(1)
        .single();
      if (d) packageDependencyId = (d as any).id;
    }
    if (!packageDependencyId) {
      return res.status(400).json({ error: 'Could not resolve dependency_id for this project dependency' });
    }

    const { error: insertError } = await supabase
      .from('organization_watchlist_cleared_commits')
      .upsert(
        {
          organization_id: organizationId,
          dependency_id: packageDependencyId,
          commit_sha: commit_sha.trim(),
          cleared_at: new Date().toISOString(),
        },
        { onConflict: 'organization_id,dependency_id,commit_sha' }
      );

    if (insertError) throw insertError;

    res.status(204).send();
  } catch (error: any) {
    console.error('Error clearing single watchtower commit:', error);
    res.status(500).json({ error: error.message || 'Failed to clear commit' });
  }
});

/**
 * Update a dependency version in package.json (dependencies or devDependencies).
 * Preserves range prefix (^ or ~) if the current value has one, so e.g. "^18.2.0" -> "^18.3.2".
 */
function updatePackageJsonDependency(
  packageJsonStr: string,
  packageName: string,
  targetVersion: string
): { content: string } | { error: string } {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(packageJsonStr);
  } catch {
    return { error: 'Invalid package.json' };
  }
  const dep = pkg.dependencies?.[packageName];
  const devDep = pkg.devDependencies?.[packageName];
  const current = dep ?? devDep;
  if (current === undefined) {
    return { error: 'This dependency is transitive; only direct dependencies can be bumped via PR.' };
  }
  // Preserve ^ or ~ from current value so Dependabot and install behavior stay consistent
  const prefix = current.startsWith('^') ? '^' : current.startsWith('~') ? '~' : '';
  const versionToWrite = prefix + targetVersion.replace(/^[\^~]/, '');
  if (dep !== undefined) {
    pkg.dependencies = { ...pkg.dependencies, [packageName]: versionToWrite };
  } else {
    pkg.devDependencies = { ...pkg.devDependencies, [packageName]: versionToWrite };
  }
  return { content: JSON.stringify(pkg, null, 2) };
}

// POST /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/watchtower/bump - Create PR to bump dependency (body.target_version optional; else uses org latest allowed)
router.post('/:id/projects/:projectId/dependencies/:dependencyId/watchtower/bump', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;
    const bodyTargetVersion = typeof (req.body as any)?.target_version === 'string' ? (req.body as any).target_version.trim() : null;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, version, dependency_version_id')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError || !depDetails) {
      if (detailsError?.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    let packageDependencyId: string | null = null;
    if ((depDetails as any).dependency_version_id) {
      const { data: dv } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', (depDetails as any).dependency_version_id)
        .single();
      if (dv) packageDependencyId = (dv as any).dependency_id;
    }
    if (!packageDependencyId) {
      const { data: d } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', depDetails.name)
        .limit(1)
        .single();
      if (d) packageDependencyId = (d as any).id;
    }
    if (!packageDependencyId) {
      return res.status(400).json({ error: 'Could not resolve package for watchlist' });
    }

    let targetVersion: string | null = bodyTargetVersion || null;
    if (!targetVersion) {
      const { data: watchlistRow } = await supabase
        .from('organization_watchlist')
        .select('latest_allowed_version')
        .eq('organization_id', organizationId)
        .eq('dependency_id', packageDependencyId)
        .maybeSingle();
      targetVersion = (watchlistRow as any)?.latest_allowed_version ?? null;
      if (!targetVersion) {
        return res.status(400).json({ error: 'No latest allowed version set for this package. Set it in organization watchlist or re-enable watching, or pass target_version in the request body.' });
      }
    }

    const bumpResult = await createBumpPrForProject(
      organizationId,
      projectId,
      depDetails.name,
      targetVersion,
      depDetails.version
    );
    if ('error' in bumpResult) {
      return res.status(400).json({ error: bumpResult.error });
    }
    const { data: existingBumpPr } = await supabase
      .from('dependency_prs')
      .select('pr_url, pr_number')
      .eq('project_id', projectId)
      .eq('dependency_id', packageDependencyId)
      .eq('type', 'bump')
      .eq('target_version', targetVersion)
      .maybeSingle();
    res.json({
      pr_url: bumpResult.pr_url,
      pr_number: bumpResult.pr_number,
      already_exists: !!existingBumpPr && (existingBumpPr as any).pr_url === bumpResult.pr_url,
    });
  } catch (error: any) {
    console.error('Error creating bump PR:', error);
    res.status(500).json({ error: error.message || 'Failed to create bump PR' });
  }
});

// POST /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/watchtower/decrease - Create PR to decrease dependency to org's latest allowed version
router.post('/:id/projects/:projectId/dependencies/:dependencyId/watchtower/decrease', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, version, dependency_version_id')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError || !depDetails) {
      if (detailsError?.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    let packageDependencyId: string | null = null;
    if ((depDetails as any).dependency_version_id) {
      const { data: dv } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', (depDetails as any).dependency_version_id)
        .single();
      if (dv) packageDependencyId = (dv as any).dependency_id;
    }
    if (!packageDependencyId) {
      const { data: d } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', depDetails.name)
        .limit(1)
        .single();
      if (d) packageDependencyId = (d as any).id;
    }
    if (!packageDependencyId) {
      return res.status(400).json({ error: 'Could not resolve package for watchlist' });
    }

    const { data: watchlistRow } = await supabase
      .from('organization_watchlist')
      .select('latest_allowed_version')
      .eq('organization_id', organizationId)
      .eq('dependency_id', packageDependencyId)
      .maybeSingle();

    const targetVersion = (watchlistRow as any)?.latest_allowed_version ?? null;
    if (!targetVersion) {
      return res.status(400).json({ error: 'No latest allowed version set for this package. Set it in organization watchlist or re-enable watching.' });
    }

    const { data: existingDecreasePr } = await supabase
      .from('dependency_prs')
      .select('pr_url, pr_number')
      .eq('project_id', projectId)
      .eq('dependency_id', packageDependencyId)
      .eq('type', 'decrease')
      .eq('target_version', targetVersion)
      .maybeSingle();
    if (existingDecreasePr) {
      return res.json({
        pr_url: (existingDecreasePr as any).pr_url,
        pr_number: (existingDecreasePr as any).pr_number,
        already_exists: true,
      });
    }

    const { data: orgRow } = await supabase
      .from('organizations')
      .select('github_installation_id')
      .eq('id', organizationId)
      .single();

    if (!orgRow?.github_installation_id) {
      return res.status(400).json({ error: 'Organization has no GitHub App connected.' });
    }

    const { data: repoRow } = await supabase
      .from('project_repositories')
      .select('repo_full_name, default_branch, installation_id, package_json_path')
      .eq('project_id', projectId)
      .maybeSingle();

    if (!repoRow?.repo_full_name || !repoRow?.default_branch) {
      return res.status(400).json({ error: 'Project has no GitHub repository connected.' });
    }

    const installationId = (repoRow as any).installation_id ?? orgRow.github_installation_id;
    const token = await createInstallationToken(installationId);
    const repoFullName = repoRow.repo_full_name;
    const defaultBranch = repoRow.default_branch;
    const packageJsonDir = (repoRow as { package_json_path?: string }).package_json_path ?? '';
    const packageJsonPath = packageJsonDir ? `${packageJsonDir}/package.json` : 'package.json';

    const { data: oldDecreasePrs } = await supabase
      .from('dependency_prs')
      .select('pr_number')
      .eq('project_id', projectId)
      .eq('dependency_id', packageDependencyId)
      .eq('type', 'decrease')
      .neq('target_version', targetVersion);
    if (oldDecreasePrs && Array.isArray(oldDecreasePrs)) {
      for (const row of oldDecreasePrs) {
        try {
          const prState = await getPullRequest(token, repoFullName, (row as any).pr_number);
          if (prState.state === 'open') {
            await closePullRequest(token, repoFullName, (row as any).pr_number);
          }
        } catch (e) {
          console.warn('Could not close old decrease PR:', (row as any).pr_number, e);
        }
      }
    }

    const fromSha = await getBranchSha(token, repoFullName, defaultBranch);
    const branchName = `deptex/decrease-${depDetails.name.replace(/[@/]/g, '-')}-${targetVersion}`;
    await createBranch(token, repoFullName, branchName, fromSha);

    const { content: currentContent, sha: fileSha } = await getRepositoryFileWithSha(
      token,
      repoFullName,
      packageJsonPath,
      branchName
    );
    const result = updatePackageJsonDependency(currentContent, depDetails.name, targetVersion);
    if ('error' in result) {
      return res.status(400).json({ error: result.error });
    }

    await createOrUpdateFileOnBranch(
      token,
      repoFullName,
      branchName,
      packageJsonPath,
      result.content,
      `chore(deps): decrease ${depDetails.name} to ${targetVersion}`,
      fileSha
    );

    const pr = await createPullRequest(
      token,
      repoFullName,
      defaultBranch,
      branchName,
      `Decrease ${depDetails.name} to ${targetVersion}`,
      `Downgrades \`${depDetails.name}\` from \`${depDetails.version}\` to \`${targetVersion}\` (organization's latest allowed version).`
    );

    await supabase.from('dependency_prs').insert({
      project_id: projectId,
      dependency_id: packageDependencyId,
      type: 'decrease',
      target_version: targetVersion,
      pr_url: pr.html_url,
      pr_number: pr.number,
      branch_name: branchName,
    });

    res.json({ pr_url: pr.html_url, pr_number: pr.number, already_exists: false });
  } catch (error: any) {
    console.error('Error creating decrease PR:', error);
    res.status(500).json({ error: error.message || 'Failed to create decrease PR' });
  }
});

// POST /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/remove-pr - Create PR to remove an unused (zombie) dependency
router.post('/:id/projects/:projectId/dependencies/:dependencyId/remove-pr', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, version, source, files_importing_count')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError || !depDetails) {
      if (detailsError?.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    const source = (depDetails as any).source;
    if (source !== 'dependencies' && source !== 'devDependencies') {
      return res.status(400).json({ error: 'Only direct dependencies can be removed via PR.' });
    }

    const filesImporting = (depDetails as any).files_importing_count ?? null;
    if (filesImporting !== 0) {
      return res.status(400).json({ error: 'This dependency is still imported in files. Only unused dependencies can be removed.' });
    }

    const result = await createRemovePrForProject(organizationId, projectId, depDetails.name);
    if ('error' in result) {
      return res.status(400).json({ error: result.error });
    }

    res.json({
      pr_url: result.pr_url,
      pr_number: result.pr_number,
      ...(result.already_exists && { already_exists: true }),
    });
  } catch (error: any) {
    console.error('Error creating remove PR:', error);
    res.status(500).json({ error: error.message || 'Failed to create remove PR' });
  }
});

// PATCH /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/watchlist-quarantine - Toggle quarantine next release (org-level)
router.patch('/:id/projects/:projectId/dependencies/:dependencyId/watchlist-quarantine', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, dependencyId } = req.params;
    const organizationId = id;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const canManage = await checkWatchtowerManagePermission(userId, id, projectId);
    if (!canManage) {
      return res.status(403).json({ error: 'You do not have permission to update quarantine. Org-level manage teams & projects or team-level manage projects is required.' });
    }

    const { data: depDetails, error: detailsError } = await supabase
      .from('project_dependencies')
      .select('id, name, dependency_version_id')
      .eq('id', dependencyId)
      .eq('project_id', projectId)
      .single();

    if (detailsError || !depDetails) {
      if (detailsError?.code === 'PGRST116') {
        return res.status(404).json({ error: 'Dependency not found' });
      }
      throw detailsError;
    }

    let packageDependencyId: string | null = null;
    if ((depDetails as any).dependency_version_id) {
      const { data: dv } = await supabase
        .from('dependency_versions')
        .select('dependency_id')
        .eq('id', (depDetails as any).dependency_version_id)
        .single();
      if (dv) packageDependencyId = (dv as any).dependency_id;
    }
    if (!packageDependencyId) {
      const { data: d } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', depDetails.name)
        .limit(1)
        .single();
      if (d) packageDependencyId = (d as any).id;
    }
    if (!packageDependencyId) {
      return res.status(400).json({ error: 'Could not resolve package for watchlist' });
    }

    const quarantine_next_release = req.body?.quarantine_next_release;
    if (typeof quarantine_next_release !== 'boolean') {
      return res.status(400).json({ error: 'Body must include quarantine_next_release (boolean)' });
    }

    const { data: watchlistRow, error: updateError } = await supabase
      .from('organization_watchlist')
      .update({ quarantine_next_release })
      .eq('organization_id', organizationId)
      .eq('dependency_id', packageDependencyId)
      .select('quarantine_next_release')
      .single();

    if (updateError) {
      if (updateError.code === 'PGRST116') {
        return res.status(404).json({ error: 'Package not in organization watchlist' });
      }
      throw updateError;
    }

    // Invalidate watchtower summary cache
    await invalidateWatchtowerSummaryCache(depDetails.name, dependencyId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate watchtower summary cache:`, err.message);
    });

    res.json({ quarantine_next_release: watchlistRow?.quarantine_next_release ?? quarantine_next_release });
  } catch (error: any) {
    console.error('Error updating watchlist quarantine:', error);
    res.status(500).json({ error: error.message || 'Failed to update quarantine' });
  }
});

// GET /api/organizations/:id/projects/:projectId/vulnerabilities - List all vulnerabilities for project dependencies
router.get('/:id/projects/:projectId/vulnerabilities', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Prefer project_dependency_vulnerabilities (reachable vulns from extraction worker) when available
    const { count: pdvCount } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('*', { count: 'exact', head: true })
      .eq('project_id', projectId);

    const usePdv = (pdvCount ?? 0) > 0;
    const rpcName = usePdv ? 'get_project_vulnerabilities_from_pdv' : 'get_project_vulnerabilities';
    const { data: rows, error: rpcError } = await supabase.rpc(rpcName, {
      p_project_id: projectId,
    });

    if (rpcError) {
      // Fallback if RPC not yet deployed: two queries (no per-dep batching)
      const { data: projectDeps, error: depsError } = await supabase
        .from('project_dependencies')
        .select('dependency_id, name, version')
        .eq('project_id', projectId);

      if (depsError) throw depsError;

      const dependencyIds = (projectDeps || [])
        .map((pd: any) => pd.dependency_id)
        .filter(Boolean);

      if (dependencyIds.length === 0) return res.json([]);

      const depInfoMap = new Map<string, { name: string; version: string }>();
      (projectDeps || []).forEach((pd: any) => {
        if (pd.dependency_id) depInfoMap.set(pd.dependency_id, { name: pd.name, version: pd.version });
      });

      const VULN_BATCH = 1000;
      const allVulnerabilities: any[] = [];
      for (let i = 0; i < dependencyIds.length; i += VULN_BATCH) {
        const batch = dependencyIds.slice(i, i + VULN_BATCH);
        const { data: vulns, error: vulnsError } = await supabase
          .from('dependency_vulnerabilities')
          .select('id, dependency_id, osv_id, severity, summary, details, aliases, fixed_versions, published_at, modified_at, created_at')
          .in('dependency_id', batch)
          .order('severity', { ascending: true })
          .order('published_at', { ascending: false, nullsFirst: false });
        if (vulnsError) throw vulnsError;
        if (vulns) allVulnerabilities.push(...vulns);
      }

      const enrichedVulnerabilities = allVulnerabilities.map((vuln: any) => {
        const depInfo = depInfoMap.get(vuln.dependency_id);
        return {
          id: vuln.id,
          osv_id: vuln.osv_id,
          severity: vuln.severity,
          summary: vuln.summary,
          details: vuln.details,
          aliases: vuln.aliases || [],
          fixed_versions: vuln.fixed_versions || [],
          published_at: vuln.published_at,
          modified_at: vuln.modified_at,
          dependency_id: vuln.dependency_id,
          dependency_name: depInfo?.name || 'Unknown',
          dependency_version: depInfo?.version || 'Unknown',
        };
      });

      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      enrichedVulnerabilities.sort((a, b) => {
        const severityDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
        if (severityDiff !== 0) return severityDiff;
        return new Date(b.published_at || 0).getTime() - new Date(a.published_at || 0).getTime();
      });
      return res.json(enrichedVulnerabilities);
    }

    const enrichedVulnerabilities = (rows || []).map((vuln: any) => ({
      id: vuln.id,
      osv_id: vuln.osv_id,
      severity: vuln.severity,
      summary: vuln.summary,
      details: vuln.details ?? null,
      aliases: vuln.aliases || [],
      fixed_versions: vuln.fixed_versions || [],
      published_at: vuln.published_at,
      modified_at: vuln.modified_at,
      dependency_id: vuln.dependency_id,
      dependency_name: vuln.dependency_name ?? 'Unknown',
      dependency_version: vuln.dependency_version ?? 'Unknown',
      ...(usePdv && {
        is_reachable: vuln.is_reachable ?? true,
        epss_score: vuln.epss_score,
        cvss_score: vuln.cvss_score ?? null,
        cisa_kev: vuln.cisa_kev ?? false,
        depscore: vuln.depscore ?? null,
      }),
    }));

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    enrichedVulnerabilities.sort((a: any, b: any) => {
      const aScore = a.depscore ?? -1;
      const bScore = b.depscore ?? -1;
      if (aScore !== bScore) return bScore - aScore;
      const severityDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
      if (severityDiff !== 0) return severityDiff;
      return new Date(b.published_at || 0).getTime() - new Date(a.published_at || 0).getTime();
    });

    res.json(enrichedVulnerabilities);
  } catch (error: any) {
    console.error('Error fetching project vulnerabilities:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch project vulnerabilities' });
  }
});

// GET /api/organizations/:id/projects/:projectId/import-status - Check import completion status
router.get('/:id/projects/:projectId/import-status', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get project repository status, extraction progress, and AST completion
    const { data: repoRecord } = await supabase
      .from('project_repositories')
      .select('status, ast_parsed_at, extraction_step, extraction_error')
      .eq('project_id', projectId)
      .single();

    if (!repoRecord) {
      return res.json({
        status: 'not_connected',
        total: 0,
        ready: 0,
        analyzing: 0,
        pending: 0,
        error: 0,
        extraction_step: null,
        extraction_error: null,
      });
    }

    const astParsedAt = (repoRecord as any).ast_parsed_at ?? null;

    // Only direct dependencies get populated (license, GHSA, registry). Use those for the analyzing progress.
    const { data: projectDeps } = await supabase
      .from('project_dependencies')
      .select('dependency_id, is_direct')
      .eq('project_id', projectId);

    const directDepIds = [...new Set((projectDeps || [])
      .filter((pd: any) => pd.is_direct === true && pd.dependency_id)
      .map((pd: any) => pd.dependency_id))];

    if (directDepIds.length === 0) {
      // No deps: still show finalizing if AST not yet run for this repo
      const status =
        (repoRecord.status === 'ready' || repoRecord.status === 'analyzing') && !astParsedAt
          ? 'finalizing'
          : repoRecord.status;
      return res.json({
        status,
        total: 0,
        ready: 0,
        analyzing: 0,
        pending: 0,
        error: 0,
        extraction_step: (repoRecord as any).extraction_step ?? null,
        extraction_error: (repoRecord as any).extraction_error ?? null,
      });
    }

    // Count by status from dependencies table (package-level reputation score status)
    const counts = {
      ready: 0,
      analyzing: 0,
      pending: 0,
      error: 0,
    };

    const BATCH_SIZE = 100;
    for (let i = 0; i < directDepIds.length; i += BATCH_SIZE) {
      const batch = directDepIds.slice(i, i + BATCH_SIZE);
      const { data: statusRows, error: scError } = await supabase
        .from('dependencies')
        .select('id, status')
        .in('id', batch);

      if (scError) {
        console.error('Error fetching dependency statuses:', scError);
        continue;
      }

      const foundIds = new Set((statusRows || []).map((d: any) => String(d.id).toLowerCase()));
      for (const did of batch) {
        const key = String(did).toLowerCase();
        if (!foundIds.has(key)) {
          counts.pending++;
          continue;
        }
        const row = (statusRows || []).find((d: any) => String(d.id).toLowerCase() === key);
        if (row && (row as any).status in counts) {
          counts[(row as any).status as keyof typeof counts]++;
        }
      }
    }

    const total = directDepIds.length;
    const allReady = counts.ready === total && total > 0;

    // When all deps are ready: if AST not yet done, status is finalizing; else ready
    let effectiveStatus: string = repoRecord.status;
    if (allReady) {
      if (!astParsedAt) {
        effectiveStatus = 'finalizing';
        await supabase
          .from('project_repositories')
          .update({ status: 'finalizing', updated_at: new Date().toISOString() })
          .eq('project_id', projectId);
      } else {
        effectiveStatus = 'ready';
        await supabase
          .from('project_repositories')
          .update({ status: 'ready', updated_at: new Date().toISOString() })
          .eq('project_id', projectId);
      }
    } else if (repoRecord.status === 'analyzing' && !allReady) {
      // Keep analyzing while deps are still being analyzed
      effectiveStatus = 'analyzing';
    }

    res.json({
      status: effectiveStatus,
      total,
      ...counts,
      extraction_step: (repoRecord as any).extraction_step ?? null,
      extraction_error: (repoRecord as any).extraction_error ?? null,
    });
  } catch (error: any) {
    console.error('Error fetching import status:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch import status' });
  }
});

// POST /api/organizations/:id/projects/:projectId/requeue-ast - Requeue AST parsing for import analysis
router.post('/:id/projects/:projectId/requeue-ast', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgPermission = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;
    if (!isOrgOwner && !hasOrgPermission) {
      return res.status(403).json({ error: 'You do not have permission to requeue import analysis' });
    }

    const { data: repoRecord, error: repoError } = await supabase
      .from('project_repositories')
      .select('repo_full_name, installation_id, default_branch, package_json_path')
      .eq('project_id', projectId)
      .single();

    if (repoError || !repoRecord) {
      return res.status(400).json({ error: 'Project has no connected repository' });
    }

    const { queueASTParsingJob } = await import('../lib/redis');
    const queueResult = await queueASTParsingJob(projectId, {
      repo_full_name: repoRecord.repo_full_name,
      installation_id: repoRecord.installation_id,
      default_branch: repoRecord.default_branch,
      package_json_path: (repoRecord as { package_json_path?: string }).package_json_path ?? '',
    });

    if (!queueResult.success) {
      return res.status(502).json({ error: queueResult.error || 'Failed to queue AST parsing job' });
    }

    // Clear ast_parsed_at so status becomes finalizing until worker completes
    await supabase
      .from('project_repositories')
      .update({
        ast_parsed_at: null,
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', projectId);

    res.json({ success: true, message: 'AST parsing job queued' });
  } catch (error: any) {
    console.error('Error requeueing AST parsing:', error);
    res.status(500).json({ error: error.message || 'Failed to requeue AST parsing' });
  }
});

// ==================== Dependency Notes ====================

// Helper: resolve author profiles with auth.users fallback + org role info
async function resolveNoteAuthors(authorIds: string[], organizationId: string) {
  const authorMap = new Map<string, { full_name: string | null; avatar_url: string | null; org_role: string | null; org_role_display_name: string | null; org_role_color: string | null }>();
  if (authorIds.length === 0) return authorMap;

  // 1. user_profiles
  const { data: profiles } = await supabase
    .from('user_profiles')
    .select('user_id, full_name, avatar_url')
    .in('user_id', authorIds);

  const profileMap = new Map((profiles || []).map((p: any) => [p.user_id, p]));

  // 2. auth.users fallback for name/avatar
  const { data: authUsers } = await supabase.auth.admin.listUsers();
  const authUserMap = new Map(authUsers?.users?.map((u: any) => [u.id, u]) || []);

  // 3. organization_members for role
  const { data: orgMembers } = await supabase
    .from('organization_members')
    .select('user_id, role')
    .eq('organization_id', organizationId)
    .in('user_id', authorIds);

  const orgMemberMap = new Map((orgMembers || []).map((m: any) => [m.user_id, m.role]));

  // 4. organization_roles for display_name + color
  const uniqueRoles = [...new Set((orgMembers || []).map((m: any) => m.role).filter(Boolean))];
  let roleInfoMap = new Map<string, { display_name: string | null; color: string | null }>();
  if (uniqueRoles.length > 0) {
    const { data: roles } = await supabase
      .from('organization_roles')
      .select('name, display_name, color')
      .eq('organization_id', organizationId)
      .in('name', uniqueRoles);

    for (const r of roles || []) {
      roleInfoMap.set(r.name, { display_name: r.display_name, color: r.color });
    }
  }

  for (const uid of authorIds) {
    const profile = profileMap.get(uid);
    const authUser = authUserMap.get(uid);
    const orgRole = orgMemberMap.get(uid) || null;
    const roleInfo = orgRole ? roleInfoMap.get(orgRole) : null;

    authorMap.set(uid, {
      full_name: profile?.full_name
        || authUser?.user_metadata?.full_name
        || authUser?.user_metadata?.name
        || null,
      avatar_url: profile?.avatar_url
        || authUser?.user_metadata?.avatar_url
        || authUser?.user_metadata?.picture
        || null,
      org_role: orgRole,
      org_role_display_name: roleInfo?.display_name || null,
      org_role_color: roleInfo?.color || null,
    });
  }

  return authorMap;
}

/** Whether the actor can delete the author's note (own note, or author ranked below actor per org/team hierarchy). */
async function canDeleteOtherMemberNote(
  actorId: string,
  authorId: string,
  organizationId: string,
  projectId: string
): Promise<boolean> {
  if (actorId === authorId) return true;

  const { data: actorMembership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', actorId)
    .single();

  if (!actorMembership) return false;

  const isOrgOwnerOrAdmin = actorMembership.role === 'owner' || actorMembership.role === 'admin';
  let hasKickPermission = isOrgOwnerOrAdmin;
  if (!hasKickPermission) {
    const { data: orgRole } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', organizationId)
      .eq('name', actorMembership.role)
      .single();
    hasKickPermission = (orgRole?.permissions as any)?.kick_members === true;
  }
  if (!hasKickPermission) return false;

  const { data: authorMembership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', authorId)
    .single();

  if (!authorMembership) return false;

  const { data: actorOrgRole } = await supabase
    .from('organization_roles')
    .select('display_order')
    .eq('organization_id', organizationId)
    .eq('name', actorMembership.role)
    .single();

  const { data: authorOrgRole } = await supabase
    .from('organization_roles')
    .select('display_order')
    .eq('organization_id', organizationId)
    .eq('name', authorMembership.role)
    .single();

  const actorRank = actorOrgRole?.display_order ?? 999;
  const authorRank = authorOrgRole?.display_order ?? 999;

  if (authorRank > actorRank) return true;

  if (authorRank < actorRank) return false;

  // Same org rank: use project owner team seniority
  const { data: projectTeams } = await supabase
    .from('project_teams')
    .select('team_id')
    .eq('project_id', projectId)
    .eq('is_owner', true)
    .limit(1);

  const ownerEntry = projectTeams?.[0] as { team_id: string } | undefined;
  const ownerTeamId = ownerEntry?.team_id;
  if (!ownerTeamId) return false;

  const { data: actorTeamMember } = await supabase
    .from('team_members')
    .select('role_id')
    .eq('team_id', ownerTeamId)
    .eq('user_id', actorId)
    .single();

  const { data: authorTeamMember } = await supabase
    .from('team_members')
    .select('role_id')
    .eq('team_id', ownerTeamId)
    .eq('user_id', authorId)
    .single();

  if (!actorTeamMember?.role_id || !authorTeamMember?.role_id) return false;

  const { data: actorTeamRole } = await supabase
    .from('team_roles')
    .select('display_order')
    .eq('id', actorTeamMember.role_id)
    .single();

  const { data: authorTeamRole } = await supabase
    .from('team_roles')
    .select('display_order')
    .eq('id', authorTeamMember.role_id)
    .single();

  const actorTeamRank = actorTeamRole?.display_order ?? 999;
  const authorTeamRank = authorTeamRole?.display_order ?? 999;

  return authorTeamRank > actorTeamRank;
}

// GET notes for a dependency
router.get('/:id/projects/:projectId/dependencies/:projectDependencyId/notes', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const cacheKey = getDependencyNotesCacheKey(id, projectId, projectDependencyId, userId);
    const cached = await getCached<{ notes: any[] }>(cacheKey);
    if (cached != null) {
      return res.json(cached);
    }

    // Fetch notes for this dependency
    const { data: notes, error: notesError } = await supabase
      .from('dependency_notes')
      .select('id, content, is_warning, created_at, author_id')
      .eq('project_dependency_id', projectDependencyId)
      .order('created_at', { ascending: false });

    if (notesError) throw notesError;

    const noteIds = (notes || []).map((n: any) => n.id);
    type ReactionEntry = { emoji: string; count: number; user_reacted: boolean; reaction_id: string | null; reactor_user_ids: string[] };
    let reactionsByNote: Map<string, ReactionEntry[]> = new Map();
    if (noteIds.length > 0) {
      let reactions: any[] = [];
      try {
        const result = await supabase
          .from('dependency_note_reactions')
          .select('id, note_id, user_id, emoji')
          .in('note_id', noteIds);
        if (!result.error) reactions = result.data || [];
      } catch {
        // Table may not exist yet; continue with no reactions
      }

      if (reactions.length > 0) {
        for (const nid of noteIds) {
          const noteReactions = (reactions as any[]).filter((r) => r.note_id === nid);
          const byEmoji = new Map<string, { count: number; userReacted: boolean; reactionId: string | null; userIds: string[] }>();
          for (const r of noteReactions) {
            const existing = byEmoji.get(r.emoji);
            if (!existing) {
              byEmoji.set(r.emoji, {
                count: 1,
                userReacted: r.user_id === userId,
                reactionId: r.user_id === userId ? r.id : null,
                userIds: [r.user_id],
              });
            } else {
              existing.count += 1;
              existing.userIds.push(r.user_id);
              if (r.user_id === userId) {
                existing.userReacted = true;
                existing.reactionId = r.id;
              }
            }
          }
          reactionsByNote.set(
            nid,
            [...byEmoji.entries()].map(([emoji, v]) => ({
              emoji,
              count: v.count,
              user_reacted: v.userReacted,
              reaction_id: v.reactionId,
              reactor_user_ids: v.userIds,
            }))
          );
        }
      }
      for (const nid of noteIds) {
        if (!reactionsByNote.has(nid)) reactionsByNote.set(nid, []);
      }
    }

    // Resolve author profiles (note authors + reaction reactors) with fallback
    const authorIds = [...new Set((notes || []).map((n: any) => n.author_id).filter(Boolean))];
    const reactorIds = [...new Set([...reactionsByNote.values()].flatMap((arr) => arr.flatMap((r) => r.reactor_user_ids || [])))];
    const authorMap = await resolveNoteAuthors([...new Set([...authorIds, ...reactorIds])], id);

    const formattedNotes = await Promise.all(
      (notes || []).map(async (n: any) => {
        const author = authorMap.get(n.author_id);
        const canDelete =
          n.author_id === userId || (await canDeleteOtherMemberNote(userId, n.author_id, id, projectId));
        const noteReactions = (reactionsByNote.get(n.id) || []).map((r) => {
          const reactor_names = (r.reactor_user_ids || []).map((uid) =>
            uid === userId ? 'You' : (authorMap.get(uid)?.full_name || 'Someone')
          );
          return {
            emoji: r.emoji,
            count: r.count,
            user_reacted: r.user_reacted,
            reaction_id: r.reaction_id,
            reactor_names: reactor_names.length > 0 ? reactor_names : undefined,
          };
        });
        return {
          id: n.id,
          content: n.content,
          is_warning: n.is_warning,
          created_at: n.created_at,
          can_delete: canDelete,
          reactions: noteReactions,
          author: {
            id: n.author_id,
            name: author?.full_name || null,
            avatar_url: author?.avatar_url || null,
            org_role: author?.org_role || null,
            org_role_display_name: author?.org_role_display_name || null,
            org_role_color: author?.org_role_color || null,
          },
        };
      })
    );

    const payload = { notes: formattedNotes };
    await setCached(cacheKey, payload, CACHE_TTL_SECONDS.DEPENDENCY_NOTES);
    await registerDependencyNotesCacheKey(id, projectId, projectDependencyId, cacheKey);
    res.json(payload);
  } catch (error: any) {
    console.error('Error fetching dependency notes:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch dependency notes' });
  }
});

// POST create a note for a dependency
router.post('/:id/projects/:projectId/dependencies/:projectDependencyId/notes', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId } = req.params;
    const { content, is_warning } = req.body;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).json({ error: 'Note content is required' });
    }

    // Insert the note
    const { data: note, error: insertError } = await supabase
      .from('dependency_notes')
      .insert({
        project_dependency_id: projectDependencyId,
        author_id: userId,
        content: content.trim(),
        is_warning: is_warning === true,
      })
      .select('id, content, is_warning, created_at, author_id')
      .single();

    if (insertError) throw insertError;

    await invalidateDependencyNotesCache(id, projectId, projectDependencyId);

    // Resolve author info
    const authorMap = await resolveNoteAuthors([userId], id);
    const author = authorMap.get(userId);

    res.status(201).json({
      id: note.id,
      content: note.content,
      is_warning: note.is_warning,
      created_at: note.created_at,
      can_delete: true,
      author: {
        id: note.author_id,
        name: author?.full_name || null,
        avatar_url: author?.avatar_url || null,
        org_role: author?.org_role || null,
        org_role_display_name: author?.org_role_display_name || null,
        org_role_color: author?.org_role_color || null,
      },
    });
  } catch (error: any) {
    console.error('Error creating dependency note:', error);
    res.status(500).json({ error: error.message || 'Failed to create dependency note' });
  }
});

// DELETE a note (only your own)
router.delete('/:id/projects/:projectId/dependencies/:projectDependencyId/notes/:noteId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId, noteId } = req.params;

    // Check if user has access to this project
    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Fetch the note to verify ownership
    const { data: note, error: fetchError } = await supabase
      .from('dependency_notes')
      .select('id, author_id')
      .eq('id', noteId)
      .eq('project_dependency_id', projectDependencyId)
      .maybeSingle();

    if (fetchError) throw fetchError;

    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }

    if (note.author_id !== userId) {
      const canDelete = await canDeleteOtherMemberNote(userId, note.author_id, id, projectId);
      if (!canDelete) {
        return res.status(403).json({ error: 'You can only delete your own notes or notes by members ranked below you' });
      }
    }

    const { error: deleteError } = await supabase
      .from('dependency_notes')
      .delete()
      .eq('id', noteId);

    if (deleteError) throw deleteError;

    await invalidateDependencyNotesCache(id, projectId, projectDependencyId);

    res.json({ message: 'Note deleted' });
  } catch (error: any) {
    console.error('Error deleting dependency note:', error);
    res.status(500).json({ error: error.message || 'Failed to delete dependency note' });
  }
});

// POST add reaction to a note
router.post('/:id/projects/:projectId/dependencies/:projectDependencyId/notes/:noteId/reactions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId, noteId } = req.params;
    const { emoji } = req.body;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    if (!emoji || typeof emoji !== 'string' || emoji.trim().length === 0) {
      return res.status(400).json({ error: 'Emoji is required' });
    }

    const { data: note, error: fetchError } = await supabase
      .from('dependency_notes')
      .select('id')
      .eq('id', noteId)
      .eq('project_dependency_id', projectDependencyId)
      .maybeSingle();

    if (fetchError) throw fetchError;
    if (!note) return res.status(404).json({ error: 'Note not found' });

    const { data: reaction, error: insertError } = await supabase
      .from('dependency_note_reactions')
      .upsert(
        { note_id: noteId, user_id: userId, emoji: emoji.trim() },
        { onConflict: 'note_id,user_id,emoji' }
      )
      .select('id, note_id, user_id, emoji, created_at')
      .single();

    if (insertError) throw insertError;

    await invalidateDependencyNotesCache(id, projectId, projectDependencyId);

    res.status(201).json(reaction);
  } catch (error: any) {
    console.error('Error adding note reaction:', error);
    res.status(500).json({ error: error.message || 'Failed to add reaction' });
  }
});

// DELETE remove reaction from a note
router.delete('/:id/projects/:projectId/dependencies/:projectDependencyId/notes/:noteId/reactions/:reactionId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { id, projectId, projectDependencyId, noteId, reactionId } = req.params;

    const accessCheck = await checkProjectAccess(userId, id, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const { data: reaction, error: fetchError } = await supabase
      .from('dependency_note_reactions')
      .select('id, user_id, note_id')
      .eq('id', reactionId)
      .eq('note_id', noteId)
      .maybeSingle();

    if (fetchError) throw fetchError;
    if (!reaction) return res.status(404).json({ error: 'Reaction not found' });
    if ((reaction as any).user_id !== userId) {
      return res.status(403).json({ error: 'You can only remove your own reactions' });
    }

    const { error: deleteError } = await supabase
      .from('dependency_note_reactions')
      .delete()
      .eq('id', reactionId);

    if (deleteError) throw deleteError;

    await invalidateDependencyNotesCache(id, projectId, projectDependencyId);

    res.json({ message: 'Reaction removed' });
  } catch (error: any) {
    console.error('Error removing note reaction:', error);
    res.status(500).json({ error: error.message || 'Failed to remove reaction' });
  }
});

// ============================================================
// Banned Versions + Bump All (org-level, supply chain)
// ============================================================

// Helper: check org membership + manage_teams_and_projects permission
async function checkOrgManagePermission(userId: string, organizationId: string): Promise<{
  hasPermission: boolean;
  error?: { status: number; message: string };
}> {
  const { data: membership, error: membershipError } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (membershipError || !membership) {
    return { hasPermission: false, error: { status: 404, message: 'Organization not found or access denied' } };
  }

  if (membership.role === 'owner') {
    return { hasPermission: true };
  }

  const { data: orgRole } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();

  if (orgRole?.permissions?.manage_teams_and_projects === true) {
    return { hasPermission: true };
  }

  return { hasPermission: false, error: { status: 403, message: 'You do not have permission to manage versions for this organization' } };
}

// GET /api/organizations/:id/banned-versions?dependency_id=X&project_id=Z
// When project_id is provided, returns org bans + team bans for teams the project belongs to.
router.get('/:id/banned-versions', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.params.id;
    const filterDependencyId = (req.query.dependency_id as string | undefined) ?? null;
    const projectId = req.query.project_id as string | undefined;

    const { data: membership, error: membershipError } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', organizationId)
      .eq('user_id', userId)
      .single();

    if (membershipError || !membership) {
      return res.status(404).json({ error: 'Organization not found or access denied' });
    }

    let orgQuery = supabase
      .from('banned_versions')
      .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at')
      .eq('organization_id', organizationId)
      .order('created_at', { ascending: false });

    if (filterDependencyId) {
      orgQuery = orgQuery.eq('dependency_id', filterDependencyId);
    }

    const { data: orgBans, error: orgBansError } = await orgQuery;
    if (orgBansError) throw orgBansError;

    const result: Array<{
      id: string;
      dependency_id: string;
      banned_version: string;
      bump_to_version: string;
      banned_by: string;
      created_at: string;
      source: 'org' | 'team';
      team_id?: string;
    }> = (orgBans ?? []).map((b: any) => ({
      ...b,
      source: 'org' as const,
    }));

    if (projectId && filterDependencyId) {
      const { data: projectTeams } = await supabase
        .from('project_teams')
        .select('team_id')
        .eq('project_id', projectId);
      const teamIds = (projectTeams ?? []).map((t: any) => t.team_id);
      if (teamIds.length > 0) {
        const { data: teamBans } = await supabase
          .from('team_banned_versions')
          .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at, team_id')
          .in('team_id', teamIds)
          .eq('dependency_id', filterDependencyId)
          .order('created_at', { ascending: false });
        for (const b of teamBans ?? []) {
          result.push({
            id: (b as any).id,
            dependency_id: (b as any).dependency_id,
            banned_version: (b as any).banned_version,
            bump_to_version: (b as any).bump_to_version,
            banned_by: (b as any).banned_by,
            created_at: (b as any).created_at,
            source: 'team',
            team_id: (b as any).team_id,
          });
        }
      }
    } else if (projectId && !filterDependencyId) {
      const { data: projectTeams } = await supabase
        .from('project_teams')
        .select('team_id')
        .eq('project_id', projectId);
      const teamIds = (projectTeams ?? []).map((t: any) => t.team_id);
      if (teamIds.length > 0) {
        const { data: teamBans } = await supabase
          .from('team_banned_versions')
          .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at, team_id')
          .in('team_id', teamIds)
          .order('created_at', { ascending: false });
        for (const b of teamBans ?? []) {
          result.push({
            id: (b as any).id,
            dependency_id: (b as any).dependency_id,
            banned_version: (b as any).banned_version,
            bump_to_version: (b as any).bump_to_version,
            banned_by: (b as any).banned_by,
            created_at: (b as any).created_at,
            source: 'team',
            team_id: (b as any).team_id,
          });
        }
      }
    }

    res.json({ banned_versions: result });
  } catch (error: any) {
    console.error('Error fetching banned versions:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch banned versions' });
  }
});

// POST /api/organizations/:id/ban-version — Ban a version org-wide (dependency_id required)
router.post('/:id/ban-version', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.params.id;
    const { dependency_id, banned_version, bump_to_version } = req.body as {
      dependency_id?: string;
      banned_version?: string;
      bump_to_version?: string;
    };

    if (!banned_version || !bump_to_version) {
      return res.status(400).json({ error: 'banned_version and bump_to_version are required' });
    }
    if (banned_version === bump_to_version) {
      return res.status(400).json({ error: 'bump_to_version must be different from banned_version' });
    }
    const resolvedDependencyId = dependency_id ?? null;
    if (!resolvedDependencyId) {
      return res.status(400).json({ error: 'dependency_id is required' });
    }

    const permCheck = await checkOrgManagePermission(userId, organizationId);
    if (!permCheck.hasPermission) {
      return res.status(permCheck.error!.status).json({ error: permCheck.error!.message });
    }

    const { data: ban, error: banError } = await supabase
      .from('banned_versions')
      .insert({
        organization_id: organizationId,
        dependency_id: resolvedDependencyId,
        banned_version,
        bump_to_version,
        banned_by: userId,
      })
      .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at')
      .single();

    if (banError) {
      if (banError.code === '23505') {
        return res.status(409).json({ error: 'This version is already banned for this package in this organization' });
      }
      throw banError;
    }

    const { data: watchlistRow } = await supabase
      .from('organization_watchlist')
      .select('id, latest_allowed_version')
      .eq('organization_id', organizationId)
      .eq('dependency_id', resolvedDependencyId)
      .maybeSingle();
    let watchlistUpdated = false;
    if (watchlistRow && (watchlistRow as any).id) {
      const currentAllowed = (watchlistRow as any).latest_allowed_version;
      if (currentAllowed === banned_version || currentAllowed == null) {
        await supabase
          .from('organization_watchlist')
          .update({ latest_allowed_version: bump_to_version })
          .eq('id', (watchlistRow as any).id);
        watchlistUpdated = true;
      }
    }
    if (watchlistUpdated) {
      const { data: depNameRow } = await supabase
        .from('dependencies')
        .select('name')
        .eq('id', resolvedDependencyId)
        .single();
      const packageName = (depNameRow as any)?.name ?? 'unknown';
      if (packageName) {
        await invalidateWatchtowerSummaryCache(packageName).catch((err: any) => {
          console.warn(`[Cache] Failed to invalidate watchtower summary after ban:`, err.message);
        });
      }
    }

    const { data: orgProjects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', organizationId);

    const projectIds = orgProjects?.map((p: any) => p.id) ?? [];
    let projectDeps: Array<{ id: string; project_id: string; name: string; version: string }> | null = [];
    if (projectIds.length > 0) {
      const { data: deps } = await supabase
        .from('project_dependencies')
        .select('id, project_id, name, version')
        .eq('dependency_id', resolvedDependencyId)
        .eq('version', banned_version)
        .in('project_id', projectIds);
      projectDeps = deps;
    }

    let projectsWithPrToBanned: Array<{ project_id: string }> = [];
    if (projectIds.length > 0) {
      const { data: prsToBanned } = await supabase
        .from('dependency_prs')
        .select('project_id')
        .eq('dependency_id', resolvedDependencyId)
        .eq('type', 'bump')
        .eq('target_version', banned_version)
        .in('project_id', projectIds);
      projectsWithPrToBanned = prsToBanned ?? [];
    }

    // Union: projects on banned version + projects with PR targeting banned version
    const seenProjects = new Set<string>();
    const projectsToBump: Array<{ project_id: string; current_version?: string }> = [];
    for (const dep of projectDeps ?? []) {
      if (!seenProjects.has(dep.project_id)) {
        seenProjects.add(dep.project_id);
        projectsToBump.push({ project_id: dep.project_id, current_version: dep.version });
      }
    }
    for (const row of projectsWithPrToBanned) {
      if (!seenProjects.has(row.project_id)) {
        seenProjects.add(row.project_id);
        projectsToBump.push({ project_id: row.project_id });
      }
    }

    const { data: depForName } = await supabase.from('dependencies').select('name').eq('id', resolvedDependencyId).single();
    const packageNameForPr = (depForName as any)?.name ?? 'unknown';

    const results: Array<{ project_id: string; pr_url?: string; pr_number?: number; error?: string }> = [];
    for (const entry of projectsToBump) {
      try {
        const bumpResult = await createBumpPrForProject(
          organizationId,
          entry.project_id,
          packageNameForPr,
          bump_to_version,
          entry.current_version
        );
        if ('error' in bumpResult) {
          results.push({ project_id: entry.project_id, error: bumpResult.error });
        } else {
          results.push({
            project_id: entry.project_id,
            pr_url: bumpResult.pr_url,
            pr_number: bumpResult.pr_number,
          });
        }
      } catch (err: any) {
        results.push({ project_id: entry.project_id, error: err.message || 'Failed to create bump PR' });
      }
    }

    await invalidateLatestSafeVersionCacheByDependencyId(resolvedDependencyId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate cache after banning version:`, err.message);
    });
    await invalidateDependencyVersionsCacheByDependencyId(resolvedDependencyId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate dependency versions cache after banning version:`, err.message);
    });
    await invalidateAllProjectCachesInOrg(organizationId, { depsOnly: true }).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate dependencies cache after banning version:`, err?.message);
    });

    res.json({
      ban,
      affected_projects: projectsToBump.length,
      pr_results: results,
    });
  } catch (error: any) {
    console.error('Error banning version:', error);
    res.status(500).json({ error: error.message || 'Failed to ban version' });
  }
});

// POST /api/organizations/:id/teams/:teamId/ban-version — Ban a version at team level (dependency_id required)
router.post('/:id/teams/:teamId/ban-version', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.params.id;
    const teamId = req.params.teamId;
    const { dependency_id, banned_version, bump_to_version } = req.body as {
      dependency_id?: string;
      banned_version?: string;
      bump_to_version?: string;
    };

    if (!banned_version || !bump_to_version) {
      return res.status(400).json({ error: 'banned_version and bump_to_version are required' });
    }
    if (banned_version === bump_to_version) {
      return res.status(400).json({ error: 'bump_to_version must be different from banned_version' });
    }
    const resolvedDependencyId = dependency_id ?? null;
    if (!resolvedDependencyId) {
      return res.status(400).json({ error: 'dependency_id is required' });
    }

    const { data: team, error: teamError } = await supabase
      .from('teams')
      .select('id, organization_id')
      .eq('id', teamId)
      .eq('organization_id', organizationId)
      .single();
    if (teamError || !team) {
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
      return res.status(403).json({ error: 'You need manage_projects permission in this team to ban versions' });
    }

    const { data: ban, error: banError } = await supabase
      .from('team_banned_versions')
      .insert({
        team_id: teamId,
        dependency_id: resolvedDependencyId,
        banned_version,
        bump_to_version,
        banned_by: userId,
      })
      .select('id, dependency_id, banned_version, bump_to_version, banned_by, created_at')
      .single();

    if (banError) {
      if (banError.code === '23505') {
        return res.status(409).json({ error: 'This version is already banned for this package in this team' });
      }
      throw banError;
    }

    const { data: teamProjects } = await supabase
      .from('project_teams')
      .select('project_id')
      .eq('team_id', teamId);
    const projectIds = (teamProjects ?? []).map((p: any) => p.project_id);
    let projectDeps: Array<{ id: string; project_id: string; name: string; version: string }> | null = [];
    if (projectIds.length > 0) {
      const { data: deps } = await supabase
        .from('project_dependencies')
        .select('id, project_id, name, version')
        .eq('dependency_id', resolvedDependencyId)
        .eq('version', banned_version)
        .in('project_id', projectIds);
      projectDeps = deps;
    }
    let projectsWithPrToBanned: Array<{ project_id: string }> = [];
    if (projectIds.length > 0) {
      const { data: prsToBanned } = await supabase
        .from('dependency_prs')
        .select('project_id')
        .eq('dependency_id', resolvedDependencyId)
        .eq('type', 'bump')
        .eq('target_version', banned_version)
        .in('project_id', projectIds);
      projectsWithPrToBanned = prsToBanned ?? [];
    }
    const seenProjects = new Set<string>();
    const projectsToBump: Array<{ project_id: string; current_version?: string }> = [];
    for (const dep of projectDeps ?? []) {
      if (!seenProjects.has(dep.project_id)) {
        seenProjects.add(dep.project_id);
        projectsToBump.push({ project_id: dep.project_id, current_version: dep.version });
      }
    }
    for (const row of projectsWithPrToBanned) {
      if (!seenProjects.has(row.project_id)) {
        seenProjects.add(row.project_id);
        projectsToBump.push({ project_id: row.project_id });
      }
    }

    const { data: depNameRow } = await supabase.from('dependencies').select('name').eq('id', resolvedDependencyId).single();
    const packageNameForTeamPr = (depNameRow as any)?.name ?? 'unknown';

    const results: Array<{ project_id: string; pr_url?: string; pr_number?: number; error?: string }> = [];
    for (const entry of projectsToBump) {
      try {
        const bumpResult = await createBumpPrForProject(
          organizationId,
          entry.project_id,
          packageNameForTeamPr,
          bump_to_version,
          entry.current_version
        );
        if ('error' in bumpResult) {
          results.push({ project_id: entry.project_id, error: bumpResult.error });
        } else {
          results.push({
            project_id: entry.project_id,
            pr_url: bumpResult.pr_url,
            pr_number: bumpResult.pr_number,
          });
        }
      } catch (err: any) {
        results.push({ project_id: entry.project_id, error: err.message || 'Failed to create bump PR' });
      }
    }

    await invalidateLatestSafeVersionCacheByDependencyId(resolvedDependencyId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate cache after banning version:`, err.message);
    });
    await invalidateDependencyVersionsCacheByDependencyId(resolvedDependencyId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate dependency versions cache after banning version:`, err.message);
    });
    await invalidateProjectCachesForTeam(organizationId, teamId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate dependencies cache after team ban:`, err?.message);
    });

    res.json({
      ban: { ...ban, source: 'team', team_id: teamId },
      affected_projects: projectsToBump.length,
      pr_results: results,
    });
  } catch (error: any) {
    console.error('Error banning version at team level:', error);
    res.status(500).json({ error: error.message || 'Failed to ban version' });
  }
});

// DELETE /api/organizations/:id/ban-version/:banId — Remove a ban (org or team)
// Org manage can remove any ban; team manage can only remove team bans for their team.
router.delete('/:id/ban-version/:banId', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.params.id;
    const banId = req.params.banId;

    const hasOrgManage = (await checkOrgManagePermission(userId, organizationId)).hasPermission;

    const { data: orgDeleted, error: orgError } = await supabase
      .from('banned_versions')
      .delete()
      .eq('id', banId)
      .eq('organization_id', organizationId)
      .select('id, dependency_id, banned_version')
      .single();

    if (!orgError && orgDeleted) {
      if (!hasOrgManage) {
        return res.status(403).json({ error: 'You do not have permission to remove organization-level bans' });
      }
      const orgDepId = (orgDeleted as any)?.dependency_id;
      if (orgDepId) {
        await invalidateLatestSafeVersionCacheByDependencyId(orgDepId).catch((err: any) => {
          console.warn(`[Cache] Failed to invalidate cache after removing ban:`, err.message);
        });
        await invalidateDependencyVersionsCacheByDependencyId(orgDepId).catch((err: any) => {
          console.warn(`[Cache] Failed to invalidate dependency versions cache after removing ban:`, err.message);
        });
      }
      const unbannedVersion = (orgDeleted as any)?.banned_version as string | undefined;
      if (unbannedVersion && orgDepId) {
        const { data: watchlistRow } = await supabase
          .from('organization_watchlist')
          .select('id, latest_allowed_version')
          .eq('organization_id', organizationId)
          .eq('dependency_id', orgDepId)
          .maybeSingle();
        if (watchlistRow && (watchlistRow as any).id) {
          const currentAllowed = (watchlistRow as any).latest_allowed_version as string | null;
          const unbannedCoerced = semver.valid(semver.coerce(unbannedVersion));
          const currentCoerced = currentAllowed ? semver.valid(semver.coerce(currentAllowed)) : null;
          const shouldUpdate =
            currentAllowed == null ||
            (unbannedCoerced && currentCoerced && semver.gt(unbannedCoerced, currentCoerced));
          if (shouldUpdate) {
            await supabase
              .from('organization_watchlist')
              .update({ latest_allowed_version: unbannedVersion })
              .eq('id', (watchlistRow as any).id);
            const { data: depRow } = await supabase
              .from('dependencies')
              .select('name')
              .eq('id', orgDepId)
              .single();
            const packageName = (depRow as any)?.name;
            if (packageName) {
              await invalidateWatchtowerSummaryCache(packageName).catch((err: any) => {
                console.warn(`[Cache] Failed to invalidate watchtower summary after unban:`, err.message);
              });
            }
          }
        }
      }
      await invalidateAllProjectCachesInOrg(organizationId, { depsOnly: true }).catch((err: any) => {
        console.warn(`[Cache] Failed to invalidate dependencies cache after removing org ban:`, err?.message);
      });
      return res.json({ message: 'Ban removed', id: orgDeleted.id });
    }

    const { data: teamBan } = await supabase
      .from('team_banned_versions')
      .select('id, team_id, dependency_id')
      .eq('id', banId)
      .single();
    if (!teamBan) {
      return res.status(404).json({ error: 'Ban not found' });
    }
    const tb = teamBan as any;
    const banTeamId = tb.team_id;
    const { data: teamRow } = await supabase
      .from('teams')
      .select('organization_id')
      .eq('id', banTeamId)
      .single();
    if (!teamRow || (teamRow as any).organization_id !== organizationId) {
      return res.status(404).json({ error: 'Ban not found' });
    }

    if (hasOrgManage) {
      // Org manage can remove team bans
    } else {
      // Must have team manage_projects for this team
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role_id')
        .eq('team_id', banTeamId)
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
        return res.status(403).json({ error: 'You need manage_projects permission in this team to remove team bans' });
      }
    }

    const { data: deleted, error: deleteError } = await supabase
      .from('team_banned_versions')
      .delete()
      .eq('id', banId)
      .select('id, dependency_id')
      .single();

    if (deleteError) throw deleteError;

    const deletedDepId = (deleted as any)?.dependency_id ?? (tb as any).dependency_id;
    if (deletedDepId) {
      await invalidateLatestSafeVersionCacheByDependencyId(deletedDepId).catch((err: any) => {
        console.warn(`[Cache] Failed to invalidate cache after removing ban:`, err.message);
      });
      await invalidateDependencyVersionsCacheByDependencyId(deletedDepId).catch((err: any) => {
        console.warn(`[Cache] Failed to invalidate dependency versions cache after removing ban:`, err.message);
      });
    }
    await invalidateProjectCachesForTeam(organizationId, banTeamId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate dependencies cache after removing team ban:`, err?.message);
    });

    res.json({ message: 'Ban removed', id: deleted.id });
  } catch (error: any) {
    console.error('Error removing ban:', error);
    res.status(500).json({ error: error.message || 'Failed to remove ban' });
  }
});

// GET /api/organizations/:id/projects/:projectId/bump-scope — Determine the user's bump scope for a project
router.get('/:id/projects/:projectId/bump-scope', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.params.id;
    const projectId = req.params.projectId;

    const accessCheck = await checkProjectAccess(userId, organizationId, projectId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Org owner or has manage_teams_and_projects → org scope
    const isOrgOwner = accessCheck.orgMembership?.role === 'owner';
    const hasOrgManage = accessCheck.orgRole?.permissions?.manage_teams_and_projects === true;
    if (isOrgOwner || hasOrgManage) {
      return res.json({ scope: 'org' });
    }

    // Check if user is in a team assigned to this project with manage_projects permission
    const { data: userTeams } = await supabase
      .from('team_members')
      .select('team_id, role_id')
      .eq('user_id', userId);

    if (userTeams && userTeams.length > 0) {
      const userTeamIds = userTeams.map((t: any) => t.team_id);

      // Get project's teams: from project_teams junction AND projects.team_id (legacy/primary)
      const { data: projectTeamsRows } = await supabase
        .from('project_teams')
        .select('team_id')
        .eq('project_id', projectId)
        .in('team_id', userTeamIds);

      const { data: projectRow } = await supabase
        .from('projects')
        .select('team_id')
        .eq('id', projectId)
        .single();

      const projectTeamIds = new Set<string>();
      (projectTeamsRows ?? []).forEach((r: any) => projectTeamIds.add(r.team_id));
      if (projectRow?.team_id && userTeamIds.includes(projectRow.team_id)) {
        projectTeamIds.add(projectRow.team_id);
      }

      for (const teamId of projectTeamIds) {
        const userTeam = userTeams.find((t: any) => t.team_id === teamId);
        if (!userTeam?.role_id) continue;

        const { data: teamRole } = await supabase
          .from('team_roles')
          .select('permissions')
          .eq('id', userTeam.role_id)
          .single();

        if (teamRole?.permissions?.manage_projects === true) {
          const { data: team } = await supabase
            .from('teams')
            .select('id, name')
            .eq('id', teamId)
            .single();

          return res.json({
            scope: 'team',
            team_id: teamId,
            team_name: team?.name ?? null,
          });
        }
      }
    }

    // Default: project scope only
    return res.json({ scope: 'project' });
  } catch (error: any) {
    console.error('Error getting bump scope:', error);
    res.status(500).json({ error: error.message || 'Failed to determine bump scope' });
  }
});

// POST /api/organizations/:id/bump-all — Bump all projects using a dependency to a target version (dependency_id required)
router.post('/:id/bump-all', async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const organizationId = req.params.id;
    const { dependency_id, target_version, team_id } = req.body as {
      dependency_id?: string;
      target_version?: string;
      team_id?: string;
    };

    if (!target_version) {
      return res.status(400).json({ error: 'target_version is required' });
    }
    const resolvedDependencyId = dependency_id ?? null;
    if (!resolvedDependencyId) {
      return res.status(400).json({ error: 'dependency_id is required' });
    }

    // If team_id is provided, validate team membership + manage_projects permission
    // Otherwise require org-level manage permission
    if (team_id) {
      const { data: teamMembership } = await supabase
        .from('team_members')
        .select('role_id')
        .eq('team_id', team_id)
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
        return res.status(403).json({ error: 'You do not have manage_projects permission in this team' });
      }
    } else {
      const permCheck = await checkOrgManagePermission(userId, organizationId);
      if (!permCheck.hasPermission) {
        return res.status(permCheck.error!.status).json({ error: permCheck.error!.message });
      }
    }

    // Find projects to bump — scoped to team if team_id provided, otherwise all org projects
    let projectIds: string[];
    if (team_id) {
      const { data: teamProjects } = await supabase
        .from('project_teams')
        .select('project_id')
        .eq('team_id', team_id);
      const fromJunction = new Set((teamProjects || []).map((p: any) => p.project_id));
      const { data: projectsByTeamId } = await supabase
        .from('projects')
        .select('id')
        .eq('team_id', team_id)
        .eq('organization_id', organizationId);
      projectIds = [...fromJunction];
      (projectsByTeamId || []).forEach((p: any) => {
        if (!fromJunction.has(p.id)) projectIds.push(p.id);
      });
    } else {
      const { data: orgProjects } = await supabase
        .from('projects')
        .select('id')
        .eq('organization_id', organizationId);
      projectIds = (orgProjects || []).map((p: any) => p.id);
    }

    if (projectIds.length === 0) {
      return res.json({ affected_projects: 0, pr_results: [] });
    }
    const { data: affectedDeps } = await supabase
      .from('project_dependencies')
      .select('id, project_id, name, version')
      .eq('dependency_id', resolvedDependencyId)
      .neq('version', target_version)
      .in('project_id', projectIds);

    if (!affectedDeps || affectedDeps.length === 0) {
      return res.json({ affected_projects: 0, pr_results: [] });
    }

    const { data: depNameRow } = await supabase.from('dependencies').select('name').eq('id', resolvedDependencyId).single();
    const packageNameForBump = (depNameRow as any)?.name ?? (affectedDeps[0] as any)?.name ?? 'unknown';

    const results: Array<{ project_id: string; current_version?: string; pr_url?: string; pr_number?: number; error?: string }> = [];
    const seenProjects = new Set<string>();

    for (const dep of affectedDeps) {
      if (seenProjects.has(dep.project_id)) continue;
      seenProjects.add(dep.project_id);

      try {
        const bumpResult = await createBumpPrForProject(
          organizationId,
          dep.project_id,
          packageNameForBump,
          target_version,
          dep.version
        );
        if ('error' in bumpResult) {
          results.push({ project_id: dep.project_id, current_version: dep.version, error: bumpResult.error });
        } else {
          results.push({
            project_id: dep.project_id,
            current_version: dep.version,
            pr_url: bumpResult.pr_url,
            pr_number: bumpResult.pr_number,
          });
        }
      } catch (err: any) {
        results.push({ project_id: dep.project_id, current_version: dep.version, error: err.message || 'Failed to create bump PR' });
      }
    }

    res.json({
      affected_projects: seenProjects.size,
      pr_results: results,
    });
  } catch (error: any) {
    console.error('Error bumping all projects:', error);
    res.status(500).json({ error: error.message || 'Failed to bump all projects' });
  }
});

// Export compliance update functions for use in other routes
export { updateProjectCompliance, updateAllProjectsCompliance };

export default router;

