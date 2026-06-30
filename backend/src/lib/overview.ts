import { supabase } from './supabase';

// Shared builders for the org-overview surface. Each `buildOrg*` function holds the VERBATIM body of
// one existing GET route (teams / projects / statuses / security-summary) so the standalone route and
// the bundled `/:id/overview` endpoint stay in lockstep — no logic drift. Builders return a
// BuilderResult instead of writing to `res`; the route wrappers (and the bundle) map that to HTTP.
export type BuilderResult<T> =
  | { data: T; error?: undefined }
  | { data?: undefined; error: { status: number; message: string } };

/** Legacy API `status` string; `projects.status` TEXT was dropped in favor of `status_id` → organization_statuses. */
export function legacyProjectComplianceLabel(
  statusId: string | null | undefined,
  isPassing: boolean | null | undefined
): string {
  if (!statusId) return 'compliant';
  if (isPassing === false) return 'non-compliant';
  return 'compliant';
}

/** Project IDs visible to the user within an org (same rules as GET /:id/projects). */
export async function getAccessibleProjectIdsInOrganization(
  userId: string,
  organizationId: string
): Promise<{ projectIds: string[]; error?: { status: number; message: string } }> {
  const { data: orgMembership, error: orgMembershipError } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (orgMembershipError || !orgMembership) {
    return { projectIds: [], error: { status: 404, message: 'Organization not found or access denied' } };
  }

  // Owners always see all projects, so skip the org_roles read for them — one fewer
  // sequential round-trip on the common case (this gate backs the org Findings page,
  // /vulnerabilities, etc.). Only non-owners need the permission lookup.
  let canViewAllProjects = orgMembership.role === 'owner';
  if (!canViewAllProjects) {
    const { data: orgRole } = await supabase
      .from('organization_roles')
      .select('permissions')
      .eq('organization_id', organizationId)
      .eq('name', orgMembership.role)
      .single();
    canViewAllProjects = orgRole?.permissions?.manage_teams_and_projects === true;
  }

  if (canViewAllProjects) {
    const { data: projects, error } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', organizationId);
    if (error) throw error;
    return { projectIds: (projects || []).map((p: any) => p.id) };
  }

  const { data: directProjects } = await supabase
    .from('project_members')
    .select('project_id')
    .eq('user_id', userId);
  const directProjectIds = (directProjects || []).map((p: any) => p.project_id);

  const { data: userTeams } = await supabase
    .from('team_members')
    .select('team_id')
    .eq('user_id', userId);
  const userTeamIds = (userTeams || []).map((t: any) => t.team_id);

  let teamProjectIds: string[] = [];
  if (userTeamIds.length > 0) {
    const { data: teamProjects } = await supabase
      .from('project_teams')
      .select('project_id')
      .in('team_id', userTeamIds);
    teamProjectIds = (teamProjects || []).map((tp: any) => tp.project_id);
  }

  const merged = [...new Set([...directProjectIds, ...teamProjectIds])];
  if (merged.length === 0) {
    return { projectIds: [] };
  }

  const { data: scopedProjects, error: scopedError } = await supabase
    .from('projects')
    .select('id')
    .eq('organization_id', organizationId)
    .in('id', merged);
  if (scopedError) throw scopedError;
  return { projectIds: (scopedProjects || []).map((p: any) => p.id) };
}

/** Body of GET /api/organizations/:id/security-summary. */
export async function buildOrgSecuritySummary(
  userId: string,
  id: string
): Promise<BuilderResult<{ projects: any[] }>> {
  // Scope to the projects this member can actually see (owner / manage_teams_and_projects ->
  // all; otherwise their team + directly-assigned projects). Matches the org /vulnerabilities
  // endpoint instead of leaking every project's posture to any member.
  const { projectIds: accessibleProjectIds, error: accessError } =
    await getAccessibleProjectIdsInOrganization(userId, id);
  if (accessError) {
    return { error: { status: accessError.status, message: accessError.message } };
  }
  if (accessibleProjectIds.length === 0) {
    return { data: { projects: [] } };
  }

  // All four reads key off the accessible project-id set and are mutually independent, so run
  // them as ONE parallel batch instead of five sequential round-trips (each await is a separate
  // network hop to Supabase). An id for a since-deleted project simply returns no rows here and is
  // dropped by the projects-driven map below. The summary read is phase64's denormalized table —
  // a single indexed PK lookup, not the old live 10-LATERAL aggregation.
  const [projectsRes, projectTeamsRes, summaryRes, repoRes] = await Promise.all([
    supabase.from('projects').select('id, name, active_extraction_run_id, infra_types').eq('organization_id', id).in('id', accessibleProjectIds),
    supabase.from('project_teams').select('project_id, team_id, is_owner').in('project_id', accessibleProjectIds),
    supabase.from('project_security_summaries').select('*').in('project_id', accessibleProjectIds),
    supabase.from('project_repositories').select('project_id, provider, repo_full_name, last_extracted_at').in('project_id', accessibleProjectIds),
  ]);

  const projects = projectsRes.data;
  if (!projects || projects.length === 0) {
    return { data: { projects: [] } };
  }
  const projectIds = projects.map((p: any) => p.id);

  const ownerTeamMap = new Map<string, string>();
  for (const pt of projectTeamsRes.data ?? []) {
    if (pt.is_owner) ownerTeamMap.set(pt.project_id, pt.team_id);
  }

  if (summaryRes.error) throw summaryRes.error;
  const countsByProject = new Map<string, any>();
  for (const c of summaryRes.data ?? []) countsByProject.set(c.project_id, c);

  // Lazy fallback: a project with no stored row yet (brand-new, or before the one-time post-deploy
  // backfill runs) is computed on the spot so the overview is never wrong. Rare — the recompute
  // hooks + daily cron keep the table populated, so this almost never fires.
  const missing = projectIds.filter((pid: string) => !countsByProject.has(pid));
  if (missing.length) {
    await Promise.allSettled(
      missing.map((pid: string) => supabase.rpc('recompute_project_summary', { p_project_id: pid })),
    );
    const { data: filled } = await supabase
      .from('project_security_summaries')
      .select('*')
      .in('project_id', missing);
    for (const c of filled ?? []) countsByProject.set(c.project_id, c);
  }

  const repoRows = repoRes.data;

  const repoByProject = new Map<string, { provider: string | null; repo_full_name: string | null; last_extracted_at: string | null }>();
  for (const r of repoRows ?? []) {
    if (!repoByProject.has(r.project_id)) {
      repoByProject.set(r.project_id, {
        provider: (r as any).provider ?? null,
        repo_full_name: (r as any).repo_full_name ?? null,
        last_extracted_at: (r as any).last_extracted_at ?? null,
      });
    }
  }

  const result = projects.map((p: any) => {
    const c = countsByProject.get(p.id);
    const repo = repoByProject.get(p.id);
    return {
      project_id: p.id,
      project_name: p.name,
      team_id: ownerTeamMap.get(p.id) ?? null,
      vuln_count: Number(c?.vuln_count ?? 0),
      critical_count: Number(c?.critical_count ?? 0),
      reachable_count: Number(c?.reachable_count ?? 0),
      worst_depscore: Number(c?.worst_depscore ?? 0),
      band_critical: Number(c?.band_critical ?? 0),
      band_high: Number(c?.band_high ?? 0),
      band_medium: Number(c?.band_medium ?? 0),
      band_low: Number(c?.band_low ?? 0),
      semgrep_count: Number(c?.semgrep_count ?? 0),
      secret_count: Number(c?.secret_count ?? 0),
      verified_secret_count: Number(c?.verified_secret_count ?? 0),
      ignored_count: Number(c?.ignored_count ?? 0),
      repo_provider: repo?.provider ?? null,
      repo_full_name: repo?.repo_full_name ?? null,
      // Latest COMPLETED scan only — NOT project_repositories.last_extracted_at, which is bumped
      // on every extraction attempt (incl. failed/incomplete) and reads stale. No completed scan → null ("Never").
      last_scan_at: c?.last_scan_at ?? null,
      infra_types: Array.isArray(p.infra_types) ? p.infra_types : [],
      has_container: !!c?.has_container,
      has_dast: !!c?.has_dast,
    };
  });

  return { data: { projects: result } };
}

/** Body of GET /api/organizations/:id/projects. */
export async function buildOrgProjects(
  userId: string,
  id: string
): Promise<BuilderResult<any[]>> {
  // Membership + the caller's org-role permissions in ONE parallel hop. The role lookup doesn't
  // need to wait on the membership round-trip — fetch the org's roles (a tiny set) alongside it and
  // pick the caller's in JS. (Saves a sequential round-trip; matters most for local dev where each
  // hop to the DB is ~100ms.)
  const [membershipRes, orgRolesRes] = await Promise.all([
    supabase.from('organization_members').select('role').eq('organization_id', id).eq('user_id', userId).single(),
    supabase.from('organization_roles').select('name, permissions').eq('organization_id', id),
  ]);
  const membership = membershipRes.data;
  if (membershipRes.error || !membership) {
    return { error: { status: 404, message: 'Organization not found or access denied' } };
  }
  const orgRole = (orgRolesRes.data ?? []).find((r: any) => r.name === membership.role) ?? null;

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
      return { data: [] };
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
    return { data: [] };
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
  // Org owners get 'owner'; everyone else (including custom roles) is
  // resolved via project_members and team memberships — never by role name.
  let projectRoles: Record<string, string> = {};

  if (membership.role === 'owner') {
    // Org owners are owners of all projects
    projectIds.forEach((pid: string) => {
      projectRoles[pid] = 'owner';
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
  if (membership.role !== 'owner' && !hasOrgManagePermission) {
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

  // Repo statuses, active jobs, org statuses, and direct-dep counts are mutually independent and
  // only need projectIds (or the org id) — fetch them in ONE parallel batch instead of three
  // sequential round-trips.
  const [repoStatusesRes, activeJobsRes, statusRes, directDepsResult] = await Promise.all([
    projectIds.length > 0
      ? supabase.from('project_repositories').select('project_id, status, extraction_step, extraction_error, last_extracted_at').in('project_id', projectIds)
      : Promise.resolve({ data: [] as any[] }),
    projectIds.length > 0
      ? supabase.from('scan_jobs').select('project_id').in('project_id', projectIds).in('status', ['queued', 'processing'])
      : Promise.resolve({ data: [] as any[] }),
    supabase.from('organization_statuses').select('id, name, color, is_passing').eq('organization_id', id),
    projectIds.length > 0
      ? supabase.from('project_dependencies').select('project_id').in('project_id', projectIds).eq('is_direct', true).is('removed_at', null)
      : Promise.resolve({ data: [] as any[] }),
  ]);

  // Repository statuses, with the "ready but a job is still queued/processing (or extraction_step
  // not completed) → extracting" override so the org overview stays consistent with run history.
  const repoStatusByProject: Record<string, { status: string; extraction_step: string | null; extraction_error: string | null; last_extracted_at: string | null }> = {};
  for (const rs of ((repoStatusesRes as any).data ?? [])) {
    repoStatusByProject[rs.project_id] = {
      status: rs.status,
      extraction_step: rs.extraction_step ?? null,
      extraction_error: rs.extraction_error ?? null,
      last_extracted_at: rs.last_extracted_at ?? null,
    };
  }
  const activeJobProjectIds = new Set(((activeJobsRes as any).data ?? []).map((j: { project_id: string }) => j.project_id));
  for (const pid of projectIds) {
    const rs = repoStatusByProject[pid];
    if (!rs || rs.status !== 'ready') continue;
    const step = rs.extraction_step;
    if (step && step !== 'completed') {
      rs.status = 'extracting';
    } else if (activeJobProjectIds.has(pid)) {
      rs.status = 'extracting';
    }
  }

  // Status display names/colors (org overview cards) + direct-dependency counts per project.
  const statusById: Record<string, { name: string; color: string | null; is_passing: boolean | null }> = {};
  let directDepsByProject: Record<string, number> = {};
  for (const s of ((statusRes as any)?.data ?? [])) {
    statusById[s.id] = { name: s.name, color: s.color ?? null, is_passing: s.is_passing };
  }
  for (const row of (directDepsResult.data ?? [])) {
    directDepsByProject[row.project_id] = (directDepsByProject[row.project_id] ?? 0) + 1;
  }

  // NOTE: per-project compliance % was removed here — it scanned EVERY dependency
  // (incl. transitive) for every project on every overview/projects load (O(total
  // deps)), but nothing consumed `compliance_score_pct`: the Compliance tab
  // recomputes its own score client-side (ProjectComplianceContent). Deleting it
  // keeps this endpoint O(projects). Re-add via the project_security_summaries
  // spine (not a live scan) if a server-side compliance number is ever needed.

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
    } else if (hasOrgManagePermission) {
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
    const statusInfo = project.status_id ? statusById[project.status_id] : null;
    return {
      id: project.id,
      organization_id: project.organization_id,
      name: project.name,
      team_ids: teamsByProject[project.id]?.map((t: any) => t.id) || [],
      health_score: project.health_score || 0,
      status: legacyProjectComplianceLabel(project.status_id, statusInfo?.is_passing),
      is_compliant: project.is_compliant !== false,
      created_at: project.created_at,
      updated_at: project.updated_at,
      team_names: teamsByProject[project.id]?.map((t: any) => t.name) || [],
      owner_team_id: ownerTeamId,
      owner_team_name: ownerTeamByProject[project.id]?.name || null,
      dependencies_count: project.dependencies_count || 0,
      direct_dependencies_count: directDepsByProject[project.id] ?? 0,
      framework: project.framework || null,
      alerts_count: project.alerts_count || 0,
      repo_status: repoStatus?.status ?? null,
      extraction_step: repoStatus?.extraction_step ?? null,
      extraction_error: repoStatus?.extraction_error ?? null,
      last_extracted_at: repoStatus?.last_extracted_at ?? null,
      role,
      permissions,
      status_id: project.status_id ?? null,
      status_name: statusInfo?.name ?? null,
      status_color: statusInfo?.color ?? null,
      importance: typeof project.importance === 'number' ? project.importance : 1.0,
      policy_evaluated_at: project.policy_evaluated_at ?? null,
      status_violations: project.status_violations ?? [],
      canvas_position_x: project.canvas_position_x ?? null,
      canvas_position_y: project.canvas_position_y ?? null,
    };
  });

  return { data: formattedProjects };
}

/** Body of GET /api/organizations/:id/teams. */
export async function buildOrgTeams(
  userId: string,
  id: string
): Promise<BuilderResult<any[]>> {
  // Membership + the caller's org-role permissions in ONE parallel hop (fetch the org's roles
  // alongside the membership and pick the caller's in JS, instead of a second sequential round-trip).
  const [membershipRes, orgRolesRes] = await Promise.all([
    supabase.from('organization_members').select('role').eq('organization_id', id).eq('user_id', userId).single(),
    supabase.from('organization_roles').select('name, permissions').eq('organization_id', id),
  ]);
  const membership = membershipRes.data;
  if (membershipRes.error || !membership) {
    return { error: { status: 404, message: 'Organization not found or access denied' } };
  }
  const orgRole = (orgRolesRes.data ?? []).find((r: any) => r.name === membership.role) ?? null;

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
      return { data: [] };
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

  // Member counts, project counts, and the caller's team roles — previously an N+1 (3-4 queries
  // PER team). Bulk-load all of it in ONE parallel batch scoped to the org's team set, then resolve
  // every per-team row in JS. (Each saved round-trip is ~100ms against the prod DB from local dev.)
  const teamIds = (teams || []).map((t: any) => t.id);
  const [teamMembersRes, teamProjectLinksRes, teamRolesRes] = await Promise.all([
    teamIds.length > 0
      ? supabase.from('team_members').select('team_id, user_id, role_id').in('team_id', teamIds)
      : Promise.resolve({ data: [] as any[] }),
    teamIds.length > 0
      ? supabase.from('project_teams').select('team_id').in('team_id', teamIds)
      : Promise.resolve({ data: [] as any[] }),
    teamIds.length > 0
      ? supabase.from('team_roles').select('id, team_id, name, display_name, color, permissions, display_order').in('team_id', teamIds)
      : Promise.resolve({ data: [] as any[] }),
  ]);

  const allTeamMembers = (teamMembersRes as any).data ?? [];
  const allProjectLinks = (teamProjectLinksRes as any).data ?? [];
  const allTeamRoles = (teamRolesRes as any).data ?? [];

  const memberCountByTeam = new Map<string, number>();
  const myMembershipByTeam = new Map<string, { role_id: string | null }>();
  for (const tm of allTeamMembers) {
    memberCountByTeam.set(tm.team_id, (memberCountByTeam.get(tm.team_id) ?? 0) + 1);
    if (tm.user_id === userId) myMembershipByTeam.set(tm.team_id, { role_id: tm.role_id ?? null });
  }
  const projectCountByTeam = new Map<string, number>();
  for (const pl of allProjectLinks) projectCountByTeam.set(pl.team_id, (projectCountByTeam.get(pl.team_id) ?? 0) + 1);
  const roleById = new Map<string, any>();
  const memberRoleByTeam = new Map<string, any>();
  for (const r of allTeamRoles) {
    roleById.set(r.id, r);
    if (r.name === 'member') memberRoleByTeam.set(r.team_id, r);
  }

  const teamsWithCounts = (teams || []).map((team: any) => {
    const memberCount = memberCountByTeam.get(team.id) ?? 0;
    const projectCount = projectCountByTeam.get(team.id) ?? 0;
    const teamMembership = myMembershipByTeam.get(team.id) ?? null;

    let userRole: string | null = 'member';
    let userRoleDisplayName: string | null = 'Member';
    let userRoleColor: string | null = null;
    let userRank: number | null = null;
    let userPermissions: Record<string, boolean> = {
      view_overview: true,
      manage_projects: false,
      manage_members: false,
      view_settings: false,
      view_roles: false,
      edit_roles: false,
      manage_notification_settings: false,
    };

    if (teamMembership?.role_id) {
      const role = roleById.get(teamMembership.role_id);
      if (role) {
        userRole = role.name;
        userRoleDisplayName = role.display_name || role.name.charAt(0).toUpperCase() + role.name.slice(1);
        userRoleColor = role.color;
        userRank = role.display_order;
        userPermissions = { ...userPermissions, ...(role.permissions || {}), view_overview: true };
      }
    } else if (teamMembership) {
      // Team member with no role_id → fall back to the team's 'member' role.
      const memberRole = memberRoleByTeam.get(team.id);
      if (memberRole) {
        userRole = memberRole.name;
        userRoleDisplayName = memberRole.display_name || 'Member';
        userRoleColor = memberRole.color;
        userRank = memberRole.display_order;
        userPermissions = { ...userPermissions, ...(memberRole.permissions || {}), view_overview: true };
      }
    }

    // Org owners / users with manage_teams_and_projects get all team permissions and rank 0.
    if (membership.role === 'owner' || canViewAllTeams) {
      userPermissions = {
        view_overview: true,
        manage_projects: true,
        manage_members: true,
        view_settings: true,
        view_roles: true,
        edit_roles: true,
        manage_notification_settings: true,
      };
      userRank = 0;
      // Not a team member but has org-level access → no role badge; team members keep theirs.
      if (!teamMembership?.role_id) {
        userRole = null;
        userRoleDisplayName = null;
        userRoleColor = null;
      }
    }

    return {
      ...team,
      member_count: memberCount,
      project_count: projectCount,
      role: userRole,
      role_display_name: userRoleDisplayName,
      role_color: userRoleColor,
      user_rank: userRank,
      permissions: userPermissions,
    };
  });

  return { data: teamsWithCounts };
}

/** Body of GET /api/organizations/:id/statuses. */
export async function buildOrgStatuses(
  userId: string,
  id: string
): Promise<BuilderResult<any[]>> {
  // The membership check and the statuses fetch are independent — run them in parallel (the
  // statuses are read into memory but only returned once membership is confirmed, so a non-member
  // still gets a 404 and never sees the data).
  const [membershipRes, statusesRes] = await Promise.all([
    supabase.from('organization_members').select('role').eq('organization_id', id).eq('user_id', userId).single(),
    supabase.from('organization_statuses').select('*').eq('organization_id', id).order('rank', { ascending: true }),
  ]);

  if (!membershipRes.data) {
    return { error: { status: 404, message: 'Organization not found or access denied' } };
  }
  if (statusesRes.error) throw statusesRes.error;
  return { data: statusesRes.data ?? [] };
}
