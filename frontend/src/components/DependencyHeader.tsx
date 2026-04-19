import { memo, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import AppHeader from './AppHeader';
import OrganizationSwitcher from './OrganizationSwitcher';
import ProjectSwitcher from './ProjectSwitcher';
import TeamSwitcher from './TeamSwitcher';
import { ProjectWithRole, Organization, api, TeamWithRole, ProjectPermissions, ProjectDependency } from '../lib/api';
import { RoleBadge } from './RoleBadge';
import { FrameworkIcon } from './framework-icon';

interface DependencyHeaderProps {
  organization: Organization | null;
  project: ProjectWithRole | null;
  dependency: ProjectDependency | null;
  userPermissions?: ProjectPermissions | null;
}

function DependencyHeader({
  organization,
  project,
  dependency,
  userPermissions
}: DependencyHeaderProps) {
  // Track org role color and display name locally
  const [orgRoleColor, setOrgRoleColor] = useState<string | null | undefined>(organization?.role_color);
  const [orgRoleDisplayName, setOrgRoleDisplayName] = useState<string>(() =>
    organization?.role_display_name
    || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
  );

  // Track team data for the project's owner team
  const [team, setTeam] = useState<TeamWithRole | null>(() => {
    const teamId = project?.owner_team_id || project?.team_ids?.[0];
    const teamName = project?.owner_team_name || project?.team_names?.[0];
    if (!organization?.id || !teamId) return null;
    const cached = api.getCachedTeam(organization.id, teamId);
    if (cached) return cached;
    const cachedRole = localStorage.getItem(`team_role_${teamId}`);
    const cachedRoleDisplayName = localStorage.getItem(`team_role_display_name_${teamId}`);
    const cachedRoleColor = localStorage.getItem(`team_role_color_${teamId}`);
    if (cachedRole) {
      return {
        id: teamId,
        name: teamName || '',
        role: cachedRole,
        role_display_name: cachedRoleDisplayName || undefined,
        role_color: cachedRoleColor || undefined,
        organization_id: organization.id,
        created_at: '',
      } as TeamWithRole;
    }
    return null;
  });
  const [teamRoleColor, setTeamRoleColor] = useState<string | null | undefined>(() => {
    const teamId = project?.owner_team_id || project?.team_ids?.[0];
    if (!teamId) return null;
    return localStorage.getItem(`team_role_color_${teamId}`) || null;
  });
  const [teamRoleDisplayName, setTeamRoleDisplayName] = useState<string>(() => {
    const teamId = project?.owner_team_id || project?.team_ids?.[0];
    if (!teamId) return 'Member';
    const cached = localStorage.getItem(`team_role_display_name_${teamId}`);
    if (cached) return cached;
    const cachedRole = localStorage.getItem(`team_role_${teamId}`);
    return cachedRole ? cachedRole.charAt(0).toUpperCase() + cachedRole.slice(1) : 'Member';
  });

  // Update local state when organization prop changes
  useEffect(() => {
    setOrgRoleColor(organization?.role_color);
    setOrgRoleDisplayName(
      organization?.role_display_name
      || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
    );
  }, [organization?.role_color, organization?.role_display_name, organization?.role]);

  // Load organization role colors from database
  useEffect(() => {
    const loadOrgRoleColors = async () => {
      if (!organization?.id || !organization?.role) {
        return;
      }

      try {
        const roles = await api.getOrganizationRoles(organization.id);
        const userRole = roles.find(r => r.name === organization.role);

        if (userRole) {
          setOrgRoleColor(userRole.color);
          setOrgRoleDisplayName(userRole.display_name || organization.role.charAt(0).toUpperCase() + organization.role.slice(1));
        }
      } catch (error) {
        console.error('Failed to load organization role colors:', error);
      }
    };

    loadOrgRoleColors();
  }, [organization?.id, organization?.role]);

  // Load team data when project has an owner team
  useEffect(() => {
    const loadTeamData = async () => {
      const teamId = project?.owner_team_id || project?.team_ids?.[0];
      if (!organization?.id || !teamId) {
        setTeam(null);
        return;
      }

      try {
        const cached = api.getCachedTeam(organization.id, teamId);
        if (cached) {
          setTeam(cached);
          setTeamRoleColor(cached.role_color);
          setTeamRoleDisplayName(
            cached.role_display_name
            || (cached.role ? cached.role.charAt(0).toUpperCase() + cached.role.slice(1) : 'Member')
          );
        }

        const teamData = await api.getTeam(organization.id, teamId);
        setTeam(teamData);
        setTeamRoleColor(teamData.role_color);
        setTeamRoleDisplayName(
          teamData.role_display_name
          || (teamData.role ? teamData.role.charAt(0).toUpperCase() + teamData.role.slice(1) : 'Member')
        );

        if (teamData.role) {
          localStorage.setItem(`team_role_${teamId}`, teamData.role);
        } else {
          localStorage.removeItem(`team_role_${teamId}`);
        }
        if (teamData.role_display_name) {
          localStorage.setItem(`team_role_display_name_${teamId}`, teamData.role_display_name);
        } else {
          localStorage.removeItem(`team_role_display_name_${teamId}`);
        }
        if (teamData.role_color) {
          localStorage.setItem(`team_role_color_${teamId}`, teamData.role_color);
        } else {
          localStorage.removeItem(`team_role_color_${teamId}`);
        }

        if (teamData.role) {
          const roles = await api.getTeamRoles(organization.id, teamId);
          const userRole = roles.find(r => r.name === teamData.role);
          if (userRole) {
            setTeamRoleColor(userRole.color);
            setTeamRoleDisplayName(userRole.display_name || teamData.role.charAt(0).toUpperCase() + teamData.role.slice(1));
            if (userRole.display_name) {
              localStorage.setItem(`team_role_display_name_${teamId}`, userRole.display_name);
            }
            if (userRole.color) {
              localStorage.setItem(`team_role_color_${teamId}`, userRole.color);
            }
          }
        }
      } catch (error) {
        console.error('Failed to load team data:', error);
      }
    };

    loadTeamData();
  }, [organization?.id, project?.owner_team_id, project?.team_ids?.[0]]);

  // Early return if dependency or project is null
  if (!dependency || !project) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
      <AppHeader
        breadcrumb={[]}
        showSearch={false}
        showNewOrg={false}
        customLeftContent={
          <div className="flex items-center gap-3">
            {/* Logo */}
            <Link to="/organizations" className="flex items-center">
              <img
                src="/images/logo.png"
                alt="Deptex"
                className="h-8 w-8"
              />
            </Link>

            {/* Slash separator */}
            <span className="text-border text-lg font-light -ml-1">/</span>

            {/* Organization section */}
            <Link
              to={`/organizations/${organization?.id}`}
              className="flex items-center gap-3"
            >
              <img
                src={organization?.avatar_url || '/images/org_profile.png'}
                alt={organization?.name}
                className="h-8 w-8 rounded-full object-cover border border-border"
              />
              <span className="text-foreground font-medium">{organization?.name}</span>
            </Link>
            <RoleBadge
              role={organization?.role || 'member'}
              roleDisplayName={orgRoleDisplayName}
              roleColor={orgRoleColor}
            />
            <OrganizationSwitcher
              currentOrganizationId={organization?.id || ''}
              currentOrganizationName={organization?.name || ''}
              showOrgName={false}
            />

            {/* Team section (if project has an owner team) */}
            {(project.owner_team_id || project.team_ids?.[0]) && (project.owner_team_name || project.team_names?.[0]) && (
              <>
                {/* Slash separator */}
                <span className="text-border text-lg font-light -ml-1">/</span>

                {/* Team section */}
                <Link
                  to={`/organizations/${organization?.id}/teams/${project.owner_team_id || project.team_ids?.[0]}`}
                  className="flex items-center gap-3"
                >
                  <img
                    src={team?.avatar_url || '/images/team_profile.png'}
                    alt={project.owner_team_name || project.team_names?.[0] || ''}
                    className="h-8 w-8 rounded-full object-cover border border-border"
                  />
                  <span className="text-foreground font-medium">{project.owner_team_name || project.team_names?.[0]}</span>
                </Link>
                {team?.role && (
                  <RoleBadge
                    role={team.role}
                    roleDisplayName={teamRoleDisplayName}
                    roleColor={teamRoleColor}
                  />
                )}
                <TeamSwitcher
                  organizationId={organization?.id || ''}
                  currentTeamId={project.owner_team_id || project.team_ids?.[0] || ''}
                  currentTeamName={project.owner_team_name || project.team_names?.[0] || ''}
                />
              </>
            )}

            {/* Slash separator */}
            <span className="text-border text-lg font-light -ml-1">/</span>

            {/* Project section - matches ProjectHeader structure */}
            <Link
              to={`/organizations/${organization?.id}/projects/${project.id}`}
              className="flex items-center gap-3"
            >
              <FrameworkIcon frameworkId={project.framework} size={22} />
              <span className="text-foreground font-medium">{project.name}</span>
            </Link>
            <ProjectSwitcher
              organizationId={organization?.id || ''}
              currentProjectId={project.id}
              currentProjectName={project.name}
            />

            {/* Slash separator */}
            <span className="text-border text-lg font-light -ml-1">/</span>

            {/* Dependency/Package section */}
            <img
              src="/images/npm_icon.png"
              alt="NPM"
              className="h-5 w-5 object-contain"
            />
            <span className="text-foreground font-medium">{dependency.name}</span>
          </div>
        }
      />
    </div>
  );
}

// Custom comparison function to prevent re-renders when data is the same
const areEqual = (prevProps: DependencyHeaderProps, nextProps: DependencyHeaderProps) => {
  if (!prevProps.dependency || !nextProps.dependency) {
    return prevProps.dependency === nextProps.dependency;
  }

  if (!prevProps.project || !nextProps.project) {
    return prevProps.project === nextProps.project;
  }

  if (!prevProps.organization || !nextProps.organization) {
    return prevProps.organization === nextProps.organization;
  }

  const prevOwnerTeamId = prevProps.project.owner_team_id || prevProps.project.team_ids?.[0];
  const nextOwnerTeamId = nextProps.project.owner_team_id || nextProps.project.team_ids?.[0];
  const prevOwnerTeamName = prevProps.project.owner_team_name || prevProps.project.team_names?.[0];
  const nextOwnerTeamName = nextProps.project.owner_team_name || nextProps.project.team_names?.[0];

  return (
    prevProps.organization.id === nextProps.organization.id &&
    prevProps.organization.name === nextProps.organization.name &&
    prevProps.organization.role === nextProps.organization.role &&
    prevProps.organization.role_display_name === nextProps.organization.role_display_name &&
    prevProps.organization.role_color === nextProps.organization.role_color &&
    prevProps.organization.avatar_url === nextProps.organization.avatar_url &&
    prevProps.project.id === nextProps.project.id &&
    prevProps.project.name === nextProps.project.name &&
    prevProps.project.role === nextProps.project.role &&
    prevProps.project.framework === nextProps.project.framework &&
    prevOwnerTeamId === nextOwnerTeamId &&
    prevOwnerTeamName === nextOwnerTeamName &&
    prevProps.dependency.id === nextProps.dependency.id &&
    prevProps.dependency.name === nextProps.dependency.name &&
    prevProps.userPermissions?.view_settings === nextProps.userPermissions?.view_settings
  );
};

export default memo(DependencyHeader, areEqual);
