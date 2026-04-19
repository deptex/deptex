import { memo, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import AppHeader from './AppHeader';
import { ProjectWithRole, Organization, api, TeamWithRole, ProjectPermissions } from '../lib/api';
import { RoleBadge } from './RoleBadge';
import { FrameworkIcon } from './framework-icon';

interface ProjectHeaderProps {
  organization: Organization | null;
  project: ProjectWithRole | null;
  userPermissions?: ProjectPermissions | null;
}

function ProjectHeader({
  organization,
  project,
  userPermissions
}: ProjectHeaderProps) {
  const [orgRoleColor, setOrgRoleColor] = useState<string | null | undefined>(organization?.role_color);
  const [orgRoleDisplayName, setOrgRoleDisplayName] = useState<string>(() =>
    organization?.role_display_name
    || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
  );

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

  useEffect(() => {
    setOrgRoleColor(organization?.role_color);
    setOrgRoleDisplayName(
      organization?.role_display_name
      || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
    );
  }, [organization?.role_color, organization?.role_display_name, organization?.role]);

  useEffect(() => {
    const loadOrgRoleColors = async () => {
      if (!organization?.id || !organization?.role) return;
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
            cached.role_display_name || (cached.role ? cached.role.charAt(0).toUpperCase() + cached.role.slice(1) : 'Member')
          );
        }
        const teamData = await api.getTeam(organization.id, teamId);
        setTeam(teamData);
        setTeamRoleColor(teamData.role_color);
        setTeamRoleDisplayName(
          teamData.role_display_name || (teamData.role ? teamData.role.charAt(0).toUpperCase() + teamData.role.slice(1) : 'Member')
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
            if (userRole.display_name) localStorage.setItem(`team_role_display_name_${teamId}`, userRole.display_name);
            if (userRole.color) localStorage.setItem(`team_role_color_${teamId}`, userRole.color);
          }
        }
      } catch (error) {
        console.error('Failed to load team data:', error);
      }
    };
    loadTeamData();
  }, [organization?.id, project?.owner_team_id, project?.team_ids?.[0]]);

  if (!project) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
      <AppHeader
        breadcrumb={[]}
        showSearch={false}
        showNewOrg={false}
        customLeftContent={
          <nav className="flex items-center gap-2 text-sm">
            {/* Logo */}
            <Link to="/organizations" className="flex items-center hover:opacity-80 transition-opacity">
              <img
                src="/images/logo.png"
                alt="Deptex"
                className="h-8 w-8"
              />
            </Link>

            <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />

            {/* Organization */}
            <div className="flex items-center gap-2 min-w-0">
              <Link
                to={`/organizations/${organization?.id}`}
                className="text-muted-foreground font-medium hover:text-foreground transition-colors truncate max-w-[140px]"
              >
                {organization?.name}
              </Link>
              <RoleBadge
                role={organization?.role || 'member'}
                roleDisplayName={orgRoleDisplayName}
                roleColor={orgRoleColor}
              />
            </div>

            {/* Team (if project has an owner team) */}
            {(project.owner_team_id || project.team_ids?.[0]) && (project.owner_team_name || project.team_names?.[0]) && (
              <>
                <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                <div className="flex items-center gap-2 min-w-0">
                  <Link
                    to={`/organizations/${organization?.id}/teams/${project.owner_team_id || project.team_ids?.[0]}`}
                    className="text-muted-foreground font-medium hover:text-foreground transition-colors truncate max-w-[140px]"
                  >
                    {project.owner_team_name || project.team_names?.[0]}
                  </Link>
                  {team?.role && (
                    <RoleBadge
                      role={team.role}
                      roleDisplayName={teamRoleDisplayName}
                      roleColor={teamRoleColor}
                    />
                  )}
                </div>
              </>
            )}

            <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />

            {/* Project */}
            <div className="flex items-center gap-2 min-w-0">
              <FrameworkIcon frameworkId={project.framework} size={18} />
              <span className="text-foreground font-medium truncate">{project.name}</span>
            </div>
          </nav>
        }
      />
    </div>
  );
}


// Custom comparison function to prevent re-renders when data is the same
const areEqual = (prevProps: ProjectHeaderProps, nextProps: ProjectHeaderProps) => {
  if (!prevProps.project || !nextProps.project) {
    return prevProps.project === nextProps.project;
  }

  // Handle null organization cases
  if (!prevProps.organization || !nextProps.organization) {
    return prevProps.organization === nextProps.organization;
  }

  // Compare owner team IDs (for team display in header)
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
    prevProps.userPermissions?.view_settings === nextProps.userPermissions?.view_settings
  );
};

export default memo(ProjectHeader, areEqual);
