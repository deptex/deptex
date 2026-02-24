import { memo, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import AppHeader from './AppHeader';
import { TeamWithRole, TeamPermissions, Organization, api } from '../lib/api';
import { RoleBadge } from './RoleBadge';

interface TeamHeaderProps {
  organization: Organization | null;
  team: TeamWithRole | null;
  userPermissions: TeamPermissions | null;
}

function TeamHeader({
  organization,
  team,
  userPermissions
}: TeamHeaderProps) {
  // Track team role color and display name locally
  const [teamRoleColor, setTeamRoleColor] = useState<string | null | undefined>(team?.role_color);
  const [teamRoleDisplayName, setTeamRoleDisplayName] = useState<string>(() =>
    team?.role_display_name
    || (team?.role ? team.role.charAt(0).toUpperCase() + team.role.slice(1) : 'Member')
  );

  // Track org role color and display name locally
  const [orgRoleColor, setOrgRoleColor] = useState<string | null | undefined>(organization?.role_color);
  const [orgRoleDisplayName, setOrgRoleDisplayName] = useState<string>(() =>
    organization?.role_display_name
    || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
  );

  // Update local state when team prop changes
  useEffect(() => {
    setTeamRoleColor(team?.role_color);
    setTeamRoleDisplayName(
      team?.role_display_name
      || (team?.role ? team.role.charAt(0).toUpperCase() + team.role.slice(1) : 'Member')
    );
  }, [team?.role_color, team?.role_display_name, team?.role]);

  // Update local state when organization prop changes
  useEffect(() => {
    setOrgRoleColor(organization?.role_color);
    setOrgRoleDisplayName(
      organization?.role_display_name
      || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
    );
  }, [organization?.role_color, organization?.role_display_name, organization?.role]);

  // Load team role colors from database
  useEffect(() => {
    const loadTeamRoleColors = async () => {
      if (!organization?.id || !team?.id || !team?.role) {
        return;
      }

      try {
        const roles = await api.getTeamRoles(organization.id, team.id);
        const userRole = roles.find(r => r.name === team.role);

        if (userRole) {
          setTeamRoleColor(userRole.color);
          setTeamRoleDisplayName(userRole.display_name || team.role.charAt(0).toUpperCase() + team.role.slice(1));
        }
      } catch (error) {
        console.error('Failed to load team role colors:', error);
      }
    };

    loadTeamRoleColors();
  }, [organization?.id, team?.id, team?.role]);

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

  // Early return if team is null
  if (!team) {
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
            <Link to="/organizations" className="flex items-center hover:opacity-80 transition-opacity">
              <img
                src="/images/logo.png"
                alt="Deptex"
                className="h-8 w-8"
              />
            </Link>
            <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
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
            <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            <div className="flex items-center gap-2 min-w-0">
              <Link
                to={`/organizations/${organization?.id}/teams/${team.id}`}
                className="text-foreground font-medium hover:text-foreground transition-colors truncate max-w-[140px]"
              >
                {team.name}
              </Link>
              {team.role && (
                <RoleBadge
                  role={team.role}
                  roleDisplayName={teamRoleDisplayName}
                  roleColor={teamRoleColor}
                />
              )}
            </div>
          </nav>
        }
      />
    </div>
  );
}

// Custom comparison function to prevent re-renders when data is the same
const areEqual = (prevProps: TeamHeaderProps, nextProps: TeamHeaderProps) => {
  if (!prevProps.team || !nextProps.team) {
    return prevProps.team === nextProps.team;
  }

  // Handle null organization cases
  if (!prevProps.organization || !nextProps.organization) {
    return prevProps.organization === nextProps.organization;
  }

  return (
    prevProps.organization.id === nextProps.organization.id &&
    prevProps.organization.name === nextProps.organization.name &&
    prevProps.organization.role === nextProps.organization.role &&
    prevProps.organization.role_display_name === nextProps.organization.role_display_name &&
    prevProps.organization.role_color === nextProps.organization.role_color &&
    prevProps.organization.avatar_url === nextProps.organization.avatar_url &&
    prevProps.team.id === nextProps.team.id &&
    prevProps.team.name === nextProps.team.name &&
    prevProps.team.role === nextProps.team.role &&
    prevProps.team.role_display_name === nextProps.team.role_display_name &&
    prevProps.team.role_color === nextProps.team.role_color &&
    prevProps.team.avatar_url === nextProps.team.avatar_url &&
    prevProps.userPermissions === nextProps.userPermissions
  );
};

export default memo(TeamHeader, areEqual);
