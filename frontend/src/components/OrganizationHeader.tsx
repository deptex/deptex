import { memo, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import AppHeader from './AppHeader';
import { Organization, api } from '../lib/api';
import { RoleBadge } from './RoleBadge';

interface OrganizationHeaderProps {
  organization: Organization | null;
}

function OrganizationHeader({ organization }: OrganizationHeaderProps) {
  // Track role color and display name locally so they can be updated without prop changes
  const [roleColor, setRoleColor] = useState<string | null | undefined>(organization?.role_color);
  const [roleDisplayName, setRoleDisplayName] = useState<string>(() =>
    organization?.role_display_name
    || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
  );

  // Update local state when organization prop changes
  useEffect(() => {
    setRoleColor(organization?.role_color);
    setRoleDisplayName(
      organization?.role_display_name
      || (organization?.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')
    );
  }, [organization?.role_color, organization?.role_display_name, organization?.role]);

  // Load role color and display name from database
  useEffect(() => {
    const loadRoleInfo = async () => {
      if (!organization?.id || !organization?.role) return;

      try {
        const roles = await api.getOrganizationRoles(organization.id);
        const userRole = roles.find(r => r.name === organization.role);
        if (userRole) {
          setRoleColor(userRole.color);
          setRoleDisplayName(userRole.display_name || organization.role.charAt(0).toUpperCase() + organization.role.slice(1));
        }
      } catch (error) {
        console.error('Failed to load org role info:', error);
      }
    };

    loadRoleInfo();
  }, [organization?.id, organization?.role]);

  useEffect(() => {
    const handleRoleUpdate = async () => {
      if (!organization?.id || !organization?.role) return;
      try {
        const roles = await api.getOrganizationRoles(organization.id);
        const userRole = roles.find(r => r.name === organization.role);
        if (userRole) {
          setRoleColor(userRole.color);
          setRoleDisplayName(userRole.display_name || organization.role.charAt(0).toUpperCase() + organization.role.slice(1));
        }
      } catch (error) {
        console.error('Failed to refresh role info:', error);
      }
    };

    window.addEventListener('rolesUpdated', handleRoleUpdate);
    return () => window.removeEventListener('rolesUpdated', handleRoleUpdate);
  }, [organization?.id, organization?.role]);

  if (!organization) {
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
                to={`/organizations/${organization.id}`}
                className="text-foreground font-medium hover:text-foreground transition-colors truncate max-w-[140px]"
              >
                {organization.name}
              </Link>
              <RoleBadge
                role={organization.role || 'member'}
                roleDisplayName={roleDisplayName}
                roleColor={roleColor}
              />
            </div>
          </nav>
        }
      />
    </div>
  );
}

// Custom comparison function to prevent re-renders when organization data is the same
const areEqual = (prevProps: OrganizationHeaderProps, nextProps: OrganizationHeaderProps) => {
  // Handle null cases
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
    JSON.stringify(prevProps.organization.permissions) === JSON.stringify(nextProps.organization.permissions)
  );
};

export default memo(OrganizationHeader, areEqual);

