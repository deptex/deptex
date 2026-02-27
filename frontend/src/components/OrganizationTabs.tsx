import { memo, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, Users, ShieldAlert, ClipboardCheck, Settings } from 'lucide-react';
import { RolePermissions } from '../lib/api';

interface OrganizationTabsProps {
  organizationId: string;
  userPermissions?: RolePermissions | null;
}

const allTabs = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'vulnerabilities', label: 'Vulnerabilities', path: 'vulnerabilities', icon: ShieldAlert, requiredPermission: null },
  { id: 'projects', label: 'Projects', path: 'projects', icon: FolderKanban, requiredPermission: null },
  { id: 'teams', label: 'Teams', path: 'teams', icon: Users, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: ClipboardCheck, requiredPermission: 'manage_compliance' as const },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

function OrganizationTabs({ organizationId, userPermissions }: OrganizationTabsProps) {
  const location = useLocation();
  const navigate = useNavigate();

  // Filter tabs based on permissions
  const visibleTabs = useMemo(() => {
    return allTabs.filter(tab => {
      // Tabs without required permissions are always visible
      if (!tab.requiredPermission) {
        return true;
      }
      // If permissions are not loaded yet, hide permission-required tabs
      // but keep showing non-permission tabs to prevent flash
      if (!userPermissions) {
        return false;
      }
      return userPermissions[tab.requiredPermission] === true;
    });
  }, [userPermissions]);

  // Extract current tab from pathname
  const pathParts = location.pathname.split('/');
  const currentTab = pathParts[pathParts.length - 1];

  // Determine active tab
  const activeTab = useMemo(() => {
    // First, try to find the tab that matches the current path
    const matchingTab = visibleTabs.find(tab => tab.path === currentTab);
    if (matchingTab) {
      return matchingTab.id;
    }

    // If we're under /organizations/:id/settings or /organizations/:id/settings/:section,
    // highlight Settings
    if (pathParts.includes('settings')) {
      const settingsTab = visibleTabs.find(tab => tab.id === 'settings');
      if (settingsTab) return 'settings';
    }

    // If we're on the org root (no tab specified)
    if (currentTab === organizationId) {
      // Check if overview is available
      const overviewTab = visibleTabs.find(tab => tab.id === 'overview');
      if (overviewTab) {
        return 'overview';
      }
      // If overview isn't available, default to projects
      return 'projects';
    }

    // Default fallback
    return 'overview';
  }, [currentTab, organizationId, visibleTabs, location.pathname]);

  const handleTabClick = (path: string) => {
    if (path === 'overview') {
      navigate(`/organizations/${organizationId}`);
    } else {
      navigate(`/organizations/${organizationId}/${path}`);
    }
  };

  return (
    <div className="border-b border-border bg-background -mt-3">
      <div className="mx-auto w-full">
        <nav className="flex items-center gap-6 px-6 pt-0" aria-label="Organization navigation">
          {visibleTabs.map((tab) => {
            const isActive = activeTab === tab.id;
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => handleTabClick(tab.path)}
                className={`group relative py-4 text-sm font-medium transition-colors flex items-center gap-2 ${isActive
                  ? 'text-foreground'
                  : 'text-foreground-secondary hover:text-foreground'
                  }`}
              >
                <Icon className="h-4 w-4 tab-icon-shake" />
                {tab.label}
                {isActive && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-foreground" />
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
}

export default memo(OrganizationTabs, (prevProps, nextProps) => {
  // Re-render if organizationId or userPermissions change
  if (prevProps.organizationId !== nextProps.organizationId) {
    return false;
  }

  // Compare permissions objects
  const prevPerms = prevProps.userPermissions;
  const nextPerms = nextProps.userPermissions;

  if (prevPerms === nextPerms) {
    return true; // Same reference, no change
  }

  if (!prevPerms || !nextPerms) {
    return false; // One is null and the other isn't, needs re-render
  }

  // Compare all permission fields
  const permissionKeys: (keyof typeof prevPerms)[] = [
    'view_settings', 'view_activity', 'manage_compliance',
    'view_members', 'add_members',
    'edit_roles', 'edit_permissions', 'kick_members',
    'manage_teams_and_projects'
  ];

  for (const key of permissionKeys) {
    if (prevPerms[key] !== nextPerms[key]) {
      return false; // Permission changed, needs re-render
    }
  }

  return true; // Permissions are the same
});

