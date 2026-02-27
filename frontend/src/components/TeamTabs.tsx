import { memo, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, Users, ShieldAlert, Settings } from 'lucide-react';
import { TeamPermissions } from '../lib/api';

interface TeamTabsProps {
  organizationId: string;
  teamId: string;
  userPermissions?: TeamPermissions | null;
}

const allTabs = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null }, // Overview is always visible
  { id: 'projects', label: 'Projects', path: 'projects', icon: FolderKanban, requiredPermission: null },
  { id: 'members', label: 'Members', path: 'members', icon: Users, requiredPermission: null }, // Members is always visible
  { id: 'alerts', label: 'Vulnerabilities', path: 'alerts', icon: ShieldAlert, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

function TeamTabs({ organizationId, teamId, userPermissions }: TeamTabsProps) {
  const location = useLocation();
  const navigate = useNavigate();

  // Filter tabs based on permissions
  const visibleTabs = useMemo(() => {
    // If permissions are not loaded yet, don't show any tabs
    if (!userPermissions) {
      return [];
    }

    return allTabs.filter(tab => {
      if (!tab.requiredPermission) {
        return true; // Tab doesn't require a specific permission
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

    // If we're on the team root (no tab specified)
    if (currentTab === teamId) {
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
  }, [currentTab, teamId, visibleTabs]);

  const handleTabClick = (path: string) => {
    if (path === 'overview') {
      navigate(`/organizations/${organizationId}/teams/${teamId}`);
    } else {
      navigate(`/organizations/${organizationId}/teams/${teamId}/${path}`);
    }
  };

  return (
    <div className="border-b border-border bg-background -mt-3">
      <div className="mx-auto w-full">
        <nav className="flex items-center gap-6 px-6 pt-0" aria-label="Team navigation">
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

export default memo(TeamTabs, (prevProps, nextProps) => {
  if (prevProps.organizationId !== nextProps.organizationId) {
    return false;
  }
  if (prevProps.teamId !== nextProps.teamId) {
    return false;
  }

  const prevPerms = prevProps.userPermissions;
  const nextPerms = nextProps.userPermissions;

  if (prevPerms === nextPerms) {
    return true;
  }

  if (!prevPerms || !nextPerms) {
    return false;
  }

  // Compare all permission fields
  const permissionKeys: (keyof typeof prevPerms)[] = [
    'view_overview', 'manage_projects',
    'manage_members', 'view_settings', 'view_roles', 'edit_roles'
  ];

  for (const key of permissionKeys) {
    if (prevPerms[key] !== nextPerms[key]) {
      return false;
    }
  }

  return true;
});
