import { memo, useState, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, Users, ShieldAlert, ClipboardCheck, Settings } from 'lucide-react';
import { cn } from '../lib/utils';
import { RolePermissions } from '../lib/api';

interface OrganizationSidebarProps {
  organizationId: string;
  userPermissions?: RolePermissions | null;
}

const allNavItems = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'security', label: 'Security', path: 'security', icon: ShieldAlert, requiredPermission: null },
  { id: 'projects', label: 'Projects', path: 'projects', icon: FolderKanban, requiredPermission: null },
  { id: 'teams', label: 'Teams', path: 'teams', icon: Users, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: ClipboardCheck, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

function OrganizationSidebar({ organizationId, userPermissions }: OrganizationSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [isHovered, setIsHovered] = useState(false);

  const visibleNavItems = useMemo(() => {
    return allNavItems.filter((item) => {
      if (!item.requiredPermission) return true;
      if (!userPermissions) return false;
      return userPermissions[item.requiredPermission] === true;
    });
  }, [userPermissions]);

  const pathParts = location.pathname.split('/');
  const currentTab = pathParts[pathParts.length - 1];

  const activeTab = useMemo(() => {
    const matchingTab = visibleNavItems.find((tab) => tab.path === currentTab);
    if (matchingTab) return matchingTab.id;
    // If we're under /organizations/:id/settings or /organizations/:id/settings/:section,
    // highlight Settings in the sidebar
    if (pathParts.includes('settings')) {
      const settingsTab = visibleNavItems.find((tab) => tab.id === 'settings');
      if (settingsTab) return 'settings';
    }
    if (currentTab === organizationId) {
      const overviewTab = visibleNavItems.find((tab) => tab.id === 'overview');
      return overviewTab ? 'overview' : 'projects';
    }
    return 'overview';
  }, [currentTab, organizationId, visibleNavItems, location.pathname]);

  const handleNavClick = (path: string) => {
    if (path === 'overview') {
      navigate(`/organizations/${organizationId}`);
    } else {
      navigate(`/organizations/${organizationId}/${path}`);
    }
  };

  return (
    <aside
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        'fixed left-0 top-12 bottom-0 bg-background border-r border-border z-40 flex flex-col transition-[width] duration-200 overflow-hidden',
        isHovered ? 'w-48' : 'w-12'
      )}
    >
      <nav className="flex-1 py-2" aria-label="Organization navigation">
        <div className="space-y-0.5 px-2">
          {visibleNavItems.map((item) => {
            const isActive = activeTab === item.id;
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.path)}
                aria-current={isActive ? 'page' : undefined}
                className={cn(
                  'w-full flex items-center gap-2.5 h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                  isActive
                    ? 'text-foreground bg-background-card'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                )}
              >
                <Icon className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0 tab-icon-shake" />
                <span
                  className={cn(
                    'truncate transition-opacity duration-200',
                    isHovered ? 'opacity-100' : 'opacity-0'
                  )}
                >
                  {item.label}
                </span>
              </button>
            );
          })}
        </div>
      </nav>
    </aside>
  );
}

export default memo(OrganizationSidebar, (prevProps, nextProps) => {
  if (prevProps.organizationId !== nextProps.organizationId) return false;

  const prevPerms = prevProps.userPermissions;
  const nextPerms = nextProps.userPermissions;

  if (prevPerms === nextPerms) return true;
  if (!prevPerms || !nextPerms) return false;

  const permissionKeys: (keyof RolePermissions)[] = [
    'view_settings', 'view_activity', 'manage_compliance',
    'view_members', 'add_members',
    'edit_roles', 'edit_permissions', 'kick_members',
    'manage_teams_and_projects'
  ];

  for (const key of permissionKeys) {
    if (prevPerms[key] !== nextPerms[key]) return false;
  }

  return true;
});
