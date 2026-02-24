import { memo, useState, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, Users, ShieldAlert, Settings } from 'lucide-react';
import { cn } from '../lib/utils';
import { TeamPermissions } from '../lib/api';

interface TeamSidebarProps {
  organizationId: string;
  teamId: string;
  userPermissions?: TeamPermissions | null;
}

const allNavItems = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'projects', label: 'Projects', path: 'projects', icon: FolderKanban, requiredPermission: null },
  { id: 'members', label: 'Members', path: 'members', icon: Users, requiredPermission: null },
  { id: 'alerts', label: 'Vulnerabilities', path: 'alerts', icon: ShieldAlert, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

function TeamSidebar({ organizationId, teamId, userPermissions }: TeamSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [isHovered, setIsHovered] = useState(false);

  const visibleNavItems = useMemo(() => {
    if (!userPermissions) return [];

    return allNavItems.filter((item) => {
      if (!item.requiredPermission) return true;
      return userPermissions[item.requiredPermission] === true;
    });
  }, [userPermissions]);

  const pathParts = location.pathname.split('/');
  const currentTab = pathParts[pathParts.length - 1];

  const activeTab = useMemo(() => {
    const matchingTab = visibleNavItems.find((tab) => tab.path === currentTab);
    if (matchingTab) return matchingTab.id;
    if (currentTab === teamId) {
      const overviewTab = visibleNavItems.find((tab) => tab.id === 'overview');
      return overviewTab ? 'overview' : 'projects';
    }
    return 'overview';
  }, [currentTab, teamId, visibleNavItems]);

  const handleNavClick = (path: string) => {
    if (path === 'overview') {
      navigate(`/organizations/${organizationId}/teams/${teamId}`);
    } else {
      navigate(`/organizations/${organizationId}/teams/${teamId}/${path}`);
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
      <nav className="flex-1 py-2" aria-label="Team navigation">
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

export default memo(TeamSidebar, (prevProps, nextProps) => {
  if (prevProps.organizationId !== nextProps.organizationId) return false;
  if (prevProps.teamId !== nextProps.teamId) return false;

  const prevPerms = prevProps.userPermissions;
  const nextPerms = nextProps.userPermissions;

  if (prevPerms === nextPerms) return true;
  if (!prevPerms || !nextPerms) return false;

  const permissionKeys: (keyof TeamPermissions)[] = [
    'view_overview', 'resolve_alerts', 'manage_projects',
    'manage_members', 'view_settings', 'view_roles', 'edit_roles',
    'manage_notification_settings'
  ];

  for (const key of permissionKeys) {
    if (prevPerms[key] !== nextPerms[key]) return false;
  }

  return true;
});
