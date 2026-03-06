import { memo, useState, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Package, Scale, TowerControl, Settings } from 'lucide-react';
import { cn } from '../lib/utils';
import { ProjectPermissions } from '../lib/api';

interface ProjectSidebarProps {
  organizationId: string;
  projectId: string;
  userPermissions?: ProjectPermissions | null;
}

type NavItemDef = {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  requiredPermission: keyof ProjectPermissions | null;
};

const allNavItems: NavItemDef[] = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'dependencies', label: 'Dependencies', path: 'dependencies', icon: Package, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: Scale, requiredPermission: null },
  { id: 'watchtower', label: 'Watchtower', path: 'watchtower', icon: TowerControl, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

/** Section grouping with borders between (matches OrganizationSidebar pattern). */
const SIDEBAR_SECTIONS: { itemIds: string[] }[] = [
  { itemIds: ['overview', 'dependencies'] },
  { itemIds: ['compliance', 'watchtower'] },
  { itemIds: ['settings'] },
];

function ProjectSidebar({ organizationId, projectId, userPermissions }: ProjectSidebarProps) {
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

  /** Per-section visible items for rendering sections with dividers. */
  const sectionsWithItems = useMemo(() => {
    return SIDEBAR_SECTIONS.map((section) => ({
      ...section,
      items: section.itemIds
        .map((id) => visibleNavItems.find((item) => item.id === id))
        .filter((item): item is NavItemDef => item != null),
    })).filter((s) => s.items.length > 0);
  }, [visibleNavItems]);

  const pathParts = location.pathname.split('/');
  // Project-level tab is the segment right after projectId (e.g. .../projects/PROJECT_ID/dependencies/...).
  // Use that instead of the last segment so opening a package's "overview" under Dependencies
  // doesn't highlight the main Overview tab.
  const projectsIndex = pathParts.indexOf('projects');
  const projectTabSegment =
    projectsIndex >= 0 ? pathParts[projectsIndex + 2] : undefined;
  const lastSegment = pathParts[pathParts.length - 1];
  const parentSegment = pathParts[pathParts.length - 2];

  const activeTab = useMemo(() => {
    // Match by project-level segment first (e.g. "dependencies", "overview", "settings")
    const matchingTab = visibleNavItems.find((tab) => tab.path === projectTabSegment);
    if (matchingTab) return matchingTab.id;
    // No segment after project id (e.g. .../projects/PROJECT_ID) or last segment is project id
    if (!projectTabSegment || lastSegment === projectId) return 'overview';
    if (projectTabSegment === 'dependencies') return 'dependencies';
    if (projectTabSegment === 'compliance' || parentSegment === 'compliance') return 'compliance';
    if (projectTabSegment === 'watchtower') return 'watchtower';
    return 'overview';
  }, [projectTabSegment, lastSegment, projectId, parentSegment, visibleNavItems]);

  const handleNavClick = (path: string) => {
    if (path === 'overview') {
      navigate(`/organizations/${organizationId}/projects/${projectId}`);
    } else if (path === 'compliance') {
      navigate(`/organizations/${organizationId}/projects/${projectId}/compliance/project`);
    } else {
      navigate(`/organizations/${organizationId}/projects/${projectId}/${path}`);
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
      <nav className="flex-1 py-2 overflow-y-auto" aria-label="Project navigation">
        <div className="px-2">
          {sectionsWithItems.map((section, sectionIndex) => (
            <div key={section.itemIds.join('-')}>
              {sectionIndex > 0 && (
                <div className="py-3" aria-hidden>
                  <div className="border-t border-border" />
                </div>
              )}
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const isActive = activeTab === item.id;
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      onClick={() => handleNavClick(item.path)}
                      aria-current={isActive ? 'page' : undefined}
                      className={cn(
                        'w-full flex items-center h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                        isHovered ? 'gap-2.5' : 'gap-0',
                        isActive
                          ? 'text-foreground bg-background-card'
                          : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      <Icon className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0 tab-icon-shake" />
                      <span
                        className={cn(
                          'truncate transition-opacity duration-200 min-w-0',
                          isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
                        )}
                      >
                        {item.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </nav>
    </aside>
  );
}

export default memo(ProjectSidebar, (prevProps, nextProps) => {
  return (
    prevProps.organizationId === nextProps.organizationId &&
    prevProps.projectId === nextProps.projectId &&
    prevProps.userPermissions?.view_settings === nextProps.userPermissions?.view_settings
  );
});
