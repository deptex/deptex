import { memo, useState, useMemo, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, Users, Settings, Plus } from 'lucide-react';
import { cn } from '../lib/utils';
import { TeamPermissions, Project } from '../lib/api';

interface TeamSidebarProps {
  organizationId: string;
  teamId: string;
  userPermissions?: TeamPermissions | null;
  projects?: Project[];
  projectsLoading?: boolean;
  canCreateProject?: boolean;
  onOpenCreateProject?: () => void;
}

type NavItemDef = {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  requiredPermission: keyof TeamPermissions | null;
};

const allNavItems: NavItemDef[] = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'members', label: 'Members', path: 'members', icon: Users, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

/** Section grouping: Overview + Projects, then (border) Members + Settings. */
const SIDEBAR_SECTIONS: { itemIds: string[]; isProjectsSection?: boolean }[] = [
  { itemIds: ['overview'], isProjectsSection: true },
  { itemIds: ['members', 'settings'] },
];

function TeamSidebar({
  organizationId,
  teamId,
  userPermissions,
  projects = [],
  projectsLoading = false,
  canCreateProject = false,
  onOpenCreateProject,
}: TeamSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [isHovered, setIsHovered] = useState(false);
  const pathParts = location.pathname.split('/');
  const projectsIndex = pathParts.indexOf('projects');
  const activeProjectId = projectsIndex >= 0 && pathParts[projectsIndex + 1] ? pathParts[projectsIndex + 1] : null;
  const [projectsExpanded, setProjectsExpanded] = useState(() => pathParts.includes('projects'));

  useEffect(() => {
    if (activeProjectId) setProjectsExpanded(true);
  }, [activeProjectId]);

  useEffect(() => {
    if (!isHovered) setProjectsExpanded(false);
  }, [isHovered]);

  const visibleNavItems = useMemo(() => {
    if (!userPermissions) return [];

    return allNavItems.filter((item) => {
      if (!item.requiredPermission) return true;
      return userPermissions[item.requiredPermission] === true;
    });
  }, [userPermissions]);

  const teamProjects = useMemo(
    () => projects.filter((p) => p.team_ids?.includes(teamId)),
    [projects, teamId]
  );

  /** Per-section visible items. Include Projects section even with 0 items so we can render dropdown + Settings. */
  const sectionsWithItems = useMemo(() => {
    return SIDEBAR_SECTIONS.map((section) => ({
      ...section,
      items: section.itemIds
        .map((id) => visibleNavItems.find((item) => item.id === id))
        .filter((item): item is NavItemDef => item != null),
    })).filter((s) => s.items.length > 0 || s.isProjectsSection);
  }, [visibleNavItems]);

  const currentTab = pathParts[pathParts.length - 1];
  const parentSegment = pathParts[pathParts.length - 2];

  const activeTab = useMemo(() => {
    if (parentSegment === 'settings') {
      const settingsTab = visibleNavItems.find((tab) => tab.id === 'settings');
      return settingsTab ? 'settings' : 'overview';
    }
    const matchingTab = visibleNavItems.find((tab) => tab.path === currentTab);
    if (matchingTab) return matchingTab.id;
    if (currentTab === teamId) return 'overview';
    return 'overview';
  }, [currentTab, parentSegment, teamId, visibleNavItems]);

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
      <nav className="flex-1 py-2 overflow-y-auto" aria-label="Team navigation">
        <div className="px-2">
          {sectionsWithItems.map((section, sectionIndex) => (
            <div key={section.itemIds.join('-') + (section.isProjectsSection ? '-projects' : '')}>
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
                {section.isProjectsSection && (
                  <>
                    <div
                      className={cn(
                        'w-full flex items-center h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                        isHovered ? 'gap-2.5' : 'gap-0',
                        'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      <button
                        type="button"
                        onClick={() => setProjectsExpanded((e) => !e)}
                        aria-expanded={projectsExpanded}
                        className="flex items-center min-w-0 flex-1 gap-2.5 text-left"
                      >
                        <FolderKanban className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0 tab-icon-shake" />
                        <span
                          className={cn(
                            'truncate transition-opacity duration-200 min-w-0',
                            isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
                          )}
                        >
                          Projects
                        </span>
                      </button>
                      {isHovered && canCreateProject && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenCreateProject?.();
                          }}
                          className="p-0.5 rounded text-muted-foreground hover:text-foreground hover:bg-background-subtle transition-colors"
                          aria-label="Create project"
                        >
                          <Plus className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                    <div
                      className={cn(
                        'grid transition-[grid-template-rows] duration-200 ease-out',
                        projectsExpanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'
                      )}
                    >
                      <div className="min-h-0 overflow-hidden">
                        <div className={cn('space-y-0.5', isHovered ? 'ml-6 pl-0' : 'ml-0')}>
                          {projectsLoading ? (
                            [1, 2, 3].map((i) => (
                              <div key={i} className="flex items-center h-9 px-1.5">
                                <div className={cn('h-3 rounded bg-muted/40 animate-pulse', isHovered ? 'w-24' : 'w-4')} />
                              </div>
                            ))
                          ) : (
                            teamProjects.map((project) => {
                              const isProjectActive = activeProjectId === project.id;
                              return (
                                <button
                                  key={project.id}
                                  onClick={() => navigate(`/organizations/${organizationId}/projects/${project.id}/overview`)}
                                  aria-current={isProjectActive ? 'page' : undefined}
                                  className={cn(
                                    'w-full flex items-center h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                                    isHovered ? 'gap-2.5' : 'gap-0',
                                    isProjectActive
                                      ? 'text-foreground bg-background-card'
                                      : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                                  )}
                                >
                                  <span
                                    className={cn(
                                      'truncate transition-opacity duration-200 min-w-0',
                                      isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
                                    )}
                                  >
                                    {project.name}
                                  </span>
                                </button>
                              );
                            })
                          )}
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </nav>
    </aside>
  );
}

export default memo(TeamSidebar, (prevProps, nextProps) => {
  if (prevProps.organizationId !== nextProps.organizationId) return false;
  if (prevProps.teamId !== nextProps.teamId) return false;
  if (prevProps.projectsLoading !== nextProps.projectsLoading) return false;
  if (prevProps.projects?.length !== nextProps.projects?.length) return false;
  const prevProjectIds = prevProps.projects?.map((p) => p.id).join(',') ?? '';
  const nextProjectIds = nextProps.projects?.map((p) => p.id).join(',') ?? '';
  if (prevProjectIds !== nextProjectIds) return false;
  if (prevProps.canCreateProject !== nextProps.canCreateProject) return false;

  const prevPerms = prevProps.userPermissions;
  const nextPerms = nextProps.userPermissions;

  if (prevPerms === nextPerms) return true;
  if (!prevPerms || !nextPerms) return false;

  const permissionKeys: (keyof TeamPermissions)[] = [
    'view_overview', 'manage_projects',
    'manage_members', 'view_settings', 'view_roles', 'edit_roles',
    'manage_notification_settings'
  ];

  for (const key of permissionKeys) {
    if (prevPerms[key] !== nextPerms[key]) return false;
  }

  return true;
});
