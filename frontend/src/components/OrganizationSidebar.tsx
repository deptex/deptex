import { memo, useState, useMemo, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, Users, Scale, TowerControl, Settings, Plus, Loader2 } from 'lucide-react';
import { cn } from '../lib/utils';
import { RolePermissions, Team, Project, api } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';

interface OrganizationSidebarProps {
  organizationId: string;
  userPermissions?: RolePermissions | null;
  teams?: Team[];
  teamsLoading?: boolean;
  onRefetchTeams?: () => void | Promise<void>;
  canCreateTeam?: boolean;
  projects?: Project[];
  projectsLoading?: boolean;
  onRefetchProjects?: () => void | Promise<void>;
  canCreateProject?: boolean;
  onOpenCreateProject?: () => void;
}

type NavItemDef = {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  requiredPermission: keyof RolePermissions | null;
};

const allNavItems: NavItemDef[] = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: Scale, requiredPermission: null },
  { id: 'watchtower', label: 'Watchtower', path: 'watchtower', icon: TowerControl, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: 'view_settings' as const },
];

/** Section label and item ids. Projects & Teams section renders custom dropdowns (no nav items). */
const SIDEBAR_SECTIONS: { label: string; itemIds: string[] }[] = [
  { label: 'Workspace', itemIds: ['overview', 'compliance', 'watchtower'] },
  { label: 'Projects & Teams', itemIds: [] },
  { label: 'Organization', itemIds: ['settings'] },
];

function OrganizationSidebar({
  organizationId,
  userPermissions,
  teams = [],
  teamsLoading = false,
  onRefetchTeams,
  canCreateTeam = false,
  projects = [],
  projectsLoading = false,
  onRefetchProjects,
  canCreateProject = false,
  onOpenCreateProject,
}: OrganizationSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [isHovered, setIsHovered] = useState(false);
  const pathParts = location.pathname.split('/');
  const teamsIndex = pathParts.indexOf('teams');
  const activeTeamId = teamsIndex >= 0 && pathParts[teamsIndex + 1] ? pathParts[teamsIndex + 1] : null;
  const projectsIndex = pathParts.indexOf('projects');
  const activeProjectId = projectsIndex >= 0 && pathParts[projectsIndex + 1] ? pathParts[projectsIndex + 1] : null;
  const [teamsExpanded, setTeamsExpanded] = useState(() => pathParts.includes('teams'));
  const [projectsExpanded, setProjectsExpanded] = useState(() => pathParts.includes('projects'));
  const [showCreateTeamModal, setShowCreateTeamModal] = useState(false);
  const [createTeamName, setCreateTeamName] = useState('');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (activeTeamId) setTeamsExpanded(true);
  }, [activeTeamId]);

  useEffect(() => {
    if (activeProjectId) setProjectsExpanded(true);
  }, [activeProjectId]);

  useEffect(() => {
    if (!isHovered) {
      setTeamsExpanded(false);
      setProjectsExpanded(false);
    }
  }, [isHovered]);

  // Listen for overview-page "Create team" so Plus dropdown can open the modal
  useEffect(() => {
    const handler = () => setShowCreateTeamModal(true);
    window.addEventListener('organization:openCreateTeam', handler);
    return () => window.removeEventListener('organization:openCreateTeam', handler);
  }, []);

  const handleCreateTeam = async () => {
    if (!organizationId || !createTeamName.trim()) {
      toast({ title: 'Error', description: 'Team name is required', variant: 'destructive' });
      return;
    }
    setCreating(true);
    try {
      await api.createTeam(organizationId, createTeamName.trim(), '');
      setShowCreateTeamModal(false);
      setCreateTeamName('');
      await onRefetchTeams?.();
      toast({ title: 'Success', description: 'Team created successfully' });
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to create team', variant: 'destructive' });
    } finally {
      setCreating(false);
    }
  };

  const visibleNavItems = useMemo(() => {
    return allNavItems.filter((item) => {
      if (!item.requiredPermission) return true;
      if (!userPermissions) return false;
      return userPermissions[item.requiredPermission] === true;
    });
  }, [userPermissions]);

  /** Per-section visible items for rendering sections with headers. Keep "Projects & Teams" even with 0 items. */
  const sectionsWithItems = useMemo(() => {
    return SIDEBAR_SECTIONS.map((section) => ({
      ...section,
      items: section.itemIds
        .map((id) => visibleNavItems.find((item) => item.id === id))
        .filter((item): item is NavItemDef => item != null),
    })).filter((s) => s.items.length > 0 || s.label === 'Projects & Teams');
  }, [visibleNavItems]);

  const currentTab = pathParts[pathParts.length - 1];

  const activeTab = useMemo(() => {
    // When under compliance (e.g. /compliance/overview), highlight Compliance in the sidebar
    if (pathParts.includes('compliance')) {
      const complianceTab = visibleNavItems.find((tab) => tab.id === 'compliance');
      if (complianceTab) return 'compliance';
    }
    const matchingTab = visibleNavItems.find((tab) => tab.path === currentTab);
    if (matchingTab) return matchingTab.id;
    // If we're under /organizations/:id/settings or /organizations/:id/settings/:section,
    // highlight Settings in the sidebar
    if (pathParts.includes('settings')) {
      const settingsTab = visibleNavItems.find((tab) => tab.id === 'settings');
      if (settingsTab) return 'settings';
    }
    if (pathParts.includes('watchtower')) return 'watchtower';
    if (currentTab === organizationId) {
      const overviewTab = visibleNavItems.find((tab) => tab.id === 'overview');
      return overviewTab ? 'overview' : 'overview';
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
    <>
    <aside
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        'fixed left-0 top-12 bottom-0 bg-background border-r border-border z-40 flex flex-col transition-[width] duration-200 overflow-hidden',
        isHovered ? 'w-48' : 'w-12'
      )}
    >
      <nav className="flex-1 py-2 overflow-y-auto" aria-label="Organization navigation">
        <div className="px-2">
          {sectionsWithItems.map((section, sectionIndex) => (
            <div key={section.label}>
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
                {section.label === 'Projects & Teams' && (
                  <>
                    {/* Projects dropdown */}
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
                            projects.map((project) => {
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
                    {/* Teams dropdown */}
                    <div
                      className={cn(
                        'w-full flex items-center h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                        isHovered ? 'gap-2.5' : 'gap-0',
                        'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      <button
                        type="button"
                        onClick={() => setTeamsExpanded((e) => !e)}
                        aria-expanded={teamsExpanded}
                        className="flex items-center min-w-0 flex-1 gap-2.5 text-left"
                      >
                        <Users className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0 tab-icon-shake" />
                        <span
                          className={cn(
                            'truncate transition-opacity duration-200 min-w-0',
                            isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
                          )}
                        >
                          Teams
                        </span>
                      </button>
                      {isHovered && canCreateTeam && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setShowCreateTeamModal(true);
                          }}
                          className="p-0.5 rounded text-muted-foreground hover:text-foreground hover:bg-background-subtle transition-colors"
                          aria-label="Create team"
                        >
                          <Plus className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                    <div
                      className={cn(
                        'grid transition-[grid-template-rows] duration-200 ease-out',
                        teamsExpanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'
                      )}
                    >
                      <div className="min-h-0 overflow-hidden">
                        <div className={cn('space-y-0.5', isHovered ? 'ml-6 pl-0' : 'ml-0')}>
                          {teamsLoading ? (
                            [1, 2, 3].map((i) => (
                              <div key={i} className="flex items-center h-9 px-1.5">
                                <div className={cn('h-3 rounded bg-muted/40 animate-pulse', isHovered ? 'w-24' : 'w-4')} />
                              </div>
                            ))
                          ) : (
                            teams.map((team) => {
                              const isTeamActive = activeTeamId === team.id;
                              return (
                                <button
                                  key={team.id}
                                  onClick={() => navigate(`/organizations/${organizationId}/teams/${team.id}`)}
                                  aria-current={isTeamActive ? 'page' : undefined}
                                  className={cn(
                                    'w-full flex items-center h-9 px-1.5 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                                    isHovered ? 'gap-2.5' : 'gap-0',
                                    isTeamActive
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
                                    {team.name}
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

    <Dialog open={showCreateTeamModal} onOpenChange={(open) => { if (!open) { setShowCreateTeamModal(false); setCreateTeamName(''); } }}>
      <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden max-h-[90vh] flex flex-col">
        <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
          <DialogTitle>Create Team</DialogTitle>
          <DialogDescription className="mt-1">
            Teams let you group projects and members together with scoped access control.
          </DialogDescription>
        </div>
        <div className="px-6 py-4 bg-background">
          <label htmlFor="sidebar-team-name" className="block text-sm font-medium text-foreground mb-2">
            Team Name
          </label>
          <input
            id="sidebar-team-name"
            type="text"
            value={createTeamName}
            onChange={(e) => setCreateTeamName(e.target.value)}
            placeholder=""
            className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleCreateTeam(); } }}
          />
        </div>
        <DialogFooter className="px-6 py-4 bg-background">
          <Button variant="outline" onClick={() => { setShowCreateTeamModal(false); setCreateTeamName(''); }}>
            Cancel
          </Button>
          <Button onClick={handleCreateTeam} disabled={creating} className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-9">
            {creating ? <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Create</> : <><Plus className="h-4 w-4 mr-2" /> Create</>}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    </>
  );
}

export default memo(OrganizationSidebar, (prevProps, nextProps) => {
  if (prevProps.organizationId !== nextProps.organizationId) return false;
  if (prevProps.teamsLoading !== nextProps.teamsLoading) return false;
  if (prevProps.canCreateTeam !== nextProps.canCreateTeam) return false;
  if (prevProps.teams?.length !== nextProps.teams?.length) return false;
  const prevTeamIds = prevProps.teams?.map((t) => t.id).join(',') ?? '';
  const nextTeamIds = nextProps.teams?.map((t) => t.id).join(',') ?? '';
  if (prevTeamIds !== nextTeamIds) return false;
  if (prevProps.projectsLoading !== nextProps.projectsLoading) return false;
  if (prevProps.canCreateProject !== nextProps.canCreateProject) return false;
  if (prevProps.projects?.length !== nextProps.projects?.length) return false;
  const prevProjectIds = prevProps.projects?.map((p) => p.id).join(',') ?? '';
  const nextProjectIds = nextProps.projects?.map((p) => p.id).join(',') ?? '';
  if (prevProjectIds !== nextProjectIds) return false;

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
