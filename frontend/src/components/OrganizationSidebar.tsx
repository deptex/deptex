import { memo, useState, useMemo, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { LayoutDashboard, Scale, ShieldAlert, Settings, Plus, Loader2, User, BookOpen, Mail, LogOut } from 'lucide-react';
import { cn } from '../lib/utils';
import { RolePermissions, Team, Project, api } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from './ui/dialog';
import { Button } from './ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';

/** Current org for profile card display (name, role, plan). */
export interface SidebarCurrentOrganization {
  id: string;
  name: string;
  role?: string;
  plan?: string;
  avatar_url?: string | null;
}

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
  /** User info for profile card at bottom of sidebar */
  user?: { email?: string | null; user_metadata?: { full_name?: string } } | null;
  avatarUrl?: string;
  onSignOut?: () => Promise<void>;
  /** Current organization for role/plan display in profile card */
  currentOrganization?: SidebarCurrentOrganization | null;
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
  { id: 'vulnerabilities', label: 'Vulnerabilities', path: 'vulnerabilities', icon: ShieldAlert, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: Scale, requiredPermission: null },
  // Settings visible to all org members; each tab inside is gated by its own permission
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: null },
];

/** Section label and item ids. */
const SIDEBAR_SECTIONS: { label: string; itemIds: string[] }[] = [
  { label: 'Workspace', itemIds: ['overview', 'vulnerabilities', 'compliance'] },
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
  user = null,
  avatarUrl = '/images/blank_profile_image.png',
  onSignOut,
  currentOrganization = null,
}: OrganizationSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [isHovered, setIsHovered] = useState(false);
  const pathParts = location.pathname.split('/');
  const [showCreateTeamModal, setShowCreateTeamModal] = useState(false);
  const [createTeamName, setCreateTeamName] = useState('');
  const [creating, setCreating] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  // Listen for overview-page "Create team" so modal can open from elsewhere
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
      const newTeam = await api.createTeam(organizationId, createTeamName.trim(), '');
      window.dispatchEvent(new CustomEvent('organization:teamCreated', {
        detail: { id: newTeam.id, name: newTeam.name, role_display_name: newTeam.role_display_name ?? null, role_color: newTeam.role_color ?? null }
      }));
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

  /** Per-section visible items for rendering sections with headers. */
  const sectionsWithItems = useMemo(() => {
    return SIDEBAR_SECTIONS.map((section) => ({
      ...section,
      items: section.itemIds
        .map((id) => visibleNavItems.find((item) => item.id === id))
        .filter((item): item is NavItemDef => item != null),
    })).filter((s) => s.items.length > 0);
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
    if (pathParts.includes('vulnerabilities')) return 'vulnerabilities';
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

  // Keep sidebar expanded when profile dropdown is open so it doesn't collapse/shift while using the menu
  const expanded = isHovered || profileOpen;

  return (
    <>
    <aside
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        'fixed left-0 top-12 bottom-0 bg-background border-r border-border z-40 flex flex-col transition-[width] duration-200 overflow-hidden',
        expanded ? 'w-48' : 'w-12'
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
                        expanded ? 'gap-2.5' : 'gap-0',
                        isActive
                          ? 'text-foreground bg-background-card'
                          : 'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                      )}
                    >
                      <Icon className="h-[1.3125rem] w-[1.3125rem] flex-shrink-0 tab-icon-shake" />
                      <span
                        className={cn(
                          'truncate transition-opacity duration-200 min-w-0',
                          expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
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

      {/* Profile at bottom — same structure as nav sections (separator + row like other tabs) */}
      {user != null && (
        <>
          <div className="py-3 flex-shrink-0" aria-hidden>
            <div className="border-t border-border" />
          </div>
          <div className="pl-1 pr-2 pb-3 flex-shrink-0">
            <div className="space-y-0.5">
              <DropdownMenu open={profileOpen} onOpenChange={setProfileOpen}>
                <DropdownMenuTrigger asChild>
                  <button
                    type="button"
                    aria-label="Open account menu"
                    className={cn(
                      'w-full flex items-center h-9 pl-0.5 pr-1 text-sm font-medium rounded-md transition-colors whitespace-nowrap',
                      expanded ? 'gap-2.5' : 'gap-0',
                      'text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50'
                    )}
                  >
                    <img
                      src={avatarUrl}
                      alt=""
                      className="h-8 w-8 min-h-8 min-w-8 rounded-full object-cover border border-border flex-shrink-0"
                      onError={(e) => {
                        e.currentTarget.src = '/images/blank_profile_image.png';
                      }}
                    />
                    <span
                      className={cn(
                        'truncate transition-opacity duration-200 min-w-0 text-foreground',
                        expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
                      )}
                    >
                      {user?.user_metadata?.full_name || user?.email || 'Account'}
                    </span>
                  </button>
                </DropdownMenuTrigger>
            <DropdownMenuContent align="end" side="right" className="w-72 p-0 px-3 pt-3 pb-3" alignOffset={8}>
              {/* User info */}
              <div className="flex items-center gap-3 px-0 py-3">
                <img
                  src={avatarUrl}
                  alt=""
                  className="h-10 w-10 rounded-full object-cover border border-border flex-shrink-0"
                  onError={(e) => {
                    e.currentTarget.src = '/images/blank_profile_image.png';
                  }}
                />
                <div className="min-w-0 flex-1">
                  {user?.user_metadata?.full_name && (
                    <p className="text-sm font-medium text-foreground truncate">{user.user_metadata.full_name}</p>
                  )}
                  <p className="text-xs text-foreground-secondary truncate">{user?.email}</p>
                </div>
              </div>
              <DropdownMenuSeparator />
              {/* Account Settings, Documentation, Support — no borders between */}
              <DropdownMenuItem asChild>
                <Link
                  to="/settings"
                  className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary"
                  onClick={() => setProfileOpen(false)}
                >
                  <User className="h-4 w-4" />
                  Account Settings
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a
                  href="/docs"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary"
                  onClick={() => setProfileOpen(false)}
                >
                  <BookOpen className="h-4 w-4" />
                  Documentation
                </a>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a
                  href="/docs/help"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary"
                  onClick={() => setProfileOpen(false)}
                >
                  <Mail className="h-4 w-4" />
                  Support
                </a>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <div className="pt-2">
                <DropdownMenuItem
                  onClick={async () => {
                    setProfileOpen(false);
                    await onSignOut?.();
                    navigate('/');
                  }}
                  className="cursor-pointer text-destructive focus:text-destructive focus:bg-destructive/10 flex items-center gap-2 rounded-md"
                >
                  <LogOut className="h-4 w-4" />
                  Log out
                </DropdownMenuItem>
              </div>
            </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </>
      )}
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
  if (prevProps.user !== nextProps.user) return false;
  if (prevProps.avatarUrl !== nextProps.avatarUrl) return false;
  const prevOrg = prevProps.currentOrganization;
  const nextOrg = nextProps.currentOrganization;
  if (prevOrg?.id !== nextOrg?.id || prevOrg?.name !== nextOrg?.name || prevOrg?.role !== nextOrg?.role || prevOrg?.plan !== nextOrg?.plan) return false;

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
