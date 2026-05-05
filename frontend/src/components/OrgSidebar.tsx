import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Scale,
  ShieldAlert,
  Settings,
  MessageSquare,
  Workflow,
  User,
  BookOpen,
  Mail,
  LogOut,
  Loader2,
  Plus,
  ChevronLeft,
  ChevronRight,
  Search,
} from 'lucide-react';

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from './ui/sidebar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from './ui/dialog';
import { Button } from './ui/button';
import OrganizationSwitcher from './OrganizationSwitcher';
import FeedbackPopover from './FeedbackPopover';
import { cn } from '../lib/utils';
import { api, Organization, RolePermissions } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import {
  buildOrgSettingsSections,
  computeEffectiveOrgPermissions,
  OrgSettingsSectionEntry,
} from '../lib/orgSettingsSections';

interface OrgSidebarProps {
  organizationId: string;
  organization: Organization | null;
  userPermissions?: RolePermissions | null;
  onRefetchTeams?: () => void | Promise<void>;
  user?: { email?: string | null; user_metadata?: { full_name?: string } } | null;
  avatarUrl?: string;
  onSignOut?: () => Promise<void>;
}

type NavItemDef = {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  requiredPermission: keyof RolePermissions | null;
  drilldown?: boolean;
};

const allNavItems: NavItemDef[] = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'aegis', label: 'Aegis', path: 'aegis', icon: MessageSquare, requiredPermission: 'interact_with_aegis' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', path: 'vulnerabilities', icon: ShieldAlert, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: Scale, requiredPermission: null },
  { id: 'flows', label: 'Flows', path: 'flows', icon: Workflow, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: null, drilldown: true },
];

export default function OrgSidebar({
  organizationId,
  organization,
  userPermissions,
  onRefetchTeams,
  user = null,
  avatarUrl = '/images/blank_profile_image.png',
  onSignOut,
}: OrgSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [profileOpen, setProfileOpen] = useState(false);
  const [feedbackOpen, setFeedbackOpen] = useState(false);

  const [showCreateTeamModal, setShowCreateTeamModal] = useState(false);
  const [createTeamName, setCreateTeamName] = useState('');
  const [creating, setCreating] = useState(false);

  // Existing event used by overview page "Create team" affordance — keep wired.
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
        detail: {
          id: newTeam.id,
          name: newTeam.name,
          role_display_name: newTeam.role_display_name ?? null,
          role_color: newTeam.role_color ?? null,
        },
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

  const activeNavId = useMemo(() => {
    const pathParts = location.pathname.split('/');
    if (pathParts.includes('settings')) return 'settings';
    if (pathParts.includes('compliance')) return 'compliance';
    if (pathParts.includes('vulnerabilities')) return 'vulnerabilities';
    if (pathParts.includes('aegis')) return 'aegis';
    if (pathParts.includes('flows')) return 'flows';
    return 'overview';
  }, [location.pathname]);

  const inSettings = useMemo(() => {
    const parts = location.pathname.split('/').filter(Boolean);
    // /organizations/:id/settings[/:section] — we only want this org's drilldown,
    // not the personal /settings route.
    return parts[0] === 'organizations' && parts[1] === organizationId && parts[2] === 'settings';
  }, [location.pathname, organizationId]);

  const settingsActiveSection = useMemo(() => {
    if (!inSettings) return null;
    const parts = location.pathname.split('/').filter(Boolean);
    return parts[3] || 'general';
  }, [inSettings, location.pathname]);

  const effectivePerms = useMemo(
    () => computeEffectiveOrgPermissions(organization?.role, userPermissions ?? null),
    [organization?.role, userPermissions],
  );

  const settingsGroups = useMemo(() => {
    if (!inSettings) return [] as { label: string | null; items: OrgSettingsSectionEntry[] }[];
    const entries = buildOrgSettingsSections(effectivePerms);
    const groups: { label: string | null; items: OrgSettingsSectionEntry[] }[] = [];
    let current: { label: string | null; items: OrgSettingsSectionEntry[] } | null = null;
    for (const entry of entries) {
      if ('isCategory' in entry && entry.isCategory) {
        current = { label: entry.label, items: [] };
        groups.push(current);
      } else if (current) {
        current.items.push(entry);
      } else {
        current = { label: null, items: [entry] };
        groups.push(current);
      }
    }
    return groups;
  }, [inSettings, effectivePerms]);

  const handleNavClick = (path: string) => {
    if (path === 'overview') {
      navigate(`/organizations/${organizationId}`);
    } else {
      navigate(`/organizations/${organizationId}/${path}`);
    }
  };

  const handleBackFromSettings = () => {
    navigate(`/organizations/${organizationId}`);
  };

  const handleSettingsItemClick = (sectionId: string) => {
    navigate(`/organizations/${organizationId}/settings/${sectionId}`);
  };

  const displayName = user?.user_metadata?.full_name || user?.email || 'Account';

  return (
    <>
      <Sidebar collapsible="offcanvas">
        <SidebarHeader className="px-2 py-2">
          {organization ? (
            <OrganizationSwitcher
              currentOrganizationId={organization.id}
              currentOrganizationName={organization.name}
              currentOrganizationAvatarUrl={organization.avatar_url}
              currentOrganizationRole={organization.role}
              currentOrganizationRoleDisplayName={organization.role_display_name}
              currentOrganizationRoleColor={organization.role_color}
              triggerVariant="full"
            />
          ) : (
            <div className="flex items-center gap-2 px-1 py-1" aria-hidden>
              <div className="h-6 w-6 rounded-full bg-muted animate-pulse flex-shrink-0" />
              <div className="h-4 w-24 rounded bg-muted animate-pulse" />
            </div>
          )}
        </SidebarHeader>

        <div className="px-2 pb-1">
          <button
            type="button"
            className="w-full flex items-center gap-2 px-3 h-9 rounded-md bg-background-subtle/50 border border-border/50 text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors text-left"
          >
            <Search className="h-4 w-4 flex-shrink-0" />
            <span className="text-sm flex-1">Find...</span>
            <kbd className="flex items-center justify-center h-5 w-5 rounded border border-border text-[10px] font-medium text-foreground-secondary bg-background">
              F
            </kbd>
          </button>
        </div>

        <SidebarContent>
          <div className="relative">
            {/* Main nav — fades out left when entering settings */}
            <div className={cn(
              'transition-[opacity,transform] duration-150 ease-out',
              inSettings ? 'opacity-0 -translate-x-2 pointer-events-none' : 'opacity-100 translate-x-0'
            )}>
              <SidebarGroup>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {visibleNavItems.map((item) => {
                      const Icon = item.icon;
                      const isActive = activeNavId === item.id;
                      return (
                        <SidebarMenuItem key={item.id}>
                          <SidebarMenuButton
                            isActive={isActive}
                            onClick={() => handleNavClick(item.path)}
                            aria-current={isActive ? 'page' : undefined}
                          >
                            <Icon className="tab-icon-shake" />
                            <span>{item.label}</span>
                            {item.drilldown && (
                              <ChevronRight className="ml-auto h-3.5 w-3.5 text-foreground-secondary flex-shrink-0" />
                            )}
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            </div>

            {/* Settings nav — fades in from right */}
            <div className={cn(
              'absolute top-0 left-0 w-full transition-[opacity,transform] duration-150 ease-out',
              inSettings ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-2 pointer-events-none'
            )}>
              <SidebarGroup>
                <SidebarGroupContent>
                  <SidebarMenu>
                    <SidebarMenuItem>
                      <button
                        onClick={handleBackFromSettings}
                        className="nav-btn relative w-full flex items-center justify-center h-9 rounded-md px-3 text-sm font-medium text-foreground-secondary hover:bg-background-subtle/75 hover:text-foreground transition-colors"
                      >
                        <ChevronLeft className="absolute left-3 h-5 w-5 tab-icon-shake" />
                        <span>Settings</span>
                      </button>
                    </SidebarMenuItem>
                    {settingsGroups.flatMap((group) => group.items).map((item) => {
                      const isActive = settingsActiveSection === item.id;
                      return (
                        <SidebarMenuItem key={item.id}>
                          <SidebarMenuButton
                            isActive={isActive}
                            onClick={() => handleSettingsItemClick(item.id)}
                            aria-current={isActive ? 'page' : undefined}
                          >
                            {item.icon}
                            <span>{item.label}</span>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            </div>
          </div>
        </SidebarContent>

        {user != null && (
          <SidebarFooter className="border-t border-border px-2 py-2">
            <DropdownMenu open={profileOpen} onOpenChange={setProfileOpen}>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label="Open account menu"
                  className="w-full flex items-center gap-2.5 h-9 px-1.5 rounded-md text-sm font-medium text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50 transition-colors"
                >
                  <img
                    src={avatarUrl}
                    alt=""
                    className="h-7 w-7 rounded-full object-cover border border-border flex-shrink-0"
                    onError={(e) => {
                      e.currentTarget.src = '/images/blank_profile_image.png';
                    }}
                  />
                  <span className="truncate min-w-0 text-foreground">{displayName}</span>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="start"
                side="top"
                className="w-72 p-0 px-3 pt-3 pb-3"
                alignOffset={0}
                sideOffset={8}
              >
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
                      <p className="text-sm font-medium text-foreground truncate">
                        {user.user_metadata.full_name}
                      </p>
                    )}
                    <p className="text-xs text-foreground-secondary truncate">{user?.email}</p>
                  </div>
                </div>
                <DropdownMenuSeparator />
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
                <DropdownMenuItem
                  onClick={() => {
                    setProfileOpen(false);
                    setFeedbackOpen(true);
                  }}
                  className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary"
                >
                  <MessageSquare className="h-4 w-4" />
                  Feedback
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
                    Contact Support
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
          </SidebarFooter>
        )}
      </Sidebar>

      <FeedbackPopover open={feedbackOpen} onOpenChange={setFeedbackOpen} hideTrigger />

      <Dialog
        open={showCreateTeamModal}
        onOpenChange={(open) => {
          if (!open) {
            setShowCreateTeamModal(false);
            setCreateTeamName('');
          }
        }}
      >
        <DialogContent
          hideClose
          className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden max-h-[90vh] flex flex-col"
        >
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
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleCreateTeam();
                }
              }}
            />
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button
              variant="outline"
              onClick={() => {
                setShowCreateTeamModal(false);
                setCreateTeamName('');
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleCreateTeam}
              disabled={creating}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-9"
            >
              {creating ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin mr-2" /> Create
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4 mr-2" /> Create
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
