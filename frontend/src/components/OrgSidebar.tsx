import { useCallback, useEffect, useMemo, useState } from 'react';
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
  SquarePen,
  MoreHorizontal,
  Zap,
  Pencil,
  Trash2,
  Pin,
  PinOff,
  Archive,
  ArchiveRestore,
  Link2,
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
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import { cn } from '../lib/utils';
import { api, Organization, RolePermissions } from '../lib/api';
import { aegisApi, AegisThread, FixStatusForBadge } from '../lib/aegis-api';
import { useToast } from '../hooks/use-toast';
import { ThreadIcon } from './aegis/ThreadIcon';
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

function fixStatusLabel(fixStatus: FixStatusForBadge | null): string | null {
  switch (fixStatus) {
    case 'awaiting_approval': return 'Awaiting approval';
    case 'running': return 'Running';
    case 'succeeded': return 'PR opened';
    case 'failed': return 'Failed';
    case 'refused': return 'Aegis refused';
    case 'rejected': return 'Plan rejected';
    default: return null;
  }
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
  { id: 'aegis', label: 'Aegis', path: 'aegis', icon: MessageSquare, requiredPermission: 'interact_with_aegis', drilldown: true },
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

  const inAegis = useMemo(() => {
    const parts = location.pathname.split('/').filter(Boolean);
    return parts[0] === 'organizations' && parts[1] === organizationId && parts[2] === 'aegis';
  }, [location.pathname, organizationId]);

  const activeAegisThreadId = useMemo(() => {
    if (!inAegis) return null;
    const parts = location.pathname.split('/').filter(Boolean);
    const seg = parts[3];
    return seg && seg !== 'routines' ? seg : null;
  }, [inAegis, location.pathname]);

  const aegisRoutinesActive = useMemo(() => {
    if (!inAegis) return false;
    const parts = location.pathname.split('/').filter(Boolean);
    return parts[3] === 'routines';
  }, [inAegis, location.pathname]);

  const inAccount = useMemo(() => {
    const parts = location.pathname.split('/').filter(Boolean);
    return parts[0] === 'organizations' && parts[1] === organizationId && parts[2] === 'account';
  }, [location.pathname, organizationId]);

  const accountActiveSection = useMemo(() => {
    if (!inAccount) return null;
    const parts = location.pathname.split('/').filter(Boolean);
    return parts[3] || 'general';
  }, [inAccount, location.pathname]);

  const canUseAegis = userPermissions?.interact_with_aegis === true;

  const [aegisThreads, setAegisThreads] = useState<AegisThread[]>([]);
  const [aegisThreadsLoading, setAegisThreadsLoading] = useState(false);
  const [aegisEditingId, setAegisEditingId] = useState<string | null>(null);
  const [aegisDraftTitle, setAegisDraftTitle] = useState('');
  const [aegisConfirmDeleteId, setAegisConfirmDeleteId] = useState<string | null>(null);
  const [aegisDeleting, setAegisDeleting] = useState(false);

  const refreshAegisThreads = useCallback(async () => {
    if (!organizationId) return;
    try {
      const list = await aegisApi.listThreads(organizationId);
      setAegisThreads(list);
    } catch {
      setAegisThreads([]);
    }
  }, [organizationId]);

  useEffect(() => {
    if (!inAegis || !canUseAegis) {
      setAegisThreads([]);
      return;
    }
    let cancelled = false;
    setAegisThreadsLoading(true);
    refreshAegisThreads().then(() => {
      if (!cancelled) setAegisThreadsLoading(false);
    });
    return () => { cancelled = true; };
  }, [inAegis, canUseAegis, refreshAegisThreads]);

  useEffect(() => {
    const handler = () => { if (inAegis && canUseAegis) void refreshAegisThreads(); };
    window.addEventListener('aegis:threadListChanged', handler);
    return () => window.removeEventListener('aegis:threadListChanged', handler);
  }, [inAegis, canUseAegis, refreshAegisThreads]);

  const handleAegisRename = useCallback(async (threadId: string, title: string) => {
    let prev: AegisThread | undefined;
    setAegisThreads((ts) => {
      prev = ts.find((t) => t.id === threadId);
      return ts.map((t) => (t.id === threadId ? { ...t, title } : t));
    });
    try {
      await aegisApi.renameThread(threadId, title);
      window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
    } catch {
      if (prev) setAegisThreads((ts) => ts.map((t) => (t.id === threadId ? prev! : t)));
      toast({ title: 'Rename failed', variant: 'destructive' });
    }
  }, [toast]);

  const handleAegisSetPinned = useCallback(async (threadId: string, pinned: boolean) => {
    const now = new Date().toISOString();
    let snapshot: AegisThread[] = [];
    setAegisThreads((ts) => { snapshot = ts; return ts.map((t) => (t.id === threadId ? { ...t, pinnedAt: pinned ? now : null } : t)); });
    try {
      await aegisApi.setThreadPinned(threadId, pinned);
      window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
    } catch {
      setAegisThreads(snapshot);
      toast({ title: pinned ? 'Pin failed' : 'Unpin failed', variant: 'destructive' });
    }
  }, [toast]);

  const handleAegisSetArchived = useCallback(async (threadId: string, archived: boolean) => {
    const now = new Date().toISOString();
    let snapshot: AegisThread[] = [];
    setAegisThreads((ts) => { snapshot = ts; return ts.map((t) => (t.id === threadId ? { ...t, archivedAt: archived ? now : null } : t)); });
    if (archived && activeAegisThreadId === threadId) navigate(`/organizations/${organizationId}/aegis`);
    try {
      await aegisApi.setThreadArchived(threadId, archived);
      window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
    } catch {
      setAegisThreads(snapshot);
      toast({ title: archived ? 'Archive failed' : 'Unarchive failed', variant: 'destructive' });
    }
  }, [activeAegisThreadId, organizationId, navigate, toast]);

  const handleAegisDelete = useCallback(async () => {
    const threadId = aegisConfirmDeleteId;
    if (!threadId) return;
    let snapshot: AegisThread[] = [];
    setAegisThreads((ts) => { snapshot = ts; return ts.filter((t) => t.id !== threadId); });
    if (activeAegisThreadId === threadId) navigate(`/organizations/${organizationId}/aegis`);
    setAegisDeleting(true);
    try {
      await aegisApi.deleteThread(threadId);
      setAegisConfirmDeleteId(null);
      window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
    } catch {
      setAegisThreads(snapshot);
      toast({ title: 'Delete failed', variant: 'destructive' });
    } finally {
      setAegisDeleting(false);
    }
  }, [aegisConfirmDeleteId, activeAegisThreadId, organizationId, navigate, toast]);

  const commitAegisRename = () => {
    if (!aegisEditingId) return;
    const title = aegisDraftTitle.trim();
    const id = aegisEditingId;
    setAegisEditingId(null);
    if (!title) return;
    void handleAegisRename(id, title);
  };

  const { aegisPinned, aegisRecents } = useMemo(() => {
    const pinned = aegisThreads.filter((t) => t.pinnedAt && !t.archivedAt);
    const recents = aegisThreads.filter((t) => !t.pinnedAt && !t.archivedAt);
    pinned.sort((a, b) => (b.pinnedAt ?? '').localeCompare(a.pinnedAt ?? ''));
    recents.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return { aegisPinned: pinned, aegisRecents: recents };
  }, [aegisThreads]);

  const renderAegisThread = (thread: AegisThread) => {
    const isActive = thread.id === activeAegisThreadId;
    const isEditing = thread.id === aegisEditingId;
    const isPinned = !!thread.pinnedAt;
    const isArchived = !!thread.archivedAt;
    return (
      <SidebarMenuItem key={thread.id}>
        <div className="relative group/thread w-full">
          {isEditing ? (
            <input
              autoFocus
              value={aegisDraftTitle}
              onChange={(e) => setAegisDraftTitle(e.target.value)}
              onBlur={commitAegisRename}
              onKeyDown={(e) => {
                if (e.key === 'Enter') { e.preventDefault(); commitAegisRename(); }
                else if (e.key === 'Escape') { e.preventDefault(); setAegisEditingId(null); }
              }}
              className="w-full bg-background-subtle px-3 py-2 text-sm text-foreground rounded-md border-0 ring-1 ring-border outline-none focus:ring-1 focus:!ring-foreground/30"
            />
          ) : (
            <Tooltip delayDuration={500}>
              <TooltipTrigger asChild>
                <SidebarMenuButton
                  isActive={isActive}
                  onClick={() => navigate(`/organizations/${organizationId}/aegis/${thread.id}`)}
                >
                  <ThreadIcon fixStatus={thread.fixStatus} />
                  <span className="block min-w-0 flex-1 whitespace-nowrap overflow-hidden [mask-image:linear-gradient(to_right,black_calc(100%-12px),transparent)] group-hover/thread:[mask-image:linear-gradient(to_right,black_calc(100%-72px),transparent)]">
                    {thread.title}
                  </span>
                  {isPinned && (
                    <Pin className="flex-shrink-0 group-hover/thread:hidden text-foreground/40" style={{ width: 15, height: 15 }} />
                  )}
                </SidebarMenuButton>
              </TooltipTrigger>
              <TooltipContent side="right" sideOffset={8} className="max-w-xs whitespace-normal break-words">
                <div className="font-semibold text-foreground">{thread.title}</div>
                {fixStatusLabel(thread.fixStatus) && (
                  <div className="mt-1 flex items-center gap-1.5 text-foreground/60 text-xs">
                    <ThreadIcon fixStatus={thread.fixStatus} className="h-3 w-3" />
                    {fixStatusLabel(thread.fixStatus)}
                  </div>
                )}
              </TooltipContent>
            </Tooltip>
          )}
          {!isEditing && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 flex items-center justify-center rounded text-foreground/60 hover:text-foreground opacity-0 group-hover/thread:opacity-100 focus:opacity-100 transition-opacity z-10"
                  onClick={(e) => e.stopPropagation()}
                  aria-label="Thread actions"
                >
                  <MoreHorizontal className="h-4 w-4" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-40">
                {thread.isCreator && (
                  <DropdownMenuItem onClick={() => { setAegisEditingId(thread.id); setAegisDraftTitle(thread.title); }}>
                    <Pencil className="h-4 w-4 mr-2" />
                    Rename
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onClick={() => void handleAegisSetPinned(thread.id, !isPinned)}>
                  {isPinned ? <PinOff className="h-4 w-4 mr-2" /> : <Pin className="h-4 w-4 mr-2" />}
                  {isPinned ? 'Unpin' : 'Pin'}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => void handleAegisSetArchived(thread.id, !isArchived)}>
                  {isArchived ? <ArchiveRestore className="h-4 w-4 mr-2" /> : <Archive className="h-4 w-4 mr-2" />}
                  {isArchived ? 'Unarchive' : 'Archive'}
                </DropdownMenuItem>
                {thread.isCreator && (
                  <DropdownMenuItem
                    className="text-red-500 focus:text-red-500"
                    onClick={() => setAegisConfirmDeleteId(thread.id)}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </SidebarMenuItem>
    );
  };

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
            className="w-full flex items-center gap-2 px-3 h-8 rounded-md bg-background-subtle/50 border border-border/50 text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors text-left"
          >
            <Search className="h-4 w-4 flex-shrink-0" />
            <span className="text-sm flex-1">Find...</span>
            <kbd className="flex items-center justify-center h-5 w-5 rounded border border-border text-[10px] font-medium text-foreground-secondary bg-background">
              F
            </kbd>
          </button>
        </div>

        <SidebarContent className="relative">
          {/* Main nav — fades out left when entering any drilldown */}
          <div className={cn(
            'transition-[opacity,transform] duration-150 ease-out',
            (inSettings || inAegis || inAccount)
              ? 'absolute top-0 inset-x-0 opacity-0 -translate-x-2 pointer-events-none'
              : 'opacity-100 translate-x-0'
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
            'absolute top-0 inset-x-0 transition-[opacity,transform] duration-150 ease-out',
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

          {/* Account settings nav */}
          <div className={cn(
            'absolute top-0 inset-x-0 transition-[opacity,transform] duration-150 ease-out',
            inAccount ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-2 pointer-events-none'
          )}>
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <button
                      onClick={() => navigate(`/organizations/${organizationId}`)}
                      className="nav-btn relative w-full flex items-center justify-center h-9 rounded-md px-3 text-sm font-medium text-foreground-secondary hover:bg-background-subtle/75 hover:text-foreground transition-colors"
                    >
                      <ChevronLeft className="absolute left-3 h-5 w-5 tab-icon-shake" />
                      <span>Account</span>
                    </button>
                  </SidebarMenuItem>
                  <SidebarMenuItem>
                    <SidebarMenuButton
                      isActive={accountActiveSection === 'general'}
                      onClick={() => navigate(`/organizations/${organizationId}/account/general`)}
                    >
                      <Settings className="tab-icon-shake" />
                      <span>General</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                  <SidebarMenuItem>
                    <SidebarMenuButton
                      isActive={accountActiveSection === 'connected-accounts'}
                      onClick={() => navigate(`/organizations/${organizationId}/account/connected-accounts`)}
                    >
                      <Link2 className="tab-icon-shake" />
                      <span>Connected Accounts</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </div>

          {/* Aegis nav — conditionally rendered, in-flow so thread list scrolls properly */}
          {inAegis && (
            <div className="animate-in fade-in slide-in-from-right-2 duration-150">
              <SidebarGroup>
                <SidebarGroupContent>
                  <SidebarMenu>
                    <SidebarMenuItem>
                      <button
                        onClick={() => navigate(`/organizations/${organizationId}`)}
                        className="nav-btn relative w-full flex items-center justify-center h-9 rounded-md px-3 text-sm font-medium text-foreground-secondary hover:bg-background-subtle/75 hover:text-foreground transition-colors"
                      >
                        <ChevronLeft className="absolute left-3 h-5 w-5 tab-icon-shake" />
                        <span>Aegis</span>
                      </button>
                    </SidebarMenuItem>
                    <SidebarMenuItem>
                      <SidebarMenuButton
                        isActive={inAegis && !activeAegisThreadId && !aegisRoutinesActive}
                        onClick={() => navigate(`/organizations/${organizationId}/aegis`)}
                      >
                        <SquarePen className="tab-icon-shake" />
                        <span>New chat</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                    <SidebarMenuItem>
                      <SidebarMenuButton
                        isActive={aegisRoutinesActive}
                        onClick={() => navigate(`/organizations/${organizationId}/aegis/routines`)}
                      >
                        <Zap className="tab-icon-shake" />
                        <span>Routines</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                    <SidebarMenuItem>
                      <SidebarMenuButton
                        onClick={() => window.dispatchEvent(new CustomEvent('aegis:openSearch'))}
                      >
                        <Search className="tab-icon-shake" />
                        <span>Search chats</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>

              {aegisThreadsLoading && aegisThreads.length === 0 && (
                <SidebarGroup>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      {[120, 88, 104, 72, 96].map((w, i) => (
                        <SidebarMenuItem key={i}>
                          <div
                            className="flex items-center gap-3 h-9 px-3"
                            style={{ opacity: 1 - i * 0.15 }}
                          >
                            <div className="h-3.5 w-3.5 rounded-full bg-foreground/[0.08] animate-pulse flex-shrink-0" style={{ animationDelay: `${i * 60}ms` }} />
                            <div className="h-2.5 rounded bg-foreground/[0.08] animate-pulse" style={{ width: w, animationDelay: `${i * 60}ms` }} />
                          </div>
                        </SidebarMenuItem>
                      ))}
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>
              )}

              {(aegisPinned.length > 0 || aegisRecents.length > 0) && (
                <SidebarGroup>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      {[...aegisPinned, ...aegisRecents].map(renderAegisThread)}
                    </SidebarMenu>
                  </SidebarGroupContent>
                </SidebarGroup>
              )}
            </div>
          )}
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
                    to={`/organizations/${organizationId}/account/general`}
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
        open={!!aegisConfirmDeleteId}
        onOpenChange={(open) => { if (!open && !aegisDeleting) setAegisConfirmDeleteId(null); }}
      >
        <DialogContent
          hideClose
          className="sm:max-w-[420px] bg-background p-0 gap-0 overflow-hidden"
        >
          <div className="px-6 pt-6 pb-4">
            <DialogTitle>Delete chat?</DialogTitle>
            <DialogDescription className="mt-1">
              This will permanently delete the thread and its messages. This cannot be undone.
            </DialogDescription>
          </div>
          <DialogFooter className="px-6 py-4 border-t border-border bg-background flex items-center justify-between">
            <Button
              variant="outline"
              onClick={() => setAegisConfirmDeleteId(null)}
              disabled={aegisDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleAegisDelete}
              disabled={aegisDeleting}
            >
              {aegisDeleting ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />Delete</> : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
