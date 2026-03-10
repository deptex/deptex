import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Outlet, useNavigate } from 'react-router-dom';
import { History, ArrowUp, Settings, FileText, Wrench, Clock, Server, BarChart3, Code2, Database } from 'lucide-react';
import OrganizationHeader from '../../components/OrganizationHeader';
import OrganizationSidebar from '../../components/OrganizationSidebar';
import { CreateProjectSidebar } from '../../components/CreateProjectSidebar';
import { InviteMemberDialog } from '../../components/InviteMemberDialog';
import { api, Organization, RolePermissions, Team, Project, OrganizationMember, OrganizationInvitation, OrganizationRole } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import { Toaster } from '../../components/ui/toaster';
import { PlanProvider } from '../../contexts/PlanContext';
import { Button } from '../../components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '../../components/ui/tooltip';
import { cn } from '../../lib/utils';

const AEGIS_SIDEBAR_WIDTH = 420;

/** Three rows of suggested prompts; each row scrolls horizontally and pauses on hover */
const AEGIS_SAMPLE_ROWS: { label: string; icon: React.ComponentType<{ className?: string }> }[][] = [
  [
    { label: 'How can I configure my service?', icon: Settings },
    { label: 'Deploy Postgres', icon: FileText },
    { label: 'Why is my build failing?', icon: Wrench },
    { label: 'Set up a cron job', icon: Clock },
  ],
  [
    { label: 'Check deployment status', icon: Server },
    { label: 'View logs', icon: BarChart3 },
    { label: 'Scale my app', icon: Settings },
    { label: 'Add environment variable', icon: Code2 },
  ],
  [
    { label: 'Run tests', icon: Wrench },
    { label: 'Fix lint errors', icon: Code2 },
    { label: 'Generate migration', icon: Database },
    { label: 'Explain this code', icon: FileText },
  ],
];

export default function OrganizationLayout() {
  const { id } = useParams<{ id: string }>();
  // Initialize with cached data if available for instant display
  const [organization, setOrganization] = useState<Organization | null>(() => {
    if (!id) return null;
    return api.getCachedOrganization(id);
  });
  const [loading, setLoading] = useState(false); // Start as false, will be set to true only when actually loading
  const { toast } = useToast();
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const { avatarUrl } = useUserProfile();


  // Try to get role and permissions from cache immediately
  const cachedRole = useMemo(() => {
    if (!id) return null;
    return localStorage.getItem(`org_role_${id}`);
  }, [id]);

  // Get cached permissions for instant tab display
  const cachedPermissions = useMemo(() => {
    if (!id) return null;
    const permissionsStr = localStorage.getItem(`org_permissions_${id}`);
    if (permissionsStr) {
      try {
        const perms = JSON.parse(permissionsStr);
        return perms as RolePermissions;
      } catch {
        return null;
      }
    }
    return null;
  }, [id]);

  const [dbPermissions, setDbPermissions] = useState<RolePermissions | null>(null);
  const [permissionsLoading, setPermissionsLoading] = useState(false);
  const [teams, setTeams] = useState<Team[]>([]);
  const [teamsLoading, setTeamsLoading] = useState(true);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [showCreateProjectSidebar, setShowCreateProjectSidebar] = useState(false);
  const [showInviteMemberDialog, setShowInviteMemberDialog] = useState(false);
  const [aegisSidebarOpen, setAegisSidebarOpen] = useState(false);
  const [aegisInput, setAegisInput] = useState('');
  const [aegisSuggestionsHovered, setAegisSuggestionsHovered] = useState(false);
  // Prefetched for Invite Member dialog so it opens instantly
  const [inviteMembers, setInviteMembers] = useState<OrganizationMember[]>([]);
  const [inviteInvitations, setInviteInvitations] = useState<OrganizationInvitation[]>([]);
  const [inviteRoles, setInviteRoles] = useState<OrganizationRole[]>([]);

  // Compute permissions - prefer database permissions, then cached permissions
  // No hardcoded role-based fallbacks - always use actual permissions from DB
  const userPermissions = useMemo(() => {
    // If we have database permissions (most accurate), use those
    if (dbPermissions) {
      return dbPermissions;
    }
    // If we have cached permissions, use them for instant display (prevents flash during loading)
    if (cachedPermissions) {
      return cachedPermissions;
    }
    // If we have permissions from the organization object (from API), use those
    if (organization?.permissions) {
      return organization.permissions;
    }
    // Return null if we have no permission information yet
    return null;
  }, [organization?.permissions, cachedPermissions, dbPermissions]);

  // Load permissions from database when organization loads (Phase 2: skip if org API already returned permissions)
  useEffect(() => {
    if (!organization?.id || !organization?.role) {
      setDbPermissions(null);
      setPermissionsLoading(false);
      return;
    }

    // Org API already returns permissions; avoid duplicate getOrganizationRoles fetch
    if (organization.permissions != null && typeof organization.permissions === 'object') {
      setDbPermissions(organization.permissions);
      return;
    }

    const loadDbPermissions = async () => {
      setPermissionsLoading(true);
      try {
        const roles = await api.getOrganizationRoles(organization.id);
        const userRole = roles.find(r => r.name === organization.role);

        if (userRole?.permissions) {
          setDbPermissions(userRole.permissions);
          localStorage.setItem(`org_permissions_${organization.id}`, JSON.stringify(userRole.permissions));
        } else {
          console.warn(`Role ${organization.role} has no permissions defined in database`);
        }
      } catch (error) {
        console.error('Failed to load permissions:', error);
      } finally {
        setPermissionsLoading(false);
      }
    };

    loadDbPermissions();
  }, [organization?.id, organization?.role, organization?.permissions]);

  // Load teams for sidebar Teams dropdown
  const refetchTeams = useMemo(() => {
    if (!id) return async () => {};
    return async () => {
      try {
        const data = await api.getTeams(id);
        setTeams(data);
      } catch {
        setTeams([]);
      }
    };
  }, [id]);

  const refetchTeamsAndNotify = useCallback(async () => {
    await refetchTeams();
    window.dispatchEvent(new CustomEvent('organization:teamsUpdated'));
  }, [refetchTeams]);

  useEffect(() => {
    if (!id) {
      setTeams([]);
      setTeamsLoading(false);
      return;
    }
    let cancelled = false;
    setTeamsLoading(true);
    api.getTeams(id)
      .then((data) => {
        if (!cancelled) setTeams(data);
      })
      .catch(() => {
        if (!cancelled) setTeams([]);
      })
      .finally(() => {
        if (!cancelled) setTeamsLoading(false);
      });
    return () => { cancelled = true; };
  }, [id]);

  const refetchProjects = useMemo(() => {
    if (!id) return async () => {};
    return async () => {
      try {
        const data = await api.getProjects(id);
        setProjects(data);
      } catch {
        setProjects([]);
      }
    };
  }, [id]);

  const refetchProjectsAndNotify = useCallback(async () => {
    await refetchProjects();
    window.dispatchEvent(new CustomEvent('organization:projectsUpdated'));
  }, [refetchProjects]);

  useEffect(() => {
    if (!id) {
      setProjects([]);
      setProjectsLoading(false);
      return;
    }
    let cancelled = false;
    setProjectsLoading(true);
    api.getProjects(id)
      .then((data) => {
        if (!cancelled) setProjects(data);
      })
      .catch(() => {
        if (!cancelled) setProjects([]);
      })
      .finally(() => {
        if (!cancelled) setProjectsLoading(false);
      });
    return () => { cancelled = true; };
  }, [id]);

  // Prefetch members, invitations, roles (and we already have teams) for Invite Member dialog
  const refetchInviteData = useMemo(() => {
    if (!id) return async () => {};
    return async () => {
      try {
        const [membersData, invitationsData, rolesData] = await Promise.all([
          api.getOrganizationMembers(id),
          api.getOrganizationInvitations(id),
          api.getOrganizationRoles(id).catch(() => []),
        ]);
        setInviteMembers(membersData);
        setInviteInvitations(invitationsData);
        setInviteRoles(rolesData);
      } catch {
        setInviteMembers([]);
        setInviteInvitations([]);
        setInviteRoles([]);
      }
    };
  }, [id]);

  useEffect(() => {
    if (!id) {
      setInviteMembers([]);
      setInviteInvitations([]);
      setInviteRoles([]);
      return;
    }
    let cancelled = false;
    Promise.all([
      api.getOrganizationMembers(id),
      api.getOrganizationInvitations(id),
      api.getOrganizationRoles(id).catch(() => []),
    ])
      .then(([membersData, invitationsData, rolesData]) => {
        if (!cancelled) {
          setInviteMembers(membersData);
          setInviteInvitations(invitationsData);
          setInviteRoles(rolesData);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setInviteMembers([]);
          setInviteInvitations([]);
          setInviteRoles([]);
        }
      });
    return () => { cancelled = true; };
  }, [id]);

  // Tab title: "Organization name | Deptex" when viewing an org
  useEffect(() => {
    if (!organization?.name) return;
    const prev = document.title;
    document.title = `${organization.name} | Deptex`;
    return () => {
      document.title = prev;
    };
  }, [organization?.name]);

  useEffect(() => {
    if (id) {
      // Check if we have cached data for this org
      const cachedOrg = api.getCachedOrganization(id);
      if (cachedOrg && (!organization || organization.id !== id)) {
        // Use cached data immediately for instant display
        setOrganization(cachedOrg);
      }

      // Always load fresh organization data to ensure permissions are up-to-date
      // The cache is only for instant display, but we need fresh data for accurate permissions
      loadOrganization();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]); // Only depend on id, not organization.id to avoid infinite loops

  // Listen for overview-page "Create project" so Plus dropdown can open the sidebar
  useEffect(() => {
    const handler = () => setShowCreateProjectSidebar(true);
    window.addEventListener('organization:openCreateProject', handler);
    return () => window.removeEventListener('organization:openCreateProject', handler);
  }, []);

  // Listen for overview-page "Invite member" so Plus dropdown can open the same dialog as Members tab
  useEffect(() => {
    const handler = () => setShowInviteMemberDialog(true);
    window.addEventListener('organization:openInvite', handler);
    return () => window.removeEventListener('organization:openInvite', handler);
  }, []);

  const loadOrganization = async (forceReload = false) => {
    if (!id) return;

    // Check for cached data - if we have it, don't show loading state
    const hasCachedData = api.getCachedOrganization(id) !== null || (organization && organization.id === id);

    try {
      // Only show loading if we don't have cached data
      if (!hasCachedData) {
        setLoading(true);
      }
      // Always fetch fresh data from API (bypass prefetch cache) to ensure permissions are up-to-date
      const data = await api.getOrganization(id, false);
      setOrganization(data);
      // Cache the role in localStorage for faster access next time
      if (data.role) {
        localStorage.setItem(`org_role_${id}`, data.role);
      }
    } catch (error: any) {
      console.error('Failed to load organization:', error);

      // Handle specific error cases
      const status = error.response?.status || error.status;
      if (status === 403) {
        // User doesn't have access to this organization
        toast({
          title: 'Access Denied',
          description: 'You do not have permission to view this organization',
        });
      } else if (status === 404) {
        // Organization doesn't exist
        toast({
          title: 'Not Found',
          description: 'This organization does not exist',
        });
      } else {
        toast({
          title: 'Error',
          description: error.message || 'Failed to load organization',
        });
      }

      // Redirect to organizations list
      navigate('/organizations', { replace: true });
    } finally {
      setLoading(false);
    }
  };

  const reloadOrganization = async () => {
    await loadOrganization(true);
  };

  return (
    <>
      <div className="min-h-screen bg-background">
        {loading && !organization && id ? (
          <>
            {/* Loading Header — skeleton only; sidebar below stays visible so layout doesn’t jump on refresh */}
            <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
              <header className="bg-background">
                <div className="mx-auto w-full">
                  <div className="flex h-12 items-center justify-between px-6">
                    <nav className="flex items-center gap-2 text-sm">
                      <img
                        src="/images/logo.png"
                        alt="Deptex"
                        className="h-8 w-8 flex-shrink-0"
                      />
                      <div className="h-4 w-px bg-border flex-shrink-0 ml-1.5 mr-3" aria-hidden />
                      <div className="flex items-center gap-2">
                        <div className="h-4 w-24 bg-muted rounded animate-pulse" />
                        <div className="h-5 w-14 bg-muted rounded animate-pulse" />
                      </div>
                    </nav>
                    <div />
                  </div>
                </div>
              </header>
            </div>
            {/* Same sidebar as loaded state — nav items are permission-null; profile uses auth user */}
            <OrganizationSidebar
              organizationId={id}
              userPermissions={userPermissions}
              teams={teams}
              teamsLoading={teamsLoading}
              onRefetchTeams={refetchTeamsAndNotify}
              canCreateTeam={userPermissions?.manage_teams_and_projects === true}
              projects={projects}
              projectsLoading={projectsLoading}
              onRefetchProjects={refetchProjects}
              canCreateProject={userPermissions?.manage_teams_and_projects === true}
              onOpenCreateProject={() => setShowCreateProjectSidebar(true)}
              user={user}
              avatarUrl={avatarUrl}
              onSignOut={signOut}
              currentOrganization={null}
            />
            <div className="h-12"></div>
          </>
        ) : organization && id ? (
          <>
            <OrganizationHeader
              organization={organization}
              aegisSidebarOpen={aegisSidebarOpen}
              onToggleAegis={() => setAegisSidebarOpen((prev) => !prev)}
            />
            <OrganizationSidebar
              organizationId={id}
              userPermissions={userPermissions}
              teams={teams}
              teamsLoading={teamsLoading}
              onRefetchTeams={refetchTeamsAndNotify}
              canCreateTeam={userPermissions?.manage_teams_and_projects === true}
              projects={projects}
              projectsLoading={projectsLoading}
              onRefetchProjects={refetchProjects}
              canCreateProject={userPermissions?.manage_teams_and_projects === true}
              onOpenCreateProject={() => setShowCreateProjectSidebar(true)}
              user={user}
              avatarUrl={avatarUrl}
              onSignOut={signOut}
              currentOrganization={organization ? { id: organization.id, name: organization.name, role: organization.role, plan: organization.plan, avatar_url: organization.avatar_url } : null}
            />
            {showCreateProjectSidebar && id && (
              <CreateProjectSidebar
                open={showCreateProjectSidebar}
                onClose={() => setShowCreateProjectSidebar(false)}
                organizationId={id}
                teams={teams}
                onProjectsReload={refetchProjectsAndNotify}
              />
            )}
            {organization && id && (
              <InviteMemberDialog
                open={showInviteMemberDialog}
                onOpenChange={setShowInviteMemberDialog}
                organizationId={id}
                organization={organization}
                sharedMembers={inviteMembers}
                sharedInvitations={inviteInvitations}
                sharedTeams={teams}
                sharedRoles={inviteRoles}
                onSuccess={refetchInviteData}
              />
            )}
            <div className="h-12"></div>
          </>
        ) : id && !organization && !loading ? (
          /* Brief moment before loadOrganization runs, or cache miss: still show sidebar shell */
          <>
            <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
              <header className="bg-background">
                <div className="mx-auto w-full">
                  <div className="flex h-12 items-center justify-between px-6">
                    <nav className="flex items-center gap-2 text-sm">
                      <img src="/images/logo.png" alt="Deptex" className="h-8 w-8 flex-shrink-0" />
                      <div className="h-4 w-px bg-border flex-shrink-0 ml-1.5 mr-3" aria-hidden />
                      <div className="h-4 w-24 bg-muted rounded animate-pulse" />
                    </nav>
                    <div />
                  </div>
                </div>
              </header>
            </div>
            <OrganizationSidebar
              organizationId={id}
              userPermissions={userPermissions}
              teams={teams}
              teamsLoading={teamsLoading}
              onRefetchTeams={refetchTeamsAndNotify}
              canCreateTeam={userPermissions?.manage_teams_and_projects === true}
              projects={projects}
              projectsLoading={projectsLoading}
              onRefetchProjects={refetchProjects}
              canCreateProject={userPermissions?.manage_teams_and_projects === true}
              onOpenCreateProject={() => setShowCreateProjectSidebar(true)}
              user={user}
              avatarUrl={avatarUrl}
              onSignOut={signOut}
              currentOrganization={null}
            />
            <div className="h-12"></div>
          </>
        ) : null}
        <PlanProvider organizationId={id || ''}>
          <div className="flex min-h-[calc(100vh-3rem)]">
            <main
              className={cn(
                'flex-1 min-w-0 min-h-0',
                /* pl-12 whenever org route has sidebar (loading or loaded) */
                id ? 'pl-12' : 'px-6',
              )}
              style={organization && aegisSidebarOpen ? { marginRight: AEGIS_SIDEBAR_WIDTH } : undefined}
            >
              <Outlet context={{ organization, reloadOrganization }} />
            </main>
            {organization && (
              <aside
                className={cn(
                  'fixed top-12 right-0 bottom-0 z-40 flex flex-col overflow-hidden bg-background border-l border-border shadow-none transition-transform duration-300 ease-out',
                  // When closed, slide fully past the viewport so border/shadow never peek (width-only collapse left a visible sliver)
                  aegisSidebarOpen ? 'translate-x-0' : 'translate-x-[calc(100%+24px)]',
                )}
                style={{ width: AEGIS_SIDEBAR_WIDTH }}
                aria-label="New Agent"
                aria-hidden={!aegisSidebarOpen}
              >
                <div className="flex flex-col h-full min-h-0 w-full">
                  {/* Header: no top border, no X button */}
                  <div className="p-4 flex items-center justify-between flex-shrink-0">
                    <span className="font-semibold text-foreground">New Agent</span>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Chat history">
                          <History className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="bottom">Chat history</TooltipContent>
                    </Tooltip>
                  </div>
                  {/* Chat area - empty for now */}
                  <div className="flex-1 overflow-auto min-h-0" />
                  {/* Three rows of rotating suggestions; hover locks animation */}
                  <div
                    className="flex-shrink-0 p-4 pt-0 flex flex-col gap-3"
                    onMouseEnter={() => setAegisSuggestionsHovered(true)}
                    onMouseLeave={() => setAegisSuggestionsHovered(false)}
                  >
                    <div className="flex flex-col gap-3 overflow-hidden">
                      {AEGIS_SAMPLE_ROWS.map((rowItems, rowIndex) => {
                        const isReverse = rowIndex % 2 === 1;
                        /* Closest to text bar (bottom) = most opaque; top = most faded */
                        const opacityClass =
                          rowIndex === 0 ? 'opacity-50' : rowIndex === 1 ? 'opacity-[0.65]' : 'opacity-80';
                        return (
                          <div
                            key={rowIndex}
                            className={cn(
                              'overflow-hidden flex-shrink-0 h-10',
                              opacityClass,
                            )}
                          >
                            <div
                              className={cn(
                                'flex gap-2 flex-shrink-0 h-full items-center',
                                isReverse ? 'aegis-scroll-animate-reverse' : 'aegis-scroll-animate',
                                aegisSuggestionsHovered && 'aegis-scroll-paused',
                              )}
                            >
                              {[1, 2].map((copy) => (
                                <div
                                  key={copy}
                                  className="flex gap-2 flex-shrink-0 h-full items-center"
                                >
                                  {rowItems.map(({ label, icon: Icon }) => (
                                    <button
                                      key={`${copy}-${label}`}
                                      type="button"
                                      className="inline-flex items-center gap-2.5 rounded-lg border border-border bg-background-card px-3.5 py-2 text-sm text-foreground-secondary hover:text-foreground hover:bg-muted/40 hover:border-border transition-colors text-left flex-shrink-0 whitespace-nowrap min-w-0"
                                      onClick={() => setAegisInput(label)}
                                    >
                                      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                                      <span className="truncate max-w-[160px]">{label}</span>
                                    </button>
                                  ))}
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div className="relative rounded-lg border border-border bg-background-card overflow-hidden">
                      <textarea
                        value={aegisInput}
                        onChange={(e) => setAegisInput(e.target.value)}
                        placeholder="Develop, debug, deploy, anything..."
                        rows={3}
                        className="w-full min-h-[88px] px-4 py-3 pr-12 text-sm text-foreground placeholder:text-muted-foreground bg-transparent focus:outline-none focus:ring-0 border-0 resize-none"
                      />
                      <Button
                        type="button"
                        size="icon"
                        className="absolute right-1.5 bottom-1.5 h-8 w-8 rounded-full shrink-0 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 disabled:opacity-50"
                        disabled={!aegisInput.trim()}
                        aria-label="Send"
                      >
                        <ArrowUp className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              </aside>
            )}
          </div>
        </PlanProvider>
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}

