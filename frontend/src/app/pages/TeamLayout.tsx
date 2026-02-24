import { useState, useEffect, useMemo } from 'react';
import { useParams, Outlet, useNavigate, useLocation, Link } from 'react-router-dom';
import { HelpCircle, Settings, LogOut, BookOpen, Mail, ChevronRight } from 'lucide-react';
import TeamHeader from '../../components/TeamHeader';
import TeamSidebar from '../../components/TeamSidebar';
import { api, TeamWithRole, TeamPermissions, Organization } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import { Toaster } from '../../components/ui/toaster';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';

// Helper function to compute permissions from role
export function getTeamPermissionsFromRole(role: string | undefined): TeamPermissions {
  const isAdmin = role === 'admin' || role === 'owner'; // Support both for backwards compatibility

  if (isAdmin) {
    return {
      view_overview: true,
      resolve_alerts: true,
      manage_projects: true,
      view_settings: true,
      view_members: true,
      add_members: true,
      kick_members: true,
      view_roles: true,
      edit_roles: true,
      manage_notification_settings: true, // Admin has all permissions
    };
  }

  // Member or default - basic permissions (can always view overview)
  return {
    view_overview: true, // Everyone can view the team overview
    resolve_alerts: false,
    manage_projects: false,
    view_settings: false,
    view_members: false,
    add_members: false,
    kick_members: false,
    view_roles: false,
    edit_roles: false,
  };
}

export default function TeamLayout() {
  const { orgId, teamId } = useParams<{ orgId: string; teamId: string }>();
  // Initialize with cached data if available for instant display
  // Also merge localStorage cached role info for instant badge display
  const [team, setTeam] = useState<TeamWithRole | null>(() => {
    if (!orgId || !teamId) return null;
    const cachedTeam = api.getCachedTeam(orgId, teamId);
    if (cachedTeam) {
      // Merge localStorage role display info if not already in cached team
      const cachedRoleDisplayName = localStorage.getItem(`team_role_display_name_${teamId}`);
      const cachedRoleColor = localStorage.getItem(`team_role_color_${teamId}`);
      return {
        ...cachedTeam,
        role_display_name: cachedTeam.role_display_name || cachedRoleDisplayName || undefined,
        role_color: cachedTeam.role_color || cachedRoleColor || undefined,
      };
    }
    return null;
  });
  const [organization, setOrganization] = useState<Organization | null>(() => {
    if (!orgId) return null;
    return api.getCachedOrganization(orgId);
  });
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const { avatarUrl } = useUserProfile();
  const location = useLocation();

  // Try to get cached permissions for instant tab display
  const cachedPermissions = useMemo(() => {
    if (!teamId) return null;
    const cached = localStorage.getItem(`team_permissions_${teamId}`);
    if (cached) {
      try {
        return JSON.parse(cached) as TeamPermissions;
      } catch { return null; }
    }
    return null;
  }, [teamId]);

  const [dbPermissions, setDbPermissions] = useState<TeamPermissions | null>(null);
  const [permissionsLoading, setPermissionsLoading] = useState(false);

  // Compute permissions - merge org-level permissions with team permissions
  const userPermissions = useMemo(() => {
    let basePermissions: TeamPermissions | null = null;

    // Priority 1: Database permissions (most accurate, fetched from team_roles)
    if (dbPermissions) {
      basePermissions = dbPermissions;
    }
    // Priority 2: Cached permissions from localStorage (set from previous DB fetch)
    else if (cachedPermissions) {
      basePermissions = cachedPermissions;
    }
    // Priority 3: Permissions from API response (teams list includes permissions)
    else if (team?.permissions) {
      basePermissions = team.permissions;
    }

    // If no permissions available yet, return null (tabs will show loading state)
    if (!basePermissions) {
      return null;
    }

    // Check if user has org-level manage_teams_and_projects permission
    // If so, grant all team management permissions (org permission supersedes team permission)
    const hasOrgManagePermission = organization?.permissions?.manage_teams_and_projects || false;

    if (hasOrgManagePermission) {
      return {
        ...basePermissions,
        view_settings: true,
        manage_projects: true,
        manage_members: true,
        add_members: true,
        kick_members: true,
        view_roles: true,
        edit_roles: true,
        manage_notification_settings: true,
      };
    }

    return basePermissions;
  }, [team?.permissions, cachedPermissions, dbPermissions, organization?.permissions?.manage_teams_and_projects]);

  // Load permissions from database when team loads
  useEffect(() => {
    const loadDbPermissions = async () => {
      if (!orgId || !team) {
        setDbPermissions(null);
        setPermissionsLoading(false);
        return;
      }

      setPermissionsLoading(true);
      try {
        let permsToSet: TeamPermissions | null = null;

        // If user is NOT a team member (no role), but has permissions from API response
        // This happens for org admins/owners who have org-level manage_teams_and_projects permission
        if (!team.role && team.permissions) {
          // Use the permissions provided by the backend - these are computed based on org role
          permsToSet = team.permissions;
        } else if (team.user_rank === 0 && team.permissions) {
          // Top ranked role - use permissions from API (includes all permissions like manage_notification_settings)
          permsToSet = team.permissions;
        } else if (team.user_rank === 0) {
          // Fallback for top ranked role if no API permissions available
          permsToSet = getTeamPermissionsFromRole('admin');
        } else if (team.role) {
          // Regular team members - look up permissions from team roles
          const roles = await api.getTeamRoles(orgId, team.id);
          const userRole = roles.find(r => r.name === team.role);

          if (userRole?.permissions) {
            // Use permissions from database
            permsToSet = userRole.permissions;
          } else {
            // Fallback to role-based permissions
            permsToSet = getTeamPermissionsFromRole(team.role);
          }
        } else {
          // No role and no permissions - use default member permissions
          permsToSet = getTeamPermissionsFromRole('member');
        }

        // Cache permissions for instant display on next visit
        if (permsToSet && team.id) {
          localStorage.setItem(`team_permissions_${team.id}`, JSON.stringify(permsToSet));
        }
        setDbPermissions(permsToSet);
      } catch (error) {
        console.error('Failed to load permissions:', error);
        // On error, check if we have API-provided permissions, otherwise use role-based
        const fallbackPerms = team.permissions || getTeamPermissionsFromRole(team.role);
        if (fallbackPerms && team.id) {
          localStorage.setItem(`team_permissions_${team.id}`, JSON.stringify(fallbackPerms));
        }
        setDbPermissions(fallbackPerms);
      } finally {
        setPermissionsLoading(false);
      }
    };

    loadDbPermissions();
  }, [orgId, team?.id, team?.role, team?.role_display_name, team?.permissions]);

  // Note: Overview is always accessible for all team members, no redirect needed

  useEffect(() => {
    if (orgId && teamId) {
      // Check if we have cached data for this team/org
      const cachedTeam = api.getCachedTeam(orgId, teamId);
      const cachedOrg = api.getCachedOrganization(orgId);

      if (cachedTeam && (!team || team.id !== teamId)) {
        // Use cached team data immediately (for fast header display)
        setTeam(cachedTeam);
      }
      if (cachedOrg && (!organization || organization.id !== orgId)) {
        // Use cached org data immediately
        setOrganization(cachedOrg);
      }

      // Always load full team data to ensure we have permissions
      // (cached data from list view doesn't include role/permissions)
      const needsPermissions = !cachedTeam?.permissions && !cachedTeam?.role;
      if (!team || team.id !== teamId || needsPermissions) {
        loadTeam();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, teamId]);

  const loadTeam = async (forceReload = false) => {
    if (!orgId || !teamId) return;

    // Don't reload if we already have this team (unless forced)
    if (!forceReload && team && team.id === teamId) {
      return;
    }

    // Check for cached data - if we have it, don't show loading state
    const hasCachedTeam = api.getCachedTeam(orgId, teamId) !== null;
    const hasCachedOrg = api.getCachedOrganization(orgId) !== null;
    const hasCachedData = hasCachedTeam && hasCachedOrg;

    try {
      // Only show loading if we don't have cached data
      if (!hasCachedData) {
        setLoading(true);
      }

      // Load team and organization data in parallel
      const [teamData, orgData] = await Promise.all([
        api.getTeam(orgId, teamId),
        api.getOrganization(orgId),
      ]);

      setTeam(teamData);
      setOrganization(orgData);

      // Cache the role info in localStorage for faster access next time
      // IMPORTANT: Clear stale values if user is NOT a team member (role is null)
      if (teamData.role) {
        localStorage.setItem(`team_role_${teamId}`, teamData.role);
      } else {
        // User is not a team member - clear any stale cached role
        localStorage.removeItem(`team_role_${teamId}`);
      }
      // Cache role display info for instant badge display
      if (teamData.role_display_name) {
        localStorage.setItem(`team_role_display_name_${teamId}`, teamData.role_display_name);
      } else {
        localStorage.removeItem(`team_role_display_name_${teamId}`);
      }
      if (teamData.role_color) {
        localStorage.setItem(`team_role_color_${teamId}`, teamData.role_color);
      } else {
        localStorage.removeItem(`team_role_color_${teamId}`);
      }
      // Also cache org role
      if (orgData.role) {
        localStorage.setItem(`org_role_${orgId}`, orgData.role);
      }
    } catch (error: any) {
      console.error('Failed to load team:', error);

      const status = error.response?.status || error.status;
      if (status === 403) {
        toast({
          title: 'Access Denied',
          description: 'You do not have permission to view this team',
        });
      } else if (status === 404) {
        toast({
          title: 'Not Found',
          description: 'This team does not exist',
        });
      } else {
        toast({
          title: 'Error',
          description: error.message || 'Failed to load team',
        });
      }

      // Redirect to organization teams list
      navigate(`/organizations/${orgId}/teams`, { replace: true });
    } finally {
      setLoading(false);
    }
  };

  const reloadTeam = async () => {
    await loadTeam(true);
  };

  // Update team data directly (e.g., after editing team settings)
  // This avoids race conditions from refetching stale data
  const updateTeamData = (updates: Partial<TeamWithRole>) => {
    setTeam(prev => prev ? { ...prev, ...updates } : prev);
    // Also update the cache
    if (orgId && teamId) {
      const cacheKey = `${orgId}:${teamId}`;
      const cached = api.getCachedTeam(orgId, teamId);
      if (cached) {
        api._teamDataCache.set(cacheKey, { ...cached, ...updates });
      }
    }
  };

  return (
    <>
      <div className="min-h-screen bg-background">
        {loading && !team ? (
          <>
            {/* Loading Header */}
            <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
              <header className="bg-background">
                <div className="mx-auto w-full">
                  <div className="flex h-12 items-center justify-between px-6">
                    {/* Left side: Logo + Loading placeholders matching TeamHeader */}
                    <nav className="flex items-center gap-2 text-sm">
                      <Link to="/organizations" className="flex items-center">
                        <img
                          src="/images/logo.png"
                          alt="Deptex"
                          className="h-8 w-8"
                        />
                      </Link>
                      <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      <div className="flex items-center gap-2">
                        <div className="h-4 w-24 bg-muted rounded animate-pulse" />
                        <div className="h-5 w-14 bg-muted rounded animate-pulse" />
                      </div>
                      <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      <div className="flex items-center gap-2">
                        <div className="h-4 w-20 bg-muted rounded animate-pulse" />
                        <div className="h-5 w-12 bg-muted rounded animate-pulse" />
                      </div>
                    </nav>

                    {/* Right side: Help and Profile */}
                    <div className="flex items-center gap-4">
                      {/* Help dropdown */}
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <button className="flex items-center justify-center rounded-md p-2 text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors">
                            <HelpCircle className="h-5 w-5" />
                          </button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-48">
                          <DropdownMenuLabel>Help & Support</DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem asChild>
                            <a href="/docs" target="_blank" rel="noopener noreferrer" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                              <BookOpen className="h-4 w-4" />
                              Docs
                            </a>
                          </DropdownMenuItem>
                          <DropdownMenuItem asChild>
                            <a href="/support" target="_blank" rel="noopener noreferrer" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                              <Mail className="h-4 w-4" />
                              Contact Support
                            </a>
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>

                      {/* Profile dropdown */}
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <button className="flex items-center justify-center rounded-full border border-border bg-background-subtle overflow-hidden hover:bg-background-card transition-colors">
                            <img
                              src={avatarUrl}
                              alt={user?.email || 'User'}
                              className="h-8 w-8 rounded-full object-cover"
                              onError={(e) => {
                                e.currentTarget.src = '/images/blank_profile_image.png';
                              }}
                            />
                          </button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-72">
                          <DropdownMenuLabel className="p-0">
                            <div className="flex items-center gap-3 px-2 py-3">
                              <div className="flex-shrink-0">
                                <img
                                  src={avatarUrl}
                                  alt={user?.email || 'User'}
                                  className="h-10 w-10 rounded-full object-cover border border-border"
                                  onError={(e) => {
                                    e.currentTarget.src = '/images/blank_profile_image.png';
                                  }}
                                />
                              </div>
                              <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                                {user?.user_metadata?.full_name && (
                                  <span className="text-sm font-medium text-foreground truncate">{user.user_metadata.full_name}</span>
                                )}
                                <span className="text-xs text-foreground-secondary truncate">{user?.email}</span>
                              </div>
                            </div>
                          </DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem asChild>
                            <Link to="/settings" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                              <Settings className="h-4 w-4" />
                              Settings
                            </Link>
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={async () => {
                              await signOut();
                              navigate('/');
                            }}
                            className="cursor-pointer text-foreground-secondary hover:text-foreground focus:bg-transparent focus:text-foreground flex items-center gap-2 transition-colors"
                          >
                            <LogOut className="h-4 w-4" />
                            Sign out
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>
                </div>
              </header>
            </div>
            <div className="h-12"></div>
          </>
        ) : team && orgId && teamId ? (
          <>
            <TeamHeader
              organization={organization}
              team={team}
              userPermissions={userPermissions}
            />
            <TeamSidebar
              organizationId={orgId}
              teamId={teamId}
              userPermissions={userPermissions}
            />
            <div className="h-12"></div>
          </>
        ) : null}
        <main className={team ? 'pl-12' : ''}>
          <Outlet context={{ team, reloadTeam, updateTeamData, organizationId: orgId, userPermissions, organization }} />
        </main>
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}
