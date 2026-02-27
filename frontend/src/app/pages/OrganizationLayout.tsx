import { useState, useEffect, useMemo } from 'react';
import { useParams, Outlet, useNavigate, Link } from 'react-router-dom';
import { User, HelpCircle, Settings, LogOut, BookOpen, Mail, ChevronRight } from 'lucide-react';
import OrganizationHeader from '../../components/OrganizationHeader';
import OrganizationSidebar from '../../components/OrganizationSidebar';
import { api, Organization, RolePermissions } from '../../lib/api';
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
        {loading && !organization ? (
          <>
            {/* Loading Header */}
            <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
              <header className="bg-background">
                <div className="mx-auto w-full">
                  <div className="flex h-12 items-center justify-between px-6">
                    {/* Left side: Logo + Loading placeholders matching OrganizationHeader */}
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
                            <a href="/docs/help" target="_blank" rel="noopener noreferrer" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
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
              {/* Loading Tabs - show with default permissions if we have org, otherwise no permissions */}
            </div>
            <div className="h-12"></div>
          </>
        ) : organization && id ? (
          <>
            <OrganizationHeader organization={organization} />
            <OrganizationSidebar organizationId={id} userPermissions={userPermissions} />
            <div className="h-12"></div>
          </>
        ) : null}
        <main className={organization ? 'pl-12' : ''}>
          <Outlet context={{ organization, reloadOrganization }} />
        </main>
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}

