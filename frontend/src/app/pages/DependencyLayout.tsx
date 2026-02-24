import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Outlet, useNavigate, Link } from 'react-router-dom';
import { HelpCircle, Settings, LogOut, BookOpen, Mail, ChevronRight } from 'lucide-react';
import DependencyHeader from '../../components/DependencyHeader';
import DependencySidebar from '../../components/DependencySidebar';
import DependencyNotesSidebar from '../../components/DependencyNotesSidebar';
import { api, ProjectWithRole, Organization, ProjectPermissions, ProjectDependency } from '../../lib/api';
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

export interface DependencyContextType {
  dependency: ProjectDependency | null;
  project: ProjectWithRole | null;
  organization: Organization | null;
  organizationId: string;
  projectId: string;
  userPermissions: ProjectPermissions | null;
}

export default function DependencyLayout() {
  const { orgId, projectId, dependencyId } = useParams<{ orgId: string; projectId: string; dependencyId: string }>();

  // Initialize with cached data if available for instant display
  const [project, setProject] = useState<ProjectWithRole | null>(() => {
    if (!orgId || !projectId) return null;
    return api.getCachedProject(orgId, projectId);
  });
  const [organization, setOrganization] = useState<Organization | null>(() => {
    if (!orgId) return null;
    return api.getCachedOrganization(orgId);
  });
  const [dependency, setDependency] = useState<ProjectDependency | null>(() => {
    if (!projectId || !dependencyId) return null;
    return api.getCachedDependency(projectId, dependencyId);
  });
  // Only show loading if we don't have cached data
  const [loading, setLoading] = useState(() => {
    if (!orgId || !projectId || !dependencyId) return true;
    const hasCachedProject = api.getCachedProject(orgId, projectId) !== null;
    const hasCachedOrg = api.getCachedOrganization(orgId) !== null;
    const hasCachedDep = api.getCachedDependency(projectId, dependencyId) !== null;
    return !(hasCachedProject && hasCachedOrg && hasCachedDep);
  });
  const { toast } = useToast();
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const { avatarUrl } = useUserProfile();

  // Get cached permissions from localStorage for instant display during loading
  const cachedPermissions = useMemo((): ProjectPermissions | null => {
    if (!projectId) return null;
    const permissionsStr = localStorage.getItem(`project_permissions_${projectId}`);
    if (permissionsStr) {
      try {
        return JSON.parse(permissionsStr) as ProjectPermissions;
      } catch {
        return null;
      }
    }
    return null;
  }, [projectId]);

  // Compute effective permissions - prefer project permissions, then cached
  const userPermissions = useMemo(() => {
    if (project?.permissions) {
      return project.permissions;
    }
    if (cachedPermissions) {
      return cachedPermissions;
    }
    return null;
  }, [project?.permissions, cachedPermissions]);

  useEffect(() => {
    if (orgId && projectId && dependencyId) {
      loadData();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, projectId, dependencyId]);

  const loadData = async () => {
    if (!orgId || !projectId || !dependencyId) return;

    // Check for cached data - if we have it all, don't show loading state
    const hasCachedProject = api.getCachedProject(orgId, projectId) !== null;
    const hasCachedOrg = api.getCachedOrganization(orgId) !== null;
    const hasCachedDep = api.getCachedDependency(projectId, dependencyId) !== null;
    const hasCachedData = hasCachedProject && hasCachedOrg && hasCachedDep;

    try {
      // Only show loading if we don't have cached data
      if (!hasCachedData) {
        setLoading(true);
      }

      // Load project, organization, and dependencies data in parallel
      const [projectData, orgData, dependenciesData] = await Promise.all([
        api.getProject(orgId, projectId),
        api.getOrganization(orgId),
        api.getProjectDependencies(orgId, projectId),
      ]);

      setProject(projectData);
      setOrganization(orgData);

      // Find the specific dependency
      const dep = dependenciesData.find(d => d.id === dependencyId);
      if (dep) {
        setDependency(dep);
        // Cache the dependency for instant display next time (already cached by getProjectDependencies, but ensure latest)
        api.cacheDependency(projectId, dep);
        // Start watchtower summary fetch immediately so sidebar badge can show sooner (same round as layout data)
        api.getWatchtowerSummary(dep.name, dep.id)
          .then((summary) => {
            const status = summary && summary.status === 'ready'
              ? (summary.is_current_version_quarantined
                ? 'not-good'
                : [summary.registry_integrity_status, summary.install_scripts_status, summary.entropy_analysis_status].some((s: string) => s === 'fail')
                  ? 'unsafe'
                  : [summary.registry_integrity_status, summary.install_scripts_status, summary.entropy_analysis_status].every((s: string) => s === 'pass')
                    ? 'safe'
                    : null)
              : null;
            setWatchtowerStatus(status);
          })
          .catch(() => { /* ignore */ });
      } else {
        toast({
          title: 'Not Found',
          description: 'This dependency does not exist',
        });
        navigate(`/organizations/${orgId}/projects/${projectId}/dependencies`, { replace: true });
        return;
      }

      // Cache the role and permissions
      if (projectData.role) {
        localStorage.setItem(`project_role_${projectId}`, projectData.role);
      }
      if (projectData.permissions) {
        localStorage.setItem(`project_permissions_${projectId}`, JSON.stringify(projectData.permissions));
      }
      if (orgData.role) {
        localStorage.setItem(`org_role_${orgId}`, orgData.role);
      }
    } catch (error: any) {
      console.error('Failed to load dependency:', error);

      const status = error.response?.status || error.status;
      if (status === 403) {
        toast({
          title: 'Access Denied',
          description: 'You do not have permission to view this dependency',
        });
      } else if (status === 404) {
        toast({
          title: 'Not Found',
          description: 'This resource does not exist',
        });
      } else {
        toast({
          title: 'Error',
          description: error.message || 'Failed to load dependency',
        });
      }

      navigate(`/organizations/${orgId}/projects/${projectId}/dependencies`, { replace: true });
    } finally {
      setLoading(false);
    }
  };

  // Notes sidebar state — lives at layout level so it persists across tab switches
  const [notesSidebarOpen, setNotesSidebarOpen] = useState(false);
  const [notesCount, setNotesCount] = useState(0);

  const handleNotesCountChange = useCallback((count: number) => {
    setNotesCount(count);
  }, []);

  // Pre-fetch notes count when dependency loads so the indicator shows immediately
  useEffect(() => {
    if (!orgId || !projectId || !dependencyId) return;
    let cancelled = false;
    api.getDependencyNotes(orgId, projectId, dependencyId)
      .then((res) => {
        if (!cancelled) setNotesCount(res.notes.length);
      })
      .catch(() => { /* ignore */ });
    return () => { cancelled = true; };
  }, [orgId, projectId, dependencyId]);

  // Watchtower status state — lives at layout level so it persists across tab switches (fetched in loadData when we have dep)
  const [watchtowerStatus, setWatchtowerStatus] = useState<'safe' | 'unsafe' | 'not-good' | null>(null);

  // Check if we have all required data to show the full header
  const hasAllData = dependency !== null && project !== null && organization !== null;

  return (
    <>
      <div className="min-h-screen bg-background">
        {loading && !hasAllData ? (
          <>
            {/* Loading Header */}
            <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
              <header className="bg-background">
                <div className="mx-auto w-full">
                  <div className="flex h-12 items-center justify-between px-6">
                    {/* Left side: Logo + Loading placeholders matching DependencyHeader breadcrumb */}
                    <nav className="flex items-center gap-2 text-sm">
                      {/* Logo */}
                      <Link to="/organizations" className="flex items-center">
                        <img
                          src="/images/logo.png"
                          alt="Deptex"
                          className="h-8 w-8"
                        />
                      </Link>
                      <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      {/* Org skeleton */}
                      <div className="flex items-center gap-2">
                        <div className="h-4 w-24 bg-muted rounded animate-pulse" />
                        <div className="h-5 w-14 bg-muted rounded animate-pulse" />
                      </div>
                      <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      {/* Project skeleton */}
                      <div className="flex items-center gap-2">
                        <div className="h-[18px] w-[18px] bg-muted rounded animate-pulse" />
                        <div className="h-4 w-28 bg-muted rounded animate-pulse" />
                      </div>
                      <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      {/* Dependency skeleton */}
                      <div className="flex items-center gap-2">
                        <div className="h-5 w-5 bg-muted rounded animate-pulse" />
                        <div className="h-4 w-32 bg-muted rounded animate-pulse" />
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
        ) : hasAllData ? (
          <>
            <DependencyHeader
              organization={organization}
              project={project}
              dependency={dependency}
              userPermissions={userPermissions}
            />
            <div className="h-12"></div>
          </>
        ) : null}

        {/* Sidebar Navigation */}
        {orgId && projectId && dependencyId && (
          <DependencySidebar
            organizationId={orgId}
            projectId={projectId}
            dependencyId={dependencyId}
            dependencyName={dependency?.name}
            notesSidebarOpen={notesSidebarOpen}
            onNotesClick={() => setNotesSidebarOpen(true)}
            notesCount={notesCount}
            watchtowerStatus={watchtowerStatus}
          />
        )}

        {/* Main Content Area */}
        <main className="pl-12">
          <Outlet context={{ dependency, project, organization, organizationId: orgId, projectId, userPermissions } as DependencyContextType} />
        </main>
      </div>
      {/* Notes Sidebar — persists across all tabs */}
      {orgId && projectId && dependencyId && (
        <DependencyNotesSidebar
          open={notesSidebarOpen}
          onOpenChange={setNotesSidebarOpen}
          organizationId={orgId}
          projectId={projectId}
          projectDependencyId={dependencyId}
          packageName={dependency?.name || 'Dependency'}
          onNotesCountChange={handleNotesCountChange}
        />
      )}

      <Toaster position="bottom-right" />
    </>
  );
}
