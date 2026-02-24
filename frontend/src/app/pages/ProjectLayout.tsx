import { useState, useEffect, useMemo } from 'react';
import { useParams, Outlet, useNavigate, Link } from 'react-router-dom';
import { HelpCircle, Settings, LogOut, BookOpen, Mail, ChevronRight } from 'lucide-react';
import ProjectHeader from '../../components/ProjectHeader';
import ProjectSidebar from '../../components/ProjectSidebar';
import { api, ProjectWithRole, Organization, ProjectPermissions } from '../../lib/api';
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
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';


export default function ProjectLayout() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  // Initialize with cached data if available for instant display
  const [project, setProject] = useState<ProjectWithRole | null>(() => {
    if (!orgId || !projectId) return null;
    return api.getCachedProject(orgId, projectId);
  });
  const [organization, setOrganization] = useState<Organization | null>(() => {
    if (!orgId) return null;
    return api.getCachedOrganization(orgId);
  });
  const [loading, setLoading] = useState(false); // Start as false, will be set to true only when actually loading
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
    if (orgId && projectId) {
      // Check if we have cached data for this project/org
      const cachedProject = api.getCachedProject(orgId, projectId);
      const cachedOrg = api.getCachedOrganization(orgId);

      if (cachedProject && (!project || project.id !== projectId)) {
        // Use cached project data immediately
        setProject(cachedProject);
      }
      if (cachedOrg && (!organization || organization.id !== orgId)) {
        // Use cached org data immediately
        setOrganization(cachedOrg);
      }

      // Only load if we don't already have this project loaded
      if (!project || project.id !== projectId) {
        loadProject();
      }
      // If we already have the project, do nothing - don't set loading
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, projectId]); // Only depend on ids, not project to avoid infinite loops

  const loadProject = async (forceReload = false) => {
    if (!orgId || !projectId) return;

    // Don't reload if we already have this project (unless forced)
    if (!forceReload && project && project.id === projectId) {
      return;
    }

    // Check for cached data - if we have it, don't show loading state
    const hasCachedProject = api.getCachedProject(orgId, projectId) !== null;
    const hasCachedOrg = api.getCachedOrganization(orgId) !== null;
    const hasCachedData = hasCachedProject && hasCachedOrg;

    try {
      // Only show loading if we don't have cached data
      if (!hasCachedData) {
        setLoading(true);
      }

      // Load project and organization data in parallel (skip cache when force reloading)
      const [projectData, orgData] = await Promise.all([
        api.getProject(orgId, projectId, !forceReload),
        api.getOrganization(orgId),
      ]);

      setProject(projectData);
      setOrganization(orgData);

      // Cache the role and permissions in localStorage for faster access next time
      if (projectData.role) {
        localStorage.setItem(`project_role_${projectId}`, projectData.role);
      }
      if (projectData.permissions) {
        localStorage.setItem(`project_permissions_${projectId}`, JSON.stringify(projectData.permissions));
      }
      // Also cache org role
      if (orgData.role) {
        localStorage.setItem(`org_role_${orgId}`, orgData.role);
      }
    } catch (error: any) {
      console.error('Failed to load project:', error);

      const status = error.response?.status || error.status;
      if (status === 403) {
        toast({
          title: 'Access Denied',
          description: 'You do not have permission to view this project',
        });
      } else if (status === 404) {
        toast({
          title: 'Not Found',
          description: 'This project does not exist',
        });
      } else {
        toast({
          title: 'Error',
          description: error.message || 'Failed to load project',
        });
      }

      // Redirect to organization projects list
      navigate(`/organizations/${orgId}/projects`, { replace: true });
    } finally {
      setLoading(false);
    }
  };

  const reloadProject = async () => {
    await loadProject(true);
  };

  return (
    <>
      <div className="min-h-screen bg-background">
        {loading && !project ? (
          <>
            {/* Loading Header */}
            <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
              <header className="bg-background">
                <div className="mx-auto w-full">
                  <div className="flex h-12 items-center justify-between px-6">
                    {/* Left side: Logo + Loading placeholders matching ProjectHeader breadcrumb */}
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
                      {/* Team skeleton */}
                      <div className="flex items-center gap-2">
                        <div className="h-4 w-20 bg-muted rounded animate-pulse" />
                        <div className="h-5 w-12 bg-muted rounded animate-pulse" />
                      </div>
                      <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      {/* Project skeleton */}
                      <div className="flex items-center gap-2">
                        <div className="h-[18px] w-[18px] bg-muted rounded animate-pulse" />
                        <div className="h-4 w-28 bg-muted rounded animate-pulse" />
                      </div>
                    </nav>

                    {/* Right side: Help and Profile */}
                    <div className="flex items-center gap-4">
                      {/* Help dropdown */}
                      <DropdownMenu>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <DropdownMenuTrigger asChild>
                              <button className="flex items-center justify-center rounded-md p-2 text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors">
                                <HelpCircle className="h-5 w-5" />
                              </button>
                            </DropdownMenuTrigger>
                          </TooltipTrigger>
                          <TooltipContent side="bottom">Help and support</TooltipContent>
                        </Tooltip>
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
        ) : project ? (
          <>
            <ProjectHeader
              organization={organization}
              project={project}
              userPermissions={userPermissions}
            />
            {orgId && projectId && (
              <ProjectSidebar
                organizationId={orgId}
                projectId={projectId}
                userPermissions={userPermissions}
              />
            )}
            <div className="h-12"></div>
          </>
        ) : null}
        <main className="pl-12">
          <Outlet
            context={{
              project,
              reloadProject,
              setProjectAutoBump: (value: boolean) =>
                setProject((prev) => (prev ? { ...prev, auto_bump: value } : null)),
              organizationId: orgId,
              userPermissions,
            }}
          />
        </main>
      </div>
      <Toaster position="bottom-right" />
    </>
  );
}
