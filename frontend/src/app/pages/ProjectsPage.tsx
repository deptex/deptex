import { useState, useEffect, useMemo, useRef } from 'react';
import { useParams, useOutletContext, useNavigate } from 'react-router-dom';
import { Plus, Search, Grid3x3, List, ChevronRight, Bell, Check, Lock, Loader2, Save } from 'lucide-react';
import { api, Project, Team, Organization, RolePermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { ProjectTeamSelect } from '../../components/ProjectTeamSelect';
import { FrameworkIcon } from '../../components/framework-icon';
import { SlideInSidebar } from '../../components/SlideInSidebar';
import { CreateProjectSidebar } from '../../components/CreateProjectSidebar';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

// Short extraction status label for project cards
function projectStatusLabel(project: Project): { label: string; inProgress: boolean; isError: boolean } {
  const status = project.repo_status;
  if (status === 'initializing' || status === 'extracting' || status === 'analyzing' || status === 'finalizing') {
    const step = project.extraction_step;
    const labels: Record<string, string> = {
      queued: 'Creating',
      cloning: 'Creating',
      sbom: 'Creating',
      deps_synced: 'Creating',
      ast_parsing: 'Creating',
      scanning: 'Creating',
      uploading: 'Creating',
      completed: 'Creating',
    };
    const label = step ? (labels[step] ?? 'Creating') : (status === 'analyzing' || status === 'finalizing' ? 'Analyzing' : 'Creating');
    return { label, inProgress: true, isError: false };
  }
  if (status === 'error') return { label: 'Failed', inProgress: false, isError: true };
  return {
    label: project.is_compliant !== false ? 'COMPLIANT' : 'NOT COMPLIANT',
    inProgress: false,
    isError: false,
  };
}

// Format date as "01 Dec 25"
const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  const day = date.getDate().toString().padStart(2, '0');
  const month = date.toLocaleDateString('en-US', { month: 'short' });
  const year = date.getFullYear().toString().slice(-2);
  return `${day} ${month} ${year}`;
};

export default function ProjectsPage() {
  const { id } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [projectName, setProjectName] = useState('');
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const { toast } = useToast();
  const navigate = useNavigate();
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Get cached permissions
  const getCachedPermissions = (): RolePermissions | null => {
    if (organization?.permissions) {
      const perms = { ...organization.permissions } as any;
      // Handle legacy key
      if (perms.create_teams_and_projects && !perms.manage_teams_and_projects) {
        perms.manage_teams_and_projects = true;
      }
      // Force owner full permissions
      if (organization.role === 'owner') {
        perms.view_all_teams_and_projects = true;
        perms.manage_teams_and_projects = true;
      }
      return perms;
    }
    if (id) {
      const cachedStr = localStorage.getItem(`org_permissions_${id}`);
      if (cachedStr) {
        try {
          const perms = JSON.parse(cachedStr);
          // Handle legacy key
          if (perms.create_teams_and_projects && !perms.manage_teams_and_projects) {
            perms.manage_teams_and_projects = true;
          }
          // Force owner full permissions
          if (organization?.role === 'owner') {

            perms.manage_teams_and_projects = true;
          }
          return perms;
        } catch { return null; }
      }
    }
    return null;
  };

  // Load user permissions
  useEffect(() => {
    const loadPermissions = async () => {
      if (!id || !organization?.role) return;

      // Try cached permissions first for instant display
      const cachedPerms = getCachedPermissions();
      if (cachedPerms) {
        setUserPermissions(cachedPerms);
      }

      try {
        const roles = await api.getOrganizationRoles(id);
        const userRole = roles.find(r => r.name === organization.role);
        if (userRole?.permissions) {
          const perms = { ...userRole.permissions } as any;

          // Handle legacy key
          if (perms.create_teams_and_projects && !perms.manage_teams_and_projects) {
            perms.manage_teams_and_projects = true;
          }

          // Force owner full permissions
          if (organization.role === 'owner') {

            perms.manage_teams_and_projects = true;
          }

          setUserPermissions(perms);
          localStorage.setItem(`org_permissions_${id}`, JSON.stringify(perms));
        }
      } catch (error) {
        console.error('Failed to load permissions:', error);
      }
    };

    loadPermissions();
  }, [id, organization?.role]);

  const handleProjectClick = (projectId: string) => {
    navigate(`/organizations/${id}/projects/${projectId}`);
  };

  // Filter projects based on search query
  const filteredProjects = useMemo(() => {
    if (!searchQuery.trim()) {
      return projects;
    }
    const query = searchQuery.toLowerCase();
    return projects.filter(project =>
      project.name.toLowerCase().includes(query) ||
      project.team_names?.some(name => name.toLowerCase().includes(query))
    );
  }, [projects, searchQuery]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && searchQuery) {
        setSearchQuery('');
        searchInputRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [searchQuery]);

  useEffect(() => {
    if (id) {
      loadData();
    }
  }, [id]);

  const loadData = async () => {
    if (!id) return;

    try {
      setLoading(true);
      const [projectsData, teamsData] = await Promise.all([
        api.getProjects(id),
        api.getTeams(id).catch(() => []),
      ]);
      setProjects(projectsData);
      setTeams(teamsData);

      // Cache project roles in localStorage for faster access when navigating to projects
      projectsData.forEach(project => {
        if (project.id && project.role) {
          localStorage.setItem(`project_role_${project.id}`, project.role);
        }
      });
    } catch (error: any) {
      console.error('Failed to load data:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to load data',
      });
    } finally {
      setLoading(false);
    }
  };

  const openCreateModal = () => {
    setEditingProject(null);
    setProjectName('');
    setSelectedTeamId(null);
    setShowCreateModal(true);
  };

  const handleUpdateProject = async () => {
    if (!id || !editingProject || !projectName.trim()) {
      return;
    }

    setCreating(true);
    try {
      const updatedProject = await api.updateProject(id, editingProject.id, {
        name: projectName.trim(),
        team_ids: selectedTeamId ? [selectedTeamId] : [],
      });
      setProjects(projects.map(p => p.id === updatedProject.id ? updatedProject : p));
      setEditingProject(null);
      setProjectName('');
      setSelectedTeamId(null);
      setShowCreateModal(false);
      toast({
        title: 'Success',
        description: 'Project updated successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update project',
        variant: 'destructive',
      });
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteProject = async (projectId: string) => {
    if (!id) return;

    if (!confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return;
    }

    try {
      await api.deleteProject(id, projectId);
      setProjects(projects.filter(p => p.id !== projectId));
      toast({
        title: 'Success',
        description: 'Project deleted successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to delete project',
        variant: 'destructive',
      });
    }
  };

  const openEditModal = (project: Project) => {
    setEditingProject(project);
    setProjectName(project.name);
    setSelectedTeamId(project.team_ids?.[0] || null);
    setShowCreateModal(true);
  };

  const closeModal = () => {
    setShowCreateModal(false);
    setEditingProject(null);
    setProjectName('');
    setSelectedTeamId(null);
  };

  // Prefetch project data on hover
  const prefetchTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());

  const handleProjectHover = (projectId: string) => {
    if (!id) return;

    // Clear any existing timeout for this project
    const existingTimeout = prefetchTimeouts.current.get(projectId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Small delay to avoid prefetching on accidental hovers
    const timeout = setTimeout(() => {
      api.prefetchProject(id, projectId).catch(() => {
        // Silently fail - prefetch errors shouldn't interrupt the user
      });
      prefetchTimeouts.current.delete(projectId);
    }, 100); // 100ms delay before prefetching

    prefetchTimeouts.current.set(projectId, timeout);
  };

  const handleProjectHoverEnd = (projectId: string) => {
    // Clear timeout if user moves mouse away before prefetch starts
    const timeout = prefetchTimeouts.current.get(projectId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchTimeouts.current.delete(projectId);
    }
  };

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Search, View Toggle, and Create Project */}
      <div className="flex items-center justify-between gap-4 mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Filter..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape' && searchQuery) {
                e.preventDefault();
                setSearchQuery('');
                searchInputRef.current?.blur();
              }
            }}
            className={`w-full pl-9 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent ${searchQuery ? 'pr-14' : 'pr-4'}`}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
              aria-label="Clear search (Esc)"
            >
              Esc
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* View Toggle */}
          <div className="flex items-center border border-border rounded-md overflow-hidden">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => setViewMode('grid')}
                  className={`px-3 py-1.5 text-sm transition-colors ${viewMode === 'grid'
                    ? 'bg-background-card text-foreground'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-background-card/50'
                    }`}
                  aria-label="Grid view"
                >
                  <Grid3x3 className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Grid view</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => setViewMode('list')}
                  className={`px-3 py-1.5 text-sm transition-colors border-l border-border ${viewMode === 'list'
                    ? 'bg-background-card text-foreground'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-background-card/50'
                    }`}
                  aria-label="List view"
                >
                  <List className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">List view</TooltipContent>
            </Tooltip>
          </div>
          {userPermissions?.manage_teams_and_projects && (
            <Button
              onClick={openCreateModal}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
            >
              <Plus className="h-4 w-4 mr-2" />
              Create Project
            </Button>
          )}
        </div>
      </div>

      {loading ? (
        viewMode === 'grid' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="bg-background-card border border-border rounded-lg p-5 animate-pulse relative"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="h-6 w-6 rounded bg-muted" />
                    <div className="h-4 w-24 rounded bg-muted" />
                    <div className="h-4 w-20 rounded bg-muted" />
                  </div>
                  <div className="h-5 w-5 rounded-full bg-muted" />
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="h-4 w-4 rounded-full bg-muted" />
                  <div className="h-4 w-20 rounded bg-muted" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-[#141618] border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Project
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Status
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Alerts
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Health Score
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Created
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[1, 2, 3].map((i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-5 w-5 rounded-full bg-muted" />
                        <div className="h-4 w-32 rounded bg-muted" />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="h-5 w-20 rounded bg-muted" />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <div className="h-4 w-4 rounded-full bg-muted" />
                        <div className="h-4 w-8 rounded bg-muted" />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="h-4 w-12 rounded bg-muted" />
                    </td>
                    <td className="px-4 py-3">
                      <div className="h-4 w-20 rounded bg-muted" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : filteredProjects.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 px-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold text-foreground mb-2">No projects found</h3>
            <p className="text-foreground-secondary mb-4">
              {searchQuery
                ? 'No projects match your search criteria.'
                : userPermissions?.manage_teams_and_projects
                  ? 'Get started by creating your first project.'
                  : 'No projects found.'}
            </p>
            {!searchQuery && userPermissions?.manage_teams_and_projects && (
              <Button
                onClick={openCreateModal}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Project
              </Button>
            )}
          </div>
        </div>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredProjects.map((project) => (
            <div
              key={project.id}
              onClick={() => handleProjectClick(project.id)}
              onMouseEnter={() => handleProjectHover(project.id)}
              onMouseLeave={() => handleProjectHoverEnd(project.id)}
              className="bg-background-card border border-border rounded-lg p-5 hover:bg-background-card/80 transition-all cursor-pointer group relative"
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <FrameworkIcon frameworkId={project.framework} size={24} />
                  <h3 className="text-base font-semibold text-foreground truncate">{project.name}</h3>
                  {(() => {
                    const { label, inProgress, isError } = projectStatusLabel(project);
                    if (inProgress) {
                      return (
                        <span className="px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 flex-shrink-0 flex items-center gap-1">
                          <Loader2 className="h-3 w-3 animate-spin" />
                          {label}
                        </span>
                      );
                    }
                    if (isError) {
                      return (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 flex-shrink-0">
                              Failed
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>{project.extraction_error || 'Extraction failed'}</TooltipContent>
                        </Tooltip>
                      );
                    }
                    return label === 'COMPLIANT' ? (
                      <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40 flex-shrink-0">
                        COMPLIANT
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 flex-shrink-0">
                        NOT COMPLIANT
                      </span>
                    );
                  })()}
                </div>
                <ChevronRight className="h-5 w-5 text-foreground-secondary group-hover:text-foreground transition-colors flex-shrink-0 ml-2" />
              </div>
              <div className="flex items-center gap-1.5 text-sm text-foreground-secondary">
                <Bell className="h-4 w-4" />
                <span>{project.alerts_count || 0} {project.alerts_count === 1 ? 'alert' : 'alerts'}</span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Project
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Status
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Alerts
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Health Score
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Created
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredProjects.map((project) => (
                <tr
                  key={project.id}
                  onClick={() => handleProjectClick(project.id)}
                  onMouseEnter={() => handleProjectHover(project.id)}
                  onMouseLeave={() => handleProjectHoverEnd(project.id)}
                  className="hover:bg-table-hover transition-colors cursor-pointer group"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <FrameworkIcon frameworkId={project.framework} size={20} />
                      <div className="text-sm font-semibold text-foreground">{project.name}</div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {(() => {
                      const { label, inProgress, isError } = projectStatusLabel(project);
                      if (inProgress) {
                        return (
                          <span className="px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 flex items-center gap-1 w-fit">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            {label}
                          </span>
                        );
                      }
                      if (isError) {
                        return (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 w-fit cursor-help">
                                Failed
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>{project.extraction_error || 'Extraction failed'}</TooltipContent>
                          </Tooltip>
                        );
                      }
                      return label === 'COMPLIANT' ? (
                        <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40">
                          COMPLIANT
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40">
                          NOT COMPLIANT
                        </span>
                      );
                    })()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <Bell className="h-4 w-4 text-foreground-secondary" />
                      <div className="text-sm text-foreground-secondary">
                        {project.alerts_count || 0}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-foreground-secondary">
                      {project.health_score}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-foreground-secondary">
                      {formatDate(project.created_at)}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Project Side Panel — shared full form with asset tier, repo connector, team */}
      {showCreateModal && !editingProject && id && (
        <CreateProjectSidebar
          open={showCreateModal}
          onClose={closeModal}
          organizationId={id}
          teams={teams}
          onProjectsReload={loadData}
        />
      )}

      {/* Edit Project Side Panel */}
      {showCreateModal && editingProject && (
        <SlideInSidebar
          open={showCreateModal}
          onClose={closeModal}
          title="Edit Project"
          description="Update the project details below."
          maxWidth="max-w-[560px]"
          footer={
            <>
              <Button variant="outline" onClick={closeModal}>Cancel</Button>
              <Button
                onClick={handleUpdateProject}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                disabled={creating || !projectName.trim()}
              >
                {creating ? (
                  <><Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />Save Changes</>
                ) : (
                  <>
                    <Save className="h-3.5 w-3.5 mr-2" />
                    Save Changes
                  </>
                )}
              </Button>
            </>
          }
        >
          <div className="space-y-6">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">
                Project Name
              </label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="Project Name"
                className="w-full px-3 py-2.5 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                onKeyDown={(e) => { if (e.key === 'Enter') handleUpdateProject(); }}
                autoFocus
              />
            </div>

            <div className="border-t border-border" />

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">
                Team
              </label>
              <ProjectTeamSelect
                value={selectedTeamId}
                onChange={setSelectedTeamId}
                teams={teams}
                variant="modal"
                placeholder="Select a team"
              />
            </div>
          </div>
        </SlideInSidebar>
      )}

    </main>
  );
}

