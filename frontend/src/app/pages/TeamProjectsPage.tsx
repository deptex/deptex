import { useState, useEffect, useMemo, useRef } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { Search, Grid3x3, List, ChevronRight, Bell, Plus, X, Loader2 } from 'lucide-react';
import { api, Project, TeamWithRole, TeamPermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { ProjectTeamSelect } from '../../components/ProjectTeamSelect';
import { FrameworkIcon } from '../../components/framework-icon';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';

interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  organizationId: string;
  userPermissions: TeamPermissions | null;
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

export default function TeamProjectsPage() {
  const { team, organizationId, userPermissions } = useOutletContext<TeamContextType>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();
  const navigate = useNavigate();

  // Filter projects to only show those belonging to this team
  const teamProjects = useMemo(() => {
    if (!team) return [];
    return projects.filter(project =>
      project.team_ids?.includes(team.id)
    );
  }, [projects, team]);

  // Filter projects based on search query
  const filteredProjects = useMemo(() => {
    if (!searchQuery.trim()) {
      return teamProjects;
    }
    const query = searchQuery.toLowerCase();
    return teamProjects.filter(project =>
      project.name.toLowerCase().includes(query)
    );
  }, [teamProjects, searchQuery]);

  useEffect(() => {
    if (organizationId) {
      loadProjects();
    }
  }, [organizationId]);

  const loadProjects = async () => {
    if (!organizationId) return;

    try {
      setLoading(true);
      const projectsData = await api.getProjects(organizationId);
      setProjects(projectsData);
    } catch (error: any) {
      console.error('Failed to load projects:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to load projects',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateProject = async () => {
    if (!organizationId || !team || !projectName.trim()) {
      toast({
        title: 'Error',
        description: 'Project name is required',
        variant: 'destructive',
      });
      return;
    }

    const trimmedName = projectName.trim();

    setCreating(true);
    try {
      await api.createProject(organizationId, {
        name: trimmedName,
        team_ids: [team.id],
      });

      // Close modal and reset form
      setShowCreateModal(false);
      setProjectName('');

      // Reload data to get the new project
      await loadProjects();

      toast({
        title: 'Success',
        description: 'Project created successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to create project',
        variant: 'destructive',
      });
    } finally {
      setCreating(false);
    }
  };

  const closeModal = () => {
    setShowCreateModal(false);
    setProjectName('');
  };

  const handleProjectClick = (projectId: string) => {
    navigate(`/organizations/${organizationId}/projects/${projectId}`);
  };

  // Prefetch project data on hover
  const prefetchTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());

  const handleProjectHover = (projectId: string) => {
    if (!organizationId) return;

    const existingTimeout = prefetchTimeouts.current.get(projectId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    const timeout = setTimeout(() => {
      api.prefetchProject(organizationId, projectId).catch(() => { });
      prefetchTimeouts.current.delete(projectId);
    }, 100);

    prefetchTimeouts.current.set(projectId, timeout);
  };

  const handleProjectHoverEnd = (projectId: string) => {
    const timeout = prefetchTimeouts.current.get(projectId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchTimeouts.current.delete(projectId);
    }
  };

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Search and View Toggle */}
      <div className="flex items-center justify-between gap-4 mb-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
          <input
            type="text"
            placeholder="Filter projects..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-64 pl-9 pr-4 h-8 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
          />
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
          {userPermissions?.manage_projects && (
            <Button
              onClick={() => {
                setProjectName('');
                setShowCreateModal(true);
              }}
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
              {teamProjects.length === 0
                ? "This team doesn't have any projects yet."
                : "No projects match your search criteria."}
            </p>
            {teamProjects.length === 0 && userPermissions?.manage_projects && (
              <Button
                onClick={() => {
                  setProjectName('');
                  setShowCreateModal(true);
                }}
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
              className="bg-background-card border border-border rounded-lg p-5 hover:bg-background-card/80 transition-all cursor-pointer group"
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

      {/* Create Project Side Panel */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={closeModal}
          />

          {/* Side Panel */}
          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
              <h2 className="text-xl font-semibold text-foreground">
                Create Project
              </h2>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
              <div className="space-y-6">
                {/* Description */}
                <div className="space-y-2">
                  <p className="text-sm text-foreground-secondary leading-relaxed">
                    Create a new project for this team. The project will be owned by{' '}
                    <span className="font-medium text-foreground">{team?.name}</span>.
                  </p>
                </div>

                {/* Form */}
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-foreground mb-2">
                      Project Name
                    </label>
                    <input
                      type="text"
                      value={projectName}
                      onChange={(e) => setProjectName(e.target.value)}
                      placeholder="My Project"
                      className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          handleCreateProject();
                        }
                      }}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-foreground mb-2">
                      Team
                    </label>
                    <ProjectTeamSelect
                      value={team?.id || null}
                      onChange={() => {}}
                      teams={team ? [team] : []}
                      variant="modal"
                      locked={true}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-5 flex items-center justify-end gap-3 flex-shrink-0">
              <Button variant="outline" onClick={closeModal}>
                Cancel
              </Button>
              <Button
                onClick={handleCreateProject}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                disabled={creating}
              >
                {creating ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Creating
                  </>
                ) : (
                  'Create'
                )}
              </Button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
