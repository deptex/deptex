import { useState, useEffect, useMemo, useRef } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { Search, Grid3x3, List, ChevronRight, Bell, Plus, X, Loader2 } from 'lucide-react';
import { api, Project, TeamWithRole, TeamPermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { FrameworkIcon } from '../../components/framework-icon';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { CreateProjectSidebar } from '../../components/CreateProjectSidebar';

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
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [showCreateModal, setShowCreateModal] = useState(false);
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

  const closeModal = () => {
    setShowCreateModal(false);
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
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Filter projects..."
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
          {userPermissions?.manage_projects && (
            <Button
              onClick={() => setShowCreateModal(true)}
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
                onClick={() => setShowCreateModal(true)}
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

      {/* Create Project Side Panel — same full form as org Projects, with team locked */}
      <CreateProjectSidebar
        open={showCreateModal}
        onClose={closeModal}
        organizationId={organizationId}
        teams={team ? [team] : []}
        lockedTeam={team}
        onProjectsReload={loadProjects}
      />
    </main>
  );
}
