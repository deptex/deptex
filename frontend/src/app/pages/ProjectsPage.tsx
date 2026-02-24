import { useState, useEffect, useMemo, useRef } from 'react';
import { useParams, useOutletContext, useNavigate } from 'react-router-dom';
import { Plus, Folder, Search, Grid3x3, List, ChevronRight, Bell, Check, Lock, Loader2, Save, Globe, Building2, FlaskConical, Crown, HelpCircle, ChevronDown } from 'lucide-react';
import { api, Project, Team, Organization, RolePermissions, type AssetTier, type CiCdConnection, type RepoWithProvider } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { ProjectTeamSelect } from '../../components/ProjectTeamSelect';
import { FrameworkIcon } from '../../components/framework-icon';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
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
  const [assetTier, setAssetTier] = useState<AssetTier>('EXTERNAL');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const { toast } = useToast();
  const navigate = useNavigate();
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Stage 2: repo connection after project creation
  const [createdProjectId, setCreatedProjectId] = useState<string | null>(null);
  const [createdProjectName, setCreatedProjectName] = useState('');
  const [sidebarRepos, setSidebarRepos] = useState<RepoWithProvider[]>([]);
  const [sidebarReposLoading, setSidebarReposLoading] = useState(false);
  const [sidebarReposError, setSidebarReposError] = useState<string | null>(null);
  const [sidebarRepoSearch, setSidebarRepoSearch] = useState('');
  const [sidebarRepoToConnect, setSidebarRepoToConnect] = useState<RepoWithProvider | null>(null);
  const [sidebarConnections, setSidebarConnections] = useState<CiCdConnection[]>([]);
  const [sidebarSelectedIntegration, setSidebarSelectedIntegration] = useState<string | null>(null);
  const [sidebarRepoScanLoading, setSidebarRepoScanLoading] = useState<string | null>(null); // repo full_name when scanning
  type SidebarScanResult = {
    full_name: string;
    isMonorepo: boolean;
    potentialProjects: Array<{ name: string; path: string; ecosystem?: string; isLinked: boolean; linkedByProjectId?: string; linkedByProjectName?: string }>;
  };
  const [sidebarRepoScanResult, setSidebarRepoScanResult] = useState<SidebarScanResult | null>(null);
  const [sidebarRepoScanResultsByRepo, setSidebarRepoScanResultsByRepo] = useState<Record<string, SidebarScanResult>>({});
  const [sidebarScanLoading, setSidebarScanLoading] = useState(false);
  const [sidebarScanResult, setSidebarScanResult] = useState<{
    isMonorepo: boolean;
    potentialProjects: Array<{ name: string; path: string; ecosystem?: string; isLinked: boolean; linkedByProjectId?: string; linkedByProjectName?: string }>;
  } | null>(null);
  const [sidebarSelectedPath, setSidebarSelectedPath] = useState('');
  const [sidebarConnecting, setSidebarConnecting] = useState(false);
  const [sidebarRepoScanError, setSidebarRepoScanError] = useState<string | null>(null);
  const [sidebarGitHubDropdownOpen, setSidebarGitHubDropdownOpen] = useState(false);
  const sidebarGitHubDropdownRef = useRef<HTMLDivElement>(null);
  const [sidebarGitHubInstallLoading, setSidebarGitHubInstallLoading] = useState(false);

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
    const handleClickOutside = (e: MouseEvent) => {
      if (sidebarGitHubDropdownRef.current && !sidebarGitHubDropdownRef.current.contains(e.target as Node)) {
        setSidebarGitHubDropdownOpen(false);
      }
    };
    if (sidebarGitHubDropdownOpen) document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [sidebarGitHubDropdownOpen]);

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

  const handleCreateProject = async () => {
    if (!id || !projectName.trim()) {
      toast({ title: 'Error', description: 'Project name is required', variant: 'destructive' });
      return;
    }

    setCreating(true);
    try {
      const newProject = await api.createProject(id, {
        name: projectName.trim(),
        team_ids: selectedTeamId ? [selectedTeamId] : undefined,
        asset_tier: assetTier,
      });

      loadData(); // refresh list in background

      if (sidebarRepoToConnect) {
        // Use cached preview scan if we have it for this repo; otherwise scan now (needs projectId for link-status)
        const cachedScan = sidebarRepoToConnect ? sidebarRepoScanResultsByRepo[sidebarRepoToConnect.full_name] : null;
        const useCachedScan = !!(cachedScan && cachedScan.potentialProjects.length > 0);
        const potentialProjects = useCachedScan ? cachedScan.potentialProjects : null;

        if (useCachedScan && potentialProjects) {
          const unlinked = potentialProjects.filter((p) => !p.isLinked);
          const pathToConnect = sidebarSelectedPath || unlinked[0]?.path || potentialProjects[0]?.path || '';
          const selectedProject = potentialProjects.find((p) => p.path === pathToConnect) || unlinked[0];
          if (unlinked.length === 0) {
            toast({ title: 'No path available', description: 'All package paths in this repo are already linked to other projects.', variant: 'destructive' });
            closeModal();
            navigate(`/organizations/${id}/projects/${newProject.id}`);
          } else {
            try {
              await api.connectProjectRepository(id, newProject.id, {
                repo_id: sidebarRepoToConnect.id,
                repo_full_name: sidebarRepoToConnect.full_name,
                default_branch: sidebarRepoToConnect.default_branch,
                framework: sidebarRepoToConnect.framework,
                package_json_path: pathToConnect || undefined,
                ecosystem: selectedProject?.ecosystem || sidebarRepoToConnect.ecosystem,
                provider: sidebarRepoToConnect.provider,
                integration_id: sidebarRepoToConnect.integration_id,
              });
              toast({ title: 'Repository connected', description: 'Extraction has started.' });
              closeModal();
              navigate(`/organizations/${id}/projects/${newProject.id}`);
            } catch (err: any) {
              toast({ title: 'Connection failed', description: err.message || 'Failed to connect repository', variant: 'destructive' });
              closeModal();
              navigate(`/organizations/${id}/projects/${newProject.id}`);
            }
          }
        } else {
          setSidebarScanLoading(true);
          try {
            const scanData = await api.getRepositoryScan(id, newProject.id, sidebarRepoToConnect.full_name, sidebarRepoToConnect.default_branch, sidebarRepoToConnect.integration_id ?? '');
            if (scanData.potentialProjects.length === 0) {
              toast({ title: 'No manifest file found', description: 'No supported manifest file found in this repository.', variant: 'destructive' });
              closeModal();
              navigate(`/organizations/${id}/projects/${newProject.id}`);
            } else {
              const unlinked = scanData.potentialProjects.filter((p) => !p.isLinked);
              if (unlinked.length <= 1) {
                await api.connectProjectRepository(id, newProject.id, {
                  repo_id: sidebarRepoToConnect.id,
                  repo_full_name: sidebarRepoToConnect.full_name,
                  default_branch: sidebarRepoToConnect.default_branch,
                  framework: sidebarRepoToConnect.framework,
                  package_json_path: (unlinked[0]?.path) || undefined,
                  ecosystem: unlinked[0]?.ecosystem || sidebarRepoToConnect.ecosystem,
                  provider: sidebarRepoToConnect.provider,
                  integration_id: sidebarRepoToConnect.integration_id,
                });
                toast({ title: 'Repository connected', description: 'Extraction has started.' });
                closeModal();
                navigate(`/organizations/${id}/projects/${newProject.id}`);
              } else {
                setCreatedProjectId(newProject.id);
                setCreatedProjectName(projectName.trim());
                setSidebarScanResult(scanData);
                const firstUnlinked = scanData.potentialProjects.find((p) => !p.isLinked);
                setSidebarSelectedPath(firstUnlinked ? firstUnlinked.path : scanData.potentialProjects[0]?.path ?? '');
              }
            }
          } catch (err: any) {
            toast({ title: 'Scan failed', description: err.message || 'Failed to scan repository', variant: 'destructive' });
            closeModal();
            navigate(`/organizations/${id}/projects/${newProject.id}`);
          } finally {
            setSidebarScanLoading(false);
          }
        }
      } else {
        closeModal();
        navigate(`/organizations/${id}/projects/${newProject.id}`);
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to create project', variant: 'destructive' });
    } finally {
      setCreating(false);
    }
  };

  const handleSidebarRepoClick = async (repo: RepoWithProvider) => {
    if (sidebarRepoToConnect?.full_name === repo.full_name) {
      setSidebarRepoToConnect(null);
      setSidebarSelectedPath('');
      return;
    }
    setSidebarRepoToConnect(repo);
    setSidebarRepoScanResult(null);
    setSidebarRepoScanError(null);
    setSidebarSelectedPath('');
    if (!id) return;
    setSidebarRepoScanLoading(repo.full_name);
    try {
      const scanData = await api.getOrganizationRepositoryScan(id, repo.full_name, repo.default_branch, repo.integration_id ?? '');
      if (scanData.potentialProjects.length === 0) {
        setSidebarRepoScanError('No projects found in this repository.');
      } else {
        const result: SidebarScanResult = {
          full_name: repo.full_name,
          isMonorepo: scanData.isMonorepo,
          potentialProjects: scanData.potentialProjects,
        };
        setSidebarRepoScanResult(result);
        setSidebarRepoScanResultsByRepo((prev) => ({ ...prev, [repo.full_name]: result }));
        const firstUnlinked = scanData.potentialProjects.find((p) => !p.isLinked);
        if (firstUnlinked) setSidebarSelectedPath(firstUnlinked.path);
      }
    } catch (err: any) {
      setSidebarRepoScanError(err.message || 'Failed to scan repository');
    } finally {
      setSidebarRepoScanLoading(null);
    }
  };

  const loadSidebarConnections = async () => {
    if (!id) return;
    try {
      const connections = await api.getOrganizationConnections(id);
      setSidebarConnections(connections);
      const gitConnections = connections.filter((c) => c.provider !== 'slack');
      if (gitConnections.length > 0) {
        const currentValid = sidebarSelectedIntegration && gitConnections.some((c) => c.id === sidebarSelectedIntegration);
        const effectiveId = currentValid ? sidebarSelectedIntegration! : gitConnections[0].id;
        if (!currentValid) setSidebarSelectedIntegration(gitConnections[0].id);
        // Load repos for the effective provider only (first by default, or current selection)
        loadSidebarRepos(effectiveId);
      }
    } catch { /* ignore */ }
  };

  const loadSidebarRepos = async (integrationId?: string) => {
    if (!id) return;
    setSidebarReposLoading(true);
    setSidebarReposError(null);
    try {
      const targetIntegration = integrationId || sidebarSelectedIntegration || undefined;
      const repoData = await api.getOrganizationRepositories(id, targetIntegration);
      setSidebarRepos(repoData.repositories);
    } catch (err: any) {
      setSidebarReposError(err.message || 'Failed to load repositories');
    } finally {
      setSidebarReposLoading(false);
    }
  };

  const openCreateModal = () => {
    setEditingProject(null);
    setProjectName('');
    setSelectedTeamId(null);
    setAssetTier('EXTERNAL');
    setShowCreateModal(true);
    if (id) {
      loadSidebarConnections(); // loads connections and first provider's repos (no separate loadSidebarRepos)
    }
  };

  const handleSidebarConnect = async (packagePath: string) => {
    if (!id || !createdProjectId || !sidebarRepoToConnect) return;

    const matchedProject = sidebarScanResult?.potentialProjects?.find((p) => p.path === packagePath);
    setSidebarConnecting(true);
    try {
      await api.connectProjectRepository(id, createdProjectId, {
        repo_id: sidebarRepoToConnect.id,
        repo_full_name: sidebarRepoToConnect.full_name,
        default_branch: sidebarRepoToConnect.default_branch,
        framework: sidebarRepoToConnect.framework,
        package_json_path: packagePath || undefined,
        ecosystem: matchedProject?.ecosystem || sidebarRepoToConnect.ecosystem,
        provider: sidebarRepoToConnect.provider,
        integration_id: sidebarRepoToConnect.integration_id,
      });
      const projectId = createdProjectId;
      closeModal();
      navigate(`/organizations/${id}/projects/${projectId}`);
      toast({ title: 'Repository connected', description: 'Extraction has started. This may take a few minutes.' });
    } catch (err: any) {
      toast({ title: 'Connection failed', description: err.message || 'Failed to connect repository', variant: 'destructive' });
    } finally {
      setSidebarConnecting(false);
    }
  };

  const handleSkipRepo = () => {
    const projectId = createdProjectId;
    closeModal();
    if (projectId) {
      navigate(`/organizations/${id}/projects/${projectId}`);
    }
  };

  const handleUpdateProject = async () => {
    if (!id || !editingProject || !projectName.trim()) {
      return;
    }

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
    setAssetTier('EXTERNAL');
    setCreatedProjectId(null);
    setCreatedProjectName('');
    setSidebarRepos([]);
    setSidebarReposLoading(false);
    setSidebarReposError(null);
    setSidebarRepoSearch('');
    setSidebarRepoToConnect(null);
    setSidebarRepoScanLoading(null);
    setSidebarRepoScanResult(null);
    setSidebarRepoScanError(null);
    setSidebarScanLoading(false);
    setSidebarScanResult(null);
    setSidebarSelectedPath('');
    setSidebarConnecting(false);
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
            <Folder className="mx-auto h-12 w-12 text-foreground-secondary mb-4" />
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
                  {project.is_compliant !== false ? (
                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40 flex-shrink-0">
                      COMPLIANT
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 flex-shrink-0">
                      NOT COMPLIANT
                    </span>
                  )}
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
                    {project.is_compliant !== false ? (
                      <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40">
                        COMPLIANT
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40">
                        NOT COMPLIANT
                      </span>
                    )}
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

      {/* Create/Edit Side Panel */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50">
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={closeModal} />

          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl flex flex-col font-sans text-sm"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header — same style as other sidebars (DeprecateSidebar, BanVersionSidebar) */}
            <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
              <h2 className="text-lg font-semibold text-foreground">
                {editingProject ? 'Edit Project' : createdProjectId ? 'Select a package' : 'New Project'}
              </h2>
              <p className="text-sm text-foreground-secondary mt-0.5">
                {editingProject
                  ? 'Update the project details below.'
                  : createdProjectId
                    ? `${sidebarRepoToConnect?.full_name} — choose which package to track.`
                    : 'Configure your project and connect a repository.'}
              </p>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto no-scrollbar">

              {/* ── Normal form (not monorepo picker mode) ── */}
              {!createdProjectId && (
                <div className="px-6 py-6 space-y-6">

                  {/* Project name */}
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
                      onKeyDown={(e) => { if (e.key === 'Enter') editingProject ? handleUpdateProject() : handleCreateProject(); }}
                      autoFocus
                    />
                  </div>

                  <div className="border-t border-border" />

                  {/* Asset tier (create only) — 4-tier Dexcore criticality */}
                  {!editingProject && (
                    <div>
                      <div className="flex items-center gap-1.5 mb-2">
                        <label className="block text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                          Asset tier
                        </label>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="inline-flex cursor-help text-foreground-secondary hover:text-foreground" aria-label="What is asset tier?">
                              <HelpCircle className="h-3.5 w-3.5" />
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="top" className="max-w-[260px]">
                            Used by Dexcore to weight vulnerability scores and blast radius (e.g. Crown Jewels vs non-production).
                          </TooltipContent>
                        </Tooltip>
                      </div>
                      <div className="space-y-2" role="radiogroup" aria-label="Asset tier">
                        {[
                          { value: 'CROWN_JEWELS' as const, label: 'Crown Jewels', icon: Crown, desc: 'Mission-critical, highest blast radius' },
                          { value: 'EXTERNAL' as const, label: 'External', icon: Globe, desc: 'Public-facing services' },
                          { value: 'INTERNAL' as const, label: 'Internal', icon: Building2, desc: 'Internal apps & services' },
                          { value: 'NON_PRODUCTION' as const, label: 'Non-production', icon: FlaskConical, desc: 'Dev & test environments' },
                        ].map(({ value, label, icon: Icon, desc }) => {
                          const isSelected = assetTier === value;
                          return (
                            <button
                              key={value}
                              type="button"
                              role="radio"
                              aria-checked={isSelected}
                              onClick={() => setAssetTier(value)}
                              className={`w-full rounded-lg border px-4 py-3 flex items-center gap-3 text-left transition-all ${
                                isSelected
                                  ? 'bg-background-card border-foreground/50 ring-1 ring-foreground/20'
                                  : 'bg-background-card border-border hover:border-foreground-secondary/30'
                              }`}
                            >
                              <div
                                className={`h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors ${
                                  isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary/50 bg-transparent'
                                }`}
                                aria-hidden
                              >
                                {isSelected && <Check className="h-2.5 w-2.5" />}
                              </div>
                              <Icon className="h-4 w-4 flex-shrink-0 text-foreground-secondary" />
                              <div className="min-w-0 flex-1">
                                <div className="font-medium text-foreground">{label}</div>
                                <div className="text-xs text-foreground-secondary mt-0.5">{desc}</div>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Repository section (only for create, not edit) */}
                  {!editingProject && (
                    <>
                      <div className="border-t border-border" />

                      <div>
                        <div className="mb-4">
                          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-0.5">
                            Connect a Repository
                          </div>
                          <div className="text-xs text-foreground-secondary">
                            You can also connect later from the overview.
                          </div>
                        </div>

                        {sidebarReposLoading ? (
                          <div className="space-y-2">
                            {/* Dropdown skeleton (same size/structure as real) + real search bar */}
                            <div className="flex items-center gap-1.5">
                              <div className="relative flex-1 min-w-0">
                                <div
                                  className="w-full px-3 py-2 border border-border rounded-lg bg-background-card flex items-center justify-between gap-2"
                                  aria-hidden
                                >
                                  <div className="flex items-center gap-2 min-w-0">
                                    <div className="h-4 w-4 flex-shrink-0 rounded-sm bg-muted animate-pulse" />
                                    <div className="h-4 rounded bg-muted animate-pulse flex-1 min-w-[80px] max-w-[140px]" />
                                  </div>
                                  <div className="h-4 w-4 flex-shrink-0 rounded bg-muted animate-pulse" />
                                </div>
                              </div>
                              <div className="relative flex-1 min-w-0">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground-secondary pointer-events-none" />
                                <input
                                  type="text"
                                  placeholder="Search..."
                                  value={sidebarRepoSearch}
                                  onChange={(e) => setSidebarRepoSearch(e.target.value)}
                                  onKeyDown={(e) => {
                                    if (e.key === 'Escape' && sidebarRepoSearch) {
                                      setSidebarRepoSearch('');
                                      (e.target as HTMLInputElement).blur();
                                    }
                                  }}
                                  className={`w-full pl-9 py-2 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all ${sidebarRepoSearch ? 'pr-14' : 'pr-3'}`}
                                />
                                {sidebarRepoSearch && (
                                  <button
                                    type="button"
                                    onClick={() => setSidebarRepoSearch('')}
                                    className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                                    aria-label="Clear search (Esc)"
                                  >
                                    Esc
                                  </button>
                                )}
                              </div>
                            </div>
                            {/* Repo list skeletons — exact match to real card (radio + two text lines, same padding/structure) */}
                            {[1, 2, 3, 4, 5].map((i) => (
                              <div
                                key={i}
                                className="rounded-lg border border-border bg-background-card"
                                aria-hidden
                              >
                                <div className="w-full px-4 py-3 flex items-center gap-3 text-left">
                                  <div className="h-4 w-4 flex-shrink-0 rounded-full bg-muted animate-pulse" />
                                  <div className="min-w-0 flex-1 space-y-1">
                                    <div
                                      className="h-3.5 rounded bg-muted animate-pulse"
                                      style={{ width: `${52 + (i % 3) * 20}%` }}
                                    />
                                    <div className="h-3 rounded bg-muted/80 animate-pulse w-10" />
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : sidebarReposError && (sidebarReposError.includes('integration') || sidebarReposError.includes('GitHub App') || sidebarReposError.includes('No source')) ? (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden p-4 text-center">
                            <p className="text-sm font-semibold text-foreground mb-1">No source code connections</p>
                            <p className="text-xs text-foreground-secondary mb-3">
                              Connect a Git provider in Organization Settings to start importing repositories.
                            </p>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => navigate(`/organizations/${id}/settings/integrations`)}
                            >
                              Go to Integrations
                            </Button>
                          </div>
                        ) : sidebarReposError ? (
                          <p className="text-sm text-foreground-secondary">{sidebarReposError}</p>
                        ) : sidebarRepos.length === 0 ? (
                          <p className="text-sm text-foreground-secondary">No repositories available.</p>
                        ) : (
                          <div className="space-y-2">
                            {/* Top bar: Source dropdown (left) + Search (right) */}
                            <div className="flex items-center gap-1.5">
                              <div className="relative flex-1 min-w-0" ref={sidebarGitHubDropdownRef}>
                                {(() => {
                                  const gitConnections = sidebarConnections.filter((c) => c.provider !== 'slack');
                                  const selectedConn = gitConnections.find((c) => c.id === sidebarSelectedIntegration) ?? gitConnections[0] ?? null;
                                  const providerLogo = (p: string) => p === 'github' ? '/images/integrations/github.png' : p === 'gitlab' ? '/images/integrations/gitlab.png' : '/images/integrations/bitbucket.png';
                                  const connectionIcon = (conn: CiCdConnection) => {
                                    const avatar = conn.provider === 'github' ? (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url : undefined;
                                    if (avatar) return avatar;
                                    return providerLogo(conn.provider);
                                  };
                                  const connectionIconClass = (conn: CiCdConnection) => (conn.provider === 'github' && (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url) ? 'h-4 w-4 flex-shrink-0 rounded-full' : 'h-4 w-4 flex-shrink-0 rounded-sm';
                                  return (
                                    <>
                                      <button
                                        type="button"
                                        onClick={() => setSidebarGitHubDropdownOpen((o) => !o)}
                                        className="w-full px-3 py-2 border border-border rounded-lg bg-background-card hover:border-foreground-secondary/30 flex items-center justify-between gap-2 text-sm text-foreground transition-all"
                                      >
                                        <div className="flex items-center gap-2 min-w-0">
                                          {selectedConn ? (
                                            <>
                                              <img src={connectionIcon(selectedConn)} alt="" className={connectionIconClass(selectedConn)} />
                                              <span className="truncate">{selectedConn.display_name || selectedConn.provider}</span>
                                            </>
                                          ) : (
                                            <span className="truncate text-foreground-secondary">No sources</span>
                                          )}
                                        </div>
                                        <ChevronDown className={`h-4 w-4 flex-shrink-0 text-foreground-secondary transition-transform ${sidebarGitHubDropdownOpen ? 'rotate-180' : ''}`} />
                                      </button>
                                      {sidebarGitHubDropdownOpen && (
                                        <div className="absolute z-50 left-0 right-0 mt-1 py-0.5 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100">
                                          {gitConnections.map((conn) => (
                                            <button
                                              key={conn.id}
                                              type="button"
                                              className="w-full px-3 py-1.5 flex items-center justify-between gap-2 hover:bg-table-hover transition-colors"
                                              onClick={() => {
                                                setSidebarSelectedIntegration(conn.id);
                                                loadSidebarRepos(conn.id);
                                              }}
                                            >
                                              <div className="flex items-center gap-2 min-w-0">
                                                <img src={connectionIcon(conn)} alt="" className={connectionIconClass(conn)} />
                                                <span className="text-sm font-medium text-foreground truncate">{conn.display_name || conn.provider}</span>
                                              </div>
                                              {sidebarSelectedIntegration === conn.id && (
                                                <div className="h-4 w-4 rounded-full border-2 border-foreground bg-foreground flex-shrink-0 flex items-center justify-center">
                                                  <Check className="h-2.5 w-2.5 text-background" />
                                                </div>
                                              )}
                                            </button>
                                          ))}
                                        </div>
                                      )}
                                    </>
                                  );
                                })()}
                              </div>
                              <div className="relative flex-1 min-w-0">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground-secondary pointer-events-none" />
                                <input
                                  type="text"
                                  placeholder="Search..."
                                  value={sidebarRepoSearch}
                                  onChange={(e) => setSidebarRepoSearch(e.target.value)}
                                  onKeyDown={(e) => {
                                    if (e.key === 'Escape' && sidebarRepoSearch) {
                                      setSidebarRepoSearch('');
                                      (e.target as HTMLInputElement).blur();
                                    }
                                  }}
                                  className={`w-full pl-9 py-2 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all ${sidebarRepoSearch ? 'pr-14' : 'pr-3'}`}
                                />
                                {sidebarRepoSearch && (
                                  <button
                                    type="button"
                                    onClick={() => setSidebarRepoSearch('')}
                                    className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                                    aria-label="Clear search (Esc)"
                                  >
                                    Esc
                                  </button>
                                )}
                              </div>
                            </div>
                            <div className="space-y-2">
                              {(() => {
                                const filteredSidebarRepos = sidebarRepos.filter(
                                  (r) => !sidebarRepoSearch.trim() || r.full_name.toLowerCase().includes(sidebarRepoSearch.toLowerCase())
                                );
                                if (sidebarRepoSearch.trim() && filteredSidebarRepos.length === 0) {
                                  return (
                                    <p className="text-sm text-foreground-secondary py-4 text-center">
                                      No repositories match your search.
                                    </p>
                                  );
                                }
                                return (
                                  <>
                                    {filteredSidebarRepos
                                      .slice(0, sidebarRepoSearch.trim() ? undefined : 5)
                                      .map((repo) => {
                                        const isSelected = sidebarRepoToConnect?.full_name === repo.full_name;
                                        const isLoading = sidebarRepoScanLoading === repo.full_name;
                                  const scanResult = sidebarRepoScanResultsByRepo[repo.full_name] ?? (isSelected ? sidebarRepoScanResult : null);
                                  const showResult = !!scanResult;
                                  return (
                                    <div key={repo.id} className="space-y-0">
                                      <div
                                        className={`rounded-lg border bg-background-card transition-colors ${
                                          isSelected ? 'border-foreground/30 ring-1 ring-foreground/10' : 'border-border hover:border-border/80'
                                        }`}
                                      >
                                        <button
                                          type="button"
                                          onClick={() => handleSidebarRepoClick(repo)}
                                          className="w-full px-4 py-3 flex items-center justify-between gap-3 text-left"
                                        >
                                          <div className="flex items-center gap-3 min-w-0">
                                            <div className="h-4 w-4 flex-shrink-0 flex items-center justify-center">
                                              {isLoading ? (
                                                <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" />
                                              ) : (
                                                <div className={`h-4 w-4 rounded-full border-2 flex items-center justify-center transition-colors ${
                                                  isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary bg-transparent'
                                                }`}>
                                                  {isSelected ? <Check className="h-2.5 w-2.5" /> : null}
                                                </div>
                                              )}
                                            </div>
                                            <div className="min-w-0">
                                              <div className="flex items-center gap-1.5">
                                                {repo.provider && (
                                                  <img
                                                    src={repo.provider === 'github' ? '/images/integrations/github.png' : repo.provider === 'gitlab' ? '/images/integrations/gitlab.png' : '/images/integrations/bitbucket.png'}
                                                    alt=""
                                                    className="h-3.5 w-3.5 rounded-sm flex-shrink-0"
                                                  />
                                                )}
                                                <span className="text-sm font-medium text-foreground truncate">{repo.full_name}</span>
                                              </div>
                                              <div className="text-xs text-foreground-secondary font-mono">{repo.default_branch}</div>
                                            </div>
                                          </div>
                                        </button>
                                      </div>
                                      <div className="space-y-0">
                                        <div
                                          className="grid transition-[grid-template-rows] duration-200 ease-out"
                                          style={{ gridTemplateRows: isSelected && showResult && scanResult && !isLoading ? '1fr' : '0fr' }}
                                        >
                                          <div className="min-h-0 overflow-hidden">
                                            {showResult && scanResult ? (
                                              <div className="space-y-2 pl-5 pt-3">
                                          {scanResult.potentialProjects.map((p) => {
                                            const isChosen = sidebarSelectedPath === p.path;
                                            const isDisabled = p.isLinked;
                                            return (
                                              <button
                                                key={p.path || '(root)'}
                                                type="button"
                                                disabled={isDisabled}
                                                onClick={(e) => { e.stopPropagation(); !isDisabled && setSidebarSelectedPath(p.path); }}
                                                className={`w-full rounded-lg border px-4 py-3 flex items-center justify-between gap-3 text-left transition-colors ${
                                                  isDisabled
                                                    ? 'opacity-50 cursor-not-allowed border-border bg-background'
                                                    : isChosen
                                                      ? 'border-foreground/30 ring-1 ring-foreground/10 bg-background-subtle/30'
                                                      : 'border-border bg-background hover:border-border/80 hover:bg-background-subtle/30'
                                                }`}
                                              >
                                                <div className="flex items-center gap-3 min-w-0">
                                                  <div className={`h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors ${isChosen ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary bg-transparent'}`}>
                                                    {isChosen && <Check className="h-2.5 w-2.5" />}
                                                  </div>
                                                  <FrameworkIcon frameworkId={repo.framework} />
                                                  <div className="min-w-0">
                                                    <div className="text-sm font-medium text-foreground truncate">{p.name}</div>
                                                    <div className="text-xs text-foreground-secondary font-mono">{p.path === '' ? 'Root' : p.path}</div>
                                                  </div>
                                                </div>
                                                {p.isLinked ? (
                                                  <span className="flex items-center gap-1 text-xs text-foreground-secondary flex-shrink-0">
                                                    <Lock className="h-3.5 w-3.5" />
                                                    {p.linkedByProjectName || 'Linked'}
                                                  </span>
                                                ) : null}
                                              </button>
                                            );
                                          })}
                                            </div>
                                          ) : null}
                                          </div>
                                        </div>
                                        {isSelected && sidebarRepoScanError && !isLoading && (
                                          <div className="pl-5 pt-3">
                                            <div className="rounded-lg border border-border bg-background px-4 py-3 text-sm text-foreground-secondary">
                                              {sidebarRepoScanError}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  );
                                      })}
                                  </>
                                );
                              })()}
                            </div>
                          </div>
                        )}
                      </div>
                    </>
                  )}

                  {!editingProject && <div className="border-t border-border" />}

                  {/* Team selector — at bottom of form */}
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
              )}

              {/* ── Monorepo picker (shown after create when multiple packages found) ── */}
              {createdProjectId && !editingProject && sidebarScanResult && (
                <div className="px-6 py-6 space-y-4">
                  <div className="flex items-center gap-2 text-sm text-success">
                    <Check className="h-4 w-4 flex-shrink-0" />
                    <span>"{createdProjectName}" created</span>
                  </div>
                  <div className="divide-y divide-border rounded-lg border border-border overflow-hidden">
                    {sidebarScanResult.potentialProjects.map((p) => {
                      const isChosen = sidebarSelectedPath === p.path;
                      const isDisabled = p.isLinked;
                      return (
                        <button
                          key={p.path || '(root)'}
                          type="button"
                          disabled={isDisabled}
                          onClick={() => !isDisabled && setSidebarSelectedPath(p.path)}
                          className={`w-full px-4 py-3 flex items-center justify-between gap-3 text-left transition-colors ${
                            isDisabled ? 'opacity-50 cursor-not-allowed bg-background' : isChosen ? 'bg-primary/5' : 'bg-background hover:bg-background-subtle/50'
                          }`}
                        >
                          <div className="flex items-center gap-2.5 min-w-0">
                            <div className={`h-2 w-2 rounded-full flex-shrink-0 ${isChosen ? 'bg-primary' : 'bg-border'}`} />
                            <div className="min-w-0">
                              <div className="text-sm font-medium text-foreground truncate">{p.name}</div>
                              <div className="text-xs text-foreground-secondary font-mono">{p.path === '' ? 'Root' : p.path}</div>
                            </div>
                          </div>
                          {p.isLinked && (
                            <span className="flex items-center gap-1 text-xs text-foreground-secondary flex-shrink-0">
                              <Lock className="h-3.5 w-3.5" />
                              {p.linkedByProjectName || 'Linked'}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Footer — Cancel beside primary, both right-aligned */}
            <div className={`px-6 py-4 flex items-center gap-3 flex-shrink-0 border-t border-border ${createdProjectId && !editingProject ? 'justify-between' : 'justify-end'}`}>
              {createdProjectId && !editingProject ? (
                <>
                  <button onClick={handleSkipRepo} className="text-sm text-foreground-secondary hover:text-foreground transition-colors">
                    Skip for now
                  </button>
                  <Button
                    className="bg-primary text-primary-foreground hover:bg-primary/90"
                    disabled={sidebarConnecting || !!sidebarScanResult?.potentialProjects.find((p) => p.path === sidebarSelectedPath)?.isLinked}
                    onClick={() => handleSidebarConnect(sidebarSelectedPath)}
                  >
                    {sidebarConnecting ? (
                      <><Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />Connect & Go to Project</>
                    ) : 'Connect & Go to Project'}
                  </Button>
                </>
              ) : (
                <>
                  <Button variant="outline" onClick={closeModal}>Cancel</Button>
                  <Button
                    onClick={editingProject ? handleUpdateProject : handleCreateProject}
                    className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                    disabled={creating || !projectName.trim() || (!!sidebarRepoToConnect && !!sidebarRepoScanLoading)}
                  >
                    {creating ? (
                      <><Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />{editingProject ? 'Save Changes' : 'Create'}</>
                    ) : (
                      <>
                        {editingProject ? <Save className="h-3.5 w-3.5 mr-2" /> : <Plus className="h-3.5 w-3.5 mr-2" />}
                        {editingProject ? 'Save Changes' : 'Create'}
                      </>
                    )}
                  </Button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

