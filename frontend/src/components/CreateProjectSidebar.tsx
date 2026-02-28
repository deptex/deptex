import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Search, Check, Lock, Loader2, Save, Globe, Building2, FlaskConical, Crown, HelpCircle, ChevronDown } from 'lucide-react';
import { api, Team, type AssetTier, type CiCdConnection, type RepoWithProvider } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { Button } from './ui/button';
import { ProjectTeamSelect } from './ProjectTeamSelect';
import { FrameworkIcon } from './framework-icon';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import { SlideInSidebar } from './SlideInSidebar';

function repoNameOnly(fullName: string): string {
  const parts = fullName.split('/');
  return parts.length > 1 ? parts[parts.length - 1] : fullName;
}

type SidebarScanResult = {
  full_name: string;
  isMonorepo: boolean;
  potentialProjects: Array<{ name: string; path: string; ecosystem?: string; isLinked: boolean; linkedByProjectId?: string; linkedByProjectName?: string }>;
};

export interface CreateProjectSidebarProps {
  open: boolean;
  onClose: () => void;
  organizationId: string;
  teams: Team[];
  lockedTeam?: Team | null;
  onProjectsReload?: () => void;
}

export function CreateProjectSidebar({
  open,
  onClose,
  organizationId,
  teams,
  lockedTeam = null,
  onProjectsReload,
}: CreateProjectSidebarProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [projectName, setProjectName] = useState('');
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [assetTier, setAssetTier] = useState<AssetTier>('EXTERNAL');
  const [creating, setCreating] = useState(false);
  const [sidebarRepos, setSidebarRepos] = useState<RepoWithProvider[]>([]);
  const [sidebarReposLoading, setSidebarReposLoading] = useState(false);
  const [sidebarReposLoadAttempted, setSidebarReposLoadAttempted] = useState(false);
  const [sidebarReposError, setSidebarReposError] = useState<string | null>(null);
  const [sidebarRepoSearch, setSidebarRepoSearch] = useState('');
  const [sidebarRepoToConnect, setSidebarRepoToConnect] = useState<RepoWithProvider | null>(null);
  const [sidebarConnections, setSidebarConnections] = useState<CiCdConnection[]>([]);
  const [sidebarSelectedIntegration, setSidebarSelectedIntegration] = useState<string | null>(null);
  const [sidebarRepoScanLoading, setSidebarRepoScanLoading] = useState<string | null>(null);
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
  const [createdProjectId, setCreatedProjectId] = useState<string | null>(null);
  const [createdProjectName, setCreatedProjectName] = useState('');
  const sidebarGitHubDropdownRef = useRef<HTMLDivElement>(null);

  const teamLocked = !!lockedTeam;
  const effectiveTeams = teamLocked && lockedTeam ? [lockedTeam] : teams;
  const effectiveTeamId = teamLocked && lockedTeam ? lockedTeam.id : selectedTeamId;

  useEffect(() => {
    if (teamLocked && lockedTeam) {
      setSelectedTeamId(lockedTeam.id);
    } else if (!teamLocked && teams.length > 0 && !selectedTeamId) {
      setSelectedTeamId(teams[0]?.id ?? null);
    }
  }, [teamLocked, lockedTeam, teams, selectedTeamId]);

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
    if (open && organizationId) {
      loadSidebarConnections();
    }
  }, [open, organizationId]);

  const closeModal = () => {
    onClose();
    setProjectName('');
    setSelectedTeamId(teamLocked && lockedTeam ? lockedTeam.id : null);
    setAssetTier('EXTERNAL');
    setCreatedProjectId(null);
    setCreatedProjectName('');
    setSidebarRepos([]);
    setSidebarReposLoading(false);
    setSidebarReposLoadAttempted(false);
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

  const loadSidebarConnections = async () => {
    if (!organizationId) return;
    try {
      const connections = await api.getOrganizationConnections(organizationId);
      setSidebarConnections(connections);
      const gitConnections = connections.filter((c) => ['github', 'gitlab', 'bitbucket'].includes(c.provider));
      if (gitConnections.length > 0) {
        const currentValid = sidebarSelectedIntegration && gitConnections.some((c) => c.id === sidebarSelectedIntegration);
        const effectiveId = currentValid ? sidebarSelectedIntegration! : gitConnections[0].id;
        if (!currentValid) setSidebarSelectedIntegration(gitConnections[0].id);
        loadSidebarRepos(effectiveId);
      } else {
        setSidebarReposLoadAttempted(true);
      }
    } catch {
      setSidebarReposLoadAttempted(true);
      /* ignore */
    }
  };

  const loadSidebarRepos = async (integrationId?: string) => {
    if (!organizationId) return;
    setSidebarReposLoading(true);
    setSidebarReposError(null);
    try {
      const targetIntegration = integrationId || sidebarSelectedIntegration || undefined;
      const repoData = await api.getOrganizationRepositories(organizationId, targetIntegration);
      setSidebarRepos(repoData.repositories);
    } catch (err: any) {
      setSidebarReposError(err.message || 'Failed to load repositories');
    } finally {
      setSidebarReposLoadAttempted(true);
      setSidebarReposLoading(false);
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
    if (!organizationId) return;
    setSidebarRepoScanLoading(repo.full_name);
    try {
      const scanData = await api.getOrganizationRepositoryScan(organizationId, repo.full_name, repo.default_branch, repo.integration_id ?? '');
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

  const handleCreateProject = async () => {
    if (!organizationId || !projectName.trim()) {
      toast({ title: 'Error', description: 'Project name is required', variant: 'destructive' });
      return;
    }

    const teamIds = teamLocked && lockedTeam ? [lockedTeam.id] : effectiveTeamId ? [effectiveTeamId] : undefined;

    setCreating(true);
    try {
      const newProject = await api.createProject(organizationId, {
        name: projectName.trim(),
        team_ids: teamIds,
        asset_tier: assetTier,
      });

      onProjectsReload?.();

      if (sidebarRepoToConnect) {
        const cachedScan = sidebarRepoScanResultsByRepo[sidebarRepoToConnect.full_name];
        const useCachedScan = !!(cachedScan && cachedScan.potentialProjects.length > 0);
        const potentialProjects = useCachedScan ? cachedScan.potentialProjects : null;

        if (useCachedScan && potentialProjects) {
          const unlinked = potentialProjects.filter((p) => !p.isLinked);
          const pathToConnect = sidebarSelectedPath || unlinked[0]?.path || potentialProjects[0]?.path || '';
          const selectedProject = potentialProjects.find((p) => p.path === pathToConnect) || unlinked[0];
          if (unlinked.length === 0) {
            toast({ title: 'No path available', description: 'All package paths in this repo are already linked to other projects.', variant: 'destructive' });
            closeModal();
            navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
          } else {
            try {
              await api.connectProjectRepository(organizationId, newProject.id, {
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
              navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
            } catch (err: any) {
              toast({ title: 'Connection failed', description: err.message || 'Failed to connect repository', variant: 'destructive' });
              closeModal();
              navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
            }
          }
        } else {
          setSidebarScanLoading(true);
          try {
            const scanData = await api.getRepositoryScan(organizationId, newProject.id, sidebarRepoToConnect.full_name, sidebarRepoToConnect.default_branch, sidebarRepoToConnect.integration_id ?? '');
            if (scanData.potentialProjects.length === 0) {
              toast({ title: 'No manifest file found', description: 'No supported manifest file found in this repository.', variant: 'destructive' });
              closeModal();
              navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
            } else {
              const unlinked = scanData.potentialProjects.filter((p) => !p.isLinked);
              if (unlinked.length <= 1) {
                await api.connectProjectRepository(organizationId, newProject.id, {
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
                navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
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
            navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
          } finally {
            setSidebarScanLoading(false);
          }
        }
      } else {
        closeModal();
        navigate(`/organizations/${organizationId}/projects/${newProject.id}`);
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to create project', variant: 'destructive' });
    } finally {
      setCreating(false);
    }
  };

  const handleSidebarConnect = async (packagePath: string) => {
    if (!organizationId || !createdProjectId || !sidebarRepoToConnect) return;

    const matchedProject = sidebarScanResult?.potentialProjects?.find((p) => p.path === packagePath);
    setSidebarConnecting(true);
    try {
      await api.connectProjectRepository(organizationId, createdProjectId, {
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
      navigate(`/organizations/${organizationId}/projects/${projectId}`);
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
      navigate(`/organizations/${organizationId}/projects/${projectId}`);
    }
  };

  const gitConnections = sidebarConnections.filter((c) => ['github', 'gitlab', 'bitbucket'].includes(c.provider));
  const selectedConn = gitConnections.find((c) => c.id === sidebarSelectedIntegration) ?? gitConnections[0] ?? null;
  const providerLogo = (p: string) => p === 'github' ? '/images/integrations/github.png' : p === 'gitlab' ? '/images/integrations/gitlab.png' : '/images/integrations/bitbucket.png';
  const connectionIcon = (conn: CiCdConnection) => {
    const avatar = conn.provider === 'github' ? (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url : undefined;
    if (avatar) return avatar;
    return providerLogo(conn.provider);
  };
  const connectionIconClass = (conn: CiCdConnection) => (conn.provider === 'github' && (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url) ? 'h-4 w-4 flex-shrink-0 rounded-full' : 'h-4 w-4 flex-shrink-0 rounded-sm';

  const filteredSidebarRepos = sidebarRepos.filter(
    (r) => !sidebarRepoSearch.trim() || r.full_name.toLowerCase().includes(sidebarRepoSearch.toLowerCase())
  );
  const displayRepos = sidebarRepoSearch.trim() ? filteredSidebarRepos : filteredSidebarRepos.slice(0, 5);
  const repoListLoading = sidebarReposLoading || (open && organizationId && !sidebarReposLoadAttempted && !sidebarReposError);

  return (
    <SlideInSidebar
      open={open}
      onClose={closeModal}
      title={createdProjectId ? 'Select a package' : 'New Project'}
      description={
        createdProjectId
          ? `${sidebarRepoToConnect?.full_name ?? ''} — choose which package to track.`
          : teamLocked && lockedTeam
            ? `Configure your project and connect a repository. The project will be owned by ${lockedTeam.name}.`
            : 'Configure your project and connect a repository.'
      }
      maxWidth="max-w-[560px]"
      footerClassName={createdProjectId ? 'justify-between' : 'justify-end'}
      footer={
        createdProjectId ? (
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
              onClick={handleCreateProject}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={creating || !projectName.trim() || (!!sidebarRepoToConnect && !!sidebarRepoScanLoading)}
            >
              {creating ? (
                <><Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />Create</>
              ) : (
                <>
                  <Plus className="h-3.5 w-3.5 mr-2" />
                  Create
                </>
              )}
            </Button>
          </>
        )
      }
    >
      {!createdProjectId ? (
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
              onKeyDown={(e) => { if (e.key === 'Enter') handleCreateProject(); }}
              autoFocus
            />
          </div>

          <div className="border-t border-border" />

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
                  Used by Depscore to weight vulnerability scores and blast radius (e.g. Crown Jewels vs non-production).
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
                      isSelected ? 'bg-background-card border-foreground/50 ring-1 ring-foreground/20' : 'bg-background-card border-border hover:border-foreground-secondary/30'
                    }`}
                  >
                    <div className={`h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors ${isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary/50 bg-transparent'}`} aria-hidden>
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

            {sidebarReposError && (sidebarReposError.includes('integration') || sidebarReposError.includes('GitHub App') || sidebarReposError.includes('No source')) ? (
              <div className="bg-background-card border border-border rounded-lg overflow-hidden p-4 text-center">
                <p className="text-sm font-semibold text-foreground mb-1">No source code connections</p>
                <p className="text-xs text-foreground-secondary mb-3">
                  Connect a Git provider in Organization Settings to start importing repositories.
                </p>
                <Button size="sm" variant="outline" onClick={() => navigate(`/organizations/${organizationId}/settings/integrations`)}>
                  Go to Integrations
                </Button>
              </div>
            ) : sidebarReposError ? (
              <p className="text-sm text-foreground-secondary">{sidebarReposError}</p>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5">
                  <div className="relative flex-1 min-w-0" ref={sidebarGitHubDropdownRef}>
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
                              setSidebarGitHubDropdownOpen(false);
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
                {repoListLoading ? (
                  <div className="space-y-2">
                    {[1, 2, 3, 4, 5].map((i) => (
                      <div key={i} className="rounded-lg border border-border bg-background-card" aria-hidden>
                        <div className="w-full px-4 py-3 flex items-center gap-3 text-left">
                          <div className="h-4 w-4 flex-shrink-0 rounded-full bg-muted animate-pulse" />
                          <div className="min-w-0 flex-1 space-y-1">
                            <div className="h-3.5 rounded bg-muted animate-pulse" style={{ width: `${52 + (i % 3) * 20}%` }} />
                            <div className="h-3 rounded bg-muted/80 animate-pulse w-10" />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : sidebarRepos.length === 0 ? (
                  <p className="text-sm text-foreground-secondary">No repositories available.</p>
                ) : (
                  <div className="space-y-2">
                    {sidebarRepoSearch.trim() && filteredSidebarRepos.length === 0 ? (
                      <p className="text-sm text-foreground-secondary py-4 text-center">No repositories match your search.</p>
                    ) : (
                      displayRepos.map((repo) => {
                        const isSelected = sidebarRepoToConnect?.full_name === repo.full_name;
                        const isLoading = sidebarRepoScanLoading === repo.full_name;
                        const scanResult = sidebarRepoScanResultsByRepo[repo.full_name] ?? (isSelected ? sidebarRepoScanResult : null);
                        const showResult = !!scanResult;
                        return (
                          <div key={repo.id} className="space-y-0">
                            <div className={`rounded-lg border bg-background-card transition-colors ${isSelected ? 'border-foreground/30 ring-1 ring-foreground/10' : 'border-border hover:border-border/80'}`}>
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
                                      <div className={`h-4 w-4 rounded-full border-2 flex items-center justify-center transition-colors ${isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary bg-transparent'}`}>
                                        {isSelected ? <Check className="h-2.5 w-2.5" /> : null}
                                      </div>
                                    )}
                                  </div>
                                  <div className="min-w-0">
                                    <div className="flex items-center gap-1.5">
                                      {repo.provider && (
                                        <img src={repo.provider === 'github' ? '/images/integrations/github.png' : repo.provider === 'gitlab' ? '/images/integrations/gitlab.png' : '/images/integrations/bitbucket.png'} alt="" className="h-3.5 w-3.5 rounded-sm flex-shrink-0" />
                                      )}
                                      <span className="text-sm font-medium text-foreground truncate">{repo.full_name}</span>
                                    </div>
                                    <div className="text-xs text-foreground-secondary font-mono">{repo.default_branch}</div>
                                  </div>
                                </div>
                              </button>
                            </div>
                            <div className="space-y-0">
                              <div className="grid transition-[grid-template-rows] duration-200 ease-out" style={{ gridTemplateRows: isSelected && showResult && scanResult && !isLoading ? '1fr' : '0fr' }}>
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
                                              isDisabled ? 'opacity-50 cursor-not-allowed border-border bg-background' : isChosen ? 'border-foreground/30 ring-1 ring-foreground/10 bg-background-subtle/30' : 'border-border bg-background hover:border-border/80 hover:bg-background-subtle/30'
                                            }`}
                                          >
                                            <div className="flex items-center gap-3 min-w-0">
                                              <div className={`h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors ${isChosen ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary bg-transparent'}`}>
                                                {isChosen && <Check className="h-2.5 w-2.5" />}
                                              </div>
                                              <FrameworkIcon frameworkId={repo.framework} />
                                              <div className="min-w-0">
                                                <div className="text-sm font-medium text-foreground truncate">{p.path === '' ? repoNameOnly(repo.full_name) : p.name}</div>
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
                                  <div className="rounded-lg border border-border bg-background px-4 py-3 text-sm text-foreground-secondary">{sidebarRepoScanError}</div>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="border-t border-border" />

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">
              Team
            </label>
            {teamLocked && lockedTeam ? (
              <div className="w-full min-h-[42px] px-3 py-2.5 rounded-lg text-sm border border-border bg-background-card flex items-center justify-between gap-2 opacity-90 cursor-default">
                <span className="flex-1 min-w-0 truncate text-foreground">{lockedTeam.name}</span>
                <Lock className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
              </div>
            ) : (
              <ProjectTeamSelect
                value={effectiveTeamId}
                onChange={setSelectedTeamId}
                teams={effectiveTeams}
                variant="modal"
                placeholder="Select a team"
              />
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-sm text-success">
            <Check className="h-4 w-4 flex-shrink-0" />
            <span>"{createdProjectName}" created</span>
          </div>
          <div className="divide-y divide-border rounded-lg border border-border overflow-hidden">
            {sidebarScanResult?.potentialProjects.map((p) => {
              const isChosen = sidebarSelectedPath === p.path;
              const isDisabled = p.isLinked;
              return (
                <button
                  key={p.path || '(root)'}
                  type="button"
                  disabled={isDisabled}
                  onClick={() => !isDisabled && setSidebarSelectedPath(p.path)}
                  className={`w-full px-4 py-3 flex items-center justify-between gap-3 text-left transition-colors ${isDisabled ? 'opacity-50 cursor-not-allowed bg-background' : isChosen ? 'bg-primary/5' : 'bg-background hover:bg-background-subtle/50'}`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className={`h-2 w-2 rounded-full flex-shrink-0 ${isChosen ? 'bg-primary' : 'bg-border'}`} />
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-foreground truncate">{p.path === '' ? (sidebarRepoToConnect ? repoNameOnly(sidebarRepoToConnect.full_name) : 'Root') : p.name}</div>
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
    </SlideInSidebar>
  );
}
