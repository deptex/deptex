import { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { Search, Check, Lock, Loader2, ChevronDown, PackageSearch, Inbox, HelpCircle } from 'lucide-react';
import { api, Team, type Project, type CiCdConnection, type RepoWithProvider, type RepoPeek } from '../../lib/api';
import { cn } from '../../lib/utils';
import { ImportanceSlider, IMP_DEFAULT } from '../../components/ImportanceSlider';
import { supabase } from '../../lib/supabase';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { ProjectTeamSelect } from '../../components/ProjectTeamSelect';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { FrameworkIcon } from '../../components/framework-icon';
import { RepoPathPickerDialog } from '../../components/RepoPathPickerDialog';

function toProjectName(name: string): string {
  return name
    .split(/[-_]/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function repoNameOnly(fullName: string): string {
  const parts = fullName.split('/');
  return toProjectName(parts.length > 1 ? parts[parts.length - 1] : fullName);
}

type ScanResult = {
  full_name: string;
  isMonorepo: boolean;
  potentialProjects: Array<{ name: string; path: string; ecosystem?: string; isLinked: boolean; linkedByProjectId?: string; linkedByProjectName?: string }>;
  framework?: string;
  ecosystem?: string;
  dockerizedPaths?: string[];
};


type ReposError =
  | { kind: 'workspace_missing'; provider: 'bitbucket' }
  | { kind: 'auth_expired'; provider: string }
  | { kind: 'no_integrations' }
  | { kind: 'rate_limited' }
  | { kind: 'network' }
  | { kind: 'generic' };

export default function NewProjectPage() {
  const { id: organizationId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  // lockedTeam + teams arrive via navigation state from the entry-point that
  // opened the page (e.g. team sidebar passes the locked team; Plus dropdown
  // passes nothing). teams may be empty if we navigated directly — we'll fetch
  // them below.
  const navState = (location.state ?? {}) as { lockedTeam?: Team | null; teams?: Team[] };
  const [lockedTeam] = useState<Team | null>(navState.lockedTeam ?? null);
  const [teams, setTeams] = useState<Team[]>(navState.teams ?? []);

  const [projectName, setProjectName] = useState('');
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(lockedTeam?.id ?? null);
  const [importance, setImportance] = useState<number>(IMP_DEFAULT);
  const [importanceExpanded, setImportanceExpanded] = useState(false);
  const [creating, setCreating] = useState(false);

  // Default true so the page renders the loading skeleton on first mount
  // rather than flashing the "no integrations" empty state before the fetch
  // for connections kicks in.
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionsError, setConnectionsError] = useState(false);
  const [teamsLoadError, setTeamsLoadError] = useState(false);
  const [connections, setConnections] = useState<CiCdConnection[]>([]);
  const [selectedIntegration, setSelectedIntegration] = useState<string | null>(null);

  const [repos, setRepos] = useState<RepoWithProvider[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposLoadAttempted, setReposLoadAttempted] = useState(false);
  const [reposError, setReposError] = useState<ReposError | null>(null);
  const [repoSearch, setRepoSearch] = useState('');

  const [repoToConnect, setRepoToConnect] = useState<RepoWithProvider | null>(null);
  // Peek = cheap root-only check (1-2 provider calls). Runs on every repo click.
  const [repoPeekLoading, setRepoPeekLoading] = useState<string | null>(null);
  const [repoPeekByRepo, setRepoPeekByRepo] = useState<Record<string, RepoPeek>>({});
  // Scan = heavy recursive tree walk. Runs only when needed — root has no manifest,
  // or user clicks Edit to open the path picker.
  const [repoScanLoading, setRepoScanLoading] = useState<string | null>(null);
  const [repoScanResultsByRepo, setRepoScanResultsByRepo] = useState<Record<string, ScanResult>>({});
  const [selectedPath, setSelectedPath] = useState('');
  // Ecosystem for the currently-committed path. Captured from the picker's per-layer
  // list-dir probe when the user picks a sub-path; from peek/scan when the user uses
  // the repo root. Without this, picker-discovered sub-paths would fall back to root's
  // ecosystem at submit time (wrong for monorepos with mixed-language sub-projects).
  const [selectedPathEcosystem, setSelectedPathEcosystem] = useState<string | undefined>();
  const [pathPickerOpen, setPathPickerOpen] = useState(false);
  const [repoScanError, setRepoScanError] = useState<string | null>(null);
  const [repoNoManifest, setRepoNoManifest] = useState(false);
  const [providerDropdownOpen, setProviderDropdownOpen] = useState(false);
  const providerDropdownRef = useRef<HTMLDivElement>(null);

  const [connectingProvider, setConnectingProvider] = useState<'github' | 'gitlab' | 'bitbucket' | null>(null);

  // Sequence + abort guards so a slow response from a previous integration
  // can't overwrite the active integration's state, and an in-flight repo
  // click is cancelled when the user clicks a different repo.
  const reposLoadSeqRef = useRef(0);
  const reposAbortRef = useRef<AbortController | null>(null);
  const peekSeqRef = useRef(0);
  const peekAbortRef = useRef<AbortController | null>(null);
  const scanSeqRef = useRef(0);
  const scanAbortRef = useRef<AbortController | null>(null);
  // Synchronous re-entry guard for Create button. State setters batch, so a
  // double-click within one tick can fire two requests before `creating`
  // flips. A ref flips synchronously and survives the batch.
  const creatingRef = useRef(false);
  // Track the last name we auto-filled from a repo / path pick so we can
  // detect whether the user has manually edited the field. If `projectName`
  // diverges from this ref, treat the field as user-owned and never clobber.
  const lastAutoNameRef = useRef('');
  // Set when the component unmounts so async resolves can skip state writes.
  const isMountedRef = useRef(true);

  function classifyError(err: unknown): ReposError {
    const e = err as { message?: string; responseBody?: { error?: string; code?: string } } | undefined;
    const body = e?.responseBody;
    const msg = e?.message ?? '';
    // Network errors are detectable from the JS error shape — keep this.
    if (e instanceof TypeError && msg === 'Failed to fetch') return { kind: 'network' };
    // Prefer structured `code` from the backend; only fall back to status-code
    // sniffing for cases the backend can't tag (e.g. transport-level rate-limit
    // headers we don't yet surface). Avoid matching English message fragments
    // because backend copy changes silently break classification.
    if (body?.code === 'integration_workspace_missing') {
      return { kind: 'workspace_missing', provider: 'bitbucket' };
    }
    if (body?.code === 'integration_auth_expired') {
      return { kind: 'auth_expired', provider: 'unknown' };
    }
    if (body?.code === 'no_integrations') {
      return { kind: 'no_integrations' };
    }
    if (body?.code === 'rate_limited' || /^429\b/.test(msg)) return { kind: 'rate_limited' };
    return { kind: 'generic' };
  }

  const teamLocked = !!lockedTeam;
  const effectiveTeams = teamLocked && lockedTeam ? [lockedTeam] : teams;
  const effectiveTeamId = teamLocked && lockedTeam ? lockedTeam.id : selectedTeamId;

  // Load teams if we didn't get them via navigation state. This happens on
  // direct navigation / page reload. Surface the error so the dropdown isn't
  // silently empty when the fetch fails.
  useEffect(() => {
    if (!organizationId || teams.length > 0) return;
    api.getTeams(organizationId)
      .then((data) => {
        if (!isMountedRef.current) return;
        setTeams(data);
        setTeamsLoadError(false);
      })
      .catch(() => {
        if (!isMountedRef.current) return;
        setTeamsLoadError(true);
      });
  }, [organizationId, teams.length]);

  // Unmount cleanup: abort in-flight requests AND mark unmounted so any
  // resolves that race past the abort don't write into a dead component.
  // Re-set the mount flag inside the effect body so StrictMode's dev-mode
  // mount→cleanup→mount cycle doesn't leave the ref stuck at false.
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      if (reposAbortRef.current) reposAbortRef.current.abort();
      if (peekAbortRef.current) peekAbortRef.current.abort();
      if (scanAbortRef.current) scanAbortRef.current.abort();
    };
  }, []);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (providerDropdownRef.current && !providerDropdownRef.current.contains(e.target as Node)) {
        setProviderDropdownOpen(false);
      }
    };
    if (providerDropdownOpen) document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [providerDropdownOpen]);

  useEffect(() => {
    if (organizationId) loadConnections();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [organizationId]);

  const loadConnections = async () => {
    if (!organizationId) return;
    setConnectionsLoading(true);
    setConnectionsError(false);
    try {
      const conns = await api.getOrganizationConnections(organizationId);
      setConnections(conns);
      const gitConns = conns.filter((c) => ['github', 'gitlab', 'bitbucket'].includes(c.provider));
      if (gitConns.length > 0) {
        const currentValid = selectedIntegration && gitConns.some((c) => c.id === selectedIntegration);
        const effectiveId = currentValid ? selectedIntegration! : gitConns[0].id;
        if (!currentValid) setSelectedIntegration(gitConns[0].id);
        loadRepos(effectiveId);
      } else {
        setReposLoadAttempted(true);
      }
    } catch (err) {
      console.error('Failed to load org connections:', err);
      setConnectionsError(true);
      setReposLoadAttempted(true);
    } finally {
      setConnectionsLoading(false);
    }
  };

  const loadRepos = async (integrationId?: string) => {
    if (!organizationId) return;
    if (reposAbortRef.current) reposAbortRef.current.abort();
    // Switching integrations must also kill any in-flight repo peek or scan, otherwise
    // a slow request against integration A can write its result into the cache maps
    // *after* we've already cleared them and the user is on integration B — yielding
    // stale framework/ecosystem on submit.
    if (peekAbortRef.current) peekAbortRef.current.abort();
    peekSeqRef.current++;
    if (scanAbortRef.current) scanAbortRef.current.abort();
    scanSeqRef.current++;
    const controller = new AbortController();
    reposAbortRef.current = controller;
    const seq = ++reposLoadSeqRef.current;

    setReposLoading(true);
    setReposError(null);
    setRepos([]);
    setRepoToConnect(null);
    setSelectedPath('');
    setSelectedPathEcosystem(undefined);
    setRepoPeekLoading(null);
    setRepoPeekByRepo({});
    setRepoScanLoading(null);
    setRepoScanError(null);
    setRepoNoManifest(false);
    setRepoScanResultsByRepo({});
    try {
      const targetIntegration = integrationId || selectedIntegration || undefined;
      const repoData = await api.getOrganizationRepositories(organizationId, targetIntegration, { signal: controller.signal });
      if (seq !== reposLoadSeqRef.current || !isMountedRef.current) return;
      setRepos(repoData.repositories);
    } catch (err: any) {
      if (controller.signal.aborted || err?.name === 'AbortError') return;
      if (seq !== reposLoadSeqRef.current || !isMountedRef.current) return;
      console.error('Failed to load repos:', err);
      setReposError(classifyError(err));
    } finally {
      if (seq === reposLoadSeqRef.current && isMountedRef.current) {
        setReposLoadAttempted(true);
        setReposLoading(false);
      }
    }
  };

  // Auto-fill `projectName` from a repo/path-derived value, but only if the
  // user hasn't manually edited the field. Tracks `lastAutoNameRef` so a
  // later auto-fill can overwrite a previous auto-fill but not user input.
  // Reads via the functional setter so an in-flight handler resuming after an
  // await still sees the LATEST projectName — not a render-time snapshot that
  // would silently clobber what the user typed during the wait.
  const maybeAutoSetProjectName = (newName: string) => {
    setProjectName((prev) => {
      const current = prev.trim();
      if (current === '' || current === lastAutoNameRef.current) {
        lastAutoNameRef.current = newName;
        return newName;
      }
      return prev;
    });
  };

  /** Fetch the full recursive-tree scan for a repo and cache it. Called lazily — only when
   * the user opens the path picker or when the cheap peek says the root has no manifest. */
  const ensureFullScan = async (repo: RepoWithProvider): Promise<ScanResult | null> => {
    if (!organizationId) return null;
    const cached = repoScanResultsByRepo[repo.full_name];
    if (cached) return cached;
    if (scanAbortRef.current) scanAbortRef.current.abort();
    const controller = new AbortController();
    scanAbortRef.current = controller;
    const seq = ++scanSeqRef.current;
    setRepoScanLoading(repo.full_name);
    setRepoScanError(null);
    try {
      const scanData = await api.getOrganizationRepositoryScan(
        organizationId,
        repo.full_name,
        repo.default_branch,
        repo.integration_id ?? '',
        { signal: controller.signal },
      );
      if (seq !== scanSeqRef.current || !isMountedRef.current) return null;
      if (scanData.potentialProjects.length === 0) {
        setRepoNoManifest(true);
        return null;
      }
      const result: ScanResult = {
        full_name: repo.full_name,
        isMonorepo: scanData.isMonorepo,
        potentialProjects: scanData.potentialProjects,
        framework: scanData.framework,
        ecosystem: scanData.ecosystem,
        dockerizedPaths: scanData.dockerizedPaths,
      };
      setRepoScanResultsByRepo((prev) => seq === scanSeqRef.current ? { ...prev, [repo.full_name]: result } : prev);
      return result;
    } catch (err: any) {
      if (controller.signal.aborted || err?.name === 'AbortError') return null;
      if (seq !== scanSeqRef.current || !isMountedRef.current) return null;
      console.error('Failed to scan repo:', err);
      setRepoScanError('We couldn’t scan that repository. Try again, or pick a different one.');
      return null;
    } finally {
      if (seq === scanSeqRef.current && isMountedRef.current) {
        setRepoScanLoading(null);
      }
    }
  };

  /** After an async hop returns, only commit state if the user hasn't navigated away from
   * this repo selection. We bump peekSeqRef on every repo click + integration switch, so a
   * mismatch means the result belongs to a previous selection. */
  const isStillCurrentPeek = (seq: number) => seq === peekSeqRef.current && isMountedRef.current;

  const handleRepoClick = async (repo: RepoWithProvider) => {
    setPathPickerOpen(false);
    if (repoToConnect?.full_name === repo.full_name) {
      setRepoToConnect(null);
      setSelectedPath('');
      return;
    }
    // Cancel any in-flight peek / scan from the previously-selected repo.
    if (peekAbortRef.current) peekAbortRef.current.abort();
    if (scanAbortRef.current) scanAbortRef.current.abort();
    const controller = new AbortController();
    peekAbortRef.current = controller;
    const seq = ++peekSeqRef.current;
    scanSeqRef.current++;

    setRepoToConnect(repo);
    setRepoScanError(null);
    setRepoNoManifest(false);
    setSelectedPath('');
    setSelectedPathEcosystem(undefined);
    maybeAutoSetProjectName(repoNameOnly(repo.full_name));
    if (!organizationId) return;

    // Use cached peek if we already fetched it for this repo (e.g., user clicked away and back).
    if (repoPeekByRepo[repo.full_name]) {
      const cached = repoPeekByRepo[repo.full_name];
      if (!cached.hasRootManifest) {
        // No root manifest — kick off the full scan to look for sub-projects.
        const scanResult = await ensureFullScan(repo);
        if (!isStillCurrentPeek(seq)) return;
        if (scanResult) {
          const firstUnlinked = scanResult.potentialProjects.find((p) => !p.isLinked);
          if (firstUnlinked) {
            setSelectedPath(firstUnlinked.path);
            setSelectedPathEcosystem(firstUnlinked.ecosystem);
            maybeAutoSetProjectName(firstUnlinked.path === '' ? repoNameOnly(repo.full_name) : toProjectName(firstUnlinked.name));
          }
        }
      }
      return;
    }

    setRepoPeekLoading(repo.full_name);
    try {
      const peek = await api.getOrganizationRepositoryPeek(
        organizationId,
        repo.full_name,
        repo.default_branch,
        repo.integration_id ?? '',
        { signal: controller.signal },
      );
      if (!isStillCurrentPeek(seq)) return;
      setRepoPeekByRepo((prev) => seq === peekSeqRef.current ? { ...prev, [repo.full_name]: peek } : prev);
      if (!peek.hasRootManifest) {
        // No root manifest. Could be a true no-manifest repo OR a monorepo with sub-projects.
        // Run the full scan to find out.
        const scanResult = await ensureFullScan(repo);
        if (!isStillCurrentPeek(seq)) return;
        if (scanResult) {
          const firstUnlinked = scanResult.potentialProjects.find((p) => !p.isLinked);
          if (firstUnlinked) {
            setSelectedPath(firstUnlinked.path);
            setSelectedPathEcosystem(firstUnlinked.ecosystem);
            maybeAutoSetProjectName(firstUnlinked.path === '' ? repoNameOnly(repo.full_name) : toProjectName(firstUnlinked.name));
          }
        }
      }
    } catch (err: any) {
      if (controller.signal.aborted || err?.name === 'AbortError') return;
      if (!isStillCurrentPeek(seq)) return;
      console.error('Failed to peek repo:', err);
      setRepoScanError('We couldn’t inspect that repository. Try again, or pick a different one.');
    } finally {
      if (isStillCurrentPeek(seq)) {
        setRepoPeekLoading(null);
      }
    }
  };

  const handleCreateProject = async () => {
    if (creatingRef.current) return;

    if (!organizationId || !projectName.trim()) {
      toast({ title: 'Project name required', description: 'Give your project a name to continue.', variant: 'destructive' });
      return;
    }

    // Mirror the Create button's disabled check so Enter inside the name input
    // can't bypass it. Without this, hitting Enter while a scan is in flight
    // could submit a half-formed payload.
    if (repoToConnect && !ready) {
      toast({
        title: inspecting ? 'Still inspecting' : 'Repository not ready',
        description: inspecting
          ? 'Wait for the repository scan to finish before creating.'
          : 'Pick a repository with a supported package manifest before creating.',
        variant: 'destructive',
      });
      return;
    }

    const teamIds = teamLocked && lockedTeam ? [lockedTeam.id] : effectiveTeamId ? [effectiveTeamId] : undefined;
    const cachedScan = repoToConnect ? repoScanResultsByRepo[repoToConnect.full_name] : null;
    const cachedPeek = repoToConnect ? repoPeekByRepo[repoToConnect.full_name] : null;
    // If user picked a sub-path via the picker, that ecosystem came from per-layer list-dir
    // (not the full scan's potentialProjects) so prefer it over root-derived fallbacks.
    const effectiveFramework = cachedScan?.framework || cachedPeek?.framework || repoToConnect?.framework || null;
    const createPayload: Parameters<typeof api.createProject>[1] = {
      name: projectName.trim(),
      team_ids: teamIds,
      framework: effectiveFramework || undefined,
      importance,
    };

    if (repoToConnect) {
      const potentialProjects = cachedScan?.potentialProjects ?? [];
      const unlinked = potentialProjects.filter((p) => !p.isLinked);
      if (potentialProjects.length > 0 && unlinked.length === 0) {
        toast({ title: 'No path available', description: 'All package paths in this repo are already linked to other projects.', variant: 'destructive' });
        return;
      }
      const pathToConnect = selectedPath || unlinked[0]?.path || potentialProjects[0]?.path || '';
      const selectedProject = potentialProjects.find((p) => p.path === pathToConnect);
      createPayload.repo = {
        repo_full_name: repoToConnect.full_name,
        integration_id: repoToConnect.integration_id ?? '',
        package_json_path: pathToConnect || undefined,
        // Ecosystem precedence: per-layer picker pick (the user's explicit choice) wins over
        // full-scan's potentialProjects, then root-derived peek/scan/repo defaults.
        ecosystem: selectedPathEcosystem || selectedProject?.ecosystem || cachedScan?.ecosystem || cachedPeek?.ecosystem || repoToConnect.ecosystem,
        framework: cachedScan?.framework || cachedPeek?.framework || repoToConnect.framework || undefined,
      };
    }

    creatingRef.current = true;
    setCreating(true);
    try {
      const newProject: Project = await api.createProject(organizationId, createPayload);
      // Component may have unmounted (user clicked Cancel) while the request
      // was in flight. Skip downstream side-effects in that case — the project
      // is created but we no longer own the navigation.
      if (!isMountedRef.current) return;
      window.dispatchEvent(new CustomEvent('organization:projectCreated', {
        detail: {
          id: newProject.id,
          name: newProject.name,
          owner_team_id: newProject.owner_team_id ?? null,
          team_ids: newProject.team_ids ?? [],
          framework: effectiveFramework ?? newProject.framework ?? null,
        },
      }));
      if (repoToConnect) {
        toast({ title: 'Project created', description: 'Extraction has started.' });
      }
      navigate(`/organizations/${organizationId}/overview`);
    } catch (err: unknown) {
      if (!isMountedRef.current) return;
      const e = err as { message?: string; responseBody?: { error?: string; code?: string } } | undefined;
      const code = e?.responseBody?.code;
      // Map known error codes to friendly copy. Never surface raw backend
      // error strings — those leak internals and shift under us.
      let title = 'Failed to create project';
      let description = 'Please try again, or contact support if this keeps happening.';
      if (code === 'plan_limit') {
        title = 'Project limit reached';
        description = 'Upgrade your plan to create more projects.';
      } else if (code === 'repo_already_linked' || code === 'duplicate_repo_link') {
        title = 'Repository already linked';
        description = 'That repository / path is already connected to another project.';
      } else if (code === 'integration_workspace_missing') {
        title = 'Workspace missing';
        description = 'Your Bitbucket workspace needs reconnecting from the Integrations page.';
      } else if (code === 'integration_auth_expired') {
        title = 'Integration sign-in expired';
        description = 'Reconnect the source-code provider from the Integrations page.';
      } else if (e?.message === 'Not authenticated') {
        title = 'Session expired';
        description = 'Please sign in again.';
      } else if (e instanceof TypeError && e.message === 'Failed to fetch') {
        title = 'Network error';
        description = 'Check your connection and try again.';
      }
      console.error('createProject failed:', err);
      toast({ title, description, variant: 'destructive' });
    } finally {
      creatingRef.current = false;
      if (isMountedRef.current) setCreating(false);
    }
  };

  const gitConnections = connections.filter((c) => ['github', 'gitlab', 'bitbucket'].includes(c.provider));
  const selectedConn = gitConnections.find((c) => c.id === selectedIntegration) ?? gitConnections[0] ?? null;
  const providerLogo = (p: string) => p === 'github' ? '/images/integrations/github.png' : p === 'gitlab' ? '/images/integrations/gitlab.png' : '/images/integrations/bitbucket.png';
  const connectionIcon = (conn: CiCdConnection) => {
    const avatar = conn.provider === 'github' ? (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url : undefined;
    if (avatar) return avatar;
    return providerLogo(conn.provider);
  };
  const connectionIconClass = (conn: CiCdConnection) => (conn.provider === 'github' && (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url) ? 'h-4 w-4 flex-shrink-0 rounded-full' : 'h-4 w-4 flex-shrink-0 rounded-sm';

  const filteredRepos = repos.filter(
    (r) => !repoSearch.trim() || r.full_name.toLowerCase().includes(repoSearch.toLowerCase())
  );
  const repoListLoading = reposLoading || (organizationId && !reposLoadAttempted && !reposError);

  const startGitProviderConnect = async (provider: 'github' | 'gitlab' | 'bitbucket') => {
    if (!organizationId) return;
    const endpoint = `${provider}/install`;
    const returnUrl = `${window.location.origin}/organizations/${organizationId}/new-project`;
    setConnectingProvider(provider);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session?.access_token) {
        toast({ title: 'Error', description: 'Please log in first.', variant: 'destructive' });
        return;
      }
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
      const response = await fetch(
        `${API_BASE_URL}/api/integrations/${endpoint}?org_id=${encodeURIComponent(organizationId)}&success_redirect=${encodeURIComponent(returnUrl)}`,
        { headers: { Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' } }
      );
      if (!response.ok) {
        const err = await response.json().catch(() => ({ error: `Failed to connect ${provider}` }));
        throw new Error(err.error || `Failed to start ${provider} connection`);
      }
      const data = await response.json();
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
      }
    } catch (err: any) {
      toast({ title: 'Error', description: err.message || `Failed to connect ${provider}.`, variant: 'destructive' });
    } finally {
      setConnectingProvider(null);
    }
  };

  const goBack = () => navigate(`/organizations/${organizationId}/overview`);

  const peekRunning = !!repoToConnect && repoPeekLoading === repoToConnect.full_name;
  const scanRunning = !!repoToConnect && repoScanLoading === repoToConnect.full_name;
  const inspecting = peekRunning || scanRunning;
  const peek = repoToConnect ? repoPeekByRepo[repoToConnect.full_name] : null;
  const scan = repoToConnect ? repoScanResultsByRepo[repoToConnect.full_name] : null;
  // Prefer the full scan's framework/ecosystem when available (it's authoritative for
  // sub-projects); fall back to peek for the common root-only case.
  const rootFramework = scan?.framework || peek?.framework;
  const rootEcosystem = scan?.ecosystem || peek?.ecosystem;
  // Ready means: we have enough info to create. Either the cheap peek confirms a root
  // manifest, OR the full scan found at least one usable sub-project.
  const ready = !!repoToConnect
    && !inspecting
    && !repoNoManifest
    && !repoScanError
    && (
      (!!peek && peek.hasRootManifest)
      || (!!scan && scan.potentialProjects.length > 0)
    );

  return (
    <>
      <div className="mx-auto max-w-4xl w-full px-4 sm:px-6 lg:px-8 py-10">
        <div className="rounded-xl border border-border bg-background-card-header overflow-hidden">
          <div className="px-8 pt-8 pb-2">
            <h1 className="text-3xl font-bold text-foreground tracking-tight">New Project</h1>
            <p className="mt-2 text-sm text-foreground-secondary">
              Connect a repository and configure your project.
            </p>
          </div>

          {teamsLoadError && (
            <div className="mx-8 mt-3 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground-secondary flex items-center justify-between gap-3">
              <span>Couldn't load teams. You can still create the project without one.</span>
              <button
                type="button"
                onClick={() => {
                  if (!organizationId) return;
                  setTeamsLoadError(false);
                  api.getTeams(organizationId).then(setTeams).catch(() => setTeamsLoadError(true));
                }}
                className="text-foreground hover:underline underline-offset-2"
              >
                Retry
              </button>
            </div>
          )}

          <div className="px-8 pt-4 pb-6">
            <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] gap-4">
              <div>
                <label className="block text-sm font-medium text-foreground-secondary mb-2">
                  Project Name
                </label>
                <input
                  type="text"
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  style={{ WebkitTapHighlightColor: 'transparent' }}
                  className="w-full px-3 py-2.5 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors"
                  onKeyDown={(e) => { if (e.key === 'Enter') handleCreateProject(); }}
                />
              </div>

              <span className="hidden sm:flex items-center justify-center self-end pb-2.5 text-lg text-foreground-secondary select-none">/</span>

              <div>
                <label className="block text-sm font-medium text-foreground-secondary mb-2">
                  Team
                </label>
                {teamLocked && lockedTeam ? (
                  <div className="w-full min-h-[42px] px-3 py-2.5 rounded-lg text-sm border border-border bg-background flex items-center justify-between gap-2 opacity-90 cursor-default">
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
                    className="bg-background"
                  />
                )}
              </div>
            </div>
          </div>

          <div className="mx-8 border-t border-border" />

          <div className="px-8 pt-6 pb-6">
            <label className="block text-sm font-medium text-foreground-secondary mb-2">
              Repository
            </label>
                {connectionsLoading ? (
                  <RepoListSkeleton />
                ) : connectionsError ? (
                  <ErrorState
                    icon={<Inbox className="h-5 w-5 text-foreground-secondary" />}
                    title="Couldn't load your integrations"
                    description="A network or server hiccup got in the way. Try again."
                    actionLabel="Try again"
                    onAction={loadConnections}
                  />
                ) : gitConnections.length === 0 || reposError?.kind === 'no_integrations' ? (
                  <NoIntegrationsState
                    connectingProvider={connectingProvider}
                    onConnect={startGitProviderConnect}
                  />
                ) : reposError?.kind === 'workspace_missing' ? (
                  <ErrorState
                    icon={<img src="/images/integrations/bitbucket.png" alt="" className="h-5 w-5 rounded-sm" />}
                    title="Your Bitbucket workspace needs reconnecting"
                    description="Bitbucket retired the cross-workspace listing API. Reconnect to pick a workspace."
                    actionLabel={connectingProvider === 'bitbucket' ? undefined : 'Reconnect Bitbucket'}
                    actionLeading={connectingProvider === 'bitbucket' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <img src="/images/integrations/bitbucket.png" alt="" className="h-3.5 w-3.5 rounded-sm" />}
                    onAction={() => startGitProviderConnect('bitbucket')}
                  />
                ) : reposError?.kind === 'auth_expired' ? (
                  <ErrorState
                    icon={<Lock className="h-5 w-5 text-foreground-secondary" />}
                    title="Your integration's token expired"
                    description="Reconnect the provider to refresh access."
                    actionLabel="Try again"
                    onAction={() => loadRepos()}
                  />
                ) : reposError?.kind === 'rate_limited' ? (
                  <ErrorState
                    icon={<Loader2 className="h-5 w-5 text-foreground-secondary" />}
                    title="We're being rate-limited"
                    description="Wait a minute and try again."
                    actionLabel="Retry"
                    onAction={() => loadRepos()}
                  />
                ) : reposError?.kind === 'network' ? (
                  <ErrorState
                    icon={<Inbox className="h-5 w-5 text-foreground-secondary" />}
                    title="Network error"
                    description="Check your connection and try again."
                    actionLabel="Retry"
                    onAction={() => loadRepos()}
                  />
                ) : reposError ? (
                  <ErrorState
                    icon={<Inbox className="h-5 w-5 text-foreground-secondary" />}
                    title="Couldn't load repositories"
                    description="Something went wrong loading your repositories. Try again."
                    actionLabel="Try again"
                    onAction={() => loadRepos()}
                  />
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <div className="relative flex-1 min-w-0" ref={providerDropdownRef}>
                        <button
                          type="button"
                          onClick={() => setProviderDropdownOpen((o) => !o)}
                          className="w-full px-3 py-2 border border-border rounded-lg bg-background hover:border-foreground-secondary/30 flex items-center justify-between gap-2 text-sm text-foreground transition-all"
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
                          <ChevronDown className={`h-4 w-4 flex-shrink-0 text-foreground-secondary transition-transform ${providerDropdownOpen ? 'rotate-180' : ''}`} />
                        </button>
                        {providerDropdownOpen && (
                          <div className="absolute z-50 left-0 right-0 mt-1 py-0.5 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100">
                            {gitConnections.map((conn) => (
                              <button
                                key={conn.id}
                                type="button"
                                className="w-full px-3 py-1.5 flex items-center justify-between gap-2 hover:bg-table-hover transition-colors"
                                onClick={() => {
                                  setSelectedIntegration(conn.id);
                                  loadRepos(conn.id);
                                  setProviderDropdownOpen(false);
                                }}
                              >
                                <div className="flex items-center gap-2 min-w-0">
                                  <img src={connectionIcon(conn)} alt="" className={connectionIconClass(conn)} />
                                  <span className="text-sm font-medium text-foreground truncate">{conn.display_name || conn.provider}</span>
                                </div>
                                {selectedIntegration === conn.id && (
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
                          value={repoSearch}
                          onChange={(e) => setRepoSearch(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Escape' && repoSearch) {
                              setRepoSearch('');
                              (e.target as HTMLInputElement).blur();
                            }
                          }}
                          className={`w-full pl-9 py-2 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors ${repoSearch ? 'pr-14' : 'pr-3'}`}
                        />
                        {repoSearch && (
                          <button
                            type="button"
                            onClick={() => setRepoSearch('')}
                            className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                            aria-label="Clear search (Esc)"
                          >
                            Esc
                          </button>
                        )}
                      </div>
                    </div>
                    {repoListLoading ? (
                      <RepoListSkeleton />
                    ) : repos.length === 0 ? (
                      <div className="flex flex-col items-center justify-center text-center py-10">
                        <div className="h-10 w-10 rounded-full border border-border bg-background flex items-center justify-center mb-3">
                          <Inbox className="h-5 w-5 text-foreground-secondary" />
                        </div>
                        <h3 className="text-sm font-semibold text-foreground mb-1">No repositories available</h3>
                        <p className="text-sm text-foreground-secondary max-w-md">Make sure the integration has access to at least one repository, then refresh.</p>
                      </div>
                    ) : repoSearch.trim() && filteredRepos.length === 0 ? (
                      <div className="flex flex-col items-center justify-center text-center py-10">
                        <div className="h-10 w-10 rounded-full border border-border bg-background flex items-center justify-center mb-3">
                          <Search className="h-5 w-5 text-foreground-secondary" />
                        </div>
                        <h3 className="text-sm font-semibold text-foreground mb-1">No repositories match your search</h3>
                        <p className="text-sm text-foreground-secondary max-w-md">Try a different search or clear it.</p>
                      </div>
                    ) : (
                      <div
                        role="radiogroup"
                        aria-label="Repositories"
                        className="rounded-lg border border-border bg-background divide-y divide-border max-h-[520px] overflow-y-auto custom-scrollbar"
                      >
                        {filteredRepos.map((repo) => {
                          const isSelected = repoToConnect?.full_name === repo.full_name;
                          return (
                            <button
                              key={repo.id}
                              type="button"
                              role="radio"
                              aria-checked={isSelected}
                              onClick={() => handleRepoClick(repo)}
                              className={cn(
                                'w-full px-4 py-3 flex items-center gap-3 text-left transition-colors',
                                'hover:bg-background-subtle/50',
                              )}
                            >
                              <div className="h-4 w-4 flex-shrink-0 flex items-center justify-center">
                                <div className={cn(
                                  'h-4 w-4 rounded-full border-2 flex items-center justify-center transition-colors',
                                  isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary bg-transparent',
                                )}>
                                  {isSelected ? <Check className="h-2.5 w-2.5" /> : null}
                                </div>
                              </div>
                              <div className="min-w-0">
                                <div className="flex items-center gap-1.5">
                                  {repo.provider && (
                                    <img src={providerLogo(repo.provider)} alt="" className="h-3.5 w-3.5 rounded-sm flex-shrink-0" />
                                  )}
                                  <span className="text-sm font-medium text-foreground truncate">{repo.full_name}</span>
                                </div>
                                <div className="text-xs text-foreground-secondary font-mono">{repo.default_branch}</div>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {repoToConnect && (repoNoManifest || repoScanError) && (
                  <div className="mt-4">
                    {repoNoManifest ? (
                      <div className="rounded-lg border border-border bg-background px-4 py-6 flex flex-col items-center text-center">
                        <div className="h-10 w-10 rounded-full border border-border bg-background flex items-center justify-center mb-3">
                          <PackageSearch className="h-5 w-5 text-foreground-secondary" />
                        </div>
                        <h3 className="text-sm font-semibold text-foreground mb-1">No supported package manifests found</h3>
                        <a
                          href="/docs/projects"
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-foreground-secondary hover:text-foreground underline underline-offset-2 transition-colors"
                        >
                          Check out our supported frameworks →
                        </a>
                      </div>
                    ) : (
                      <div className="rounded-lg border border-border bg-background px-4 py-3 text-sm text-foreground-secondary">{repoScanError}</div>
                    )}
                  </div>
                )}
          </div>

          <div className="mx-8 border-t border-border" />

          <div className="px-8 pt-6 pb-6 space-y-5">
                <div>
                  <label className="block text-sm font-medium text-foreground-secondary mb-2">
                    Project Root
                  </label>
                  <div className="rounded-lg border border-border bg-background px-3 py-2">
                    <div className="flex items-center justify-between gap-3">
                      <div className={cn('flex items-center gap-3 min-w-0 flex-1', ready || inspecting ? '' : 'opacity-60')}>
                        <span className="h-5 w-5 flex-shrink-0 flex items-center justify-center">
                          {inspecting ? (
                            <Loader2 className="h-4 w-4 animate-spin text-foreground/70" />
                          ) : ready && (rootFramework || rootEcosystem) ? (
                            <FrameworkIcon frameworkId={rootFramework || rootEcosystem} size={20} />
                          ) : (
                            <img src="/images/logo_white.png" alt="" className="h-5 w-5 object-contain block" />
                          )}
                        </span>
                        <span className="text-sm text-foreground font-mono truncate leading-none">
                          {selectedPath === '' ? './' : `./${selectedPath}`}
                        </span>
                      </div>
                      <Button
                        type="button"
                        variant="outline"
                        disabled={!ready}
                        onClick={() => setPathPickerOpen(true)}
                        className="!h-8 !px-3 !rounded-lg text-sm flex-shrink-0"
                        title={ready ? undefined : !repoToConnect ? 'Pick a repository first' : inspecting ? 'Inspecting repository…' : 'Repository inspection needs to finish'}
                      >
                        Edit
                      </Button>
                    </div>
                  </div>
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => setImportanceExpanded((v) => !v)}
                    aria-expanded={importanceExpanded}
                    className="flex w-full items-center justify-between text-left transition-colors hover:text-foreground group"
                  >
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="inline-flex items-center gap-1.5 text-sm font-medium text-foreground-secondary group-hover:text-foreground transition-colors cursor-help">
                          Project Importance
                          <HelpCircle className="h-3.5 w-3.5" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-[280px] p-3">
                        <p className="text-sm font-semibold text-foreground normal-case tracking-normal">Project importance</p>
                        <p className="mt-1 text-xs text-foreground-secondary normal-case tracking-normal">
                          Weights every finding's depscore for this project. Raise it for high-stakes services like payments or auth where a bug hurts most; lower it for internal sandboxes.
                        </p>
                      </TooltipContent>
                    </Tooltip>
                    <span className="flex items-center gap-2">
                      <span className="text-sm tabular-nums text-foreground">{importance.toFixed(1)}×</span>
                      <ChevronDown
                        className={cn(
                          'h-4 w-4 text-foreground-secondary transition-transform duration-200',
                          importanceExpanded && 'rotate-180',
                        )}
                      />
                    </span>
                  </button>
                  <div
                    className={cn(
                      'grid transition-[grid-template-rows] duration-200 ease-out',
                      importanceExpanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]',
                    )}
                  >
                    <div className="overflow-hidden">
                      <div className="pt-4">
                        <ImportanceSlider value={importance} onChange={setImportance} hideHeader />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

          <div className="px-8 py-4 border-t border-border bg-background-card flex items-center justify-between">
            <Button
              variant="outline"
              className="!h-8 !px-3 !rounded-lg"
              onClick={goBack}
            >
              Cancel
            </Button>
            <Button
              variant="green"
              onClick={handleCreateProject}
              disabled={creating || !projectName.trim() || !ready}
              title={
                creating
                  ? 'Creating…'
                  : !projectName.trim()
                    ? 'Give your project a name'
                    : !repoToConnect
                      ? 'Pick a repository to connect'
                      : inspecting
                        ? 'Inspecting repository…'
                        : repoNoManifest
                          ? 'No supported package manifest found in this repo'
                          : repoScanError
                            ? 'Scan failed — try again'
                            : undefined
              }
            >
              {creating ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                'Create'
              )}
            </Button>
          </div>
        </div>
      </div>

      {repoToConnect && (
        <RepoPathPickerDialog
          open={pathPickerOpen}
          onOpenChange={setPathPickerOpen}
          organizationId={organizationId ?? ''}
          repoFullName={repoToConnect.full_name}
          defaultBranch={repoToConnect.default_branch}
          integrationId={repoToConnect.integration_id ?? ''}
          initialPath={selectedPath}
          onConfirm={(path, ecosystem) => {
            setSelectedPath(path);
            // For root selection fall back to peek/scan-derived ecosystem; for sub-paths the
            // picker provides its per-layer probed ecosystem directly.
            setSelectedPathEcosystem(path === '' ? rootEcosystem : ecosystem);
            const segment = path === '' ? repoNameOnly(repoToConnect.full_name) : (path.split('/').pop() || repoNameOnly(repoToConnect.full_name));
            maybeAutoSetProjectName(toProjectName(segment));
          }}
          rootName={repoNameOnly(repoToConnect.full_name)}
          rootFramework={rootFramework || repoToConnect.framework}
          rootEcosystem={rootEcosystem}
          rootDockerized={peek?.rootDockerized}
          initialEcosystem={
            // Root row uses peek/scan-derived ecosystem; sub-paths use the value captured
            // via the picker's onConfirm. Falls back to scan's potentialProjects in case the
            // full scan ran for a no-root-manifest repo.
            selectedPath === ''
              ? rootEcosystem
              : selectedPathEcosystem || scan?.potentialProjects.find((p) => p.path === selectedPath)?.ecosystem
          }
          pathHints={(() => {
            const hints: Record<string, string | undefined> = {};
            for (const p of scan?.potentialProjects ?? []) {
              if (p.path) hints[p.path] = p.ecosystem;
            }
            return hints;
          })()}
          dockerizedPaths={scan?.dockerizedPaths ?? []}
        />
      )}
    </>
  );
}

function RepoListSkeleton() {
  return (
    <div className="space-y-2">
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="rounded-lg border border-border bg-background" aria-hidden>
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
  );
}

function ErrorState({
  icon,
  title,
  description,
  actionLabel,
  actionLeading,
  onAction,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  actionLeading?: React.ReactNode;
  onAction?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-10">
      <div className="h-10 w-10 rounded-full border border-border bg-background flex items-center justify-center mb-3">
        {icon}
      </div>
      <h3 className="text-sm font-semibold text-foreground mb-1">{title}</h3>
      <p className="text-sm text-foreground-secondary max-w-md mb-3">{description}</p>
      {onAction && (
        <Button size="sm" variant="outline" className="gap-2" onClick={onAction}>
          {actionLeading}
          {actionLabel}
        </Button>
      )}
    </div>
  );
}

function NoIntegrationsState({
  connectingProvider,
  onConnect,
}: {
  connectingProvider: 'github' | 'gitlab' | 'bitbucket' | null;
  onConnect: (provider: 'github' | 'gitlab' | 'bitbucket') => void;
}) {
  const providers: Array<{ key: 'github' | 'gitlab' | 'bitbucket'; label: string }> = [
    { key: 'github', label: 'GitHub' },
    { key: 'gitlab', label: 'GitLab' },
    { key: 'bitbucket', label: 'Bitbucket' },
  ];
  return (
    <div className="flex flex-col items-center justify-center text-center py-10">
      <div className="h-10 w-10 rounded-full border border-border bg-background flex items-center justify-center mb-3">
        <Inbox className="h-5 w-5 text-foreground-secondary" />
      </div>
      <h3 className="text-sm font-semibold text-foreground mb-1">No source code integrations</h3>
      <p className="text-sm text-foreground-secondary max-w-md mb-4">Connect a Git provider to start importing repositories.</p>
      <div className="flex flex-wrap gap-2 justify-center">
        {providers.map(({ key, label }) => (
          <Button key={key} size="sm" variant="outline" className="gap-2" disabled={!!connectingProvider} onClick={() => onConnect(key)}>
            {connectingProvider === key ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <img src={`/images/integrations/${key}.png`} alt="" className="h-3.5 w-3.5 rounded-sm" />
            )}
            Add {label}
          </Button>
        ))}
      </div>
    </div>
  );
}
