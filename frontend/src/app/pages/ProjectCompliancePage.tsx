import { useState, useEffect, useMemo, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Package,
  Shield,
  ShieldAlert,
  ChevronDown,
  Download,
  RefreshCw,
  Search,
  Loader2,
  Clock,
  FileText,
  AlertCircle,
  ChevronRight,
  Sparkles,
  Info,
  GitPullRequest,
  GitCommitHorizontal,
  Scale,
  ExternalLink,
  ChevronLeft,
  FileCode2,
} from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import {
  api,
  ProjectWithRole,
  ProjectPermissions,
  ProjectDependency,
  ProjectEffectivePolicies,
  RegistrySearchResult,
  LicenseObligationGroup,
  ProjectPullRequest,
  ProjectCommit,
} from '../../lib/api';
import { downloadFile } from '../../lib/compliance-utils';
import { useToast } from '../../hooks/use-toast';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { Toaster } from '../../components/ui/toaster';
import { cn } from '../../lib/utils';
import { ComplianceSidepanel, type ComplianceSection } from '../../components/ComplianceSidepanel';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

const VALID_SECTIONS: ComplianceSection[] = ['project', 'policy-results', 'updates', 'export-notice', 'export-sbom'];
function isValidSection(s: string | undefined): s is ComplianceSection {
  return !!s && VALID_SECTIONS.includes(s as ComplianceSection);
}

function formatTimeAgo(dateString: string | null | undefined): string {
  if (!dateString) return 'Never';
  const diff = Date.now() - new Date(dateString).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function getReasonCategory(reason: string): string {
  const lower = reason.toLowerCase();
  if (lower.includes('license') || lower.includes('gpl') || lower.includes('agpl') || lower.includes('copyleft')) return 'License Violation';
  if (lower.includes('malicious') || lower.includes('malware')) return 'Malicious Package';
  if (lower.includes('score') || lower.includes('reputation')) return 'Low Score';
  if (lower.includes('slsa') || lower.includes('provenance')) return 'SLSA';
  if (lower.includes('supply') || lower.includes('chain') || lower.includes('anomal')) return 'Supply Chain';
  return 'Other';
}

function getReasonBadgeColor(category: string): string {
  switch (category) {
    case 'License Violation': return 'bg-red-500/15 text-red-400 border-red-500/20';
    case 'Malicious Package': return 'bg-red-600/15 text-red-300 border-red-600/20';
    case 'Low Score': return 'bg-orange-500/15 text-orange-400 border-orange-500/20';
    case 'SLSA': return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/20';
    case 'Supply Chain': return 'bg-purple-500/15 text-purple-400 border-purple-500/20';
    default: return 'bg-zinc-500/15 text-zinc-400 border-zinc-500/20';
  }
}

// ─── Preflight Sidebar ───

function PreflightSidebar({
  open,
  onClose,
  organizationId,
  projectId,
  projectEcosystems,
}: {
  open: boolean;
  onClose: () => void;
  organizationId: string;
  projectId: string;
  projectEcosystems: string[];
}) {
  const [panelVisible, setPanelVisible] = useState(false);
  const [ecosystem, setEcosystem] = useState(projectEcosystems[0] || 'npm');
  const [searchQuery, setSearchQuery] = useState('');
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<RegistrySearchResult[]>([]);
  const [searchMode, setSearchMode] = useState<'search' | 'exact'>('search');
  const [searchError, setSearchError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<{ allowed: boolean; reasons: string[]; tierName: string; packageInfo: RegistrySearchResult } | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    setPanelVisible(false);
    const raf = requestAnimationFrame(() => {
      requestAnimationFrame(() => setPanelVisible(true));
    });
    return () => cancelAnimationFrame(raf);
  }, []);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(onClose, 150);
  }, [onClose]);

  const isExactLookup = ['pypi', 'golang', 'go'].includes(ecosystem.toLowerCase());

  const handleSearch = useCallback(async () => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    setSearchError(null);
    setCheckResult(null);
    try {
      const result = await api.searchRegistry(organizationId, projectId, ecosystem, searchQuery.trim());
      setSearchResults(result.results);
      setSearchMode(result.mode);
    } catch (err: any) {
      setSearchError(err.message || 'Search failed');
      setSearchResults([]);
    } finally {
      setSearching(false);
    }
  }, [organizationId, projectId, ecosystem, searchQuery]);

  const handleCheck = useCallback(async (pkg: RegistrySearchResult) => {
    setChecking(true);
    try {
      const result = await api.preflightCheck(organizationId, projectId, pkg.name, pkg.version || undefined, ecosystem);
      setCheckResult({
        allowed: result.allowed,
        reasons: result.reasons,
        tierName: result.tierName,
        packageInfo: pkg,
      });
    } catch (err: any) {
      toast({ title: 'Preflight check failed', description: err.message, variant: 'destructive' });
    } finally {
      setChecking(false);
    }
  }, [organizationId, projectId, ecosystem, toast]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className={cn(
          'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
          panelVisible ? 'opacity-100' : 'opacity-0'
        )}
        onClick={handleClose}
      />
      <div
        className={cn(
          'fixed right-4 top-4 bottom-4 w-full max-w-[480px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
          panelVisible ? 'translate-x-0' : 'translate-x-full'
        )}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-5 pb-3 flex-shrink-0">
          <h2 className="text-xl font-semibold text-foreground">Preflight Check</h2>
          <p className="text-sm text-foreground-secondary mt-1">Test if adding a package would affect compliance</p>
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
          {!checkResult ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground-secondary">Ecosystem</label>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="w-full justify-between h-9 text-sm">
                      {ecosystem}
                      <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="w-[200px]">
                    {projectEcosystems.map((eco) => (
                      <DropdownMenuItem key={eco} onClick={() => { setEcosystem(eco); setSearchResults([]); setSearchError(null); }}>
                        {eco}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground-secondary">
                  {isExactLookup ? 'Package name' : 'Search packages'}
                </label>
                <div className="flex gap-2">
                  <Input
                    placeholder={isExactLookup ? 'Enter package name...' : 'Search packages...'}
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                    className="h-9"
                  />
                  <Button size="sm" onClick={handleSearch} disabled={searching || !searchQuery.trim()} className="h-9 px-3">
                    {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  </Button>
                </div>
              </div>

              {searchError && (
                <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 border border-destructive/20 rounded-lg px-3 py-2">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  {searchError}
                </div>
              )}

              {searchResults.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-foreground-secondary">{searchResults.length} result{searchResults.length !== 1 ? 's' : ''}</p>
                  <div className="space-y-1.5 max-h-[400px] overflow-y-auto custom-scrollbar">
                    {searchResults.map((pkg, i) => (
                      <div key={`${pkg.name}-${i}`} className="bg-background-card border border-border rounded-lg p-3 hover:border-foreground/20 transition-colors">
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-foreground truncate">{pkg.name}</span>
                              <Badge variant="secondary" className="text-[10px] shrink-0">{pkg.version}</Badge>
                            </div>
                            {pkg.description && (
                              <p className="text-xs text-foreground-secondary mt-1 line-clamp-2">{pkg.description}</p>
                            )}
                            <div className="flex items-center gap-3 mt-1.5 text-xs text-foreground-secondary">
                              {pkg.license && <span>{pkg.license}</span>}
                              {pkg.downloads != null && <span>{pkg.downloads.toLocaleString()} downloads</span>}
                            </div>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 text-xs shrink-0"
                            onClick={() => handleCheck(pkg)}
                            disabled={checking}
                          >
                            {checking ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Check'}
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {!searching && searchResults.length === 0 && searchQuery && !searchError && (
                <p className="text-sm text-foreground-secondary text-center py-4">No results found</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className={cn(
                'rounded-lg border p-4',
                checkResult.allowed
                  ? 'bg-emerald-500/10 border-emerald-500/20'
                  : 'bg-red-500/10 border-red-500/20'
              )}>
                <div className="flex items-center gap-2 mb-2">
                  {checkResult.allowed ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-400" />
                  )}
                  <span className={cn('text-lg font-semibold', checkResult.allowed ? 'text-emerald-400' : 'text-red-400')}>
                    {checkResult.allowed ? 'Allowed' : 'Blocked'}
                  </span>
                </div>
                {checkResult.reasons.length > 0 && (
                  <div className="space-y-1 mt-2">
                    {checkResult.reasons.map((reason, i) => (
                      <p key={i} className="text-sm text-foreground-secondary flex items-start gap-1.5">
                        <span className="text-red-400 mt-0.5">•</span>
                        {reason}
                      </p>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-background-card border border-border rounded-lg p-4 space-y-2">
                <h4 className="text-sm font-medium text-foreground">{checkResult.packageInfo.name}</h4>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-foreground-secondary">Version:</span>{' '}
                    <span className="text-foreground">{checkResult.packageInfo.version}</span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">License:</span>{' '}
                    <span className="text-foreground">{checkResult.packageInfo.license || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">Tier:</span>{' '}
                    <span className="text-foreground">{checkResult.tierName}</span>
                  </div>
                  {checkResult.packageInfo.downloads != null && (
                    <div>
                      <span className="text-foreground-secondary">Downloads:</span>{' '}
                      <span className="text-foreground">{checkResult.packageInfo.downloads.toLocaleString()}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2 text-xs text-foreground-secondary bg-background-card border border-border rounded-lg px-3 py-2">
                <Info className="h-3.5 w-3.5 shrink-0" />
                Reachability analysis and import count are not available in preflight checks.
              </div>

              <Button variant="outline" size="sm" onClick={() => { setCheckResult(null); setSearchQuery(''); setSearchResults([]); }} className="w-full">
                Check Another Package
              </Button>
            </div>
          )}
        </div>

        <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
          <Button variant="outline" onClick={handleClose}>Close</Button>
        </div>
      </div>
    </div>
  );
}

// ─── Exception Diff Dialog ───

function ExceptionDiffDialog({
  open,
  onClose,
  onConfirm,
  originalCode,
  proposedCode,
  packageName,
  confirming,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  originalCode: string;
  proposedCode: string;
  packageName: string;
  confirming: boolean;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-background border border-border rounded-xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="px-6 pt-5 pb-3">
          <h3 className="text-lg font-semibold text-foreground">Review AI-Generated Exception</h3>
          <p className="text-sm text-foreground-secondary mt-1">Exception for <span className="font-medium text-foreground">{packageName}</span></p>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Original Policy</h4>
            <pre className="bg-background-card border border-border rounded-lg p-3 text-xs text-foreground-secondary overflow-x-auto max-h-40">
              {originalCode}
            </pre>
          </div>
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Proposed Policy (AI-Modified)</h4>
            <pre className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3 text-xs text-foreground overflow-x-auto max-h-40">
              {proposedCode}
            </pre>
          </div>
        </div>
        <div className="px-6 py-4 flex items-center justify-end gap-3 border-t border-border bg-background-card-header">
          <Button variant="outline" onClick={onClose} disabled={confirming}>Cancel</Button>
          <Button onClick={onConfirm} disabled={confirming}>
            {confirming ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Sparkles className="h-4 w-4 mr-2" />}
            Confirm Exception
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ───

export default function ProjectCompliancePage() {
  const { project, organizationId, userPermissions, reloadProject } = useOutletContext<ProjectContextType>();
  const { projectId, section: urlSection } = useParams<{ projectId: string; section?: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();

  const activeSection: ComplianceSection = isValidSection(urlSection) ? urlSection : 'project';
  const [policyResultsTab, setPolicyResultsTab] = useState<'issues' | 'all'>('issues');
  const [policyResultFilter, setPolicyResultFilter] = useState<string>('all');
  const [directFilter, setDirectFilter] = useState<'all' | 'direct' | 'transitive'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const [dependencies, setDependencies] = useState<ProjectDependency[]>([]);
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [obligations, setObligations] = useState<LicenseObligationGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [reevaluating, setReevaluating] = useState(false);
  const [reevalDisabledUntil, setReevalDisabledUntil] = useState(0);
  const [showPreflight, setShowPreflight] = useState(false);
  const [exporting, setExporting] = useState<'sbom' | 'notice' | null>(null);
  const [obligationsOpen, setObligationsOpen] = useState(false);

  // Updates tab state
  const [updatesSubTab, setUpdatesSubTab] = useState<'pull-requests' | 'commits'>('pull-requests');
  const [pullRequests, setPullRequests] = useState<ProjectPullRequest[]>([]);
  const [prTotal, setPrTotal] = useState(0);
  const [prPage, setPrPage] = useState(1);
  const [prStatusFilter, setPrStatusFilter] = useState<string>('all');
  const [prSearch, setPrSearch] = useState('');
  const [prLoading, setPrLoading] = useState(false);

  const [commits, setCommits] = useState<ProjectCommit[]>([]);
  const [commitsTotal, setCommitsTotal] = useState(0);
  const [commitsPage, setCommitsPage] = useState(1);
  const [commitsComplianceFilter, setCommitsComplianceFilter] = useState<string>('all');
  const [commitsSearch, setCommitsSearch] = useState('');
  const [commitsLoading, setCommitsLoading] = useState(false);

  const [exceptionLoading, setExceptionLoading] = useState<string | null>(null);
  const [diffDialog, setDiffDialog] = useState<{
    open: boolean;
    packageName: string;
    version: string;
    originalCode: string;
    proposedCode: string;
    changeId?: string;
    status?: string;
  } | null>(null);
  const [confirming, setConfirming] = useState(false);

  const canManageSettings = userPermissions?.edit_settings === true || userPermissions?.view_settings === true;
  const realtime = useRealtimeStatus(organizationId, projectId);
  const isExtracting = realtime.status !== 'ready';

  const loadData = useCallback(async () => {
    if (!organizationId || !projectId) return;
    try {
      setLoading(true);
      setError(null);
      // Progressive load: try cached dependencies first for instant paint when cache exists
      const [cachedDeps, policiesData, obligationsData] = await Promise.all([
        api.getProjectDependencies(organizationId, projectId, { cachedOnly: true }),
        api.getProjectPolicies(organizationId, projectId),
        api.getLicenseObligations(organizationId, projectId).catch(() => []),
      ]);
      setPolicies(policiesData);
      setObligations(obligationsData);
      setDependencies(cachedDeps ?? []);
      // If cache miss (no deps), or we have cached deps and want to refresh in background, fetch full deps
      if ((cachedDeps ?? []).length === 0) {
        const fullDeps = await api.getProjectDependencies(organizationId, projectId);
        setDependencies(fullDeps);
      } else {
        // Refresh deps in background so next visit has warm cache and data is fresh
        api.getProjectDependencies(organizationId, projectId).then(setDependencies).catch(() => {});
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load compliance data');
    } finally {
      setLoading(false);
    }
  }, [organizationId, projectId]);

  useEffect(() => {
    if (project && organizationId && projectId) {
      loadData();
    }
  }, [project, organizationId, projectId, loadData]);

  useEffect(() => {
    if (!organizationId || !projectId) return;
    if (!urlSection || !isValidSection(urlSection)) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/compliance/project`, { replace: true });
    }
  }, [urlSection, navigate, organizationId, projectId]);

  const handleSectionSelect = useCallback((section: ComplianceSection) => {
    navigate(`/organizations/${organizationId}/projects/${projectId}/compliance/${section}`, { replace: true });
  }, [navigate, organizationId, projectId]);

  // Derived data
  const violatedDeps = useMemo(() =>
    dependencies.filter((d) => d.policy_result && d.policy_result.allowed === false),
    [dependencies]
  );

  const allViolationReasons = useMemo(() => {
    const reasons = new Set<string>();
    for (const dep of violatedDeps) {
      for (const r of dep.policy_result?.reasons || []) {
        reasons.add(r);
      }
    }
    return [...reasons];
  }, [violatedDeps]);

  const projectEcosystems = useMemo(() => {
    const ecos = new Set<string>();
    for (const dep of dependencies) {
      const source = dep.source;
      if (source === 'dependencies' || source === 'devDependencies') ecos.add('npm');
    }
    if (ecos.size === 0) ecos.add('npm');
    return [...ecos];
  }, [dependencies]);

  const policyEvaluatedAt = (project as any)?.policy_evaluated_at as string | null;
  const isStale = policyEvaluatedAt ? (Date.now() - new Date(policyEvaluatedAt).getTime()) > 24 * 60 * 60 * 1000 : false;
  const statusName = (project as any)?.status_name || (violatedDeps.length > 0 ? 'Non-Compliant' : 'Compliant');
  const statusColor = violatedDeps.length > 0 ? '#ef4444' : '#22c55e';
  const statusViolations = (project as any)?.status_violations as string[] || [];

  // Filtered deps for Policy Results tab
  const filteredPolicyDeps = useMemo(() => {
    let filtered = [...dependencies];

    if (policyResultsTab === 'issues') {
      filtered = filtered.filter((d) => d.policy_result && d.policy_result.allowed === false);
    }

    if (policyResultFilter !== 'all') {
      filtered = filtered.filter((d) => {
        if (!d.policy_result?.reasons?.length) return policyResultFilter === 'all';
        return d.policy_result.reasons.some((r) => getReasonCategory(r) === policyResultFilter);
      });
    }

    if (directFilter === 'direct') filtered = filtered.filter((d) => d.is_direct);
    else if (directFilter === 'transitive') filtered = filtered.filter((d) => !d.is_direct);

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter((d) => d.name.toLowerCase().includes(q));
    }

    return filtered;
  }, [dependencies, policyResultsTab, policyResultFilter, directFilter, searchQuery]);

  // Quick stats
  const licenseIssueCount = useMemo(() =>
    dependencies.filter((d) => d.policy_result?.reasons?.some((r) => getReasonCategory(r) === 'License Violation')).length,
    [dependencies]
  );
  const vulnDepCount = useMemo(() =>
    dependencies.filter((d) => d.analysis && (d.analysis as any).vuln_critical > 0 || (d.analysis as any).vuln_high > 0).length,
    [dependencies]
  );
  const avgScore = useMemo(() => {
    const scored = dependencies.filter((d) => (d.analysis as any)?.dependency_score != null);
    if (scored.length === 0) return null;
    const sum = scored.reduce((acc, d) => acc + ((d.analysis as any)?.dependency_score || 0), 0);
    return Math.round(sum / scored.length);
  }, [dependencies]);

  // Handlers
  const handleReevaluate = useCallback(async () => {
    if (!organizationId || !projectId || reevaluating || Date.now() < reevalDisabledUntil) return;
    setReevaluating(true);
    try {
      const result = await api.reEvaluateProjectPolicy(organizationId, projectId);
      toast({ title: 'Policy Re-evaluated', description: `Status: ${result.statusName}. ${result.depResults} dependencies evaluated.` });
      setReevalDisabledUntil(Date.now() + 5000);
      await loadData();
      await reloadProject();
    } catch (err: any) {
      if (err.message?.includes('409') || err.message?.includes('extraction')) {
        toast({ title: 'Cannot re-evaluate', description: 'Extraction is currently in progress.', variant: 'destructive' });
      } else if (err.message?.includes('429') || err.message?.includes('rate limit')) {
        toast({ title: 'Rate limited', description: 'Please wait before re-evaluating.', variant: 'destructive' });
      } else {
        toast({ title: 'Re-evaluation failed', description: err.message, variant: 'destructive' });
      }
    } finally {
      setReevaluating(false);
    }
  }, [organizationId, projectId, reevaluating, reevalDisabledUntil, toast, loadData, reloadProject]);

  const handleExportSBOM = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setExporting('sbom');
    try {
      const blob = await api.downloadProjectSBOM(organizationId, projectId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project?.name || 'project'}-sbom.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: 'SBOM Downloaded', description: 'CycloneDX SBOM has been downloaded.' });
    } catch (err: any) {
      toast({ title: 'SBOM Download Failed', description: err.message, variant: 'destructive' });
    } finally {
      setExporting(null);
    }
  }, [organizationId, projectId, project, toast]);

  const handleExportNotice = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setExporting('notice');
    try {
      const blob = await api.downloadProjectLegalNotice(organizationId, projectId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project?.name || 'project'}-THIRD-PARTY-NOTICES.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: 'Legal Notice Downloaded', description: 'Third-party notice has been downloaded.' });
    } catch (err: any) {
      toast({ title: 'Legal Notice Download Failed', description: err.message, variant: 'destructive' });
    } finally {
      setExporting(null);
    }
  }, [organizationId, projectId, project, toast]);

  const handleApplyException = useCallback(async (dep: ProjectDependency) => {
    if (!organizationId || !projectId) return;
    setExceptionLoading(dep.id);
    try {
      const reasons = dep.policy_result?.reasons?.join(', ') || dep.name;
      const result = await api.applyForException(organizationId, projectId, dep.name, dep.version, reasons);
      setDiffDialog({
        open: true,
        packageName: dep.name,
        version: dep.version,
        originalCode: result.originalCode,
        proposedCode: result.proposedCode,
        changeId: result.change?.id,
        status: result.status,
      });
    } catch (err: any) {
      toast({ title: 'Exception Failed', description: err.message, variant: 'destructive' });
    } finally {
      setExceptionLoading(null);
    }
  }, [organizationId, projectId, toast]);

  const handleConfirmException = useCallback(async () => {
    if (!diffDialog) return;
    setConfirming(true);
    try {
      if (diffDialog.status === 'accepted') {
        toast({ title: 'Exception Applied', description: `Exception for ${diffDialog.packageName} has been applied. Re-evaluating...` });
        await loadData();
      } else {
        toast({ title: 'Exception Requested', description: `Exception for ${diffDialog.packageName} is awaiting admin approval.` });
      }
      setDiffDialog(null);
    } finally {
      setConfirming(false);
    }
  }, [diffDialog, toast, loadData]);

  const PER_PAGE = 15;

  const loadPullRequests = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setPrLoading(true);
    try {
      const res = await api.getProjectPullRequests(organizationId, projectId, {
        status: prStatusFilter,
        search: prSearch || undefined,
        page: prPage,
        perPage: PER_PAGE,
      });
      setPullRequests(res?.data ?? []);
      setPrTotal(res?.total ?? 0);
    } catch {
      setPullRequests([]);
      setPrTotal(0);
    } finally {
      setPrLoading(false);
    }
  }, [organizationId, projectId, prStatusFilter, prSearch, prPage]);

  const loadCommits = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setCommitsLoading(true);
    try {
      const res = await api.getProjectCommits(organizationId, projectId, {
        compliance_status: commitsComplianceFilter,
        search: commitsSearch || undefined,
        page: commitsPage,
        perPage: PER_PAGE,
      });
      setCommits(res?.data ?? []);
      setCommitsTotal(res?.total ?? 0);
    } catch {
      setCommits([]);
      setCommitsTotal(0);
    } finally {
      setCommitsLoading(false);
    }
  }, [organizationId, projectId, commitsComplianceFilter, commitsSearch, commitsPage]);

  useEffect(() => {
    if (activeSection === 'updates' && updatesSubTab === 'pull-requests') {
      loadPullRequests();
    }
  }, [activeSection, updatesSubTab, loadPullRequests]);

  useEffect(() => {
    if (activeSection === 'updates' && updatesSubTab === 'commits') {
      loadCommits();
    }
  }, [activeSection, updatesSubTab, loadCommits]);

  const prTotalPages = Math.max(1, Math.ceil(prTotal / PER_PAGE));
  const commitsTotalPages = Math.max(1, Math.ceil(commitsTotal / PER_PAGE));

  // Loading
  if (!project || loading) {
    return (
      <div className="min-h-[calc(100vh-3rem)] px-6 py-6">
        <div className="mx-auto max-w-7xl">
          <div className="h-8 w-48 bg-muted rounded animate-pulse mb-6" />
          <div className="grid grid-cols-4 gap-4 mb-6">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-20 bg-muted rounded-lg animate-pulse" />
            ))}
          </div>
          <div className="h-64 bg-muted rounded-lg animate-pulse" />
        </div>
        <Toaster position="bottom-right" />
      </div>
    );
  }

  // Error
  if (error) {
    return (
      <div className="min-h-[calc(100vh-3rem)] px-6 py-6">
        <div className="mx-auto max-w-7xl">
          <h1 className="text-2xl font-bold text-foreground mb-4">Compliance</h1>
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4 text-sm text-destructive">{error}</div>
        </div>
        <Toaster position="bottom-right" />
      </div>
    );
  }

  const noExtraction = dependencies.length === 0;
  const noPolicy = !policies?.effective_policy_code && !policies?.inherited_policy_code;

  return (
    <>
      <div className="flex min-h-[calc(100vh-3rem)] overflow-hidden">
        {/* Sticky compliance sidebar */}
        <ComplianceSidepanel
          activeSection={activeSection}
          onSelect={handleSectionSelect}
          canViewSettings={!!canManageSettings}
          disabledExports={noExtraction || isExtracting}
        />

        <div className="flex-1 min-w-0 overflow-auto">
          <div className="px-6 py-6 mx-auto max-w-5xl">
            {/* Re-evaluate button when on project/policy/updates and not extracting */}
            {(activeSection === 'project' || activeSection === 'policy-results' || activeSection === 'updates') && canManageSettings && !isExtracting && (
              <div className="flex items-center justify-end mb-6">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleReevaluate}
                  disabled={reevaluating || Date.now() < reevalDisabledUntil}
                  className="h-8 text-xs"
                >
                  {reevaluating ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
                  Re-evaluate
                </Button>
              </div>
            )}

            {/* ─── PROJECT SECTION ─── */}
            {activeSection === 'project' && (
            <div className="space-y-8">
              <div>
                <h1 className="text-xl font-semibold text-foreground tracking-tight">Project compliance</h1>
                <p className="text-sm text-foreground-secondary mt-1">
                  Policy status, license and vulnerability summary, and active violations from the latest scan.
                </p>
              </div>

              {isExtracting ? (
                <div className="rounded-lg border border-border bg-background-card shadow-sm p-6">
                  <div className="flex items-center gap-4">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                      <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" aria-hidden />
                    </div>
                    <div className="flex-1 space-y-1 min-w-0">
                      <h3 className="text-sm font-semibold text-foreground">Extraction in progress</h3>
                      <p className="text-sm text-foreground-secondary">
                        Compliance status will appear here once the scan completes.
                      </p>
                    </div>
                  </div>
                </div>
              ) : noExtraction ? (
                <div className="rounded-lg border border-border bg-background-card shadow-sm p-10 text-center">
                  <div className="flex justify-center">
                    <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-border bg-background-subtle">
                      <Package className="h-6 w-6 text-foreground-secondary" />
                    </div>
                  </div>
                  <h3 className="text-base font-semibold text-foreground mt-4 mb-1">No scan data yet</h3>
                  <p className="text-sm text-foreground-secondary mb-5 max-w-sm mx-auto">
                    Connect a repository and run your first extraction to see compliance status and policy results.
                  </p>
                  <Button size="sm" onClick={() => navigate(`/organizations/${organizationId}/projects/${projectId}/settings`)}>
                    Go to Settings
                  </Button>
                </div>
              ) : (
                <>
                  {/* Status Card */}
                  <div className="rounded-lg border border-border bg-background-card shadow-sm p-6">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3 min-w-0">
                        <div
                          className="w-3.5 h-3.5 rounded-full shrink-0 mt-0.5"
                          style={{ backgroundColor: statusColor }}
                        />
                        <div className="min-w-0">
                          <h2 className="text-lg font-semibold text-foreground">{statusName}</h2>
                          {violatedDeps.length > 0 ? (
                            <p className="text-sm text-foreground-secondary mt-0.5">
                              {violatedDeps.length} violation{violatedDeps.length !== 1 ? 's' : ''} detected in the latest scan
                            </p>
                          ) : (
                            <p className="text-sm text-foreground-secondary mt-0.5">
                              {noPolicy
                                ? 'No policy rules defined — all packages allowed by default.'
                                : 'All dependencies comply with the current policy.'}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-foreground-secondary">
                        <Clock className="h-3.5 w-3.5" />
                        {policyEvaluatedAt ? `Last evaluated ${formatTimeAgo(policyEvaluatedAt)}` : 'Not yet evaluated'}
                      </div>
                    </div>

                    {allViolationReasons.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-3">
                        {allViolationReasons.slice(0, 8).map((reason, i) => {
                          const cat = getReasonCategory(reason);
                          return (
                            <span key={i} className={cn('text-[11px] px-2 py-0.5 rounded-full border', getReasonBadgeColor(cat))}>
                              {reason.length > 40 ? reason.slice(0, 40) + '...' : reason}
                            </span>
                          );
                        })}
                        {allViolationReasons.length > 8 && (
                          <span className="text-[11px] px-2 py-0.5 rounded-full border bg-zinc-500/15 text-zinc-400 border-zinc-500/20">
                            +{allViolationReasons.length - 8} more
                          </span>
                        )}
                      </div>
                    )}

                    {isStale && (
                      <div className="mt-3 flex items-center gap-2 text-xs text-yellow-400">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        Policy data may be out of date. Consider re-evaluating.
                      </div>
                    )}
                  </div>

                  {/* Quick Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="rounded-lg border border-border bg-background-card shadow-sm px-4 py-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">License issues</p>
                      <p className="text-xl font-semibold text-foreground mt-1.5">{licenseIssueCount}</p>
                    </div>
                    <div className="rounded-lg border border-border bg-background-card shadow-sm px-4 py-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Vulnerable deps</p>
                      <p className="text-xl font-semibold text-foreground mt-1.5">{vulnDepCount}</p>
                    </div>
                    <div className="rounded-lg border border-border bg-background-card shadow-sm px-4 py-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Avg score</p>
                      <p className="text-xl font-semibold text-foreground mt-1.5">{avgScore ?? '—'}</p>
                    </div>
                    <div className="rounded-lg border border-border bg-background-card shadow-sm px-4 py-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Total dependencies</p>
                      <p className="text-xl font-semibold text-foreground mt-1.5">{dependencies.length}</p>
                    </div>
                  </div>

                  {/* Active Violations */}
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-2">
                        <h3 className="text-base font-semibold text-foreground">Active violations</h3>
                        {violatedDeps.length > 0 && (
                          <Badge variant="destructive" className="text-[10px]">{violatedDeps.length} items</Badge>
                        )}
                      </div>
                      <Button variant="outline" size="sm" onClick={() => setShowPreflight(true)} className="h-8 text-xs">
                        <Shield className="h-3.5 w-3.5 mr-1.5" />
                        Check a package
                      </Button>
                    </div>
                    {violatedDeps.length === 0 ? (
                      <div className="rounded-lg border border-border bg-background-card shadow-sm p-8 text-center">
                        <CheckCircle2 className="h-9 w-9 text-emerald-400 mx-auto mb-3" />
                        <p className="text-sm font-medium text-foreground">No active violations</p>
                        <p className="text-xs text-foreground-secondary mt-1">All dependencies comply with the current policy.</p>
                      </div>
                    ) : (
                      <div className="rounded-lg border border-border bg-background-card shadow-sm overflow-hidden">
                        <div className="divide-y divide-border">
                          {violatedDeps.slice(0, 20).map((dep) => (
                            <div
                              key={dep.id}
                              className="flex items-center gap-3 px-4 py-2.5 hover:bg-table-hover transition-colors cursor-pointer"
                              onClick={() => navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies/${dep.dependency_id}/overview`)}
                            >
                              <Package className="h-4 w-4 text-foreground-secondary shrink-0" />
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-medium text-foreground truncate">{dep.name}</span>
                                  <Badge variant="secondary" className="text-[10px]">{dep.version}</Badge>
                                </div>
                              </div>
                              <div className="flex flex-wrap gap-1 justify-end max-w-[50%]">
                                {(dep.policy_result?.reasons || []).slice(0, 2).map((reason, i) => (
                                  <span key={i} className={cn('text-[10px] px-1.5 py-0.5 rounded border', getReasonBadgeColor(getReasonCategory(reason)))}>
                                    {reason.length > 30 ? reason.slice(0, 30) + '...' : reason}
                                  </span>
                                ))}
                              </div>
                              <ChevronRight className="h-4 w-4 text-foreground-secondary shrink-0" />
                            </div>
                          ))}
                        </div>
                        {violatedDeps.length > 20 && (
                          <div className="px-4 py-2 text-xs text-foreground-secondary border-t border-border">
                            Showing 20 of {violatedDeps.length} violations.{' '}
                            <button onClick={() => handleSectionSelect('policy-results')} className="text-primary hover:underline">
                              View all in Policy Results
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Blocked PRs placeholder */}
                  <div>
                    <h3 className="text-base font-semibold text-foreground mb-4">Blocked pull requests</h3>
                    <div className="rounded-lg border border-border bg-background-card shadow-sm p-8 text-center">
                      <GitPullRequest className="h-9 w-9 text-foreground-secondary mx-auto mb-3" />
                      <p className="text-sm font-medium text-foreground">PR checks not configured</p>
                      <p className="text-xs text-foreground-secondary mt-1">Enable webhooks in project or organization settings to see blocked PRs.</p>
                    </div>
                  </div>

                  {/* Policy Source Card */}
                  <div>
                    <h3 className="text-base font-semibold text-foreground mb-4">Policy source</h3>
                    <div className="rounded-lg border border-border bg-background-card shadow-sm divide-y divide-border">
                      {(['Package Policy', 'Status Code', 'PR Check'] as const).map((label) => {
                        const isInherited = true;
                        return (
                          <div key={label} className="flex items-center justify-between px-4 py-3">
                            <div className="flex items-center gap-2">
                              <ShieldAlert className="h-4 w-4 text-foreground-secondary" />
                              <span className="text-sm text-foreground">{label}</span>
                            </div>
                            <Badge variant={isInherited ? 'secondary' : 'default'} className="text-[10px]">
                              {isInherited ? 'Inherited' : 'Custom'}
                            </Badge>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* ─── POLICY RESULTS SECTION ─── */}
          {activeSection === 'policy-results' && (
            <div className="space-y-4">
              {isExtracting ? (
                <div className="rounded-lg border border-border bg-background-card p-6">
                  <div className="flex items-center gap-4">
                    <div className="flex-1 space-y-2 min-w-0">
                      <h3 className="text-sm font-semibold text-foreground">Project extraction still in progress</h3>
                      <p className="text-sm text-foreground-secondary">
                        Compliance will appear here once extraction completes.
                      </p>
                    </div>
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                      <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
                    </div>
                  </div>
                </div>
              ) : (
                <>
              {/* Sub-tabs */}
              <div className="flex items-center justify-between">
                <div className="flex gap-4">
                  <button
                    onClick={() => setPolicyResultsTab('issues')}
                    className={cn(
                      'text-sm font-medium transition-colors pb-1 border-b-2',
                      policyResultsTab === 'issues' ? 'text-foreground border-foreground' : 'text-foreground-secondary border-transparent hover:text-foreground'
                    )}
                  >
                    Issues
                    {violatedDeps.length > 0 && (
                      <span className="ml-1.5 text-[10px] bg-destructive/20 text-destructive px-1.5 py-0.5 rounded-full">
                        {violatedDeps.length}
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() => setPolicyResultsTab('all')}
                    className={cn(
                      'text-sm font-medium transition-colors pb-1 border-b-2',
                      policyResultsTab === 'all' ? 'text-foreground border-foreground' : 'text-foreground-secondary border-transparent hover:text-foreground'
                    )}
                  >
                    All Packages
                  </button>
                </div>
              </div>

              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="h-8 text-xs">
                      Category: {policyResultFilter === 'all' ? 'All' : policyResultFilter}
                      <ChevronDown className="h-3 w-3 ml-1" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    {['all', 'License Violation', 'Malicious Package', 'Low Score', 'SLSA', 'Supply Chain', 'Other'].map((cat) => (
                      <DropdownMenuItem key={cat} onClick={() => setPolicyResultFilter(cat)}>
                        {cat === 'all' ? 'All Categories' : cat}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>

                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="h-8 text-xs">
                      {directFilter === 'all' ? 'All deps' : directFilter === 'direct' ? 'Direct' : 'Transitive'}
                      <ChevronDown className="h-3 w-3 ml-1" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    <DropdownMenuItem onClick={() => setDirectFilter('all')}>All</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setDirectFilter('direct')}>Direct</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setDirectFilter('transitive')}>Transitive</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>

                <div className="flex-1 max-w-xs">
                  <Input
                    placeholder="Search by package name..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="h-8 text-xs"
                  />
                </div>
              </div>

              {/* Table */}
              <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-background-card-header border-b border-border">
                      <tr>
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[30%]">Package</th>
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Version</th>
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[14%]">License</th>
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Status</th>
                        <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[22%]">Reasons</th>
                        <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {filteredPolicyDeps.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="px-4 py-8 text-center text-sm text-foreground-secondary">
                            {policyResultsTab === 'issues' ? 'No policy violations found.' : 'No dependencies to display.'}
                          </td>
                        </tr>
                      ) : (
                        filteredPolicyDeps.map((dep) => {
                          const isAllowed = dep.policy_result?.allowed !== false;
                          return (
                            <tr key={dep.id} className="group hover:bg-table-hover transition-colors">
                              <td className="px-4 py-2.5">
                                <div className="flex items-center gap-2 min-w-0">
                                  <Package className="h-4 w-4 text-foreground-secondary shrink-0" />
                                  <span className="text-sm font-medium text-foreground truncate">{dep.name}</span>
                                  {dep.is_direct && <Badge variant="secondary" className="text-[9px] shrink-0">direct</Badge>}
                                </div>
                              </td>
                              <td className="px-4 py-2.5">
                                <Badge variant="secondary" className="text-[10px]">{dep.version}</Badge>
                              </td>
                              <td className="px-4 py-2.5">
                                <span className="text-sm text-foreground-secondary">{dep.license || 'Unknown'}</span>
                              </td>
                              <td className="px-4 py-2.5">
                                {isAllowed ? (
                                  <Badge variant="success" className="gap-1 text-[10px]">
                                    <CheckCircle2 className="h-3 w-3" />
                                    Allowed
                                  </Badge>
                                ) : (
                                  <Badge variant="destructive" className="gap-1 text-[10px]">
                                    <XCircle className="h-3 w-3" />
                                    Blocked
                                  </Badge>
                                )}
                              </td>
                              <td className="px-4 py-2.5">
                                <div className="flex flex-wrap gap-1">
                                  {(dep.policy_result?.reasons || []).slice(0, 3).map((reason, i) => (
                                    <span key={i} className={cn('text-[10px] px-1.5 py-0.5 rounded border', getReasonBadgeColor(getReasonCategory(reason)))}>
                                      {reason.length > 25 ? reason.slice(0, 25) + '...' : reason}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-4 py-2.5 text-right">
                                {!isAllowed && (
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    className="opacity-0 group-hover:opacity-100 transition-opacity h-7 text-[11px] px-2"
                                    onClick={() => handleApplyException(dep)}
                                    disabled={exceptionLoading === dep.id}
                                  >
                                    {exceptionLoading === dep.id ? (
                                      <Loader2 className="h-3 w-3 animate-spin" />
                                    ) : (
                                      <>
                                        <Sparkles className="h-3 w-3 mr-1" />
                                        Exception
                                      </>
                                    )}
                                  </Button>
                                )}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* License Obligations collapsible */}
              {obligations.length > 0 && (
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <button
                    onClick={() => setObligationsOpen(!obligationsOpen)}
                    className="w-full flex items-center justify-between px-4 py-3 hover:bg-table-hover transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <Scale className="h-4 w-4 text-foreground-secondary" />
                      <span className="text-sm font-medium text-foreground">License Obligations</span>
                      <Badge variant="secondary" className="text-[10px]">{obligations.length} licenses</Badge>
                    </div>
                    <ChevronDown className={cn('h-4 w-4 text-foreground-secondary transition-transform', obligationsOpen && 'rotate-180')} />
                  </button>
                  {obligationsOpen && (
                    <div className="border-t border-border divide-y divide-border">
                      {obligations.map((group) => (
                        <div key={group.license} className="px-4 py-3">
                          <div className="flex items-center justify-between mb-1.5">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-foreground">{group.license}</span>
                              <span className="text-xs text-foreground-secondary">{group.count} package{group.count !== 1 ? 's' : ''}</span>
                            </div>
                            <div className="flex gap-1">
                              {group.obligations?.requires_attribution && (
                                <Badge variant="secondary" className="text-[9px]">Attribution</Badge>
                              )}
                              {group.obligations?.requires_source_disclosure && (
                                <Badge variant="secondary" className="text-[9px]">Source Disclosure</Badge>
                              )}
                              {group.obligations?.is_copyleft && (
                                <Badge variant="destructive" className="text-[9px]">Copyleft</Badge>
                              )}
                              {group.obligations?.is_weak_copyleft && (
                                <Badge variant="warning" className="text-[9px]">Weak Copyleft</Badge>
                              )}
                              {group.obligations?.requires_notice_file && (
                                <Badge variant="secondary" className="text-[9px]">NOTICE File</Badge>
                              )}
                            </div>
                          </div>
                          {group.obligations?.summary && (
                            <p className="text-xs text-foreground-secondary">{group.obligations.summary}</p>
                          )}
                          {!group.obligations && group.license !== 'Unknown' && (
                            <p className="text-xs text-foreground-secondary italic">Obligation details not available for this license.</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
                </>
              )}
            </div>
          )}

          {/* ─── UPDATES SECTION ─── */}
          {activeSection === 'updates' && (
            <div className="space-y-4">
              {isExtracting ? (
                <div className="rounded-lg border border-border bg-background-card p-6">
                  <div className="flex items-center gap-4">
                    <div className="flex-1 space-y-2 min-w-0">
                      <h3 className="text-sm font-semibold text-foreground">Project extraction still in progress</h3>
                      <p className="text-sm text-foreground-secondary">
                        Pull requests and commits will appear here once extraction completes.
                      </p>
                    </div>
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                      <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
                    </div>
                  </div>
                </div>
              ) : (
                <>
              {/* Sub-tabs */}
              <div className="flex items-center gap-4">
                <button
                  onClick={() => { setUpdatesSubTab('pull-requests'); setPrPage(1); }}
                  className={cn(
                    'text-sm font-medium transition-colors pb-1 border-b-2',
                    updatesSubTab === 'pull-requests' ? 'text-foreground border-foreground' : 'text-foreground-secondary border-transparent hover:text-foreground'
                  )}
                >
                  Pull Requests
                  {prTotal > 0 && (
                    <span className="ml-1.5 text-[10px] bg-foreground/10 text-foreground-secondary px-1.5 py-0.5 rounded-full">
                      {prTotal}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => { setUpdatesSubTab('commits'); setCommitsPage(1); }}
                  className={cn(
                    'text-sm font-medium transition-colors pb-1 border-b-2',
                    updatesSubTab === 'commits' ? 'text-foreground border-foreground' : 'text-foreground-secondary border-transparent hover:text-foreground'
                  )}
                >
                  Commits
                  {commitsTotal > 0 && (
                    <span className="ml-1.5 text-[10px] bg-foreground/10 text-foreground-secondary px-1.5 py-0.5 rounded-full">
                      {commitsTotal}
                    </span>
                  )}
                </button>
              </div>

              {/* ── Pull Requests ── */}
              {updatesSubTab === 'pull-requests' && (
                <div className="space-y-4">
                  {/* Filters */}
                  <div className="flex flex-wrap items-center gap-2">
                    {(['all', 'open', 'merged', 'closed'] as const).map((status) => (
                      <Button
                        key={status}
                        variant={prStatusFilter === status ? 'default' : 'outline'}
                        size="sm"
                        className="h-8 text-xs capitalize"
                        onClick={() => { setPrStatusFilter(status); setPrPage(1); }}
                      >
                        {status === 'all' ? 'All' : status}
                      </Button>
                    ))}
                    <div className="flex-1 max-w-xs">
                      <Input
                        placeholder="Search by title or author..."
                        value={prSearch}
                        onChange={(e) => { setPrSearch(e.target.value); setPrPage(1); }}
                        className="h-8 text-xs"
                      />
                    </div>
                  </div>

                  {/* Table */}
                  {prLoading ? (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="divide-y divide-border">
                        {[1, 2, 3, 4, 5].map((i) => (
                          <div key={i} className="flex items-center gap-4 px-4 py-3">
                            <div className="h-4 w-4 bg-muted rounded animate-pulse" />
                            <div className="flex-1 space-y-1.5">
                              <div className="h-4 w-3/5 bg-muted rounded animate-pulse" />
                              <div className="h-3 w-1/4 bg-muted rounded animate-pulse" />
                            </div>
                            <div className="h-5 w-16 bg-muted rounded-full animate-pulse" />
                            <div className="h-5 w-16 bg-muted rounded-full animate-pulse" />
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : pullRequests.length === 0 ? (
                    <div className="bg-background-card border border-border rounded-lg p-8 text-center">
                      <GitPullRequest className="h-10 w-10 text-foreground-secondary mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-foreground mb-1">No pull requests yet.</h3>
                      <p className="text-sm text-foreground-secondary">
                        Pull requests will appear here once webhooks deliver PR events.
                      </p>
                    </div>
                  ) : (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Pull Request</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[14%]">Author</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]">Status</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Check</th>
                              <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]">Deps</th>
                              <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]">Time</th>
                              <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[4%]"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {pullRequests.map((pr) => {
                              const depsChanged = pr.deps_added + pr.deps_updated + pr.deps_removed;
                              const timestamp = pr.merged_at || pr.closed_at || pr.opened_at || pr.created_at;
                              return (
                                <tr key={pr.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-2.5">
                                    <div className="min-w-0">
                                      <div className="flex items-center gap-1.5">
                                        <GitPullRequest className={cn(
                                          'h-3.5 w-3.5 shrink-0',
                                          pr.status === 'merged' ? 'text-purple-400' : pr.status === 'closed' ? 'text-red-400' : 'text-green-400'
                                        )} />
                                        <span className="text-sm font-medium text-foreground truncate">{pr.title || `PR #${pr.pr_number}`}</span>
                                        <span className="text-xs text-foreground-secondary shrink-0">#{pr.pr_number}</span>
                                      </div>
                                      {pr.head_branch && (
                                        <span className="text-[11px] text-foreground-secondary mt-0.5 block truncate">{pr.head_branch}</span>
                                      )}
                                    </div>
                                  </td>
                                  <td className="px-4 py-2.5">
                                    <div className="flex items-center gap-1.5">
                                      {pr.author_avatar_url ? (
                                        <img src={pr.author_avatar_url} alt="" className="h-5 w-5 rounded-full shrink-0" />
                                      ) : (
                                        <div className="h-5 w-5 rounded-full bg-foreground/10 shrink-0" />
                                      )}
                                      <span className="text-xs text-foreground-secondary truncate">{pr.author_login || 'Unknown'}</span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-2.5">
                                    <Badge className={cn('text-[10px]',
                                      pr.status === 'merged' ? 'bg-purple-500/15 text-purple-400 border-purple-500/20' :
                                      pr.status === 'open' ? 'bg-green-500/15 text-green-400 border-green-500/20' :
                                      'bg-zinc-500/15 text-zinc-400 border-zinc-500/20'
                                    )}>
                                      {pr.status === 'merged' ? 'Merged' : pr.status === 'open' ? 'Open' : 'Closed'}
                                    </Badge>
                                  </td>
                                  <td className="px-4 py-2.5">
                                    {pr.check_result ? (
                                      <Badge className={cn('text-[10px]',
                                        pr.check_result === 'passed' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                                        pr.check_result === 'failed' ? 'bg-red-500/15 text-red-400 border-red-500/20' :
                                        pr.check_result === 'pending' ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/20' :
                                        'bg-zinc-500/15 text-zinc-400 border-zinc-500/20'
                                      )}>
                                        {pr.check_result === 'passed' ? 'Passed' :
                                         pr.check_result === 'failed' ? 'Failed' :
                                         pr.check_result === 'pending' ? 'Pending' : 'Skipped'}
                                      </Badge>
                                    ) : (
                                      <span className="text-xs text-foreground-secondary">—</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-2.5 text-right">
                                    {depsChanged > 0 ? (
                                      <span className="text-xs text-foreground-secondary">{depsChanged} changed</span>
                                    ) : (
                                      <span className="text-xs text-foreground-secondary">—</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-2.5 text-right">
                                    <span className="text-xs text-foreground-secondary">{formatTimeAgo(timestamp)}</span>
                                  </td>
                                  <td className="px-4 py-2.5 text-right">
                                    {pr.provider_url && (
                                      <a href={pr.provider_url} target="_blank" rel="noopener noreferrer" className="text-foreground-secondary hover:text-foreground transition-colors">
                                        <ExternalLink className="h-3.5 w-3.5" />
                                      </a>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>

                      {/* Pagination */}
                      {prTotalPages > 1 && (
                        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
                          <span className="text-xs text-foreground-secondary">
                            Page {prPage} of {prTotalPages} ({prTotal} total)
                          </span>
                          <div className="flex items-center gap-1.5">
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs px-2"
                              disabled={prPage <= 1}
                              onClick={() => setPrPage((p) => Math.max(1, p - 1))}
                            >
                              <ChevronLeft className="h-3.5 w-3.5 mr-0.5" />
                              Prev
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs px-2"
                              disabled={prPage >= prTotalPages}
                              onClick={() => setPrPage((p) => p + 1)}
                            >
                              Next
                              <ChevronRight className="h-3.5 w-3.5 ml-0.5" />
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* ── Commits ── */}
              {updatesSubTab === 'commits' && (
                <div className="space-y-4">
                  {/* Filters */}
                  <div className="flex flex-wrap items-center gap-2">
                    {(['all', 'COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN'] as const).map((status) => (
                      <Button
                        key={status}
                        variant={commitsComplianceFilter === status ? 'default' : 'outline'}
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => { setCommitsComplianceFilter(status); setCommitsPage(1); }}
                      >
                        {status === 'all' ? 'All' : status === 'COMPLIANT' ? 'Compliant' : status === 'NON_COMPLIANT' ? 'Non-Compliant' : 'Unknown'}
                      </Button>
                    ))}
                    <div className="flex-1 max-w-xs">
                      <Input
                        placeholder="Search by message or author..."
                        value={commitsSearch}
                        onChange={(e) => { setCommitsSearch(e.target.value); setCommitsPage(1); }}
                        className="h-8 text-xs"
                      />
                    </div>
                  </div>

                  {/* Table */}
                  {commitsLoading ? (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="divide-y divide-border">
                        {[1, 2, 3, 4, 5].map((i) => (
                          <div key={i} className="flex items-center gap-4 px-4 py-3">
                            <div className="h-4 w-4 bg-muted rounded animate-pulse" />
                            <div className="flex-1 space-y-1.5">
                              <div className="h-4 w-3/5 bg-muted rounded animate-pulse" />
                              <div className="h-3 w-1/4 bg-muted rounded animate-pulse" />
                            </div>
                            <div className="h-5 w-16 bg-muted rounded-full animate-pulse" />
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : commits.length === 0 ? (
                    <div className="bg-background-card border border-border rounded-lg p-8 text-center">
                      <GitCommitHorizontal className="h-10 w-10 text-foreground-secondary mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-foreground mb-1">No commits recorded yet.</h3>
                      <p className="text-sm text-foreground-secondary">
                        Commits will appear here once webhooks deliver push events.
                      </p>
                    </div>
                  ) : (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full">
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Commit</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[14%]">Author</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Compliance</th>
                              <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[8%]">Manifest</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Extraction</th>
                              <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[10%]">Time</th>
                              <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[4%]"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {commits.map((commit) => {
                              const firstLine = (commit.message || '').split('\n')[0];
                              const truncatedMsg = firstLine.length > 72 ? firstLine.slice(0, 72) + '...' : firstLine;
                              return (
                                <tr key={commit.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-2.5">
                                    <div className="min-w-0">
                                      <div className="flex items-center gap-1.5">
                                        <GitCommitHorizontal className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />
                                        <span className="text-sm font-medium text-foreground truncate">{truncatedMsg || 'No message'}</span>
                                      </div>
                                      <span className="text-[11px] text-foreground-secondary font-mono mt-0.5 block">{commit.sha.slice(0, 7)}</span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-2.5">
                                    <div className="flex items-center gap-1.5">
                                      {commit.author_avatar_url ? (
                                        <img src={commit.author_avatar_url} alt="" className="h-5 w-5 rounded-full shrink-0" />
                                      ) : (
                                        <div className="h-5 w-5 rounded-full bg-foreground/10 shrink-0" />
                                      )}
                                      <span className="text-xs text-foreground-secondary truncate">{commit.author_name || 'Unknown'}</span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-2.5">
                                    <Badge className={cn('text-[10px]',
                                      commit.compliance_status === 'COMPLIANT' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                                      commit.compliance_status === 'NON_COMPLIANT' ? 'bg-red-500/15 text-red-400 border-red-500/20' :
                                      'bg-zinc-500/15 text-zinc-400 border-zinc-500/20'
                                    )}>
                                      {commit.compliance_status === 'COMPLIANT' ? 'Compliant' :
                                       commit.compliance_status === 'NON_COMPLIANT' ? 'Non-Compliant' : 'Unknown'}
                                    </Badge>
                                  </td>
                                  <td className="px-4 py-2.5 text-center">
                                    {commit.manifest_changed ? (
                                      <FileCode2 className="h-4 w-4 text-yellow-400 mx-auto" />
                                    ) : (
                                      <span className="text-xs text-foreground-secondary">—</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-2.5">
                                    {commit.extraction_triggered ? (
                                      <Badge className={cn('text-[10px]',
                                        commit.extraction_status === 'completed' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                                        commit.extraction_status === 'processing' ? 'bg-blue-500/15 text-blue-400 border-blue-500/20' :
                                        commit.extraction_status === 'failed' ? 'bg-red-500/15 text-red-400 border-red-500/20' :
                                        'bg-zinc-500/15 text-zinc-400 border-zinc-500/20'
                                      )}>
                                        {commit.extraction_status === 'completed' ? 'Completed' :
                                         commit.extraction_status === 'processing' ? 'Running' :
                                         commit.extraction_status === 'failed' ? 'Failed' :
                                         commit.extraction_status || 'Queued'}
                                      </Badge>
                                    ) : (
                                      <span className="text-xs text-foreground-secondary">—</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-2.5 text-right">
                                    <span className="text-xs text-foreground-secondary">{formatTimeAgo(commit.committed_at || commit.created_at)}</span>
                                  </td>
                                  <td className="px-4 py-2.5 text-right">
                                    {commit.provider_url && (
                                      <a href={commit.provider_url} target="_blank" rel="noopener noreferrer" className="text-foreground-secondary hover:text-foreground transition-colors">
                                        <ExternalLink className="h-3.5 w-3.5" />
                                      </a>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>

                      {/* Pagination */}
                      {commitsTotalPages > 1 && (
                        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
                          <span className="text-xs text-foreground-secondary">
                            Page {commitsPage} of {commitsTotalPages} ({commitsTotal} total)
                          </span>
                          <div className="flex items-center gap-1.5">
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs px-2"
                              disabled={commitsPage <= 1}
                              onClick={() => setCommitsPage((p) => Math.max(1, p - 1))}
                            >
                              <ChevronLeft className="h-3.5 w-3.5 mr-0.5" />
                              Prev
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs px-2"
                              disabled={commitsPage >= commitsTotalPages}
                              onClick={() => setCommitsPage((p) => p + 1)}
                            >
                              Next
                              <ChevronRight className="h-3.5 w-3.5 ml-0.5" />
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
                </>
              )}
            </div>
          )}

          {/* ─── EXPORT LEGAL NOTICE SECTION ─── */}
          {activeSection === 'export-notice' && (
            <div className="space-y-6">
              <h1 className="text-2xl font-bold text-foreground">Export Legal Notice</h1>
              <p className="text-sm text-foreground-secondary">
                Download a third-party notices file (THIRD-PARTY-NOTICES.txt) generated from your project&apos;s dependencies and license obligations.
              </p>
              <div className="bg-background-card border border-border rounded-lg p-6">
                {isExtracting ? (
                  <div className="flex items-center gap-4">
                    <div className="flex-1 space-y-2 min-w-0">
                      <h3 className="text-sm font-semibold text-foreground">Project extraction still in progress</h3>
                      <p className="text-sm text-foreground-secondary">
                        Export will be available once extraction completes.
                      </p>
                    </div>
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                      <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
                    </div>
                  </div>
                ) : noExtraction ? (
                  <div className="text-center py-4">
                    <FileText className="h-10 w-10 text-foreground-secondary mx-auto mb-3" />
                    <p className="text-sm text-foreground-secondary">Run an extraction first to generate a legal notice.</p>
                  </div>
                ) : (
                  <Button
                    onClick={handleExportNotice}
                    disabled={!!exporting}
                    className="gap-2"
                  >
                    {exporting === 'notice' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Scale className="h-4 w-4" />}
                    {exporting === 'notice' ? 'Downloading...' : 'Download Legal Notice'}
                  </Button>
                )}
              </div>
            </div>
          )}

          {/* ─── EXPORT SBOM SECTION ─── */}
          {activeSection === 'export-sbom' && (
            <div className="space-y-6">
              <h1 className="text-2xl font-bold text-foreground">Export SBOM</h1>
              <p className="text-sm text-foreground-secondary">
                Download a CycloneDX Software Bill of Materials (JSON) for this project.
              </p>
              <div className="bg-background-card border border-border rounded-lg p-6">
                {isExtracting ? (
                  <div className="flex items-center gap-4">
                    <div className="flex-1 space-y-2 min-w-0">
                      <h3 className="text-sm font-semibold text-foreground">Project extraction still in progress</h3>
                      <p className="text-sm text-foreground-secondary">
                        Export will be available once extraction completes.
                      </p>
                    </div>
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                      <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
                    </div>
                  </div>
                ) : noExtraction ? (
                  <div className="text-center py-4">
                    <FileText className="h-10 w-10 text-foreground-secondary mx-auto mb-3" />
                    <p className="text-sm text-foreground-secondary">Run an extraction first to generate an SBOM.</p>
                  </div>
                ) : (
                  <Button
                    onClick={handleExportSBOM}
                    disabled={!!exporting}
                    variant="outline"
                    className="gap-2"
                  >
                    {exporting === 'sbom' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                    {exporting === 'sbom' ? 'Downloading...' : 'Download SBOM (CycloneDX)'}
                  </Button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>

      {/* Preflight Sidebar */}
      {showPreflight && (
        <PreflightSidebar
          open={showPreflight}
          onClose={() => setShowPreflight(false)}
          organizationId={organizationId}
          projectId={projectId!}
          projectEcosystems={projectEcosystems}
        />
      )}

      {/* Exception Diff Dialog */}
      {diffDialog?.open && (
        <ExceptionDiffDialog
          open={diffDialog.open}
          onClose={() => setDiffDialog(null)}
          onConfirm={handleConfirmException}
          originalCode={diffDialog.originalCode}
          proposedCode={diffDialog.proposedCode}
          packageName={diffDialog.packageName}
          confirming={confirming}
        />
      )}

      <Toaster position="bottom-right" />
    </>
  );
}
