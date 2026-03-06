import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
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
  Scale,
  ExternalLink,
  ChevronLeft,
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

const VALID_SECTIONS: ComplianceSection[] = ['project', 'export-notice', 'export-sbom'];
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

/** Ecosystem to icon path for compliance table and Check a package dropdown; fallback to null (use Package icon). */
const ECOSYSTEM_ICON: Record<string, string> = {
  npm: '/images/npm_icon.png',
  pypi: '/images/frameworks/python.png',
  maven: '/images/frameworks/java.png',
  golang: '/images/frameworks/go.png',
  cargo: '/images/frameworks/rust.png',
  gem: '/images/frameworks/ruby.png',
  composer: '/images/frameworks/php.png',
};
function getEcosystemIcon(ecosystem: string | null | undefined): string | null {
  if (!ecosystem) return null;
  return ECOSYSTEM_ICON[ecosystem.toLowerCase()] ?? null;
}

/** All ecosystems supported for preflight / Check a package (order + display label). */
const ALL_ECOSYSTEMS: { id: string; label: string }[] = [
  { id: 'npm', label: 'npm' },
  { id: 'pypi', label: 'PyPI' },
  { id: 'maven', label: 'Maven' },
  { id: 'golang', label: 'Go' },
  { id: 'cargo', label: 'Cargo' },
  { id: 'gem', label: 'RubyGems' },
  { id: 'composer', label: 'Composer' },
  { id: 'nuget', label: 'NuGet' },
  { id: 'pub', label: 'Pub' },
  { id: 'hex', label: 'Hex' },
  { id: 'swift', label: 'Swift' },
];

// ─── Preflight Sidebar ───

function PreflightSidebar({
  open,
  onClose,
  organizationId,
  projectId,
  projectEcosystems,
  initialEcosystem,
}: {
  open: boolean;
  onClose: () => void;
  organizationId: string;
  projectId: string;
  projectEcosystems: string[];
  initialEcosystem?: string | null;
}) {
  const [panelVisible, setPanelVisible] = useState(false);
  const [ecosystem, setEcosystem] = useState(initialEcosystem ?? projectEcosystems[0] ?? 'npm');

  useEffect(() => {
    if (open && initialEcosystem) setEcosystem(initialEcosystem);
  }, [open, initialEcosystem]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<RegistrySearchResult[]>([]);
  const [searchMode, setSearchMode] = useState<'search' | 'exact'>('search');
  const [searchError, setSearchError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkingPackageKey, setCheckingPackageKey] = useState<string | null>(null);
  const [checkResult, setCheckResult] = useState<{
    allowed: boolean;
    reasons: string[];
    tierName: string;
    packageInfo: RegistrySearchResult;
    license?: string | null;
    dependencyScore?: number | null;
    openSsfScore?: number | null;
    slsaLevel?: number | null;
  } | null>(null);
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
      setHasSearched(true);
    }
  }, [organizationId, projectId, ecosystem, searchQuery]);

  const handleCheck = useCallback(async (pkg: RegistrySearchResult) => {
    const key = `${pkg.name}@${pkg.version ?? ''}`;
    setChecking(true);
    setCheckingPackageKey(key);
    try {
      const result = await api.preflightCheck(organizationId, projectId, pkg.name, pkg.version || undefined, ecosystem);
      setCheckResult({
        allowed: result.allowed,
        reasons: result.reasons,
        tierName: result.tierName,
        packageInfo: pkg,
        license: result.license,
        dependencyScore: result.dependencyScore,
        openSsfScore: result.openSsfScore,
        slsaLevel: result.slsaLevel,
      });
    } catch (err: any) {
      toast({ title: 'Preflight check failed', description: err.message, variant: 'destructive' });
    } finally {
      setChecking(false);
      setCheckingPackageKey(null);
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
        <div className="px-6 pt-5 pb-3 flex-shrink-0 flex items-center gap-3">
          <div className="shrink-0 flex items-center justify-center">
            {getEcosystemIcon(ecosystem) ? (
              <img src={getEcosystemIcon(ecosystem)!} alt="" className="h-6 w-6 object-contain" aria-hidden />
            ) : (
              <Package className="h-6 w-6 text-foreground-secondary" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-xl font-semibold text-foreground">Preflight Check</h2>
            <p className="text-sm text-foreground-secondary mt-1">Test if adding a package would affect compliance</p>
          </div>
        </div>

        <div className="flex-1 flex flex-col min-h-0 px-6 pt-4 pb-0">
          {!checkResult ? (
            <div className="flex flex-col min-h-0 flex-1">
              <div className="flex-shrink-0 mb-4">
                <Input
                  placeholder={isExactLookup ? 'Package name' : 'Search packages...'}
                  value={searchQuery}
                  onChange={(e) => { setSearchQuery(e.target.value); setHasSearched(false); }}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleSearch(); } }}
                  className="h-9"
                />
              </div>

              {searchError && (
                <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 border border-destructive/20 rounded-lg px-3 py-2 flex-shrink-0 mb-4">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  {searchError}
                </div>
              )}

              {searching && (
                <div className="flex flex-col min-h-0 flex-1 mt-2 space-y-1.5">
                  {[1, 2, 3, 4, 5, 6].map((i) => (
                    <div key={i} className="bg-background-card border border-border rounded-lg p-3 animate-pulse">
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0 flex-1 space-y-2">
                          <div className="flex items-center gap-2">
                            <div className="h-4 rounded w-24 bg-foreground/15" />
                            <div className="h-4 rounded w-12 bg-foreground/10" />
                          </div>
                          <div className="h-3 rounded w-full max-w-[280px] bg-foreground/10" />
                          <div className="flex items-center gap-2">
                            <div className="h-3 rounded w-14 bg-foreground/10" />
                            <div className="h-3 rounded w-20 bg-foreground/10" />
                          </div>
                        </div>
                        <div className="h-7 w-14 shrink-0 rounded bg-foreground/10" />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {!searching && searchResults.length > 0 && (
                <div className="flex flex-col min-h-0 flex-1 mt-2">
                  <p className="text-xs text-foreground-secondary flex-shrink-0 mb-2">{searchResults.length} result{searchResults.length !== 1 ? 's' : ''}</p>
                  <div className="space-y-1.5 flex-1 min-h-0 overflow-y-auto custom-scrollbar">
                    {searchResults.map((pkg, i) => {
                      const packageKey = `${pkg.name}@${pkg.version ?? ''}`;
                      const isCheckingThis = checkingPackageKey === packageKey;
                      return (
                        <div key={`${pkg.name}-${i}`} className="bg-background-card border border-border rounded-lg p-3 hover:border-foreground/20 transition-colors">
                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium text-foreground truncate">{pkg.name}</span>
                                {pkg.version && (
                                  <span className="text-[10px] shrink-0 px-1.5 py-0.5 rounded border border-border bg-transparent text-foreground-secondary">
                                    {pkg.version}
                                  </span>
                                )}
                              </div>
                              {pkg.description && (
                                <p className="text-xs text-foreground-secondary mt-1 line-clamp-2">{pkg.description}</p>
                              )}
                              <div className="flex items-center gap-3 mt-1.5 text-xs text-foreground-secondary">
                                {pkg.license && <span>{pkg.license}</span>}
                                {pkg.downloads != null && (
                                  <span className="flex items-center gap-1">
                                    <Download className="h-3 w-3 shrink-0" />
                                    {pkg.downloads.toLocaleString()} downloads
                                  </span>
                                )}
                              </div>
                            </div>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-xs shrink-0"
                              onClick={() => handleCheck(pkg)}
                              disabled={isCheckingThis}
                            >
                              {isCheckingThis ? <Loader2 className="h-3 w-3 animate-spin" /> : 'Check'}
                            </Button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {hasSearched && !searching && searchResults.length === 0 && !searchError && (
                <p className="text-sm text-foreground-secondary text-center py-4 flex-shrink-0">No results found</p>
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
                <div className="flex items-center gap-2">
                  {checkResult.allowed ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-400 shrink-0" />
                  )}
                  <span className={cn('text-lg font-semibold', checkResult.allowed ? 'text-emerald-400' : 'text-red-400')}>
                    {checkResult.allowed ? 'Allowed' : 'Blocked'}
                  </span>
                </div>
                {!checkResult.allowed && checkResult.reasons.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {checkResult.reasons.map((reason, i) => (
                      <p key={i} className="text-sm text-foreground-secondary">
                        {reason}
                      </p>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-background-card border border-border rounded-lg p-4 space-y-2">
                <h4 className="text-sm font-medium text-foreground">{checkResult.packageInfo.name}</h4>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                  <div>
                    <span className="text-foreground-secondary">Version:</span>{' '}
                    <span className="text-foreground">{checkResult.packageInfo.version}</span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">License:</span>{' '}
                    <span className="text-foreground">{checkResult.license ?? checkResult.packageInfo.license ?? 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">Project tier:</span>{' '}
                    <span className="text-foreground">{checkResult.tierName}</span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">Score:</span>{' '}
                    <span className="text-foreground">
                      {checkResult.dependencyScore != null ? checkResult.dependencyScore : '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">OpenSSF:</span>{' '}
                    <span className="text-foreground">
                      {checkResult.openSsfScore != null ? checkResult.openSsfScore : '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-foreground-secondary">SLSA:</span>{' '}
                    <span className="text-foreground">
                      {checkResult.slsaLevel != null ? `L${checkResult.slsaLevel}` : '—'}
                    </span>
                  </div>
                  {checkResult.packageInfo.downloads != null && (
                    <div className="flex items-center gap-1">
                      <Download className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />
                      <span className="text-foreground-secondary">Downloads:</span>{' '}
                      <span className="text-foreground">{checkResult.packageInfo.downloads.toLocaleString()}</span>
                    </div>
                  )}
                </div>
              </div>
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
  const [directFilter, setDirectFilter] = useState<'all' | 'direct' | 'transitive'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const complianceSearchInputRef = useRef<HTMLInputElement>(null);

  const [dependencies, setDependencies] = useState<ProjectDependency[]>([]);
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [obligations, setObligations] = useState<LicenseObligationGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [reevaluating, setReevaluating] = useState(false);
  const [reevalDisabledUntil, setReevalDisabledUntil] = useState(0);
  const [showPreflight, setShowPreflight] = useState(false);
  const [preflightInitialEcosystem, setPreflightInitialEcosystem] = useState<string | null>(null);
  const [exporting, setExporting] = useState<'sbom' | 'notice' | null>(null);
  const [obligationsOpen, setObligationsOpen] = useState(false);

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
  // Only show "Extraction in progress" when a scan is actively running (not when pending/ready/error/not_connected)
  const EXTRACTING_STATUSES = ['initializing', 'extracting', 'analyzing', 'finalizing'];
  const isExtracting = EXTRACTING_STATUSES.includes(realtime.status);

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
    // Only 'project' is a tab; export-notice and export-sbom are download buttons, so redirect to project
    if (!urlSection || urlSection !== 'project') {
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

  // Compliance score = % of packages that are allowed (policy_result.allowed !== false)
  const complianceScorePct = useMemo(() => {
    if (dependencies.length === 0) return null;
    const allowed = dependencies.filter((d) => d.policy_result?.allowed !== false).length;
    return Math.round((allowed / dependencies.length) * 100);
  }, [dependencies]);

  // Human-readable last scan time (policy evaluation = when we last had a full scan)
  const lastScannedLabel = useMemo(() => {
    if (!policyEvaluatedAt) return 'Never';
    const d = new Date(policyEvaluatedAt);
    const now = new Date();
    const sameDay = d.getDate() === now.getDate() && d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    const isYesterday = d.getDate() === yesterday.getDate() && d.getMonth() === yesterday.getMonth() && d.getFullYear() === yesterday.getFullYear();
    const timeStr = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
    if (sameDay) return `Today, ${timeStr}`;
    if (isYesterday) return `Yesterday, ${timeStr}`;
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }, [policyEvaluatedAt]);
  const statusColor = violatedDeps.length > 0 ? '#ef4444' : '#22c55e';
  const statusViolations = (project as any)?.status_violations as string[] || [];

  // Filtered deps for Policy Results tab
  const filteredPolicyDeps = useMemo(() => {
    let filtered = [...dependencies];

    if (policyResultsTab === 'issues') {
      filtered = filtered.filter((d) => d.policy_result && d.policy_result.allowed === false);
    }

    if (directFilter === 'direct') filtered = filtered.filter((d) => d.is_direct);
    else if (directFilter === 'transitive') filtered = filtered.filter((d) => !d.is_direct);

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter((d) => d.name.toLowerCase().includes(q));
    }

    return filtered;
  }, [dependencies, policyResultsTab, directFilter, searchQuery]);

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

  const noExtraction = dependencies.length === 0;
  const noPolicy = !policies?.effective_policy_code && !policies?.inherited_policy_code;

  // Content-area skeleton matching project compliance layout: score, filters, table
  const contentSkeleton = (
    <div className="px-6 py-6 mx-auto max-w-5xl space-y-8">
      {/* Score + last scanned row */}
      <div className="flex flex-wrap items-center gap-8">
        <div className="flex items-baseline gap-3">
          <div className="h-10 w-20 bg-muted rounded animate-pulse" />
          <div className="h-3 w-24 bg-muted rounded animate-pulse" />
        </div>
        <div className="min-w-0">
          <div className="h-3 w-16 bg-muted rounded animate-pulse mb-1.5" />
          <div className="h-4 w-28 bg-muted rounded animate-pulse" />
        </div>
      </div>
      {/* Search + filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="h-9 w-64 bg-muted rounded-md animate-pulse flex-shrink-0" />
        <div className="h-8 w-20 bg-muted rounded animate-pulse ml-auto" />
      </div>
      {/* Table */}
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <div className="border-b border-border px-4 py-3 flex gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className={cn('h-3 bg-muted rounded animate-pulse', i === 1 ? 'w-32' : 'w-16')} />
          ))}
        </div>
        <div className="divide-y divide-border">
          {[1, 2, 3, 4, 5, 6, 7, 8].map((row) => (
            <div key={row} className="px-4 py-2.5 flex gap-4 items-center">
              <div className="h-4 w-28 bg-muted rounded animate-pulse flex-shrink-0" />
              <div className="h-4 w-14 bg-muted rounded animate-pulse" />
              <div className="h-4 w-8 bg-muted rounded animate-pulse" />
              <div className="h-4 w-8 bg-muted rounded animate-pulse" />
              <div className="h-5 w-16 bg-muted rounded animate-pulse" />
              <div className="h-4 flex-1 max-w-[120px] bg-muted rounded animate-pulse" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // Full-page placeholder only when project not loaded yet
  if (!project) {
    return (
      <div className="min-h-[calc(100vh-3rem)] px-6 py-6">
        <div className="mx-auto max-w-7xl">
          <div className="h-8 w-48 bg-muted rounded animate-pulse mb-6" />
          <div className="h-64 bg-muted rounded-lg animate-pulse" />
        </div>
        <Toaster position="bottom-right" />
      </div>
    );
  }

  return (
    <>
      <div className="flex min-h-[calc(100vh-3rem)] overflow-hidden">
        {/* Sticky compliance sidebar */}
        <ComplianceSidepanel
          activeSection={activeSection}
          onSelect={handleSectionSelect}
          canViewSettings={!!canManageSettings}
          disabledExports={noExtraction || isExtracting}
          onExportNotice={canManageSettings ? handleExportNotice : undefined}
          onExportSBOM={canManageSettings ? handleExportSBOM : undefined}
          exporting={exporting}
        />

        <div className="flex-1 min-w-0 overflow-auto">
          {loading ? (
            contentSkeleton
          ) : error ? (
            <div className="px-6 py-6 mx-auto max-w-5xl">
              <h1 className="text-2xl font-bold text-foreground mb-4">Compliance</h1>
              <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-4 text-sm text-destructive">{error}</div>
            </div>
          ) : (
          <div className="px-6 py-6 mx-auto max-w-5xl">
            {/* ─── PROJECT SECTION ─── */}
            {activeSection === 'project' && (
            <div className="space-y-8">
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
                  {/* Compliance Score — no card */}
                  <div className="flex flex-wrap items-center gap-8">
                    <div className="flex items-baseline gap-3">
                      <span className="text-4xl font-semibold tabular-nums text-foreground">
                        {complianceScorePct != null ? `${complianceScorePct}%` : '—'}
                      </span>
                      <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Compliance score</span>
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm text-foreground-secondary">Last scanned</p>
                      <p className="text-sm text-foreground">{lastScannedLabel}</p>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-8 text-xs ml-auto w-[180px] justify-between"
                        >
                          <Shield className="h-3.5 w-3.5 mr-1.5" />
                          Check a package
                          <ChevronDown className="h-3.5 w-3.5 ml-1 opacity-70" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-[180px]">
                        {ALL_ECOSYSTEMS.map(({ id, label }) => {
                          const icon = getEcosystemIcon(id);
                          return (
                            <DropdownMenuItem
                              key={id}
                              onClick={() => {
                                setPreflightInitialEcosystem(id);
                                setShowPreflight(true);
                              }}
                              className="flex items-center gap-2"
                            >
                              {icon ? (
                                <img src={icon} alt="" className="h-4 w-4 shrink-0 object-contain" aria-hidden />
                              ) : (
                                <Package className="h-4 w-4 shrink-0 text-foreground-secondary" />
                              )}
                              <span>{label}</span>
                            </DropdownMenuItem>
                          );
                        })}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>

                  {/* Issues / All Packages tabs, filters, table */}
                  <div className="space-y-4 mt-8">
                    <div className="border-b border-border">
                      <div className="flex gap-6">
                        <button
                          onClick={() => setPolicyResultsTab('issues')}
                          className={cn(
                            'text-sm font-medium transition-colors pb-3 border-b-2 -mb-px',
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
                            'text-sm font-medium transition-colors pb-3 border-b-2 -mb-px',
                            policyResultsTab === 'all' ? 'text-foreground border-foreground' : 'text-foreground-secondary border-transparent hover:text-foreground'
                          )}
                        >
                          All Packages
                        </button>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <div className="relative max-w-xs w-full sm:w-64 flex-shrink-0">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
                        <input
                          ref={complianceSearchInputRef}
                          type="text"
                          placeholder="Search by package name"
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Escape' && searchQuery) {
                              e.preventDefault();
                              setSearchQuery('');
                              complianceSearchInputRef.current?.blur();
                            }
                          }}
                          className="w-full pl-9 pr-12 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                        />
                        {searchQuery && (
                          <button
                            type="button"
                            onClick={() => { setSearchQuery(''); complianceSearchInputRef.current?.focus(); }}
                            aria-label="Clear search (Esc)"
                            className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                          >
                            Esc
                          </button>
                        )}
                      </div>
                      <div className="flex items-center gap-2 ml-auto">
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
                      </div>
                    </div>

                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="overflow-x-auto">
                        <table className="w-full table-fixed">
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[32%] min-w-[180px]">Package</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">License</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[7%]">Score</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[6%]">SLSA</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[12%]">Status</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[18%]">Reasons</th>
                              <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[13%]"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {filteredPolicyDeps.length === 0 ? (
                              <tr>
                                <td colSpan={7} className="px-4 py-2.5 text-center text-sm text-foreground-secondary">
                                  {policyResultsTab === 'issues' ? 'No policy violations found.' : 'No dependencies to display.'}
                                </td>
                              </tr>
                            ) : (
                              filteredPolicyDeps.map((dep) => {
                                const isAllowed = dep.policy_result?.allowed !== false;
                                const ecosystemIcon = getEcosystemIcon(dep.ecosystem);
                                const score = dep.analysis?.score ?? null;
                                const slsaLevel = dep.slsa_level ?? null;
                                return (
                                  <tr key={dep.id} className="group hover:bg-table-hover transition-colors">
                                    <td className="px-4 py-2.5">
                                      <div className="flex items-center gap-2 min-w-0">
                                        {ecosystemIcon ? (
                                          <img src={ecosystemIcon} alt="" className="h-4 w-4 shrink-0 object-contain" aria-hidden />
                                        ) : (
                                          <Package className="h-4 w-4 text-foreground-secondary shrink-0" />
                                        )}
                                        <span className="text-sm font-medium text-foreground truncate">{dep.name}</span>
                                        {!dep.is_direct && (
                                          <span className="text-[9px] shrink-0 px-1.5 py-0.5 rounded-md border border-border bg-transparent text-foreground-secondary font-medium">transitive</span>
                                        )}
                                      </div>
                                    </td>
                                    <td className="px-4 py-2.5">
                                      <span className="text-sm text-foreground-secondary">{dep.license ?? 'Unknown'}</span>
                                    </td>
                                    <td className="px-4 py-2.5">
                                      <span className="text-sm text-foreground-secondary">
                                        {score != null ? String(score) : '—'}
                                      </span>
                                    </td>
                                    <td className="px-4 py-2.5">
                                      <span className="text-sm text-foreground-secondary">
                                        {slsaLevel != null ? `L${slsaLevel}` : '—'}
                                      </span>
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
                  </div>

                </>
              )}
            </div>
          )}

          </div>
            )}
        </div>
      </div>

      {/* Preflight Sidebar */}
      {showPreflight && (
        <PreflightSidebar
          open={showPreflight}
          onClose={() => { setShowPreflight(false); setPreflightInitialEcosystem(null); }}
          organizationId={organizationId}
          projectId={projectId!}
          projectEcosystems={projectEcosystems}
          initialEcosystem={preflightInitialEcosystem}
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
