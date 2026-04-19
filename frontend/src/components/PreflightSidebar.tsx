import { useState, useEffect, useCallback } from 'react';
import {
  CheckCircle2,
  XCircle,
  Package,
  Download,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { api, RegistrySearchResult } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { cn } from '../lib/utils';

/** Ecosystem to icon path; fallback to null (use Package icon). */
export const ECOSYSTEM_ICON: Record<string, string> = {
  npm: '/images/npm_icon.png',
  pypi: '/images/frameworks/python.png',
  maven: '/images/frameworks/java.png',
  golang: '/images/frameworks/go.png',
  cargo: '/images/frameworks/rust.png',
  gem: '/images/frameworks/ruby.png',
  composer: '/images/frameworks/php.png',
};

export function getEcosystemIcon(ecosystem: string | null | undefined): string | null {
  if (!ecosystem) return null;
  return ECOSYSTEM_ICON[ecosystem.toLowerCase()] ?? null;
}

/** All ecosystems supported for preflight / Check a package (order + display label). */
export const ALL_ECOSYSTEMS: { id: string; label: string }[] = [
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

export function PreflightSidebar({
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

              <Button
                variant="ghost"
                size="sm"
                className="text-xs text-foreground-secondary"
                onClick={() => setCheckResult(null)}
              >
                ← Back to search
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
