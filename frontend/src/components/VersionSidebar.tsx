import { useState, useEffect } from 'react';
import {
  CheckCircle,
  AlertCircle,
  Tag,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ExternalLink,
  GitPullRequest,
  Eye,
} from 'lucide-react';
import { Button } from './ui/button';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import {
  api,
  DependencyVersionsResponse,
  DependencyVersionItem,
  WatchtowerPRItem,
} from '../lib/api';
import { useToast } from '../hooks/use-toast';

interface VersionSidebarProps {
  packageName: string;
  currentVersion: string;
  organizationId: string;
  projectId: string;
  dependencyId: string;
  /** Version strings that are currently in quarantine (for "In quarantine" badge). */
  versionsInQuarantine?: string[];
  onClose: () => void;
  /** When 'supply-chain', card footer shows only Preview (no Create/View PR). */
  variant?: 'watchtower' | 'supply-chain';
  /** Called when user clicks Preview in supply-chain variant. */
  onPreviewVersion?: (version: string) => void;
  /** When true, show Watchtower checks (Registry, Install scripts, Entropy). Only set when package is on org's watchtower. */
  onWatchtower?: boolean;
}

const OSV_BASE = 'https://osv.dev/vulnerability/';
const GHSA_BASE = 'https://github.com/advisories/';
/** Link to GitHub Advisory for GHSA ids, else OSV. */
function getVulnUrl(id: string): string {
  return id.startsWith('GHSA-') ? `${GHSA_BASE}${id}` : `${OSV_BASE}${id}`;
}

/** Compare semver-style versions: -1 if a < b, 0 if equal, 1 if a > b. Ensures 5.10.0 > 5.9.0. */
function compareVersions(a: string, b: string): number {
  const parse = (v: string) =>
    v
      .replace(/^v/, '')
      .split('.')
      .map((p) => parseInt(p, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  const maxLen = Math.max(pa.length, pb.length);
  for (let i = 0; i < maxLen; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

function WatchtowerStatusIcon({
  status,
  reason,
  label,
}: {
  status: string | null;
  reason: string | null;
  label: string;
}) {
  const content = reason ? `${label}: ${reason}` : label;
  const icon =
    status === 'pass' ? (
      <span className="text-success">
        <CheckCircle2 className="h-3.5 w-3.5" />
      </span>
    ) : status === 'warning' ? (
      <span className="text-warning">
        <AlertTriangle className="h-3.5 w-3.5" />
      </span>
    ) : status === 'fail' ? (
      <span className="text-destructive">
        <XCircle className="h-3.5 w-3.5" />
      </span>
    ) : (
      <span className="text-foreground-secondary">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      </span>
    );
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex cursor-default">{icon}</span>
      </TooltipTrigger>
      <TooltipContent>{content}</TooltipContent>
    </Tooltip>
  );
}

function VersionCardSkeleton() {
  return (
    <li className="rounded-lg border border-border bg-background-card px-4 pt-3 pb-0 text-sm space-y-3 animate-pulse">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <div className="h-4 w-4 rounded bg-muted shrink-0" />
          <div className="h-4 w-20 bg-muted rounded" />
          <div className="h-5 w-14 bg-muted rounded" />
        </div>
      </div>
      <div>
        <div className="flex items-center gap-1.5">
          <div className="h-4 w-4 rounded bg-muted shrink-0" />
          <div className="h-3 w-28 bg-muted rounded" />
        </div>
      </div>
      <div className="flex items-center gap-3">
        <div className="h-3 w-12 bg-muted rounded" />
        <div className="flex gap-2">
          <div className="h-3.5 w-3.5 rounded-full bg-muted" />
          <div className="h-3.5 w-3.5 rounded-full bg-muted" />
          <div className="h-3.5 w-3.5 rounded-full bg-muted" />
        </div>
      </div>
      <div className="mt-3 -mx-4 px-4 py-2 border-t border-border bg-[#141618] rounded-b-lg">
        <div className="h-7 w-24 bg-muted rounded" />
      </div>
    </li>
  );
}

export function VersionSidebar({
  packageName,
  currentVersion,
  organizationId,
  projectId,
  dependencyId,
  versionsInQuarantine = [],
  onClose,
  variant = 'watchtower',
  onPreviewVersion,
  onWatchtower = false,
}: VersionSidebarProps) {
  const [data, setData] = useState<DependencyVersionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creatingForVersion, setCreatingForVersion] = useState<string | null>(null);
  const { toast } = useToast();

  const fetchVersions = () => {
    if (!organizationId || !projectId || !dependencyId) return;
    setLoading(true);
    setError(null);
    api
      .getDependencyVersions(organizationId, projectId, dependencyId)
      .then((res) => setData(res))
      .catch((err) => setError(err.message ?? 'Failed to load versions'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (!organizationId || !projectId || !dependencyId) {
      setLoading(false);
      return;
    }
    fetchVersions();
  }, [organizationId, projectId, dependencyId]);

  const prForVersion = (version: string, prs: WatchtowerPRItem[]) =>
    prs.find((p) => p.target_version === version);

  const handleCreatePR = async (version: string) => {
    setCreatingForVersion(version);
    try {
      const result = await api.createWatchtowerBumpPR(
        organizationId,
        projectId,
        dependencyId,
        version
      );
      toast({
        title: result.already_exists ? 'PR already exists' : 'Pull request created',
        description: result.already_exists
          ? 'Opening existing bump PR.'
          : 'Open the PR to review and merge the version bump.',
      });
      window.open(result.pr_url, '_blank');
      fetchVersions();
    } catch (err: unknown) {
      toast({
        title: 'Failed to create PR',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setCreatingForVersion(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden
      />
      <div
        className="fixed right-0 top-0 h-full w-full max-w-xl bg-background border-l border-border shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
          <h2 className="text-lg font-semibold text-foreground">Versions</h2>
        </div>
        <div className="flex-1 overflow-y-auto px-6 pt-4 pb-6">
          {loading && (
            <ul className="space-y-2">
              {[1, 2, 3, 4, 5].map((i) => (
                <VersionCardSkeleton key={i} />
              ))}
            </ul>
          )}
          {error && (
            <p className="text-sm text-destructive py-4">{error}</p>
          )}
          {!loading && !error && data && (
            <ul className="space-y-3">
              {[...data.versions]
                .sort((a, b) => compareVersions(b.version, a.version))
                .map((item: DependencyVersionItem) => {
                const isCurrent = item.version === data.currentVersion;
                const isLatest = item.version === data.latestVersion;
                const totalVulnCount =
                  (item.totalVulnCount ?? (item.vulnCount ?? 0) + (item.transitiveVulnCount ?? 0));
                const noVulns = totalVulnCount === 0;
                const checksAllPass =
                  (item.registry_integrity_status === 'pass' || item.registry_integrity_status == null) &&
                  (item.install_scripts_status === 'pass' || item.install_scripts_status == null) &&
                  (item.entropy_analysis_status === 'pass' || item.entropy_analysis_status == null);
                const noSecurityIssues = noVulns && checksAllPass;
                const pr = prForVersion(item.version, data.prs ?? []);
                const isBanned = (data.bannedVersions ?? []).includes(item.version);

                return (
                  <li
                    key={item.version}
                    className="rounded-lg border border-border bg-background-card px-4 pt-3 pb-0 text-sm space-y-3"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2 min-w-0">
                        <Tag className="h-4 w-4 text-foreground-secondary shrink-0" />
                        <span className="font-mono text-foreground truncate">{item.version}</span>
                        {isCurrent && (
                          <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-success/10 text-success border border-success/20">
                            Current
                          </span>
                        )}
                        {isLatest && !isCurrent && (
                          <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-transparent text-foreground-secondary border border-border">
                            Latest
                          </span>
                        )}
                        {versionsInQuarantine.includes(item.version) && (
                          <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30">
                            In quarantine
                          </span>
                        )}
                        {(data.bannedVersions ?? []).includes(item.version) && (
                          <span className="shrink-0 text-xs px-1.5 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/30">
                            Banned
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Vulnerabilities & security summary */}
                    <div>
                      {noSecurityIssues ? (
                        <div className="flex items-center gap-1.5">
                          <CheckCircle className="h-4 w-4 text-success shrink-0" />
                          <span className="text-xs text-success">No security issues</span>
                        </div>
                      ) : !noVulns ? (
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-1.5">
                            <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
                            <span className="text-xs text-destructive">
                              {totalVulnCount} {totalVulnCount === 1 ? 'vulnerability' : 'vulnerabilities'}
                              {(item.vulnCount != null || (item.transitiveVulnCount ?? 0) > 0) &&
                                (item.vulnCount ?? 0) + (item.transitiveVulnCount ?? 0) > 0 && (
                                  <span className="text-foreground-secondary font-normal">
                                    {' '}
                                    ({(item.vulnCount ?? 0)} direct + {(item.transitiveVulnCount ?? 0)} transitive)
                                  </span>
                                )}
                            </span>
                          </div>
                          {item.vulnerabilities && item.vulnerabilities.length > 0 && (
                            <>
                              <span className="text-xs font-medium text-foreground-secondary block">
                                In this package
                              </span>
                              <ul className="pl-5 space-y-2">
                                {item.vulnerabilities.slice(0, 5).map((v) => {
                                  const alias = (v.aliases && v.aliases[0]) || v.osv_id;
                                  const severityClass =
                                    v.severity === 'critical'
                                      ? 'bg-destructive/10 text-destructive border-destructive/20'
                                      : v.severity === 'high'
                                        ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20'
                                        : v.severity === 'medium'
                                          ? 'bg-warning/10 text-warning border-warning/20'
                                          : 'bg-foreground-secondary/10 text-foreground-secondary border-border';
                                  return (
                                    <li
                                      key={v.osv_id}
                                      className="rounded-md border border-border bg-background-card px-3 py-2 text-xs"
                                    >
                                      <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                                        <span className="font-mono text-foreground font-medium truncate max-w-[200px]">
                                          {alias}
                                        </span>
                                        <span
                                          className={`shrink-0 px-1.5 py-0.5 rounded border text-[10px] font-medium capitalize ${severityClass}`}
                                        >
                                          {v.severity}
                                        </span>
                                      </div>
                                      {v.summary && (
                                        <p className="text-foreground-secondary leading-relaxed mb-2 line-clamp-2">
                                          {v.summary}
                                        </p>
                                      )}
                                      <a
                                        href={getVulnUrl(v.osv_id)}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="inline-flex items-center gap-1 text-foreground-secondary hover:text-foreground hover:underline"
                                      >
                                        <ExternalLink className="h-3 w-3" />
                                        {v.osv_id.startsWith('GHSA-') ? 'View on GitHub Advisory' : 'View on OSV'}
                                      </a>
                                    </li>
                                  );
                                })}
                                {item.vulnerabilities.length > 5 && (
                                  <li className="text-foreground-secondary text-xs pl-1">
                                    +{item.vulnerabilities.length - 5} more
                                  </li>
                                )}
                              </ul>
                            </>
                          )}
                          {item.transitiveVulnerabilities && item.transitiveVulnerabilities.length > 0 && (
                            <>
                              <span className="text-xs font-medium text-foreground-secondary block">
                                In dependencies ({item.transitiveVulnCount ?? item.transitiveVulnerabilities.length}{' '}
                                {item.transitiveVulnCount === 1 ? 'vulnerability' : 'vulnerabilities'})
                              </span>
                              <ul className="pl-5 space-y-2">
                                {item.transitiveVulnerabilities.slice(0, 5).map((v) => {
                                  const alias = (v.aliases && v.aliases[0]) || v.osv_id;
                                  const severityClass =
                                    v.severity === 'critical'
                                      ? 'bg-destructive/10 text-destructive border-destructive/20'
                                      : v.severity === 'high'
                                        ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20'
                                        : v.severity === 'medium'
                                          ? 'bg-warning/10 text-warning border-warning/20'
                                          : 'bg-foreground-secondary/10 text-foreground-secondary border-border';
                                  return (
                                    <li
                                      key={v.osv_id}
                                      className="rounded-md border border-border bg-background-card px-3 py-2 text-xs"
                                    >
                                      <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                                        <span className="font-mono text-foreground font-medium truncate max-w-[200px]">
                                          {alias}
                                        </span>
                                        <span
                                          className={`shrink-0 px-1.5 py-0.5 rounded border text-[10px] font-medium capitalize ${severityClass}`}
                                        >
                                          {v.severity}
                                        </span>
                                      </div>
                                      {v.summary && (
                                        <p className="text-foreground-secondary leading-relaxed mb-2 line-clamp-2">
                                          {v.summary}
                                        </p>
                                      )}
                                      <a
                                        href={getVulnUrl(v.osv_id)}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="inline-flex items-center gap-1 text-foreground-secondary hover:text-foreground hover:underline"
                                      >
                                        <ExternalLink className="h-3 w-3" />
                                        {v.osv_id.startsWith('GHSA-') ? 'View on GitHub Advisory' : 'View on OSV'}
                                      </a>
                                    </li>
                                  );
                                })}
                                {item.transitiveVulnerabilities.length > 5 && (
                                  <li className="text-foreground-secondary text-xs pl-1">
                                    +{item.transitiveVulnerabilities.length - 5} more
                                  </li>
                                )}
                              </ul>
                            </>
                          )}
                        </div>
                      ) : null}
                    </div>

                    {/* Watchtower checks — only when package is on org's watchtower */}
                    {onWatchtower && (
                      <div className="flex items-center gap-3 text-foreground-secondary">
                        <span className="text-xs font-medium text-foreground-secondary">Checks:</span>
                        <div className="flex items-center gap-2">
                          <WatchtowerStatusIcon
                            status={item.registry_integrity_status}
                            reason={item.registry_integrity_reason}
                            label="Registry"
                          />
                          <span className="text-xs sr-only">Registry</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <WatchtowerStatusIcon
                            status={item.install_scripts_status}
                            reason={item.install_scripts_reason}
                            label="Install scripts"
                          />
                          <span className="text-xs sr-only">Install</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <WatchtowerStatusIcon
                            status={item.entropy_analysis_status}
                            reason={item.entropy_analysis_reason}
                            label="Entropy"
                          />
                          <span className="text-xs sr-only">Entropy</span>
                        </div>
                      </div>
                    )}

                    {/* PR action (watchtower) or Preview (supply-chain) — full-width bottom strip */}
                    <div className="mt-3 -mx-4 px-4 py-2 border-t border-border bg-[#141618] rounded-b-lg">
                      {variant === 'supply-chain' ? (
                        isCurrent ? (
                          <span className="text-xs text-foreground-secondary">Current version</span>
                        ) : isBanned ? (
                          <span className="text-xs text-foreground-secondary">Banned</span>
                        ) : onPreviewVersion ? (
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs gap-1"
                            onClick={() => onPreviewVersion(item.version)}
                          >
                            <Eye className="h-3.5 w-3.5" />
                            Preview
                          </Button>
                        ) : null
                      ) : isCurrent ? (
                        <span className="text-xs text-foreground-secondary">Current version — no PR</span>
                      ) : isBanned ? (
                        <span className="text-xs text-foreground-secondary">Banned — no PR</span>
                      ) : pr ? (
                        <a
                          href={pr.pr_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground hover:underline"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                          View PR #{pr.pr_number}
                        </a>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs gap-1"
                          disabled={!!creatingForVersion}
                          onClick={() => handleCreatePR(item.version)}
                        >
                          {creatingForVersion === item.version ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <GitPullRequest className="h-3.5 w-3.5" />
                          )}
                          Create PR
                        </Button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
