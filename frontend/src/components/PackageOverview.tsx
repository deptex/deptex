import { useState, useCallback, useEffect } from 'react';
import {
  Scale,
  Download,
  ExternalLink,
  CheckCircle,
  AlertCircle,
  XCircle,
  Clock,
  Info,
  FileCode,
  GitFork,
  Github,
  Loader2,
  RefreshCw,
  Wand2,
  Building2,
  Ghost,
  GitPullRequest,
  AlertTriangle,
  Ban,
  Sparkles,
  ArrowUpCircle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import { ProjectDependency, ProjectEffectivePolicies, api, type LatestSafeVersionResponse } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { isLicenseAllowed, getComplianceStatus, getIssueLabel } from '../lib/compliance-utils';

import { ScoreBreakdownSidebar } from './ScoreBreakdownSidebar';
import { DeprecateSidebar } from './DeprecateSidebar';

interface PackageOverviewProps {
  dependency: ProjectDependency;
  organizationId: string;
  projectId: string;
  /** Latest version from dependencies table (e.g. dist-tags.latest). When provided, used in Version card. */
  latestVersion?: string | null;
  /** Project/org effective policies for license compliance. When provided, License card shows policy-based status. */
  policies?: ProjectEffectivePolicies | null;
  /** Org or team deprecation info for this dependency, if any. */
  deprecation?: { recommended_alternative: string; deprecated_by: string | null; created_at: string; scope?: 'organization' | 'team'; team_id?: string } | null;
  /** Whether the current user has permission to manage deprecations (org or team manage). Only affects visibility of Deprecate/Remove Deprecation actions; the deprecated card is always shown when deprecation is set. */
  canManageDeprecations?: boolean;
  /** Callback to deprecate this dependency (org or team scope). */
  onDeprecate?: (alternativeName: string) => Promise<void>;
  /** Callback to remove the deprecation for this dependency. */
  onRemoveDeprecation?: () => Promise<void>;
  /** Existing removal PR URL from overview API (so "View removal PR" persists after reload). */
  removePrUrlFromOverview?: string | null;
  /** Latest safe version data from supply chain analysis. */
  safeVersionData?: LatestSafeVersionResponse | null;
  /** Current severity filter for safe version calculation. */
  safeVersionSeverity?: string;
  /** Callback when severity filter changes. */
  onSeverityChange?: (severity: string) => void;
  /** Callback to create bump PR for safe version. */
  onBumpVersion?: () => Promise<void>;
  /** Whether safe version data is loading. */
  safeVersionLoading?: boolean;
  /** Existing bump PR URL for the safe version. */
  bumpPrUrl?: string | null;
  /** Whether we're still checking if a bump PR exists. */
  bumpPrCheckLoading?: boolean;
  /** Whether bump PR is being created. */
  bumping?: boolean;
  /** When true, show "X other projects across your org"; when false, show "X other projects in your team". Set false when user lacks org-level manage teams & projects. */
  otherProjectsScopeIsOrg?: boolean;
  /** When true, show a "Dev dependency" badge (package is in devDependencies, not used at runtime in production). */
  isDevDependency?: boolean;
}

// Score color helper
const getScoreColors = (score: number | null | undefined) => {
  if (score === null || score === undefined) {
    return {
      text: 'text-foreground-secondary',
      progress: 'bg-foreground-secondary',
      border: 'border-border',
    };
  }
  if (score >= 70) {
    return {
      text: 'text-green-600',
      progress: 'bg-green-600',
      border: 'border-green-600/30',
    };
  }
  if (score >= 40) {
    return {
      text: 'text-warning',
      progress: 'bg-warning',
      border: 'border-warning/30',
    };
  }
  return {
    text: 'text-destructive',
    progress: 'bg-destructive',
    border: 'border-destructive/30',
  };
};

// Helper to check if date is older than 1 year
const isOlderThanOneYear = (dateString: string | null): boolean => {
  if (!dateString) return false;
  const date = new Date(dateString);
  const oneYearAgo = new Date();
  oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
  return date < oneYearAgo;
};



// License description helper
const getLicenseInfo = (license: string | null): { description: string; type: 'permissive' | 'copyleft' | 'unknown' } => {
  if (!license) {
    return { description: 'License information not available', type: 'unknown' };
  }
  const l = license.toLowerCase();
  if (l.includes('mit') || l.includes('isc') || l.includes('bsd') || l.includes('unlicense')) {
    return { description: 'Permissive license - safe for commercial use', type: 'permissive' };
  }
  if (l.includes('apache')) {
    return { description: 'Permissive license - safe for commercial use with attribution', type: 'permissive' };
  }
  if (l.includes('gpl') && !l.includes('lgpl')) {
    return { description: 'Copyleft license - requires source code disclosure', type: 'copyleft' };
  }
  if (l.includes('lgpl')) {
    return { description: 'Weak copyleft - limited source code disclosure', type: 'copyleft' };
  }
  if (l.includes('mpl')) {
    return { description: 'Weak copyleft - file-level source disclosure', type: 'copyleft' };
  }
  return { description: 'Check license terms for usage rights', type: 'unknown' };
};

// Format relative time
const formatRelativeTime = (dateString: string | null): string => {
  if (!dateString) return 'Unknown';
  const date = new Date(dateString);
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 60) return 'Just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
  if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)} days ago`;
  if (diffInSeconds < 31536000) return `${Math.floor(diffInSeconds / 2592000)} months ago`;
  return `${Math.floor(diffInSeconds / 31536000)} years ago`;
};

// Format downloads
const formatDownloads = (downloads: number | null): string => {
  if (downloads === null) return 'N/A';
  if (downloads >= 1000000000) return `${(downloads / 1000000000).toFixed(1)}B`;
  if (downloads >= 1000000) return `${(downloads / 1000000).toFixed(1)}M`;
  if (downloads >= 1000) return `${(downloads / 1000).toFixed(1)}K`;
  return downloads.toString();
};

/**
 * Renders AI summary content with support for markdown code blocks.
 * Splits content on triple-backtick fences and renders text as paragraphs
 * and code blocks as styled <pre><code> elements.
 */
function AiSummaryRenderer({ content }: { content: string }) {
  // Split on code fences: ```lang\n...\n```
  const parts = content.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-3">
      {parts.map((part, i) => {
        if (part.startsWith('```')) {
          // Extract language hint and code content
          const lines = part.slice(3, -3).split('\n');
          const firstLine = lines[0]?.trim() || '';
          // First line after ``` might be a language or file path
          const hasLangHint = firstLine && !firstLine.includes(' ') && firstLine.length < 100;
          const label = hasLangHint ? firstLine : null;
          const codeLines = hasLangHint ? lines.slice(1) : lines;
          const code = codeLines.join('\n').trim();

          return (
            <div key={i} className="rounded-md border border-border overflow-hidden bg-background">
              {label && (
                <div className="px-3 py-1.5 bg-background border-b border-border">
                  <span className="text-xs font-mono text-foreground-secondary">{label}</span>
                </div>
              )}
              <pre className="p-3 bg-background overflow-x-auto">
                <code className="text-xs font-mono text-foreground-secondary whitespace-pre">{code}</code>
              </pre>
            </div>
          );
        }

        // Regular text — render paragraphs
        const trimmed = part.trim();
        if (!trimmed) return null;

        return (
          <div key={i} className="text-sm text-foreground-secondary leading-relaxed">
            {trimmed.split('\n\n').map((paragraph, j) => (
              <p key={j} className={j > 0 ? 'mt-2' : ''}>
                {paragraph.split('\n').map((line, k) => (
                  <span key={k}>
                    {k > 0 && <br />}
                    {/* Render inline code with backticks */}
                    {line.split(/(`[^`]+`)/).map((segment, l) =>
                      segment.startsWith('`') && segment.endsWith('`') ? (
                        <code
                          key={l}
                          className="px-1.5 py-0.5 rounded bg-background border border-border text-xs font-mono text-foreground-secondary"
                        >
                          {segment.slice(1, -1)}
                        </code>
                      ) : (
                        <span key={l}>{segment}</span>
                      )
                    )}
                  </span>
                ))}
              </p>
            ))}
          </div>
        );
      })}
    </div>
  );
}

export default function PackageOverview({ dependency, organizationId, projectId, latestVersion, policies, deprecation, canManageDeprecations, onDeprecate, onRemoveDeprecation, removePrUrlFromOverview, safeVersionData, safeVersionSeverity = 'high', onSeverityChange, onBumpVersion, safeVersionLoading = false, bumpPrUrl = null, bumpPrCheckLoading = false, bumping = false, otherProjectsScopeIsOrg = true, isDevDependency = false }: PackageOverviewProps) {

  const [scoreSidebarOpen, setScoreSidebarOpen] = useState(false);
  const [aiSummary, setAiSummary] = useState<string | null>(dependency.ai_usage_summary ?? null);
  const [aiAnalyzedAt, setAiAnalyzedAt] = useState<string | null>(dependency.ai_usage_analyzed_at ?? null);
  const [analyzing, setAnalyzing] = useState(false);
  const [removingPr, setRemovingPr] = useState(false);
  const [removePrUrl, setRemovePrUrl] = useState<string | null>(removePrUrlFromOverview ?? null);
  const [deprecateSidebarOpen, setDeprecateSidebarOpen] = useState(false);
  const [deprecating, setDeprecating] = useState(false);
  const [removingDeprecation, setRemovingDeprecation] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (removePrUrlFromOverview != null) setRemovePrUrl(removePrUrlFromOverview);
  }, [removePrUrlFromOverview]);

  const isZombie = dependency.is_direct && dependency.files_importing_count === 0;

  const handleCreateRemovePr = useCallback(async () => {
    setRemovingPr(true);
    try {
      const result = await api.createRemoveDependencyPR(organizationId, projectId, dependency.id);
      setRemovePrUrl(result.pr_url);
      window.open(result.pr_url, '_blank');
      toast({ title: 'PR Created', description: `Pull request created to remove ${dependency.name}.` });
    } catch {
      toast({ title: 'Error', description: 'Failed to create removal PR. Please try again.' });
    } finally {
      setRemovingPr(false);
    }
  }, [organizationId, projectId, dependency.id, dependency.name, toast]);

  const handleAnalyzeUsage = useCallback(async () => {
    setAnalyzing(true);
    try {
      const result = await api.analyzeDependencyUsage(organizationId, projectId, dependency.id);
      setAiSummary(result.ai_usage_summary);
      setAiAnalyzedAt(result.ai_usage_analyzed_at);
    } catch {
      toast({ title: 'Error', description: 'Failed to analyze usage. Please try again.' });
    } finally {
      setAnalyzing(false);
    }
  }, [organizationId, projectId, dependency.id, toast]);

  const handleDeprecateSubmit = useCallback(async (alternativeName: string) => {
    if (!onDeprecate) return;
    setDeprecating(true);
    try {
      await onDeprecate(alternativeName);
      toast({ title: 'Deprecated', description: `${dependency.name} has been deprecated.` });
    } catch {
      toast({ title: 'Error', description: 'Failed to deprecate package. Please try again.' });
    } finally {
      setDeprecating(false);
    }
  }, [onDeprecate, dependency.name, toast]);

  const handleRemoveDeprecation = useCallback(async () => {
    if (!onRemoveDeprecation) return;
    setRemovingDeprecation(true);
    try {
      await onRemoveDeprecation();
      toast({ title: 'Deprecation removed', description: `${dependency.name} is no longer deprecated.` });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to remove deprecation. Please try again.';
      toast({ title: 'Error', description: message });
    } finally {
      setRemovingDeprecation(false);
    }
  }, [onRemoveDeprecation, dependency.name, toast]);

  const analysis = dependency.analysis;
  const score = analysis?.score ?? null;
  const scoreColors = getScoreColors(score);

  const totalVulns =
    (analysis?.critical_vulns || 0) +
    (analysis?.high_vulns || 0) +
    (analysis?.medium_vulns || 0) +
    (analysis?.low_vulns || 0);

  const licenseInfo = getLicenseInfo(dependency.license);
  const compliance = getComplianceStatus(dependency, policies ?? null);
  const licenseAllowed = isLicenseAllowed(dependency.license, policies ?? null);

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="space-y-6">
        {/* Package Info + Suggested Version + Reputation Score */}
        <div className="flex items-center gap-4 flex-wrap">
          <div className="min-w-0">
            <h1 className="text-2xl font-bold text-foreground mb-2 flex items-center gap-2 flex-wrap">
              {dependency.name}
              <span className="text-foreground-secondary font-normal">@{dependency.version}</span>
              {isDevDependency && (
                <span className="inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium bg-foreground/5 text-foreground-secondary border border-foreground/10 shrink-0">
                  Dev
                </span>
              )}
            </h1>
            <div className="flex items-center gap-4 text-sm text-foreground-secondary flex-wrap">
              <a
                href={`https://www.npmjs.com/package/${dependency.name}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 hover:text-foreground transition-colors"
              >
                <img src="/images/npm_icon.png" alt="NPM" className="w-4 h-4" />
                <span>NPM</span>
                <ExternalLink className="h-3 w-3" />
              </a>
              {dependency.github_url && (
                <a
                  href={dependency.github_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 hover:text-foreground transition-colors"
                >
                  <Github className="h-4 w-4" />
                  <span>GitHub</span>
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {dependency.license && (
                <span className="flex items-center gap-1.5">
                  {policies != null ? (
                    compliance.status === 'COMPLIANT' && licenseAllowed === true ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex cursor-default">
                            <CheckCircle className="h-3.5 w-3.5 text-green-600" />
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>License complies with project policies</TooltipContent>
                      </Tooltip>
                    ) : compliance.status === 'VIOLATION' ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex cursor-default">
                            <XCircle className="h-3.5 w-3.5 text-destructive" />
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>License does not comply with project policies</TooltipContent>
                      </Tooltip>
                    ) : (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex cursor-default">
                            <AlertCircle className="h-3.5 w-3.5 text-warning" />
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>License unknown or not in project policy list</TooltipContent>
                      </Tooltip>
                    )
                  ) : (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="inline-flex cursor-default">
                          <Scale className="h-4 w-4" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>No project license policy configured</TooltipContent>
                    </Tooltip>
                  )}
                  {dependency.license}
                </span>
              )}
              {analysis?.weekly_downloads && (
                <span className="flex items-center gap-1.5">
                  <Download className="h-4 w-4" />
                  {formatDownloads(analysis.weekly_downloads)}/week
                </span>
              )}
            </div>
          </div>
          {/* Reputation score (x/100) - click to open breakdown */}
          <button
            type="button"
            onClick={() => setScoreSidebarOpen(true)}
            className={`ml-auto inline-flex items-center rounded-lg border px-3 py-2 w-fit shrink-0 transition-all hover:ring-2 hover:ring-primary/20 ${scoreColors.border} bg-background-card`}
          >
            {analysis?.status === 'pending' || analysis?.status === 'analyzing' ? (
              <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
            ) : (
              <span className={`text-lg font-bold ${scoreColors.text}`}>
                {score !== null ? score : '—'}<span className="text-foreground-secondary font-normal">/100</span>
              </span>
            )}
          </button>
        </div>

        {/* Package Description row – description on left, Suggestion aligned right (hidden for ghost packages) */}
        <div className="flex items-center gap-4 justify-between">
          <div className="flex items-start gap-3 min-w-0 flex-1">
            {dependency.description && (
              <>
                <Info className="h-4 w-4 text-foreground-secondary mt-0.5 shrink-0" />
                <p className="text-sm text-foreground-secondary leading-relaxed">
                  {dependency.description}
                </p>
              </>
            )}
          </div>
          {!isZombie && (
          <div className="flex items-center gap-2 shrink-0">
              <span className="text-xs font-medium text-foreground-secondary shrink-0">Suggestion</span>
              {safeVersionLoading && !safeVersionData ? (
                <div className="flex items-center gap-2 text-xs text-foreground-secondary">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Checking...</span>
                </div>
              ) : safeVersionData?.isCurrent ? (
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-3.5 w-3.5 text-green-600 shrink-0" />
                  <span className="text-xs text-foreground-secondary">Using latest safe version</span>
                </div>
              ) : safeVersionData?.safeVersion ? (
                <>
                  <span className="text-xs text-foreground-secondary">
                    v{dependency.version} → v{safeVersionData.safeVersion}
                  </span>
                  {onBumpVersion && (
                    bumpPrUrl ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => window.open(bumpPrUrl, '_blank')}
                        className="h-7 text-xs px-2"
                      >
                        <GitPullRequest className="h-3 w-3 mr-1" />
                        View PR
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={onBumpVersion}
                        disabled={bumping || bumpPrCheckLoading}
                        className="h-7 text-xs px-2 text-foreground-secondary hover:text-foreground hover:bg-transparent"
                      >
                        {bumping || bumpPrCheckLoading ? (
                          <Loader2 className="h-3 w-3 animate-spin mr-1" />
                        ) : (
                          <ArrowUpCircle className="h-3 w-3 mr-1" />
                        )}
                        Bump
                      </Button>
                    )
                  )}
                </>
              ) : (
                <div className="flex items-center gap-2 text-xs text-foreground-secondary">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                  <span>No safe version</span>
                </div>
              )}
            </div>
          )}
          </div>
        </div>

      {/* Deprecation Banner – shown when deprecated (org or team); Remove button gated by canManageDeprecations */}
      {deprecation && (
        <div className="rounded-lg border border-warning/30 bg-warning/5 p-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-warning shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-warning">
                {deprecation.scope === 'team' ? 'Deprecated by your team' : 'Deprecated by your organization'}
              </p>
              <p className="text-sm text-foreground-secondary mt-1">
                Use <span className="font-semibold text-foreground">{deprecation.recommended_alternative}</span> instead
              </p>
            </div>
            {canManageDeprecations && onRemoveDeprecation && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleRemoveDeprecation}
                disabled={removingDeprecation}
                className="shrink-0 border-warning/30 text-warning hover:bg-warning/10 hover:text-warning"
              >
                {removingDeprecation ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 mr-1.5" />
                )}
                Remove Deprecation
              </Button>
            )}
          </div>
        </div>
      )}

      {/* Usage Card — lighter card on dark background; header strip + code block for hierarchy */}
      <Card>
        <CardHeader className="p-4 pt-3 pb-3 rounded-t-lg bg-background-card-header border-b border-border">
          <div className="flex items-center gap-2">
            <FileCode className="h-5 w-5 text-foreground-secondary" />
            <CardTitle className="text-base">Usage</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          <div className="space-y-4">
            {/* Main status row: left = status + PR action, right = action buttons */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
              {/* Left side: Usage status + zombie PR */}
              <div className="flex items-center gap-3 min-w-0">
                {dependency.is_direct ? (
                  isZombie ? (
                    <>
                      <div className="w-8 h-8 rounded-md bg-warning/10 border border-warning/20 flex items-center justify-center shrink-0">
                        <Ghost className="h-4 w-4 text-warning" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-warning">Zombie Package</p>
                        <p className="text-xs text-foreground-secondary mt-0.5">Not imported in any file</p>
                      </div>
                      {/* Create PR to Remove - right beside the zombie text */}
                      {removePrUrl ? (
                        <a
                          href={removePrUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 text-sm font-medium text-warning hover:underline shrink-0"
                        >
                          View removal PR
                        </a>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={handleCreateRemovePr}
                          disabled={removingPr}
                          className="h-7 px-2 bg-warning/10 border border-warning/20 text-warning hover:bg-warning/20 hover:border-warning/30 shrink-0"
                        >
                          {removingPr ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
                          ) : (
                            <GitPullRequest className="h-3.5 w-3.5 mr-1.5" />
                          )}
                          Create PR to Remove
                        </Button>
                      )}
                    </>
                  ) : (() => {
                    const filePaths = dependency.imported_file_paths ?? [];
                    const hasFileList = filePaths.length > 0;
                    const maxShow = 25;
                    const showPaths = filePaths.slice(0, maxShow);
                    const remaining = filePaths.length - maxShow;
                    const paragraph = (
                      <p className="text-sm text-foreground-secondary">
                        Imported in <span className="font-medium text-foreground">{dependency.files_importing_count ?? 0}</span> {(dependency.files_importing_count ?? 0) === 1 ? 'file' : 'files'}
                        {' · '}
                        Used in <span className="font-medium text-foreground">{dependency.other_projects_using_count ?? 0}</span> other {(dependency.other_projects_using_count ?? 0) === 1 ? 'project' : 'projects'} {otherProjectsScopeIsOrg ? 'across your org' : 'in your team'}
                      </p>
                    );
                    if (hasFileList) {
                      return (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="cursor-default inline-block">{paragraph}</span>
                          </TooltipTrigger>
                          <TooltipContent side="bottom" className="max-w-sm">
                            <p className="text-xs font-medium text-foreground mb-1.5">Imported in:</p>
                            <ul className="text-xs text-foreground-secondary space-y-0.5 max-h-48 overflow-y-auto list-none pl-0">
                              {showPaths.map((fp) => (
                                <li key={fp} className="truncate font-mono" title={fp}>{fp}</li>
                              ))}
                              {remaining > 0 && (
                                <li className="text-foreground-secondary/80">… and {remaining} more</li>
                              )}
                            </ul>
                          </TooltipContent>
                        </Tooltip>
                      );
                    }
                    return paragraph;
                  })()
                ) : (
                  <div className="flex items-center gap-2">
                    <GitFork className="h-4 w-4 text-foreground-secondary" />
                    <p className="text-sm text-foreground-secondary">Transitive dependency — not directly imported</p>
                  </div>
                )}
              </div>

              {/* Right side: Deprecate + Aegis analyze buttons */}
              {(dependency.is_direct || canManageDeprecations) && (
                <div className="flex items-center gap-2 shrink-0">
                  {/* Deprecate button */}
                  {canManageDeprecations && !deprecation && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setDeprecateSidebarOpen(true)}
                      className="h-8 text-xs border-warning/20 bg-warning/5 text-warning hover:bg-warning/10 hover:border-warning/30"
                    >
                      <Ban className="h-3.5 w-3.5 mr-1.5" />
                      Deprecate
                    </Button>
                  )}

                  {/* Analyze usage button */}
                  {dependency.is_direct && !aiSummary && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleAnalyzeUsage}
                      disabled={analyzing}
                      className="h-8 text-xs"
                    >
                      {analyzing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
                      ) : (
                        <Sparkles className="h-3.5 w-3.5 mr-1.5" />
                      )}
                      Have Aegis analyze usage
                    </Button>
                  )}
                </div>
              )}
            </div>



            {/* AI Usage Analysis - already analyzed */}
            {dependency.is_direct && aiSummary && (
              <div className="pt-3 border-t border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-foreground-secondary" />
                    <span className="text-sm font-medium text-foreground">Aegis Usage Analysis</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {aiAnalyzedAt && (
                      <span className="text-xs text-foreground-secondary">
                        {formatRelativeTime(aiAnalyzedAt)}
                      </span>
                    )}
                    <button
                      onClick={handleAnalyzeUsage}
                      disabled={analyzing}
                      className="p-1 rounded hover:bg-background-subtle text-foreground-secondary hover:text-foreground transition-colors disabled:opacity-50"
                      title="Re-analyze usage"
                    >
                      {analyzing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                </div>
                <AiSummaryRenderer content={aiSummary} />
              </div>
            )}

            {/* Deprecation info if already deprecated */}
            {deprecation && (
              <div className="pt-3 border-t border-border">
                <div className="flex items-center gap-2">
                  <Ban className="h-4 w-4 text-warning" />
                  <span className="text-sm font-medium text-warning">
                    {deprecation.scope === 'team' ? 'Deprecated team-wide' : 'Deprecated org-wide'}
                  </span>
                  <span className="text-xs text-foreground-secondary ml-auto">
                    Use <span className="font-medium text-foreground">{deprecation.recommended_alternative}</span>
                  </span>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {scoreSidebarOpen && (
        <ScoreBreakdownSidebar
          dependency={dependency}
          organizationId={organizationId}
          projectId={projectId}
          onClose={() => setScoreSidebarOpen(false)}
        />
      )}

      {deprecateSidebarOpen && (
        <DeprecateSidebar
          dependencyName={dependency.name}
          onClose={() => setDeprecateSidebarOpen(false)}
          onDeprecate={handleDeprecateSubmit}
        />
      )}

    </div >
  );
}
