import { useState, useCallback, useEffect } from 'react';
import {
  Scale,
  Download,
  Package,
  Info,
  GitFork,
  Github,
  Loader2,
  RefreshCw,
  Ghost,
  Atom,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';
import { Popover, PopoverTrigger, PopoverContent } from './ui/popover';
import { ProjectDependency, api } from '../lib/api';
import { useToast } from '../hooks/use-toast';

interface PackageOverviewProps {
  dependency: ProjectDependency;
  organizationId: string;
  projectId: string;
  /** Latest version from dependencies table (e.g. dist-tags.latest). When provided, used in Version card. */
  latestVersion?: string | null;
  /** When true, show a "Dev dependency" badge (package is in devDependencies, not used at runtime in production). */
  isDevDependency?: boolean;
}

// Score color helper — tinted-chip treatment (same language as the depscore band pills)
const getScoreColors = (score: number | null | undefined) => {
  if (score === null || score === undefined) {
    return {
      text: 'text-foreground-secondary',
      progress: 'bg-foreground-secondary',
      border: 'border-border',
      bg: 'bg-background-card',
    };
  }
  if (score >= 70) {
    return {
      text: 'text-green-400',
      progress: 'bg-green-500',
      border: 'border-green-500/30',
      bg: 'bg-green-500/10',
    };
  }
  if (score >= 40) {
    return {
      text: 'text-yellow-400',
      progress: 'bg-yellow-500',
      border: 'border-yellow-500/30',
      bg: 'bg-yellow-500/10',
    };
  }
  return {
    text: 'text-red-400',
    progress: 'bg-red-500',
    border: 'border-red-500/30',
    bg: 'bg-red-500/10',
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

const ECOSYSTEM_ICON_SRCS: Record<string, string> = {
  npm: '/images/npm_icon.png',
  pypi: '/images/pypi_icon.png',
  maven: '/images/maven_icon.png',
  nuget: '/images/nuget_icon.png',
  golang: '/images/go_icon.png',
  go: '/images/go_icon.png',
  cargo: '/images/cargo_icon.png',
  gem: '/images/frameworks/ruby.png',
  composer: '/images/frameworks/php.png',
};

function ecosystemIconNode(ecosystem: string | null | undefined): React.ReactNode {
  const src = ECOSYSTEM_ICON_SRCS[ecosystem ?? 'npm'];
  if (src) return <img src={src} alt="" className="w-4 h-4 object-contain" aria-hidden />;
  return <Package className="h-4 w-4" />;
}

// Registry link helper — returns URL and display label for the package's ecosystem
const getRegistryLink = (name: string, ecosystem?: string | null): { url: string; label: string; icon: React.ReactNode } => {
  switch (ecosystem) {
    case 'pypi':
      return { url: `https://pypi.org/project/${name}`, label: 'PyPI', icon: ecosystemIconNode(ecosystem) };
    case 'maven': {
      const parts = name.split(':');
      const url = parts.length === 2
        ? `https://central.sonatype.com/artifact/${parts[0]}/${parts[1]}`
        : `https://search.maven.org/search?q=${encodeURIComponent(name)}`;
      return { url, label: 'Maven', icon: ecosystemIconNode(ecosystem) };
    }
    case 'golang':
    case 'go':
      return { url: `https://pkg.go.dev/${name}`, label: 'Go', icon: ecosystemIconNode(ecosystem) };
    case 'cargo':
      return { url: `https://crates.io/crates/${name}`, label: 'crates.io', icon: ecosystemIconNode(ecosystem) };
    case 'nuget':
      return { url: `https://www.nuget.org/packages/${name}`, label: 'NuGet', icon: ecosystemIconNode(ecosystem) };
    case 'gem':
    case 'rubygems':
      return { url: `https://rubygems.org/gems/${name}`, label: 'RubyGems', icon: ecosystemIconNode('gem') };
    case 'composer':
      return { url: `https://packagist.org/packages/${name}`, label: 'Packagist', icon: ecosystemIconNode('composer') };
    default:
      return { url: `https://www.npmjs.com/package/${name}`, label: 'npm', icon: ecosystemIconNode('npm') };
  }
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

        // Render inline segments: **bold** and `code`
        function renderInline(text: string) {
          return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/).map((seg, idx) => {
            if (seg.startsWith('**') && seg.endsWith('**')) {
              return <strong key={idx} className="font-semibold text-foreground">{seg.slice(2, -2)}</strong>;
            }
            if (seg.startsWith('`') && seg.endsWith('`')) {
              return <code key={idx} className="px-1.5 py-0.5 rounded bg-background border border-border text-xs font-mono text-foreground-secondary">{seg.slice(1, -1)}</code>;
            }
            return <span key={idx}>{seg}</span>;
          });
        }

        return (
          <div key={i} className="text-sm text-foreground/80 leading-relaxed">
            {trimmed.split('\n\n').map((paragraph, j) => (
              <p key={j} className={j > 0 ? 'mt-2' : ''}>
                {paragraph.split('\n').map((line, k) => (
                  <span key={k}>
                    {k > 0 && <br />}
                    {renderInline(line)}
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

export default function PackageOverview({ dependency, organizationId, projectId, latestVersion, isDevDependency = false }: PackageOverviewProps) {

  const [aiSummary, setAiSummary] = useState<string | null>(dependency.ai_usage_summary ?? null);
  const [aiAnalyzedAt, setAiAnalyzedAt] = useState<string | null>(dependency.ai_usage_analyzed_at ?? null);
  const [analyzing, setAnalyzing] = useState(false);

  // Sync AI summary state when dependency changes (guards against prop updates without remount)
  useEffect(() => {
    setAiSummary(dependency.ai_usage_summary ?? null);
    setAiAnalyzedAt(dependency.ai_usage_analyzed_at ?? null);
  }, [dependency.id]);
  const { toast } = useToast();


  const handleAnalyzeUsage = useCallback(async (refresh?: boolean) => {
    setAnalyzing(true);
    try {
      const result = await api.analyzeDependencyUsage(organizationId, projectId, dependency.id, refresh);
      setAiSummary(result.ai_usage_summary);
      setAiAnalyzedAt(result.ai_usage_analyzed_at);
      // Any prefetched overview snapshot predates this analysis — drop it so a later
      // visit refetches and keeps the summary instead of consuming stale data.
      api.clearDependencyOverviewPrefetch(organizationId, projectId, dependency.id);
    } catch {
      toast({ title: 'Error', description: 'Failed to analyze usage. Please try again.' });
    } finally {
      setAnalyzing(false);
    }
  }, [organizationId, projectId, dependency.id, toast]);

  const analysis = dependency.analysis;
  const score = analysis?.score ?? null;
  const scoreColors = getScoreColors(score);

  const totalVulns =
    (analysis?.critical_vulns || 0) +
    (analysis?.high_vulns || 0) +
    (analysis?.medium_vulns || 0) +
    (analysis?.low_vulns || 0);

  const licenseInfo = getLicenseInfo(dependency.license);

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
              {(() => {
                const reg = getRegistryLink(dependency.name, dependency.ecosystem);
                return (
                  <a
                    href={reg.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 hover:text-foreground transition-colors"
                  >
                    {reg.icon}
                    <span>{reg.label}</span>
                  </a>
                );
              })()}
              {dependency.github_url && (
                <a
                  href={dependency.github_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 hover:text-foreground transition-colors"
                >
                  <Github className="h-4 w-4" />
                  <span>GitHub</span>
                </a>
              )}
              {dependency.license && (
                <span className="flex items-center gap-1.5">
                  <Scale className="h-4 w-4" />
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
          {/* Reputation score (x/100) - click for breakdown */}
          <Popover>
            <PopoverTrigger asChild>
              <button className={`ml-auto inline-flex items-center rounded-lg border px-3 py-2 w-fit shrink-0 cursor-pointer hover:brightness-125 transition-[filter] ${scoreColors.border} ${scoreColors.bg}`}>
                {analysis?.status === 'pending' || analysis?.status === 'analyzing' ? (
                  <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
                ) : (
                  <span className={`text-lg font-bold ${scoreColors.text}`}>
                    {score !== null ? score : '—'}<span className={`font-normal text-sm opacity-60`}>/100</span>
                  </span>
                )}
              </button>
            </PopoverTrigger>
            <PopoverContent side="bottom" align="end" className="w-72 p-0 overflow-hidden">
              {/* Header band — matches the house card-header strip */}
              <div className="px-4 py-3 bg-background-card-header border-b border-border flex items-center justify-between">
                <p className="text-sm font-medium text-foreground">Reputation score</p>
                <span className={`text-base font-bold ${scoreColors.text}`}>
                  {score !== null ? score : '—'}
                  <span className="text-foreground-secondary font-normal text-sm">/100</span>
                </span>
              </div>
              <div className="px-4 py-3 space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground-secondary">OpenSSF Scorecard</span>
                  <span className="text-foreground tabular-nums font-medium">{analysis?.openssf_score != null ? `${analysis.openssf_score.toFixed(1)}/10` : '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground-secondary">Weekly downloads</span>
                  <span className="text-foreground tabular-nums font-medium">{analysis?.weekly_downloads != null ? formatDownloads(analysis.weekly_downloads) : '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground-secondary">Releases past 12 months</span>
                  <span className="text-foreground tabular-nums font-medium">{analysis?.releases_last_12_months ?? '—'}</span>
                </div>
                {dependency.slsa_level != null && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-foreground-secondary">SLSA level</span>
                    <span className="text-foreground tabular-nums font-medium">L{dependency.slsa_level}</span>
                  </div>
                )}
                {analysis?.is_malicious && (
                  <div className="mt-1 rounded-md border border-destructive/30 bg-destructive/10 px-2.5 py-1.5 text-xs font-medium text-destructive">
                    Flagged as malicious
                  </div>
                )}
              </div>
            </PopoverContent>
          </Popover>
        </div>

        {/* Package Description */}
        {dependency.description && (
          <div className="flex items-start gap-3">
            <Info className="h-4 w-4 text-foreground-secondary mt-0.5 shrink-0" />
            <p className="text-sm text-foreground-secondary leading-relaxed">
              {dependency.description}
            </p>
          </div>
        )}

      </div>

      {/* Usage — house card: header strip + body. Status line + capability chips on the
          left, the analyze action on the right, AI summary below. */}
      <Card>
        <CardHeader className="p-4 pt-3 pb-3 rounded-t-lg bg-background-card-header border-b border-border">
          <CardTitle className="text-base">Usage</CardTitle>
        </CardHeader>
        <CardContent className="pt-4 space-y-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-3 min-w-0">
            {dependency.is_direct ? (
              (dependency.files_importing_count === 0) ? (
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-md bg-warning/10 border border-warning/20 flex items-center justify-center shrink-0">
                    <Ghost className="h-4 w-4 text-warning" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-warning">Unused Package</p>
                    <p className="text-xs text-foreground-secondary mt-0.5">Not imported in any file</p>
                  </div>
                </div>
              ) : dependency.files_importing_count == null ? null : (() => {
                const filePaths = dependency.imported_file_paths ?? [];
                const hasFileList = filePaths.length > 0;
                const maxShow = 25;
                const showPaths = filePaths.slice(0, maxShow);
                const remaining = filePaths.length - maxShow;
                const paragraph = (
                  <p className="text-sm text-foreground">
                    Imported in <span className="font-semibold">{dependency.files_importing_count ?? 0}</span> {(dependency.files_importing_count ?? 0) === 1 ? 'file' : 'files'}
                    {' · '}
                    Used in <span className="font-semibold">{dependency.other_projects_using_count ?? 0}</span> other {(dependency.other_projects_using_count ?? 0) === 1 ? 'project' : 'projects'} across your org
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
                            <li key={fp} className="truncate font-mono">{fp}</li>
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
                <p className="text-sm text-foreground">Transitive dependency — not directly imported</p>
              </div>
            )}
          </div>

          {dependency.is_direct && !aiSummary && (
            <Button
              variant="outline"
              onClick={() => handleAnalyzeUsage()}
              disabled={analyzing}
              className="h-8 rounded-lg px-3 shrink-0"
            >
              {analyzing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
              ) : (
                <Atom className="h-3.5 w-3.5 mr-1.5" />
              )}
              Analyze usage
            </Button>
          )}
        </div>

        {/* AI usage analysis — subtle contained block so the summary reads as one unit */}
        {dependency.is_direct && aiSummary && (
          <div className="rounded-lg border border-border bg-background-subtle/30 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Atom className="h-4 w-4 text-foreground-secondary" />
                <span className="text-sm font-medium text-foreground">AI usage analysis</span>
              </div>
              <div className="flex items-center gap-2">
                {aiAnalyzedAt && (
                  <span className="text-xs text-foreground-secondary">
                    {formatRelativeTime(aiAnalyzedAt)}
                  </span>
                )}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      onClick={() => handleAnalyzeUsage(true)}
                      disabled={analyzing}
                      className="p-1 rounded hover:bg-background-subtle text-foreground-secondary hover:text-foreground transition-colors disabled:opacity-50"
                      aria-label="Re-analyze usage"
                    >
                      {analyzing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="top">Re-analyze usage</TooltipContent>
                </Tooltip>
              </div>
            </div>
            <AiSummaryRenderer content={aiSummary} />
          </div>
        )}
        </CardContent>
      </Card>

    </div >
  );
}
