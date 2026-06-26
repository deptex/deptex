import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Bug, Code2, KeyRound, ChevronRight } from 'lucide-react';
import type { FixFindingDetail } from '../../lib/api';
import { cn } from '../../lib/utils';

/**
 * The scanner-truth issue a fix plan targets, rendered in the same visual
 * language as the Findings table: depscore-band pill (Aikido ramp), type
 * icon, reachability tag. Links to the project's vulnerabilities sidebar —
 * same destination as ProjectEmbedCard.
 */

// Same band thresholds + ramp as the Findings table's DepscoreValue /
// SeverityPills: >=90 C / >=70 H / >=40 M / <40 L, red→orange→yellow→gray.
function bandClasses(detail: FixFindingDetail): string {
  const sev =
    detail.depscore != null
      ? detail.depscore >= 90
        ? 'critical'
        : detail.depscore >= 70
          ? 'high'
          : detail.depscore >= 40
            ? 'medium'
            : 'low'
      : (detail.severity ?? 'medium').toLowerCase();
  switch (sev) {
    case 'critical':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'high':
      return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    case 'medium':
      return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    default:
      return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20';
  }
}

const KIND_ICONS = {
  vulnerability: Bug,
  semgrep: Code2,
  secret: KeyRound,
} as const;

const REACHABILITY_LABELS: Record<string, string> = {
  confirmed: 'Confirmed reachable',
  data_flow: 'Data-flow reachable',
  function: 'Function reachable',
  module: 'Module reachable',
  unreachable: 'Unreachable',
};

interface FixIssueCardProps {
  organizationId: string;
  projectId: string;
  detail: FixFindingDetail;
}

export function FixIssueCard({ organizationId, projectId, detail }: FixIssueCardProps) {
  const to = useMemo(
    () => ({
      pathname: `/organizations/${organizationId}/overview`,
      search: new URLSearchParams({
        sidebar: 'project',
        projectId,
        tab: 'vulnerabilities',
      }).toString(),
    }),
    [organizationId, projectId],
  );

  const Icon = KIND_ICONS[detail.kind] ?? Bug;
  const reachLabel = detail.reachabilityLevel
    ? REACHABILITY_LABELS[detail.reachabilityLevel] ?? detail.reachabilityLevel
    : null;
  const locator =
    detail.filePath != null
      ? `${detail.filePath}${detail.line != null ? `:${detail.line}` : ''}`
      : null;

  return (
    <Link
      to={to}
      className={cn(
        'group flex items-center gap-3 rounded-md border border-border bg-background-subtle/30 px-3.5 py-2.5',
        'transition-colors hover:bg-table-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
      )}
    >
      <span
        className={cn(
          'inline-flex h-7 min-w-[1.875rem] shrink-0 items-center justify-center rounded-full border px-2.5 text-[13px] font-semibold tabular-nums',
          bandClasses(detail),
        )}
      >
        {detail.depscore != null ? detail.depscore : (detail.severity ?? '—').charAt(0).toUpperCase()}
      </span>
      <Icon className="h-4 w-4 shrink-0 text-foreground-secondary" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-foreground">{detail.title}</div>
        {(reachLabel || locator) && (
          <div className="mt-0.5 flex items-center gap-2 text-xs text-foreground-secondary">
            {reachLabel && <span className="truncate">{reachLabel}</span>}
            {locator && <span className="truncate font-mono">{locator}</span>}
          </div>
        )}
      </div>
      <ChevronRight className="h-4 w-4 shrink-0 text-foreground-secondary transition-colors group-hover:text-foreground" />
    </Link>
  );
}
