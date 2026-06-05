import { cn } from '../lib/utils';

/**
 * Depscore-band issue pills (Critical / High / Medium / Low). The bands come from each finding's
 * reachability-aware Depscore (>=90 C / >=70 H / >=40 M / <40 L) — NOT raw CVSS severity — so an
 * unreachable "Critical" CVE correctly lands in a lower band. Zero bands render dimmed so the
 * non-empty ones pop while table columns stay aligned.
 */
export interface SeverityPillsProps {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  className?: string;
  /** Hide bands with a zero count instead of dimming them. */
  hideZeros?: boolean;
}

const BANDS = [
  { key: 'critical', label: 'C', active: 'bg-red-500/15 text-red-300', title: 'Critical (depscore ≥ 90)' },
  { key: 'high', label: 'H', active: 'bg-orange-500/15 text-orange-300', title: 'High (depscore ≥ 70)' },
  { key: 'medium', label: 'M', active: 'bg-amber-500/15 text-amber-300', title: 'Medium (depscore ≥ 40)' },
  { key: 'low', label: 'L', active: 'bg-sky-500/15 text-sky-300', title: 'Low (depscore < 40)' },
] as const;

export function SeverityPills({ critical = 0, high = 0, medium = 0, low = 0, className, hideZeros }: SeverityPillsProps) {
  const counts: Record<string, number> = { critical, high, medium, low };
  const total = critical + high + medium + low;

  if (total === 0 && hideZeros) {
    return <span className={cn('text-xs text-foreground-secondary', className)}>No issues</span>;
  }

  return (
    <div className={cn('flex items-center gap-1', className)}>
      {BANDS.map((band) => {
        const count = counts[band.key];
        if (hideZeros && count === 0) return null;
        const isActive = count > 0;
        return (
          <span
            key={band.key}
            title={band.title}
            className={cn(
              'inline-flex h-6 min-w-[1.75rem] items-center justify-center gap-0.5 rounded-md px-1.5 text-xs font-semibold tabular-nums',
              isActive ? band.active : 'bg-background-subtle/40 text-foreground-secondary/40',
            )}
          >
            <span className="opacity-70">{band.label}</span>
            {count}
          </span>
        );
      })}
    </div>
  );
}

export default SeverityPills;
