import { cn } from '../lib/utils';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';

/**
 * Depscore-band finding counts, rendered as soft pills in the same visual language as the
 * Depscore column in the Findings table (`DepscoreValue`): rounded-full, faint tinted fill,
 * matching colored border, tabular numerals. The band each count falls into comes from the
 * finding's reachability-aware Depscore (>=90 C / >=70 H / >=40 M / <40 L) — NOT raw CVSS
 * severity — so an unreachable "Critical" CVE correctly lands in a lower band.
 *
 * Counts only: the colour carries the band, a Radix tooltip spells it out on hover. By default
 * all four bands render (zeros muted) so they column-align across table rows; pass `hideZeros`
 * to drop empty bands instead.
 */
export interface SeverityPillsProps {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  className?: string;
  /** Drop bands with a zero count instead of rendering them muted. */
  hideZeros?: boolean;
}

// Aikido-style band ramp: red → orange → blue → green (critical → high → medium → low).
const BANDS = [
  { key: 'critical', label: 'Critical', active: 'bg-red-500/10 text-red-400 border-red-500/20', title: 'Critical — depscore ≥ 90' },
  { key: 'high', label: 'High', active: 'bg-orange-500/10 text-orange-400 border-orange-500/20', title: 'High — depscore ≥ 70' },
  { key: 'medium', label: 'Medium', active: 'bg-blue-500/10 text-blue-400 border-blue-500/20', title: 'Medium — depscore ≥ 40' },
  { key: 'low', label: 'Low', active: 'bg-green-500/10 text-green-400 border-green-500/20', title: 'Low — depscore < 40' },
] as const;

export function SeverityPills({ critical = 0, high = 0, medium = 0, low = 0, className, hideZeros }: SeverityPillsProps) {
  const counts: Record<string, number> = { critical, high, medium, low };
  const total = critical + high + medium + low;

  if (total === 0 && hideZeros) {
    return <span className={cn('text-xs text-foreground-secondary', className)}>No findings</span>;
  }

  return (
    <div className={cn('flex items-center gap-1.5', className)}>
      {BANDS.map((band) => {
        const count = counts[band.key];
        if (hideZeros && count === 0) return null;
        const isActive = count > 0;
        return (
          <Tooltip key={band.key}>
            <TooltipTrigger asChild>
              <span
                className={cn(
                  'inline-flex h-7 min-w-[1.875rem] items-center justify-center rounded-full border px-2.5 text-[13px] font-semibold tabular-nums',
                  isActive ? band.active : 'border-transparent bg-background-subtle/40 text-foreground-secondary/30',
                )}
              >
                {count}
              </span>
            </TooltipTrigger>
            <TooltipContent>{band.title}</TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
}

export default SeverityPills;
