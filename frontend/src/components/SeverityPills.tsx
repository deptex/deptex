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
  /** `xs` shrinks the pills for tight surfaces (e.g. under graph project tiles). */
  size?: 'default' | 'xs';
}

// Depscore band ramp: red → orange → yellow → gray (critical → high → medium → low).
const BANDS = [
  { key: 'critical', label: 'Critical', active: 'bg-red-500/10 text-red-400 border-red-500/20', title: 'Critical — depscore ≥ 90' },
  { key: 'high', label: 'High', active: 'bg-orange-500/10 text-orange-400 border-orange-500/20', title: 'High — depscore ≥ 70' },
  { key: 'medium', label: 'Medium', active: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20', title: 'Medium — depscore ≥ 40' },
  { key: 'low', label: 'Low', active: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20', title: 'Low — depscore < 40' },
] as const;

export function SeverityPills({ critical = 0, high = 0, medium = 0, low = 0, className, hideZeros, size = 'default' }: SeverityPillsProps) {
  const counts: Record<string, number> = { critical, high, medium, low };
  const total = critical + high + medium + low;
  const isXs = size === 'xs';

  if (total === 0 && hideZeros) {
    return <span className={cn(isXs ? 'text-[10px]' : 'text-xs', 'text-foreground-secondary', className)}>No findings</span>;
  }

  return (
    <div className={cn('flex items-center', isXs ? 'gap-[3px]' : 'gap-1.5', className)}>
      {BANDS.map((band) => {
        const count = counts[band.key];
        if (hideZeros && count === 0) return null;
        const isActive = count > 0;
        return (
          <Tooltip key={band.key}>
            <TooltipTrigger asChild>
              <span
                className={cn(
                  'inline-flex items-center justify-center rounded-full border font-semibold tabular-nums',
                  isXs ? 'h-[15px] min-w-[1.125rem] px-1 text-[9px]' : 'h-7 min-w-[1.875rem] px-2.5 text-[13px]',
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
