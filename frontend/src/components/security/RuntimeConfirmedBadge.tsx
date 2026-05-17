// v2.1c: badge shown on an SCA finding whose reachability was flipped to
// 'confirmed' because a Nuclei DAST scan independently observed the
// vulnerability at runtime. Engine-agnostic copy — any DAST engine that
// produces a runtime confirmation lights this up.

import { ShieldCheck } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';

interface RuntimeConfirmedBadgeProps {
  /** reachability level the finding held before the runtime confirmation. */
  priorLevel?: string | null;
  className?: string;
}

export function RuntimeConfirmedBadge({ priorLevel, className }: RuntimeConfirmedBadgeProps) {
  const prior = priorLevel ? priorLevel.replace(/_/g, ' ') : null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            'inline-flex items-center gap-1 rounded border border-emerald-500/20 bg-emerald-500/10',
            'px-1.5 py-0.5 text-[10px] font-medium leading-none text-emerald-400',
            className,
          )}
        >
          <ShieldCheck className="h-3 w-3" />
          Runtime Confirmed
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        A DAST scan independently observed this vulnerability at runtime —
        {prior ? ` upgraded from ${prior} to confirmed.` : ' reachability upgraded to confirmed.'}
      </TooltipContent>
    </Tooltip>
  );
}
