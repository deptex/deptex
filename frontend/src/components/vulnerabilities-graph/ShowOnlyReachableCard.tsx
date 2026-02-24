import { memo } from 'react';
import { Switch } from '../ui/switch';
import { cn } from '../../lib/utils';

interface ShowOnlyReachableCardProps {
  /** When true, only vulnerabilities where is_reachable is true are shown; node colors always use only reachable. */
  showOnlyReachable: boolean;
  onToggle: (value: boolean) => void;
  /** Optional class for the container (e.g. position overrides). */
  className?: string;
}

function ShowOnlyReachableCardComponent({
  showOnlyReachable,
  onToggle,
  className,
}: ShowOnlyReachableCardProps) {
  return (
    <div
      className={cn(
        'absolute right-3 bottom-3 z-30 w-[240px] rounded-lg border border-border bg-background-card/95 backdrop-blur-sm shadow-md overflow-hidden pointer-events-auto',
        className
      )}
    >
      <div className="px-3.5 py-3 flex items-center justify-between gap-3">
        <span className="text-xs font-medium text-foreground-secondary">
          Show only is reachable
        </span>
        <Switch
          checked={showOnlyReachable}
          onCheckedChange={onToggle}
          aria-label="Show only reachable vulnerabilities"
        />
      </div>
    </div>
  );
}

export const ShowOnlyReachableCard = memo(ShowOnlyReachableCardComponent);
