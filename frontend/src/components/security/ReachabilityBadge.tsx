import { Crosshair, Layers, PackageOpen, PackageX, HelpCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

export type MaliciousReachabilityLevel =
  | 'function'
  | 'module'
  | 'imported_unused'
  | 'unimported';

interface ReachabilityBadgeProps {
  level: MaliciousReachabilityLevel | null;
  /** Optional resolver detail surfaced in the tooltip. */
  details?: {
    entry_points?: string[];
    sink_file?: string;
    sink_line?: number;
  } | null;
  className?: string;
}

const LEVEL_STYLES: Record<MaliciousReachabilityLevel, { label: string; tone: string; Icon: typeof Crosshair }> = {
  function: {
    label: 'Function-reachable',
    tone: 'bg-red-500/10 text-red-400 border-red-500/20',
    Icon: Crosshair,
  },
  module: {
    label: 'Module-reachable',
    tone: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    Icon: Layers,
  },
  imported_unused: {
    label: 'Imported, unused',
    tone: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    Icon: PackageOpen,
  },
  unimported: {
    label: 'Unimported',
    tone: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
    Icon: PackageX,
  },
};

const UNKNOWN_STYLE = {
  label: 'Reachability unknown',
  tone: 'bg-zinc-500/10 text-zinc-500 border-zinc-500/20',
  Icon: HelpCircle,
};

function buildTooltip(level: MaliciousReachabilityLevel | null, details: ReachabilityBadgeProps['details']): string {
  if (level === 'function') {
    if (details?.entry_points?.length) {
      return `Called from: ${details.entry_points.slice(0, 3).join(', ')}`;
    }
    if (details?.sink_file) {
      return `Invoked at ${details.sink_file}${details.sink_line ? `:${details.sink_line}` : ''}`;
    }
    return 'A symbol from this package is invoked in your code.';
  }
  if (level === 'module') {
    return 'A symbol from this package is referenced in your code, but never called.';
  }
  if (level === 'imported_unused') {
    return 'This package is imported but no symbol from it is referenced — likely a dead import.';
  }
  if (level === 'unimported') {
    return 'This package is in your dependency tree but no source file imports it.';
  }
  return 'Reachability could not be determined for this finding.';
}

export function ReachabilityBadge({ level, details, className }: ReachabilityBadgeProps) {
  const style = level ? LEVEL_STYLES[level] : UNKNOWN_STYLE;
  const { label, tone, Icon } = style;
  const tooltip = buildTooltip(level, details);

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border',
        tone,
        className,
      )}
      title={tooltip}
    >
      <Icon className="h-3 w-3 mr-1" />
      {label}
    </span>
  );
}
