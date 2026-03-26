import { Building2, UsersRound, FolderKanban } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';

const SCOPE = {
  organization: { label: 'Organization', Icon: Building2 },
  team: { label: 'Team', Icon: UsersRound },
  project: { label: 'Project', Icon: FolderKanban },
} as const;

export type GraphScopeType = keyof typeof SCOPE;

/** Compact scope label for org overview graph nodes (top-right). */
export function GraphScopePill({ type, className = '' }: { type: GraphScopeType; className?: string }) {
  const { label, Icon } = SCOPE[type];
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={`inline-flex items-center justify-center rounded-md border border-border/90 bg-muted/30 px-1.5 py-0.5 text-muted-foreground shadow-sm cursor-default select-none ${className}`}
          aria-label={label}
        >
          <Icon className="h-3 w-3 shrink-0 opacity-90" aria-hidden />
          <span className="sr-only">{label}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={6}>
        {label}
      </TooltipContent>
    </Tooltip>
  );
}
