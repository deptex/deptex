import { Loader2 } from 'lucide-react';
import type { Project } from '../lib/api';
import { projectStatusLabel } from '../lib/projectStatusLabel';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { cn } from '../lib/utils';

type Props = {
  project: Project;
  className?: string;
};

/**
 * Policy / org-status badge plus extraction and error states. Shared by Projects page and Org Compliance overview.
 */
export function ProjectStatusBadge({ project, className }: Props) {
  const { label, inProgress, isError, statusColor } = projectStatusLabel(project);

  // In-progress and error states are exclusive — never pair them with the
  // degraded chip (a running/failed scan isn't a trustworthy-but-partial one).
  if (inProgress) {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 shrink-0',
          className
        )}
      >
        <Loader2 className="h-3 w-3 animate-spin" />
        {label}
      </span>
    );
  }

  if (isError) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn(
              'inline-flex px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 shrink-0 cursor-help',
              className
            )}
          >
            Failed
          </span>
        </TooltipTrigger>
        <TooltipContent>{project.extraction_error || 'Extraction failed'}</TooltipContent>
      </Tooltip>
    );
  }

  // Terminal states (custom status / compliance).
  let primaryBadge: JSX.Element;
  if (project.status_name) {
    if (statusColor) {
      primaryBadge = (
        <span
          className={cn('inline-flex px-2 py-0.5 rounded text-xs font-medium border shrink-0', className)}
          style={{
            backgroundColor: `${statusColor}20`,
            color: statusColor,
            borderColor: `${statusColor}40`,
          }}
        >
          {label}
        </span>
      );
    } else {
      primaryBadge = (
        <span
          className={cn(
            'inline-flex px-2 py-0.5 rounded text-xs font-medium border bg-transparent text-foreground-secondary border-foreground/20 shrink-0',
            className
          )}
        >
          {label}
        </span>
      );
    }
  } else if (label === 'COMPLIANT') {
    primaryBadge = (
      <span
        className={cn(
          'inline-flex px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40 shrink-0',
          className
        )}
      >
        COMPLIANT
      </span>
    );
  } else {
    primaryBadge = (
      <span
        className={cn(
          'inline-flex px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 shrink-0',
          className
        )}
      >
        NOT COMPLIANT
      </span>
    );
  }

  return primaryBadge;
}
