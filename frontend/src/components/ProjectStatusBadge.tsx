import { Loader2, AlertTriangle } from 'lucide-react';
import type { Project } from '../lib/api';
import { projectStatusLabel } from '../lib/projectStatusLabel';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { cn } from '../lib/utils';

type Props = {
  project: Project;
  className?: string;
};

/**
 * The ⚠️ "Scan incomplete" chip. Shown next to a terminal status when the last
 * scan finalized but a security-critical step produced no/partial signal — so
 * the green result is not fully trustworthy. Never shown alongside an
 * in-progress or failed status (those already tell the whole story).
 */
function ScanIncompleteChip() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border bg-amber-500/10 text-amber-500 border-amber-500/20 shrink-0 cursor-help">
          <AlertTriangle className="h-3 w-3" />
          Scan incomplete
        </span>
      </TooltipTrigger>
      <TooltipContent>Some scanners didn't complete; results may be partial.</TooltipContent>
    </Tooltip>
  );
}

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

  // Terminal states (custom status / compliance) — these can carry the degraded
  // chip when the run finalized but a scanner produced no/partial signal.
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

  if (!project.scan_degraded) return primaryBadge;
  return (
    <span className="inline-flex items-center gap-1.5">
      {primaryBadge}
      <ScanIncompleteChip />
    </span>
  );
}
