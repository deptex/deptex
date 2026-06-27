import { Archive, AlertCircle, Circle, CircleCheck, CircleX, Loader2 } from 'lucide-react';
import type { AegisTaskStatus, FixStatusForBadge } from '../../lib/aegis-api';
import { cn } from '../../lib/utils';

interface ThreadIconProps {
  fixStatus: FixStatusForBadge | null;
  archived?: boolean;
  className?: string;
}

export function ThreadIcon({ fixStatus, archived, className }: ThreadIconProps) {
  const iconClass = cn('h-3.5 w-3.5 shrink-0', className);
  if (archived) {
    return <Archive className={cn(iconClass, 'text-foreground/40')} aria-label="Archived" />;
  }
  switch (fixStatus) {
    case 'awaiting_approval':
      return <CircleCheck className={cn(iconClass, 'text-foreground/50')} aria-label="Awaiting approval" />;
    case 'running':
      return <Loader2 className={cn(iconClass, 'text-foreground/80 animate-spin')} aria-label="Running" />;
    case 'succeeded':
      return <CircleCheck className={cn(iconClass, 'text-success/75')} aria-label="Fix succeeded" />;
    case 'failed':
    case 'refused':
    case 'rejected':
      return <CircleX className={cn(iconClass, 'text-error/75')} aria-label="Fix did not land" />;
    default:
      return <Circle className={cn(iconClass, 'text-foreground/40')} aria-label="Chat" />;
  }
}

/** Status glyph for an Aegis Task row in the sidebar pile. */
export function TaskIcon({ status, className }: { status: AegisTaskStatus; className?: string }) {
  const iconClass = cn('h-3.5 w-3.5 shrink-0', className);
  switch (status) {
    case 'working':
      return <Loader2 className={cn(iconClass, 'text-foreground/80 animate-spin')} aria-label="Working" />;
    case 'completed':
      return <CircleCheck className={cn(iconClass, 'text-success/75')} aria-label="Completed" />;
    case 'completed_with_failures':
      return <AlertCircle className={cn(iconClass, 'text-amber-500/80')} aria-label="Completed with failures" />;
    case 'failed':
      return <CircleX className={cn(iconClass, 'text-error/75')} aria-label="Failed" />;
    case 'proposed':
      return <Circle className={cn(iconClass, 'text-foreground/50')} aria-label="Proposed" />;
    default:
      return <Circle className={cn(iconClass, 'text-foreground/40')} aria-label="Task" />;
  }
}
