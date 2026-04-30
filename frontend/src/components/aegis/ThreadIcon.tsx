import { Archive, Circle, CircleCheck, CircleX, Loader2 } from 'lucide-react';
import type { FixStatusForBadge } from '../../lib/aegis-api';
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
