import { AlertTriangle, CheckCircle2, Loader2, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import type { FixStatus } from '../../lib/api';

export function FixStatusPill({ status }: { status: FixStatus }) {
  const base =
    'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium border';
  if (status === 'planning') {
    return (
      <span className={cn(base, 'bg-foreground/5 text-foreground-secondary border-border')}>
        <Loader2 className="h-3 w-3 animate-spin" />
        Planning
      </span>
    );
  }
  if (status === 'awaiting_approval') {
    return (
      <span className={cn(base, 'bg-warning/10 text-warning border-warning/30')}>
        Awaiting approval
      </span>
    );
  }
  if (status === 'approved' || status === 'executing') {
    return (
      <span className={cn(base, 'bg-blue-500/10 text-blue-300 border-blue-500/30')}>
        <Loader2 className="h-3 w-3 animate-spin" />
        {status === 'approved' ? 'Approved · queued' : 'Executing'}
      </span>
    );
  }
  if (status === 'completed') {
    return (
      <span className={cn(base, 'bg-success/10 text-success border-success/30')}>
        <CheckCircle2 className="h-3 w-3" />
        Completed
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span className={cn(base, 'bg-destructive/10 text-destructive border-destructive/30')}>
        <AlertTriangle className="h-3 w-3" />
        Failed
      </span>
    );
  }
  return (
    <span className={cn(base, 'bg-foreground/5 text-foreground-secondary border-border')}>
      <X className="h-3 w-3" />
      Rejected
    </span>
  );
}
