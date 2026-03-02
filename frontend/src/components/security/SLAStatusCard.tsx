import { Clock, CheckCircle, Shield, AlertTriangle } from 'lucide-react';
import { cn } from '../../lib/utils';
import { Progress } from '../ui/progress';

type SlaStatus = 'on_track' | 'warning' | 'breached' | 'met' | 'resolved_late' | 'exempt';

interface SLAStatusCardProps {
  slaStatus: SlaStatus | string | null | undefined;
  slaDeadlineAt: string | null | undefined;
  slaMetAt: string | null | undefined;
  slaExemptReason: string | null | undefined;
  detectedAt: string | null | undefined;
}

function formatRemaining(deadline: string): string {
  const diff = new Date(deadline).getTime() - Date.now();
  const hours = Math.floor(diff / 3600000);
  if (hours < 0) {
    const absHours = Math.abs(hours);
    if (absHours < 24) return `${absHours}h overdue`;
    const days = Math.floor(absHours / 24);
    return `${days}d overdue`;
  }
  if (hours < 24) return `${hours}h remaining`;
  const days = Math.floor(hours / 24);
  return `${days}d remaining`;
}

function formatOverdue(deadline: string): string {
  const diff = Date.now() - new Date(deadline).getTime();
  const hours = Math.floor(diff / 3600000);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function elapsedPercent(detectedAt: string, deadlineAt: string): number {
  const start = new Date(detectedAt).getTime();
  const end = new Date(deadlineAt).getTime();
  const now = Date.now();
  if (now >= end) return 100;
  if (now <= start) return 0;
  return Math.min(100, Math.round(((now - start) / (end - start)) * 100));
}

export function SLAStatusCard({
  slaStatus,
  slaDeadlineAt,
  slaMetAt,
  slaExemptReason,
  detectedAt,
}: SLAStatusCardProps) {
  if (slaStatus == null || slaStatus === '') return null;

  if (slaStatus === 'exempt') {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-border bg-zinc-900/50 px-4 py-3">
        <Shield className="h-5 w-5 text-zinc-500 flex-shrink-0" />
        <div>
          <p className="text-sm font-medium text-zinc-400">SLA exempt</p>
          <p className="text-xs text-zinc-500">{slaExemptReason || 'Excluded from SLA compliance'}</p>
        </div>
      </div>
    );
  }

  if (slaStatus === 'met' || slaStatus === 'resolved_late') {
    const metInTime = slaStatus === 'met';
    return (
      <div className={cn(
        'flex items-center gap-3 rounded-lg border px-4 py-3',
        metInTime ? 'border-green-500/30 bg-green-500/5' : 'border-amber-500/30 bg-amber-500/5'
      )}>
        <CheckCircle className={cn('h-5 w-5 flex-shrink-0', metInTime ? 'text-green-500' : 'text-amber-500')} />
        <div>
          <p className={cn('text-sm font-medium', metInTime ? 'text-green-400' : 'text-amber-400')}>
            {metInTime ? 'SLA met' : 'Resolved after deadline'}
          </p>
          {slaMetAt && (
            <p className="text-xs text-zinc-500">Resolved {new Date(slaMetAt).toLocaleDateString()}</p>
          )}
        </div>
      </div>
    );
  }

  if (slaStatus === 'breached') {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
        <Clock className="h-5 w-5 text-red-500 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-red-400">SLA BREACHED</p>
          <p className="text-xs text-red-300/90">
            {slaDeadlineAt ? `${formatOverdue(slaDeadlineAt)} — Immediate action required` : 'Deadline passed'}
          </p>
        </div>
      </div>
    );
  }

  if (slaStatus === 'warning') {
    const remaining = slaDeadlineAt ? formatRemaining(slaDeadlineAt) : '';
    return (
      <div className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3">
        <Clock className="h-5 w-5 text-amber-500 flex-shrink-0 animate-pulse" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-amber-400">SLA: {remaining}</p>
          <Progress value={detectedAt && slaDeadlineAt ? elapsedPercent(detectedAt, slaDeadlineAt) : 75} className="h-1.5 mt-1 bg-amber-500/20" />
        </div>
      </div>
    );
  }

  if (slaStatus === 'on_track') {
    const remaining = slaDeadlineAt ? formatRemaining(slaDeadlineAt) : '';
    const pct = detectedAt && slaDeadlineAt ? elapsedPercent(detectedAt, slaDeadlineAt) : 0;
    return (
      <div className="flex items-center gap-3 rounded-lg border border-border bg-zinc-900/50 px-4 py-3">
        <Clock className="h-5 w-5 text-green-500 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-green-400">SLA: {remaining}</p>
          <Progress value={pct} className="h-1.5 mt-1" />
        </div>
      </div>
    );
  }

  return null;
}
