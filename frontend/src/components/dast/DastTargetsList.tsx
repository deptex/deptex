import { AlertTriangle, Globe, Loader2, MoreHorizontal, Pencil, Play, Power, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import type { DastJobDTO, DastTargetDTO } from '../../lib/api';

interface DastTargetsListProps {
  targets: DastTargetDTO[];
  /** Most recent scan_jobs row per target, keyed by target_id. */
  jobsByTargetId: Record<string, DastJobDTO | undefined>;
  scanningTargetId: string | null;
  drainModeOn: boolean;
  canManage: boolean;
  onScan: (target: DastTargetDTO, engine: 'zap' | 'nuclei') => void;
  onEdit: (target: DastTargetDTO) => void;
  onConfigureAuth: (target: DastTargetDTO) => void;
  onToggleEnabled: (target: DastTargetDTO, next: boolean) => void;
  onDelete: (target: DastTargetDTO) => void;
}

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const diffSec = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diffSec < 60) return 'Just now';
  const min = Math.floor(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const d = Math.floor(hr / 24);
  if (d < 30) return `${d}d ago`;
  return `${Math.floor(d / 30)}mo ago`;
}

function statusDot(status: DastJobDTO['status']) {
  if (status === 'queued' || status === 'processing') {
    return <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-foreground-secondary" />;
  }
  if (status === 'completed') {
    return <span className="h-2 w-2 rounded-full shrink-0 bg-emerald-500" />;
  }
  if (status === 'cancelled') {
    return <span className="h-2 w-2 rounded-full shrink-0 bg-amber-500" />;
  }
  return <span className="h-2 w-2 rounded-full shrink-0 bg-destructive" />;
}

function jobStatusText(job: DastJobDTO): string {
  switch (job.status) {
    case 'queued': return 'Queued';
    case 'processing': return 'Scanning';
    case 'completed': return 'Completed';
    case 'failed': return 'Failed';
    case 'cancelled': return 'Cancelled';
    default: return job.status;
  }
}

// Only surface the runtime when it's the non-default SPA case (classic /
// unknown are noise — the scanner adapts automatically either way).
function runtimeBadge(runtime: DastTargetDTO['detected_runtime']) {
  if (runtime === 'spa') {
    return <Badge variant="outline" className="text-[11px] px-1.5 py-0 border-info/40 text-info">SPA</Badge>;
  }
  return null;
}

// Only surface auth when the target actually has credentials — "Anonymous" is
// the default and just adds clutter.
function authChip(target: DastTargetDTO) {
  if (!target.has_credentials) return null;
  const label = target.auth_strategy === 'form'
    ? 'Form'
    : target.auth_strategy === 'jwt'
      ? 'JWT'
      : target.auth_strategy === 'cookie'
        ? 'Cookie'
        : target.auth_strategy === 'recorded'
          ? 'Recorded'
          : 'Auth';
  return (
    <Badge variant="outline" className="text-[11px] px-1.5 py-0 border-emerald-500/30 text-emerald-500">
      <ShieldCheck className="h-3 w-3 mr-1" /> {label}
    </Badge>
  );
}

export function DastTargetsList({
  targets,
  jobsByTargetId,
  scanningTargetId,
  drainModeOn,
  canManage,
  onScan,
  onEdit,
  onConfigureAuth,
  onToggleEnabled,
  onDelete,
}: DastTargetsListProps) {
  if (targets.length === 0) {
    return (
      <div className="px-4 py-10 text-center">
        <Globe className="h-6 w-6 text-foreground-muted mx-auto mb-2" />
        <p className="text-sm text-foreground">No targets yet</p>
        <p className="text-xs text-foreground-secondary mt-1 max-w-sm mx-auto">
          Add a target URL to start scanning. DAST runs against your deployed app, so use staging
          if you have one.
        </p>
      </div>
    );
  }

  const showActions = canManage;

  return (
    <table className="w-full table-fixed">
      <colgroup>
        <col className={showActions ? 'w-[44%]' : 'w-[60%]'} />
        <col className="w-[16%]" />
        <col className="w-[15%]" />
        {showActions ? <col className="w-[25%]" /> : null}
      </colgroup>
      <thead className="bg-background-card-header border-b border-border">
        <tr>
          <th className="text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Target</th>
          <th className="text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Status</th>
          <th className="text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Last scan</th>
          {showActions ? <th className="px-4 py-2.5" aria-label="Actions" /> : null}
        </tr>
      </thead>
      <tbody className="divide-y divide-border">
        {targets.map((target) => {
          const job = jobsByTargetId[target.id];
          const authLost = job?.error_category === 'auth_failed';
          const inFlight = job?.status === 'queued' || job?.status === 'processing';
          const lastScanText = formatRelative(target.last_scanned_at);
          const scanDisabled = !canManage || drainModeOn || !target.enabled || inFlight || scanningTargetId === target.id;

          let scanDisabledReason: string | null = null;
          if (drainModeOn) scanDisabledReason = 'DAST queue is paused for maintenance';
          else if (!target.enabled) scanDisabledReason = 'Target is disabled — enable it first';
          else if (inFlight) scanDisabledReason = 'A scan is already running for this target';

          return (
            <tr key={target.id} className="hover:bg-table-hover transition-colors align-top">
              {/* Target */}
              <td className="px-4 py-3">
                <div className="flex items-center gap-2 flex-wrap min-w-0">
                  <span className="text-sm font-medium text-foreground truncate">
                    {target.label ?? target.target_url}
                  </span>
                  {runtimeBadge(target.detected_runtime)}
                  {authChip(target)}
                  {!target.enabled ? (
                    <Badge variant="outline" className="text-[11px] px-1.5 py-0 text-foreground-muted">Disabled</Badge>
                  ) : null}
                </div>
                {target.label ? (
                  <div className="mt-1 text-xs text-foreground-secondary truncate font-mono">
                    {target.target_url}
                  </div>
                ) : null}
                {authLost ? (
                  <button
                    onClick={() => onEdit(target)}
                    className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-400 hover:bg-amber-500/10"
                  >
                    <ShieldAlert className="h-3 w-3" />
                    <span>Authentication lost during scan — check logged-out indicator</span>
                  </button>
                ) : null}
              </td>

              {/* Status */}
              <td className="px-4 py-3 align-middle">
                {job?.status ? (
                  <div className="flex items-center gap-2">
                    {statusDot(job.status)}
                    <span className="text-sm font-medium text-foreground truncate">{jobStatusText(job)}</span>
                    {job.status === 'failed' && job.error ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-destructive" />
                        </TooltipTrigger>
                        <TooltipContent className="max-w-md">
                          {job.error_category ? `${job.error_category}: ${job.error}` : job.error}
                        </TooltipContent>
                      </Tooltip>
                    ) : null}
                  </div>
                ) : (
                  <span className="text-sm text-foreground-secondary">Not scanned</span>
                )}
              </td>

              {/* Last scan */}
              <td className="px-4 py-3 align-middle text-sm text-foreground-secondary tabular-nums">{lastScanText}</td>

              {/* Actions */}
              {showActions ? (
                <td className="px-4 py-3 align-middle">
                  <div className="flex items-center justify-end">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="w-8 px-0 text-foreground-secondary hover:text-foreground"
                          aria-label="Target actions"
                        >
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-52">
                        <DropdownMenuItem
                          onClick={() => onScan(target, 'zap')}
                          disabled={scanDisabled}
                          className={scanDisabled && scanDisabledReason && !inFlight ? 'flex-col items-start gap-0.5' : undefined}
                        >
                          <span className="flex items-center">
                            {scanningTargetId === target.id || inFlight ? (
                              <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" />
                            ) : (
                              <Play className="h-3.5 w-3.5 mr-2" />
                            )}
                            {inFlight ? 'Scanning…' : 'Run scan'}
                          </span>
                          {scanDisabled && scanDisabledReason && !inFlight ? (
                            <span className="text-xs text-foreground-secondary pl-[22px]">{scanDisabledReason}</span>
                          ) : null}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onEdit(target)}>
                          <Pencil className="h-3.5 w-3.5 mr-2" /> Edit target
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onConfigureAuth(target)}>
                          <ShieldCheck className="h-3.5 w-3.5 mr-2" /> Authentication
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => onToggleEnabled(target, !target.enabled)}>
                          <Power className="h-3.5 w-3.5 mr-2" /> {target.enabled ? 'Disable target' : 'Enable target'}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onDelete(target)}
                          className="text-destructive focus:text-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5 mr-2" /> Delete target
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </td>
              ) : null}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
