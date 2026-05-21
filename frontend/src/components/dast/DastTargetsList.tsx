import { ChevronDown, FileCode, Globe, Loader2, Pencil, Play, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import type { DastJobDTO, DastTargetDTO } from '../../lib/api';

interface DastTargetsListProps {
  targets: DastTargetDTO[];
  /** Most recent scan_jobs row per target, keyed by target_id. */
  jobsByTargetId: Record<string, DastJobDTO | undefined>;
  scanningTargetId: string | null;
  recheckingRuntimeTargetId: string | null;
  drainModeOn: boolean;
  canManage: boolean;
  onScan: (target: DastTargetDTO, engine: 'zap' | 'nuclei') => void;
  onEdit: (target: DastTargetDTO) => void;
  onRecheckRuntime: (target: DastTargetDTO) => void;
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

function runtimeBadge(runtime: DastTargetDTO['detected_runtime']) {
  if (runtime === 'spa') {
    return <Badge variant="outline" className="text-[11px] px-1.5 py-0 border-info/40 text-info">SPA</Badge>;
  }
  if (runtime === 'classic') {
    return <Badge variant="outline" className="text-[11px] px-1.5 py-0">Classic</Badge>;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className="text-[11px] px-1.5 py-0 text-foreground-muted">Unknown</Badge>
      </TooltipTrigger>
      <TooltipContent>Runtime probe failed or hasn't run yet — re-check from the row menu.</TooltipContent>
    </Tooltip>
  );
}

function authChip(target: DastTargetDTO) {
  if (!target.has_credentials) {
    return <Badge variant="outline" className="text-[11px] px-1.5 py-0">Anonymous</Badge>;
  }
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

// Phase 35 (v1.1) — OpenAPI spec source + endpoint count chip per target row.
function specChip(target: DastTargetDTO) {
  const cfg = target.spec_config;
  if (!cfg || cfg.api_spec_source === 'none') return null;
  const count = cfg.last_synthesis_endpoint_count ?? null;
  const label =
    cfg.api_spec_source === 'synthesized'
      ? `Synthesized${count !== null ? ` · ${count}` : ''}`
      : `URL${count !== null ? ` · ${count}` : ''}`;
  return (
    <Badge variant="outline" className="text-[11px] px-1.5 py-0 border-sky-500/30 text-sky-500">
      <FileCode className="h-3 w-3 mr-1" /> {label}
    </Badge>
  );
}

export function DastTargetsList({
  targets,
  jobsByTargetId,
  scanningTargetId,
  recheckingRuntimeTargetId,
  drainModeOn,
  canManage,
  onScan,
  onEdit,
  onRecheckRuntime,
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

  return (
    <ul className="divide-y divide-border">
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
          <li key={target.id} className="px-4 py-3 hover:bg-table-hover transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm text-foreground truncate font-medium">
                    {target.label ?? target.target_url}
                  </span>
                  {runtimeBadge(target.detected_runtime)}
                  {authChip(target)}
                  {specChip(target)}
                  {!target.enabled ? (
                    <Badge variant="outline" className="text-[11px] px-1.5 py-0 text-foreground-muted">Disabled</Badge>
                  ) : null}
                </div>
                {target.label ? (
                  <div className="mt-1 text-xs text-foreground-secondary truncate font-mono">
                    {target.target_url}
                  </div>
                ) : null}
                <div className="mt-1 text-xs text-foreground-secondary flex items-center gap-3 flex-wrap">
                  <span>Last scan: {lastScanText}</span>
                  {job?.status ? <span>Status: {jobStatusText(job)}</span> : null}
                </div>
                {authLost ? (
                  <button
                    onClick={() => onEdit(target)}
                    className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/5 px-2 py-1 text-[11px] text-amber-400 hover:bg-amber-500/10"
                  >
                    <ShieldAlert className="h-3 w-3" />
                    <span>
                      Authentication lost during scan — check logged-out indicator
                    </span>
                  </button>
                ) : null}
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {canManage ? (
                  scanDisabled ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span>
                          <Button variant="outline" size="sm" disabled>
                            {scanningTargetId === target.id || inFlight ? (
                              <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" />
                            ) : (
                              <Play className="h-3.5 w-3.5 mr-2" />
                            )}
                            {inFlight ? 'Running' : 'Scan'}
                          </Button>
                        </span>
                      </TooltipTrigger>
                      {scanDisabledReason ? (
                        <TooltipContent>{scanDisabledReason}</TooltipContent>
                      ) : null}
                    </Tooltip>
                  ) : (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm">
                          <Play className="h-3.5 w-3.5 mr-2" />
                          Scan
                          <ChevronDown className="h-3.5 w-3.5 ml-1.5 -mr-0.5 opacity-60" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-60">
                        <DropdownMenuItem
                          onClick={() => onScan(target, 'zap')}
                          className="flex-col items-start gap-0.5"
                        >
                          <span className="text-sm text-foreground">ZAP</span>
                          <span className="text-xs text-foreground-secondary">
                            Crawl + active/passive web scan
                          </span>
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onScan(target, 'nuclei')}
                          className="flex-col items-start gap-0.5"
                        >
                          <span className="text-sm text-foreground">Nuclei</span>
                          <span className="text-xs text-foreground-secondary">
                            Template-based CVE &amp; exposure checks
                          </span>
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )
                ) : null}
                {canManage ? (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => onRecheckRuntime(target)}
                        disabled={recheckingRuntimeTargetId === target.id}
                        aria-label="Re-probe runtime"
                      >
                        {recheckingRuntimeTargetId === target.id ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Re-probe SPA detection</TooltipContent>
                  </Tooltip>
                ) : null}
                {canManage ? (
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => onEdit(target)}
                    aria-label="Edit target"
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                ) : null}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function jobStatusText(job: DastJobDTO): string {
  switch (job.status) {
    case 'queued': return 'Queued';
    case 'processing': return 'Scanning';
    case 'completed': return 'Completed';
    case 'failed': return job.error_category ? `Failed (${job.error_category})` : 'Failed';
    case 'cancelled': return 'Cancelled';
    default: return job.status;
  }
}
