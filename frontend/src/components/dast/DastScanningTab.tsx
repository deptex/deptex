import { useEffect, useMemo, useRef, useState } from 'react';
import { Loader2, AlertTriangle, History } from 'lucide-react';
import { Button } from '../ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../ui/dialog';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import { supabase } from '../../lib/supabase';
import {
  api,
  type DastJobDTO,
  type DastScanProfile,
  type DastScopeConfig,
  type DastTargetDTO,
} from '../../lib/api';
import { DastTargetsList } from './DastTargetsList';
import { DastTargetEditDialog } from './DastTargetEditDialog';
import { DastTargetAuthDialog } from './DastTargetAuthDialog';
import {
  ActiveScanOptInDialog,
  hasActiveScanOptIn,
  recordActiveScanOptIn,
} from './ActiveScanOptInDialog';

interface DastScanningTabProps {
  projectId: string;
  /** RBAC: false hides every write affordance. */
  canManage: boolean;
}

interface TabState {
  enabled: boolean;
  scan_profile: DastScanProfile;
  scan_timeout_minutes: number;
  scope_config: DastScopeConfig;
}

// Profile / timeout / scope are no longer surfaced as user controls — every
// project runs the safe passive baseline and the worker handles escalation.
// We still round-trip whatever the project has saved so a toggle never
// clobbers an existing config.
const DEFAULT_STATE: TabState = {
  enabled: false,
  scan_profile: 'auto',
  scan_timeout_minutes: 30,
  scope_config: {},
};

// In-memory cache (per browser session) of the last-loaded DAST state per project. The
// DAST tab unmounts/remounts on every settings-section switch, so without this it re-fetches
// from scratch and flashes a full skeleton each time you return. Seeding from the cache on
// mount (then refreshing in the background) makes a return paint instantly.
type DastCacheEntry = { config: TabState; targets: DastTargetDTO[]; jobs: DastJobDTO[] };
const dastTabCache = new Map<string, DastCacheEntry>();
function putDastCache(projectId: string, partial: Partial<DastCacheEntry>) {
  const prev = dastTabCache.get(projectId) ?? { config: DEFAULT_STATE, targets: [], jobs: [] };
  dastTabCache.set(projectId, { ...prev, ...partial });
}

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return '';
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

function formatDuration(seconds: number | null): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
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

function statusLabel(status: DastJobDTO['status']): string {
  switch (status) {
    case 'queued': return 'Queued';
    case 'processing': return 'Scanning';
    case 'completed': return 'Completed';
    case 'cancelled': return 'Cancelled';
    case 'failed': return 'Failed';
    default: return status;
  }
}

export function DastScanningTab({ projectId, canManage }: DastScanningTabProps) {
  const { toast } = useToast();

  // Seed from the session cache so returning to the tab paints instantly (see dastTabCache).
  const seeded = dastTabCache.get(projectId);
  const [loading, setLoading] = useState(!seeded);
  const [config, setConfig] = useState<TabState>(seeded?.config ?? DEFAULT_STATE);
  const [saving, setSaving] = useState(false);

  const [targets, setTargets] = useState<DastTargetDTO[]>(seeded?.targets ?? []);
  const [jobs, setJobs] = useState<DastJobDTO[]>(seeded?.jobs ?? []);
  const [jobsLoading, setJobsLoading] = useState(!seeded);

  const [editingTargetId, setEditingTargetId] = useState<string | null>(null);
  const [authTargetId, setAuthTargetId] = useState<string | null>(null);
  const [deletingTarget, setDeletingTarget] = useState<DastTargetDTO | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [scanningTargetId, setScanningTargetId] = useState<string | null>(null);
  const [activeScanDialog, setActiveScanDialog] = useState<DastTargetDTO | null>(null);
  // Engine chosen at the moment the active-scan opt-in dialog opened, replayed
  // when the user confirms it.
  const [pendingScanEngine, setPendingScanEngine] = useState<'zap' | 'nuclei'>('zap');

  const fallbackPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshConfig = async () => {
    const cfg = await api.getDastConfig(projectId);
    const nextConfig: TabState = {
      enabled: !!cfg.enabled,
      scan_profile: cfg.scan_profile ?? 'auto',
      scan_timeout_minutes: cfg.scan_timeout_minutes ?? 30,
      scope_config: cfg.scope_config ?? {},
    };
    const nextTargets = cfg.targets ?? [];
    setConfig(nextConfig);
    setTargets(nextTargets);
    putDastCache(projectId, { config: nextConfig, targets: nextTargets });
  };

  const refreshJobs = async () => {
    try {
      const next = await api.getDastJobs(projectId, { limit: 25 });
      setJobs(next);
      putDastCache(projectId, { jobs: next });
    } catch (e: any) {
      console.error('[dast] failed to load jobs', e);
    } finally {
      setJobsLoading(false);
    }
  };

  const refreshTargets = async () => {
    try {
      const next = await api.getDastTargets(projectId);
      setTargets(next);
      putDastCache(projectId, { targets: next });
    } catch (e: any) {
      console.error('[dast] failed to load targets', e);
    }
  };

  useEffect(() => {
    let cancelled = false;
    // Seed from the session cache (covers a projectId switch while mounted; the useState
    // initializers cover a fresh remount). Only show skeletons when there's nothing cached;
    // a cache hit refreshes silently in the background.
    const cached = dastTabCache.get(projectId);
    if (cached) {
      setConfig(cached.config);
      setTargets(cached.targets);
      setJobs(cached.jobs);
      setLoading(false);
      setJobsLoading(false);
    } else {
      setLoading(true);
      setJobsLoading(true);
    }

    (async () => {
      try {
        await Promise.all([refreshConfig(), refreshJobs()]);
      } catch (e: any) {
        if (!cancelled) {
          toast({
            title: 'Failed to load DAST config',
            description: e?.message,
            variant: 'destructive',
          });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  // Realtime: scan_jobs (per-project) + project_dast_targets (per-project).
  useEffect(() => {
    if (!projectId) return;
    let realtimeOk = true;

    const channel = supabase
      .channel(`dast-${projectId}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'scan_jobs', filter: `project_id=eq.${projectId}` },
        () => {
          void refreshJobs();
          void refreshTargets();
        },
      )
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'project_dast_targets',
          filter: `project_id=eq.${projectId}`,
        },
        () => {
          void refreshTargets();
        },
      )
      .subscribe((status) => {
        if (status === 'TIMED_OUT' || status === 'CHANNEL_ERROR') {
          realtimeOk = false;
          if (!fallbackPollRef.current) {
            fallbackPollRef.current = setInterval(() => {
              void refreshJobs();
              void refreshTargets();
            }, 5_000);
          }
        }
      });

    const timeout = setTimeout(() => {
      if (!realtimeOk && !fallbackPollRef.current) {
        fallbackPollRef.current = setInterval(() => {
          void refreshJobs();
          void refreshTargets();
        }, 5_000);
      }
    }, 5_000);

    return () => {
      clearTimeout(timeout);
      supabase.removeChannel(channel);
      if (fallbackPollRef.current) {
        clearInterval(fallbackPollRef.current);
        fallbackPollRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  // Latest job per target_id, for the per-row scan status / auth-failed banner.
  const jobsByTargetId = useMemo(() => {
    const map: Record<string, DastJobDTO | undefined> = {};
    for (const job of jobs) {
      const tid = job.target_id;
      if (!tid) continue;
      if (!map[tid]) map[tid] = job;
    }
    return map;
  }, [jobs]);

  const editingTarget = useMemo(
    () => targets.find((t) => t.id === editingTargetId) ?? null,
    [targets, editingTargetId],
  );

  const authTarget = useMemo(
    () => targets.find((t) => t.id === authTargetId) ?? null,
    [targets, authTargetId],
  );

  // The enable toggle auto-saves (optimistic) — it's the only setting on this
  // tab, so an explicit Save button would be ceremony. Round-trips the
  // preserved profile/timeout/scope so they're never reset.
  const handleToggleEnabled = async (next: boolean) => {
    if (!canManage) return;
    const prev = config;
    setConfig({ ...config, enabled: next });
    setSaving(true);
    try {
      const saved = await api.saveDastConfig(projectId, {
        enabled: next,
        scan_profile: prev.scan_profile,
        scan_timeout_minutes: prev.scan_timeout_minutes,
        scope_config: prev.scope_config,
      });
      setConfig({
        enabled: !!saved.enabled,
        scan_profile: saved.scan_profile ?? 'auto',
        scan_timeout_minutes: saved.scan_timeout_minutes ?? 30,
        scope_config: saved.scope_config ?? {},
      });
      if (saved.targets) setTargets(saved.targets);
    } catch (e: any) {
      setConfig(prev);
      const detail = (e?.responseBody as any)?.detail || e?.message || 'Update failed';
      toast({ title: 'Failed to update DAST', description: detail, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const triggerScan = async (target: DastTargetDTO, engine: 'zap' | 'nuclei') => {
    if (!canManage) return;
    setScanningTargetId(target.id);
    try {
      await api.triggerDastScan(projectId, { target_id: target.id, engine });
      toast({
        title: `${engine === 'nuclei' ? 'Nuclei' : 'ZAP'} scan queued`,
        description: 'Findings will appear in the Findings tab once the scan completes.',
      });
      void refreshJobs();
      void refreshTargets();
    } catch (e: any) {
      const code = e?.message ?? 'failed';
      const detail = humanizeScanError(code);
      toast({ title: 'Failed to start scan', description: detail, variant: 'destructive' });
    } finally {
      setScanningTargetId(null);
    }
  };

  const handleScan = async (target: DastTargetDTO, engine: 'zap' | 'nuclei') => {
    // ActiveScanOptInDialog gates only on profile='full'. Auto / quick / api
    // are passive — no consent dialog. localStorage memo per target after the
    // first confirmation.
    if (config.scan_profile === 'full' && !hasActiveScanOptIn(target.id)) {
      setPendingScanEngine(engine);
      setActiveScanDialog(target);
      return;
    }
    await triggerScan(target, engine);
  };

  const handleConfirmActiveScan = async () => {
    if (!activeScanDialog) return;
    recordActiveScanOptIn(activeScanDialog.id);
    await triggerScan(activeScanDialog, pendingScanEngine);
  };

  const handleToggleTargetEnabled = async (target: DastTargetDTO, next: boolean) => {
    if (!canManage) return;
    setTargets((prev) => prev.map((t) => (t.id === target.id ? { ...t, enabled: next } : t)));
    try {
      const updated = await api.updateDastTarget(projectId, target.id, { enabled: next });
      setTargets((prev) => prev.map((t) => (t.id === target.id ? updated : t)));
    } catch (e: any) {
      setTargets((prev) => prev.map((t) => (t.id === target.id ? { ...t, enabled: !next } : t)));
      toast({ title: 'Failed to update target', description: e?.message, variant: 'destructive' });
    }
  };

  const handleConfirmDelete = async () => {
    if (!deletingTarget || !canManage) return;
    setDeleting(true);
    try {
      await api.deleteDastTarget(projectId, deletingTarget.id);
      setTargets((prev) => prev.filter((t) => t.id !== deletingTarget.id));
      toast({ title: 'Target removed' });
      setDeletingTarget(null);
    } catch (e: any) {
      toast({ title: 'Failed to remove target', description: e?.message, variant: 'destructive' });
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      {loading ? (
        <ScanningTabSkeleton />
      ) : (
        <>
          {/* DAST — title + description + enable toggle (header) / targets (body) / Add target (footer) */}
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 pt-6 pb-4 space-y-4">
              <div>
                <h3 className="text-lg font-semibold text-foreground">DAST</h3>
                <p className="text-sm text-foreground-secondary mt-1 max-w-2xl">
                  Dynamic application security testing scans your deployed app's live endpoints for
                  runtime vulnerabilities and cross-links them to reachable dependency CVEs.
                </p>
              </div>
              <button
                type="button"
                role="checkbox"
                aria-checked={config.enabled}
                aria-label="Enable dynamic scanning"
                onClick={() => handleToggleEnabled(!config.enabled)}
                disabled={!canManage || saving}
                className={cn(
                  'w-full rounded-lg border px-4 py-3 flex items-center gap-3 text-left transition-all disabled:cursor-not-allowed',
                  config.enabled
                    ? 'bg-background-card border-foreground/50 ring-1 ring-foreground/20'
                    : 'bg-black/20 border-border hover:border-foreground-secondary/30 hover:bg-black/30',
                )}
              >
                <div
                  className={cn(
                    'h-4 w-4 rounded-full border-2 flex-shrink-0 transition-colors',
                    config.enabled ? 'border-foreground bg-foreground' : 'border-foreground-secondary/50 bg-transparent',
                  )}
                  aria-hidden
                />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-foreground">Dynamic scanning</div>
                  <p className="text-xs text-foreground-secondary mt-0.5">
                    When on, add targets and run security scans against your deployed app. Off keeps
                    existing findings but stops new scans.
                  </p>
                </div>
                {saving ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-foreground-secondary" /> : null}
              </button>
            </div>

            {/* Targets + Add target collapse/expand with the toggle (no snap). */}
            <div
              className="grid transition-[grid-template-rows] duration-300 ease-out"
              style={{ gridTemplateRows: config.enabled ? '1fr' : '0fr' }}
            >
              <div className="overflow-hidden">
                <div className="px-6 pb-6">
                  <div className="rounded-lg border border-border overflow-hidden">
                    <DastTargetsList
                      targets={targets}
                      jobsByTargetId={jobsByTargetId}
                      scanningTargetId={scanningTargetId}
                      drainModeOn={false /* surfaced via 503 + per-row tooltip when triggered */}
                      canManage={canManage}
                      onScan={handleScan}
                      onEdit={(t) => setEditingTargetId(t.id)}
                      onConfigureAuth={(t) => setAuthTargetId(t.id)}
                      onToggleEnabled={handleToggleTargetEnabled}
                      onDelete={(t) => setDeletingTarget(t)}
                    />
                  </div>
                </div>
                {canManage ? (
                  <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                    <Button
                      variant="green"
                      onClick={() => setCreateDialogOpen(true)}
                      disabled={!config.enabled}
                    >
                      Add target
                    </Button>
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          {/* Scan history — bare table, same chrome as the Repository tab's activity table */}
          <div>
            <h3 className="text-base font-semibold text-foreground mb-3">Scan history</h3>
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              {jobsLoading ? (
                <TableSkeleton />
              ) : jobs.length === 0 ? (
                <div className="px-4 py-10 text-center">
                  <History className="h-6 w-6 text-foreground-muted mx-auto mb-2" />
                  <p className="text-sm text-foreground">No scans yet</p>
                  <p className="text-xs text-foreground-secondary mt-1 max-w-sm mx-auto">
                    Add a target and run a scan to see activity here.
                  </p>
                </div>
              ) : (
                <table className="w-full table-fixed">
                  <ScanHistoryColgroup />
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Target</th>
                      <th className="text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Status</th>
                      <th className="text-right text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Findings</th>
                      <th className="text-right text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Duration</th>
                      <th className="text-right text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {jobs.map((job) => (
                      <tr key={job.id} className="hover:bg-table-hover transition-colors">
                        <td className="px-4 py-3">
                          {job.target_url ? (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="block text-sm text-foreground truncate cursor-default">
                                  {job.target_url}
                                </span>
                              </TooltipTrigger>
                              <TooltipContent className="max-w-md break-all">{job.target_url}</TooltipContent>
                            </Tooltip>
                          ) : (
                            <span className="text-sm text-foreground-secondary">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {statusDot(job.status)}
                            <span className="text-sm font-medium text-foreground">{statusLabel(job.status)}</span>
                            {job.status === 'failed' && job.error ? (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
                                </TooltipTrigger>
                                <TooltipContent className="max-w-md">
                                  {job.error_category ? `${job.error_category}: ${job.error}` : job.error}
                                </TooltipContent>
                              </Tooltip>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground-secondary text-right tabular-nums">
                          {job.findings_count ?? '—'}
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground-secondary text-right tabular-nums">
                          {formatDuration(job.duration_seconds)}
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground-secondary text-right tabular-nums">
                          {formatRelative(job.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}

      <DastTargetEditDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        projectId={projectId}
        target={null}
        canManage={canManage}
        onSaved={(t) => {
          setTargets((prev) => [...prev, t]);
        }}
      />

      <DastTargetEditDialog
        open={editingTargetId !== null}
        onOpenChange={(o) => !o && setEditingTargetId(null)}
        projectId={projectId}
        target={editingTarget}
        canManage={canManage}
        onSaved={(t) => {
          setTargets((prev) => prev.map((p) => (p.id === t.id ? t : p)));
        }}
      />

      <DastTargetAuthDialog
        open={authTargetId !== null}
        onOpenChange={(o) => !o && setAuthTargetId(null)}
        projectId={projectId}
        target={authTarget}
        canManage={canManage}
        onChanged={() => void refreshTargets()}
      />

      <Dialog open={deletingTarget !== null} onOpenChange={(o) => !o && !deleting && setDeletingTarget(null)}>
        <DialogContent hideClose className="sm:max-w-[440px] bg-background p-0 gap-0 overflow-hidden flex flex-col">
          <div className="px-6 pt-6 pb-4">
            <DialogTitle>Delete target?</DialogTitle>
            <DialogDescription className="mt-1">
              This removes <span className="font-mono text-foreground">{deletingTarget?.label ?? deletingTarget?.target_url}</span> and all of its DAST findings. This can't be undone.
            </DialogDescription>
          </div>
          <DialogFooter className="px-6 py-4 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
            <Button
              variant="outline"
              className="h-8 rounded-lg px-3"
              disabled={deleting}
              onClick={() => setDeletingTarget(null)}
            >
              Cancel
            </Button>
            <Button
              variant="outline"
              className="h-8 rounded-lg px-3 relative text-destructive hover:text-destructive"
              disabled={deleting}
              onClick={handleConfirmDelete}
            >
              <span className={deleting ? 'invisible' : undefined}>Delete target</span>
              {deleting && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                </span>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ActiveScanOptInDialog
        open={activeScanDialog !== null}
        onOpenChange={(o) => !o && setActiveScanDialog(null)}
        targetUrl={activeScanDialog?.target_url ?? ''}
        onConfirm={handleConfirmActiveScan}
      />
    </div>
  );
}

/** Shared column widths so the scan-history table never shifts. */
function ScanHistoryColgroup() {
  return (
    <colgroup>
      <col className="w-[40%]" />
      <col className="w-[20%]" />
      <col className="w-[13%]" />
      <col className="w-[13%]" />
      <col className="w-[14%]" />
    </colgroup>
  );
}

function TableSkeleton() {
  return (
    <table className="w-full table-fixed">
      <ScanHistoryColgroup />
      <thead className="bg-background-card-header border-b border-border">
        <tr>
          {['Target', 'Status', 'Findings', 'Duration', 'Time'].map((h, i) => (
            <th
              key={h}
              className={`text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-4 py-2.5 ${i === 0 || i === 1 ? 'text-left' : 'text-right'}`}
            >
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-border">
        {[1, 2, 3].map((i) => (
          <tr key={i} className="animate-pulse">
            <td className="px-4 py-3"><div className="h-4 w-48 bg-muted rounded" /></td>
            <td className="px-4 py-3"><div className="h-4 w-20 bg-muted rounded" /></td>
            <td className="px-4 py-3"><div className="h-4 w-8 bg-muted rounded ml-auto" /></td>
            <td className="px-4 py-3"><div className="h-4 w-10 bg-muted rounded ml-auto" /></td>
            <td className="px-4 py-3"><div className="h-4 w-14 bg-muted rounded ml-auto" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ScanningTabSkeleton() {
  const pulse = 'bg-muted animate-pulse rounded';
  return (
    <div className="space-y-6">
      {/* Dynamic scanning card: header (title + toggle) / body / footer */}
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <div className="px-6 pt-6 pb-4 space-y-4">
          <div className="space-y-2">
            <div className={`h-5 w-16 ${pulse}`} />
            <div className={`h-3 w-96 max-w-full ${pulse}`} />
          </div>
          <div className="w-full rounded-lg border border-border bg-black/20 px-4 py-3 flex items-center gap-3">
            <div className={`h-4 w-4 rounded-full ${pulse}`} />
            <div className="flex-1 space-y-2">
              <div className={`h-4 w-36 ${pulse}`} />
              <div className={`h-3 w-72 max-w-full ${pulse}`} />
            </div>
          </div>
        </div>
        <div className="px-6 pb-6">
          <div className="rounded-lg border border-border px-6 py-10 flex justify-center">
            <div className={`h-4 w-56 ${pulse}`} />
          </div>
        </div>
        <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
          <div className={`h-8 w-24 rounded-lg ${pulse}`} />
        </div>
      </div>
    </div>
  );
}

function humanizeScanError(code: string): string {
  switch (code) {
    case 'project_concurrent_dast_blocked':
      return 'Another scan is already running for this project.';
    case 'org_concurrent_dast_cap':
      return 'Organization is at its concurrent scan cap. Wait for a scan to finish.';
    case 'target_disabled':
      return 'Target is disabled — enable it before scanning.';
    case 'target_not_found':
      return 'Target no longer exists.';
    case 'invalid_target_url':
      return 'Target URL became invalid (DNS / private host).';
    case 'dast_queue_paused':
      return 'DAST queue is paused for maintenance.';
    default:
      return 'See console for details.';
  }
}
