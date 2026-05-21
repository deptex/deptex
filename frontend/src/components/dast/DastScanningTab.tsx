import { useEffect, useMemo, useRef, useState } from 'react';
import { Loader2, AlertTriangle, ShieldCheck, Plus } from 'lucide-react';
import { Button } from '../ui/button';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Switch } from '../ui/switch';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { useToast } from '../../hooks/use-toast';
import { supabase } from '../../lib/supabase';
import {
  api,
  type DastConfigDTO,
  type DastJobDTO,
  type DastScanProfile,
  type DastScopeConfig,
  type DastTargetDTO,
} from '../../lib/api';
import { DastScopePanel } from './DastScopePanel';
import { DastTargetsList } from './DastTargetsList';
import { DastTargetEditDialog } from './DastTargetEditDialog';
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

const SCAN_PROFILE_LABELS: Record<DastScanProfile, string> = {
  auto: 'Auto (passive baseline)',
  quick: 'Quick (passive only, ~2 min)',
  full: 'Full (active fuzzing, ~20+ min)',
  api: 'API only (uses framework routes)',
};

const TIMEOUT_PRESETS = [10, 20, 30, 45, 60];

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
    case 'completed': return 'Done';
    case 'cancelled': return 'Cancelled';
    case 'failed': return 'Failed';
    default: return status;
  }
}

const EMPTY_STATE: TabState = {
  enabled: false,
  scan_profile: 'auto',
  scan_timeout_minutes: 30,
  scope_config: {},
};

export function DastScanningTab({ projectId, canManage }: DastScanningTabProps) {
  const { toast } = useToast();

  const [loading, setLoading] = useState(true);
  const [config, setConfig] = useState<TabState>(EMPTY_STATE);
  const [savedConfig, setSavedConfig] = useState<TabState | null>(null);
  const [saving, setSaving] = useState(false);

  const [targets, setTargets] = useState<DastTargetDTO[]>([]);
  const [jobs, setJobs] = useState<DastJobDTO[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);

  const [editingTargetId, setEditingTargetId] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [scanningTargetId, setScanningTargetId] = useState<string | null>(null);
  const [recheckingRuntimeTargetId, setRecheckingRuntimeTargetId] = useState<string | null>(null);
  const [activeScanDialog, setActiveScanDialog] = useState<DastTargetDTO | null>(null);
  // Engine chosen at the moment the active-scan opt-in dialog opened, replayed
  // when the user confirms it.
  const [pendingScanEngine, setPendingScanEngine] = useState<'zap' | 'nuclei'>('zap');

  const fallbackPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshConfig = async () => {
    const cfg = await api.getDastConfig(projectId);
    const normalized: TabState = {
      enabled: !!cfg.enabled,
      scan_profile: cfg.scan_profile ?? 'auto',
      scan_timeout_minutes: cfg.scan_timeout_minutes ?? 30,
      scope_config: cfg.scope_config ?? {},
    };
    setConfig(normalized);
    setSavedConfig(normalized);
    setTargets(cfg.targets ?? []);
  };

  const refreshJobs = async () => {
    try {
      const next = await api.getDastJobs(projectId, { limit: 25 });
      setJobs(next);
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
    } catch (e: any) {
      console.error('[dast] failed to load targets', e);
    }
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setJobsLoading(true);

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

  const isDirty = useMemo(() => {
    if (!savedConfig) return false;
    return (
      config.enabled !== savedConfig.enabled ||
      config.scan_profile !== savedConfig.scan_profile ||
      config.scan_timeout_minutes !== savedConfig.scan_timeout_minutes ||
      JSON.stringify(config.scope_config) !== JSON.stringify(savedConfig.scope_config)
    );
  }, [config, savedConfig]);

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

  const handleSave = async () => {
    if (!canManage) return;
    setSaving(true);
    try {
      const saved = await api.saveDastConfig(projectId, {
        enabled: config.enabled,
        scan_profile: config.scan_profile,
        scan_timeout_minutes: config.scan_timeout_minutes,
        scope_config: config.scope_config,
      });
      const normalized: TabState = {
        enabled: !!saved.enabled,
        scan_profile: saved.scan_profile ?? 'auto',
        scan_timeout_minutes: saved.scan_timeout_minutes ?? 30,
        scope_config: saved.scope_config ?? {},
      };
      setConfig(normalized);
      setSavedConfig(normalized);
      if (saved.targets) setTargets(saved.targets);
      toast({ title: 'DAST settings saved' });
    } catch (e: any) {
      const detail = (e?.responseBody as any)?.detail || e?.message || 'Save failed';
      toast({ title: 'Failed to save', description: detail, variant: 'destructive' });
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
        description: 'Findings will appear in the Security tab once the scan completes.',
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

  const handleRecheckRuntime = async (target: DastTargetDTO) => {
    setRecheckingRuntimeTargetId(target.id);
    try {
      const result = await api.recheckDastTargetRuntime(projectId, target.id);
      setTargets((prev) => prev.map((t) => (t.id === target.id ? result.target : t)));
      toast({
        title: 'Runtime re-probed',
        description: result.probe.probed
          ? `Detected as ${result.target.detected_runtime} (confidence ${Math.round(result.probe.confidence * 100)}%).`
          : 'Probe inconclusive — first scan will retry.',
      });
    } catch (e: any) {
      toast({
        title: 'Failed to re-probe runtime',
        description: e?.message,
        variant: 'destructive',
      });
    } finally {
      setRecheckingRuntimeTargetId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold text-foreground">Scanning</h2>
        <p className="text-sm text-foreground-secondary mt-1">
          Configure dynamic application security testing (DAST) for your deployed app. Scan
          multiple URLs, store credentials securely per target, and cross-link findings to known
          vulnerabilities in reachable dependencies.
        </p>
      </div>

      {loading ? (
        <ScanningTabSkeleton />
      ) : (
        <>
          <ProfileAndTimeoutCard
            config={config}
            savedConfig={savedConfig}
            isDirty={isDirty}
            saving={saving}
            canManage={canManage}
            onChange={setConfig}
            onSave={handleSave}
          />

          <Card title="Scope">
            <div className="p-4">
              <DastScopePanel
                value={config.scope_config}
                onChange={(scope) => setConfig((c) => ({ ...c, scope_config: scope }))}
                disabled={!canManage}
              />
            </div>
          </Card>

          <Card
            title="Targets"
            action={
              canManage ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCreateDialogOpen(true)}
                  disabled={!config.enabled}
                >
                  <Plus className="h-3.5 w-3.5 mr-2" /> Add target
                </Button>
              ) : null
            }
          >
            <DastTargetsList
              targets={targets}
              jobsByTargetId={jobsByTargetId}
              scanningTargetId={scanningTargetId}
              recheckingRuntimeTargetId={recheckingRuntimeTargetId}
              drainModeOn={false /* surfaced via 503 + per-row tooltip when triggered */}
              canManage={canManage}
              onScan={handleScan}
              onEdit={(t) => setEditingTargetId(t.id)}
              onRecheckRuntime={handleRecheckRuntime}
            />
          </Card>

          <Card title="Scan history">
            {jobsLoading ? (
              <div className="p-4 space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-10 bg-muted animate-pulse rounded" />
                ))}
              </div>
            ) : jobs.length === 0 ? (
              <div className="p-8 text-center">
                <p className="text-sm text-foreground-secondary">No scans yet.</p>
                <p className="text-xs text-foreground-secondary mt-1">
                  Add a target above and click Scan to run your first scan.
                </p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left text-xs font-medium text-foreground-secondary px-4 py-2.5">Target</th>
                    <th className="text-left text-xs font-medium text-foreground-secondary px-4 py-2.5">Profile</th>
                    <th className="text-left text-xs font-medium text-foreground-secondary px-4 py-2.5">Status</th>
                    <th className="text-right text-xs font-medium text-foreground-secondary px-4 py-2.5">Findings</th>
                    <th className="text-right text-xs font-medium text-foreground-secondary px-4 py-2.5">Duration</th>
                    <th className="text-right text-xs font-medium text-foreground-secondary px-4 py-2.5">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {jobs.map((job) => (
                    <tr key={job.id} className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3 text-sm text-foreground truncate max-w-xs" title={job.target_url ?? undefined}>
                        {job.target_url ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-sm text-foreground-secondary">
                        <Badge variant="outline" className="capitalize">{job.scan_profile ?? '—'}</Badge>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 text-sm text-foreground-secondary">
                          {statusDot(job.status)}
                          <span>{statusLabel(job.status)}</span>
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
          </Card>
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
        onDeleted={(id) => {
          setTargets((prev) => prev.filter((p) => p.id !== id));
        }}
      />

      <ActiveScanOptInDialog
        open={activeScanDialog !== null}
        onOpenChange={(o) => !o && setActiveScanDialog(null)}
        targetUrl={activeScanDialog?.target_url ?? ''}
        onConfirm={handleConfirmActiveScan}
      />
    </div>
  );
}

interface CardProps {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}
function Card({ title, action, children }: CardProps) {
  return (
    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}

interface ProfileAndTimeoutCardProps {
  config: TabState;
  savedConfig: TabState | null;
  isDirty: boolean;
  saving: boolean;
  canManage: boolean;
  onChange: (next: TabState) => void;
  onSave: () => void;
}
function ProfileAndTimeoutCard({ config, savedConfig, isDirty, saving, canManage, onChange, onSave }: ProfileAndTimeoutCardProps) {
  return (
    <Card title="Profile & timeout">
      <div className="p-4 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <Label className="text-sm text-foreground">DAST enabled</Label>
            <p className="text-xs text-foreground-secondary mt-0.5">
              Required to add targets and trigger scans. Disabling preserves existing findings.
            </p>
          </div>
          <Switch
            checked={config.enabled}
            onCheckedChange={(v) => onChange({ ...config, enabled: v })}
            disabled={!canManage}
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-xl">
          <div>
            <Label className="text-sm text-foreground">Scan profile</Label>
            <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
              Auto runs a passive baseline. Full activates fuzzing — gated by an opt-in dialog.
            </p>
            <Select
              value={config.scan_profile}
              onValueChange={(v) => onChange({ ...config, scan_profile: v as DastScanProfile })}
              disabled={!canManage}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(SCAN_PROFILE_LABELS) as DastScanProfile[]).map((p) => (
                  <SelectItem key={p} value={p}>{SCAN_PROFILE_LABELS[p]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-sm text-foreground">Timeout</Label>
            <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
              Hard limit on scan duration (5–60 minutes).
            </p>
            <Select
              value={String(config.scan_timeout_minutes)}
              onValueChange={(v) => onChange({ ...config, scan_timeout_minutes: Number(v) })}
              disabled={!canManage}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TIMEOUT_PRESETS.map((m) => (
                  <SelectItem key={m} value={String(m)}>{m} minutes</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>
      <div className="px-4 py-3 border-t border-border bg-background-card-header flex items-center justify-between">
        <p className="text-xs text-foreground-secondary">
          {savedConfig?.enabled
            ? <span className="inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" /> Active for this project</span>
            : <span className="inline-flex items-center gap-1 text-foreground-secondary"><AlertTriangle className="h-3.5 w-3.5" /> Disabled — saved scans won't run automatically</span>}
        </p>
        {canManage && (
          <Button variant="outline" size="sm" onClick={onSave} disabled={!isDirty || saving}>
            {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" /> : null}
            Save
          </Button>
        )}
      </div>
    </Card>
  );
}

function ScanningTabSkeleton() {
  const pulse = 'bg-muted animate-pulse rounded';
  return (
    <div className="space-y-6">
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <div className={`h-4 w-20 ${pulse}`} />
        </div>
        <div className="p-4 space-y-4">
          <div className={`h-10 w-full max-w-xl ${pulse}`} />
          <div className={`h-10 w-full max-w-xl ${pulse}`} />
        </div>
      </div>
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <div className={`h-4 w-24 ${pulse}`} />
          <div className={`h-8 w-24 ${pulse}`} />
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
