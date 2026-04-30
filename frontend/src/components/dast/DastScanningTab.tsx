import { useEffect, useRef, useState } from 'react';
import { Loader2, Globe, AlertTriangle, ShieldCheck, Play } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
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
} from '../../lib/api';

interface DastScanningTabProps {
  projectId: string;
  /** RBAC: false hides every write affordance. */
  canManage: boolean;
}

const SCAN_PROFILE_LABELS: Record<DastScanProfile, string> = {
  auto: 'Auto (recommended)',
  quick: 'Quick (passive only, ~2 min)',
  full: 'Full (active, ~20+ min)',
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

export function DastScanningTab({ projectId, canManage }: DastScanningTabProps) {
  const { toast } = useToast();

  const [loading, setLoading] = useState(true);
  const [config, setConfig] = useState<DastConfigDTO>({
    enabled: false,
    target_url: '',
    scan_profile: 'auto',
    scan_timeout_minutes: 30,
  });
  const [savedConfig, setSavedConfig] = useState<DastConfigDTO | null>(null);
  const [saving, setSaving] = useState(false);
  const [scanning, setScanning] = useState(false);

  const [jobs, setJobs] = useState<DastJobDTO[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);

  const fallbackPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshJobs = async () => {
    try {
      const next = await api.getDastJobs(projectId);
      setJobs(next);
    } catch (e: any) {
      console.error('[dast] failed to load jobs', e);
    } finally {
      setJobsLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setJobsLoading(true);

    (async () => {
      try {
        const [cfg] = await Promise.all([
          api.getDastConfig(projectId),
          refreshJobs(),
        ]);
        if (cancelled) return;
        const normalized: DastConfigDTO = {
          enabled: cfg.enabled,
          target_url: cfg.target_url ?? '',
          scan_profile: cfg.scan_profile ?? 'auto',
          scan_timeout_minutes: cfg.scan_timeout_minutes ?? 30,
        };
        setConfig(normalized);
        setSavedConfig(normalized);
      } catch (e: any) {
        if (!cancelled) {
          toast({ title: 'Failed to load DAST config', description: e?.message, variant: 'destructive' });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  // Realtime: subscribe to scan_jobs changes for this project. RLS scopes
  // server-side, but we belt-and-brace by also filtering on type='dast' in the
  // refresh query (jobs API already does this).
  useEffect(() => {
    if (!projectId) return;
    let realtimeOk = true;

    const channel = supabase
      .channel(`dast-jobs-${projectId}`)
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'scan_jobs',
          filter: `project_id=eq.${projectId}`,
        },
        () => { void refreshJobs(); }
      )
      .subscribe((status) => {
        if (status === 'TIMED_OUT' || status === 'CHANNEL_ERROR') {
          realtimeOk = false;
          if (!fallbackPollRef.current) {
            fallbackPollRef.current = setInterval(refreshJobs, 5_000);
          }
        }
      });

    const timeout = setTimeout(() => {
      if (!realtimeOk && !fallbackPollRef.current) {
        fallbackPollRef.current = setInterval(refreshJobs, 5_000);
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

  const isDirty =
    savedConfig !== null && (
      config.enabled !== savedConfig.enabled ||
      (config.target_url ?? '') !== (savedConfig.target_url ?? '') ||
      config.scan_profile !== savedConfig.scan_profile ||
      config.scan_timeout_minutes !== savedConfig.scan_timeout_minutes
    );

  const canScan = canManage && savedConfig?.enabled === true && !!savedConfig?.target_url && !scanning;
  const hasActiveJob = jobs.some((j) => j.status === 'queued' || j.status === 'processing');

  const handleSave = async () => {
    if (!canManage) return;
    setSaving(true);
    try {
      const saved = await api.saveDastConfig(projectId, {
        enabled: config.enabled,
        target_url: config.target_url ? config.target_url.trim() : null,
        scan_profile: config.scan_profile,
        scan_timeout_minutes: config.scan_timeout_minutes,
      });
      const normalized: DastConfigDTO = {
        enabled: saved.enabled,
        target_url: saved.target_url ?? '',
        scan_profile: saved.scan_profile ?? 'auto',
        scan_timeout_minutes: saved.scan_timeout_minutes ?? 30,
      };
      setConfig(normalized);
      setSavedConfig(normalized);
      toast({ title: 'DAST settings saved' });
    } catch (e: any) {
      const detail = e?.detail || e?.message || 'Save failed';
      toast({ title: 'Failed to save', description: detail, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleScan = async () => {
    if (!canManage) return;
    setScanning(true);
    try {
      await api.triggerDastScan(projectId);
      toast({ title: 'Scan queued', description: 'Findings will appear in the Security tab once the scan completes.' });
      void refreshJobs();
    } catch (e: any) {
      const detail = e?.detail || e?.message || 'Failed to start scan';
      toast({ title: 'Failed to start scan', description: detail, variant: 'destructive' });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold text-foreground">Scanning</h2>
        <p className="text-sm text-foreground-secondary mt-1">
          Configure dynamic application security testing (DAST) for your deployed app.
          Findings cross-link to known vulnerabilities in reachable dependencies.
        </p>
      </div>

      {loading ? (
        <ScanningTabSkeleton />
      ) : (
        <>
          {/* Target configuration card */}
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <h3 className="text-sm font-semibold text-foreground">Target</h3>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <Label className="text-sm text-foreground">DAST enabled</Label>
                  <p className="text-xs text-foreground-secondary mt-0.5">
                    Required to trigger scans. Disabling preserves existing findings.
                  </p>
                </div>
                <Switch
                  checked={config.enabled}
                  onCheckedChange={(v) => setConfig((c) => ({ ...c, enabled: v }))}
                  disabled={!canManage}
                />
              </div>

              <div>
                <Label htmlFor="dast-target-url" className="text-sm text-foreground">Target URL</Label>
                <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
                  Public-facing URL of the deployed app (staging recommended).
                  Loopback, RFC1918, and Fly internal hosts are blocked.
                </p>
                <div className="flex items-center gap-2 max-w-xl">
                  <Globe className="h-4 w-4 text-foreground-secondary shrink-0" />
                  <Input
                    id="dast-target-url"
                    type="url"
                    value={config.target_url ?? ''}
                    onChange={(e) => setConfig((c) => ({ ...c, target_url: e.target.value }))}
                    placeholder="https://staging.example.com"
                    disabled={!canManage}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-xl">
                <div>
                  <Label className="text-sm text-foreground">Scan profile</Label>
                  <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
                    Auto picks API-scan when framework routes are detected, otherwise a passive baseline.
                  </p>
                  <Select
                    value={config.scan_profile}
                    onValueChange={(v) => setConfig((c) => ({ ...c, scan_profile: v as DastScanProfile }))}
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
                    onValueChange={(v) => setConfig((c) => ({ ...c, scan_timeout_minutes: Number(v) }))}
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
            <div className="px-4 py-3 border-t border-border bg-black/20 flex items-center justify-between">
              <p className="text-xs text-foreground-secondary">
                {savedConfig?.enabled
                  ? <span className="inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" /> Active for this project</span>
                  : <span className="inline-flex items-center gap-1 text-foreground-secondary"><AlertTriangle className="h-3.5 w-3.5" /> Disabled — saved scans won't run automatically</span>}
              </p>
              {canManage && (
                <Button variant="outline" size="sm" onClick={handleSave} disabled={!isDirty || saving}>
                  {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" /> : null}
                  Save
                </Button>
              )}
            </div>
          </div>

          {/* Scan now card */}
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <h3 className="text-sm font-semibold text-foreground">Manual scan</h3>
              {canManage && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleScan}
                        disabled={!canScan || hasActiveJob}
                      >
                        {scanning ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                        ) : (
                          <Play className="h-3.5 w-3.5 mr-2" />
                        )}
                        Scan now
                      </Button>
                    </span>
                  </TooltipTrigger>
                  {!canScan ? (
                    <TooltipContent>
                      {!savedConfig?.enabled
                        ? 'Enable DAST and save before scanning'
                        : !savedConfig?.target_url
                          ? 'Save a target URL before scanning'
                          : hasActiveJob
                            ? 'Another scan is already in progress'
                            : 'Save settings before scanning'}
                    </TooltipContent>
                  ) : null}
                </Tooltip>
              )}
            </div>
            <div className="p-4">
              <p className="text-xs text-foreground-secondary">
                Triggers an out-of-band scan. The depscanner worker boots a Fly machine and reports back to the Security tab on completion.
                Concurrency: 1 active scan per project, 3 across the org.
              </p>
            </div>
          </div>

          {/* History */}
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <h3 className="text-sm font-semibold text-foreground">Scan history</h3>
            </div>
            {jobsLoading ? (
              <div className="p-4 space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-10 bg-muted animate-pulse rounded" />
                ))}
              </div>
            ) : jobs.length === 0 ? (
              <div className="p-8 text-center">
                <p className="text-sm text-foreground-secondary">No scans yet.</p>
                <p className="text-xs text-foreground-secondary mt-1">Save a target URL above and click Scan now to run your first scan.</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-background-subtle/30 border-b border-border">
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
                              <TooltipContent className="max-w-md">{job.error}</TooltipContent>
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
        </>
      )}
    </div>
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
