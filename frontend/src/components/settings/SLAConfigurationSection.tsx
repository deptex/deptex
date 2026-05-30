import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, Shield, Loader2, PauseCircle, PlayCircle, Info, Trash2 } from 'lucide-react';
import { api, type SlaPolicy } from '../../lib/api';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Switch } from '../ui/switch';
import { Slider } from '../ui/slider';
import { Badge } from '../ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog';
import { useToast } from '../../hooks/use-toast';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '../ui/tooltip';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const DEFAULT_HOURS: Record<string, number> = {
  critical: 48,
  high: 168,
  medium: 720,
  low: 2160,
};

type SlaRow = {
  severity: string;
  id?: string;
  max_hours: number;
  warning_threshold_percent: number;
  enabled: boolean;
};

interface SLAConfigurationSectionProps {
  organizationId: string;
}

function formatHours(h: number): string {
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d`;
  const m = Math.floor(d / 30);
  return `${m}mo`;
}

function rowsFromPolicies(policies: SlaPolicy[]): SlaRow[] {
  return SEVERITIES.map((sev) => {
    const p = policies.find((x) => x.severity === sev);
    return {
      severity: sev,
      id: p?.id,
      max_hours: p?.max_hours ?? DEFAULT_HOURS[sev],
      warning_threshold_percent: p?.warning_threshold_percent ?? 75,
      enabled: p?.enabled ?? true,
    };
  });
}

export default function SLAConfigurationSection({ organizationId }: SLAConfigurationSectionProps) {
  const { toast } = useToast();
  const navigate = useNavigate();
  const [policies, setPolicies] = useState<SlaPolicy[]>([]);
  const [slaPausedAt, setSlaPausedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);
  /** Draft rows for the (single, flat) policy table. Only saved when user clicks Save. */
  const [draftRows, setDraftRows] = useState<SlaRow[]>([]);

  const load = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    try {
      const slaRes = await api.getSlaPolicies(organizationId);
      const pols = slaRes.policies ?? [];
      setPolicies(pols);
      setSlaPausedAt(slaRes.sla_paused_at);
      setDraftRows(rowsFromPolicies(pols));
    } catch (err) {
      console.error('Failed to load SLA policies:', err);
      toast({ title: 'Failed to load SLA settings', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [organizationId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const handleEnable = async () => {
    if (!organizationId) return;
    setSaving(true);
    try {
      const res = await api.enableSlaPolicies(organizationId);
      setPolicies(res.policies);
      setDraftRows(rowsFromPolicies(res.policies));
      toast({ title: 'Security SLAs enabled', description: `Backfilled ${res.backfill_updated} existing vulnerabilities.` });
    } catch (err) {
      console.error('Failed to enable SLAs:', err);
      toast({ title: 'Error', description: 'Failed to enable Security SLAs', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const updateDraft = (updater: (rows: SlaRow[]) => SlaRow[]) => {
    setDraftRows((prev) => updater(prev));
  };

  const handleSave = async () => {
    if (!organizationId) return;
    if (!draftRows.length) return;
    setSaving(true);
    try {
      const policiesPayload = draftRows.map((r) => ({
        severity: r.severity,
        max_hours: r.max_hours,
        warning_threshold_percent: r.warning_threshold_percent,
        enabled: r.enabled,
      }));
      const res = await api.updateSlaPolicies(organizationId, policiesPayload);
      setPolicies(res.policies);
      setDraftRows(rowsFromPolicies(res.policies));
      toast({ title: 'SLA policies saved' });
    } catch (err) {
      console.error('Failed to save SLA policies:', err);
      toast({ title: 'Error', description: 'Failed to save SLA policies', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleResetToDefaults = () => {
    const rows: SlaRow[] = SEVERITIES.map((sev) => ({
      severity: sev,
      max_hours: DEFAULT_HOURS[sev],
      warning_threshold_percent: 75,
      enabled: true,
    }));
    updateDraft(() => rows);
  };

  const handlePause = async () => {
    if (!organizationId) return;
    setPausing(true);
    try {
      const res = await api.pauseSlaPolicies(organizationId);
      setSlaPausedAt(res.sla_paused_at);
      toast({ title: 'SLA timers paused' });
    } catch (err) {
      console.error('Failed to pause SLAs:', err);
      toast({ title: 'Error', description: 'Failed to pause SLA timers', variant: 'destructive' });
    } finally {
      setPausing(false);
    }
  };

  const handleResume = async () => {
    if (!organizationId) return;
    setPausing(true);
    try {
      await api.resumeSlaPolicies(organizationId);
      setSlaPausedAt(null);
      toast({ title: 'SLA timers resumed' });
    } catch (err) {
      console.error('Failed to resume SLAs:', err);
      toast({ title: 'Error', description: 'Failed to resume SLA timers', variant: 'destructive' });
    } finally {
      setPausing(false);
    }
  };

  const handleDisable = async () => {
    if (!organizationId) return;
    setDisabling(true);
    setShowDisableConfirm(false);
    try {
      await api.disableSlaPolicies(organizationId);
      setPolicies([]);
      setDraftRows([]);
      setSlaPausedAt(null);
      toast({ title: 'Security SLAs disabled', description: 'You can re-enable at any time to start tracking again.' });
    } catch (err) {
      console.error('Failed to disable SLAs:', err);
      toast({ title: 'Error', description: 'Failed to disable SLAs', variant: 'destructive' });
    } finally {
      setDisabling(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (policies.length === 0) {
    return (
      <div className="space-y-8">
        <div>
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Security SLAs
          </h2>
          <p className="text-sm text-muted-foreground mt-1 max-w-xl">
            Define maximum remediation timeframes per severity. Timers start when a vulnerability is first detected. Aegis will prioritize fixes approaching their SLA deadline.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-muted/20 p-8 flex flex-col items-center justify-center gap-4">
          <Shield className="h-12 w-12 text-muted-foreground" />
          <p className="text-sm text-muted-foreground text-center max-w-md">
            Enable Security SLAs to set deadlines per severity (e.g. critical 48h, high 7d) and track compliance across all projects.
          </p>
          <Button onClick={handleEnable} disabled={saving}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Enable Security SLAs
          </Button>
        </div>
      </div>
    );
  }

  return (
    <TooltipProvider>
      <div className="space-y-8">
        {/* Header: title, description, severity vs Depscore note, actions */}
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Security SLAs
              </h2>
              <p className="text-sm text-muted-foreground mt-1">
                SLAs define maximum remediation timeframes per severity. Timers start when a vulnerability is first detected.
              </p>
              <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                <Info className="h-3.5 w-3.5 shrink-0" />
                Based on severity (critical/high/medium/low) for audit and compliance (e.g. SOC 2, PCI DSS). For prioritization by actual risk in your codebase, use Depscore on the Security tab.
              </p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {slaPausedAt ? (
                <Button variant="outline" size="sm" onClick={handleResume} disabled={pausing}>
                  {pausing ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
                  Resume timers
                </Button>
              ) : (
                <Button variant="outline" size="sm" onClick={handlePause} disabled={pausing}>
                  {pausing ? <Loader2 className="h-4 w-4 animate-spin" /> : <PauseCircle className="h-4 w-4" />}
                  Pause timers
                </Button>
              )}
              <Button variant="outline" size="sm" className="text-destructive hover:text-destructive hover:bg-destructive/10" onClick={() => setShowDisableConfirm(true)} disabled={disabling}>
                {disabling ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                Disable SLAs
              </Button>
            </div>
          </div>
          {slaPausedAt && (
            <p className="text-sm text-amber-600 dark:text-amber-500 flex items-center gap-1">
              <Info className="h-4 w-4" />
              SLA timers are paused. Resume to shift all deadlines by the pause duration.
            </p>
          )}
        </div>

        {/* Flat single-table layout: one row per severity */}
        <div className="space-y-4">
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[120px]">Severity</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Max hours</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Warning at %</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[100px]">Enabled</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {draftRows.map((row) => (
                    <tr key={row.severity} className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3">
                        <Badge variant={row.severity === 'critical' ? 'destructive' : row.severity === 'high' ? 'default' : 'secondary'}>
                          {row.severity}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Input
                            type="number"
                            min={1}
                            value={row.max_hours}
                            onChange={(e) => {
                              const v = parseInt(e.target.value, 10);
                              if (!isNaN(v) && v > 0) {
                                updateDraft((r) =>
                                  r.map((x) => (x.severity === row.severity ? { ...x, max_hours: v } : x))
                                );
                              }
                            }}
                            className="w-20 h-8 text-sm"
                          />
                          <span className="text-xs text-muted-foreground">{formatHours(row.max_hours)}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 max-w-[200px]">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="text-xs text-muted-foreground shrink-0">Alert when % of time elapsed</span>
                            </TooltipTrigger>
                            <TooltipContent>Alert when this percentage of the SLA time has elapsed (e.g. 75% = 36h for 48h critical).</TooltipContent>
                          </Tooltip>
                          <Slider
                            value={row.warning_threshold_percent}
                            min={10}
                            max={95}
                            step={5}
                            onValueChange={(v) => {
                              updateDraft((r) =>
                                r.map((x) => (x.severity === row.severity ? { ...x, warning_threshold_percent: v } : x))
                              );
                            }}
                            className="flex-1"
                          />
                          <span className="text-xs text-muted-foreground w-8">{row.warning_threshold_percent}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={row.enabled}
                            onCheckedChange={(checked) => {
                              updateDraft((r) =>
                                r.map((x) => (x.severity === row.severity ? { ...x, enabled: checked } : x))
                              );
                            }}
                          />
                          <span className="text-sm text-muted-foreground">{row.enabled ? 'On' : 'Off'}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={handleResetToDefaults}>
              Reset to defaults
            </Button>
            <Button size="sm" onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Save changes
            </Button>
          </div>
        </div>

        <Dialog open={showDisableConfirm} onOpenChange={setShowDisableConfirm}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Disable Security SLAs?</DialogTitle>
              <DialogDescription>
                All SLA policies will be removed and existing SLA timers cleared. You can re-enable at any time; re-enabling will backfill deadlines for current vulnerabilities.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setShowDisableConfirm(false)}>Cancel</Button>
              <Button variant="destructive" onClick={handleDisable} disabled={disabling}>
                {disabling ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Disable SLAs
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}
