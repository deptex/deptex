import { useState, useEffect, useCallback } from 'react';
import { Clock, Shield, Loader2, PauseCircle, PlayCircle, Info, History } from 'lucide-react';
import { api, type SlaPolicy, type SlaPolicyChange, type OrganizationAssetTier } from '../../lib/api';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Switch } from '../ui/switch';
import { Slider } from '../ui/slider';
import { Label } from '../ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
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

export default function SLAConfigurationSection({ organizationId }: SLAConfigurationSectionProps) {
  const { toast } = useToast();
  const [policies, setPolicies] = useState<SlaPolicy[]>([]);
  const [slaPausedAt, setSlaPausedAt] = useState<string | null>(null);
  const [assetTiers, setAssetTiers] = useState<OrganizationAssetTier[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [changes, setChanges] = useState<SlaPolicyChange[]>([]);
  const [loadingChanges, setLoadingChanges] = useState(false);
  const [activeTierTab, setActiveTierTab] = useState<string>('default');

  const load = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    try {
      const [slaRes, tiersRes] = await Promise.all([
        api.getSlaPolicies(organizationId),
        api.getOrganizationAssetTiers(organizationId),
      ]);
      setPolicies(slaRes.policies);
      setSlaPausedAt(slaRes.sla_paused_at);
      setAssetTiers(tiersRes);
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

  useEffect(() => {
    if (!organizationId) return;
    setLoadingChanges(true);
    api.getSlaPolicyChanges(organizationId)
      .then(setChanges)
      .catch(console.error)
      .finally(() => setLoadingChanges(false));
  }, [organizationId]);

  const policiesByTier = policies.reduce((acc, p) => {
    const key = p.asset_tier_id ?? 'default';
    if (!acc[key]) acc[key] = [];
    acc[key].push(p);
    return acc;
  }, {} as Record<string, SlaPolicy[]>);

  const handleEnable = async () => {
    if (!organizationId) return;
    setSaving(true);
    try {
      const res = await api.enableSlaPolicies(organizationId);
      setPolicies(res.policies);
      toast({ title: 'Security SLAs enabled', description: `Backfilled ${res.backfill_updated} existing vulnerabilities.` });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleSave = async (tierKey: string, rows: Array<{ severity: string; max_hours: number; warning_threshold_percent: number; enabled: boolean }>) => {
    if (!organizationId) return;
    setSaving(true);
    try {
      const assetTierId = tierKey === 'default' ? null : tierKey;
      const policiesPayload = rows.map((r) => ({
        severity: r.severity,
        asset_tier_id: assetTierId,
        max_hours: r.max_hours,
        warning_threshold_percent: r.warning_threshold_percent,
        enabled: r.enabled,
      }));
      const res = await api.updateSlaPolicies(organizationId, policiesPayload);
      setPolicies(res.policies);
      toast({ title: 'SLA policies saved' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleResetToDefaults = (tierKey: string) => {
    const rows = SEVERITIES.map((sev) => ({
      severity: sev,
      max_hours: DEFAULT_HOURS[sev],
      warning_threshold_percent: 75,
      enabled: true,
    }));
    handleSave(tierKey, rows);
  };

  const handlePause = async () => {
    if (!organizationId) return;
    setPausing(true);
    try {
      const res = await api.pauseSlaPolicies(organizationId);
      setSlaPausedAt(res.sla_paused_at);
      toast({ title: 'SLA timers paused' });
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
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
    } catch (err: any) {
      toast({ title: 'Error', description: err.message, variant: 'destructive' });
    } finally {
      setPausing(false);
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
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Security SLAs
            </CardTitle>
            <CardDescription>
              Define maximum remediation timeframes per severity. Timers start when a vulnerability is first detected. Aegis will prioritize fixes approaching their SLA deadline.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-lg border border-border bg-muted/30 p-6 flex flex-col items-center justify-center gap-4">
              <Shield className="h-12 w-12 text-muted-foreground" />
              <p className="text-sm text-muted-foreground text-center max-w-md">
                Enable Security SLAs to set deadlines per severity (e.g. critical 48h, high 7d) and track compliance across all projects.
              </p>
              <Button onClick={handleEnable} disabled={saving}>
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Enable Security SLAs
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const tierTabs = [
    { key: 'default', label: 'Default (org-wide)' },
    ...assetTiers.map((t) => ({ key: t.id, label: t.name })),
  ];

  return (
    <TooltipProvider>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  Security SLAs
                </CardTitle>
                <CardDescription>
                  SLAs define maximum remediation timeframes per severity. Timers start when a vulnerability is first detected.
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
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
              </div>
            </div>
            {slaPausedAt && (
              <p className="text-sm text-amber-600 dark:text-amber-500 flex items-center gap-1">
                <Info className="h-4 w-4" />
                SLA timers are paused. Resume to shift all deadlines by the pause duration.
              </p>
            )}
          </CardHeader>
          <CardContent>
            <Tabs value={activeTierTab} onValueChange={setActiveTierTab}>
              <TabsList className="mb-4">
                {tierTabs.map((tab) => (
                  <TabsTrigger key={tab.key} value={tab.key}>
                    {tab.label}
                  </TabsTrigger>
                ))}
              </TabsList>
              {tierTabs.map((tab) => {
                const tierPolicies = policiesByTier[tab.key] ?? [];
                const rows = SEVERITIES.map((sev) => {
                  const p = tierPolicies.find((x) => x.severity === sev);
                  return {
                    severity: sev,
                    id: p?.id,
                    max_hours: p?.max_hours ?? DEFAULT_HOURS[sev],
                    warning_threshold_percent: p?.warning_threshold_percent ?? 75,
                    enabled: p?.enabled ?? true,
                  };
                });
                return (
                  <TabsContent key={tab.key} value={tab.key} className="space-y-4">
                    <div className="flex justify-end">
                      <Button variant="ghost" size="sm" onClick={() => handleResetToDefaults(tab.key)}>
                        Reset to defaults
                      </Button>
                    </div>
                    <div className="space-y-4">
                      {rows.map((row) => (
                        <div
                          key={row.severity}
                          className="flex flex-wrap items-center gap-4 rounded-lg border border-border p-4"
                        >
                          <Badge variant={row.severity === 'critical' ? 'destructive' : row.severity === 'high' ? 'default' : 'secondary'}>
                            {row.severity}
                          </Badge>
                          <div className="flex items-center gap-2">
                            <Label className="text-sm whitespace-nowrap">Max hours</Label>
                            <Input
                              type="number"
                              min={1}
                              value={row.max_hours}
                              onChange={(e) => {
                                const v = parseInt(e.target.value, 10);
                                if (!isNaN(v) && v > 0) {
                                  const newRows = rows.map((r) =>
                                    r.severity === row.severity ? { ...r, max_hours: v } : r
                                  );
                                  handleSave(tab.key, newRows.map((r) => ({ severity: r.severity, max_hours: r.max_hours, warning_threshold_percent: r.warning_threshold_percent, enabled: r.enabled })));
                                }
                              }}
                              className="w-24"
                            />
                            <span className="text-xs text-muted-foreground">{formatHours(row.max_hours)}</span>
                          </div>
                          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="text-sm whitespace-nowrap">Warning at %</span>
                              </TooltipTrigger>
                              <TooltipContent>Alert when this percentage of the SLA time has elapsed (e.g. 75% = 36h for 48h critical).</TooltipContent>
                            </Tooltip>
                            <Slider
                              value={[row.warning_threshold_percent]}
                              min={10}
                              max={95}
                              step={5}
                              onValueCommit={([v]) => {
                                const newRows = rows.map((r) =>
                                  r.severity === row.severity ? { ...r, warning_threshold_percent: v } : r
                                );
                                handleSave(tab.key, newRows.map((r) => ({ severity: r.severity, max_hours: r.max_hours, warning_threshold_percent: r.warning_threshold_percent, enabled: r.enabled })));
                              }}
                              className="w-24"
                            />
                            <span className="text-xs text-muted-foreground w-8">{row.warning_threshold_percent}%</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Switch
                              checked={row.enabled}
                              onCheckedChange={(checked) => {
                                const newRows = rows.map((r) =>
                                  r.severity === row.severity ? { ...r, enabled: checked } : r
                                );
                                handleSave(tab.key, newRows.map((r) => ({ severity: r.severity, max_hours: r.max_hours, warning_threshold_percent: r.warning_threshold_percent, enabled: r.enabled })));
                              }}
                            />
                            <span className="text-sm text-muted-foreground">Enabled</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </TabsContent>
                );
              })}
            </Tabs>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Change history
            </CardTitle>
            <CardDescription>Recent SLA policy and pause/resume changes.</CardDescription>
          </CardHeader>
          <CardContent>
            {loadingChanges ? (
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            ) : changes.length === 0 ? (
              <p className="text-sm text-muted-foreground">No changes yet.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {changes.slice(0, 20).map((c) => (
                  <li key={c.id} className="flex justify-between gap-4 py-1 border-b border-border/50 last:border-0">
                    <span className="font-medium capitalize">{c.change_type}</span>
                    <span className="text-muted-foreground">{new Date(c.created_at).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </TooltipProvider>
  );
}
