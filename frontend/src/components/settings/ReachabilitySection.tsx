import { useCallback, useEffect, useState } from 'react';
import {
  Info, Loader2, Sparkles, ShieldAlert, DollarSign,
} from 'lucide-react';
import {
  api,
  type ReachabilitySettings,
} from '../../lib/api';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Switch } from '../ui/switch';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../ui/select';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import { DEFAULT_GENERATOR_MONTHLY_BUDGET_USD } from '../../lib/taint-engine-defaults';
import GeneratedRulesTable from './GeneratedRulesTable';

interface ReachabilitySectionProps {
  organizationId: string;
  canManage: boolean;
}

type Provider = 'anthropic' | 'openai' | 'google';

interface ProviderModelOption {
  value: string;
  label: string;
  // Estimated USD cost for ~6k input + 1.5k output tokens — a rough rule generation budget.
  // Used purely as decorative cost guidance in the picker.
  estimatedCost: number;
}

const PROVIDER_MODELS: Record<Provider, ProviderModelOption[]> = {
  anthropic: [
    { value: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6', estimatedCost: 0.04 },
    { value: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5', estimatedCost: 0.005 },
    { value: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet', estimatedCost: 0.04 },
  ],
  openai: [
    { value: 'gpt-4o', label: 'GPT-4o', estimatedCost: 0.04 },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini', estimatedCost: 0.003 },
    { value: 'o1-mini', label: 'o1 Mini', estimatedCost: 0.015 },
  ],
  google: [
    { value: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', estimatedCost: 0.003 },
    { value: 'gemini-1.5-pro', label: 'Gemini 1.5 Pro', estimatedCost: 0.035 },
  ],
};

const SEVERITY_OPTIONS: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];

const SEVERITY_LABELS: Record<typeof SEVERITY_OPTIONS[number], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

function modelOptionsFor(provider: Provider): ProviderModelOption[] {
  return PROVIDER_MODELS[provider] ?? [];
}

function findModelLabel(provider: Provider, model: string): string {
  return modelOptionsFor(provider).find((m) => m.value === model)?.label ?? model;
}

function findModelCost(provider: Provider, model: string): number | null {
  return modelOptionsFor(provider).find((m) => m.value === model)?.estimatedCost ?? null;
}

export default function ReachabilitySection({ organizationId, canManage }: ReachabilitySectionProps) {
  const { toast } = useToast();

  const [settings, setSettings] = useState<ReachabilitySettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [savingField, setSavingField] = useState<keyof ReachabilitySettings | null>(null);

  const [budgetInput, setBudgetInput] = useState('');
  const [waitInput, setWaitInput] = useState('');

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const s = await api.getReachabilitySettings(organizationId);
      setSettings(s);
      setBudgetInput(String(s.monthly_budget_usd ?? DEFAULT_GENERATOR_MONTHLY_BUDGET_USD));
      setWaitInput(String(s.max_wait_seconds ?? 300));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load settings';
      toast({ title: 'Failed to load reachability settings', description: message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [organizationId, toast]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const updateField = useCallback(
    async <K extends keyof ReachabilitySettings>(field: K, value: ReachabilitySettings[K]) => {
      if (!settings) return;
      // Optimistic update so toggles don't visibly lag.
      setSettings({ ...settings, [field]: value });
      setSavingField(field);
      try {
        const next = await api.updateReachabilitySettings(organizationId, { [field]: value } as Partial<ReachabilitySettings>);
        setSettings(next);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to save';
        toast({ title: 'Save failed', description: message, variant: 'destructive' });
        // Reload to discard the optimistic write.
        await loadAll();
      } finally {
        setSavingField(null);
      }
    },
    [organizationId, settings, toast, loadAll],
  );

  const handleToggleSeverity = (sev: typeof SEVERITY_OPTIONS[number]) => {
    if (!settings || !canManage) return;
    const current = new Set(settings.trigger_severities);
    if (current.has(sev)) current.delete(sev);
    else current.add(sev);
    if (current.size === 0) {
      toast({ title: 'Pick at least one severity', variant: 'destructive' });
      return;
    }
    updateField('trigger_severities', Array.from(current) as ReachabilitySettings['trigger_severities']);
  };

  const handleBudgetBlur = () => {
    if (!settings) return;
    const raw = budgetInput.trim();
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1000) {
      toast({ title: 'Enter a budget between 0 and 1000', variant: 'destructive' });
      setBudgetInput(String(settings.monthly_budget_usd));
      return;
    }
    const rounded = Math.round(parsed * 100) / 100;
    if (rounded === settings.monthly_budget_usd) return;
    updateField('monthly_budget_usd', rounded);
  };

  const handleWaitBlur = () => {
    if (!settings) return;
    const raw = waitInput.trim();
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed < 30 || parsed > 1800) {
      toast({ title: 'Enter wait seconds between 30 and 1800', variant: 'destructive' });
      setWaitInput(String(settings.max_wait_seconds));
      return;
    }
    if (parsed === settings.max_wait_seconds) return;
    updateField('max_wait_seconds', parsed);
  };

  if (loading || !settings) {
    return (
      <div className="space-y-6 pt-8">
        <div className="h-8 w-72 bg-muted/40 animate-pulse rounded" />
        <div className="space-y-3">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 bg-muted/30 animate-pulse rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  const disabled = !canManage;
  const providerOptions: { value: Provider; label: string }[] = [
    { value: 'anthropic', label: 'Anthropic' },
    { value: 'openai', label: 'OpenAI' },
    { value: 'google', label: 'Google' },
  ];

  const currentModelCost = findModelCost(settings.ai_provider, settings.ai_model);

  return (
    <div className="space-y-6 pt-8">
      <div>
        <h2 className="text-2xl font-bold text-foreground">Reachability</h2>
        <p className="mt-1.5 text-sm text-foreground-secondary max-w-3xl">
          Auto-generate Semgrep taint rules for your organization&apos;s vulnerabilities. Rules are validated
          against the upstream patch and only enabled when they correctly flag the vulnerable code while
          leaving the patched version alone.
        </p>
      </div>

      {/* Master toggle */}
      <div className="rounded-lg border border-border bg-background-card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex gap-3 min-w-0">
            <div className="h-9 w-9 shrink-0 rounded-md bg-background-subtle flex items-center justify-center">
              <Sparkles className="h-4 w-4 text-foreground-secondary" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-foreground">Auto-generate reachability rules</h3>
              <p className="text-xs text-foreground-secondary mt-0.5 max-w-2xl">
                When enabled, the extraction pipeline drafts rules for vulnerabilities that match your
                trigger policy. New rules run on the next scan once validated.
              </p>
            </div>
          </div>
          <div className="shrink-0 flex items-center gap-2">
            {savingField === 'auto_generate_enabled' && (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary" />
            )}
            <Switch
              checked={settings.auto_generate_enabled}
              onCheckedChange={(v) => updateField('auto_generate_enabled', v)}
              disabled={disabled || savingField === 'auto_generate_enabled'}
              aria-label="Auto-generate reachability rules"
            />
          </div>
        </div>
      </div>

      {/* Trigger policy */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-foreground-secondary" />
            <h3 className="text-sm font-semibold text-foreground">Trigger policy</h3>
          </div>
          <p className="text-xs text-foreground-secondary mt-1">
            Only generate rules for vulnerabilities that meet every active filter.
          </p>
        </div>
        <div className="p-5 space-y-5">
          <div>
            <Label className="text-sm text-foreground mb-2 block">Severity</Label>
            <div className="flex items-center gap-2 flex-wrap">
              {SEVERITY_OPTIONS.map((sev) => {
                const active = settings.trigger_severities.includes(sev);
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => handleToggleSeverity(sev)}
                    disabled={disabled || savingField === 'trigger_severities'}
                    className={cn(
                      'px-3 py-1 rounded-md border text-xs font-medium transition-colors',
                      active
                        ? 'border-primary/40 bg-primary/10 text-foreground'
                        : 'border-border bg-background-card text-foreground-secondary hover:text-foreground hover:bg-background-subtle',
                      'disabled:cursor-not-allowed disabled:opacity-50',
                    )}
                  >
                    {SEVERITY_LABELS[sev]}
                  </button>
                );
              })}
              {savingField === 'trigger_severities' && (
                <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary" />
              )}
            </div>
          </div>

          <div className="flex items-start justify-between gap-4 pt-1">
            <div className="min-w-0">
              <p className="text-sm text-foreground">CISA KEV only</p>
              <p className="text-xs text-foreground-secondary mt-0.5">
                Restrict to vulnerabilities in CISA&apos;s Known Exploited Vulnerabilities catalog.
              </p>
            </div>
            <Switch
              checked={settings.trigger_kev}
              onCheckedChange={(v) => updateField('trigger_kev', v)}
              disabled={disabled || savingField === 'trigger_kev'}
              aria-label="CISA KEV only"
            />
          </div>

          <div className="flex items-start justify-between gap-4 pt-1">
            <div className="min-w-0">
              <p className="text-sm text-foreground">Newly discovered vulnerabilities</p>
              <p className="text-xs text-foreground-secondary mt-0.5">
                Generate when a previously unseen CVE matches the policy.
              </p>
            </div>
            <Switch
              checked={settings.trigger_newly_discovered}
              onCheckedChange={(v) => updateField('trigger_newly_discovered', v)}
              disabled={disabled || savingField === 'trigger_newly_discovered'}
              aria-label="Newly discovered"
            />
          </div>
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-sm text-foreground">Re-evaluate existing vulnerabilities</p>
              <p className="text-xs text-foreground-secondary mt-0.5">
                Also regenerate rules for already-seen CVEs each scan. Increases cost.
              </p>
            </div>
            <Switch
              checked={settings.trigger_reevaluate_existing}
              onCheckedChange={(v) => updateField('trigger_reevaluate_existing', v)}
              disabled={disabled || savingField === 'trigger_reevaluate_existing'}
              aria-label="Re-evaluate existing"
            />
          </div>
        </div>
      </div>

      {/* Model + Budget */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <DollarSign className="h-4 w-4 text-foreground-secondary" />
            <h3 className="text-sm font-semibold text-foreground">AI model and budget</h3>
          </div>
          <p className="text-xs text-foreground-secondary mt-1">
            Generation uses the platform AI key.
          </p>
        </div>
        <div className="p-5 grid gap-5">
          <div className="grid sm:grid-cols-2 gap-5">
            <div>
              <Label className="text-sm text-foreground mb-2 block">Provider</Label>
              <Select
                value={settings.ai_provider}
                onValueChange={(v) => {
                  const p = v as Provider;
                  // Reset the model to the first available for the new provider.
                  const fallbackModel = modelOptionsFor(p)[0]?.value ?? settings.ai_model;
                  updateField('ai_provider', p);
                  if (settings.ai_model !== fallbackModel) {
                    void updateField('ai_model', fallbackModel);
                  }
                }}
                disabled={disabled || savingField === 'ai_provider'}
              >
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {providerOptions.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-sm text-foreground mb-2 block">Model</Label>
              <Select
                value={settings.ai_model}
                onValueChange={(v) => updateField('ai_model', v)}
                disabled={disabled || savingField === 'ai_model'}
              >
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue>{findModelLabel(settings.ai_provider, settings.ai_model)}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {modelOptionsFor(settings.ai_provider).map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      <span className="flex items-center justify-between gap-3 w-full">
                        <span>{m.label}</span>
                        <span className="text-xs text-foreground-secondary tabular-nums">~${m.estimatedCost.toFixed(3)}/rule</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {currentModelCost != null && (
                <p className="text-xs text-foreground-secondary mt-2">
                  Estimated cost ~${currentModelCost.toFixed(3)} per rule.
                </p>
              )}
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-5">
            <div>
              <Label htmlFor="reach-monthly-budget" className="text-sm text-foreground mb-2 block">
                Monthly budget (USD)
              </Label>
              <Input
                id="reach-monthly-budget"
                type="number"
                inputMode="decimal"
                min={0}
                max={1000}
                step={0.5}
                value={budgetInput}
                onChange={(e) => setBudgetInput(e.target.value)}
                onBlur={handleBudgetBlur}
                disabled={disabled || savingField === 'monthly_budget_usd'}
                className="h-9"
              />
              <p className="text-xs text-foreground-secondary mt-1.5">
                Hard cap. Generation pauses or downgrades once cumulative cost reaches this.
              </p>
            </div>
            <div>
              <Label className="text-sm text-foreground mb-2 block">When budget is exceeded</Label>
              <Select
                value={settings.on_budget_exhaustion}
                onValueChange={(v) => updateField('on_budget_exhaustion', v as ReachabilitySettings['on_budget_exhaustion'])}
                disabled={disabled || savingField === 'on_budget_exhaustion'}
              >
                <SelectTrigger className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="skip">Skip generation</SelectItem>
                  <SelectItem value="fall_back_to_haiku">Fall back to Haiku (cheaper)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-foreground-secondary mt-1.5">
                Haiku fallback uses Anthropic Haiku regardless of provider above.
              </p>
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-5">
            <div>
              <Label htmlFor="reach-max-wait" className="text-sm text-foreground mb-2 block">
                Max wait per scan (seconds)
              </Label>
              <Input
                id="reach-max-wait"
                type="number"
                inputMode="numeric"
                min={30}
                max={1800}
                step={10}
                value={waitInput}
                onChange={(e) => setWaitInput(e.target.value)}
                onBlur={handleWaitBlur}
                disabled={disabled || savingField === 'max_wait_seconds'}
                className="h-9"
              />
              <p className="text-xs text-foreground-secondary mt-1.5">
                Hard timeout for the generation step. The scan continues with whatever rules finished.
              </p>
            </div>
          </div>

          <div className="flex items-start gap-2 rounded-md border border-border bg-background-subtle/30 px-3 py-2">
            <Info className="h-3.5 w-3.5 text-foreground-secondary shrink-0 mt-0.5" />
            <p className="text-xs text-foreground-secondary">
              Costs are billed by your AI provider, not Deptex. Track cumulative spend in{' '}
              <span className="font-medium text-foreground">AI Configuration · Usage</span>.
            </p>
          </div>
        </div>
      </div>

      {/* Generated rules table */}
      <GeneratedRulesTable organizationId={organizationId} settings={settings} canManage={canManage} />
    </div>
  );
}
