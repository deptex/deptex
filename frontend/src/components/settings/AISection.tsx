import { useEffect, useMemo, useRef, useState } from 'react';
import { Cpu, Loader2 } from 'lucide-react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import {
  api,
  type AIModelMetadata,
  type AIModelsResponse,
  type AIUsageSummary,
  type AegisToolBreakdownResponse,
  type DailyUsageResponse,
} from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import { AIProviderIcon, brandForModel } from '../ai-provider-icon';

interface AISectionProps {
  organizationId: string;
  canManageSettings: boolean;
  canViewSpending: boolean;
}

const CHART_COLORS = {
  axis: '#6C757D',
  grid: '#2C3138',
  line: '#F0F4F8',
  bar: '#F0F4F8',
  tooltipBg: '#1A1C1E',
  tooltipBorder: '#2C3138',
};

function formatDollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

// Bucket models into 4 cost tiers based on output price per 1M (output
// dominates spend for chat/agent use). Visualised as $/$$/$$$/$$$$ in the
// table so users compare cheap-vs-expensive at a glance instead of doing
// mental math on per-million pricing.
function costTier(outputPricePer1M: number): 1 | 2 | 3 | 4 {
  if (outputPricePer1M < 1.5) return 1;
  if (outputPricePer1M < 8) return 2;
  if (outputPricePer1M < 25) return 3;
  return 4;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function shortDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  const diff = Date.now() - t;
  const m = Math.floor(diff / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export default function AISection({ organizationId, canManageSettings, canViewSpending }: AISectionProps) {
  const { toast } = useToast();
  const [modelsState, setModelsState] = useState<AIModelsResponse | null>(null);
  // Bumped on each PATCH so out-of-order responses can't clobber the latest
  // optimistic state.
  const requestSeq = useRef(0);
  const [summary, setSummary] = useState<AIUsageSummary | null>(null);
  const [daily, setDaily] = useState<DailyUsageResponse | null>(null);
  const [tools, setTools] = useState<AegisToolBreakdownResponse | null>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const data = await api.getAIModels(organizationId);
        if (!cancelled) setModelsState(data);
      } catch (err: any) {
        if (!cancelled) {
          toast({ title: 'Could not load AI models', description: err.message ?? 'Unknown error', variant: 'destructive' });
        }
      }

      if (canViewSpending) {
        try {
          const [s, d, t, l] = await Promise.all([
            api.getAIUsage(organizationId, '30d'),
            api.getAIUsageDaily(organizationId, 30),
            api.getAegisToolBreakdown(organizationId, 30, 10),
            api.getAIUsageLogs(organizationId, 1, 25),
          ]);
          if (!cancelled) {
            setSummary(s);
            setDaily(d);
            setTools(t);
            setLogs(l.logs ?? []);
          }
        } catch (err: any) {
          if (!cancelled) {
            toast({ title: 'Could not load AI usage', description: err.message ?? 'Unknown error', variant: 'destructive' });
          }
        }
      }
      if (!cancelled) setLoading(false);
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [organizationId, canViewSpending, toast]);

  const requireManage = () => {
    if (!canManageSettings) {
      toast({
        title: 'Permission required',
        description: 'You need manage_organization_settings to change AI models.',
        variant: 'destructive',
      });
      return false;
    }
    return true;
  };

  // Apply the local change instantly, then sync to the backend in the
  // background. On failure, revert and toast. requestSeq guards against
  // out-of-order responses overwriting a newer optimistic state.
  const patchModels = (
    optimistic: AIModelsResponse,
    patch: { defaultModel?: string; enabledModels?: string[] },
  ) => {
    const prev = modelsState;
    const seq = ++requestSeq.current;
    setModelsState(optimistic);
    api
      .updateAIModels(organizationId, patch)
      .then((next) => {
        if (requestSeq.current === seq) setModelsState(next);
      })
      .catch((err: any) => {
        if (requestSeq.current === seq) {
          if (prev) setModelsState(prev);
          toast({ title: 'Could not update model', description: err.message ?? 'Unknown error', variant: 'destructive' });
        }
      });
  };

  const handleSetDefault = (modelId: string) => {
    if (!modelsState || !requireManage()) return;
    if (modelsState.defaultModel === modelId) return;
    const willEnable = !modelsState.enabledModels.includes(modelId);
    const enabledModels = willEnable ? [...modelsState.enabledModels, modelId] : modelsState.enabledModels;
    patchModels(
      { ...modelsState, defaultModel: modelId, enabledModels },
      { defaultModel: modelId, ...(willEnable ? { enabledModels } : {}) },
    );
  };

  const handleToggle = (modelId: string, nextEnabled: boolean) => {
    if (!modelsState || !requireManage()) return;
    const isEnabled = modelsState.enabledModels.includes(modelId);
    if (isEnabled === nextEnabled) return;

    if (nextEnabled) {
      const enabledModels = [...modelsState.enabledModels, modelId];
      patchModels({ ...modelsState, enabledModels }, { enabledModels });
      return;
    }

    if (modelsState.enabledModels.length === 1) {
      toast({ title: 'At least one model must remain enabled', variant: 'destructive' });
      return;
    }

    const enabledModels = modelsState.enabledModels.filter((id) => id !== modelId);
    // If disabling the current default, auto-pick a new one (same provider preferred).
    let nextDefault = modelsState.defaultModel;
    if (modelsState.defaultModel === modelId) {
      const meta = modelsState.models.find((m) => m.id === modelId);
      const sameProviderEnabled = enabledModels.find((id) => modelsState.models.find((m) => m.id === id)?.provider === meta?.provider);
      nextDefault = sameProviderEnabled ?? enabledModels[0];
    }
    patchModels(
      { ...modelsState, enabledModels, defaultModel: nextDefault },
      { enabledModels, ...(nextDefault !== modelsState.defaultModel ? { defaultModel: nextDefault } : {}) },
    );
  };

  // Sort models newest-first by release date.
  const sortedModels = useMemo<AIModelMetadata[]>(() => {
    if (!modelsState) return [];
    return [...modelsState.models].sort((a, b) => b.releasedAt.localeCompare(a.releasedAt));
  }, [modelsState]);

  const totalTokens = summary ? summary.totalInputTokens + summary.totalOutputTokens : 0;
  const totalCostCents = summary ? Math.round(summary.totalEstimatedCost * 100) : 0;
  const capCents = summary ? Math.round(summary.monthlyCostCap * 100) : 0;
  const capPct = capCents > 0 ? Math.min(100, Math.round((totalCostCents / capCents) * 100)) : 0;
  const capColor = capPct >= 90 ? 'bg-destructive' : capPct >= 75 ? 'bg-warning' : 'bg-foreground';

  const featureRows = useMemo(() => {
    if (!summary) return [];
    return Object.entries(summary.byFeature)
      .map(([feature, v]) => ({ feature, ...v }))
      .sort((a, b) => b.cost - a.cost);
  }, [summary]);

  return (
    <div className="space-y-6">
      {/* Aegis Models title (outside the card) */}
      <div>
        <h2 className="text-xl font-semibold text-foreground">Aegis Models</h2>
        <p className="mt-1 text-sm text-foreground-secondary">
          Toggle which models Aegis can pick from.
        </p>
      </div>

      <section className="rounded-lg border border-border bg-background-card overflow-hidden">
        {!modelsState ? (
          <div className="flex items-center justify-center py-12 text-sm text-foreground-secondary">
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Loading models…
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Model</th>
                <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-36">SWE-Bench</th>
                <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-24">Cost</th>
                <th className="text-center px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary w-32">Enabled</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sortedModels.map((m) => (
                <ModelRow
                  key={m.id}
                  model={m}
                  enabled={modelsState.enabledModels.includes(m.id)}
                  isDefault={modelsState.defaultModel === m.id}
                  canEdit={canManageSettings}
                  onSetDefault={handleSetDefault}
                  onToggle={handleToggle}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {!canViewSpending && (
        <section className="rounded-lg border border-border bg-background-card p-6 text-sm text-foreground-secondary">
          You don't have permission to view AI spending. Ask an admin to grant <span className="font-mono text-foreground">view_ai_spending</span>.
        </section>
      )}

      {canViewSpending && (
        <>
          {/* Top-line stats */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <StatCard label="Tokens (30d)" value={loading ? '—' : formatTokens(totalTokens)} />
            <StatCard label="Estimated cost (30d)" value={loading ? '—' : formatDollars(totalCostCents)} />
            <div className="rounded-lg border border-border bg-background-card p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Monthly cap</p>
              <p className="mt-1 text-2xl font-semibold text-foreground">
                {loading ? '—' : `${formatDollars(totalCostCents)} / ${formatDollars(capCents)}`}
              </p>
              <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-background-subtle">
                <div className={cn('h-full transition-all', capColor)} style={{ width: `${capPct}%` }} />
              </div>
              <p className="mt-1.5 text-xs text-foreground-secondary">{capPct}% of cap used</p>
            </div>
          </div>

          {/* Daily trend chart */}
          <section className="rounded-lg border border-border bg-background-card overflow-hidden">
            <header className="px-6 py-4 border-b border-border">
              <h2 className="text-base font-semibold text-foreground">Daily AI usage</h2>
              <p className="mt-0.5 text-xs text-foreground-secondary">Estimated cost per day across all features (last 30 days).</p>
            </header>
            <div className="h-64 px-2 pt-4 pb-2">
              {daily && daily.points.some((p) => p.cost_cents > 0) ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={daily.points.map((p) => ({ ...p, cost: p.cost_cents / 100 }))}>
                    <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="date"
                      tickFormatter={shortDate}
                      tick={{ fill: CHART_COLORS.axis, fontSize: 11 }}
                      axisLine={{ stroke: CHART_COLORS.grid }}
                      tickLine={false}
                      minTickGap={24}
                    />
                    <YAxis
                      tickFormatter={(v) => `$${v.toFixed(2)}`}
                      tick={{ fill: CHART_COLORS.axis, fontSize: 11 }}
                      axisLine={{ stroke: CHART_COLORS.grid }}
                      tickLine={false}
                      width={48}
                    />
                    <Tooltip
                      contentStyle={{
                        background: CHART_COLORS.tooltipBg,
                        border: `1px solid ${CHART_COLORS.tooltipBorder}`,
                        borderRadius: 6,
                        fontSize: 12,
                      }}
                      labelFormatter={(v) => shortDate(String(v))}
                      formatter={(value: number) => [`$${value.toFixed(2)}`, 'Cost']}
                    />
                    <Line type="monotone" dataKey="cost" stroke={CHART_COLORS.line} strokeWidth={1.5} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <EmptyChart label={loading ? 'Loading…' : 'No AI usage yet — start a chat with Aegis.'} />
              )}
            </div>
          </section>

          {/* Feature breakdown */}
          <section className="rounded-lg border border-border bg-background-card overflow-hidden">
            <header className="px-6 py-4 border-b border-border">
              <h2 className="text-base font-semibold text-foreground">By feature</h2>
              <p className="mt-0.5 text-xs text-foreground-secondary">Cost split across AI surfaces (last 30 days).</p>
            </header>
            {featureRows.length > 0 ? (
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Feature</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Calls</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Tokens</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {featureRows.map((r) => (
                    <tr key={r.feature} className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-2.5 text-sm font-mono text-foreground">{r.feature}</td>
                      <td className="px-4 py-2.5 text-sm text-right text-foreground">{r.count.toLocaleString()}</td>
                      <td className="px-4 py-2.5 text-sm text-right text-foreground">{formatTokens(r.tokens)}</td>
                      <td className="px-4 py-2.5 text-sm text-right text-foreground">${r.cost.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="px-6 py-6 text-sm text-foreground-secondary">{loading ? 'Loading…' : 'No usage recorded yet.'}</p>
            )}
          </section>

          {/* Aegis tool breakdown */}
          <section className="rounded-lg border border-border bg-background-card overflow-hidden">
            <header className="px-6 py-4 border-b border-border">
              <h2 className="text-base font-semibold text-foreground">Top Aegis tools</h2>
              <p className="mt-0.5 text-xs text-foreground-secondary">How often each tool is invoked by the agent (last 30 days).</p>
            </header>
            <div className="h-72 px-2 pt-4 pb-2">
              {tools && tools.tools.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={tools.tools} layout="vertical" margin={{ left: 16, right: 16, top: 4, bottom: 4 }}>
                    <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 3" horizontal={false} />
                    <XAxis
                      type="number"
                      tick={{ fill: CHART_COLORS.axis, fontSize: 11 }}
                      axisLine={{ stroke: CHART_COLORS.grid }}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="tool_name"
                      tick={{ fill: CHART_COLORS.axis, fontSize: 11 }}
                      axisLine={{ stroke: CHART_COLORS.grid }}
                      tickLine={false}
                      width={160}
                    />
                    <Tooltip
                      contentStyle={{
                        background: CHART_COLORS.tooltipBg,
                        border: `1px solid ${CHART_COLORS.tooltipBorder}`,
                        borderRadius: 6,
                        fontSize: 12,
                      }}
                      formatter={(value: number) => [value.toLocaleString(), 'Executions']}
                    />
                    <Bar dataKey="executions" fill={CHART_COLORS.bar} radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyChart label={loading ? 'Loading…' : 'No Aegis tool calls recorded yet.'} />
              )}
            </div>
          </section>

          {/* Recent activity */}
          <section className="rounded-lg border border-border bg-background-card overflow-hidden">
            <header className="px-6 py-4 border-b border-border">
              <h2 className="text-base font-semibold text-foreground">Recent activity</h2>
              <p className="mt-0.5 text-xs text-foreground-secondary">The last 25 AI calls across your org.</p>
            </header>
            {logs.length > 0 ? (
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">When</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Feature</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Model</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Tokens</th>
                    <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {logs.map((row) => (
                    <tr key={row.id} className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-2.5 text-sm text-foreground-secondary">{relativeTime(row.created_at)}</td>
                      <td className="px-4 py-2.5 text-sm font-mono text-foreground">{row.feature}</td>
                      <td className="px-4 py-2.5 text-sm font-mono text-foreground-secondary">{row.model}</td>
                      <td className="px-4 py-2.5 text-sm text-right text-foreground">
                        {formatTokens((row.input_tokens || 0) + (row.output_tokens || 0))}
                      </td>
                      <td className="px-4 py-2.5 text-sm text-right text-foreground">
                        ${Number(row.estimated_cost || 0).toFixed(4)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="px-6 py-6 text-sm text-foreground-secondary">{loading ? 'Loading…' : 'No AI calls yet.'}</p>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-background-card p-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-foreground">{value}</p>
    </div>
  );
}

function EmptyChart({ label }: { label: string }) {
  return (
    <div className="flex h-full items-center justify-center text-sm text-foreground-secondary">
      <Cpu className="mr-2 h-4 w-4" />
      {label}
    </div>
  );
}

function CostTier({ tier }: { tier: 1 | 2 | 3 | 4 }) {
  return (
    <span className="inline-flex items-baseline font-mono text-sm tabular-nums">
      {[1, 2, 3, 4].map((i) => (
        <span key={i} className={cn(i <= tier ? 'text-foreground' : 'text-foreground/20')}>$</span>
      ))}
    </span>
  );
}

interface ModelRowProps {
  model: AIModelMetadata;
  enabled: boolean;
  isDefault: boolean;
  canEdit: boolean;
  onSetDefault: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
}

function ModelRow({
  model: m,
  enabled,
  isDefault,
  canEdit,
  onSetDefault,
  onToggle,
}: ModelRowProps) {
  return (
    <tr className="group transition-colors hover:bg-table-hover">
      <td className="px-4 py-3">
        <div className="flex items-center gap-3">
          <AIProviderIcon brand={brandForModel(m)} size={18} className="shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-sm font-semibold text-foreground truncate">{m.label}</p>
              {isDefault && (
                <span className="inline-flex items-center gap-1 rounded-full border border-border bg-background-subtle px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-foreground">
                  <span className="h-1.5 w-1.5 rounded-full bg-foreground" />
                  Default
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <p className="text-xs text-foreground-secondary truncate">{m.description}</p>
              {!isDefault && enabled && canEdit && (
                <button
                  type="button"
                  onClick={() => onSetDefault(m.id)}
                  className="shrink-0 text-[11px] text-foreground-secondary underline-offset-2 opacity-0 transition-opacity hover:text-foreground hover:underline group-hover:opacity-100 focus:opacity-100"
                >
                  Set as default
                </button>
              )}
            </div>
          </div>
        </div>
      </td>
      <td className="px-4 py-3 text-right text-sm text-foreground tabular-nums">
        {m.sweBenchVerified != null ? `${m.sweBenchVerified.toFixed(1)}%` : <span className="text-foreground-secondary">—</span>}
      </td>
      <td className="px-4 py-3 text-right">
        <CostTier tier={costTier(m.outputPricePer1M)} />
      </td>
      <td className="px-4 py-3 text-center">
        <button
          type="button"
          disabled={!canEdit}
          onClick={() => onToggle(m.id, !enabled)}
          aria-pressed={enabled}
          className={cn(
            'inline-flex h-7 w-16 items-center justify-center rounded-md border text-[11px] font-medium transition-colors box-border disabled:pointer-events-none disabled:opacity-50',
            enabled
              ? 'bg-foreground text-background border-foreground hover:bg-foreground/90'
              : 'bg-background-card text-foreground border-input hover:bg-background-card/80',
          )}
        >
          {enabled ? 'Enabled' : 'Disabled'}
        </button>
      </td>
    </tr>
  );
}
