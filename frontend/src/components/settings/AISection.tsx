import { useEffect, useMemo, useState } from 'react';
import { Sparkles, Bot, Cpu, Wand2, Loader2, Check, Zap } from 'lucide-react';
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
  type AIDefaultProvider,
  type AIUsageSummary,
  type AegisToolBreakdownResponse,
  type DailyUsageResponse,
  type PlatformAIProvider,
} from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';

interface AISectionProps {
  organizationId: string;
  canManageSettings: boolean;
  canViewSpending: boolean;
}

interface ProviderMeta {
  id: PlatformAIProvider;
  name: string;
  modelLabel: string;
  blurb: string;
  Icon: typeof Sparkles;
}

const PROVIDERS: ProviderMeta[] = [
  {
    id: 'anthropic',
    name: 'Anthropic',
    modelLabel: 'Claude Sonnet 4.6',
    blurb: 'Strongest tool-calling, balanced cost.',
    Icon: Sparkles,
  },
  {
    id: 'openai',
    name: 'OpenAI',
    modelLabel: 'GPT-4o',
    blurb: 'Solid all-rounder for chat + tools.',
    Icon: Bot,
  },
  {
    id: 'google',
    name: 'Google',
    modelLabel: 'Gemini 2.5 Flash',
    blurb: 'Cheapest among hosted frontier providers.',
    Icon: Wand2,
  },
  {
    id: 'deepinfra',
    name: 'DeepInfra',
    modelLabel: 'Qwen3 235B',
    blurb: 'Open-weight (Qwen3 / DeepSeek). Lowest cost per token.',
    Icon: Zap,
  },
];

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
  const [defaultProvider, setDefaultProvider] = useState<AIDefaultProvider | null>(null);
  const [savingProvider, setSavingProvider] = useState<PlatformAIProvider | null>(null);
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
        const provider = await api.getAIDefaultProvider(organizationId);
        if (!cancelled) setDefaultProvider(provider);
      } catch (err: any) {
        if (!cancelled) {
          toast({ title: 'Could not load AI provider', description: err.message ?? 'Unknown error', variant: 'destructive' });
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

  const handlePickProvider = async (provider: PlatformAIProvider) => {
    if (!canManageSettings) {
      toast({ title: 'Permission required', description: 'You need manage_organization_settings to change the default AI provider.', variant: 'destructive' });
      return;
    }
    if (defaultProvider?.provider === provider || savingProvider) return;
    setSavingProvider(provider);
    try {
      const next = await api.setAIDefaultProvider(organizationId, provider);
      setDefaultProvider(next);
      toast({ title: 'Default provider updated', description: `Aegis will use ${PROVIDERS.find((p) => p.id === provider)?.name}.` });
    } catch (err: any) {
      toast({ title: 'Could not update provider', description: err.message ?? 'Unknown error', variant: 'destructive' });
    } finally {
      setSavingProvider(null);
    }
  };

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
      <div>
        <h1 className="text-2xl font-semibold text-foreground">AI</h1>
        <p className="mt-1 text-sm text-foreground-secondary">
          Choose which AI provider powers Aegis and review your usage. We provide the API key — you don't need to bring your own.
        </p>
      </div>

      {/* Provider picker */}
      <section className="rounded-lg border border-border bg-background-card overflow-hidden">
        <header className="px-6 py-4 border-b border-border">
          <h2 className="text-base font-semibold text-foreground">Default provider</h2>
          <p className="mt-0.5 text-xs text-foreground-secondary">
            Aegis and other AI features will route through whichever provider you select.
          </p>
        </header>
        <div className="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2 lg:grid-cols-4">
          {PROVIDERS.map((p) => {
            const selected = defaultProvider?.provider === p.id;
            const saving = savingProvider === p.id;
            return (
              <button
                key={p.id}
                type="button"
                disabled={!canManageSettings || !!savingProvider}
                onClick={() => handlePickProvider(p.id)}
                className={cn(
                  'group relative flex flex-col items-start rounded-lg border p-4 text-left transition-colors',
                  selected
                    ? 'border-foreground bg-background-subtle'
                    : 'border-border bg-background-card hover:border-foreground/40 hover:bg-background-subtle/50',
                  (!canManageSettings || (savingProvider && !saving)) && 'cursor-not-allowed opacity-60',
                )}
              >
                <div className="flex w-full items-center justify-between">
                  <div className="flex items-center gap-2">
                    <p.Icon className="h-4 w-4 text-foreground" />
                    <span className="text-sm font-semibold text-foreground">{p.name}</span>
                  </div>
                  {selected && !saving && (
                    <span className="inline-flex items-center gap-1 rounded-full border border-border bg-background-card px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-foreground-secondary">
                      <Check className="h-3 w-3" /> Default
                    </span>
                  )}
                  {saving && <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" />}
                </div>
                <p className="mt-2 text-xs font-mono text-foreground-secondary">{p.modelLabel}</p>
                <p className="mt-1 text-xs text-foreground-secondary">{p.blurb}</p>
              </button>
            );
          })}
        </div>
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
