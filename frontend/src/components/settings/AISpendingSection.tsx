import { useEffect, useMemo, useState } from 'react';
import { Check, ChevronDown, Cpu } from 'lucide-react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import {
  api,
  type AIUsageSummary,
  type AegisToolBreakdownResponse,
  type DailyUsageResponse,
} from '../../lib/api';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';

interface AISpendingSectionProps {
  organizationId: string;
  canViewSpending: boolean;
}

type SpendingTimeframe = '7d' | '30d' | '90d';

const SPENDING_TIMEFRAME_LABEL: Record<SpendingTimeframe, string> = {
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
  '90d': 'Last 90 days',
};

const SPENDING_TIMEFRAME_DAYS: Record<SpendingTimeframe, number> = {
  '7d': 7,
  '30d': 30,
  '90d': 90,
};

const CHART_COLORS = {
  axis: '#6C757D',
  grid: '#2C3138',
  line: '#10b981',
  bar: '#10b981',
  tooltipBg: '#1A1C1E',
  tooltipBorder: '#2C3138',
};

const FEATURE_LABEL_OVERRIDES: Record<string, string> = {
  'aegis.chat': 'Aegis Chat',
  'aegis.fix': 'Aegis Fix Agent',
  'aegis.plan': 'Aegis Planner',
  'docs.assistant': 'Docs Assistant',
  'policy.ai': 'Policy AI',
  'notification.ai': 'Notification AI',
  'usage.analysis': 'Usage Analysis',
  'rule_generation': 'Reachability Rule Generation',
  'epd_scoring': 'EPD Scoring',
};

function humanise(key: string): string {
  if (!key) return '—';
  return key
    .replace(/[._-]+/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function featureLabel(key: string): string {
  return FEATURE_LABEL_OVERRIDES[key] ?? humanise(key);
}

function toolLabel(key: string): string {
  return humanise(key);
}

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

export default function AISpendingSection({ organizationId, canViewSpending }: AISpendingSectionProps) {
  const [timeframe, setTimeframe] = useState<SpendingTimeframe>('30d');
  const [summary, setSummary] = useState<AIUsageSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [daily, setDaily] = useState<DailyUsageResponse | null>(null);
  const [dailyLoading, setDailyLoading] = useState(true);
  const [tools, setTools] = useState<AegisToolBreakdownResponse | null>(null);
  const [toolsLoading, setToolsLoading] = useState(true);

  useEffect(() => {
    if (!canViewSpending) return;
    let cancelled = false;
    const days = SPENDING_TIMEFRAME_DAYS[timeframe];

    setSummaryLoading(true);
    api.getAIUsage(organizationId, timeframe)
      .then((s) => { if (!cancelled) setSummary(s); })
      .catch(() => { /* silent */ })
      .finally(() => { if (!cancelled) setSummaryLoading(false); });

    setDailyLoading(true);
    api.getAIUsageDaily(organizationId, days)
      .then((d) => { if (!cancelled) setDaily(d); })
      .catch(() => { /* silent */ })
      .finally(() => { if (!cancelled) setDailyLoading(false); });

    setToolsLoading(true);
    api.getAegisToolBreakdown(organizationId, days, 10)
      .then((t) => { if (!cancelled) setTools(t); })
      .catch(() => { /* silent */ })
      .finally(() => { if (!cancelled) setToolsLoading(false); });

    return () => { cancelled = true; };
  }, [organizationId, canViewSpending, timeframe]);

  const totalTokens = summary ? summary.totalInputTokens + summary.totalOutputTokens : 0;
  const totalCostCents = summary ? Math.round(summary.totalEstimatedCost * 100) : 0;
  const capCents = summary ? Math.round(summary.monthlyCostCap * 100) : 0;
  const capPct = capCents > 0 ? Math.min(100, Math.round((totalCostCents / capCents) * 100)) : 0;
  const capColor = capPct >= 90 ? 'bg-destructive' : capPct >= 75 ? 'bg-warning' : 'bg-emerald-500';

  const featureRows = useMemo(() => {
    if (!summary) return [];
    return Object.entries(summary.byFeature)
      .map(([feature, v]) => ({ feature, ...v }))
      .sort((a, b) => b.cost - a.cost);
  }, [summary]);

  const toolBars = useMemo(() => {
    if (!tools) return [];
    return tools.tools.map((t) => ({ ...t, displayName: toolLabel(t.tool_name) }));
  }, [tools]);

  if (!canViewSpending) {
    return null;
  }

  return (
    <section className="space-y-4" data-testid="ai-spending-section">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-base font-semibold text-foreground">AI spending</h3>
          <p className="mt-0.5 text-xs text-foreground-secondary">Track AI usage and cost across all features.</p>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="!h-8 !px-3 !rounded-lg gap-1.5">
              {SPENDING_TIMEFRAME_LABEL[timeframe]}
              <ChevronDown className="h-3 w-3 opacity-50" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {(Object.entries(SPENDING_TIMEFRAME_LABEL) as Array<[SpendingTimeframe, string]>).map(([value, label]) => (
              <DropdownMenuItem key={value} onClick={() => setTimeframe(value)}>
                {label}
                {timeframe === value && <Check className="h-3.5 w-3.5 ml-auto" />}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden divide-y divide-border">
        <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-border">
          <HeadlineStat label="Tokens" value={summaryLoading ? '—' : formatTokens(totalTokens)} />
          <HeadlineStat label="Estimated cost" value={summaryLoading ? '—' : formatDollars(totalCostCents)} />
          <HeadlineStat
            label="Monthly cap"
            value={summaryLoading ? '—' : `${formatDollars(totalCostCents)} / ${formatDollars(capCents)}`}
            bar={summaryLoading ? null : { pct: capPct, color: capColor }}
          />
        </div>

        <div>
          <header className="px-6 py-4 border-b border-border">
            <h4 className="text-sm font-semibold text-foreground">Daily cost</h4>
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
                  <RechartsTooltip
                    contentStyle={{
                      background: CHART_COLORS.tooltipBg,
                      border: `1px solid ${CHART_COLORS.tooltipBorder}`,
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                    labelFormatter={(v) => shortDate(String(v))}
                    formatter={(value: number) => [`$${value.toFixed(2)}`, 'Cost']}
                  />
                  <Line type="monotone" dataKey="cost" stroke={CHART_COLORS.line} strokeWidth={1.75} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <EmptyChart label={dailyLoading ? 'Loading…' : 'No AI usage yet — start a chat with Aegis.'} />
            )}
          </div>
        </div>

        <div>
          <header className="px-6 py-4 border-b border-border">
            <h4 className="text-sm font-semibold text-foreground">By feature</h4>
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
                    <td className="px-4 py-2.5 text-sm text-foreground">{featureLabel(r.feature)}</td>
                    <td className="px-4 py-2.5 text-sm text-right text-foreground tabular-nums">{r.count.toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-sm text-right text-foreground tabular-nums">{formatTokens(r.tokens)}</td>
                    <td className="px-4 py-2.5 text-sm text-right text-foreground tabular-nums">${r.cost.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="px-6 py-6 text-sm text-foreground-secondary">{summaryLoading ? 'Loading…' : 'No usage recorded yet.'}</p>
          )}
        </div>

        <div>
          <header className="px-6 py-4 border-b border-border">
            <h4 className="text-sm font-semibold text-foreground">Top Aegis tools</h4>
          </header>
          <div className="h-72 px-2 pt-4 pb-2">
            {toolBars.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={toolBars} layout="vertical" margin={{ left: 16, right: 16, top: 4, bottom: 4 }}>
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
                    dataKey="displayName"
                    tick={{ fill: CHART_COLORS.axis, fontSize: 11 }}
                    axisLine={{ stroke: CHART_COLORS.grid }}
                    tickLine={false}
                    width={180}
                  />
                  <RechartsTooltip
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
              <EmptyChart label={toolsLoading ? 'Loading…' : 'No Aegis tool calls recorded yet.'} />
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function HeadlineStat({ label, value, bar }: { label: string; value: string; bar?: { pct: number; color: string } | null }) {
  return (
    <div className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-foreground tabular-nums">{value}</p>
      {bar && (
        <>
          <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-background-subtle">
            <div className={cn('h-full transition-all', bar.color)} style={{ width: `${bar.pct}%` }} />
          </div>
          <p className="mt-1.5 text-xs text-foreground-secondary">{bar.pct}% of cap used</p>
        </>
      )}
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
