import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react';
import { Button } from '../../../components/ui/button';
import { Badge } from '../../../components/ui/badge';
import { useToast } from '../../../hooks/use-toast';
import {
  apiAdminListExtractionFailures,
  apiAdminFleetMetrics,
  apiAdminExtractionTrend,
  type ExtractionFailure,
  type FleetMetrics,
  type ExtractionTrendPoint,
} from '../../../lib/api';
import { RANGES, type RangeKey, RangeTabs, dayLabel } from './adminUi';

const PER_PAGE = 50;
const MESSAGE_PREVIEW_LIMIT = 120;
const ERROR_COLOR = '#ef4444'; // red-500
const WARN_COLOR = '#f59e0b'; // amber-500

type SeverityFilter = 'all' | 'warn' | 'error';

const SEVERITIES: { key: SeverityFilter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'error', label: 'Errors' },
  { key: 'warn', label: 'Warnings' },
];

function formatDate(s: string | null): string {
  if (!s) return '—';
  return new Date(s).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function truncate(s: string, n: number): string {
  if (!s) return '';
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="lg:px-4 lg:first:pl-0">
      <div className="text-xs text-foreground-secondary">{label}</div>
      <div className="text-xl font-semibold text-foreground tabular-nums">{value}</div>
      {sub ? <div className="text-xs text-foreground-secondary mt-0.5">{sub}</div> : null}
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-foreground-secondary">
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

function Page({ children }: { children: ReactNode }) {
  return <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">{children}</div>;
}

/**
 * Live fleet-dispatcher metrics. Polls every 5s — "watch the autoscaler react to
 * load." Rendered as a bare divided KPI strip with a live indicator + cap bar.
 */
function FleetPanel() {
  const [m, setM] = useState<FleetMetrics | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const data = await apiAdminFleetMetrics('extraction');
        if (alive) {
          setM(data);
          setError(false);
        }
      } catch {
        if (alive) setError(true);
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (error && !m) return null; // fleet metrics unavailable (CE / Fly not configured) — hide silently
  if (!m) {
    return (
      <section>
        <div className="mb-3 h-4 w-28 animate-pulse rounded bg-muted" />
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded bg-muted/40" />
          ))}
        </div>
      </section>
    );
  }

  const fleetPct = m.maxFleet > 0 ? Math.min(100, Math.round((m.inflight / m.maxFleet) * 100)) : 0;
  const fmtSec = (s: number | null) => (s == null ? '—' : s >= 60 ? `${Math.round(s / 60)}m` : `${s}s`);

  return (
    <section>
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-foreground">Extraction fleet</h2>
        {m.spendBlocked ? (
          <Badge variant="destructive">spend cap reached</Badge>
        ) : (
          <span className="inline-flex items-center gap-1 text-xs text-foreground-secondary">
            <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" /> live
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6 lg:gap-0 lg:divide-x lg:divide-border">
        <Stat label="Queue depth" value={String(m.queued)} />
        <Stat label="Running" value={String(m.running)} sub={`${m.starting} starting`} />
        <Stat label="Inflight / max" value={`${m.inflight} / ${m.maxFleet}`} sub={`${fleetPct}% of cap`} />
        <Stat label="Throughput" value={`${m.throughputPerHour}/hr`} />
        <Stat label="Queue wait p50 / p95" value={`${fmtSec(m.p50QueueSeconds)} / ${fmtSec(m.p95QueueSeconds)}`} />
        <Stat
          label="Spend (this hour)"
          value={`$${m.spendThisHourUsd.toFixed(2)}`}
          sub={m.spendCapUsd != null ? `cap $${m.spendCapUsd.toFixed(2)}` : 'no cap'}
        />
      </div>
      <div className="mt-4 h-1 w-full overflow-hidden rounded-full bg-muted/60">
        <div
          className={`h-full rounded-full transition-all duration-300 ${fleetPct >= 100 ? 'bg-amber-500' : 'bg-emerald-500'}`}
          style={{ width: `${fleetPct}%` }}
        />
      </div>
    </section>
  );
}

function TrendTooltip({ active, payload }: { active?: boolean; payload?: any[] }) {
  if (!active || !payload || payload.length === 0) return null;
  const label = payload[0]?.payload?.label;
  const errors = payload.find((p) => p.dataKey === 'errors')?.value ?? 0;
  const warns = payload.find((p) => p.dataKey === 'warns')?.value ?? 0;
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background-card shadow-2xl">
      <div className="space-y-1.5 px-4 py-2.5">
        <div className="flex items-center gap-3">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: ERROR_COLOR }} />
          <span className="flex-1 text-xs text-foreground-secondary">Errors</span>
          <span className="font-mono text-sm tabular-nums text-foreground">{errors}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: WARN_COLOR }} />
          <span className="flex-1 text-xs text-foreground-secondary">Warnings</span>
          <span className="font-mono text-sm tabular-nums text-foreground">{warns}</span>
        </div>
      </div>
      <div className="flex items-center justify-between border-t border-border px-4 py-1.5 text-xs text-foreground-secondary">
        <span>{label}</span>
        <span className="font-mono tabular-nums">{errors + warns} total</span>
      </div>
    </div>
  );
}

function TrendChart({ data }: { data: ExtractionTrendPoint[] }) {
  const chartData = data.map((d) => ({ ...d, label: dayLabel(d.date) }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 12, fill: 'rgba(255,255,255,0.55)' }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
          minTickGap={36}
        />
        <YAxis
          tick={{ fontSize: 12, fill: 'rgba(255,255,255,0.55)' }}
          tickLine={false}
          axisLine={false}
          width={36}
          allowDecimals={false}
          domain={[0, (max: number) => Math.max(4, Math.ceil(max * 1.15))]}
        />
        <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} content={<TrendTooltip />} />
        <Bar dataKey="warns" stackId="a" fill={WARN_COLOR} isAnimationActive={false} />
        <Bar dataKey="errors" stackId="a" fill={ERROR_COLOR} radius={[2, 2, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function SkeletonRows({ rows }: { rows: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="animate-pulse border-b border-border last:border-0">
          <td className="px-4 py-3"><div className="h-4 w-4 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-32 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-40 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-20 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-14 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-16 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-56 bg-muted rounded" /></td>
          <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
        </tr>
      ))}
    </>
  );
}

export default function ExtractionFailuresPage() {
  const { toast } = useToast();

  // Failures table.
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<ExtractionFailure[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Failures-over-time chart.
  const [trend, setTrend] = useState<ExtractionTrendPoint[] | null>(null);
  const [range, setRange] = useState<RangeKey>('30d');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await apiAdminListExtractionFailures({
        page,
        per_page: PER_PAGE,
        severity: severity === 'all' ? undefined : severity,
      });
      setRows(resp.data);
      setTotal(resp.total);
    } catch (e: unknown) {
      toast({
        title: 'Failed to load failures',
        description: e instanceof Error ? e.message : 'Unknown error',
        variant: 'destructive',
      });
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, severity, toast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const t = await apiAdminExtractionTrend();
        if (alive) setTrend(t.series);
      } catch {
        if (alive) setTrend([]);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / PER_PAGE)), [total]);

  const pickSeverity = (s: SeverityFilter) => {
    setSeverity(s);
    setPage(1);
    setExpanded(new Set());
  };

  const toggleRow = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const activeRange = RANGES.find((r) => r.key === range) ?? RANGES[1];
  const trendSlice = (trend ?? []).slice(-activeRange.days);
  const trendTotal = trendSlice.reduce((s, d) => s + d.errors + d.warns, 0);
  const trendHasData = trendSlice.some((d) => d.errors + d.warns > 0);

  return (
    <Page>
      <FleetPanel />

      {/* Failures over time */}
      <section className="space-y-3">
        <div className="rounded-lg border border-border bg-background-card">
          <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Extraction failures</h3>
              <p className="mt-0.5 text-xs text-foreground-secondary">Errors &amp; warnings logged per day</p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <RangeTabs value={range} onChange={setRange} />
              <div className="text-right">
                <span className="text-2xl font-bold tabular-nums text-foreground">
                  {trendTotal.toLocaleString()}
                </span>
                <span className="ml-2 text-xs text-foreground-secondary">{activeRange.totalLabel}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-4 px-5 pb-1">
            <LegendDot color={ERROR_COLOR} label="Errors" />
            <LegendDot color={WARN_COLOR} label="Warnings" />
          </div>
          <div className="h-64 px-2 pb-5 pt-1">
            {trend === null ? (
              <div className="flex h-full items-center justify-center">
                <Loader2 className="h-6 w-6 animate-spin text-foreground-secondary" />
              </div>
            ) : trendHasData ? (
              <TrendChart data={trendSlice} />
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-foreground-secondary">
                No failures in {activeRange.emptyLabel}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Failures table */}
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-sm font-semibold text-foreground">Recent failures</h2>
          <div className="flex rounded-md border border-border bg-background p-0.5">
            {SEVERITIES.map((s) => (
              <button
                key={s.key}
                type="button"
                onClick={() => pickSeverity(s.key)}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                  severity === s.key
                    ? 'bg-background-card-hover text-foreground'
                    : 'text-foreground-secondary hover:text-foreground'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-hidden rounded-lg border border-border bg-background-card">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header">
              <tr className="border-b border-border text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                <th className="w-8 px-4 py-2.5" />
                <th className="text-left px-4 py-2.5">Created</th>
                <th className="text-left px-4 py-2.5">Project</th>
                <th className="text-left px-4 py-2.5">Step</th>
                <th className="text-left px-4 py-2.5">Code</th>
                <th className="text-left px-4 py-2.5">Severity</th>
                <th className="text-right px-4 py-2.5">Duration</th>
                <th className="text-left px-4 py-2.5">Message</th>
                <th className="text-left px-4 py-2.5">Machine</th>
              </tr>
            </thead>
            <tbody>
              {loading && rows.length === 0 ? (
                <SkeletonRows rows={8} />
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-16 text-center text-foreground-secondary">
                    No extraction failures found
                  </td>
                </tr>
              ) : (
                rows.map((row) => {
                  const isExpanded = expanded.has(row.id);
                  const preview = truncate(row.message ?? '', MESSAGE_PREVIEW_LIMIT);
                  const messageTruncated = (row.message ?? '').length > MESSAGE_PREVIEW_LIMIT;
                  return (
                    <>
                      <tr
                        key={row.id}
                        className="border-b border-border last:border-0 hover:bg-table-hover cursor-pointer"
                        onClick={() => toggleRow(row.id)}
                      >
                        <td className="px-4 py-3 align-top text-foreground-secondary">
                          {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                        </td>
                        <td className="px-4 py-3 align-top whitespace-nowrap text-foreground-secondary">
                          {formatDate(row.created_at)}
                        </td>
                        <td className="px-4 py-3 align-top text-foreground">
                          {row.project_name || (
                            <span className="font-mono text-xs text-foreground-secondary">
                              {row.project_id.slice(0, 8)}…
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 align-top font-mono text-xs text-foreground">{row.step}</td>
                        <td className="px-4 py-3 align-top font-mono text-xs text-foreground">{row.code}</td>
                        <td className="px-4 py-3 align-top">
                          <Badge variant={row.severity === 'error' ? 'destructive' : 'warning'}>
                            {row.severity}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 align-top text-right tabular-nums text-foreground-secondary whitespace-nowrap">
                          {row.duration_ms != null ? `${row.duration_ms} ms` : '—'}
                        </td>
                        <td className="px-4 py-3 align-top text-foreground">
                          <span className="block max-w-xl">
                            {preview}
                            {messageTruncated && !isExpanded ? (
                              <span className="ml-1 text-xs text-foreground-secondary">(expand)</span>
                            ) : null}
                          </span>
                        </td>
                        <td className="px-4 py-3 align-top font-mono text-xs text-foreground-secondary">
                          {row.machine_id || '—'}
                        </td>
                      </tr>
                      {isExpanded ? (
                        <tr key={`${row.id}-detail`} className="border-b border-border last:border-0 bg-muted/20">
                          <td />
                          <td colSpan={8} className="px-4 py-4">
                            <div className="space-y-3">
                              <div>
                                <div className="text-xs font-medium text-foreground-secondary mb-1">Message</div>
                                <pre className="text-xs text-foreground bg-background rounded border border-border p-3 whitespace-pre-wrap break-words">
                                  {row.message || '(empty)'}
                                </pre>
                              </div>
                              {row.stack ? (
                                <div>
                                  <div className="text-xs font-medium text-foreground-secondary mb-1">Stack</div>
                                  <pre className="text-xs text-foreground bg-background rounded border border-border p-3 whitespace-pre-wrap break-words max-h-96 overflow-auto">
                                    {row.stack}
                                  </pre>
                                </div>
                              ) : null}
                              <div className="grid grid-cols-2 gap-3 text-xs text-foreground-secondary">
                                <div>
                                  <span className="font-medium text-foreground">Project ID:</span>{' '}
                                  <span className="font-mono">{row.project_id}</span>
                                </div>
                                <div>
                                  <span className="font-medium text-foreground">Job ID:</span>{' '}
                                  <span className="font-mono">{row.extraction_job_id}</span>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between">
          <div className="text-xs text-foreground-secondary">
            {loading ? (
              <span className="inline-flex items-center gap-1">
                <Loader2 className="h-3 w-3 animate-spin" /> Loading…
              </span>
            ) : total === 0 ? (
              '0 results'
            ) : (
              `Showing ${(page - 1) * PER_PAGE + 1}–${Math.min(page * PER_PAGE, total)} of ${total}`
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
            >
              Previous
            </Button>
            <span className="text-xs text-foreground-secondary tabular-nums">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || loading}
            >
              Next
            </Button>
          </div>
        </div>
      </section>
    </Page>
  );
}
