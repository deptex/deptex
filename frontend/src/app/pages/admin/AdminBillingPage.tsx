import { useEffect, useState, type ReactNode } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Badge } from '../../../components/ui/badge';
import { useToast } from '../../../hooks/use-toast';
import { apiAdminBilling, type AdminBilling, type AdminRevenuePoint } from '../../../lib/api';
import {
  GREEN,
  RANGES,
  type RangeKey,
  RangeTabs,
  Kpi,
  usd,
  signedUsd,
  formatDate,
  dayLabel,
} from './adminUi';

const KIND_LABEL: Record<string, string> = {
  topup: 'Top-up',
  auto_recharge_topup: 'Auto-recharge',
  refund: 'Refund',
  adjustment: 'Adjustment',
};

function DepositsTooltip({ active, payload }: { active?: boolean; payload?: any[] }) {
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0];
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background-card shadow-2xl">
      <div className="flex items-center justify-between gap-8 px-4 py-2.5">
        <span className="text-xs text-foreground-secondary">{p.payload.label}</span>
        <span className="font-mono text-sm font-semibold tabular-nums text-foreground">
          {(p.value as number).toLocaleString(undefined, { style: 'currency', currency: 'USD' })}
        </span>
      </div>
    </div>
  );
}

function DepositsChart({ data }: { data: AdminRevenuePoint[] }) {
  const chartData = data.map((d) => ({ label: dayLabel(d.date), dollars: d.cents / 100 }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="adminRevFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={GREEN} stopOpacity={0.3} />
            <stop offset="100%" stopColor={GREEN} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 12, fill: 'rgba(255,255,255,0.55)' }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
          minTickGap={36}
          padding={{ left: 8, right: 8 }}
        />
        <YAxis
          tick={{ fontSize: 12, fill: 'rgba(255,255,255,0.55)' }}
          tickLine={false}
          axisLine={false}
          width={48}
          allowDecimals={false}
          tickFormatter={(v: number) => (v >= 1000 ? `$${(v / 1000).toFixed(0)}k` : `$${v}`)}
          domain={[0, (max: number) => (max > 0 ? Math.ceil(max * 1.15) : 10)]}
        />
        <Tooltip cursor={{ stroke: 'rgba(255,255,255,0.12)' }} content={<DepositsTooltip />} />
        <Area
          type="monotone"
          dataKey="dollars"
          stroke={GREEN}
          strokeWidth={2}
          fill="url(#adminRevFill)"
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function Page({ children }: { children: ReactNode }) {
  return <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-10">{children}</div>;
}

export default function AdminBillingPage() {
  const { toast } = useToast();
  const [data, setData] = useState<AdminBilling | null>(null);
  const [loading, setLoading] = useState(true);
  const [range, setRange] = useState<RangeKey>('30d');

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const d = await apiAdminBilling();
        if (alive) setData(d);
      } catch (e: unknown) {
        if (alive) {
          toast({
            title: 'Failed to load billing',
            description: e instanceof Error ? e.message : 'Unknown error',
            variant: 'destructive',
          });
        }
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  if (loading && !data) {
    return (
      <Page>
        <div className="grid grid-cols-2 gap-6">
          {Array.from({ length: 2 }).map((_, i) => (
            <div key={i}>
              <div className="h-8 w-24 animate-pulse rounded bg-muted" />
              <div className="mt-3 h-3 w-28 animate-pulse rounded bg-muted/50" />
            </div>
          ))}
        </div>
        <div className="h-80 animate-pulse rounded-lg border border-border bg-background-card" />
      </Page>
    );
  }

  if (!data) {
    return (
      <Page>
        <div className="rounded-lg border border-dashed border-border px-5 py-12 text-center text-sm text-foreground-secondary">
          Could not load billing.
        </div>
      </Page>
    );
  }

  const { financials: f, revenueSeries, recentActivity } = data;
  const activeRange = RANGES.find((r) => r.key === range) ?? RANGES[1];
  const rangeSeries = revenueSeries.slice(-activeRange.days);
  const rangeTotalCents = rangeSeries.reduce((s, d) => s + d.cents, 0);
  const rangeHasDeposits = rangeSeries.some((d) => d.cents > 0);

  return (
    <Page>
      <section className="grid grid-cols-2 gap-6 sm:gap-0 sm:divide-x sm:divide-border">
        <Kpi label="Deposits" value={usd(f.depositsCents)} />
        <Kpi label="Free credit burned" value={usd(f.freeCreditBurnedCents)} />
      </section>

      <section className="space-y-3">
        <div className="rounded-lg border border-border bg-background-card">
          <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Deposits</h3>
              <p className="mt-0.5 text-xs text-foreground-secondary">Top-ups + auto-recharge</p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <RangeTabs value={range} onChange={setRange} />
              <div className="text-right">
                <span className="text-2xl font-bold tabular-nums text-foreground">
                  {usd(rangeTotalCents)}
                </span>
                <span className="ml-2 text-xs text-foreground-secondary">{activeRange.totalLabel}</span>
              </div>
            </div>
          </div>
          <div className="h-72 px-2 pb-5 pt-1">
            {rangeHasDeposits ? (
              <DepositsChart data={rangeSeries} />
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-foreground-secondary">
                No deposits in {activeRange.emptyLabel}
              </div>
            )}
          </div>
        </div>
        {f.truncated && (
          <p className="text-xs text-foreground-muted">
            Some totals are a floor — ledger row cap reached.
          </p>
        )}
      </section>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">Recent billing activity</h2>
          <span className="text-xs text-foreground-secondary">
            {recentActivity.length} {recentActivity.length === 1 ? 'event' : 'events'}
          </span>
        </div>

        {recentActivity.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border px-5 py-10 text-center text-sm text-foreground-secondary">
            No recent billing activity
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border bg-background-card">
            <div className="grid grid-cols-[12rem_minmax(0,1fr)_9rem_8rem] gap-4 border-b border-border bg-background-card-header px-5 py-2.5 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
              <span>When</span>
              <span>Organization</span>
              <span>Type</span>
              <span className="text-right">Amount</span>
            </div>
            <div className="divide-y divide-border">
              {recentActivity.map((a) => (
                <div
                  key={a.id}
                  className="grid grid-cols-[12rem_minmax(0,1fr)_9rem_8rem] items-center gap-4 px-5 py-3 transition-colors hover:bg-table-hover"
                >
                  <span className="whitespace-nowrap text-sm text-foreground-secondary">
                    {formatDate(a.created_at)}
                  </span>
                  <span className="truncate text-sm text-foreground">
                    {a.organization_name || (
                      <span className="font-mono text-xs text-foreground-secondary">
                        {a.organization_id.slice(0, 8)}…
                      </span>
                    )}
                  </span>
                  <div className="flex">
                    <Badge variant="secondary">{KIND_LABEL[a.kind] ?? a.kind}</Badge>
                  </div>
                  <span
                    className={`text-right font-mono text-sm tabular-nums ${
                      a.amount_cents < 0 ? 'text-foreground-secondary' : 'text-emerald-500'
                    }`}
                  >
                    {signedUsd(a.amount_cents)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </Page>
  );
}
