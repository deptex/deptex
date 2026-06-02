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
import { AlertTriangle, Ban, RefreshCw, Wallet } from 'lucide-react';
import { Badge } from '../../../components/ui/badge';
import { useToast } from '../../../hooks/use-toast';
import { apiAdminOverview, type AdminOverview, type AdminRevenuePoint } from '../../../lib/api';

const GREEN = '#10b981'; // emerald-500 — the brand accent; recharts needs a literal

function usd(cents: number): string {
  return (cents / 100).toLocaleString(undefined, { style: 'currency', currency: 'USD' });
}

function signedUsd(cents: number): string {
  const sign = cents < 0 ? '−' : '+';
  return `${sign}${(Math.abs(cents) / 100).toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
  })}`;
}

function num(n: number): string {
  return n.toLocaleString();
}

function formatDate(s: string | null): string {
  if (!s) return '—';
  return new Date(s).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function dayLabel(date: string): string {
  return new Date(`${date}T00:00:00Z`).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

const KIND_LABEL: Record<string, string> = {
  topup: 'Top-up',
  auto_recharge_topup: 'Auto-recharge',
  refund: 'Refund',
  adjustment: 'Adjustment',
  signup_grant: 'Signup credit',
};

// ── Revenue chart ──────────────────────────────────────────────────────────

function RevenueTooltip({ active, payload }: { active?: boolean; payload?: any[] }) {
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

function RevenueChart({ data }: { data: AdminRevenuePoint[] }) {
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
        <Tooltip cursor={{ stroke: 'rgba(255,255,255,0.12)' }} content={<RevenueTooltip />} />
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

// ── Small building blocks ────────────────────────────────────────────────────

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="sm:px-6 sm:first:pl-0">
      <div className="text-3xl font-bold leading-none tabular-nums text-foreground">{value}</div>
      <div className="mt-2 text-xs font-medium uppercase tracking-wider text-foreground-secondary">
        {label}
      </div>
    </div>
  );
}

function SideStat({
  icon,
  label,
  hint,
  value,
  tone = 'default',
}: {
  icon: ReactNode;
  label: string;
  hint: string;
  value: string;
  tone?: 'default' | 'warn';
}) {
  return (
    <div className="flex items-center gap-3 px-5 py-4">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background text-foreground-secondary">
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm text-foreground">{label}</div>
        <div className="text-xs text-foreground-muted">{hint}</div>
      </div>
      <div
        className={`font-mono text-base font-semibold tabular-nums ${
          tone === 'warn' ? 'text-warning' : 'text-foreground'
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function Page({ children }: { children: ReactNode }) {
  return <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-8">{children}</div>;
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AdminOverviewPage() {
  const { toast } = useToast();
  const [data, setData] = useState<AdminOverview | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const d = await apiAdminOverview();
        if (alive) setData(d);
      } catch (e: unknown) {
        if (alive) {
          toast({
            title: 'Failed to load overview',
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
        <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i}>
              <div className="h-8 w-20 animate-pulse rounded bg-muted" />
              <div className="mt-3 h-3 w-24 animate-pulse rounded bg-muted/50" />
            </div>
          ))}
        </div>
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="h-80 animate-pulse rounded-lg border border-border bg-background-card lg:col-span-2" />
          <div className="h-80 animate-pulse rounded-lg border border-border bg-background-card" />
        </div>
      </Page>
    );
  }

  if (!data) {
    return (
      <Page>
        <div className="rounded-lg border border-dashed border-border px-5 py-12 text-center text-sm text-foreground-secondary">
          Could not load the platform overview.
        </div>
      </Page>
    );
  }

  const { totals, billing, revenueSeries, recentActivity } = data;
  const hasRevenue = revenueSeries.some((d) => d.cents > 0);

  return (
    <Page>
      {/* Platform totals — bare numbers, not one-card-each */}
      <section className="grid grid-cols-2 gap-6 sm:grid-cols-4 sm:gap-0 sm:divide-x sm:divide-border">
        <Kpi label="Organizations" value={num(totals.organizations)} />
        <Kpi label="Projects" value={num(totals.projects)} />
        <Kpi label="Users" value={num(totals.users)} />
        <Kpi label="Scans · 30d" value={num(totals.scans30d)} />
      </section>

      {/* Revenue chart + billing metrics */}
      <section className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-background-card lg:col-span-2">
          <div className="flex items-start justify-between border-b border-border px-5 py-4">
            <div>
              <h2 className="text-sm font-semibold text-foreground">Revenue</h2>
              <p className="mt-0.5 text-xs text-foreground-secondary">
                Top-ups + auto-recharge · last 30 days
              </p>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold leading-none tabular-nums text-foreground">
                {usd(billing.revenue30dCents)}
              </div>
              <div className="mt-1 text-xs text-foreground-secondary">total</div>
            </div>
          </div>
          <div className="h-64 px-2 py-4">
            {hasRevenue ? (
              <RevenueChart data={revenueSeries} />
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-foreground-secondary">
                No revenue in the last 30 days
              </div>
            )}
          </div>
        </div>

        <div className="divide-y divide-border rounded-lg border border-border bg-background-card">
          <SideStat
            icon={<Wallet className="h-4 w-4" />}
            label="Balance held"
            hint="across all orgs"
            value={usd(billing.totalBalanceCents)}
          />
          <SideStat
            icon={<RefreshCw className="h-4 w-4" />}
            label="Auto-recharge on"
            hint="organizations"
            value={num(billing.autoRechargeOn)}
          />
          <SideStat
            icon={<AlertTriangle className="h-4 w-4" />}
            label="Failed payments"
            hint="last 7 days"
            value={num(billing.failedPayments7d)}
            tone={billing.failedPayments7d > 0 ? 'warn' : 'default'}
          />
          <SideStat
            icon={<Ban className="h-4 w-4" />}
            label="Orgs at $0"
            hint="empty balance"
            value={num(billing.zeroBalanceOrgs)}
            tone={billing.zeroBalanceOrgs > 0 ? 'warn' : 'default'}
          />
        </div>
      </section>

      {/* Recent activity — a real table on the page, not buried in a card */}
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
            <div className="grid grid-cols-[7rem_1.4fr_8rem_auto] gap-4 border-b border-border bg-background-card-header px-5 py-2.5 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
              <span>When</span>
              <span>Organization</span>
              <span>Type</span>
              <span className="text-right">Amount</span>
            </div>
            <div className="divide-y divide-border">
              {recentActivity.map((a) => (
                <div
                  key={a.id}
                  className="grid grid-cols-[7rem_1.4fr_8rem_auto] items-center gap-4 px-5 py-3 transition-colors hover:bg-table-hover"
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
                  <span>
                    <Badge variant="secondary">{KIND_LABEL[a.kind] ?? a.kind}</Badge>
                  </span>
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
