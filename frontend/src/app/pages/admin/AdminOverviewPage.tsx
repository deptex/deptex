import { useEffect, useState, type ReactNode } from 'react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useToast } from '../../../hooks/use-toast';
import { apiAdminOverview, type AdminOverview, type AdminGrowthPoint } from '../../../lib/api';
import { RANGES, type RangeKey, RangeTabs, Kpi, num, dayLabel } from './adminUi';

const SERIES = [
  { key: 'orgs', label: 'Organizations', color: '#10b981' }, // emerald-500
  { key: 'projects', label: 'Projects', color: '#3b82f6' }, // blue-500
  { key: 'users', label: 'Users', color: '#a78bfa' }, // violet-400
] as const;

function GrowthTooltip({ active, payload }: { active?: boolean; payload?: any[] }) {
  if (!active || !payload || payload.length === 0) return null;
  const label = payload[0]?.payload?.label;
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background-card shadow-2xl">
      <div className="space-y-1.5 px-4 py-2.5">
        {payload.map((p: any) => (
          <div key={p.dataKey} className="flex items-center gap-3">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: p.color }} />
            <span className="flex-1 text-xs text-foreground-secondary">
              {SERIES.find((s) => s.key === p.dataKey)?.label ?? p.dataKey}
            </span>
            <span className="font-mono text-sm tabular-nums text-foreground">{p.value}</span>
          </div>
        ))}
      </div>
      <div className="border-t border-border px-4 py-1.5 text-xs text-foreground-secondary">{label}</div>
    </div>
  );
}

function GrowthChart({ data }: { data: AdminGrowthPoint[] }) {
  const chartData = data.map((d) => ({ ...d, label: dayLabel(d.date) }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
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
          width={40}
          allowDecimals={false}
          domain={[0, (max: number) => Math.max(4, Math.ceil(max * 1.15))]}
        />
        <Tooltip cursor={{ stroke: 'rgba(255,255,255,0.12)' }} content={<GrowthTooltip />} />
        {SERIES.map((s) => (
          <Line
            key={s.key}
            type="monotone"
            dataKey={s.key}
            stroke={s.color}
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
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
  return <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-10">{children}</div>;
}

export default function AdminOverviewPage() {
  const { toast } = useToast();
  const [data, setData] = useState<AdminOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [range, setRange] = useState<RangeKey>('30d');

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
        <div className="h-80 animate-pulse rounded-lg border border-border bg-background-card" />
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

  const { totals, growthSeries } = data;
  const activeRange = RANGES.find((r) => r.key === range) ?? RANGES[1];
  const rangeSeries = growthSeries.slice(-activeRange.days);

  return (
    <Page>
      <section className="grid grid-cols-3 gap-6 sm:gap-0 sm:divide-x sm:divide-border">
        <Kpi label="Organizations" value={num(totals.organizations)} />
        <Kpi label="Projects" value={num(totals.projects)} />
        <Kpi label="Users" value={num(totals.users)} />
      </section>

      <section className="space-y-3">
        <div className="rounded-lg border border-border bg-background-card">
          <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Growth</h3>
              <p className="mt-0.5 text-xs text-foreground-secondary">
                Cumulative organizations, projects &amp; users
              </p>
            </div>
            <RangeTabs value={range} onChange={setRange} />
          </div>
          <div className="flex items-center gap-4 px-5 pb-1">
            {SERIES.map((s) => (
              <LegendDot key={s.key} color={s.color} label={s.label} />
            ))}
          </div>
          <div className="h-72 px-2 pb-5 pt-1">
            <GrowthChart data={rangeSeries} />
          </div>
        </div>
      </section>
    </Page>
  );
}
