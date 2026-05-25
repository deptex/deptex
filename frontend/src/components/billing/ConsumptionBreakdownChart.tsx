import React, { useMemo, useState } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Checkbox } from '../ui/checkbox';
import { Skeleton } from '../ui/skeleton';
import { cn } from '../../lib/utils';
import { ProductBreakdownTable } from './ProductBreakdownTable';
import {
  type UsageBreakdownResponse,
  type UsageGranularity,
  featureColor,
  featureLabel,
} from './usage-types';

const TAB_OPTIONS: Array<{ id: UsageGranularity; label: string }> = [
  { id: 'day', label: 'Daily' },
  { id: 'week', label: 'Weekly' },
  { id: 'month', label: 'Monthly' },
];

function formatTick(ts: string, granularity: UsageGranularity): string {
  const d = new Date(ts + (granularity === 'month' ? 'T00:00:00Z' : 'T00:00:00Z'));
  if (granularity === 'month') {
    return d.toLocaleDateString(undefined, { month: 'short', year: '2-digit' });
  }
  if (granularity === 'week') {
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function formatCentsAxis(value: number): string {
  if (value === 0) return '$0';
  if (value < 100) return `$${(value / 100).toFixed(2)}`;
  return `$${(value / 100).toFixed(0)}`;
}

interface ConsumptionBreakdownChartProps {
  data: UsageBreakdownResponse | null;
  loading: boolean;
  granularity: UsageGranularity;
  onGranularityChange: (g: UsageGranularity) => void;
  cumulative: boolean;
  onCumulativeChange: (b: boolean) => void;
}

interface TooltipPayloadEntry {
  dataKey: string;
  value: number;
  color: string;
  payload?: { ts?: string };
}

function formatTooltipDate(ts: string | undefined, granularity: UsageGranularity): string {
  if (!ts) return '';
  const d = new Date(ts + 'T00:00:00Z');
  if (granularity === 'month') {
    return d.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  }
  if (granularity === 'week') {
    const end = new Date(d);
    end.setUTCDate(end.getUTCDate() + 6);
    const monthFmt = (x: Date) => x.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    return `${monthFmt(d)} – ${monthFmt(end)}, ${end.getUTCFullYear()}`;
  }
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatCentsTooltip(cents: number): string {
  const dollars = cents / 100;
  if (dollars >= 1) return `$${dollars.toFixed(2)}`;
  if (dollars >= 0.01) return `$${dollars.toFixed(2)}`;
  return `$${dollars.toFixed(4)}`;
}

const SKELETON_BAR_HEIGHTS = [
  42, 55, 38, 71, 48, 62, 35, 58, 67, 51, 44, 73, 60, 49, 65, 56, 41, 68, 53, 47,
  60, 52, 64, 45, 70, 58, 49, 63, 55, 50,
];

function ChartSkeleton() {
  return (
    <div className="flex h-full items-end gap-1 px-10 pb-6 pt-2">
      {SKELETON_BAR_HEIGHTS.map((h, i) => (
        <Skeleton key={i} className="flex-1 rounded-t-sm" style={{ height: `${h}%` }} />
      ))}
    </div>
  );
}

function ChartTooltip({
  active,
  payload,
  granularity,
}: {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  granularity: UsageGranularity;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const filtered = payload.filter((p) => p.value > 0).sort((a, b) => b.value - a.value);
  if (filtered.length === 0) return null;
  const total = filtered.reduce((sum, p) => sum + p.value, 0);
  const ts = payload[0]?.payload?.ts;
  const dateLabel = formatTooltipDate(ts, granularity);

  return (
    <div className="min-w-[240px] overflow-hidden rounded-lg border border-border bg-background-card shadow-2xl">
      <div className="space-y-2 px-4 py-3">
        {filtered.map((p) => (
          <div key={p.dataKey} className="flex items-center gap-3">
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-full"
              style={{ backgroundColor: p.color }}
            />
            <span className="flex-1 truncate text-sm text-foreground">{featureLabel(p.dataKey)}</span>
            <span className="font-mono text-sm tabular-nums text-foreground">
              {formatCentsTooltip(p.value)}
            </span>
          </div>
        ))}
      </div>
      <div className="flex items-center justify-between border-t border-border px-4 py-2.5">
        <span className="text-xs text-foreground-secondary">{dateLabel}</span>
        <span className="font-mono text-sm font-semibold tabular-nums text-foreground">
          {formatCentsTooltip(total)}
        </span>
      </div>
    </div>
  );
}

export function ConsumptionBreakdownChart({
  data,
  loading,
  granularity,
  onGranularityChange,
  cumulative,
  onCumulativeChange,
}: ConsumptionBreakdownChartProps) {
  const chartData = useMemo(() => {
    if (!data) return [];
    return data.buckets.map((bucket) => ({
      ...bucket.byFeature,
      ts: bucket.ts,
      _label: formatTick(bucket.ts, granularity),
    }));
  }, [data, granularity]);

  const features = useMemo(() => {
    if (!data) return [] as string[];
    const set = new Set<string>();
    for (const bucket of data.buckets) {
      for (const key of Object.keys(bucket.byFeature)) set.add(key);
    }
    return [...set];
  }, [data]);

  const [hoveredProduct, setHoveredProduct] = useState<string | null>(null);
  const activeProduct = hoveredProduct;

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background-card">
      <div className="flex items-center justify-between border-b border-border bg-background-card-header px-5 py-4">
        <h3 className="text-base font-semibold text-foreground">Consumption Breakdown</h3>
        <div className="flex items-center gap-4">
          <div className="flex rounded-md border border-border bg-background p-0.5">
            {TAB_OPTIONS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => onGranularityChange(tab.id)}
                className={cn(
                  'rounded px-3 py-1 text-xs font-medium transition-colors',
                  granularity === tab.id
                    ? 'bg-background-card-hover text-foreground'
                    : 'text-foreground-secondary hover:text-foreground',
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <label
            className={cn(
              'flex cursor-pointer select-none items-center gap-2 rounded-md px-2 py-1 text-xs transition-colors',
              'text-foreground-secondary hover:bg-background-subtle hover:text-foreground',
            )}
          >
            <Checkbox
              checked={cumulative}
              onCheckedChange={(c) => onCumulativeChange(c === true)}
              className="data-[state=checked]:border-white data-[state=checked]:bg-white data-[state=checked]:text-black"
            />
            Cumulative
          </label>
        </div>
      </div>
      <div className="relative h-72 px-2 py-4">
        {loading && !data ? (
          <ChartSkeleton />
        ) : (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis
                  dataKey="_label"
                  tick={{ fontSize: 12, fill: 'rgba(255,255,255,0.55)' }}
                  tickLine={false}
                  axisLine={false}
                  interval="preserveStartEnd"
                  minTickGap={36}
                  padding={{ left: 12, right: 12 }}
                />
                <YAxis
                  tick={{ fontSize: 12, fill: 'rgba(255,255,255,0.55)' }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={formatCentsAxis}
                  width={44}
                  domain={[0, (dataMax: number) => (dataMax > 0 ? Math.ceil(dataMax * 1.1) : 500)]}
                  allowDecimals={false}
                  tickCount={6}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  content={(props: any) => <ChartTooltip {...props} granularity={granularity} />}
                />
                {features.map((feature, idx) => {
                  const dim = activeProduct !== null && activeProduct !== feature;
                  return (
                    <Bar
                      key={feature}
                      dataKey={feature}
                      stackId="a"
                      fill={featureColor(feature, idx)}
                      fillOpacity={dim ? 0.15 : 1}
                      radius={idx === features.length - 1 ? [2, 2, 0, 0] : 0}
                      isAnimationActive={false}
                    />
                  );
                })}
              </BarChart>
            </ResponsiveContainer>
            {(!data || data.totalCents === 0) && (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
                <span className="rounded-full border border-border bg-background-card/80 px-3 py-1 text-xs text-foreground-secondary backdrop-blur-sm">
                  No usage in this range
                </span>
              </div>
            )}
          </>
        )}
      </div>
      <ProductBreakdownTable
        products={data?.products ?? []}
        loading={loading}
        onProductHover={setHoveredProduct}
      />
    </div>
  );
}
