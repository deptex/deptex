import React, { useMemo } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Checkbox } from '../ui/checkbox';
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
    return `wk ${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}`;
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
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: TooltipPayloadEntry[]; label?: string }) {
  if (!active || !payload || payload.length === 0) return null;
  const filtered = payload.filter((p) => p.value > 0);
  const total = filtered.reduce((sum, p) => sum + p.value, 0);
  return (
    <div className="rounded-md border border-border bg-background-card px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-foreground">{label}</p>
      <div className="mt-1 space-y-0.5">
        {filtered.map((p) => (
          <div key={p.dataKey} className="flex items-center gap-2 text-foreground-secondary">
            <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: p.color }} />
            <span className="flex-1">{featureLabel(p.dataKey)}</span>
            <span className="font-mono text-foreground">${(p.value / 100).toFixed(4)}</span>
          </div>
        ))}
      </div>
      <div className="mt-1 flex items-center justify-between border-t border-border pt-1 text-foreground">
        <span>Total</span>
        <span className="font-mono">${(total / 100).toFixed(4)}</span>
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

  return (
    <div className="rounded-lg border border-border bg-background-card">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
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
          <label className="flex items-center gap-2 text-xs text-foreground-secondary">
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
          <div className="flex h-full items-center justify-center text-sm text-foreground-secondary">Loading…</div>
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
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} content={<ChartTooltip />} />
                {features.map((feature, idx) => (
                  <Bar
                    key={feature}
                    dataKey={feature}
                    stackId="a"
                    fill={featureColor(feature, idx)}
                    radius={idx === features.length - 1 ? [2, 2, 0, 0] : 0}
                  />
                ))}
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
      {features.length > 0 && (
        <div className="flex flex-wrap gap-x-4 gap-y-2 border-t border-border px-5 py-3 text-xs text-foreground-secondary">
          {features.map((feature, idx) => (
            <div key={feature} className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: featureColor(feature, idx) }} />
              <span>{featureLabel(feature)}</span>
            </div>
          ))}
        </div>
      )}
      <div className="border-t border-border">
        <ProductBreakdownTable products={data?.products ?? []} loading={loading} />
      </div>
    </div>
  );
}
