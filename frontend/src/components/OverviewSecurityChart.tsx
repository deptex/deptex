import { useEffect, useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import { api } from '../lib/api';
import type { ProjectStats } from '../lib/api';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#64748b',
};

interface OverviewSecurityChartProps {
  organizationId: string;
  projectId: string;
  stats: ProjectStats | null;
  statsLoading: boolean;
}

export function OverviewSecurityChart({
  organizationId,
  projectId,
  stats,
  statsLoading,
}: OverviewSecurityChartProps) {
  const [timeline, setTimeline] = useState<{ date: string; detected: number; resolved: number }[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    setTimelineLoading(true);
    api
      .getProjectVulnerabilityTimeline(organizationId, projectId, 30)
      .then((r) => {
        if (mounted) setTimeline(r.timeline ?? []);
      })
      .catch(() => {
        if (mounted) setTimeline([]);
      })
      .finally(() => {
        if (mounted) setTimelineLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [organizationId, projectId]);

  // Build full 30-day timeline (so we always show a graph, with zeros when no events)
  const last30Days: { date: string; detected: number; resolved: number }[] = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    last30Days.push({ date: d.toISOString().slice(0, 10), detected: 0, resolved: 0 });
  }
  const timelineByDate = new Map(timeline.map((t) => [t.date, { detected: t.detected, resolved: t.resolved }]));
  const chartTimeline = last30Days.map((day) => {
    const fromApi = timelineByDate.get(day.date);
    return fromApi ? { date: day.date, detected: fromApi.detected, resolved: fromApi.resolved } : day;
  });

  // Severity: always show all four bars (value can be 0)
  const severityData = [
    { key: 'critical', label: 'Critical', value: stats?.vulnerabilities?.critical ?? 0 },
    { key: 'high', label: 'High', value: stats?.vulnerabilities?.high ?? 0 },
    { key: 'medium', label: 'Medium', value: stats?.vulnerabilities?.medium ?? 0 },
    { key: 'low', label: 'Low', value: stats?.vulnerabilities?.low ?? 0 },
  ];

  if (statsLoading && timelineLoading) {
    return (
      <div className="rounded-lg border border-border bg-background-card p-5">
        <h3 className="text-sm font-semibold text-foreground mb-4">Security</h3>
        <div className="h-48 animate-pulse rounded bg-muted/30" />
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-background-card p-5">
      <h3 className="text-sm font-semibold text-foreground mb-4">Security</h3>

      {/* Vulnerabilities over time — always show graph (zeros when no data) */}
      {timelineLoading ? (
        <div className="h-40 animate-pulse rounded bg-muted/20 mb-5" />
      ) : (
        <div className="h-40 w-full mb-5">
          <p className="text-xs text-foreground-secondary mb-2">Vulnerability events (last 30 days)</p>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartTimeline} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10 }}
                tickFormatter={(v) => (v ? new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '')}
              />
              <YAxis tick={{ fontSize: 10 }} allowDecimals={false} width={24} domain={[0, 'auto']} />
              <Tooltip
                labelFormatter={(label) => (label ? new Date(label).toLocaleDateString() : '')}
                formatter={(value: number) => [value, '']}
                contentStyle={{
                  backgroundColor: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
              />
              <Area
                type="monotone"
                dataKey="detected"
                name="Detected"
                stackId="1"
                stroke="#f97316"
                fill="#f97316"
                fillOpacity={0.4}
              />
              <Area
                type="monotone"
                dataKey="resolved"
                name="Resolved"
                stackId="2"
                stroke="#22c55e"
                fill="#22c55e"
                fillOpacity={0.4}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Vulnerabilities by severity — always show graph (zeros when no vulns) */}
      <p className="text-xs text-foreground-secondary mb-2">Vulnerabilities by severity</p>
      <div className="h-20 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={severityData} layout="vertical" margin={{ top: 0, right: 8, left: 40, bottom: 0 }}>
            <XAxis type="number" tick={{ fontSize: 10 }} allowDecimals={false} domain={[0, 'auto']} />
            <YAxis type="category" dataKey="label" tick={{ fontSize: 10 }} width={50} />
            <Bar dataKey="value" name="Count" radius={0}>
              {severityData.map((entry) => (
                <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key as keyof typeof SEVERITY_COLORS] ?? '#64748b'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
