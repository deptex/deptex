import React, { useState, useEffect } from 'react';
import { Sparkles, ArrowRight, Star, TrendingUp } from 'lucide-react';
import { Card, CardContent } from '../ui/card';
import {
  BarChart, Bar, LineChart, Line, Area, AreaChart, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Cell,
} from 'recharts';
import { api, LearningDashboard as LearningDashboardData } from '../../lib/api';

interface LearningDashboardProps {
  orgId: string;
}

export function LearningDashboard({ orgId }: LearningDashboardProps) {
  const [data, setData] = useState<LearningDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<string>('all');

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    api.getLearningDashboard(orgId, timeRange === 'all' ? undefined : timeRange)
      .then(d => { if (mounted) setData(d); })
      .catch(() => { if (mounted) setData(null); })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [orgId, timeRange]);

  if (loading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map(i => (
          <Card key={i} className="bg-[#18181b] border-[#27272a]">
            <CardContent className="p-5">
              <div className="h-40 animate-pulse bg-zinc-800/50 rounded" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (!data || data.totalOutcomes === 0) {
    return (
      <Card className="bg-[#18181b] border-[#27272a] max-w-lg">
        <CardContent className="pt-12 pb-12 text-center">
          <Sparkles className="h-12 w-12 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">Aegis Learning</h3>
          <p className="text-zinc-400 text-sm">No fix outcomes recorded yet.</p>
          <p className="text-zinc-500 text-xs mt-1">
            As Aegis fixes vulnerabilities, it will learn which strategies work best for your organization.
          </p>
        </CardContent>
      </Card>
    );
  }

  const overallRate = data.totalOutcomes > 0
    ? Math.round((data.totalSuccesses / data.totalOutcomes) * 100)
    : 0;

  return (
    <div className="space-y-4">
      {/* Strategy Performance Matrix */}
      <Card className="bg-[#18181b] border-[#27272a]">
        <CardContent className="p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[15px] font-semibold text-white">Strategy Performance</h3>
            <div className="flex gap-1.5">
              {['30d', '90d', 'all'].map(range => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-2.5 py-1 text-xs rounded transition-colors ${
                    timeRange === range
                      ? 'bg-zinc-700 text-white'
                      : 'text-zinc-500 hover:text-zinc-400'
                  }`}
                >
                  {range === '30d' ? 'Last 30 days' : range === '90d' ? 'Last 90 days' : 'All time'}
                </button>
              ))}
            </div>
          </div>

          {data.strategyMatrix.length === 0 ? (
            <EmptySection text="No strategy patterns computed yet." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-zinc-500 text-xs">
                  <th className="text-left pb-2 font-medium">Strategy</th>
                  <th className="text-left pb-2 font-medium w-[140px]">Success Rate</th>
                  <th className="text-right pb-2 font-medium">Samples</th>
                  <th className="text-right pb-2 font-medium">Confidence</th>
                  <th className="text-right pb-2 font-medium">Avg Cost</th>
                  <th className="text-right pb-2 font-medium">Avg Duration</th>
                </tr>
              </thead>
              <tbody>
                {data.strategyMatrix
                  .sort((a, b) => b.successRate - a.successRate)
                  .map((row, idx) => {
                    const pct = Math.round(row.successRate * 100);
                    const isBest = idx === 0;
                    return (
                      <tr
                        key={row.strategy}
                        className={isBest ? 'bg-green-500/[0.03]' : ''}
                      >
                        <td className="py-1.5 text-white">{row.displayName}</td>
                        <td className="py-1.5">
                          <div className="flex items-center gap-2">
                            <div className="w-[90px] h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                              <div
                                className="h-full rounded-full bg-green-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <span className="font-mono text-xs text-white">{pct}%</span>
                          </div>
                        </td>
                        <td className="py-1.5 text-right font-mono text-xs text-zinc-400">{row.samples}</td>
                        <td className="py-1.5 text-right">
                          <ConfidenceBadge confidence={row.confidence} />
                        </td>
                        <td className="py-1.5 text-right font-mono text-xs text-zinc-400">
                          {row.avgCost != null ? `$${Number(row.avgCost).toFixed(2)}` : '—'}
                        </td>
                        <td className="py-1.5 text-right font-mono text-xs text-zinc-400">
                          {row.avgDuration != null ? `${Math.round(row.avgDuration / 60)}m` : '—'}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* Learning Curve */}
      <Card className="bg-[#18181b] border-[#27272a]">
        <CardContent className="p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[15px] font-semibold text-white">Fix Success Rate Over Time</h3>
            {data.learningCurve.length >= 3 && (
              <span className="text-xs text-green-500 flex items-center gap-1">
                <TrendingUp className="h-3 w-3" />
                {overallRate}% overall
              </span>
            )}
          </div>

          {data.learningCurve.length < 3 ? (
            <EmptySection text="Not enough data yet. Need at least 3 months of fix activity." />
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={data.learningCurve} margin={{ top: 5, right: 5, bottom: 5, left: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                <XAxis
                  dataKey="month"
                  tick={{ fontSize: 10, fill: '#71717a' }}
                  tickFormatter={(v) => v.slice(5)}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 1]}
                  tickFormatter={(v) => `${Math.round(v * 100)}%`}
                  tick={{ fontSize: 10, fill: '#71717a' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#a1a1aa' }}
                  formatter={(value: number, _name: string, props: any) =>
                    [`${Math.round(value * 100)}% (${props.payload.successes}/${props.payload.total})`, 'Success Rate']
                  }
                />
                <defs>
                  <linearGradient id="successGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22c55e" stopOpacity={0.1} />
                    <stop offset="100%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <Area
                  type="monotone"
                  dataKey="successRate"
                  stroke="#22c55e"
                  strokeWidth={2}
                  fill="url(#successGrad)"
                  dot={{ fill: '#22c55e', r: 3 }}
                />
                <Line
                  type="monotone"
                  dataKey={() => 0.5}
                  stroke="#3f3f46"
                  strokeDasharray="4 4"
                  strokeWidth={1}
                  dot={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* Failure Analysis */}
      <Card className="bg-[#18181b] border-[#27272a]">
        <CardContent className="p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[15px] font-semibold text-white">Common Failure Reasons</h3>
            <span className="text-xs text-zinc-500">
              {data.totalOutcomes - data.totalSuccesses} total failures
            </span>
          </div>

          {data.failureAnalysis.length === 0 ? (
            <EmptySection text="No failures recorded yet." />
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(120, data.failureAnalysis.length * 32)}>
              <BarChart data={data.failureAnalysis} layout="vertical" margin={{ left: 100, right: 40 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="displayName"
                  tick={{ fontSize: 11, fill: '#a1a1aa' }}
                  axisLine={false}
                  tickLine={false}
                  width={95}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a', borderRadius: 8, fontSize: 12 }}
                  formatter={(value: number, _name: string, props: any) =>
                    [`${value} (${Math.round(props.payload.percentage * 100)}%)`, 'Count']
                  }
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {data.failureAnalysis.map((_, i) => (
                    <Cell key={i} fill="rgba(239, 68, 68, 0.7)" />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* Follow-up Chains */}
      <Card className="bg-[#18181b] border-[#27272a]">
        <CardContent className="p-5">
          <h3 className="text-[15px] font-semibold text-white mb-4">
            When a Strategy Fails, What Works Next?
          </h3>

          {data.followupChains.length === 0 ? (
            <EmptySection text="No follow-up chains detected yet." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-zinc-500 text-xs">
                  <th className="text-left pb-2 font-medium">Failed Strategy</th>
                  <th className="text-left pb-2 font-medium"></th>
                  <th className="text-left pb-2 font-medium">Best Follow-up</th>
                  <th className="text-left pb-2 font-medium w-[120px]">Success Rate</th>
                  <th className="text-right pb-2 font-medium">Samples</th>
                </tr>
              </thead>
              <tbody>
                {data.followupChains.map((chain, i) => (
                  <tr key={i}>
                    <td className="py-1.5 text-red-400">{chain.failedDisplayName}</td>
                    <td className="py-1.5 text-center">
                      <ArrowRight className="h-3 w-3 text-zinc-600 mx-auto" />
                    </td>
                    <td className="py-1.5 text-green-400">{chain.followupDisplayName}</td>
                    <td className="py-1.5">
                      <div className="flex items-center gap-2">
                        <div className="w-[70px] h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                          <div
                            className="h-full rounded-full bg-green-500"
                            style={{ width: `${Math.round(chain.followupSuccessRate * 100)}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs text-white">
                          {Math.round(chain.followupSuccessRate * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="py-1.5 text-right font-mono text-xs text-zinc-400">{chain.samples}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* Quality Insights */}
      <Card className="bg-[#18181b] border-[#27272a]">
        <CardContent className="p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[15px] font-semibold text-white">Human Quality Ratings</h3>
            <span className="text-xs text-zinc-500">
              Based on {data.totalRatings} rating{data.totalRatings !== 1 ? 's' : ''}
            </span>
          </div>

          {data.qualityInsights.length === 0 ? (
            <EmptySection text="No feedback collected yet." />
          ) : (
            <div className="space-y-3">
              {data.qualityInsights.map(insight => (
                <div key={insight.strategy} className="flex items-center gap-4">
                  <span className="text-sm text-white w-28 shrink-0">{insight.displayName}</span>
                  <div className="flex items-center gap-0.5">
                    {[1, 2, 3, 4, 5].map(star => (
                      <Star
                        key={star}
                        className={`h-3.5 w-3.5 ${
                          star <= Math.round(insight.avgRating)
                            ? 'text-amber-400 fill-amber-400'
                            : 'text-zinc-700'
                        }`}
                      />
                    ))}
                  </div>
                  <span className="text-xs font-mono text-white">
                    {insight.avgRating.toFixed(1)}
                  </span>
                  <span className="text-xs text-zinc-500">
                    ({insight.totalRatings})
                  </span>
                  <div className="flex-1 flex h-1.5 rounded-full overflow-hidden bg-zinc-800">
                    {insight.distribution.map((count, i) => {
                      const total = insight.distribution.reduce((a, b) => a + b, 0);
                      const pct = total > 0 ? (count / total) * 100 : 0;
                      const colors = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#22c55e'];
                      return pct > 0 ? (
                        <div
                          key={i}
                          className="h-full"
                          style={{ width: `${pct}%`, backgroundColor: colors[i] }}
                        />
                      ) : null;
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const classes = confidence === 'high'
    ? 'bg-green-500/10 text-green-400'
    : confidence === 'medium'
    ? 'bg-amber-500/10 text-amber-400'
    : 'bg-zinc-800 text-zinc-500';

  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded ${classes}`}>
      {confidence.charAt(0).toUpperCase() + confidence.slice(1)}
    </span>
  );
}

function EmptySection({ text }: { text: string }) {
  return (
    <div className="py-8 text-center">
      <Sparkles className="h-8 w-8 text-zinc-700 mx-auto mb-2" />
      <p className="text-xs text-zinc-500">{text}</p>
    </div>
  );
}
