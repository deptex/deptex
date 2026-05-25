import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { supabase } from '../../lib/supabase';
import { useBilling } from '../../contexts/PlanContext';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../ui/select';
import { Progress } from '../ui/progress';
import { DateRangePicker } from './DateRangePicker';
import { ConsumptionBreakdownChart } from './ConsumptionBreakdownChart';
import { ProductBreakdownTable } from './ProductBreakdownTable';
import {
  type DateRange,
  type FeatureCategory,
  type ProjectOption,
  type UsageBreakdownResponse,
  type UsageGranularity,
  featureLabel,
} from './usage-types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

async function authedFetch(input: string, init?: RequestInit) {
  const { data: session } = await supabase.auth.getSession();
  const token = session.session?.access_token;
  if (!token) throw new Error('Not authenticated');
  return fetch(input, {
    ...init,
    headers: { ...(init?.headers ?? {}), Authorization: `Bearer ${token}` },
  });
}

const CATEGORY_OPTIONS: Array<{ value: FeatureCategory; label: string }> = [
  { value: 'all', label: 'All products' },
  { value: 'ai', label: 'AI usage' },
  { value: 'workers', label: 'Worker time' },
];

const WORKER_FEATURE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'all', label: 'All workers' },
  { value: 'depscanner.scan', label: 'Extraction worker' },
  { value: 'depscanner.dast', label: 'DAST worker' },
  { value: 'depscanner.dast_zap_dry_run', label: 'DAST probe' },
  { value: 'fix-worker.task', label: 'Fix worker' },
];

const AI_FEATURE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'all', label: 'All AI' },
  { value: 'aegis.chat', label: 'Aegis chat' },
  { value: 'rule.generation', label: 'Rule generation' },
  { value: 'epd.scoring', label: 'EPD scoring' },
];

interface UsageSectionContentProps {
  organizationId: string;
}

function defaultRange(): DateRange {
  return {
    start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    end: new Date(),
    preset: 'last_30d',
  };
}

export function UsageSectionContent({ organizationId }: UsageSectionContentProps) {
  const { billing } = useBilling();
  const [range, setRange] = useState<DateRange>(defaultRange);
  const [category, setCategory] = useState<FeatureCategory>('all');
  const [subFeature, setSubFeature] = useState<string>('all');
  const [projectId, setProjectId] = useState<string>('all');
  const [granularity, setGranularity] = useState<UsageGranularity>('day');
  const [cumulative, setCumulative] = useState(false);

  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [data, setData] = useState<UsageBreakdownResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset subFeature when category changes so the dropdown stays consistent.
  useEffect(() => {
    setSubFeature('all');
  }, [category]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/projects`);
        if (!res.ok) return;
        const body = (await res.json()) as { projects?: Array<{ id: string; name: string }> } | Array<{ id: string; name: string }>;
        const list = Array.isArray(body) ? body : body.projects ?? [];
        if (!cancelled) setProjects(list.map((p) => ({ id: p.id, name: p.name })));
      } catch (err) {
        console.warn('[usage] projects load failed', err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [organizationId]);

  const loadBreakdown = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        granularity,
        category,
        cumulative: String(cumulative),
        start: range.start.toISOString(),
        end: range.end.toISOString(),
      });
      if (subFeature !== 'all') params.set('feature', subFeature);
      if (projectId !== 'all') params.set('project_id', projectId);

      const res = await authedFetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/billing/usage/breakdown?${params.toString()}`,
      );
      if (!res.ok) throw new Error(`Failed to load (${res.status})`);
      const body = (await res.json()) as UsageBreakdownResponse;
      setData(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load usage');
    } finally {
      setLoading(false);
    }
  }, [organizationId, granularity, category, cumulative, range, subFeature, projectId]);

  useEffect(() => {
    void loadBreakdown();
  }, [loadBreakdown]);

  const subFeatureOptions = category === 'ai'
    ? AI_FEATURE_OPTIONS
    : category === 'workers'
    ? WORKER_FEATURE_OPTIONS
    : null;

  const balanceCents = billing?.balanceCents ?? 0;
  const totalCents = data?.totalCents ?? 0;
  const signupGrant = 500;
  const usedFromGrant = Math.min(totalCents, signupGrant);
  const grantUsedPct = (usedFromGrant / signupGrant) * 100;
  const totalDollars = (totalCents / 100).toFixed(2);
  const balanceDollars = (balanceCents / 100).toFixed(2);

  return (
    <div className="space-y-6 pt-8">
      <header>
        <h2 className="text-2xl font-semibold tracking-tight text-foreground">Usage</h2>
        <p className="mt-1 text-sm text-foreground-secondary">
          Itemized billing across AI tokens and worker time.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2">
        <DateRangePicker value={range} onChange={setRange} />

        <Select value={category} onValueChange={(v) => setCategory(v as FeatureCategory)}>
          <SelectTrigger className="h-9 min-w-[180px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            {CATEGORY_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {subFeatureOptions && (
          <Select value={subFeature} onValueChange={setSubFeature}>
            <SelectTrigger className="h-9 min-w-[180px]">
              <SelectValue placeholder="Feature" />
            </SelectTrigger>
            <SelectContent>
              {subFeatureOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        <Select value={projectId} onValueChange={setProjectId}>
          <SelectTrigger className="h-9 min-w-[180px]">
            <SelectValue placeholder="Project" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All projects</SelectItem>
            {projects.map((project) => (
              <SelectItem key={project.id} value={project.id}>
                {project.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-lg border border-border bg-background-card p-6">
          <p className="text-xs uppercase tracking-wider text-foreground-secondary">Spend in range</p>
          <p className="mt-2 text-3xl font-semibold tracking-tight text-foreground">${totalDollars}</p>
          <p className="mt-1 text-xs text-foreground-secondary">
            {data ? `${data.buckets.reduce((n, b) => n + Object.keys(b.byFeature).length, 0)} events` : '—'}
          </p>
        </div>
        <div className="rounded-lg border border-border bg-background-card p-6">
          <div className="flex items-baseline justify-between">
            <p className="text-xs uppercase tracking-wider text-foreground-secondary">Welcome credit used</p>
            <p className="font-mono text-xs text-foreground-secondary">
              ${(usedFromGrant / 100).toFixed(2)} / $5.00
            </p>
          </div>
          <p className="mt-2 text-3xl font-semibold tracking-tight text-foreground">${balanceDollars}</p>
          <p className="mt-1 text-xs text-foreground-secondary">Current balance</p>
          <Progress value={grantUsedPct} className="mt-3 h-2" />
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      <ConsumptionBreakdownChart
        data={data}
        loading={loading}
        granularity={granularity}
        onGranularityChange={setGranularity}
        cumulative={cumulative}
        onCumulativeChange={setCumulative}
      />

      <section>
        <h3 className="mb-3 text-base font-semibold text-foreground">By product</h3>
        <ProductBreakdownTable products={data?.products ?? []} loading={loading} />
      </section>

      <footer className="pt-2 text-xs text-foreground-secondary">
        {subFeature !== 'all' ? <p>Filtered to: {featureLabel(subFeature)}</p> : null}
      </footer>
    </div>
  );
}
