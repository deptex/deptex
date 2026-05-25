import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { supabase } from '../../lib/supabase';
import { MultiSelect, type MultiSelectOption } from '../ui/multi-select';
import { FrameworkIcon } from '../framework-icon';
import { DateRangePicker } from './DateRangePicker';
import { ConsumptionBreakdownChart } from './ConsumptionBreakdownChart';
import { ProductBreakdownTable } from './ProductBreakdownTable';
import {
  FEATURE_LABEL,
  type DateRange,
  type ProjectOption,
  type UsageBreakdownResponse,
  type UsageGranularity,
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

const PRODUCT_OPTIONS: MultiSelectOption[] = [
  { value: 'aegis.chat', label: FEATURE_LABEL['aegis.chat'] },
  { value: 'rule.generation', label: FEATURE_LABEL['rule.generation'] },
  { value: 'epd.scoring', label: FEATURE_LABEL['epd.scoring'] },
  { value: 'depscanner.scan', label: FEATURE_LABEL['depscanner.scan'] },
  { value: 'depscanner.dast', label: FEATURE_LABEL['depscanner.dast'] },
  { value: 'depscanner.dast_zap_dry_run', label: FEATURE_LABEL['depscanner.dast_zap_dry_run'] },
  { value: 'fix-worker.task', label: FEATURE_LABEL['fix-worker.task'] },
];
const ALL_PRODUCT_VALUES = PRODUCT_OPTIONS.map((o) => o.value);

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
  const [range, setRange] = useState<DateRange>(defaultRange);
  const [selectedProducts, setSelectedProducts] = useState<string[]>(ALL_PRODUCT_VALUES);
  const [selectedProjects, setSelectedProjects] = useState<string[]>([]);
  const [allProjectsSelected, setAllProjectsSelected] = useState(true);
  const [granularity, setGranularity] = useState<UsageGranularity>('day');
  const [cumulative, setCumulative] = useState(false);

  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [data, setData] = useState<UsageBreakdownResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/projects`);
        if (!res.ok) return;
        const body = (await res.json()) as
          | { projects?: Array<{ id: string; name: string; framework?: string | null }> }
          | Array<{ id: string; name: string; framework?: string | null }>;
        const list = Array.isArray(body) ? body : body.projects ?? [];
        const mapped: ProjectOption[] = list.map((p) => ({ id: p.id, name: p.name, framework: p.framework ?? null }));
        if (!cancelled) {
          setProjects(mapped);
          setSelectedProjects(mapped.map((p) => p.id));
        }
      } catch (err) {
        console.warn('[usage] projects load failed', err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [organizationId]);

  const projectOptions = useMemo<MultiSelectOption[]>(
    () =>
      projects.map((p) => ({
        value: p.id,
        label: p.name,
        icon: <FrameworkIcon frameworkId={p.framework ?? undefined} size={14} className="text-foreground-secondary" />,
      })),
    [projects],
  );

  const loadBreakdown = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        granularity,
        cumulative: String(cumulative),
        start: range.start.toISOString(),
        end: range.end.toISOString(),
      });
      if (selectedProducts.length < ALL_PRODUCT_VALUES.length) {
        params.set('features', selectedProducts.length > 0 ? selectedProducts.join(',') : '__none__');
      }
      if (!allProjectsSelected && projects.length > 0) {
        params.set('project_ids', selectedProjects.length > 0 ? selectedProjects.join(',') : '__none__');
      }

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
  }, [
    organizationId,
    granularity,
    cumulative,
    range,
    selectedProducts,
    selectedProjects,
    allProjectsSelected,
    projects.length,
  ]);

  useEffect(() => {
    void loadBreakdown();
  }, [loadBreakdown]);

  const totalDollars = ((data?.totalCents ?? 0) / 100).toFixed(2);

  return (
    <div className="space-y-6 pt-8">
      <header>
        <h2 className="text-2xl font-semibold tracking-tight text-foreground">Usage</h2>
        <p className="mt-1 text-sm text-foreground-secondary">
          Itemized billing across AI tokens and worker time. Balance and top-ups live on the Plan & Billing tab.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2">
        <DateRangePicker value={range} onChange={setRange} />

        <MultiSelect
          options={PRODUCT_OPTIONS}
          selected={selectedProducts}
          onChange={setSelectedProducts}
          renderLabel={(count, total) =>
            count === 0
              ? 'No products'
              : count === total
              ? 'All products selected'
              : `${count} product${count === 1 ? '' : 's'} selected`
          }
          triggerClassName="w-[200px]"
        />

        <MultiSelect
          options={projectOptions}
          selected={allProjectsSelected ? projectOptions.map((o) => o.value) : selectedProjects}
          onChange={(values) => {
            setSelectedProjects(values);
            setAllProjectsSelected(values.length === projectOptions.length);
          }}
          renderLabel={(count, total) =>
            total === 0
              ? 'No projects'
              : count === 0
              ? 'No projects'
              : count === total
              ? 'All projects selected'
              : `${count} project${count === 1 ? '' : 's'} selected`
          }
          triggerClassName="w-[200px]"
        />

        <div className="ml-auto text-right">
          <p className="text-[10px] font-medium uppercase tracking-wider text-foreground-secondary">Total spend</p>
          <p className="text-lg font-semibold tabular-nums text-foreground">${totalDollars}</p>
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

      <section className="space-y-3">
        <h3 className="text-base font-semibold text-foreground">By product</h3>
        <ProductBreakdownTable products={data?.products ?? []} loading={loading} />
      </section>
    </div>
  );
}
