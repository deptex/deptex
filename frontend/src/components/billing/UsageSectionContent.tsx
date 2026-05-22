import React, { useCallback, useEffect, useState } from 'react';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import { Skeleton } from '../ui/skeleton';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface UsageActivity {
  id: string;
  feature: string;
  eventType: 'ai_tokens' | 'worker_minutes';
  costCentsCharged: number;
  emittedAt: string;
  attribution: {
    userId: string | null;
    resourceType: string | null;
    resourceId: string | null;
  };
  modelId: string | null;
  machineSize: string | null;
}

interface UsageResponse {
  totalCents: number;
  activity: UsageActivity[];
  nextCursor: string | null;
}

const FEATURE_LABEL: Record<string, string> = {
  'aegis.chat': 'Aegis chat',
  'depscanner.scan': 'Repo scan',
  'depscanner.dast': 'DAST scan',
  'depscanner.dast_zap_dry_run': 'DAST probe',
  'fix-worker.task': 'Aegis fix',
};

function featureLabel(feature: string): string {
  return FEATURE_LABEL[feature] ?? feature;
}

function formatTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

interface UsageSectionContentProps {
  organizationId: string;
}

export function UsageSectionContent({ organizationId }: UsageSectionContentProps) {
  const [data, setData] = useState<UsageResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const { data: session } = await supabase.auth.getSession();
        const token = session.session?.access_token;
        if (!token) throw new Error('Not authenticated');
        const url = new URL(`${API_BASE_URL}/api/organizations/${organizationId}/billing/usage`);
        if (cursor) url.searchParams.set('cursor', cursor);
        const res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) throw new Error(`Failed to load usage (${res.status})`);
        const next = (await res.json()) as UsageResponse;
        setData((prev) =>
          cursor && prev
            ? { ...next, activity: [...prev.activity, ...next.activity], totalCents: prev.totalCents }
            : next,
        );
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load usage');
      } finally {
        setLoading(false);
      }
    },
    [organizationId],
  );

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !data) {
    return (
      <div className="space-y-4 pt-8">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error) {
    return <p className="pt-8 text-sm text-destructive">{error}</p>;
  }

  if (!data) {
    return null;
  }

  const totalDollars = (data.totalCents / 100).toFixed(2);

  return (
    <div className="space-y-8 pt-8">
      <section>
        <h3 className="text-base font-semibold text-foreground">Spend this period</h3>
        <p className="mt-1 text-sm text-foreground-secondary">Last 30 days.</p>
        <div className="mt-3 rounded-lg border border-border bg-background-card p-6">
          <p className="text-3xl font-semibold tracking-tight text-foreground">${totalDollars}</p>
        </div>
      </section>

      <section className="space-y-4">
        <h3 className="text-base font-semibold text-foreground">Activity</h3>
        {data.activity.length === 0 ? (
          <div className="rounded-lg border border-border bg-background-card p-6 text-sm text-foreground-secondary">
            No usage yet. Try running a scan or starting an Aegis chat.
          </div>
        ) : (
          <div className="divide-y divide-border rounded-lg border border-border bg-background-card">
            {data.activity.map((entry) => (
              <div key={entry.id} className="flex items-center justify-between px-4 py-3 text-sm">
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-foreground">{featureLabel(entry.feature)}</p>
                  <p className="text-xs text-foreground-secondary">
                    {entry.modelId ?? entry.machineSize ?? ''} • {formatTimeAgo(entry.emittedAt)}
                  </p>
                </div>
                <p className="ml-4 font-mono text-foreground-secondary">${(entry.costCentsCharged / 100).toFixed(4)}</p>
              </div>
            ))}
          </div>
        )}
        {data.nextCursor && (
          <div className="flex justify-center">
            <Button variant="outline" size="sm" disabled={loading} onClick={() => load(data.nextCursor ?? undefined)}>
              {loading ? 'Loading…' : 'Load more'}
            </Button>
          </div>
        )}
      </section>
    </div>
  );
}
