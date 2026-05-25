import { supabase } from '../supabase';

export type UsageGranularity = 'day' | 'week' | 'month';
export type FeatureCategory = 'all' | 'ai' | 'workers';

export interface UsageBreakdownInput {
  organizationId: string;
  start: Date;
  end: Date;
  granularity: UsageGranularity;
  category?: FeatureCategory;
  featureFilter?: string;
  projectId?: string;
  cumulative?: boolean;
}

export interface UsageBucket {
  ts: string;
  byFeature: Record<string, number>;
  totalCents: number;
}

export interface ProductRow {
  feature: string;
  eventType: 'ai_tokens' | 'worker_minutes' | null;
  totalCents: number;
  totalQuantity: number;
  sparkline: number[];
}

export interface UsageBreakdownResult {
  buckets: UsageBucket[];
  products: ProductRow[];
  totalCents: number;
  granularity: UsageGranularity;
  cumulative: boolean;
  start: string;
  end: string;
}

function bucketKey(d: Date, g: UsageGranularity): string {
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  if (g === 'month') return `${year}-${month}-01`;
  if (g === 'week') {
    const dayOfWeek = d.getUTCDay();
    const monday = new Date(Date.UTC(year, d.getUTCMonth(), d.getUTCDate() - ((dayOfWeek + 6) % 7)));
    return monday.toISOString().slice(0, 10);
  }
  return `${year}-${month}-${day}`;
}

function enumerateBuckets(start: Date, end: Date, g: UsageGranularity): string[] {
  const out: string[] = [];
  const cursor = new Date(start.getTime());
  cursor.setUTCHours(0, 0, 0, 0);
  if (g === 'month') {
    cursor.setUTCDate(1);
  } else if (g === 'week') {
    const dayOfWeek = cursor.getUTCDay();
    cursor.setUTCDate(cursor.getUTCDate() - ((dayOfWeek + 6) % 7));
  }
  while (cursor.getTime() <= end.getTime()) {
    out.push(bucketKey(cursor, g));
    if (g === 'month') {
      cursor.setUTCMonth(cursor.getUTCMonth() + 1);
    } else if (g === 'week') {
      cursor.setUTCDate(cursor.getUTCDate() + 7);
    } else {
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
  }
  return out;
}

function categoryMatches(category: FeatureCategory | undefined, eventType: string | null): boolean {
  if (!category || category === 'all') return true;
  if (category === 'ai') return eventType === 'ai_tokens';
  if (category === 'workers') return eventType === 'worker_minutes';
  return true;
}

interface UsageRow {
  feature: string | null;
  event_type: string | null;
  amount_cents: number;
  quantity: number | null;
  created_at: string;
  project_id: string | null;
}

export async function loadUsageBreakdown(input: UsageBreakdownInput): Promise<UsageBreakdownResult> {
  let query = supabase
    .from('billing_transactions')
    .select('feature, event_type, amount_cents, quantity, created_at, project_id')
    .eq('organization_id', input.organizationId)
    .eq('kind', 'usage_deduction')
    .gte('created_at', input.start.toISOString())
    .lte('created_at', input.end.toISOString());

  if (input.featureFilter) {
    query = query.eq('feature', input.featureFilter);
  }
  if (input.projectId) {
    query = query.eq('project_id', input.projectId);
  }

  const { data: rows, error } = await query;
  if (error) {
    throw new Error(`loadUsageBreakdown: ${error.message}`);
  }

  const bucketKeys = enumerateBuckets(input.start, input.end, input.granularity);
  const bucketMap = new Map<string, Map<string, number>>();
  for (const key of bucketKeys) bucketMap.set(key, new Map());

  const productAgg = new Map<
    string,
    { eventType: string | null; totalCents: number; totalQuantity: number; perBucket: Map<string, number> }
  >();
  let totalCents = 0;

  for (const row of (rows ?? []) as UsageRow[]) {
    if (!categoryMatches(input.category, row.event_type)) continue;
    const feature = row.feature ?? 'other';
    const cents = Math.abs(row.amount_cents);
    const created = new Date(row.created_at);
    const key = bucketKey(created, input.granularity);
    if (!bucketMap.has(key)) bucketMap.set(key, new Map());
    const bucket = bucketMap.get(key)!;
    bucket.set(feature, (bucket.get(feature) ?? 0) + cents);

    let agg = productAgg.get(feature);
    if (!agg) {
      agg = { eventType: row.event_type, totalCents: 0, totalQuantity: 0, perBucket: new Map() };
      productAgg.set(feature, agg);
    }
    agg.totalCents += cents;
    agg.totalQuantity += Number(row.quantity ?? 0);
    agg.perBucket.set(key, (agg.perBucket.get(key) ?? 0) + cents);
    totalCents += cents;
  }

  const sortedBucketKeys = [...bucketMap.keys()].sort();
  const buckets: UsageBucket[] = sortedBucketKeys.map((ts) => {
    const byFeature: Record<string, number> = {};
    const map = bucketMap.get(ts)!;
    let bucketTotal = 0;
    for (const [feature, cents] of map.entries()) {
      byFeature[feature] = cents;
      bucketTotal += cents;
    }
    return { ts, byFeature, totalCents: bucketTotal };
  });

  if (input.cumulative) {
    const runningByFeature: Record<string, number> = {};
    let runningTotal = 0;
    for (const bucket of buckets) {
      for (const feature of Object.keys(bucket.byFeature)) {
        runningByFeature[feature] = (runningByFeature[feature] ?? 0) + bucket.byFeature[feature];
      }
      runningTotal += bucket.totalCents;
      bucket.byFeature = { ...runningByFeature };
      bucket.totalCents = runningTotal;
    }
  }

  const products: ProductRow[] = [...productAgg.entries()]
    .map(([feature, agg]) => ({
      feature,
      eventType: agg.eventType as ProductRow['eventType'],
      totalCents: agg.totalCents,
      totalQuantity: agg.totalQuantity,
      sparkline: sortedBucketKeys.map((k) => agg.perBucket.get(k) ?? 0),
    }))
    .sort((a, b) => b.totalCents - a.totalCents);

  return {
    buckets,
    products,
    totalCents,
    granularity: input.granularity,
    cumulative: !!input.cumulative,
    start: input.start.toISOString(),
    end: input.end.toISOString(),
  };
}
