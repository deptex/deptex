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
  featureFilters?: string[];
  projectId?: string;
  projectIds?: string[];
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

// One pre-aggregated row from get_usage_breakdown (phase66). `bucket` is a date the
// RPC already aligned to the UTC day/week/month; `cents`/`quantity` are SUMs. bigint /
// numeric can come back as strings from PostgREST, so coerce with Number().
interface AggRow {
  bucket: string;
  feature: string | null;
  event_type: string | null;
  cents: number | string;
  quantity: number | string | null;
}

export async function loadUsageBreakdown(input: UsageBreakdownInput): Promise<UsageBreakdownResult> {
  const featureFilter =
    input.featureFilters && input.featureFilters.length > 0
      ? input.featureFilters
      : input.featureFilter
        ? [input.featureFilter]
        : null;
  const projectFilter =
    input.projectIds && input.projectIds.length > 0
      ? input.projectIds
      : input.projectId
        ? [input.projectId]
        : null;

  // Aggregate in the DB (one row per bucket × feature × event_type) rather than pulling
  // every transaction and summing in JS — see phase66_usage_breakdown_rpc.sql.
  const { data: rows, error } = await supabase.rpc('get_usage_breakdown', {
    p_organization_id: input.organizationId,
    p_start: input.start.toISOString(),
    p_end: input.end.toISOString(),
    p_granularity: input.granularity,
    p_features: featureFilter,
    p_project_ids: projectFilter,
  });
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

  for (const row of (rows ?? []) as AggRow[]) {
    if (!categoryMatches(input.category, row.event_type)) continue;
    const feature = row.feature ?? 'other';
    const cents = Number(row.cents) || 0;
    const key = String(row.bucket);
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
