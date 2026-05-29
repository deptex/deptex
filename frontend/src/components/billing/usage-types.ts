export type UsageGranularity = 'day' | 'week' | 'month';
export type FeatureCategory = 'all' | 'ai' | 'workers';

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

export interface UsageBreakdownResponse {
  buckets: UsageBucket[];
  products: ProductRow[];
  totalCents: number;
  granularity: UsageGranularity;
  cumulative: boolean;
  start: string;
  end: string;
}

export interface ProjectOption {
  id: string;
  name: string;
  framework?: string | null;
}

export type DateRangePreset = 'last_7d' | 'last_30d' | 'this_month' | 'last_month' | 'last_90d' | 'custom';

export interface DateRange {
  start: Date;
  end: Date;
  preset: DateRangePreset;
}

// Display groups. The underlying feature_type values get folded into one of
// these four buckets for the chart, legend, and product table. The MultiSelect
// also operates on these group keys; when sending to the backend we expand
// each selected group back to its underlying features.
export interface ProductGroup {
  key: string;
  label: string;
  features: string[];
  color: string;
  eventType: 'ai_tokens' | 'worker_minutes';
}

export const PRODUCT_GROUPS: ProductGroup[] = [
  {
    key: 'scan_machines',
    label: 'Scan machines',
    features: ['depscanner.scan', 'depscanner.dast', 'depscanner.dast_zap_dry_run'],
    color: '#3b82f6',
    eventType: 'worker_minutes',
  },
  {
    key: 'aegis_tokens',
    label: 'Aegis tokens',
    features: ['aegis.chat', 'epd.scoring'],
    color: '#a78bfa',
    eventType: 'ai_tokens',
  },
  {
    key: 'rule_generation',
    label: 'Rule generation',
    features: ['rule.generation'],
    color: '#ec4899',
    eventType: 'ai_tokens',
  },
  {
    key: 'aegis_fix_machines',
    label: 'Aegis fix machines',
    features: ['fix-worker.task'],
    color: '#22c55e',
    eventType: 'worker_minutes',
  },
];

const FEATURE_TO_GROUP_KEY: Record<string, string> = {};
for (const g of PRODUCT_GROUPS) {
  for (const f of g.features) FEATURE_TO_GROUP_KEY[f] = g.key;
}

export function featureToGroupKey(feature: string): string {
  return FEATURE_TO_GROUP_KEY[feature] ?? feature;
}

export const FEATURE_LABEL: Record<string, string> = Object.fromEntries(
  PRODUCT_GROUPS.map((g) => [g.key, g.label]),
);

export function featureLabel(feature: string): string {
  return FEATURE_LABEL[feature] ?? feature;
}

export const FEATURE_COLOR: Record<string, string> = Object.fromEntries(
  PRODUCT_GROUPS.map((g) => [g.key, g.color]),
);

const FALLBACK_COLORS = ['#64748b', '#0ea5e9', '#d946ef', '#10b981', '#f97316'];

export function featureColor(feature: string, index = 0): string {
  return FEATURE_COLOR[feature] ?? FALLBACK_COLORS[index % FALLBACK_COLORS.length];
}

// Re-aggregate a backend UsageBreakdownResponse so every key in byFeature /
// every product row is a group key. Backend stays feature-level; frontend
// owns the grouping for display.
export function regroupBreakdown(data: UsageBreakdownResponse): UsageBreakdownResponse {
  const regroupedBuckets: UsageBucket[] = data.buckets.map((bucket) => {
    const byGroup: Record<string, number> = {};
    for (const [feature, cents] of Object.entries(bucket.byFeature)) {
      const key = featureToGroupKey(feature);
      byGroup[key] = (byGroup[key] ?? 0) + cents;
    }
    return { ts: bucket.ts, byFeature: byGroup, totalCents: bucket.totalCents };
  });

  const productsByGroup = new Map<
    string,
    { totalCents: number; totalQuantity: number; eventType: ProductRow['eventType']; perBucket: number[] }
  >();
  const bucketCount = data.buckets.length;
  for (const product of data.products) {
    const key = featureToGroupKey(product.feature);
    let agg = productsByGroup.get(key);
    if (!agg) {
      agg = {
        totalCents: 0,
        totalQuantity: 0,
        eventType: product.eventType,
        perBucket: new Array(bucketCount).fill(0),
      };
      productsByGroup.set(key, agg);
    }
    agg.totalCents += product.totalCents;
    agg.totalQuantity += product.totalQuantity;
    for (let i = 0; i < bucketCount; i++) {
      agg.perBucket[i] += product.sparkline[i] ?? 0;
    }
  }
  const products: ProductRow[] = [...productsByGroup.entries()]
    .map(([key, agg]) => ({
      feature: key,
      eventType: agg.eventType,
      totalCents: agg.totalCents,
      totalQuantity: agg.totalQuantity,
      sparkline: agg.perBucket,
    }))
    .sort((a, b) => b.totalCents - a.totalCents);

  return { ...data, buckets: regroupedBuckets, products };
}

export function formatQuantity(eventType: ProductRow['eventType'], quantity: number): string {
  if (eventType === 'worker_minutes') {
    if (quantity < 60) return `${quantity.toFixed(0)}s`;
    if (quantity < 3600) return `${(quantity / 60).toFixed(1)}m`;
    return `${(quantity / 3600).toFixed(2)}h`;
  }
  if (eventType === 'ai_tokens') {
    if (quantity < 1000) return `${quantity.toFixed(0)} tok`;
    if (quantity < 1_000_000) return `${(quantity / 1000).toFixed(1)}K tok`;
    return `${(quantity / 1_000_000).toFixed(2)}M tok`;
  }
  return quantity.toLocaleString();
}

export function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}
