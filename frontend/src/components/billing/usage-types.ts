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

export const FEATURE_LABEL: Record<string, string> = {
  'aegis.chat': 'Aegis chat',
  'depscanner.scan': 'Repo scan',
  'depscanner.dast': 'DAST scan',
  'depscanner.dast_zap_dry_run': 'DAST probe',
  'fix-worker.task': 'Aegis fix',
  'rule.generation': 'Rule generation',
  'epd.scoring': 'EPD scoring',
};

export function featureLabel(feature: string): string {
  return FEATURE_LABEL[feature] ?? feature;
}

// Stable palette per feature for the stacked chart.
export const FEATURE_COLOR: Record<string, string> = {
  'aegis.chat': '#a78bfa',          // violet-400
  'fix-worker.task': '#22c55e',     // emerald-500
  'depscanner.scan': '#3b82f6',     // blue-500
  'depscanner.dast': '#f59e0b',     // amber-500
  'depscanner.dast_zap_dry_run': '#eab308', // yellow-500
  'rule.generation': '#ec4899',     // pink-500
  'epd.scoring': '#06b6d4',         // cyan-500
};

const FALLBACK_COLORS = ['#64748b', '#0ea5e9', '#d946ef', '#10b981', '#f97316'];

export function featureColor(feature: string, index = 0): string {
  return FEATURE_COLOR[feature] ?? FALLBACK_COLORS[index % FALLBACK_COLORS.length];
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
