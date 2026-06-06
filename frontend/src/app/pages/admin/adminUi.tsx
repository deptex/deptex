// Shared widgets + helpers for the admin console tabs (Overview, Billing).

export const GREEN = '#10b981'; // emerald-500 — brand accent; recharts needs a literal

export const RANGES = [
  { key: '7d', label: '7D', days: 7, totalLabel: 'last 7 days', emptyLabel: 'the last 7 days' },
  { key: '30d', label: '30D', days: 30, totalLabel: 'last 30 days', emptyLabel: 'the last 30 days' },
  { key: '90d', label: '90D', days: 90, totalLabel: 'last 90 days', emptyLabel: 'the last 90 days' },
  { key: '12m', label: '12M', days: 365, totalLabel: 'last 12 months', emptyLabel: 'the last 12 months' },
] as const;
export type RangeKey = (typeof RANGES)[number]['key'];

export function usd(cents: number): string {
  return (cents / 100).toLocaleString(undefined, { style: 'currency', currency: 'USD' });
}

export function signedUsd(cents: number): string {
  const sign = cents < 0 ? '−' : '+';
  return `${sign}${(Math.abs(cents) / 100).toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
  })}`;
}

export function num(n: number): string {
  return n.toLocaleString();
}

export function formatDate(s: string | null): string {
  if (!s) return '—';
  return new Date(s).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function dayLabel(date: string): string {
  return new Date(`${date}T00:00:00Z`).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

/** A bare KPI: big tabular number + uppercase caption. Sits in a divided strip. */
export function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="sm:px-6 sm:first:pl-0">
      <div className="text-3xl font-bold leading-none tabular-nums text-foreground">{value}</div>
      <div className="mt-2 text-xs font-medium uppercase tracking-wider text-foreground-secondary">
        {label}
      </div>
    </div>
  );
}

/** Segmented 7D / 30D / 90D / 12M control for the charts. */
export function RangeTabs({ value, onChange }: { value: RangeKey; onChange: (k: RangeKey) => void }) {
  return (
    <div className="flex rounded-md border border-border bg-background p-0.5">
      {RANGES.map((r) => (
        <button
          key={r.key}
          type="button"
          onClick={() => onChange(r.key)}
          className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
            value === r.key
              ? 'bg-background-card-hover text-foreground'
              : 'text-foreground-secondary hover:text-foreground'
          }`}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}
