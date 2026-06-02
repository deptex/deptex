import { useEffect, useState, type ReactNode } from 'react';
import { Badge } from '../../../components/ui/badge';
import { useToast } from '../../../hooks/use-toast';
import { apiAdminOverview, type AdminOverview } from '../../../lib/api';

function formatDate(s: string | null): string {
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function usd(cents: number): string {
  return (cents / 100).toLocaleString(undefined, { style: 'currency', currency: 'USD' });
}

function signedUsd(cents: number): string {
  const sign = cents < 0 ? '−' : '+';
  return `${sign}${(Math.abs(cents) / 100).toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
  })}`;
}

const KIND_LABEL: Record<string, string> = {
  topup: 'Top-up',
  auto_recharge_topup: 'Auto-recharge',
  refund: 'Refund',
  adjustment: 'Adjustment',
  signup_grant: 'Signup credit',
};

function Stat({
  label,
  value,
  sub,
  tone = 'default',
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: 'default' | 'warn';
}) {
  return (
    <div className="rounded-lg border border-border bg-background p-3">
      <div className="text-xs text-foreground-secondary">{label}</div>
      <div
        className={`text-xl font-semibold tabular-nums ${
          tone === 'warn' ? 'text-amber-500' : 'text-foreground'
        }`}
      >
        {value}
      </div>
      {sub ? <div className="text-xs text-foreground-secondary mt-0.5">{sub}</div> : null}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-background-card p-4 mb-4">
      <h2 className="text-sm font-semibold text-foreground mb-3">{title}</h2>
      {children}
    </div>
  );
}

function SkeletonPanel({ stats }: { stats: number }) {
  return (
    <div className="rounded-lg border border-border bg-background-card p-4 mb-4">
      <div className="h-5 w-40 bg-muted rounded animate-pulse mb-3" />
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
        {Array.from({ length: stats }).map((_, j) => (
          <div key={j} className="h-16 bg-muted/40 rounded-lg animate-pulse" />
        ))}
      </div>
    </div>
  );
}

export default function AdminOverviewPage() {
  const { toast } = useToast();
  const [data, setData] = useState<AdminOverview | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const d = await apiAdminOverview();
        if (alive) setData(d);
      } catch (e: unknown) {
        if (alive) {
          toast({
            title: 'Failed to load overview',
            description: e instanceof Error ? e.message : 'Unknown error',
            variant: 'destructive',
          });
        }
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  if (loading && !data) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-7xl">
        <SkeletonPanel stats={4} />
        <SkeletonPanel stats={4} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-7xl">
        <div className="rounded-lg border border-border bg-background-card p-8 text-center text-foreground-secondary">
          Could not load platform overview.
        </div>
      </div>
    );
  }

  const { totals, billing, recentActivity } = data;

  return (
    <div className="container mx-auto py-8 px-4 max-w-7xl">
      <Panel title="Platform">
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
          <Stat label="Organizations" value={totals.organizations.toLocaleString()} />
          <Stat label="Projects" value={totals.projects.toLocaleString()} />
          <Stat label="Users" value={totals.users.toLocaleString()} sub="distinct members" />
          <Stat label="Scans (30d)" value={totals.scans30d.toLocaleString()} />
        </div>
      </Panel>

      <Panel title="Billing & revenue">
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
          <Stat label="Balance held" value={usd(billing.totalBalanceCents)} sub="across all orgs" />
          <Stat
            label="Revenue (30d)"
            value={usd(billing.revenue30dCents)}
            sub="top-ups + auto-recharge"
          />
          <Stat label="Auto-recharge on" value={billing.autoRechargeOn.toLocaleString()} sub="orgs" />
          <Stat
            label="Failed payments (7d)"
            value={billing.failedPayments7d.toLocaleString()}
            tone={billing.failedPayments7d > 0 ? 'warn' : 'default'}
          />
          <Stat
            label="Orgs at $0"
            value={billing.zeroBalanceOrgs.toLocaleString()}
            tone={billing.zeroBalanceOrgs > 0 ? 'warn' : 'default'}
          />
        </div>
      </Panel>

      <Panel title="Recent billing activity">
        {recentActivity.length === 0 ? (
          <div className="text-sm text-foreground-secondary py-6 text-center">
            No recent billing activity
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-background-card-header">
                <tr className="border-b border-border">
                  <th className="text-left font-medium px-4 py-2.5 text-foreground">When</th>
                  <th className="text-left font-medium px-4 py-2.5 text-foreground">Organization</th>
                  <th className="text-left font-medium px-4 py-2.5 text-foreground">Kind</th>
                  <th className="text-right font-medium px-4 py-2.5 text-foreground">Amount</th>
                  <th className="text-left font-medium px-4 py-2.5 text-foreground">Description</th>
                </tr>
              </thead>
              <tbody>
                {recentActivity.map((a) => (
                  <tr key={a.id} className="border-b border-border last:border-0">
                    <td className="px-4 py-2.5 align-top whitespace-nowrap text-foreground-secondary">
                      {formatDate(a.created_at)}
                    </td>
                    <td className="px-4 py-2.5 align-top text-foreground">
                      {a.organization_name || (
                        <span className="font-mono text-xs text-foreground-secondary">
                          {a.organization_id.slice(0, 8)}…
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 align-top">
                      <Badge variant="secondary">{KIND_LABEL[a.kind] ?? a.kind}</Badge>
                    </td>
                    <td
                      className={`px-4 py-2.5 align-top text-right tabular-nums whitespace-nowrap ${
                        a.amount_cents < 0 ? 'text-foreground-secondary' : 'text-foreground'
                      }`}
                    >
                      {signedUsd(a.amount_cents)}
                    </td>
                    <td className="px-4 py-2.5 align-top text-foreground-secondary">
                      {a.description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
