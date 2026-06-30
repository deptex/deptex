import React, { useEffect, useState } from 'react';
import { useBilling } from '../../contexts/PlanContext';
import { supabase } from '../../lib/supabase';
import { ChevronDown, Coins, Download, Loader2 } from 'lucide-react';
import { PaymentMethodsCard } from './PaymentMethodsCard';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Skeleton } from '../ui/skeleton';
import { Switch } from '../ui/switch';
import { TopUpForm } from './TopUpForm';

const INPUT_NEUTRAL_FOCUS =
  'focus-visible:!border-foreground-secondary/60 focus-visible:!ring-foreground-secondary/30';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface PlanBillingSectionContentProps {
  organizationId: string;
}

async function authedFetch(input: string, init?: RequestInit) {
  const { data: session } = await supabase.auth.getSession();
  const token = session.session?.access_token;
  if (!token) throw new Error('Not authenticated');
  return fetch(input, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });
}

export function PlanBillingSectionContent({ organizationId }: PlanBillingSectionContentProps) {
  const { billing, loading, error, refetch } = useBilling();
  const [depositsRefreshKey, setDepositsRefreshKey] = useState(0);
  const onTopUpSuccess = async () => {
    await refetch();
    setDepositsRefreshKey((k) => k + 1);
  };

  if (loading && !billing) {
    return <BillingSectionSkeleton />;
  }
  if (error) {
    return <p className="pt-8 text-sm text-destructive">{error}</p>;
  }
  if (!billing) {
    return <p className="pt-8 text-sm text-foreground-secondary">Billing isn't initialized for this organization yet.</p>;
  }

  const balanceDollars = (billing.balanceCents / 100).toFixed(2);

  return (
    <div className="space-y-6 pt-8">
      <div className="overflow-hidden rounded-lg border border-border bg-background-card">
        <div className="p-5">
          {/* Inner card: balance + auto-reload */}
          <div className="overflow-hidden rounded-md border border-border bg-background-card-header">
            {/* Balance row */}
            <div className="flex items-center gap-4 px-4 py-4">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                <Coins className="h-5 w-5 text-foreground-secondary" />
              </span>
              <div className="flex-1">
                <p className="text-xs text-foreground-secondary">Current balance</p>
                <p className="mt-0.5 text-2xl font-semibold tabular-nums text-foreground">${balanceDollars}</p>
              </div>
            </div>
            {/* Auto-reload (collapsible) */}
            <div className="border-t border-border">
              <AutoReloadDropdown organizationId={organizationId} billing={billing} onSaved={refetch} />
            </div>
          </div>
        </div>
        {/* Add credit footer */}
        <div className="flex items-center justify-between gap-3 border-t border-border bg-background-card-header px-5 py-3">
          <p className="text-sm text-foreground-secondary">Add credit to your balance</p>
          <TopUpForm organizationId={organizationId} onSuccess={onTopUpSuccess} />
        </div>
      </div>

      <PaymentMethodsCard organizationId={organizationId} />

      <DepositsTable organizationId={organizationId} refreshKey={depositsRefreshKey} />
    </div>
  );
}

interface Deposit {
  id: string;
  kind: 'topup' | 'auto_recharge_topup';
  amountCents: number;
  description: string;
  createdAt: string;
  stripePaymentIntentId: string | null;
}

function DepositsTable({ organizationId, refreshKey = 0 }: { organizationId: string; refreshKey?: number }) {
  const [deposits, setDeposits] = useState<Deposit[] | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const downloadReceipt = async (txnId: string) => {
    setDownloadingId(txnId);
    try {
      const res = await authedFetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/billing/transactions/${txnId}/receipt`,
      );
      if (!res.ok) {
        console.warn('[billing] receipt fetch failed', res.status);
        return;
      }
      const { url } = (await res.json()) as { url: string };
      if (url) window.open(url, '_blank', 'noopener,noreferrer');
    } catch (err) {
      console.warn('[billing] receipt fetch threw', err);
    } finally {
      setDownloadingId(null);
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await authedFetch(
          `${API_BASE_URL}/api/organizations/${organizationId}/billing/transactions?kinds=topup,auto_recharge_topup&limit=20`,
        );
        if (!res.ok) return;
        const data = (await res.json()) as { transactions: Deposit[] };
        if (!cancelled) setDeposits(data.transactions);
      } catch (err) {
        console.warn('[billing] deposits fetch failed', err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [organizationId, refreshKey]);

  return (
    <div
      className={`overflow-hidden rounded-lg border border-border bg-background-card${
        deposits == null ? ' pointer-events-none select-none' : ''
      }`}
      // While loading, fade the whole card downward (like the app's other loading
      // tables) so the rows dissolve instead of sitting in a solid-bordered box.
      style={
        deposits == null
          ? {
              maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
              WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
            }
          : undefined
      }
    >
      <div className="border-b border-border bg-background-card-header px-5 py-3">
        <p className="text-sm font-semibold text-foreground">Deposits</p>
      </div>
      {deposits == null ? (
        <div className="divide-y divide-border">
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="grid grid-cols-[2fr_1fr_1fr] items-center gap-4 px-5 py-4">
              <div className="space-y-2">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-3 w-24" />
              </div>
              <Skeleton className="h-4 w-16" />
              <div className="flex justify-end">
                <Skeleton className="h-3 w-28" />
              </div>
            </div>
          ))}
        </div>
      ) : deposits.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-foreground-secondary">
          No deposits yet. Add credit above to get started.
        </p>
      ) : (
        <div className="divide-y divide-border">
          {deposits.map((d) => {
            const isDemo = d.stripePaymentIntentId?.startsWith('pi_demo_') ?? true;
            const isDownloading = downloadingId === d.id;
            return (
              <div
                key={d.id}
                className="grid grid-cols-[2fr_1fr_1fr_auto] items-center gap-4 px-5 py-4 transition-colors hover:bg-table-hover"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold text-foreground">{formatMonthYear(d.createdAt)}</p>
                    <span className="rounded-full bg-emerald-900/40 px-2 py-0.5 text-[10px] font-medium text-emerald-300">
                      Paid
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-foreground-secondary">{labelForKind(d.kind)}</p>
                </div>
                <div>
                  <p className="text-xs text-foreground-secondary">Amount</p>
                  <p className="mt-0.5 text-sm font-semibold tabular-nums text-foreground">
                    ${(d.amountCents / 100).toFixed(2)}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-foreground-secondary">{formatLongDate(d.createdAt)}</p>
                </div>
                <button
                  type="button"
                  onClick={() => downloadReceipt(d.id)}
                  disabled={isDemo || isDownloading}
                  title={isDemo ? 'No invoice available (demo data)' : 'Download invoice'}
                  className="relative flex h-8 w-8 items-center justify-center rounded-md text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-foreground-secondary"
                >
                  {isDownloading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4" />
                  )}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function labelForKind(kind: Deposit['kind']): string {
  return kind === 'auto_recharge_topup' ? 'Auto-reload' : 'Manual top-up';
}

function formatMonthYear(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
}

function formatLongDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

interface AutoReloadDropdownProps {
  organizationId: string;
  billing: NonNullable<ReturnType<typeof useBilling>['billing']>;
  onSaved: () => void;
}

function AutoReloadDropdown({ organizationId, billing, onSaved }: AutoReloadDropdownProps) {
  const DEFAULT_MONTHLY_CAP_CENTS = 10000;
  const initialEnabled = billing.autoRecharge.enabled;
  const initialThresholdCents = billing.autoRecharge.thresholdCents ?? 500;
  const initialAmountCents = billing.autoRecharge.amountCents ?? 2000;
  const initialMonthlyCapCents = billing.autoRecharge.monthlyCapCents ?? DEFAULT_MONTHLY_CAP_CENTS;

  const [expanded, setExpanded] = useState(false);
  const [enabled, setEnabled] = useState(initialEnabled);
  const [enabledSaved, setEnabledSaved] = useState(initialEnabled);
  const [threshold, setThreshold] = useState(Math.round(initialThresholdCents / 100).toString());
  const [amount, setAmount] = useState(Math.round(initialAmountCents / 100).toString());
  const [monthlyCap, setMonthlyCap] = useState(Math.round(initialMonthlyCapCents / 100).toString());
  const [savedThresholdCents, setSavedThresholdCents] = useState(initialThresholdCents);
  const [savedAmountCents, setSavedAmountCents] = useState(initialAmountCents);
  const [savedMonthlyCapCents, setSavedMonthlyCapCents] = useState(initialMonthlyCapCents);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const currentThresholdCents = Math.round(Number(threshold) * 100);
  const currentAmountCents = Math.round(Number(amount) * 100);
  const currentMonthlyCapCents = Math.round(Number(monthlyCap) * 100);
  const inputsValid =
    Number.isFinite(currentThresholdCents) &&
    currentThresholdCents > 0 &&
    Number.isFinite(currentAmountCents) &&
    currentAmountCents >= 500 &&
    Number.isFinite(currentMonthlyCapCents) &&
    currentMonthlyCapCents > 0;
  const isDirty =
    enabled !== enabledSaved ||
    currentThresholdCents !== savedThresholdCents ||
    currentAmountCents !== savedAmountCents ||
    currentMonthlyCapCents !== savedMonthlyCapCents;
  const saveDisabled = saving || !inputsValid || !isDirty;

  const cancel = () => {
    setEnabled(enabledSaved);
    setThreshold(Math.round(savedThresholdCents / 100).toString());
    setAmount(Math.round(savedAmountCents / 100).toString());
    setMonthlyCap(Math.round(savedMonthlyCapCents / 100).toString());
    setError(null);
    setExpanded(false);
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/auto-recharge`, {
        method: 'PUT',
        body: JSON.stringify({
          enabled,
          threshold_cents: currentThresholdCents,
          amount_cents: currentAmountCents,
          monthly_cap_cents: currentMonthlyCapCents,
        }),
      });
      if (!res.ok) {
        const { error: apiErr } = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(apiErr ?? `Failed (${res.status})`);
      }
      setEnabledSaved(enabled);
      setSavedThresholdCents(currentThresholdCents);
      setSavedAmountCents(currentAmountCents);
      setSavedMonthlyCapCents(currentMonthlyCapCents);
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        <ChevronDown
          className={`h-4 w-4 text-foreground-secondary transition-transform duration-200 ${expanded ? '' : '-rotate-90'}`}
        />
        <span className="text-sm font-medium text-foreground">Auto-reload</span>
        {enabledSaved && (
          <span className="ml-1 rounded-full bg-background-subtle px-2 py-0.5 text-[10px] font-medium text-foreground-secondary">
            On
          </span>
        )}
      </button>
      <div
        className={`grid transition-[grid-template-rows] duration-200 ease-out ${
          expanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'
        }`}
      >
        <div className="overflow-hidden">
          <div className="space-y-4 px-4 pb-4 pt-1">
            <div className="flex items-center justify-between gap-4">
              <span className="text-sm text-foreground">Enable</span>
              <Switch
                checked={enabled}
                onCheckedChange={setEnabled}
                className="data-[state=checked]:!bg-foreground [&>span[data-state=checked]]:!bg-background"
              />
            </div>
            <MonthlySpendProgress
              spentCents={billing.autoRecharge.spentLast30DaysCents}
              capCents={savedMonthlyCapCents}
            />
            <div className="flex flex-wrap gap-x-10 gap-y-4">
              <RechargeRow
                label="Balance threshold"
                value={threshold}
                onChange={setThreshold}
                step="1"
              />
              <RechargeRow
                label="Deposit"
                value={amount}
                onChange={setAmount}
                step="1"
              />
              <RechargeRow
                label="Monthly cap"
                value={monthlyCap}
                onChange={setMonthlyCap}
                step="1"
              />
            </div>
            {error && <p className="text-xs text-destructive">{error}</p>}
            <div className="flex items-center justify-end gap-2 pt-1">
              <Button
                variant="outline"
                onClick={cancel}
                disabled={saving}
                className="!h-8 !px-3 !rounded-lg"
              >
                Cancel
              </Button>
              <Button variant="white" onClick={save} disabled={saveDisabled} className="relative">
                <span className={saving ? 'invisible' : undefined}>Save</span>
                {saving && (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <Loader2 className="h-4 w-4 animate-spin" />
                  </span>
                )}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function BillingSectionSkeleton() {
  return (
    <div className="space-y-6 pt-8">
      {/* Top card: balance + auto-reload + add credit footer */}
      <div className="overflow-hidden rounded-lg border border-border bg-background-card">
        <div className="p-5">
          <div className="overflow-hidden rounded-md border border-border bg-background-card-header">
            {/* Balance row */}
            <div className="flex items-center gap-4 px-4 py-4">
              <Skeleton className="h-10 w-10 shrink-0 rounded-full" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-3 w-24" />
                <Skeleton className="h-7 w-24" />
              </div>
            </div>
            {/* Auto-reload collapsed row */}
            <div className="flex items-center gap-3 border-t border-border px-4 py-3">
              <Skeleton className="h-4 w-4" />
              <Skeleton className="h-4 w-24" />
            </div>
          </div>
        </div>
        {/* Add credit footer */}
        <div className="flex items-center justify-between gap-3 border-t border-border bg-background-card-header px-5 py-3">
          <Skeleton className="h-4 w-40" />
          <div className="flex items-center gap-2">
            <Skeleton className="h-8 w-20" />
            <Skeleton className="h-8 w-24" />
          </div>
        </div>
      </div>

      {/* Payment methods card */}
      <div className="overflow-hidden rounded-lg border border-border bg-background-card">
        <div className="flex items-center justify-between border-b border-border bg-background-card-header px-5 py-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-8 w-20" />
        </div>
        <div className="space-y-3 p-5">
          <div className="flex items-center gap-3">
            <Skeleton className="h-8 w-8 rounded" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-40" />
              <Skeleton className="h-3 w-24" />
            </div>
            <Skeleton className="h-6 w-6 rounded" />
          </div>
        </div>
      </div>

      {/* Deposits table — fades downward like the app's other loading tables */}
      <div
        className="overflow-hidden rounded-lg border border-border bg-background-card pointer-events-none select-none"
        style={{
          maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
          WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
        }}
      >
        <div className="border-b border-border bg-background-card-header px-5 py-3">
          <Skeleton className="h-4 w-20" />
        </div>
        <div className="divide-y divide-border">
          {[0, 1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="grid grid-cols-[2fr_1fr_1fr_auto] items-center gap-4 px-5 py-4"
            >
              <div className="space-y-2">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-3 w-24" />
              </div>
              <div className="space-y-2">
                <Skeleton className="h-3 w-12" />
                <Skeleton className="h-4 w-16" />
              </div>
              <div className="flex justify-end">
                <Skeleton className="h-3 w-28" />
              </div>
              <Skeleton className="h-8 w-8 rounded" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

interface MonthlySpendProgressProps {
  spentCents: number;
  capCents: number | null;
}

function MonthlySpendProgress({ spentCents, capCents }: MonthlySpendProgressProps) {
  if (capCents == null || capCents <= 0) return null;
  const pct = Math.min(100, Math.round((spentCents / capCents) * 100));
  const overCap = spentCents >= capCents;
  const spentDollars = (spentCents / 100).toFixed(2);
  const capDollars = (capCents / 100).toFixed(2);
  return (
    <div className="space-y-2">
      <p className={`text-sm tabular-nums ${overCap ? 'text-destructive' : 'text-foreground'}`}>
        ${spentDollars} of ${capDollars} in the last 30 days
        {overCap && (
          <span className="ml-1.5 font-normal">— cap reached, paused until older charges roll off</span>
        )}
      </p>
      <div className="h-1 w-full overflow-hidden rounded-full bg-background-subtle">
        <div
          className={`h-full transition-[width] duration-300 ${overCap ? 'bg-destructive' : 'bg-foreground'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

interface RechargeRowProps {
  label: string;
  value: string;
  onChange: (v: string) => void;
  step: string;
}

function RechargeRow({ label, value, onChange, step }: RechargeRowProps) {
  return (
    <label className="block">
      <span className="text-sm text-foreground">{label}</span>
      <div className="relative mt-1.5">
        <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-sm text-foreground-secondary">
          $
        </span>
        <Input
          type="number"
          step={step}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={`h-8 w-32 rounded-lg pl-6 ${INPUT_NEUTRAL_FOCUS}`}
        />
      </div>
    </label>
  );
}
