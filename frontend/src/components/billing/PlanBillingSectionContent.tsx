import React, { useState } from 'react';
import { Elements } from '@stripe/react-stripe-js';
import { useBilling } from '../../contexts/PlanContext';
import { stripePromise } from '../../lib/stripe-client';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Switch } from '../ui/switch';
import { Label } from '../ui/label';
import { Badge } from '../ui/badge';
import { Skeleton } from '../ui/skeleton';
import { TopUpForm } from './TopUpForm';
import { TransactionsTable } from './TransactionsTable';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface SectionHeadingProps {
  title: string;
  description?: string;
}

function SectionHeading({ title, description }: SectionHeadingProps) {
  return (
    <div>
      <h3 className="text-base font-semibold text-foreground">{title}</h3>
      {description && <p className="mt-1 text-sm text-foreground-secondary">{description}</p>}
    </div>
  );
}

interface PlanBillingSectionContentProps {
  organizationId: string;
}

export function PlanBillingSectionContent({ organizationId }: PlanBillingSectionContentProps) {
  const { billing, loading, error, refetch } = useBilling();

  if (loading && !billing) {
    return (
      <div className="space-y-6 pt-8">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (error) {
    return <p className="pt-8 text-sm text-destructive">{error}</p>;
  }

  if (!billing) {
    return <p className="pt-8 text-sm text-foreground-secondary">Billing isn't initialized for this organization yet.</p>;
  }

  const balanceDollars = (billing.balanceCents / 100).toFixed(2);
  const lowBalance = billing.balanceCents > 0 && billing.balanceCents <= billing.lowBalanceAlertThresholdCents;
  const zeroBalance = billing.balanceCents <= 0;

  return (
    <Elements stripe={stripePromise}>
      <div className="space-y-10 pt-8">
        <section className="space-y-4">
          <SectionHeading title="Balance" description="Your current prepaid balance." />
          <div className="rounded-lg border border-border bg-background-card p-6">
            <div className="flex items-baseline gap-3">
              <span className="text-4xl font-semibold tracking-tight text-foreground">${balanceDollars}</span>
              {zeroBalance && <Badge variant="destructive">Out of credit</Badge>}
              {!zeroBalance && lowBalance && <Badge variant="warning">Low</Badge>}
            </div>
          </div>
        </section>

        <section className="space-y-4">
          <SectionHeading title="Top up" description="Add credit. Minimum $5." />
          <TopUpForm organizationId={organizationId} onSuccess={refetch} />
        </section>

        <section className="space-y-4">
          <SectionHeading
            title="Auto-recharge"
            description="Automatically add credit when your balance drops below a threshold."
          />
          <AutoRechargePanel organizationId={organizationId} billing={billing} onSaved={refetch} />
        </section>

        <section className="space-y-4">
          <SectionHeading
            title="Spending controls"
            description="Get an email alert when your balance drops below this threshold."
          />
          <LowBalanceThresholdPanel
            organizationId={organizationId}
            currentCents={billing.lowBalanceAlertThresholdCents}
            onSaved={refetch}
          />
          <BillingEmailPanel
            organizationId={organizationId}
            currentEmail={billing.billingEmailOverride}
            onSaved={refetch}
          />
        </section>

        <section className="space-y-4">
          <SectionHeading title="Payment method" />
          <PaymentMethodPanel
            organizationId={organizationId}
            paymentMethod={billing.paymentMethod}
            onChanged={refetch}
          />
        </section>

        <section className="space-y-4">
          <SectionHeading title="Recent transactions" />
          <TransactionsTable organizationId={organizationId} />
        </section>
      </div>
    </Elements>
  );
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

interface AutoRechargePanelProps {
  organizationId: string;
  billing: NonNullable<ReturnType<typeof useBilling>['billing']>;
  onSaved: () => void;
}

function AutoRechargePanel({ organizationId, billing, onSaved }: AutoRechargePanelProps) {
  const [enabled, setEnabled] = useState(billing.autoRecharge.enabled);
  const [threshold, setThreshold] = useState(((billing.autoRecharge.thresholdCents ?? 500) / 100).toFixed(2));
  const [amount, setAmount] = useState(((billing.autoRecharge.amountCents ?? 2000) / 100).toFixed(2));
  const [monthlyCap, setMonthlyCap] = useState(
    billing.autoRecharge.monthlyCapCents ? (billing.autoRecharge.monthlyCapCents / 100).toFixed(2) : '',
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { enabled };
      if (enabled) {
        body.threshold_cents = Math.round(Number(threshold) * 100);
        body.amount_cents = Math.round(Number(amount) * 100);
        body.monthly_cap_cents = monthlyCap.trim() ? Math.round(Number(monthlyCap) * 100) : null;
      }
      const res = await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/auto-recharge`, {
        method: 'PUT',
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const { error: apiErr } = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(apiErr ?? `Failed (${res.status})`);
      }
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4 rounded-lg border border-border bg-background-card p-6">
      <div className="flex items-center justify-between">
        <Label htmlFor="auto-recharge-toggle" className="text-sm font-medium">
          Enable auto-recharge
        </Label>
        <Switch id="auto-recharge-toggle" checked={enabled} onCheckedChange={setEnabled} />
      </div>
      {enabled && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <Label htmlFor="ar-threshold" className="text-xs text-foreground-secondary">When below ($)</Label>
            <Input id="ar-threshold" type="number" min="0" step="0.01" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="ar-amount" className="text-xs text-foreground-secondary">Add ($)</Label>
            <Input id="ar-amount" type="number" min="5" step="0.01" value={amount} onChange={(e) => setAmount(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="ar-cap" className="text-xs text-foreground-secondary">Monthly cap ($, optional)</Label>
            <Input id="ar-cap" type="number" min="0" step="0.01" placeholder="No cap" value={monthlyCap} onChange={(e) => setMonthlyCap(e.target.value)} />
          </div>
        </div>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="flex justify-end">
        <Button variant="green" size="sm" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </Button>
      </div>
    </div>
  );
}

interface LowBalanceThresholdPanelProps {
  organizationId: string;
  currentCents: number;
  onSaved: () => void;
}

function LowBalanceThresholdPanel({ organizationId, currentCents, onSaved }: LowBalanceThresholdPanelProps) {
  const [value, setValue] = useState((currentCents / 100).toFixed(2));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/low-balance-threshold`, {
        method: 'PUT',
        body: JSON.stringify({ threshold_cents: Math.round(Number(value) * 100) }),
      });
      if (!res.ok) throw new Error(`Failed (${res.status})`);
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex items-end gap-3 rounded-lg border border-border bg-background-card p-4">
      <div className="flex-1">
        <Label htmlFor="low-balance-threshold" className="text-xs text-foreground-secondary">Low-balance alert threshold ($)</Label>
        <Input id="low-balance-threshold" type="number" min="0" step="0.01" value={value} onChange={(e) => setValue(e.target.value)} />
      </div>
      <Button variant="green" size="sm" onClick={save} disabled={saving}>
        {saving ? 'Saving…' : 'Save'}
      </Button>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

interface BillingEmailPanelProps {
  organizationId: string;
  currentEmail: string | null;
  onSaved: () => void;
}

function BillingEmailPanel({ organizationId, currentEmail, onSaved }: BillingEmailPanelProps) {
  const [value, setValue] = useState(currentEmail ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async (newValue: string | null) => {
    setSaving(true);
    setError(null);
    try {
      const res = await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/billing-email`, {
        method: 'PUT',
        body: JSON.stringify({ email: newValue }),
      });
      if (!res.ok) throw new Error(`Failed (${res.status})`);
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex items-end gap-3 rounded-lg border border-border bg-background-card p-4">
      <div className="flex-1">
        <Label htmlFor="billing-email" className="text-xs text-foreground-secondary">Billing email override (optional)</Label>
        <Input
          id="billing-email"
          type="email"
          placeholder="billing@yourcompany.com"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
      </div>
      <Button variant="green" size="sm" onClick={() => save(value.trim() || null)} disabled={saving}>
        {saving ? 'Saving…' : 'Save'}
      </Button>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

interface PaymentMethodPanelProps {
  organizationId: string;
  paymentMethod: NonNullable<ReturnType<typeof useBilling>['billing']>['paymentMethod'];
  onChanged: () => void;
}

function PaymentMethodPanel({ organizationId, paymentMethod, onChanged }: PaymentMethodPanelProps) {
  const [removing, setRemoving] = useState(false);

  const remove = async () => {
    if (!confirm('Remove this payment method? Auto-recharge will be disabled.')) return;
    setRemoving(true);
    try {
      await authedFetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/payment-method`, { method: 'DELETE' });
      onChanged();
    } finally {
      setRemoving(false);
    }
  };

  if (!paymentMethod) {
    return (
      <div className="rounded-lg border border-border bg-background-card p-4 text-sm text-foreground-secondary">
        No payment method on file. Top up to add one.
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between rounded-lg border border-border bg-background-card p-4">
      <div>
        <p className="text-sm font-medium text-foreground">
          {paymentMethod.brand.toUpperCase()} •••• {paymentMethod.last4}
        </p>
        <p className="text-xs text-foreground-secondary">
          Expires {String(paymentMethod.expiresMonth).padStart(2, '0')}/{paymentMethod.expiresYear}
        </p>
      </div>
      <Button variant="outline" size="sm" onClick={remove} disabled={removing}>
        {removing ? 'Removing…' : 'Remove'}
      </Button>
    </div>
  );
}
