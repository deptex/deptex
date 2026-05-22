import React, { useState } from 'react';
import { CardElement, useElements, useStripe } from '@stripe/react-stripe-js';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import { Input } from '../ui/input';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
const QUICK_AMOUNTS_CENTS = [500, 1000, 2500, 5000];
const POLL_INTERVAL_MS = 1000;
const POLL_TIMEOUT_MS = 10_000;

interface TopUpFormProps {
  organizationId: string;
  onSuccess: () => Promise<void> | void;
}

export function TopUpForm({ organizationId, onSuccess }: TopUpFormProps) {
  const stripe = useStripe();
  const elements = useElements();

  const [amountCents, setAmountCents] = useState<number>(2500);
  const [customAmount, setCustomAmount] = useState<string>('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);

  const effectiveCents = customAmount.trim()
    ? Math.round(Number(customAmount) * 100)
    : amountCents;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!stripe || !elements) return;
    if (effectiveCents < 500) {
      setError('Minimum top-up is $5.');
      return;
    }

    setError(null);
    setSubmitting(true);
    try {
      const { data: session } = await supabase.auth.getSession();
      const token = session.session?.access_token;
      if (!token) throw new Error('Not authenticated');

      const createRes = await fetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/topup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ amount_cents: effectiveCents }),
      });
      if (!createRes.ok) {
        const { error: apiErr } = (await createRes.json().catch(() => ({}))) as { error?: string };
        throw new Error(apiErr ?? `Failed to start top-up (${createRes.status})`);
      }
      const { clientSecret } = (await createRes.json()) as { clientSecret: string };

      const cardElement = elements.getElement(CardElement);
      if (!cardElement) throw new Error('Card form not ready');

      const confirmResult = await stripe.confirmCardPayment(clientSecret, {
        payment_method: { card: cardElement },
      });
      if (confirmResult.error) {
        throw new Error(confirmResult.error.message ?? 'Payment failed');
      }

      setPolling(true);
      const pollStart = Date.now();
      while (Date.now() - pollStart < POLL_TIMEOUT_MS) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        try {
          await onSuccess();
        } catch {
          // ignore — keep polling
        }
        if (Date.now() - pollStart >= POLL_TIMEOUT_MS) break;
      }
      setPolling(false);

      cardElement.clear();
      setCustomAmount('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Top-up failed');
    } finally {
      setSubmitting(false);
      setPolling(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4 rounded-lg border border-border bg-background-card p-6">
      <div>
        <p className="text-xs text-foreground-secondary mb-2">Amount</p>
        <div className="flex flex-wrap gap-2">
          {QUICK_AMOUNTS_CENTS.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => {
                setAmountCents(c);
                setCustomAmount('');
              }}
              className={`rounded-md border px-3 py-1.5 text-sm transition-colors ${
                customAmount === '' && amountCents === c
                  ? 'border-primary bg-primary/10 text-foreground'
                  : 'border-border text-foreground-secondary hover:bg-background-card-hover'
              }`}
            >
              ${(c / 100).toFixed(0)}
            </button>
          ))}
          <Input
            type="number"
            min="5"
            step="0.01"
            placeholder="Custom"
            value={customAmount}
            onChange={(e) => setCustomAmount(e.target.value)}
            className="max-w-[140px]"
          />
        </div>
      </div>

      <div>
        <p className="text-xs text-foreground-secondary mb-2">Card</p>
        <div className="rounded-md border border-border bg-background px-3 py-3">
          <CardElement
            options={{
              style: {
                base: {
                  fontSize: '14px',
                  color: '#f5f5f5',
                  '::placeholder': { color: '#888' },
                },
                invalid: { color: '#ef4444' },
              },
            }}
          />
        </div>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {polling && <p className="text-sm text-foreground-secondary">Payment confirmed. Updating balance…</p>}

      <div className="flex justify-end">
        <Button type="submit" variant="green" disabled={!stripe || !elements || submitting || polling}>
          {submitting ? 'Processing…' : `Top up $${(effectiveCents / 100).toFixed(2)}`}
        </Button>
      </div>
    </form>
  );
}
