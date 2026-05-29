import React, { useState } from 'react';
import { Elements, useElements, useStripe } from '@stripe/react-stripe-js';
import { Loader2 } from 'lucide-react';
import { supabase } from '../../lib/supabase';
import { stripePromise } from '../../lib/stripe-client';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface TopUpFormProps {
  organizationId: string;
  onSuccess?: () => Promise<void> | void;
}

interface TopUpResponse {
  status: 'succeeded' | 'requires_action' | 'requires_payment_method' | 'needs_setup';
  client_secret: string | null;
  payment_intent_id: string | null;
  invoice_id: string;
  subtotal_cents: number;
  tax_cents: number;
  total_cents: number;
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

export function TopUpForm({ organizationId, onSuccess }: TopUpFormProps) {
  const [amount, setAmount] = useState('25');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionClientSecret, setActionClientSecret] = useState<string | null>(null);

  const numericAmount = Number(amount);
  const cents = Math.round(numericAmount * 100);
  const isValid = Number.isFinite(numericAmount) && cents >= 500;
  const belowMinimum = amount.trim() !== '' && Number.isFinite(numericAmount) && cents < 500;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!isValid) return;

    setSubmitting(true);
    try {
      const res = await authedFetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/billing/topup-intent`,
        { method: 'POST', body: JSON.stringify({ amount_cents: cents }) },
      );
      if (!res.ok) {
        const { error: apiErr } = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(apiErr ?? `Failed (${res.status})`);
      }
      const data = (await res.json()) as TopUpResponse;

      if (data.status === 'succeeded') {
        if (onSuccess) await onSuccess();
        setSubmitting(false);
        return;
      }
      if (data.status === 'needs_setup') {
        setError('Billing address missing. Re-add your card to capture it.');
        setSubmitting(false);
        return;
      }
      if (data.status === 'requires_payment_method') {
        setError('Add a payment method first.');
        setSubmitting(false);
        return;
      }
      if (data.status === 'requires_action' && data.client_secret) {
        setActionClientSecret(data.client_secret);
        // Keep submitting=true until 3DS resolves
        return;
      }
      setError('Unexpected response — try again.');
      setSubmitting(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Top-up failed');
      setSubmitting(false);
    }
  };

  return (
    <>
      <TooltipProvider delayDuration={150}>
        <form onSubmit={submit} noValidate className="flex items-center gap-3">
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="relative">
                <span
                  className={cn(
                    'pointer-events-none absolute inset-y-0 left-3 flex items-center text-sm',
                    belowMinimum ? 'text-destructive' : 'text-foreground-secondary',
                  )}
                >
                  $
                </span>
                <Input
                  type="number"
                  step="1"
                  inputMode="decimal"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  className={cn(
                    'h-8 w-32 rounded-lg pl-6',
                    belowMinimum
                      ? '!border-destructive !text-destructive focus-visible:!border-destructive focus-visible:!ring-destructive/30'
                      : 'focus-visible:!border-foreground-secondary/60 focus-visible:!ring-foreground-secondary/30',
                  )}
                  placeholder="Amount"
                />
              </div>
            </TooltipTrigger>
            {belowMinimum && (
              <TooltipContent side="top">Minimum top-up is $5</TooltipContent>
            )}
          </Tooltip>
          <Button type="submit" variant="white" disabled={!isValid || submitting} className="relative">
            <span className={submitting ? 'invisible' : undefined}>Add credit</span>
            {submitting && (
              <span className="absolute inset-0 flex items-center justify-center">
                <Loader2 className="h-4 w-4 animate-spin" />
              </span>
            )}
          </Button>
        </form>
        {error && <p className="mt-1 text-right text-xs text-destructive">{error}</p>}
      </TooltipProvider>
      {actionClientSecret && (
        <Elements
          stripe={stripePromise}
          options={{
            clientSecret: actionClientSecret,
            appearance: { theme: 'night', variables: { colorPrimary: '#047857' } },
          }}
        >
          <ThreeDSResolver
            clientSecret={actionClientSecret}
            onResolved={async (ok) => {
              setActionClientSecret(null);
              setSubmitting(false);
              if (ok && onSuccess) await onSuccess();
              else if (!ok) setError('Card verification failed. Try a different card.');
            }}
          />
        </Elements>
      )}
    </>
  );
}

function ThreeDSResolver({
  clientSecret,
  onResolved,
}: {
  clientSecret: string;
  onResolved: (success: boolean) => Promise<void> | void;
}) {
  const stripe = useStripe();
  const ranRef = React.useRef(false);

  React.useEffect(() => {
    if (!stripe || ranRef.current) return;
    ranRef.current = true;
    (async () => {
      const result = await stripe.handleNextAction({ clientSecret });
      const status = result.paymentIntent?.status;
      await onResolved(status === 'succeeded');
    })();
  }, [stripe, clientSecret, onResolved]);

  return null;
}
