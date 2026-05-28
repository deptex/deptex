import React, { useEffect, useState } from 'react';
import { AddressElement, Elements, PaymentElement, useElements, useStripe } from '@stripe/react-stripe-js';
import { Loader2 } from 'lucide-react';
import { supabase } from '../../lib/supabase';
import { stripePromise } from '../../lib/stripe-client';
import { Button } from '../ui/button';
import { Skeleton } from '../ui/skeleton';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface AddCardModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  defaultEmail: string | null;
  onSaved: () => Promise<void> | void;
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

export function AddCardModal({ open, onOpenChange, organizationId, defaultEmail, onSaved }: AddCardModalProps) {
  const [clientSecret, setClientSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stripeReady, setStripeReady] = useState(false);

  // Lock body scroll while the modal is open.
  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prevOverflow;
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      setClientSecret(null);
      setError(null);
      setStripeReady(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await authedFetch(
          `${API_BASE_URL}/api/organizations/${organizationId}/billing/setup-intent`,
          { method: 'POST', body: JSON.stringify({}) },
        );
        if (!res.ok) {
          const { error: apiErr } = (await res.json().catch(() => ({}))) as { error?: string };
          throw new Error(apiErr ?? `Failed (${res.status})`);
        }
        const data = (await res.json()) as { client_secret: string };
        if (!cancelled) setClientSecret(data.client_secret);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to start add-card flow');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, organizationId]);

  if (!open) return null;

  const close = () => onOpenChange(false);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4"
      onClick={close}
    >
      <div
        className="relative flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden rounded-lg border border-border bg-background-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        {(!clientSecret || (clientSecret && !stripeReady)) && !error && <LoadingSkeleton onCancel={close} />}
        {error && (
          <>
            <ModalHeader />
            <p className="bg-background-card-header py-8 text-center text-sm text-destructive">{error}</p>
            <div className="shrink-0 flex items-center justify-between gap-2 border-t border-border bg-background-card px-6 py-3">
              <Button
                type="button"
                variant="outline"
                onClick={close}
                className="!h-8 !px-3 !rounded-lg"
              >
                Close
              </Button>
              <span />
            </div>
          </>
        )}
        {clientSecret && (
          <div
            className={
              stripeReady ? 'flex flex-1 flex-col overflow-hidden' : 'pointer-events-none absolute h-0 w-0 overflow-hidden opacity-0'
            }
          >
            <Elements
              stripe={stripePromise}
              options={{
                clientSecret,
                appearance: {
                  theme: 'night',
                  variables: {
                    colorPrimary: '#047857',
                    colorBackground: '#050505',
                    colorText: '#fafafa',
                    colorTextSecondary: '#a1a1a1',
                    colorDanger: '#D43A38',
                    fontFamily: 'system-ui, -apple-system, sans-serif',
                    borderRadius: '8px',
                    spacingUnit: '4px',
                  },
                  rules: {
                    '.Input': {
                      backgroundColor: '#0a0a0a',
                      border: '1px solid #262626',
                    },
                    '.Input:focus': {
                      border: '1px solid #a1a1a160',
                      boxShadow: '0 0 0 3px #a1a1a130',
                    },
                    '.Tab': {
                      backgroundColor: '#0a0a0a',
                      border: '1px solid #262626',
                    },
                    '.Tab--selected': {
                      backgroundColor: '#171717',
                      border: '1px solid #404040',
                    },
                  },
                },
              }}
            >
              <SaveCardForm
                organizationId={organizationId}
                defaultEmail={defaultEmail}
                onReady={() => setStripeReady(true)}
                onSaved={async () => {
                  await onSaved();
                  close();
                }}
                onCancel={close}
              />
            </Elements>
          </div>
        )}
      </div>
    </div>
  );
}

function ModalHeader() {
  return (
    <div className="shrink-0 bg-background-card-header px-6 pb-4 pt-6">
      <h2 className="text-base font-semibold text-foreground">Add a payment method</h2>
      <p className="mt-1 text-xs text-foreground-secondary">
        Saved securely with Stripe. Used for top-ups and auto-reload.
      </p>
    </div>
  );
}

function LoadingSkeleton({ onCancel }: { onCancel: () => void }) {
  return (
    <>
      <div className="custom-scrollbar flex-1 overflow-y-auto bg-background-card-header px-6 pb-5 pt-6">
        <div className="mb-5">
          <h2 className="text-base font-semibold text-foreground">Add a payment method</h2>
          <p className="mt-1 text-xs text-foreground-secondary">
            Saved securely with Stripe. Used for top-ups and auto-reload.
          </p>
        </div>
        <div className="space-y-5">
          <SkeletonField labelWidth="w-20" />
          <SkeletonField labelWidth="w-28" />
          <SkeletonField labelWidth="w-16" />
          <div className="grid grid-cols-2 gap-3">
            <SkeletonField labelWidth="w-10" />
            <SkeletonField labelWidth="w-24" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <SkeletonField labelWidth="w-20" />
            <SkeletonField labelWidth="w-16" />
          </div>
          <div className="space-y-2 pt-2">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="h-10 w-full" />
          </div>
          <SkeletonField labelWidth="w-24" />
        </div>
      </div>
      <div className="shrink-0 flex items-center justify-between gap-2 border-t border-border bg-background-card px-6 py-3">
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          className="!h-8 !px-3 !rounded-lg"
        >
          Cancel
        </Button>
        <Button type="button" variant="white" disabled>
          Save card
        </Button>
      </div>
    </>
  );
}

function SkeletonField({ labelWidth }: { labelWidth: string }) {
  return (
    <div className="space-y-2">
      <Skeleton className={`h-3 ${labelWidth}`} />
      <Skeleton className="h-10 w-full" />
    </div>
  );
}

interface SaveCardFormProps {
  organizationId: string;
  defaultEmail: string | null;
  onReady: () => void;
  onSaved: () => Promise<void> | void;
  onCancel: () => void;
}

function SaveCardForm({ organizationId, defaultEmail, onReady, onSaved, onCancel }: SaveCardFormProps) {
  const stripe = useStripe();
  const elements = useElements();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!stripe || !elements) return;
    setSubmitting(true);
    setError(null);
    const { error: confirmErr, setupIntent } = await stripe.confirmSetup({
      elements,
      redirect: 'if_required',
      confirmParams: { return_url: window.location.href },
    });
    if (confirmErr) {
      setError(confirmErr.message ?? 'Failed to save card');
      setSubmitting(false);
      return;
    }
    if (!setupIntent || setupIntent.status !== 'succeeded') {
      setError('Card was not saved. Try again.');
      setSubmitting(false);
      return;
    }
    // Persist as default + write to our DB
    try {
      const pmId =
        typeof setupIntent.payment_method === 'string'
          ? setupIntent.payment_method
          : setupIntent.payment_method?.id;
      if (pmId) {
        await authedFetch(
          `${API_BASE_URL}/api/organizations/${organizationId}/billing/payment-methods/${pmId}/default`,
          { method: 'POST', body: JSON.stringify({}) },
        );
      }
      await onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Card saved but failed to set as default');
      setSubmitting(false);
    }
  };

  return (
    <>
      {/* Scrollable content includes the header (dark) */}
      <div className="custom-scrollbar flex-1 overflow-y-auto bg-background-card-header px-6 pb-5 pt-6">
        <div className="mb-5">
          <h2 className="text-base font-semibold text-foreground">Add a payment method</h2>
          <p className="mt-1 text-xs text-foreground-secondary">
            Saved securely with Stripe. Used for top-ups and auto-reload.
          </p>
        </div>
        <div className="space-y-4">
          <AddressElement
            options={{
              mode: 'billing',
              defaultValues: defaultEmail ? { name: '', address: undefined } : undefined,
              fields: { phone: 'never' },
            }}
          />
          <PaymentElement
            options={{
              wallets: { applePay: 'auto', googlePay: 'auto' },
              layout: { type: 'tabs', defaultCollapsed: false },
            }}
            onReady={onReady}
          />
          {error && <p className="text-xs text-destructive">{error}</p>}
        </div>
      </div>
      {/* Footer (light, pinned outside scroll area) — Cancel left, Save right */}
      <div className="shrink-0 flex items-center justify-between gap-2 border-t border-border bg-background-card px-6 py-3">
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={submitting}
          className="!h-8 !px-3 !rounded-lg"
        >
          Cancel
        </Button>
        <Button
          type="button"
          variant="white"
          onClick={submit}
          disabled={submitting || !stripe}
          className="relative"
        >
          <span className={submitting ? 'invisible' : undefined}>Save card</span>
          {submitting && (
            <span className="absolute inset-0 flex items-center justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />
            </span>
          )}
        </Button>
      </div>
    </>
  );
}
