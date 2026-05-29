import React, { useCallback, useEffect, useState } from 'react';
import { CreditCard, Loader2, MoreHorizontal, Star, Trash2 } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { Skeleton } from '../ui/skeleton';
import { AddCardModal } from './AddCardModal';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface PaymentMethod {
  id: string;
  brand: string;
  last4: string;
  expiresMonth: number;
  expiresYear: number;
  isDefault: boolean;
}

interface PaymentMethodsCardProps {
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

export function PaymentMethodsCard({ organizationId }: PaymentMethodsCardProps) {
  const { user } = useAuth();
  const [methods, setMethods] = useState<PaymentMethod[] | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const refetch = useCallback(async () => {
    try {
      const res = await authedFetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/billing/payment-methods`,
      );
      if (!res.ok) return;
      const data = (await res.json()) as { payment_methods: PaymentMethod[] };
      setMethods(data.payment_methods);
    } catch (err) {
      console.warn('[billing] payment-methods fetch failed', err);
    }
  }, [organizationId]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  const setDefault = async (pmId: string) => {
    setBusyId(pmId);
    try {
      await authedFetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/billing/payment-methods/${pmId}/default`,
        { method: 'POST', body: JSON.stringify({}) },
      );
      await refetch();
    } finally {
      setBusyId(null);
    }
  };

  const remove = async (pmId: string) => {
    setBusyId(pmId);
    try {
      await authedFetch(
        `${API_BASE_URL}/api/organizations/${organizationId}/billing/payment-methods/${pmId}`,
        { method: 'DELETE' },
      );
      await refetch();
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background-card">
      <div className="px-5 pt-5 pb-4">
        <p className="text-base font-semibold text-foreground">Payment methods</p>
        <p className="mt-1 text-sm text-foreground-secondary">
          Top-ups and auto-reload charge the default card.
        </p>
      </div>
      <div className="border-t border-border">
        {methods == null ? (
          <div className="divide-y divide-border">
            {[0, 1].map((i) => (
              <div key={i} className="flex items-center gap-3 px-5 py-4">
                <Skeleton className="h-8 w-12 rounded" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-32" />
                </div>
                <Skeleton className="h-3 w-24" />
              </div>
            ))}
          </div>
        ) : methods.length === 0 ? (
          <div className="flex flex-col items-center px-5 py-12">
            <span className="flex h-10 w-10 items-center justify-center rounded-full border border-border">
              <CreditCard className="h-4 w-4 text-foreground-secondary" />
            </span>
            <p className="mt-3 text-sm font-semibold text-foreground">No payment methods</p>
            <p className="mt-1 text-xs text-foreground-secondary">
              Add a card to enable auto-reload and seamless top-ups.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {methods.map((m) => (
              <div
                key={m.id}
                className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-table-hover"
              >
                <CardBrandBadge brand={m.brand} />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-foreground">
                      {capitalize(m.brand)} •••• {m.last4}
                    </p>
                    {m.isDefault && (
                      <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-emerald-300">
                        Default
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-foreground-secondary tabular-nums">
                    Valid until {m.expiresMonth}/{m.expiresYear}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <button
                        type="button"
                        disabled={busyId === m.id}
                        className="flex h-8 w-8 items-center justify-center rounded-md text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground disabled:opacity-50"
                      >
                        {busyId === m.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <MoreHorizontal className="h-4 w-4" />
                        )}
                      </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-44">
                      {!m.isDefault && (
                        <DropdownMenuItem onSelect={() => setDefault(m.id)}>
                          <Star className="mr-2 h-3.5 w-3.5" />
                          Set as default
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem
                        onSelect={() => remove(m.id)}
                        className="text-destructive focus:text-destructive"
                      >
                        <Trash2 className="mr-2 h-3.5 w-3.5" />
                        Remove
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center justify-end gap-3 border-t border-border bg-background-card-header px-5 py-3">
        <Button
          type="button"
          variant="white"
          onClick={() => setAddOpen(true)}
          className="!h-8 !px-3 !rounded-lg"
        >
          Add card
        </Button>
      </div>
      <AddCardModal
        open={addOpen}
        onOpenChange={setAddOpen}
        organizationId={organizationId}
        defaultEmail={user?.email ?? null}
        onSaved={refetch}
      />
    </div>
  );
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function CardBrandBadge({ brand }: { brand: string }) {
  const b = brand.toLowerCase();
  if (b === 'visa') {
    return (
      <div className="flex h-7 w-10 shrink-0 items-center justify-center rounded bg-[#1A1F71]">
        <span className="text-[10px] font-bold italic tracking-tight text-white">VISA</span>
      </div>
    );
  }
  if (b === 'mastercard') {
    return (
      <div className="flex h-7 w-10 shrink-0 items-center justify-center rounded bg-black">
        <div className="relative h-3 w-5">
          <span className="absolute left-0 top-0 block h-3 w-3 rounded-full bg-[#EB001B]" />
          <span className="absolute right-0 top-0 block h-3 w-3 rounded-full bg-[#F79E1B] opacity-80" />
        </div>
      </div>
    );
  }
  if (b === 'amex') {
    return (
      <div className="flex h-7 w-10 shrink-0 items-center justify-center rounded bg-[#006FCF]">
        <span className="text-[8px] font-bold tracking-tight text-white">AMEX</span>
      </div>
    );
  }
  if (b === 'discover') {
    return (
      <div className="flex h-7 w-10 shrink-0 items-center justify-center rounded bg-[#F58220]">
        <span className="text-[8px] font-bold tracking-tight text-white">DISC</span>
      </div>
    );
  }
  return (
    <div className="flex h-7 w-10 shrink-0 items-center justify-center rounded border border-border bg-background-subtle">
      <CreditCard className="h-3.5 w-3.5 text-foreground-secondary" />
    </div>
  );
}
