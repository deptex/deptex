import React, { createContext, useContext, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { supabase } from '../lib/supabase';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

export interface BillingPaymentMethod {
  brand: string;
  last4: string;
  expiresMonth: number;
  expiresYear: number;
}

export interface BillingState {
  balanceCents: number;
  autoRecharge: {
    enabled: boolean;
    thresholdCents: number | null;
    amountCents: number | null;
    monthlyCapCents: number | null;
  };
  lowBalanceAlertThresholdCents: number;
  paymentMethod: BillingPaymentMethod | null;
}

interface BillingContextValue {
  billing: BillingState | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  showTopUpModal: boolean;
  openTopUp: (reason?: 'low_balance' | 'zero_balance' | 'insufficient_credit' | 'manual') => void;
  closeTopUp: () => void;
  topUpReason: 'low_balance' | 'zero_balance' | 'insufficient_credit' | 'manual' | null;
}

const BillingContext = createContext<BillingContextValue | null>(null);

export interface BillingProviderProps {
  organizationId: string | null;
  children: React.ReactNode;
}

export function BillingProvider({ organizationId, children }: BillingProviderProps) {
  const [billing, setBilling] = useState<BillingState | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [showTopUpModal, setShowTopUpModal] = useState(false);
  const [topUpReason, setTopUpReason] = useState<BillingContextValue['topUpReason']>(null);

  const fetchBilling = useCallback(async () => {
    if (!organizationId) {
      setBilling(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { data: session } = await supabase.auth.getSession();
      const token = session.session?.access_token;
      if (!token) throw new Error('Not authenticated');

      const res = await fetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 404) {
        setBilling(null);
        return;
      }
      if (!res.ok) throw new Error(`Failed to load billing (${res.status})`);
      const data = (await res.json()) as BillingState;
      setBilling(data);
    } catch (err) {
      console.error('[billing] fetch failed', err);
      setError(err instanceof Error ? err.message : 'Failed to load billing');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    void fetchBilling();
  }, [fetchBilling]);

  // Refetch when the tab regains focus or visibility (e.g. user comes back
  // after a top-up, or after auto-recharge ran in the background).
  useEffect(() => {
    if (!organizationId) return;
    const onFocus = () => void fetchBilling();
    const onVisible = () => {
      if (document.visibilityState === 'visible') void fetchBilling();
    };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [organizationId, fetchBilling]);

  // Realtime subscription on organization_billing — any UPDATE to balance,
  // auto-recharge state, or PM triggers an immediate refetch. Catches the
  // server-side auto-recharge case where the user never leaves the page.
  useEffect(() => {
    if (!organizationId) return;
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    (async () => {
      const { data: { session } } = await supabase.auth.getSession();
      await (supabase.realtime as unknown as { setAuth: (t: string | null) => Promise<void> }).setAuth(
        session?.access_token ?? null,
      );
      if (cancelled) return;
      channel = supabase
        .channel(`billing-org-${organizationId}`)
        .on(
          'postgres_changes',
          { event: 'UPDATE', schema: 'public', table: 'organization_billing', filter: `organization_id=eq.${organizationId}` },
          () => {
            void fetchBilling();
          },
        )
        .subscribe();
    })();
    return () => {
      cancelled = true;
      if (channel) supabase.removeChannel(channel);
    };
  }, [organizationId, fetchBilling]);

  const openTopUp = useCallback(
    (reason: BillingContextValue['topUpReason'] = 'manual') => {
      setTopUpReason(reason);
      setShowTopUpModal(true);
    },
    [],
  );

  const closeTopUp = useCallback(() => {
    setShowTopUpModal(false);
    setTopUpReason(null);
  }, []);

  const value = useMemo<BillingContextValue>(
    () => ({
      billing,
      loading,
      error,
      refetch: fetchBilling,
      showTopUpModal,
      openTopUp,
      closeTopUp,
      topUpReason,
    }),
    [billing, loading, error, fetchBilling, showTopUpModal, openTopUp, closeTopUp, topUpReason],
  );

  return <BillingContext.Provider value={value}>{children}</BillingContext.Provider>;
}

export function useBilling(): BillingContextValue {
  const ctx = useContext(BillingContext);
  if (!ctx) {
    throw new Error('useBilling must be used inside a BillingProvider');
  }
  return ctx;
}

// Backwards-compat shims for the 4-tier API surface — every feature is
// now allowed (prepaid model gives everyone everything). These exist ONLY
// to keep stale call sites compiling until they're deleted. New code
// should use useBilling() directly.

export type PlanTier = 'free' | 'pro' | 'team' | 'enterprise';
export type GatableFeature = string;
export type LimitableResource = string;

interface PermissiveGate {
  allowed: true;
  upgradeUrl: string;
  requiredTier: PlanTier;
}

interface PermissiveLimit {
  allowed: true;
  limit: number;
  current: number;
}

const PERMISSIVE_GATE: PermissiveGate = {
  allowed: true,
  upgradeUrl: '#',
  requiredTier: 'free',
};

const PERMISSIVE_LIMIT: PermissiveLimit = {
  allowed: true,
  limit: Number.POSITIVE_INFINITY,
  current: 0,
};

export const TIER_DISPLAY: Record<PlanTier, string> = {
  free: 'Free',
  pro: 'Pro',
  team: 'Team',
  enterprise: 'Enterprise',
};

export interface PlanData {
  tier: PlanTier;
}

export const PlanProvider = BillingProvider;

interface PlanShim {
  plan: PlanData | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  isFeatureAllowed: (_: GatableFeature) => boolean;
  getPlanGate: (_: GatableFeature) => PermissiveGate;
  getPlanLimit: (_: LimitableResource) => PermissiveLimit;
  highestUsagePercent: () => number;
}

export function usePlan(): PlanShim {
  const { loading, error, refetch } = useBilling();
  return {
    plan: { tier: 'free' as const },
    loading,
    error,
    refetch,
    isFeatureAllowed: () => true,
    getPlanGate: () => PERMISSIVE_GATE,
    getPlanLimit: () => PERMISSIVE_LIMIT,
    highestUsagePercent: () => 0,
  };
}

export function usePlanGate(_: GatableFeature): PermissiveGate {
  return PERMISSIVE_GATE;
}

export function usePlanLimit(_: LimitableResource): PermissiveLimit {
  return PERMISSIVE_LIMIT;
}
