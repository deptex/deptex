import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { supabase } from '../lib/supabase';

// ─── Types ───

export type PlanTier = 'free' | 'pro' | 'team' | 'enterprise';

export type GatableFeature =
  | 'aegis_chat' | 'ai_fixes' | 'background_monitoring' | 'watchtower_forensics'
  | 'sso' | 'mfa_enforcement' | 'ip_allowlist' | 'legal_docs' | 'aegis_management' | 'audit_logs'
  | 'custom_sla' | 'security_slas' | 'sync_frequency';

export type LimitableResource =
  | 'projects' | 'members' | 'syncs' | 'watchtower' | 'teams'
  | 'notification_rules' | 'integrations' | 'automations';

interface TierLimits {
  projects: number;
  members: number;
  syncs: number;
  watchtower: number;
  teams: number;
  notification_rules: number;
  integrations: number;
  automations: number;
  api_rpm: number;
}

interface TierFeatures {
  aegis_chat: boolean;
  ai_fixes: boolean;
  background_monitoring: boolean;
  watchtower_forensics: boolean;
  sso: boolean;
  mfa_enforcement: boolean;
  ip_allowlist: boolean;
  legal_docs: boolean;
  aegis_management: boolean;
  audit_logs: boolean;
  custom_sla: boolean;
  security_slas: boolean;
  sync_frequency: boolean;
}

interface UsageData {
  projects: number;
  members: number;
  syncs: number;
  watchtower: number;
  teams: number;
  notification_rules: number;
  integrations: number;
  automations: number;
}

export interface PlanData {
  tier: PlanTier;
  status: string;
  limits: TierLimits;
  usage: UsageData;
  features: TierFeatures;
  syncs_reset_at: string;
  current_period_end: string | null;
  billing_cycle: string;
  cancel_at_period_end: boolean;
  cancel_at: string | null;
  payment_method_brand: string | null;
  payment_method_last4: string | null;
  billing_email: string | null;
}

interface PlanGateResult {
  allowed: boolean;
  requiredTier: PlanTier;
  currentTier: PlanTier;
  upgradeUrl: string;
}

interface PlanLimitResult {
  allowed: boolean;
  current: number;
  limit: number;
  percentage: number;
  isUnlimited: boolean;
}

interface PlanContextValue {
  plan: PlanData | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
  isFeatureAllowed: (feature: GatableFeature) => boolean;
  getPlanGate: (feature: GatableFeature) => PlanGateResult;
  getPlanLimit: (resource: LimitableResource) => PlanLimitResult;
  highestUsagePercent: number;
}

// ─── Feature -> minimum tier mapping ───

const FEATURE_REQUIRED_TIER: Record<GatableFeature, PlanTier> = {
  aegis_chat: 'pro',
  ai_fixes: 'pro',
  background_monitoring: 'pro',
  watchtower_forensics: 'pro',
  sync_frequency: 'pro',
  sso: 'team',
  mfa_enforcement: 'team',
  ip_allowlist: 'team',
  legal_docs: 'team',
  aegis_management: 'pro',
  audit_logs: 'team',
  custom_sla: 'enterprise',
  security_slas: 'team',
};

export const TIER_DISPLAY: Record<PlanTier, string> = {
  free: 'Free',
  pro: 'Pro',
  team: 'Team',
  enterprise: 'Enterprise',
};

// ─── Context ───

const PlanContext = createContext<PlanContextValue | null>(null);

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

export function PlanProvider({ organizationId, children }: { organizationId: string; children: React.ReactNode }) {
  const [plan, setPlan] = useState<PlanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPlan = useCallback(async () => {
    if (!organizationId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        setLoading(false);
        return;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      const res = await fetch(`${API_BASE_URL}/api/organizations/${organizationId}/billing/plan`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error((errBody as { error?: string }).error || `Failed to fetch plan (${res.status})`);
      }
      const data = await res.json();
      setPlan(data);
    } catch (e: any) {
      setError(e?.message || 'Failed to load plan');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    fetchPlan();
  }, [fetchPlan]);

  const isFeatureAllowed = useCallback((feature: GatableFeature): boolean => {
    if (!plan) return true;
    return plan.features[feature] === true;
  }, [plan]);

  const getPlanGate = useCallback((feature: GatableFeature): PlanGateResult => {
    const tier = plan?.tier || 'free';
    const allowed = plan?.features[feature] === true;
    return {
      allowed: allowed ?? false,
      requiredTier: FEATURE_REQUIRED_TIER[feature],
      currentTier: tier,
      upgradeUrl: `/organizations/${organizationId}/settings/plan`,
    };
  }, [plan, organizationId]);

  const getPlanLimit = useCallback((resource: LimitableResource): PlanLimitResult => {
    if (!plan) return { allowed: true, current: 0, limit: -1, percentage: 0, isUnlimited: true };
    const limit = plan.limits[resource];
    const current = plan.usage[resource];
    const isUnlimited = limit === -1;
    const percentage = isUnlimited ? 0 : limit > 0 ? Math.round((current / limit) * 100) : 0;
    return { allowed: isUnlimited || current < limit, current, limit, percentage, isUnlimited };
  }, [plan]);

  const highestUsagePercent = useMemo(() => {
    if (!plan) return 0;
    const resources: LimitableResource[] = ['projects', 'members', 'syncs', 'watchtower', 'teams'];
    let max = 0;
    for (const r of resources) {
      const limit = plan.limits[r];
      if (limit === -1) continue;
      const pct = limit > 0 ? Math.round((plan.usage[r] / limit) * 100) : 0;
      if (pct > max) max = pct;
    }
    return max;
  }, [plan]);

  const value = useMemo(() => ({
    plan,
    loading,
    error,
    refetch: fetchPlan,
    isFeatureAllowed,
    getPlanGate,
    getPlanLimit,
    highestUsagePercent,
  }), [plan, loading, error, fetchPlan, isFeatureAllowed, getPlanGate, getPlanLimit, highestUsagePercent]);

  return <PlanContext.Provider value={value}>{children}</PlanContext.Provider>;
}

export function usePlan() {
  const ctx = useContext(PlanContext);
  if (!ctx) {
    return {
      plan: null,
      loading: false,
      error: null,
      refetch: () => {},
      isFeatureAllowed: () => true,
      getPlanGate: (feature: GatableFeature) => ({ allowed: true, requiredTier: 'free' as PlanTier, currentTier: 'free' as PlanTier, upgradeUrl: '' }),
      getPlanLimit: () => ({ allowed: true, current: 0, limit: -1, percentage: 0, isUnlimited: true }),
      highestUsagePercent: 0,
    };
  }
  return ctx;
}

export function usePlanGate(feature: GatableFeature) {
  const { getPlanGate } = usePlan();
  return getPlanGate(feature);
}

export function usePlanLimit(resource: LimitableResource) {
  const { getPlanLimit } = usePlan();
  return getPlanLimit(resource);
}
