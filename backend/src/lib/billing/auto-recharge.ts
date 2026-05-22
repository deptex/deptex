import { supabase } from '../supabase';
import { isBillingEnforcementEnabled } from './enforcement';
import { createPaymentIntent } from './stripe-billing';

const STUCK_FLAG_RECOVERY_MS = 30 * 60 * 1000;

export interface AutoRechargeResult {
  attempted: boolean;
  reason?:
    | 'enforcement_off'
    | 'disabled'
    | 'above_threshold'
    | 'no_payment_method'
    | 'monthly_cap_reached'
    | 'in_progress'
    | 'stuck_flag_cleared'
    | 'pi_created'
    | 'pi_failed';
  paymentIntentId?: string;
}

async function clearStuckFlag(orgId: string): Promise<void> {
  await supabase
    .from('organization_billing')
    .update({
      auto_recharge_in_progress: false,
      auto_recharge_in_progress_started_at: null,
    })
    .eq('organization_id', orgId);
}

async function sumThisMonth(orgId: string): Promise<number> {
  const monthStart = new Date();
  monthStart.setUTCDate(1);
  monthStart.setUTCHours(0, 0, 0, 0);

  const { data, error } = await supabase
    .from('billing_transactions')
    .select('amount_cents')
    .eq('organization_id', orgId)
    .eq('kind', 'auto_recharge_topup')
    .gte('created_at', monthStart.toISOString());
  if (error || !data) return 0;
  return data.reduce((sum, row) => sum + Math.max(0, row.amount_cents), 0);
}

export async function maybeAutoRecharge(orgId: string): Promise<AutoRechargeResult> {
  if (!isBillingEnforcementEnabled()) {
    return { attempted: false, reason: 'enforcement_off' };
  }

  const { data: billing, error } = await supabase
    .from('organization_billing')
    .select('*')
    .eq('organization_id', orgId)
    .single();
  if (error || !billing) return { attempted: false, reason: 'disabled' };

  if (!billing.auto_recharge_enabled) {
    return { attempted: false, reason: 'disabled' };
  }
  if (
    billing.auto_recharge_threshold_cents == null ||
    billing.auto_recharge_amount_cents == null
  ) {
    return { attempted: false, reason: 'disabled' };
  }
  if (!billing.stripe_default_payment_method_id) {
    return { attempted: false, reason: 'no_payment_method' };
  }

  if (billing.auto_recharge_in_progress) {
    const startedAt = billing.auto_recharge_in_progress_started_at
      ? new Date(billing.auto_recharge_in_progress_started_at).getTime()
      : 0;
    if (Date.now() - startedAt > STUCK_FLAG_RECOVERY_MS) {
      console.warn(
        '[auto-recharge] stuck flag detected, force-clearing',
        { orgId, startedAt: billing.auto_recharge_in_progress_started_at },
      );
      await clearStuckFlag(orgId);
      return { attempted: false, reason: 'stuck_flag_cleared' };
    }
    return { attempted: false, reason: 'in_progress' };
  }

  if (billing.balance_cents >= billing.auto_recharge_threshold_cents) {
    return { attempted: false, reason: 'above_threshold' };
  }

  if (billing.auto_recharge_monthly_cap_cents != null) {
    const sumMonth = await sumThisMonth(orgId);
    if (sumMonth + billing.auto_recharge_amount_cents > billing.auto_recharge_monthly_cap_cents) {
      return { attempted: false, reason: 'monthly_cap_reached' };
    }
  }

  const { error: lockErr } = await supabase
    .from('organization_billing')
    .update({
      auto_recharge_in_progress: true,
      auto_recharge_in_progress_started_at: new Date().toISOString(),
      auto_recharge_last_attempt_at: new Date().toISOString(),
    })
    .eq('organization_id', orgId)
    .eq('auto_recharge_in_progress', false);

  if (lockErr) {
    return { attempted: false, reason: 'in_progress' };
  }

  try {
    const { paymentIntent } = await createPaymentIntent({
      orgId,
      amountCents: billing.auto_recharge_amount_cents,
      purpose: 'auto_recharge_topup',
      offSession: true,
      paymentMethodId: billing.stripe_default_payment_method_id,
    });
    return { attempted: true, reason: 'pi_created', paymentIntentId: paymentIntent.id };
  } catch (err) {
    console.error('[auto-recharge] PaymentIntent creation failed', err);
    await clearStuckFlag(orgId);
    await supabase
      .from('organization_billing')
      .update({ auto_recharge_enabled: false })
      .eq('organization_id', orgId);
    return { attempted: true, reason: 'pi_failed' };
  }
}
