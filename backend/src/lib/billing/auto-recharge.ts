import { supabase } from '../supabase';
import { isBillingEnforcementEnabled } from './enforcement';
import { createTopUpInvoice } from './stripe-billing';
import { resolveBillingRecipients, sendAutoRechargeFailed } from './alerts';

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
    const recipients = await resolveBillingRecipients(orgId).catch(() => [] as string[]);
    const fallbackEmail = recipients[0];

    const result = await createTopUpInvoice({
      orgId,
      amountCents: billing.auto_recharge_amount_cents,
      purpose: 'auto_recharge_topup',
      fallbackEmail,
    });

    if (result.status === 'succeeded') {
      // payment_intent.succeeded webhook will credit balance + clear in_progress flag.
      return { attempted: true, reason: 'pi_created', paymentIntentId: result.paymentIntentId ?? undefined };
    }

    // Off-session failure modes. For off-session 3DS-required cards Stripe does NOT fire
    // payment_intent.payment_failed — it fires invoice.payment_failed instead. So we can't
    // rely on the webhook to disable + email; do it inline for every non-success status.
    console.warn('[auto-recharge] non-success status from createTopUpInvoice', {
      orgId,
      status: result.status,
    });
    await clearStuckFlag(orgId);

    const reasonByStatus: Record<'needs_setup' | 'requires_action' | 'requires_payment_method', string> = {
      needs_setup: 'Billing address missing on Stripe customer',
      requires_action: 'Card requires authentication and cannot be charged off-session',
      requires_payment_method: 'Card was declined',
    };
    const reason = reasonByStatus[result.status] ?? 'Auto-recharge failed';

    await supabase
      .from('organization_billing')
      .update({ auto_recharge_enabled: false })
      .eq('organization_id', orgId);
    await sendAutoRechargeFailed(orgId, reason).catch((err) =>
      console.error('[auto-recharge] sendAutoRechargeFailed failed', err),
    );

    return { attempted: true, reason: 'pi_failed' };
  } catch (err) {
    console.error('[auto-recharge] createTopUpInvoice threw', err);
    await clearStuckFlag(orgId);
    await supabase
      .from('organization_billing')
      .update({ auto_recharge_enabled: false })
      .eq('organization_id', orgId);
    await sendAutoRechargeFailed(orgId, err instanceof Error ? err.message : 'unknown').catch(() => {});
    return { attempted: true, reason: 'pi_failed' };
  }
}
