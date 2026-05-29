import crypto from 'crypto';
import { supabase } from '../supabase';
import { isBillingEnforcementEnabled } from './enforcement';
import { createTopUpInvoice, voidOpenInvoice } from './stripe-billing';
import { resolveBillingRecipients, sendAutoRechargeFailed, sendAutoRechargeCapReached } from './alerts';

// Recovery window for a stuck auto_recharge_in_progress flag. Bumped from 30 → 60 min
// because Stripe's async invoice settlement (especially 3DS retries + slow gateways) can
// occasionally run past 30 min. At 60 min the worst case is one extra minute of user
// lock-out; the upside is we no longer race a real in-flight PI by clearing the flag
// under it. The clear itself is logged so an unexpected uptick is grep-able.
const STUCK_FLAG_RECOVERY_MS = 60 * 60 * 1000;

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

// Rolling 30-day window. We don't have a billing cycle (pure prepaid), so a calendar-month
// reset would create a cliff at month boundaries — spend the cap on the 31st, then spend it
// again on the 1st. Rolling 30 days enforces the cap consistently regardless of when in the
// month charges happen.
const ROLLING_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

async function sumLast30Days(orgId: string): Promise<number> {
  const windowStart = new Date(Date.now() - ROLLING_WINDOW_MS);

  const { data, error } = await supabase
    .from('billing_transactions')
    .select('amount_cents')
    .eq('organization_id', orgId)
    .eq('kind', 'auto_recharge_topup')
    .gte('created_at', windowStart.toISOString());
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
      console.warn('[billing] stuck flag detected, force-clearing', {
        orgId,
        startedAt: billing.auto_recharge_in_progress_started_at,
        ageMs: Date.now() - startedAt,
      });
      await clearStuckFlag(orgId);
      return { attempted: false, reason: 'stuck_flag_cleared' };
    }
    return { attempted: false, reason: 'in_progress' };
  }

  if (billing.balance_cents >= billing.auto_recharge_threshold_cents) {
    return { attempted: false, reason: 'above_threshold' };
  }

  if (billing.auto_recharge_monthly_cap_cents != null) {
    const sumWindow = await sumLast30Days(orgId);
    if (sumWindow + billing.auto_recharge_amount_cents > billing.auto_recharge_monthly_cap_cents) {
      // Fire-and-forget: email the org once per UTC month so cap-reached is never silent.
      sendAutoRechargeCapReached(orgId, sumWindow, billing.auto_recharge_monthly_cap_cents).catch(
        (err) => console.error('[auto-recharge] sendAutoRechargeCapReached failed', err),
      );
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

  // Correlation ID stamped on every log line + Stripe PI/Invoice metadata for this
  // attempt. Lets you grep [billing] for one auto-recharge cycle and see
  // meter-event → auto-recharge → Stripe PI → webhook credit as one chain.
  const correlationId = crypto.randomUUID();
  console.info('[billing] auto-recharge attempt', { correlationId, orgId, amountCents: billing.auto_recharge_amount_cents });

  try {
    const recipients = await resolveBillingRecipients(orgId).catch(() => [] as string[]);
    const fallbackEmail = recipients[0];

    const result = await createTopUpInvoice({
      orgId,
      amountCents: billing.auto_recharge_amount_cents,
      purpose: 'auto_recharge_topup',
      fallbackEmail,
      correlationId,
    });

    if (result.status === 'succeeded') {
      // payment_intent.succeeded webhook will credit balance + clear in_progress flag.
      console.info('[billing] auto-recharge pi_created', { correlationId, orgId, paymentIntentId: result.paymentIntentId });
      return { attempted: true, reason: 'pi_created', paymentIntentId: result.paymentIntentId ?? undefined };
    }

    // Off-session failure modes. For off-session 3DS-required cards Stripe does NOT fire
    // payment_intent.payment_failed — it fires invoice.payment_failed instead. So we can't
    // rely on the webhook to disable + email; do it inline for every non-success status.
    console.warn('[billing] auto-recharge non-success', {
      correlationId,
      orgId,
      status: result.status,
    });
    await clearStuckFlag(orgId);

    // Void the open invoice so Stripe's Smart Retries don't keep charging a card we've just
    // disabled auto-recharge on. needs_setup returns no invoice id; skip the void there.
    if (result.invoiceId) {
      await voidOpenInvoice(result.invoiceId);
    }

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
      console.error('[billing] sendAutoRechargeFailed failed', { correlationId, err }),
    );

    return { attempted: true, reason: 'pi_failed' };
  } catch (err) {
    console.error('[billing] auto-recharge createTopUpInvoice threw', { correlationId, orgId, err });
    await clearStuckFlag(orgId);
    await supabase
      .from('organization_billing')
      .update({ auto_recharge_enabled: false })
      .eq('organization_id', orgId);
    await sendAutoRechargeFailed(orgId, err instanceof Error ? err.message : 'unknown').catch(() => {});
    return { attempted: true, reason: 'pi_failed' };
  }
}
