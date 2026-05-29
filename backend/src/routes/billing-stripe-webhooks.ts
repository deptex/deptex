import express from 'express';
import { supabase } from '../lib/supabase';
import { sendAutoRechargeFailed, checkAndDispatchBalanceAlerts } from '../lib/billing/alerts';
import { isBillingEnforcementEnabled } from '../lib/billing/enforcement';

const router = express.Router();

router.post('/', async (req, res) => {
  try {
    const signature = req.headers['stripe-signature'] as string | undefined;
    if (!signature) return res.status(400).json({ error: 'Missing stripe-signature header' });

    // Stripe signs raw request bytes — prefer the Buffer (byte-exact) over the UTF-8
    // string fallback. The fallback only fires if a future middleware reorder strips
    // rawBodyBuffer, in which case we still attempt verification but log the drift.
    const rawBodyBuffer = (req as any).rawBodyBuffer as Buffer | undefined;
    const rawBodyString = (req as any).rawBody as string | undefined;
    const rawBody: Buffer | undefined = rawBodyBuffer
      ? rawBodyBuffer
      : typeof rawBodyString === 'string'
        ? Buffer.from(rawBodyString, 'utf8')
        : undefined;
    if (!rawBody) return res.status(400).json({ error: 'Missing raw body' });
    if (!rawBodyBuffer) {
      console.warn('[billing-webhook] rawBodyBuffer missing — falling back to utf8 round-trip');
    }

    let stripeLib: typeof import('../lib/billing/stripe-billing');
    try {
      stripeLib = require('../lib/billing/stripe-billing');
    } catch {
      return res.status(503).json({ error: 'Billing module not available' });
    }

    let event: any;
    try {
      event = stripeLib.constructWebhookEvent(rawBody, signature);
    } catch (err: any) {
      console.error('[billing-webhook] signature verify failed', err?.message);
      return res.status(400).json({ error: 'Invalid signature' });
    }

    // INSERT-first dedup. Replaces the prior check-then-insert which had a TOCTOU
    // window: two concurrent Stripe retries could both pass isEventProcessed before
    // either reached markEventProcessed, running the handler twice. The unique
    // constraint on event_id makes this atomic — exactly one replica claims, the
    // other returns the already_processed response without running the handler.
    const { claimed } = await stripeLib.claimWebhookEvent(event.id, event.type);
    if (!claimed) {
      return res.json({ received: true, status: 'already_processed' });
    }

    try {
      switch (event.type) {
        case 'payment_intent.succeeded':
          await handlePaymentIntentSucceeded(event.data.object);
          break;
        case 'payment_intent.payment_failed':
          await handlePaymentIntentFailed(event.data.object);
          break;
        case 'invoice.payment_failed':
        case 'invoice.payment_action_required':
          await handleInvoicePaymentFailed(event.data.object);
          break;
        case 'payment_method.detached':
          await handlePaymentMethodDetached(event.data.object);
          break;
        case 'customer.deleted':
          await handleCustomerDeleted(event.data.object);
          break;
        default:
          // Reduced from console.log to debug-level via no-op — high-volume default at scale.
          break;
      }
      res.json({ received: true });
    } catch (handlerErr: any) {
      // Handlers throw ONLY on retryable failures (a DB write that must land). The event is
      // already claimed, so a Stripe retry would no-op unless we release the claim first —
      // release it and return 500 to ask Stripe to retry. Re-running is safe: credits are
      // idempotent (uq on stripe_payment_intent_id) and the per-row updates are idempotent.
      // Terminal conditions (missing metadata, unknown purpose, cross-tenant mismatch) `return`
      // inside the handlers rather than throwing, so they don't reach here and aren't retried.
      console.error('[billing-webhook] handler threw after claim — releasing claim for retry', {
        event_id: event.id,
        event_type: event.type,
        err: handlerErr?.message ?? handlerErr,
      });
      try {
        await stripeLib.releaseWebhookEvent(event.id);
      } catch (relErr) {
        console.error('[billing-webhook] releaseWebhookEvent failed', { event_id: event.id, err: relErr });
      }
      res.status(500).json({ error: 'handler_failed_retry' });
    }
  } catch (err: any) {
    console.error('[billing-webhook] error', err?.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Clears the auto-recharge in-progress lock. Throws on DB error so the webhook router can
// release the claim and let Stripe retry — a stuck flag would otherwise block the org's next
// auto-recharge until the 60-minute stuck-flag recovery kicks in.
async function clearAutoRechargeInProgress(orgId: string): Promise<void> {
  const { error } = await supabase
    .from('organization_billing')
    .update({ auto_recharge_in_progress: false, auto_recharge_in_progress_started_at: null })
    .eq('organization_id', orgId);
  if (error) {
    console.error('[billing-webhook] failed to clear auto_recharge_in_progress', { org_id: orgId, err: error });
    throw new Error(`clear auto_recharge_in_progress failed for ${orgId}: ${error.message}`);
  }
}

export async function handlePaymentIntentSucceeded(pi: any): Promise<void> {
  const metadata = pi.metadata || {};
  let orgId: string | undefined = metadata.organization_id;
  let purpose: string | undefined = metadata.purpose;

  // Fallback: if metadata was wiped (race with Stripe's auto-charge during invoice finalize),
  // pull it from the invoice this PI is attached to.
  if ((!orgId || !purpose) && pi.invoice) {
    try {
      const stripeLib = require('../lib/billing/stripe-billing') as typeof import('../lib/billing/stripe-billing');
      const invMeta = await stripeLib.getInvoiceMetadata(pi.invoice);
      orgId = orgId ?? invMeta?.organization_id;
      purpose = purpose ?? invMeta?.purpose;
    } catch (err) {
      console.warn('[billing-webhook] invoice metadata fallback failed', err);
    }
  }

  if (!orgId || !purpose) {
    console.error('[billing-webhook] missing metadata.organization_id or purpose', {
      pi_id: pi.id,
      metadata,
      invoice: pi.invoice,
    });
    return;
  }
  if (purpose !== 'topup' && purpose !== 'auto_recharge_topup') {
    console.error('[billing-webhook] unknown metadata.purpose', { pi_id: pi.id, purpose });
    return;
  }

  // Kill switch: when DEPTEX_BILLING_ENFORCEMENT is off we must not credit balances (an
  // in-flight webhook during an ops "billing off" window would otherwise credit the org).
  // Skip the credit — but still clear the in_progress flag for an auto-recharge PI so the
  // org isn't wedged once enforcement is turned back on.
  if (!isBillingEnforcementEnabled()) {
    console.warn('[billing-webhook] enforcement off — skipping credit', { pi_id: pi.id, amount: pi.amount, org_id: orgId });
    if (purpose === 'auto_recharge_topup') {
      await clearAutoRechargeInProgress(orgId);
    }
    return;
  }

  if (pi.customer) {
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('organization_id')
      .eq('stripe_customer_id', pi.customer)
      .single();
    if (billing && billing.organization_id !== orgId) {
      console.error('[billing-webhook] cross-tenant PI/Customer mismatch', {
        pi_id: pi.id,
        metadata_org_id: orgId,
        customer_owner_org_id: billing.organization_id,
      });
      return;
    }
  }

  const amountCents: number = pi.amount;
  const description =
    purpose === 'topup' ? `Top up — $${(amountCents / 100).toFixed(2)}` : `Auto-recharge — $${(amountCents / 100).toFixed(2)}`;

  const { error: rpcErr } = await supabase.rpc('credit_balance', {
    p_organization_id: orgId,
    p_amount_cents: amountCents,
    p_kind: purpose,
    p_description: description,
    p_stripe_payment_intent_id: pi.id,
    p_created_by_user_id: null,
  });

  const correlationId = metadata.correlation_id;
  if (rpcErr) {
    if (rpcErr.code === '23505') {
      console.log('[billing] webhook duplicate credit prevented by uq_billing_transactions_pi_credit', {
        correlationId,
        pi_id: pi.id,
      });
    } else {
      // Retryable: throw so the router releases the claim and Stripe retries. The credit is
      // idempotent (uq_billing_transactions_pi_credit on stripe_payment_intent_id), so a
      // re-run can't double-credit — far safer than silently losing the credit forever.
      console.error('[billing] webhook credit_balance failed — releasing claim for retry', {
        correlationId,
        pi_id: pi.id,
        org_id: orgId,
        amount_cents: amountCents,
        err: rpcErr,
      });
      throw new Error(`credit_balance failed for pi ${pi.id}: ${rpcErr.message ?? rpcErr.code}`);
    }
  } else {
    console.info('[billing] webhook credited', {
      correlationId,
      pi_id: pi.id,
      org_id: orgId,
      amount_cents: amountCents,
      purpose,
    });
  }

  if (purpose === 'auto_recharge_topup') {
    await clearAutoRechargeInProgress(orgId);
  }

  // After a successful credit the balance may have crossed back above the alert threshold.
  // Fire the alert dispatcher so future drops re-trigger alerts (the deduction path was the
  // only place this ran before — credits could silently leave alert flags stuck).
  try {
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('balance_cents')
      .eq('organization_id', orgId)
      .single();
    if (billing) {
      await checkAndDispatchBalanceAlerts(orgId, billing.balance_cents);
    }
  } catch (err) {
    console.error('[billing-webhook] post-credit alert dispatch failed', { org_id: orgId, err });
  }

  // Receipt email is sent by Stripe's hosted-invoice email (we enabled invoice_creation).
}

export async function handlePaymentIntentFailed(pi: any): Promise<void> {
  const metadata = pi.metadata || {};
  const orgId: string | undefined = metadata.organization_id;
  const purpose: string | undefined = metadata.purpose;
  if (!orgId) return;

  if (purpose === 'auto_recharge_topup') {
    await supabase
      .from('organization_billing')
      .update({
        auto_recharge_enabled: false,
        auto_recharge_in_progress: false,
        auto_recharge_in_progress_started_at: null,
      })
      .eq('organization_id', orgId);

    const reason: string = pi.last_payment_error?.message || pi.last_payment_error?.code || 'unknown';
    await sendAutoRechargeFailed(orgId, reason).catch((err) =>
      console.error('[billing-webhook] auto-recharge failed alert failed', err),
    );
  }
}

export async function handleInvoicePaymentFailed(invoice: any): Promise<void> {
  // For off-session auto-recharge of a 3DS-required card, Stripe fires invoice.payment_failed
  // (not payment_intent.payment_failed), so the PI-failure handler never runs. We treat any
  // failure on an auto_recharge_topup invoice as a hard auto-recharge failure: disable, clear
  // the in-progress flag, void the invoice to stop Smart Retries, and notify the org.
  const metadata = invoice.metadata || {};
  const orgId: string | undefined = metadata.organization_id;
  const purpose: string | undefined = metadata.purpose;
  if (!orgId || purpose !== 'auto_recharge_topup') return;

  // Cross-tenant guard mirroring handlePaymentIntentSucceeded — if invoice.customer's
  // owner-org disagrees with the metadata-claimed org, reject. Defense-in-depth against
  // stale or spoofed metadata.
  if (invoice.customer) {
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('organization_id')
      .eq('stripe_customer_id', invoice.customer)
      .single();
    if (billing && billing.organization_id !== orgId) {
      console.error('[billing-webhook] cross-tenant invoice/customer mismatch', {
        invoice_id: invoice.id,
        metadata_org_id: orgId,
        customer_owner_org_id: billing.organization_id,
      });
      return;
    }
  }

  const { error: updErr } = await supabase
    .from('organization_billing')
    .update({
      auto_recharge_enabled: false,
      auto_recharge_in_progress: false,
      auto_recharge_in_progress_started_at: null,
    })
    .eq('organization_id', orgId);
  if (updErr) {
    console.error('[billing-webhook] failed to disable auto_recharge after invoice failure — releasing for retry', {
      org_id: orgId,
      err: updErr,
    });
    throw new Error(`disable auto_recharge after invoice failure failed for ${orgId}: ${updErr.message}`);
  }

  if (invoice.id) {
    try {
      const stripeLib = require('../lib/billing/stripe-billing') as typeof import('../lib/billing/stripe-billing');
      await stripeLib.voidOpenInvoice(invoice.id);
    } catch (err) {
      console.warn('[billing-webhook] voidOpenInvoice from invoice.payment_failed failed', err);
    }
  }

  const last = invoice.last_finalization_error || invoice.last_payment_error;
  const reason: string = last?.message || last?.code || 'Payment attempt failed';
  await sendAutoRechargeFailed(orgId, reason).catch((err) =>
    console.error('[billing-webhook] sendAutoRechargeFailed (invoice path) failed', err),
  );
}

export async function handlePaymentMethodDetached(pm: any): Promise<void> {
  const { data: billing, error: lookupErr } = await supabase
    .from('organization_billing')
    .select('organization_id')
    .eq('stripe_default_payment_method_id', pm.id)
    .maybeSingle();
  if (lookupErr) {
    console.error('[billing-webhook] PM detach lookup failed', { pm_id: pm.id, err: lookupErr });
    return;
  }
  if (!billing) return;

  const { error: updErr } = await supabase
    .from('organization_billing')
    .update({
      stripe_default_payment_method_id: null,
      auto_recharge_enabled: false,
    })
    .eq('organization_id', billing.organization_id);
  if (updErr) {
    console.error('[billing-webhook] PM detach update failed — releasing for retry', {
      org_id: billing.organization_id,
      err: updErr,
    });
    throw new Error(`PM detach update failed for ${billing.organization_id}: ${updErr.message}`);
  }
}

// Stripe customer was deleted in the Stripe Dashboard (rare, but if it happens we must
// stop pointing at a ghost customer — subsequent off-session charges would fail anyway).
export async function handleCustomerDeleted(customer: any): Promise<void> {
  if (!customer?.id) return;
  const { error } = await supabase
    .from('organization_billing')
    .update({
      stripe_customer_id: null,
      stripe_default_payment_method_id: null,
      auto_recharge_enabled: false,
      auto_recharge_in_progress: false,
      auto_recharge_in_progress_started_at: null,
    })
    .eq('stripe_customer_id', customer.id);
  if (error) {
    console.error('[billing-webhook] customer.deleted cleanup failed', {
      customer_id: customer.id,
      err: error,
    });
  }
}

export default router;
