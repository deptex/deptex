import express from 'express';
import { supabase } from '../lib/supabase';
import { sendAutoRechargeFailed } from '../lib/billing/alerts';

const router = express.Router();

router.post('/', async (req, res) => {
  try {
    const signature = req.headers['stripe-signature'] as string | undefined;
    if (!signature) return res.status(400).json({ error: 'Missing stripe-signature header' });

    const rawBody = (req as any).rawBody;
    if (!rawBody) return res.status(400).json({ error: 'Missing raw body' });

    let stripeLib: typeof import('../lib/billing/stripe-billing');
    try {
      stripeLib = require('../lib/billing/stripe-billing');
    } catch {
      return res.status(503).json({ error: 'Billing module not available' });
    }

    let event: any;
    try {
      event = stripeLib.constructWebhookEvent(Buffer.from(rawBody), signature);
    } catch (err: any) {
      console.error('[billing-webhook] signature verify failed', err?.message);
      return res.status(400).json({ error: 'Invalid signature' });
    }

    const alreadyProcessed = await stripeLib.isEventProcessed(event.id);
    if (alreadyProcessed) {
      return res.json({ received: true, status: 'already_processed' });
    }

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
      default:
        console.log(`[billing-webhook] unhandled type: ${event.type}`);
    }

    await stripeLib.markEventProcessed(event.id, event.type);
    res.json({ received: true });
  } catch (err: any) {
    console.error('[billing-webhook] error', err?.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

async function handlePaymentIntentSucceeded(pi: any): Promise<void> {
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

  if (rpcErr) {
    if (rpcErr.code === '23505') {
      console.log('[billing-webhook] duplicate credit prevented by uq_billing_transactions_pi_credit', { pi_id: pi.id });
    } else {
      console.error('[billing-webhook] credit_balance failed', rpcErr);
      throw new Error(`credit_balance failed: ${rpcErr.message}`);
    }
  }

  if (purpose === 'auto_recharge_topup') {
    await supabase
      .from('organization_billing')
      .update({
        auto_recharge_in_progress: false,
        auto_recharge_in_progress_started_at: null,
      })
      .eq('organization_id', orgId);
  }

  // Receipt email is sent by Stripe's hosted-invoice email (we enabled invoice_creation).
}

async function handlePaymentIntentFailed(pi: any): Promise<void> {
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

async function handleInvoicePaymentFailed(invoice: any): Promise<void> {
  // For off-session auto-recharge of a 3DS-required card, Stripe fires invoice.payment_failed
  // (not payment_intent.payment_failed), so the PI-failure handler never runs. We treat any
  // failure on an auto_recharge_topup invoice as a hard auto-recharge failure: disable, clear
  // the in-progress flag, and notify the org's billing recipients.
  const metadata = invoice.metadata || {};
  const orgId: string | undefined = metadata.organization_id;
  const purpose: string | undefined = metadata.purpose;
  if (!orgId || purpose !== 'auto_recharge_topup') return;

  await supabase
    .from('organization_billing')
    .update({
      auto_recharge_enabled: false,
      auto_recharge_in_progress: false,
      auto_recharge_in_progress_started_at: null,
    })
    .eq('organization_id', orgId);

  const last = invoice.last_finalization_error || invoice.last_payment_error;
  const reason: string = last?.message || last?.code || 'Payment attempt failed';
  await sendAutoRechargeFailed(orgId, reason).catch((err) =>
    console.error('[billing-webhook] sendAutoRechargeFailed (invoice path) failed', err),
  );
}

async function handlePaymentMethodDetached(pm: any): Promise<void> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('organization_id')
    .eq('stripe_default_payment_method_id', pm.id)
    .single();
  if (!billing) return;

  await supabase
    .from('organization_billing')
    .update({
      stripe_default_payment_method_id: null,
      auto_recharge_enabled: false,
    })
    .eq('organization_id', billing.organization_id);
}

export default router;
