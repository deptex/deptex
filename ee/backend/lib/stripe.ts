import Stripe from 'stripe';
import { supabase } from '../../../backend/src/lib/supabase';
import { PLAN_LIMITS, PlanTier, invalidatePlanCache, TIER_DISPLAY_NAMES } from './plan-limits';
import { createActivity } from './activities';

// ─── Lazy Stripe Client ───

let stripeClient: Stripe | null = null;

function getStripe(): Stripe {
  if (!stripeClient) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error('STRIPE_SECRET_KEY is not configured');
    stripeClient = new Stripe(key, { apiVersion: '2025-02-24.acacia' });
  }
  return stripeClient;
}

// ─── Price ID Config ───

interface PriceConfig {
  monthly: string;
  annual: string;
}

function getPriceIds(): Record<string, PriceConfig> {
  return {
    pro: {
      monthly: process.env.STRIPE_PRO_MONTHLY_PRICE_ID || '',
      annual: process.env.STRIPE_PRO_ANNUAL_PRICE_ID || '',
    },
    team: {
      monthly: process.env.STRIPE_TEAM_MONTHLY_PRICE_ID || '',
      annual: process.env.STRIPE_TEAM_ANNUAL_PRICE_ID || '',
    },
  };
}

// ─── Tier from Price ID ───

function tierFromPriceId(priceId: string): PlanTier {
  const prices = getPriceIds();
  if (priceId === prices.pro.monthly || priceId === prices.pro.annual) return 'pro';
  if (priceId === prices.team.monthly || priceId === prices.team.annual) return 'team';
  return 'free';
}

function cycleFromPriceId(priceId: string): 'monthly' | 'annual' {
  const prices = getPriceIds();
  if (priceId === prices.pro.annual || priceId === prices.team.annual) return 'annual';
  return 'monthly';
}

// ─── Checkout Session ───

export async function createCheckoutSession(
  orgId: string,
  priceId: string,
  successUrl: string,
  cancelUrl: string,
  billingEmail?: string,
): Promise<string> {
  const stripe = getStripe();

  const { data: plan } = await supabase
    .from('organization_plans')
    .select('stripe_customer_id, billing_email')
    .eq('organization_id', orgId)
    .single();

  let customerId = plan?.stripe_customer_id;

  if (!customerId) {
    const customer = await stripe.customers.create({
      email: billingEmail || plan?.billing_email || undefined,
      metadata: { organization_id: orgId },
    });
    customerId = customer.id;
    await supabase
      .from('organization_plans')
      .update({ stripe_customer_id: customerId, updated_at: new Date().toISOString() })
      .eq('organization_id', orgId);
  }

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    mode: 'subscription',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: successUrl,
    cancel_url: cancelUrl,
    subscription_data: {
      metadata: { organization_id: orgId },
    },
    allow_promotion_codes: true,
    metadata: { organization_id: orgId },
  });

  return session.url || '';
}

// ─── Customer Portal Session ───

export async function createPortalSession(orgId: string, returnUrl: string): Promise<string> {
  const stripe = getStripe();

  const { data: plan } = await supabase
    .from('organization_plans')
    .select('stripe_customer_id')
    .eq('organization_id', orgId)
    .single();

  if (!plan?.stripe_customer_id) {
    throw new Error('No Stripe customer found for this organization');
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: plan.stripe_customer_id,
    return_url: returnUrl,
  });

  return session.url;
}

// ─── List Invoices ───

export async function getInvoices(orgId: string, limit = 10, startingAfter?: string) {
  const stripe = getStripe();

  const { data: plan } = await supabase
    .from('organization_plans')
    .select('stripe_customer_id')
    .eq('organization_id', orgId)
    .single();

  if (!plan?.stripe_customer_id) return { invoices: [], has_more: false };

  const params: Stripe.InvoiceListParams = {
    customer: plan.stripe_customer_id,
    limit,
  };
  if (startingAfter) params.starting_after = startingAfter;

  const result = await stripe.invoices.list(params);

  return {
    invoices: result.data.map((inv: Stripe.Invoice) => ({
      id: inv.id,
      number: inv.number,
      amount_due: inv.amount_due,
      amount_paid: inv.amount_paid,
      currency: inv.currency,
      status: inv.status,
      created: inv.created,
      period_start: inv.period_start,
      period_end: inv.period_end,
      invoice_pdf: inv.invoice_pdf,
      hosted_invoice_url: inv.hosted_invoice_url,
    })),
    has_more: result.has_more,
  };
}

// ─── Webhook Event Handlers ───

export async function handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
  const orgId = session.metadata?.organization_id;
  if (!orgId) return;

  const subscriptionId = typeof session.subscription === 'string'
    ? session.subscription
    : session.subscription?.id;

  if (!subscriptionId) return;

  const stripe = getStripe();
  const subscription = await stripe.subscriptions.retrieve(subscriptionId);
  const priceId = subscription.items.data[0]?.price.id || '';
  const tier = tierFromPriceId(priceId);
  const cycle = cycleFromPriceId(priceId);

  await supabase
    .from('organization_plans')
    .update({
      plan_tier: tier,
      subscription_status: 'active',
      stripe_subscription_id: subscriptionId,
      stripe_price_id: priceId,
      stripe_customer_id: typeof session.customer === 'string' ? session.customer : session.customer?.id,
      billing_email: session.customer_email || undefined,
      billing_cycle: cycle,
      current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
      current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
      syncs_used: 0,
      syncs_reset_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', orgId);

  invalidatePlanCache(orgId);

  await createActivity({
    organization_id: orgId,
    activity_type: 'plan_upgraded',
    description: `Organization upgraded to ${TIER_DISPLAY_NAMES[tier]} plan (${cycle})`,
    metadata: { plan_tier: tier, billing_cycle: cycle },
  });
}

export async function handleSubscriptionUpdated(subscription: Stripe.Subscription): Promise<void> {
  const orgId = subscription.metadata?.organization_id;
  if (!orgId) return;

  const priceId = subscription.items.data[0]?.price.id || '';
  const tier = tierFromPriceId(priceId);
  const cycle = cycleFromPriceId(priceId);

  const paymentMethod = subscription.default_payment_method;
  let brand: string | undefined;
  let last4: string | undefined;

  if (typeof paymentMethod === 'object' && paymentMethod?.type === 'card') {
    brand = paymentMethod.card?.brand || undefined;
    last4 = paymentMethod.card?.last4 || undefined;
  }

  const update: Record<string, any> = {
    plan_tier: tier,
    subscription_status: subscription.status,
    stripe_price_id: priceId,
    billing_cycle: cycle,
    current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
    cancel_at_period_end: subscription.cancel_at_period_end,
    cancel_at: subscription.cancel_at ? new Date(subscription.cancel_at * 1000).toISOString() : null,
    updated_at: new Date().toISOString(),
  };

  if (brand) update.payment_method_brand = brand;
  if (last4) update.payment_method_last4 = last4;

  await supabase.from('organization_plans').update(update).eq('organization_id', orgId);
  invalidatePlanCache(orgId);
}

export async function handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
  const orgId = subscription.metadata?.organization_id;
  if (!orgId) return;

  await supabase
    .from('organization_plans')
    .update({
      plan_tier: 'free',
      subscription_status: 'cancelled',
      stripe_subscription_id: null,
      stripe_price_id: null,
      cancel_at_period_end: false,
      cancel_at: null,
      syncs_used: 0,
      updated_at: new Date().toISOString(),
    })
    .eq('organization_id', orgId);

  invalidatePlanCache(orgId);

  await createActivity({
    organization_id: orgId,
    activity_type: 'plan_downgraded',
    description: 'Organization plan cancelled, reverted to Free tier',
    metadata: { plan_tier: 'free' },
  });
}

export async function handlePaymentSucceeded(invoice: Stripe.Invoice): Promise<void> {
  const customerId = typeof invoice.customer === 'string' ? invoice.customer : invoice.customer?.id;
  if (!customerId) return;

  const { data: plan } = await supabase
    .from('organization_plans')
    .select('organization_id, subscription_status')
    .eq('stripe_customer_id', customerId)
    .single();

  if (!plan) return;

  if (plan.subscription_status === 'past_due') {
    await supabase
      .from('organization_plans')
      .update({ subscription_status: 'active', updated_at: new Date().toISOString() })
      .eq('organization_id', plan.organization_id);
    invalidatePlanCache(plan.organization_id);
  }

  await createActivity({
    organization_id: plan.organization_id,
    activity_type: 'payment_succeeded',
    description: `Payment of $${((invoice.amount_paid || 0) / 100).toFixed(2)} succeeded`,
    metadata: { amount_cents: invoice.amount_paid, invoice_id: invoice.id },
  });
}

export async function handlePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
  const customerId = typeof invoice.customer === 'string' ? invoice.customer : invoice.customer?.id;
  if (!customerId) return;

  const { data: plan } = await supabase
    .from('organization_plans')
    .select('organization_id')
    .eq('stripe_customer_id', customerId)
    .single();

  if (!plan) return;

  await supabase
    .from('organization_plans')
    .update({ subscription_status: 'past_due', updated_at: new Date().toISOString() })
    .eq('organization_id', plan.organization_id);

  invalidatePlanCache(plan.organization_id);

  await createActivity({
    organization_id: plan.organization_id,
    activity_type: 'payment_failed',
    description: 'Payment failed. Please update your payment method.',
    metadata: { invoice_id: invoice.id },
  });
}

// ─── Sync Counter Reset ───

export async function resetDueSyncCounters(): Promise<number> {
  const now = new Date().toISOString();

  const { data: dueOrgs, error } = await supabase
    .from('organization_plans')
    .select('organization_id')
    .lt('current_period_end', now)
    .neq('plan_tier', 'free')
    .gt('syncs_used', 0);

  if (error || !dueOrgs?.length) return 0;

  for (const org of dueOrgs) {
    await supabase
      .from('organization_plans')
      .update({ syncs_used: 0, syncs_reset_at: now, updated_at: now })
      .eq('organization_id', org.organization_id);
    invalidatePlanCache(org.organization_id);
  }

  // Free tier: reset monthly based on syncs_reset_at (no Stripe period)
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const { data: freeOrgs } = await supabase
    .from('organization_plans')
    .select('organization_id')
    .eq('plan_tier', 'free')
    .lt('syncs_reset_at', thirtyDaysAgo)
    .gt('syncs_used', 0);

  if (freeOrgs?.length) {
    for (const org of freeOrgs) {
      await supabase
        .from('organization_plans')
        .update({ syncs_used: 0, syncs_reset_at: now, updated_at: now })
        .eq('organization_id', org.organization_id);
      invalidatePlanCache(org.organization_id);
    }
  }

  return (dueOrgs?.length || 0) + (freeOrgs?.length || 0);
}

// ─── Webhook Signature Verification ───

export function constructWebhookEvent(rawBody: Buffer, signature: string): Stripe.Event {
  const stripe = getStripe();
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw new Error('STRIPE_WEBHOOK_SECRET is not configured');
  return stripe.webhooks.constructEvent(rawBody, signature, secret);
}

// ─── Webhook Idempotency ───

export async function isEventProcessed(eventId: string): Promise<boolean> {
  const { data } = await supabase
    .from('stripe_webhook_events')
    .select('id')
    .eq('event_id', eventId)
    .maybeSingle();
  return !!data;
}

export async function markEventProcessed(eventId: string, eventType: string): Promise<boolean> {
  const { error } = await supabase
    .from('stripe_webhook_events')
    .insert({ event_id: eventId, event_type: eventType });
  return !error;
}
