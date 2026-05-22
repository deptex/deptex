import Stripe from 'stripe';
import { supabase } from '../supabase';
import { setStripePaymentMethodFetcher } from './ledger';
import type { BillingPaymentMethod, PaymentIntentPurpose } from './types';

let stripeClient: Stripe | null = null;

function getStripe(): Stripe {
  if (!stripeClient) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error('STRIPE_SECRET_KEY is not configured');
    stripeClient = new Stripe(key);
  }
  return stripeClient;
}

export function constructWebhookEvent(rawBody: Buffer, signature: string): Stripe.Event {
  const stripe = getStripe();
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw new Error('STRIPE_WEBHOOK_SECRET is not configured');
  return stripe.webhooks.constructEvent(rawBody, signature, secret);
}

export async function isEventProcessed(eventId: string): Promise<boolean> {
  const { data } = await supabase
    .from('billing_stripe_webhook_events')
    .select('event_id')
    .eq('event_id', eventId)
    .maybeSingle();
  return !!data;
}

export async function markEventProcessed(eventId: string, eventType: string): Promise<boolean> {
  const { error } = await supabase
    .from('billing_stripe_webhook_events')
    .insert({ event_id: eventId, event_type: eventType });
  return !error;
}

export async function ensureStripeCustomer(orgId: string): Promise<string> {
  const { data: billing, error } = await supabase
    .from('organization_billing')
    .select('stripe_customer_id')
    .eq('organization_id', orgId)
    .single();
  if (error || !billing) {
    throw new Error(`ensureStripeCustomer: organization_billing not found for ${orgId}`);
  }
  if (billing.stripe_customer_id) return billing.stripe_customer_id;

  const { data: org } = await supabase
    .from('organizations')
    .select('id, name')
    .eq('id', orgId)
    .single();

  const customer = await getStripe().customers.create({
    name: org?.name ?? `org_${orgId}`,
    metadata: { organization_id: orgId },
  });

  const { error: updateErr } = await supabase
    .from('organization_billing')
    .update({ stripe_customer_id: customer.id })
    .eq('organization_id', orgId);
  if (updateErr) {
    console.error('[stripe-billing] failed to persist customer id', updateErr);
  }
  return customer.id;
}

export interface CreatePaymentIntentInput {
  orgId: string;
  amountCents: number;
  purpose: PaymentIntentPurpose;
  offSession?: boolean;
  setupFutureUsage?: 'off_session';
  paymentMethodId?: string;
}

export interface CreatePaymentIntentResult {
  paymentIntent: Stripe.PaymentIntent;
  customerId: string;
}

export async function createPaymentIntent(
  input: CreatePaymentIntentInput,
): Promise<CreatePaymentIntentResult> {
  const customerId = await ensureStripeCustomer(input.orgId);
  const stripe = getStripe();

  const params: Stripe.PaymentIntentCreateParams = {
    amount: input.amountCents,
    currency: 'usd',
    customer: customerId,
    metadata: {
      organization_id: input.orgId,
      purpose: input.purpose,
    },
  };
  if (input.offSession) {
    params.off_session = true;
    params.confirm = true;
    if (input.paymentMethodId) params.payment_method = input.paymentMethodId;
  } else if (input.setupFutureUsage) {
    params.setup_future_usage = input.setupFutureUsage;
  }

  const paymentIntent = await stripe.paymentIntents.create(params);
  return { paymentIntent, customerId };
}

export async function detachPaymentMethod(orgId: string): Promise<void> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('stripe_default_payment_method_id')
    .eq('organization_id', orgId)
    .single();

  const pmId = billing?.stripe_default_payment_method_id;
  if (pmId) {
    try {
      await getStripe().paymentMethods.detach(pmId);
    } catch (err) {
      console.warn('[stripe-billing] detach failed (possibly already detached)', err);
    }
  }

  const { error } = await supabase
    .from('organization_billing')
    .update({
      stripe_default_payment_method_id: null,
      auto_recharge_enabled: false,
    })
    .eq('organization_id', orgId);
  if (error) {
    console.error('[stripe-billing] failed to clear payment method', error);
  }
}

export async function getPaymentMethod(orgId: string): Promise<BillingPaymentMethod | null> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('stripe_customer_id, stripe_default_payment_method_id')
    .eq('organization_id', orgId)
    .single();
  if (!billing?.stripe_customer_id || !billing?.stripe_default_payment_method_id) return null;

  return fetchPaymentMethodFromStripe(
    billing.stripe_customer_id,
    billing.stripe_default_payment_method_id,
  );
}

async function fetchPaymentMethodFromStripe(
  _customerId: string,
  paymentMethodId: string,
): Promise<BillingPaymentMethod | null> {
  try {
    const pm = await getStripe().paymentMethods.retrieve(paymentMethodId);
    if (!pm.card) return null;
    return {
      brand: pm.card.brand,
      last4: pm.card.last4,
      expiresMonth: pm.card.exp_month,
      expiresYear: pm.card.exp_year,
    };
  } catch (err) {
    console.error('[stripe-billing] payment method retrieve failed', err);
    return null;
  }
}

// Register the lazy fetcher so getBalance() can resolve card metadata
// without a circular module dependency from ledger -> stripe-billing.
setStripePaymentMethodFetcher(fetchPaymentMethodFromStripe);

export async function setDefaultPaymentMethod(
  orgId: string,
  paymentMethodId: string,
): Promise<void> {
  const customerId = await ensureStripeCustomer(orgId);
  await getStripe().paymentMethods.attach(paymentMethodId, { customer: customerId });
  await getStripe().customers.update(customerId, {
    invoice_settings: { default_payment_method: paymentMethodId },
  });

  const { error } = await supabase
    .from('organization_billing')
    .update({ stripe_default_payment_method_id: paymentMethodId })
    .eq('organization_id', orgId);
  if (error) {
    console.error('[stripe-billing] failed to persist default PM', error);
  }
}

export function __resetStripeClientForTesting(): void {
  stripeClient = null;
}

export function __injectStripeClientForTesting(client: Stripe | null): void {
  stripeClient = client;
}
