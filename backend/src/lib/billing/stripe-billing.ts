import Stripe from 'stripe';
import { supabase } from '../supabase';
import { setStripePaymentMethodFetcher } from './ledger';
import type { BillingPaymentMethod, PaymentIntentPurpose } from './types';
import { captureBillingError } from '../observability/capture';

let stripeClient: Stripe | null = null;

function getStripe(): Stripe {
  if (!stripeClient) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) throw new Error('STRIPE_SECRET_KEY is not configured');
    // Pin to the account's current API version so the default can't drift under us. This MUST
    // be a version the Stripe account actually accepts — a string the account doesn't recognize
    // 400s EVERY request ("Invalid Stripe API version"). 2026-04-22.dahlia is the account
    // default and supports the Invoice.payments[].payment.payment_intent schema extractPiId
    // reads. Bumping this is a deliberate decision; verify the new version is accepted first.
    stripeClient = new Stripe(key, { apiVersion: '2026-04-22.dahlia' as Stripe.LatestApiVersion });
  }
  return stripeClient;
}

// True when Stripe reports the referenced object doesn't exist under the active key —
// e.g. a `stripe_customer_id` created in test mode while the live key is configured (or a
// different account / a deleted customer). This is the signal to re-provision rather than
// keep 404ing forever. Deliberately narrow: auth/rate-limit/network errors are NOT this,
// and must surface instead of silently orphaning a real customer.
export function isStripeResourceMissing(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const e = err as { code?: string; type?: string; statusCode?: number };
  return e.code === 'resource_missing' || (e.type === 'StripeInvalidRequestError' && e.statusCode === 404);
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

// Atomic claim — INSERT first; if the row already exists (Postgres 23505) the event was
// already processed (or is being processed by a concurrent replica) and we return false.
// Replaces the check-then-insert pattern which had a TOCTOU window letting two retries
// run handlers in parallel.
export async function claimWebhookEvent(
  eventId: string,
  eventType: string,
): Promise<{ claimed: boolean }> {
  const { error } = await supabase
    .from('billing_stripe_webhook_events')
    .insert({ event_id: eventId, event_type: eventType });
  if (!error) return { claimed: true };
  // 23505 = unique_violation. Anything else (DB down, etc.) we treat as not-claimed so
  // the webhook handler skips and Stripe retries — better than running the handler twice.
  if ((error as any).code !== '23505') {
    console.error('[stripe-billing] claimWebhookEvent unexpected error', error);
  }
  return { claimed: false };
}

// Undo a claim so a failed handler can be retried by Stripe. Safe because the webhook
// handlers are idempotent; the worst case on a re-run is a duplicate-credit attempt blocked
// by the uq_billing_transactions_pi_credit constraint.
export async function releaseWebhookEvent(eventId: string): Promise<void> {
  const { error } = await supabase
    .from('billing_stripe_webhook_events')
    .delete()
    .eq('event_id', eventId);
  if (error) {
    console.error('[stripe-billing] releaseWebhookEvent failed', { eventId, error });
  }
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

  // Verify a stored customer still exists under the ACTIVE Stripe key before trusting it.
  // A key/account switch (test ⇄ live) leaves a stale id that 404s on every billing call —
  // listing payment methods, top-up, add-card all break with "No such customer". When that
  // happens, clear the dead id (and its dependent default PM) and fall through to provision
  // a fresh customer. Only resource_missing/deleted triggers this; a genuine auth/network
  // error re-throws so we never orphan a real customer over a transient outage.
  if (billing.stripe_customer_id) {
    try {
      const existing = await getStripe().customers.retrieve(billing.stripe_customer_id);
      if (!('deleted' in existing) || !existing.deleted) {
        return billing.stripe_customer_id;
      }
      console.warn('[stripe-billing] stored customer was deleted in Stripe — re-provisioning', {
        orgId,
        staleCustomerId: billing.stripe_customer_id,
      });
    } catch (err) {
      if (!isStripeResourceMissing(err)) throw err;
      console.warn('[stripe-billing] stored customer not found under active key — re-provisioning', {
        orgId,
        staleCustomerId: billing.stripe_customer_id,
      });
    }
    await supabase
      .from('organization_billing')
      .update({ stripe_customer_id: null, stripe_default_payment_method_id: null })
      .eq('organization_id', orgId);
  }

  const { data: org } = await supabase
    .from('organizations')
    .select('id, name')
    .eq('id', orgId)
    .single();

  // Idempotency keyed on org_id — if two ensureStripeCustomer calls race on first-time
  // creation, Stripe returns the same customer for the second call instead of creating a
  // duplicate. The key is stable across retries and is org-scoped (no cross-tenant collision).
  const customer = await getStripe().customers.create(
    {
      name: org?.name ?? `org_${orgId}`,
      metadata: { organization_id: orgId },
    },
    { idempotencyKey: `customer:${orgId}` },
  );

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

  // Per-attempt idempotency key. Bucketed to the minute so a user retrying within the
  // same minute (network hiccup) re-uses the same PI instead of creating a duplicate
  // charge. Different amount or different minute → fresh PI.
  const minuteBucket = Math.floor(Date.now() / 60_000);
  const idempotencyKey = `pi:${input.orgId}:${input.purpose}:${input.amountCents}:${minuteBucket}`;
  const paymentIntent = await stripe.paymentIntents.create(params, { idempotencyKey });
  return { paymentIntent, customerId };
}

export interface StripeBillingAddress {
  line1: string;
  line2?: string | null;
  city: string;
  state?: string | null;
  postal_code: string;
  country: string;
}

export interface CreateTopUpInvoiceInput {
  orgId: string;
  amountCents: number;
  billingEmail?: string;
  billingAddress?: StripeBillingAddress;
  fallbackEmail?: string;
  purpose?: 'topup' | 'auto_recharge_topup';
  // Optional correlation ID stamped on Stripe PI/Invoice metadata so logs from the
  // webhook handler can link back to the originating auto-recharge / top-up attempt.
  correlationId?: string;
}

export type TopUpStatus = 'succeeded' | 'requires_action' | 'requires_payment_method' | 'needs_setup';

export interface CreateTopUpInvoiceResult {
  status: TopUpStatus;
  clientSecret: string | null;
  paymentIntentId: string | null;
  invoiceId: string;
  subtotalCents: number;
  taxCents: number;
  totalCents: number;
}

export async function createTopUpInvoice(input: CreateTopUpInvoiceInput): Promise<CreateTopUpInvoiceResult> {
  const customerId = await ensureStripeCustomer(input.orgId);
  const stripe = getStripe();
  const purpose: 'topup' | 'auto_recharge_topup' = input.purpose ?? 'topup';
  const itemDescription = purpose === 'auto_recharge_topup' ? 'Deptex credit (auto-recharge)' : 'Deptex credit';

  // Sync customer's address + email if provided (only used on first-time flow).
  if (input.billingAddress || input.billingEmail) {
    await stripe.customers.update(customerId, {
      email: input.billingEmail,
      address: input.billingAddress
        ? {
            line1: input.billingAddress.line1,
            line2: input.billingAddress.line2 ?? undefined,
            city: input.billingAddress.city,
            state: input.billingAddress.state ?? undefined,
            postal_code: input.billingAddress.postal_code,
            country: input.billingAddress.country,
          }
        : undefined,
    });
  }

  // Make sure the customer has an email so Stripe can send the hosted invoice receipt.
  const existingCustomer = await stripe.customers.retrieve(customerId);
  if ((!('deleted' in existingCustomer) || !existingCustomer.deleted)) {
    const ec = existingCustomer as Stripe.Customer;
    if (!ec.email && input.fallbackEmail) {
      await stripe.customers.update(customerId, { email: input.fallbackEmail });
    }
  }

  // Need an address on the customer for automatic_tax. If not present, try to recover one from
  // the saved default PM's billing_details before giving up (the Stripe AddressElement attaches
  // address to the PM, not to the Customer, so first-card flows land here without an address).
  let customer = await stripe.customers.retrieve(customerId);
  if (!('deleted' in customer) || !customer.deleted) {
    let c = customer as Stripe.Customer;
    if (!c.address?.line1) {
      const recovered = await syncCustomerAddressFromDefaultPM(input.orgId, customerId);
      if (recovered) {
        customer = await stripe.customers.retrieve(customerId);
        if (!('deleted' in customer) || !customer.deleted) {
          c = customer as Stripe.Customer;
        }
      }
    }
    if (!c.address?.line1) {
      return {
        status: 'needs_setup',
        clientSecret: null,
        paymentIntentId: null,
        invoiceId: '',
        subtotalCents: input.amountCents,
        taxCents: 0,
        totalCents: input.amountCents,
      };
    }
  }

  // Per-attempt idempotency. Same minute + same orgId + same amount + same purpose →
  // Stripe returns the existing invoice item / invoice instead of creating duplicates on
  // network retries. Different minute → fresh attempt (this is intentional: a user clicking
  // "Add credit" 2 minutes apart should get a new invoice, not the stale failed one).
  const minuteBucket = Math.floor(Date.now() / 60_000);
  const idemSuffix = `${input.orgId}:${purpose}:${input.amountCents}:${minuteBucket}`;

  // Create the invoice item first so it's "pending" and attached on invoice creation.
  await stripe.invoiceItems.create(
    {
      customer: customerId,
      amount: input.amountCents,
      currency: 'usd',
      description: itemDescription,
      tax_behavior: 'exclusive',
    },
    { idempotencyKey: `invoiceitem:${idemSuffix}` },
  );

  const invoice = await stripe.invoices.create(
    {
      customer: customerId,
      collection_method: 'charge_automatically',
      automatic_tax: { enabled: true },
      auto_advance: false,
      pending_invoice_items_behavior: 'include',
      metadata: { organization_id: input.orgId, purpose },
    },
    { idempotencyKey: `invoice:${idemSuffix}` },
  );

  if (!invoice.id) {
    throw new Error('Stripe invoice creation returned no id');
  }

  let finalized = await stripe.invoices.finalizeInvoice(
    invoice.id,
    { expand: ['payments'] },
    { idempotencyKey: `finalize:${idemSuffix}` },
  );

  type InvoiceWithPayments = Stripe.Invoice & {
    payments?: { data?: Array<{ payment?: { payment_intent?: string | null } }> };
  };

  const extractPiId = (inv: Stripe.Invoice): string | undefined =>
    ((inv as InvoiceWithPayments).payments?.data ?? [])[0]?.payment?.payment_intent ?? undefined;

  let piId = extractPiId(finalized);
  console.log('[billing] topup finalized', {
    correlationId: input.correlationId,
    invoiceId: finalized.id,
    status: finalized.status,
    piId,
  });

  if (!piId) {
    throw new Error('Finalized invoice has no payment_intent attached');
  }

  const metadataBase: Record<string, string> = {
    organization_id: input.orgId,
    purpose,
    ...(input.correlationId ? { correlation_id: input.correlationId } : {}),
  };

  // Also stamp metadata on the invoice — the webhook handler reads this as a fallback when
  // the PI's own metadata was wiped by Stripe's auto-charge-on-finalize racing us.
  try {
    await stripe.invoices.update(invoice.id, {
      metadata: metadataBase,
    });
  } catch (err) {
    console.warn('[billing] topup invoices.update metadata failed', err);
    captureBillingError(err, 'topup_invoice_metadata_failed', { orgId: input.orgId, extra: { correlationId: input.correlationId } });
  }

  // Stamp PI metadata BEFORE attempting payment so payment_intent.succeeded webhook
  // (if it fires synchronously during pay()) has the org_id + purpose it needs.
  // Also set receipt_email so Stripe sends a PI receipt independent of invoice emails.
  try {
    await stripe.paymentIntents.update(piId, {
      metadata: { ...metadataBase, invoice_id: finalized.id ?? '' },
      receipt_email: input.fallbackEmail ?? input.billingEmail,
    });
  } catch (err) {
    console.warn('[topup] paymentIntents.update metadata pre-pay failed', err);
    captureBillingError(err, 'topup_pi_metadata_failed', { orgId: input.orgId, extra: { correlationId: input.correlationId } });
  }

  // Pay the invoice using the saved default PM (this is the canonical path for invoice PIs;
  // paymentIntents.confirm is not the right call here — invoices have their own pay endpoint).
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('stripe_default_payment_method_id')
    .eq('organization_id', input.orgId)
    .single();
  const defaultPmId = billing?.stripe_default_payment_method_id;
  console.log('[topup] default PM', { defaultPmId });

  if (defaultPmId && (finalized.status === 'open' || finalized.status === 'draft')) {
    try {
      finalized = await stripe.invoices.pay(
        invoice.id,
        {
          payment_method: defaultPmId,
          off_session: true,
          expand: ['payments'],
        },
        { idempotencyKey: `pay:${idemSuffix}` },
      );
      piId = extractPiId(finalized) ?? piId;
      console.log('[topup] paid', { status: finalized.status, piId });
    } catch (err: any) {
      console.warn('[topup] invoices.pay threw', {
        type: err?.type,
        code: err?.code,
        message: err?.message,
      });
      try {
        finalized = (await stripe.invoices.retrieve(invoice.id, {
          expand: ['payments'],
        })) as typeof finalized;
        piId = extractPiId(finalized) ?? piId;
      } catch (refetchErr) {
        console.warn('[topup] invoice refetch after pay() failure threw', refetchErr);
        captureBillingError(refetchErr, 'topup_invoice_state_unknown', { orgId: input.orgId, extra: { correlationId: input.correlationId } });
      }
    }
  }

  const pi = await stripe.paymentIntents.retrieve(piId);
  console.log('[topup] PI final state', { piId, status: pi.status, invoiceStatus: finalized.status });

  // In API 2025-11-17+, Invoice.tax is gone; compute from total - subtotal (tax_behavior=exclusive).
  const taxCents = Math.max(0, finalized.total - finalized.subtotal);

  const status: TopUpStatus =
    pi.status === 'succeeded'
      ? 'succeeded'
      : pi.status === 'requires_action'
        ? 'requires_action'
        : 'requires_payment_method';

  return {
    status,
    clientSecret: pi.client_secret ?? null,
    paymentIntentId: pi.id,
    invoiceId: finalized.id ?? '',
    subtotalCents: finalized.subtotal,
    taxCents,
    totalCents: finalized.total,
  };
}

// Void an open/uncollectible invoice so Stripe Smart Retries don't keep attempting to charge a
// card we've already disabled auto-recharge on. Safe to call after any failed top-up: if the
// invoice isn't void-able (already paid, already void, etc.) we just log and move on.
export async function voidOpenInvoice(invoiceId: string): Promise<void> {
  if (!invoiceId) return;
  try {
    await getStripe().invoices.voidInvoice(invoiceId);
    console.log('[stripe-billing] voided invoice after failed top-up', { invoiceId });
  } catch (err: any) {
    console.warn('[stripe-billing] voidOpenInvoice failed (likely not void-able)', {
      invoiceId,
      code: err?.code,
      message: err?.message,
    });
  }
}

export async function getInvoiceMetadata(invoiceId: string): Promise<Record<string, string> | null> {
  try {
    const inv = await getStripe().invoices.retrieve(invoiceId);
    return (inv.metadata as Record<string, string> | null) ?? {};
  } catch (err) {
    console.warn('[stripe-billing] getInvoiceMetadata failed', err);
    return null;
  }
}

export async function getInvoiceUrlForPaymentIntent(paymentIntentId: string): Promise<string | null> {
  const stripe = getStripe();
  const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
  const customerId = typeof pi.customer === 'string' ? pi.customer : pi.customer?.id;
  if (!customerId) return null;

  // Stripe API 2025-11-17+ moved the invoice→payment-intent link out of Invoice.payment_intent
  // and into Invoice.payments[].payment.payment_intent (a list of InvoicePayment objects).
  const invoices = await stripe.invoices.list({
    customer: customerId,
    limit: 100,
    expand: ['data.payments'],
  });
  const match = invoices.data.find((inv) => {
    const payments = (inv as Stripe.Invoice & { payments?: { data?: Array<{ payment?: { payment_intent?: string | null } }> } }).payments?.data ?? [];
    return payments.some((p) => p.payment?.payment_intent === paymentIntentId);
  });
  if (!match) return null;
  return match.invoice_pdf ?? match.hosted_invoice_url ?? null;
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
    captureBillingError(error, 'default_pm_db_clear_failed', { orgId });
  }
}

export interface SavedPaymentMethod {
  id: string;
  brand: string;
  last4: string;
  expiresMonth: number;
  expiresYear: number;
  isDefault: boolean;
}

export async function listSavedPaymentMethods(orgId: string): Promise<SavedPaymentMethod[]> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('stripe_customer_id, stripe_default_payment_method_id')
    .eq('organization_id', orgId)
    .single();
  if (!billing?.stripe_customer_id) return [];

  const stripe = getStripe();
  let pms: Stripe.ApiList<Stripe.PaymentMethod>;
  try {
    pms = await stripe.paymentMethods.list({
      customer: billing.stripe_customer_id,
      type: 'card',
      limit: 20,
    });
  } catch (err) {
    // Stale customer under the active key (test ⇄ live switch) — surface no cards rather
    // than a 500. ensureStripeCustomer re-provisions on the next add-card/top-up.
    if (isStripeResourceMissing(err)) return [];
    throw err;
  }
  const defaultId = billing.stripe_default_payment_method_id ?? null;
  return pms.data
    .filter((pm) => !!pm.card)
    .map((pm) => ({
      id: pm.id,
      brand: pm.card!.brand,
      last4: pm.card!.last4,
      expiresMonth: pm.card!.exp_month,
      expiresYear: pm.card!.exp_year,
      isDefault: pm.id === defaultId,
    }));
}

export async function detachPaymentMethodById(orgId: string, paymentMethodId: string): Promise<void> {
  const stripe = getStripe();

  // Snapshot the current default + customer before detaching.
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('stripe_customer_id, stripe_default_payment_method_id')
    .eq('organization_id', orgId)
    .single();
  const wasDefault = billing?.stripe_default_payment_method_id === paymentMethodId;
  const customerId = billing?.stripe_customer_id ?? null;

  // Verify the PM actually belongs to this org's Stripe customer before detaching. Without
  // this check, an authenticated user could pass another org's pm_xxx id and detach their
  // card (Stripe accepts the detach regardless of who calls). The route layer already
  // gates on manage_billing for THIS org — this check binds the PM to THIS org's customer.
  if (customerId) {
    try {
      const pm = await stripe.paymentMethods.retrieve(paymentMethodId);
      const pmCustomer = typeof pm.customer === 'string' ? pm.customer : pm.customer?.id ?? null;
      if (pmCustomer && pmCustomer !== customerId) {
        console.error('[stripe-billing] detach refused — PM belongs to different customer', {
          org_id: orgId,
          pm_id: paymentMethodId,
          pm_customer: pmCustomer,
          org_customer: customerId,
        });
        throw new Error('Payment method does not belong to this organization');
      }
    } catch (err: any) {
      if (err?.message === 'Payment method does not belong to this organization') throw err;
      console.warn('[stripe-billing] PM ownership check failed (proceeding cautiously)', err);
    }
  }

  try {
    await stripe.paymentMethods.detach(paymentMethodId);
  } catch (err) {
    console.warn('[stripe-billing] detach by id failed (possibly already detached)', err);
  }

  if (!wasDefault) return;

  // The deleted card was the default — pick another saved PM to promote, or
  // null the default + disable auto-recharge if nothing's left.
  let promotedPmId: string | null = null;
  if (customerId) {
    try {
      const remaining = await stripe.paymentMethods.list({
        customer: customerId,
        type: 'card',
        limit: 20,
      });
      const next = remaining.data.find((pm) => pm.id !== paymentMethodId);
      if (next) promotedPmId = next.id;
    } catch (err) {
      console.warn('[stripe-billing] list PMs for promotion failed', err);
    }
  }

  if (promotedPmId) {
    // Reuse setDefaultPaymentMethod so customer.invoice_settings + customer.address sync
    await setDefaultPaymentMethod(orgId, promotedPmId);
    return;
  }

  // No remaining PM → clear default + disable auto-recharge (off-session pay would fail anyway)
  await supabase
    .from('organization_billing')
    .update({
      stripe_default_payment_method_id: null,
      auto_recharge_enabled: false,
      auto_recharge_in_progress: false,
      auto_recharge_in_progress_started_at: null,
    })
    .eq('organization_id', orgId);
}

export async function createSetupIntentForOrg(orgId: string): Promise<{ clientSecret: string }> {
  const customerId = await ensureStripeCustomer(orgId);
  const stripe = getStripe();
  // Per-attempt idempotency. If the network drops the response, retrying within the
  // minute returns the same SetupIntent (same client_secret) instead of generating two.
  const minuteBucket = Math.floor(Date.now() / 60_000);
  const si = await stripe.setupIntents.create(
    {
      customer: customerId,
      usage: 'off_session',
      payment_method_types: ['card'],
      metadata: { organization_id: orgId, purpose: 'add_card' },
    },
    { idempotencyKey: `setupintent:${orgId}:${minuteBucket}` },
  );
  if (!si.client_secret) {
    throw new Error('SetupIntent has no client_secret');
  }
  return { clientSecret: si.client_secret };
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
  fallbackEmail?: string,
): Promise<void> {
  const customerId = await ensureStripeCustomer(orgId);
  const stripe = getStripe();

  // Verify the PM is either unattached or already attached to THIS org's customer before
  // we attach it. Without this, an attacker could pass another org's pm_xxx ID — Stripe
  // refuses to re-attach already-attached PMs but the error mode is generic, so we'd let
  // the request error out without explaining why. Explicit refusal is more honest.
  try {
    const pm = await stripe.paymentMethods.retrieve(paymentMethodId);
    const pmCustomer = typeof pm.customer === 'string' ? pm.customer : pm.customer?.id ?? null;
    if (pmCustomer && pmCustomer !== customerId) {
      console.error('[stripe-billing] setDefault refused — PM belongs to different customer', {
        org_id: orgId,
        pm_id: paymentMethodId,
        pm_customer: pmCustomer,
        org_customer: customerId,
      });
      throw new Error('Payment method does not belong to this organization');
    }
  } catch (err: any) {
    if (err?.message === 'Payment method does not belong to this organization') throw err;
    // Stripe API timeout etc. — fall through. The attach call below will fail cleanly
    // if the PM is really not ours; we've already logged the ambiguous state.
    console.warn('[stripe-billing] PM ownership check failed (proceeding to attach)', err);
  }

  await stripe.paymentMethods.attach(paymentMethodId, { customer: customerId });
  await stripe.customers.update(customerId, {
    invoice_settings: { default_payment_method: paymentMethodId },
  });

  // Propagate billing_details from the PM onto the Customer so automatic_tax can be computed
  // and so the customer has an email for Stripe-hosted invoice receipts.
  await copyPMAddressToCustomer(customerId, paymentMethodId, fallbackEmail);

  const { error } = await supabase
    .from('organization_billing')
    .update({ stripe_default_payment_method_id: paymentMethodId })
    .eq('organization_id', orgId);
  if (error) {
    console.error('[stripe-billing] failed to persist default PM', error);
    captureBillingError(error, 'default_pm_db_update_failed', { orgId });
  }
}

async function copyPMAddressToCustomer(
  customerId: string,
  paymentMethodId: string,
  fallbackEmail?: string,
): Promise<boolean> {
  const stripe = getStripe();
  try {
    const pm = await stripe.paymentMethods.retrieve(paymentMethodId);
    const bd = pm.billing_details;
    const customer = await stripe.customers.retrieve(customerId);
    const existingEmail = ('deleted' in customer ? null : (customer as Stripe.Customer).email) ?? null;
    const email = bd?.email ?? existingEmail ?? fallbackEmail ?? undefined;

    if (!bd?.address?.line1 || !bd.address.country) {
      // No address — still update email if we have one to set
      if (!existingEmail && email) {
        await stripe.customers.update(customerId, { email });
      }
      return false;
    }
    await stripe.customers.update(customerId, {
      email,
      name: bd.name ?? undefined,
      address: {
        line1: bd.address.line1,
        line2: bd.address.line2 ?? undefined,
        city: bd.address.city ?? undefined,
        state: bd.address.state ?? undefined,
        postal_code: bd.address.postal_code ?? undefined,
        country: bd.address.country,
      },
    });
    return true;
  } catch (err) {
    console.warn('[stripe-billing] copyPMAddressToCustomer failed', err);
    return false;
  }
}

async function syncCustomerAddressFromDefaultPM(orgId: string, customerId: string): Promise<boolean> {
  const { data: billing } = await supabase
    .from('organization_billing')
    .select('stripe_default_payment_method_id')
    .eq('organization_id', orgId)
    .single();
  const pmId = billing?.stripe_default_payment_method_id;
  if (!pmId) return false;
  return copyPMAddressToCustomer(customerId, pmId);
}

export function __resetStripeClientForTesting(): void {
  stripeClient = null;
}

export function __injectStripeClientForTesting(client: Stripe | null): void {
  stripeClient = client;
}
