import express from 'express';
import { z } from 'zod';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { userHasOrgPermission } from '../lib/permissions';
import { getBalance, listTransactions, listUsageActivity } from '../lib/billing/ledger';
import { loadUsageBreakdown, type UsageGranularity, type FeatureCategory } from '../lib/billing/usage-breakdown';
import {
  createPaymentIntent,
  createSetupIntentForOrg,
  createTopUpInvoice,
  detachPaymentMethod,
  detachPaymentMethodById,
  getInvoiceUrlForPaymentIntent,
  listSavedPaymentMethods,
  setDefaultPaymentMethod,
} from '../lib/billing/stripe-billing';
import { maybeAutoRecharge } from '../lib/billing/auto-recharge';
import { supabase } from '../lib/supabase';

const router = express.Router();
router.use(authenticateUser);

const MIN_TOPUP_CENTS = 500;
const MIN_AUTO_RECHARGE_AMOUNT_CENTS = 500;

async function gateBilling(
  req: AuthRequest,
  res: express.Response,
  permission: 'manage_billing' | 'view_settings',
): Promise<string | null> {
  const userId = req.user?.id;
  if (!userId) {
    res.status(401).json({ error: 'Unauthenticated' });
    return null;
  }
  const orgId = req.params.id;
  if (!orgId) {
    res.status(400).json({ error: 'Missing organization id' });
    return null;
  }
  if (permission === 'manage_billing') {
    const ok = await userHasOrgPermission(userId, orgId, 'manage_billing');
    if (!ok) {
      res.status(403).json({ error: 'Permission denied' });
      return null;
    }
    return orgId;
  }
  const [manage, view] = await Promise.all([
    userHasOrgPermission(userId, orgId, 'manage_billing'),
    userHasOrgPermission(userId, orgId, 'view_settings'),
  ]);
  if (!manage && !view) {
    res.status(403).json({ error: 'Permission denied' });
    return null;
  }
  return orgId;
}

router.get('/:id/billing', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'view_settings');
  if (!orgId) return;
  try {
    const state = await getBalance(orgId);
    if (!state) return res.status(404).json({ error: 'Billing not initialized' });
    res.json(state);
  } catch (err) {
    console.error('[billing.GET] failed', err);
    res.status(500).json({ error: 'Failed to load billing' });
  }
});

const topupSchema = z.object({
  amount_cents: z.number().int().min(MIN_TOPUP_CENTS).max(100_000_00),
});

router.post('/:id/billing/topup', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  const parsed = topupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid top-up amount' });
  }
  try {
    const { paymentIntent } = await createPaymentIntent({
      orgId,
      amountCents: parsed.data.amount_cents,
      purpose: 'topup',
      setupFutureUsage: 'off_session',
    });
    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      amountCents: parsed.data.amount_cents,
    });
  } catch (err) {
    console.error('[billing.topup] failed', err);
    res.status(500).json({ error: 'Top-up failed. Please try again.' });
  }
});

const topupIntentSchema = z.object({
  amount_cents: z.number().int().min(MIN_TOPUP_CENTS).max(100_000_00),
  billing_email: z.string().email().optional(),
  billing_address: z
    .object({
      line1: z.string().min(1),
      line2: z.string().nullable().optional(),
      city: z.string().min(1),
      state: z.string().nullable().optional(),
      postal_code: z.string().min(1),
      country: z.string().length(2),
    })
    .optional(),
});

router.post('/:id/billing/topup-intent', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  const parsed = topupIntentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid top-up request' });
  }
  try {
    const result = await createTopUpInvoice({
      orgId,
      amountCents: parsed.data.amount_cents,
      billingEmail: parsed.data.billing_email,
      billingAddress: parsed.data.billing_address,
      fallbackEmail: req.user?.email,
    });
    res.json({
      status: result.status,
      client_secret: result.clientSecret,
      payment_intent_id: result.paymentIntentId,
      invoice_id: result.invoiceId,
      subtotal_cents: result.subtotalCents,
      tax_cents: result.taxCents,
      total_cents: result.totalCents,
    });
  } catch (err: any) {
    console.error('[billing.topup-intent] failed', err?.message ?? err);
    res.status(500).json({ error: 'Failed to start top-up. Please try again.' });
  }
});

router.get('/:id/billing/payment-methods', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'view_settings');
  if (!orgId) return;
  try {
    const methods = await listSavedPaymentMethods(orgId);
    res.json({ payment_methods: methods });
  } catch (err) {
    console.error('[billing.payment-methods] failed', err);
    res.status(500).json({ error: 'Failed to load payment methods' });
  }
});

router.post('/:id/billing/setup-intent', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  try {
    const { clientSecret } = await createSetupIntentForOrg(orgId);
    res.json({ client_secret: clientSecret });
  } catch (err) {
    console.error('[billing.setup-intent] failed', err);
    res.status(500).json({ error: 'Failed to start add-card flow' });
  }
});

router.delete('/:id/billing/payment-methods/:pmId', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  try {
    await detachPaymentMethodById(orgId, req.params.pmId);
    res.json({ ok: true });
  } catch (err: any) {
    console.error('[billing.payment-methods.detach] failed', err?.message ?? err);
    res.status(500).json({ error: 'Failed to remove payment method' });
  }
});

router.post('/:id/billing/payment-methods/:pmId/default', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  try {
    await setDefaultPaymentMethod(orgId, req.params.pmId, req.user?.email);
    res.json({ ok: true });
  } catch (err: any) {
    console.error('[billing.payment-methods.set-default] failed', err?.message ?? err);
    res.status(500).json({ error: 'Failed to set default payment method' });
  }
});

const autoRechargeSchema = z.object({
  enabled: z.boolean(),
  threshold_cents: z.number().int().positive().nullable().optional(),
  amount_cents: z.number().int().min(MIN_AUTO_RECHARGE_AMOUNT_CENTS).nullable().optional(),
  monthly_cap_cents: z.number().int().positive().nullable().optional(),
});

router.put('/:id/billing/auto-recharge', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  const parsed = autoRechargeSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid auto-recharge config' });
  }
  const { enabled, threshold_cents, amount_cents, monthly_cap_cents } = parsed.data;

  if (enabled) {
    if (!threshold_cents || !amount_cents) {
      return res.status(400).json({ error: 'threshold_cents and amount_cents required when enabling' });
    }
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('stripe_default_payment_method_id')
      .eq('organization_id', orgId)
      .single();
    if (!billing?.stripe_default_payment_method_id) {
      return res.status(400).json({ error: 'Add a payment method before enabling auto-recharge' });
    }
  }

  const { error } = await supabase
    .from('organization_billing')
    .update({
      auto_recharge_enabled: enabled,
      auto_recharge_threshold_cents: threshold_cents ?? null,
      auto_recharge_amount_cents: amount_cents ?? null,
      auto_recharge_monthly_cap_cents: monthly_cap_cents ?? null,
    })
    .eq('organization_id', orgId);
  if (error) {
    console.error('[billing.auto-recharge] update failed', error);
    return res.status(500).json({ error: 'Failed to update auto-recharge' });
  }

  if (enabled) {
    maybeAutoRecharge(orgId).catch((err) => {
      console.error('[billing.auto-recharge] fire-on-enable failed', err);
    });
  }

  res.json({ ok: true });
});

const lowBalanceSchema = z.object({
  threshold_cents: z.number().int().min(0).max(100_000_00),
});

router.put('/:id/billing/low-balance-threshold', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  const parsed = lowBalanceSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid threshold' });

  const { error } = await supabase
    .from('organization_billing')
    .update({ low_balance_alert_threshold_cents: parsed.data.threshold_cents })
    .eq('organization_id', orgId);
  if (error) {
    console.error('[billing.low-balance] update failed', error);
    return res.status(500).json({ error: 'Failed to update threshold' });
  }
  res.json({ ok: true });
});


router.delete('/:id/billing/payment-method', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  try {
    await detachPaymentMethod(orgId);
    res.json({ ok: true });
  } catch (err) {
    console.error('[billing.detach-pm] failed', err);
    res.status(500).json({ error: 'Failed to remove payment method' });
  }
});

const attachPmSchema = z.object({
  payment_method_id: z.string().min(1),
});

router.post('/:id/billing/payment-method', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'manage_billing');
  if (!orgId) return;
  const parsed = attachPmSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payment_method_id' });
  try {
    await setDefaultPaymentMethod(orgId, parsed.data.payment_method_id);
    res.json({ ok: true });
  } catch (err) {
    console.error('[billing.attach-pm] failed', err);
    res.status(500).json({ error: 'Failed to attach payment method' });
  }
});

router.get('/:id/billing/transactions/:txnId/receipt', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'view_settings');
  if (!orgId) return;
  const txnId = req.params.txnId;

  const { data: txn, error } = await supabase
    .from('billing_transactions')
    .select('stripe_payment_intent_id')
    .eq('id', txnId)
    .eq('organization_id', orgId)
    .single();
  if (error || !txn || !txn.stripe_payment_intent_id) {
    return res.status(404).json({ error: 'No invoice available' });
  }
  if (txn.stripe_payment_intent_id.startsWith('pi_demo_')) {
    return res.status(404).json({ error: 'No invoice available' });
  }

  try {
    const url = await getInvoiceUrlForPaymentIntent(txn.stripe_payment_intent_id);
    if (!url) return res.status(404).json({ error: 'No invoice available' });
    res.json({ url });
  } catch (err) {
    console.error('[billing.receipt] failed', err);
    res.status(500).json({ error: 'Failed to load invoice' });
  }
});

router.get('/:id/billing/transactions', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'view_settings');
  if (!orgId) return;
  const cursor = typeof req.query.cursor === 'string' ? req.query.cursor : undefined;
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  const kinds = typeof req.query.kinds === 'string' && req.query.kinds.length > 0
    ? req.query.kinds.split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  try {
    const result = await listTransactions(orgId, cursor, limit, kinds);
    res.json(result);
  } catch (err) {
    console.error('[billing.transactions] failed', err);
    res.status(500).json({ error: 'Failed to load transactions' });
  }
});

router.get('/:id/billing/usage/breakdown', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'view_settings');
  if (!orgId) return;

  const granularity = (req.query.granularity as UsageGranularity) || 'day';
  if (!['day', 'week', 'month'].includes(granularity)) {
    return res.status(400).json({ error: 'Invalid granularity' });
  }
  const category = (req.query.category as FeatureCategory) || 'all';
  if (!['all', 'ai', 'workers'].includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }
  const featureFilter = typeof req.query.feature === 'string' && req.query.feature !== 'all' ? req.query.feature : undefined;
  const featureFilters = typeof req.query.features === 'string' && req.query.features.length > 0
    ? req.query.features.split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  const projectId = typeof req.query.project_id === 'string' && req.query.project_id !== 'all' ? req.query.project_id : undefined;
  const projectIds = typeof req.query.project_ids === 'string' && req.query.project_ids.length > 0
    ? req.query.project_ids.split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;
  const cumulative = req.query.cumulative === 'true';

  const rangeDays = Math.min(Math.max(Number(req.query.range_days) || 30, 1), 365);
  let start: Date;
  let end: Date;
  if (typeof req.query.start === 'string' && typeof req.query.end === 'string') {
    start = new Date(req.query.start);
    end = new Date(req.query.end);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({ error: 'Invalid start/end' });
    }
  } else {
    end = new Date();
    start = new Date(end.getTime() - rangeDays * 24 * 60 * 60 * 1000);
  }

  try {
    const result = await loadUsageBreakdown({
      organizationId: orgId,
      start,
      end,
      granularity,
      category,
      featureFilter,
      featureFilters,
      projectId,
      projectIds,
      cumulative,
    });
    res.json(result);
  } catch (err) {
    console.error('[billing.usage.breakdown] failed', err);
    res.status(500).json({ error: 'Failed to load usage breakdown' });
  }
});

router.get('/:id/billing/usage', async (req: AuthRequest, res) => {
  const orgId = await gateBilling(req, res, 'view_settings');
  if (!orgId) return;
  const cursor = typeof req.query.cursor === 'string' ? req.query.cursor : undefined;
  const rangeDays = Math.min(Math.max(Number(req.query.range_days) || 30, 1), 90);
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  try {
    const result = await listUsageActivity(orgId, rangeDays, cursor, limit);
    res.json(result);
  } catch (err) {
    console.error('[billing.usage] failed', err);
    res.status(500).json({ error: 'Failed to load usage' });
  }
});

export default router;
