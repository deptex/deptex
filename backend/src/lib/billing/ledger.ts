import { supabase } from '../supabase';
import { isBillingEnforcementEnabled } from './enforcement';
import type {
  RecordMeterEventInput,
  RecordMeterEventResult,
  CanChargeResponse,
  BillingState,
  BillingPaymentMethod,
  BillingTransaction,
  UsageActivity,
  UsageResponse,
  TransactionsResponse,
} from './types';

interface DeductBalanceMetadata {
  event_type: string;
  provider: string;
  feature: string;
  quantity: number;
  output_quantity?: number;
  unit: string;
  cost_cents_cog: number;
  attribution_user_id?: string;
  attribution_resource_type?: string;
  attribution_resource_id?: string;
  model_id?: string;
  machine_size?: string;
  idempotency_key: string;
  project_id?: string;
}

function buildDeductMetadata(input: RecordMeterEventInput): DeductBalanceMetadata {
  const md: DeductBalanceMetadata = {
    event_type: input.eventType,
    provider: input.provider,
    feature: input.feature,
    quantity: input.quantity,
    unit: input.unit,
    cost_cents_cog: input.cogCents,
    idempotency_key: input.idempotencyKey,
  };
  if (input.outputQuantity !== undefined) md.output_quantity = input.outputQuantity;
  if (input.modelId) md.model_id = input.modelId;
  if (input.machineSize) md.machine_size = input.machineSize;
  if (input.attribution?.userId) md.attribution_user_id = input.attribution.userId;
  if (input.attribution?.resourceType) md.attribution_resource_type = input.attribution.resourceType;
  if (input.attribution?.resourceId) md.attribution_resource_id = input.attribution.resourceId;
  if (input.projectId) md.project_id = input.projectId;
  return md;
}

async function existingEventForKey(orgId: string, idempotencyKey: string) {
  const { data } = await supabase
    .from('billing_transactions')
    .select('id, amount_cents')
    .eq('organization_id', orgId)
    .eq('idempotency_key', idempotencyKey)
    .eq('kind', 'usage_deduction')
    .maybeSingle();
  return data;
}

export async function recordMeterEvent(input: RecordMeterEventInput): Promise<RecordMeterEventResult> {
  if (!isBillingEnforcementEnabled()) {
    console.info('[billing.enforcement_off]', {
      orgId: input.organizationId,
      feature: input.feature,
      cogCents: input.cogCents,
      chargedCents: input.chargedCents,
      idempotencyKey: input.idempotencyKey,
    });
    return { deducted: false, newBalanceCents: null, reason: 'enforcement_off' };
  }

  const existing = await existingEventForKey(input.organizationId, input.idempotencyKey);
  if (existing) {
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('balance_cents')
      .eq('organization_id', input.organizationId)
      .single();
    return {
      deducted: false,
      newBalanceCents: billing?.balance_cents ?? null,
      reason: 'duplicate_idempotency_key',
    };
  }

  const metadata = buildDeductMetadata(input);
  const description = `${input.feature} (${input.eventType})`;

  const { data, error } = await supabase.rpc('deduct_balance', {
    p_organization_id: input.organizationId,
    p_amount_cents: input.chargedCents,
    p_description: description,
    p_event_metadata: metadata,
  });

  if (error) {
    if (error.code === '23505') {
      const refetched = await existingEventForKey(input.organizationId, input.idempotencyKey);
      if (refetched) {
        const { data: billing } = await supabase
          .from('organization_billing')
          .select('balance_cents')
          .eq('organization_id', input.organizationId)
          .single();
        return {
          deducted: false,
          newBalanceCents: billing?.balance_cents ?? null,
          reason: 'duplicate_idempotency_key',
        };
      }
    }
    console.error('[billing.deduct] RPC error', error);
    throw new Error(`deduct_balance failed: ${error.message}`);
  }

  if (data === null) {
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('balance_cents')
      .eq('organization_id', input.organizationId)
      .single();
    return {
      deducted: false,
      newBalanceCents: billing?.balance_cents ?? null,
      reason: 'insufficient_credit',
    };
  }

  const newBalanceCents = data as number;

  console.info('[billing] deducted', {
    orgId: input.organizationId,
    amountCents: input.chargedCents,
    cogCents: input.cogCents,
    newBalanceCents,
    idempotencyKey: input.idempotencyKey,
    eventType: input.eventType,
  });

  // Fire post-deduction side-effects. Lazy-required to avoid the static import cycle
  // (ledger → auto-recharge → stripe-billing → ledger). Best-effort: never blocks the
  // meter-event call. Every caller of recordMeterEvent gets these for free — don't
  // re-implement them in HTTP routes or domain code.
  //
  // Defensive structure: the outer try/catch + per-promise .catch() ensure that no
  // failure here can escape as an unhandled rejection (which on Node ≥16 with default
  // --unhandled-rejections=throw would crash the process and kill billing for the org).
  setImmediate(() => {
    try {
      let maybeAutoRecharge: typeof import('./auto-recharge').maybeAutoRecharge | undefined;
      let checkAndDispatchBalanceAlerts:
        | typeof import('./alerts').checkAndDispatchBalanceAlerts
        | undefined;
      try {
        ({ maybeAutoRecharge } = require('./auto-recharge') as typeof import('./auto-recharge'));
      } catch (err) {
        console.error('[billing] require(./auto-recharge) failed', {
          orgId: input.organizationId,
          err,
        });
      }
      try {
        ({ checkAndDispatchBalanceAlerts } = require('./alerts') as typeof import('./alerts'));
      } catch (err) {
        console.error('[billing] require(./alerts) failed', {
          orgId: input.organizationId,
          err,
        });
      }

      if (checkAndDispatchBalanceAlerts) {
        Promise.resolve()
          .then(() => checkAndDispatchBalanceAlerts!(input.organizationId, newBalanceCents))
          .catch((err) =>
            console.error('[billing] checkAndDispatchBalanceAlerts threw', {
              orgId: input.organizationId,
              err,
            }),
          );
      }
      if (maybeAutoRecharge) {
        Promise.resolve()
          .then(() => maybeAutoRecharge!(input.organizationId))
          .catch((err) =>
            console.error('[billing] maybeAutoRecharge threw', {
              orgId: input.organizationId,
              err,
            }),
          );
      }
    } catch (err) {
      // Last-ditch guard. Should not reach here given the inner guards above, but if
      // a logger or anything else throws synchronously we must not let it escape.
      try {
        console.error('[billing] post-deduction side-effects setup failed', {
          orgId: input.organizationId,
          err,
        });
      } catch {
        // Swallow: console itself failed; nothing safe to do.
      }
    }
  });

  return { deducted: true, newBalanceCents };
}

export async function canCharge(orgId: string, estimatedCents: number): Promise<CanChargeResponse> {
  if (!isBillingEnforcementEnabled()) {
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('balance_cents')
      .eq('organization_id', orgId)
      .single();
    return {
      allowed: true,
      balanceCents: billing?.balance_cents ?? 0,
      reason: 'enforcement_off',
    };
  }

  const { data: billing, error } = await supabase
    .from('organization_billing')
    .select('balance_cents')
    .eq('organization_id', orgId)
    .single();

  // Distinguish "the DB couldn't tell us the balance" from "the balance is too low".
  // Returning insufficient_credit on a DB outage would show "your balance is too low"
  // to a user whose balance is actually fine — a confusing failure mode during incidents.
  // Callers can decide whether to fail-open or fail-closed on db_unavailable.
  if (error) {
    console.error('[billing.canCharge] DB query failed', { orgId, err: error });
    return { allowed: false, balanceCents: 0, reason: 'db_unavailable' };
  }
  if (!billing) {
    return { allowed: false, balanceCents: 0, reason: 'insufficient_credit' };
  }

  const allowed = billing.balance_cents >= Math.ceil(estimatedCents);
  return {
    allowed,
    balanceCents: billing.balance_cents,
    reason: allowed ? undefined : 'insufficient_credit',
  };
}

interface StripePaymentMethodFetcher {
  (stripeCustomerId: string, paymentMethodId: string): Promise<BillingPaymentMethod | null>;
}

let stripePaymentMethodFetcher: StripePaymentMethodFetcher | null = null;

export function setStripePaymentMethodFetcher(fetcher: StripePaymentMethodFetcher | null): void {
  stripePaymentMethodFetcher = fetcher;
}

async function fetchPaymentMethod(
  stripeCustomerId: string | null,
  stripePaymentMethodId: string | null,
): Promise<BillingPaymentMethod | null> {
  if (!stripeCustomerId || !stripePaymentMethodId || !stripePaymentMethodFetcher) return null;
  try {
    return await stripePaymentMethodFetcher(stripeCustomerId, stripePaymentMethodId);
  } catch (err) {
    console.error('[billing.getBalance] payment-method fetch failed', err);
    return null;
  }
}

// Rolling 30-day window — mirrors the cap check in auto-recharge.ts.
const ROLLING_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

async function sumAutoRechargeLast30Days(orgId: string): Promise<number> {
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

export async function getBalance(orgId: string): Promise<BillingState | null> {
  const { data, error } = await supabase
    .from('organization_billing')
    .select('*')
    .eq('organization_id', orgId)
    .single();
  if (error || !data) return null;

  const [paymentMethod, spentLast30DaysCents] = await Promise.all([
    fetchPaymentMethod(data.stripe_customer_id, data.stripe_default_payment_method_id),
    sumAutoRechargeLast30Days(orgId),
  ]);

  return {
    balanceCents: data.balance_cents,
    autoRecharge: {
      enabled: data.auto_recharge_enabled,
      thresholdCents: data.auto_recharge_threshold_cents,
      amountCents: data.auto_recharge_amount_cents,
      monthlyCapCents: data.auto_recharge_monthly_cap_cents,
      spentLast30DaysCents,
    },
    lowBalanceAlertThresholdCents: data.low_balance_alert_threshold_cents,
    paymentMethod,
  };
}

export async function listTransactions(
  orgId: string,
  cursor?: string,
  limit = 50,
  kinds?: string[],
): Promise<TransactionsResponse> {
  let query = supabase
    .from('billing_transactions')
    .select('id, kind, amount_cents, description, stripe_payment_intent_id, created_at')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .order('id', { ascending: false })
    .limit(limit + 1);

  if (kinds && kinds.length > 0) {
    query = query.in('kind', kinds);
  }

  if (cursor) {
    const [createdAt, id] = decodeCursor(cursor);
    if (createdAt && id) {
      query = query.or(
        `created_at.lt.${createdAt},and(created_at.eq.${createdAt},id.lt.${id})`,
      );
    }
  }

  const { data, error } = await query;
  if (error) {
    console.error('[billing.listTransactions]', error);
    return { transactions: [], nextCursor: null };
  }

  const rows = data ?? [];
  const hasMore = rows.length > limit;
  const trimmed = hasMore ? rows.slice(0, limit) : rows;

  const transactions: BillingTransaction[] = trimmed.map((row) => ({
    id: row.id,
    kind: row.kind,
    amountCents: row.amount_cents,
    description: row.description,
    createdAt: row.created_at,
    stripePaymentIntentId: row.stripe_payment_intent_id,
  }));

  const last = trimmed[trimmed.length - 1];
  const nextCursor = hasMore && last ? encodeCursor(last.created_at, last.id) : null;

  return { transactions, nextCursor };
}

export async function listUsageActivity(
  orgId: string,
  rangeDays = 30,
  cursor?: string,
  limit = 50,
): Promise<UsageResponse> {
  const since = new Date(Date.now() - rangeDays * 24 * 60 * 60 * 1000).toISOString();

  const { data: totalRows, error: totalErr } = await supabase
    .from('billing_transactions')
    .select('amount_cents')
    .eq('organization_id', orgId)
    .eq('kind', 'usage_deduction')
    .gte('created_at', since);

  let totalCents = 0;
  if (!totalErr && totalRows) {
    for (const row of totalRows) {
      totalCents += Math.abs(row.amount_cents);
    }
  }

  let query = supabase
    .from('billing_transactions')
    .select(
      'id, feature, event_type, amount_cents, created_at, attribution_user_id, attribution_resource_type, attribution_resource_id, model_id, machine_size',
    )
    .eq('organization_id', orgId)
    .eq('kind', 'usage_deduction')
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .order('id', { ascending: false })
    .limit(limit + 1);

  if (cursor) {
    const [createdAt, id] = decodeCursor(cursor);
    if (createdAt && id) {
      query = query.or(
        `created_at.lt.${createdAt},and(created_at.eq.${createdAt},id.lt.${id})`,
      );
    }
  }

  const { data: rows, error } = await query;
  if (error || !rows) {
    return { totalCents, activity: [], nextCursor: null };
  }

  const hasMore = rows.length > limit;
  const trimmed = hasMore ? rows.slice(0, limit) : rows;

  const activity: UsageActivity[] = trimmed.map((row) => ({
    id: row.id,
    feature: row.feature ?? 'unknown',
    eventType: row.event_type ?? 'ai_tokens',
    costCentsCharged: Math.abs(row.amount_cents),
    emittedAt: row.created_at,
    attribution: {
      userId: row.attribution_user_id,
      resourceType: row.attribution_resource_type,
      resourceId: row.attribution_resource_id,
    },
    modelId: row.model_id,
    machineSize: row.machine_size,
  }));

  const last = trimmed[trimmed.length - 1];
  const nextCursor = hasMore && last ? encodeCursor(last.created_at, last.id) : null;

  return { totalCents, activity, nextCursor };
}

function encodeCursor(createdAt: string, id: string): string {
  return Buffer.from(`${createdAt}|${id}`).toString('base64url');
}

function decodeCursor(cursor: string): [string | null, string | null] {
  try {
    const decoded = Buffer.from(cursor, 'base64url').toString('utf-8');
    const [createdAt, id] = decoded.split('|');
    if (!createdAt || !id) return [null, null];
    return [createdAt, id];
  } catch {
    return [null, null];
  }
}
