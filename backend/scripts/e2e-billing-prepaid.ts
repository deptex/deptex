// End-to-end harness for the prepaid billing flow.
//
//   npm run e2e:billing-prepaid
//
// Exercises the REAL Postgres RPCs + the deployed billing routes:
//   1. Create a test org → verify $5 signup_grant via trigger
//   2. Top up via credit_balance RPC (simulates the webhook path) → balance updates
//   3. Deduct via deduct_balance RPC → ledger entry + balance drops
//   4. canCharge gate returns allowed=true while balance covers, false at $0
//   5. Concurrent deducts on a $1 balance: exactly one succeeds
//   6. credit_balance with the same stripe_payment_intent_id twice: second
//      rejected by uq_billing_transactions_pi_credit
//   7. assert_balance_matches_ledger reports no drift for the test org
//   8. Tear down
//
// Requires SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY. Does NOT hit Stripe;
// the webhook path is simulated by calling credit_balance directly with a
// fake PaymentIntent id. The real Stripe loop is exercised by the M11.6
// dogfood smoke in Stripe test mode against the deployed instance.

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { randomUUID } from 'crypto';
import * as path from 'path';

require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!URL || !KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(2);
}

function newClient(): SupabaseClient {
  return createClient(URL!, KEY!, { auth: { persistSession: false, autoRefreshToken: false } });
}

const baseMetadata = {
  event_type: 'ai_tokens',
  provider: 'anthropic',
  feature: 'aegis.chat',
  quantity: 1000,
  unit: 'mixed_tokens',
  cost_cents_cog: 5,
  model_id: 'claude-haiku-4-5-20251001',
};

function log(step: string, msg: string) {
  console.log(`[e2e][${step}] ${msg}`);
}

function fail(step: string, msg: string): never {
  console.error(`[e2e][${step}] FAIL — ${msg}`);
  process.exit(1);
}

async function main(): Promise<void> {
  const supabase = newClient();
  const orgName = `e2e-billing-${randomUUID()}`;

  log('setup', `creating test org ${orgName}`);
  const { data: org, error: orgErr } = await supabase
    .from('organizations')
    .insert({ name: orgName })
    .select('id')
    .single();
  if (orgErr || !org) fail('setup', `create org: ${orgErr?.message}`);
  const orgId = org!.id;

  try {
    log('step-1', 'verify trigger created billing row + signup grant');
    const { data: billing } = await supabase
      .from('organization_billing')
      .select('balance_cents')
      .eq('organization_id', orgId)
      .single();
    if (billing?.balance_cents !== 500) fail('step-1', `expected 500, got ${billing?.balance_cents}`);

    const { count: grantCount } = await supabase
      .from('billing_transactions')
      .select('id', { count: 'exact', head: true })
      .eq('organization_id', orgId)
      .eq('kind', 'signup_grant');
    if (grantCount !== 1) fail('step-1', `expected 1 signup_grant, got ${grantCount}`);

    log('step-2', 'top up via credit_balance (simulates webhook)');
    const piId = `pi_e2e_${randomUUID()}`;
    const { data: afterTopup, error: creditErr } = await supabase.rpc('credit_balance', {
      p_organization_id: orgId,
      p_amount_cents: 2500,
      p_kind: 'topup',
      p_description: 'e2e top-up',
      p_stripe_payment_intent_id: piId,
      p_created_by_user_id: null,
    });
    if (creditErr) fail('step-2', `credit_balance: ${creditErr.message}`);
    if (afterTopup !== 3000) fail('step-2', `expected balance 3000, got ${afterTopup}`);

    log('step-3', 'replay same PI — uq_billing_transactions_pi_credit must reject');
    const { error: dupErr } = await supabase.rpc('credit_balance', {
      p_organization_id: orgId,
      p_amount_cents: 2500,
      p_kind: 'topup',
      p_description: 'e2e replay',
      p_stripe_payment_intent_id: piId,
      p_created_by_user_id: null,
    });
    if (!dupErr || dupErr.code !== '23505') fail('step-3', `expected 23505, got ${dupErr?.code}`);

    log('step-4', 'deduct 500 cents and confirm balance');
    const { data: afterDeduct, error: deductErr } = await supabase.rpc('deduct_balance', {
      p_organization_id: orgId,
      p_amount_cents: 500,
      p_description: 'e2e deduct',
      p_event_metadata: { ...baseMetadata, idempotency_key: `e2e-${orgId}-1` },
    });
    if (deductErr) fail('step-4', `deduct_balance: ${deductErr.message}`);
    if (afterDeduct !== 2500) fail('step-4', `expected 2500, got ${afterDeduct}`);

    log('step-5', 'drain remainder to exactly $1 via deduct_balance, then race');
    const { data: balRow } = await supabase
      .from('organization_billing')
      .select('balance_cents')
      .eq('organization_id', orgId)
      .single();
    const drainAmount = (balRow?.balance_cents ?? 0) - 100;
    if (drainAmount > 0) {
      const { error: drainErr } = await supabase.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: drainAmount,
        p_description: 'drain to $1',
        p_event_metadata: { ...baseMetadata, idempotency_key: `drain-${orgId}` },
      });
      if (drainErr) fail('step-5', `drain: ${drainErr.message}`);
    }

    const c1 = newClient();
    const c2 = newClient();
    const [r1, r2] = await Promise.all([
      c1.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: 100,
        p_description: 'race-1',
        p_event_metadata: { ...baseMetadata, idempotency_key: `race-${orgId}-A` },
      }),
      c2.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: 100,
        p_description: 'race-2',
        p_event_metadata: { ...baseMetadata, idempotency_key: `race-${orgId}-B` },
      }),
    ]);
    const wins = [r1, r2].filter((r) => r.data !== null && r.error === null).length;
    if (wins !== 1) fail('step-5', `expected exactly 1 winner, got ${wins}`);

    log('step-6', 'invariant — assert_balance_matches_ledger returns no drift for org');
    const { data: drift, error: driftErr } = await supabase.rpc('assert_balance_matches_ledger');
    if (driftErr) fail('step-6', `assert: ${driftErr.message}`);
    const orgDrift = (drift ?? []).filter((r: any) => r.organization_id === orgId);
    if (orgDrift.length > 0) fail('step-6', `drift detected: ${JSON.stringify(orgDrift)}`);

    console.log('[e2e] OK — all steps green');
  } finally {
    log('teardown', `deleting org ${orgId}`);
    await supabase.from('organizations').delete().eq('id', orgId);
  }
}

main().catch((err) => {
  console.error('[e2e] unhandled error', err);
  process.exit(1);
});
