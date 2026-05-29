// Real-Postgres test for the reconcile script invariant call.
//
// Verifies that assert_balance_matches_ledger returns an empty result when
// the ledger is consistent and surfaces drift when it isn't. The script
// itself wraps this RPC; this test exercises the underlying contract.

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { randomUUID } from 'crypto';
import * as path from 'path';

require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const hasDb = Boolean(URL && KEY);
const liveDescribe = hasDb ? describe : describe.skip;

function newClient(): SupabaseClient {
  if (!URL || !KEY) throw new Error('SUPABASE_URL/KEY missing');
  return createClient(URL, KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

liveDescribe('reconcile invariant assert_balance_matches_ledger', () => {
  let client: SupabaseClient;
  let orgId: string | null = null;

  beforeAll(() => {
    client = newClient();
  });

  afterEach(async () => {
    if (orgId) await client.from('organizations').delete().eq('id', orgId);
    orgId = null;
  });

  test('returns no drift for the test org after a normal credit+debit sequence', async () => {
    const name = `reconcile-test-${randomUUID()}`;
    const { data: org } = await client.from('organizations').insert({ name }).select('id').single();
    orgId = org!.id;

    await client.rpc('credit_balance', {
      p_organization_id: orgId,
      p_amount_cents: 1000,
      p_kind: 'topup',
      p_description: 'reconcile-credit',
      p_stripe_payment_intent_id: `pi_${orgId}`,
      p_created_by_user_id: null,
    });

    await client.rpc('deduct_balance', {
      p_organization_id: orgId,
      p_amount_cents: 250,
      p_description: 'reconcile-debit',
      p_event_metadata: {
        event_type: 'ai_tokens',
        provider: 'anthropic',
        feature: 'aegis.chat',
        quantity: 100,
        unit: 'mixed_tokens',
        cost_cents_cog: 125,
        model_id: 'claude-haiku-4-5-20251001',
        idempotency_key: `reconcile-${orgId}-1`,
      },
    });

    const { data: drift, error } = await client.rpc('assert_balance_matches_ledger');
    expect(error).toBeNull();
    const driftForOrg = (drift ?? []).filter((row: any) => row.organization_id === orgId);
    expect(driftForOrg).toEqual([]);
  }, 30_000);

  test('surfaces drift when balance_cents is manually mutated outside the RPCs', async () => {
    const name = `reconcile-drift-${randomUUID()}`;
    const { data: org } = await client.from('organizations').insert({ name }).select('id').single();
    orgId = org!.id;

    await client.from('organization_billing').update({ balance_cents: 9999 }).eq('organization_id', orgId);

    const { data: drift, error } = await client.rpc('assert_balance_matches_ledger');
    expect(error).toBeNull();
    const driftForOrg = (drift ?? []).filter((row: any) => row.organization_id === orgId);
    expect(driftForOrg.length).toBe(1);
    expect(driftForOrg[0].balance_cents).toBe(9999);
    expect(driftForOrg[0].ledger_sum).toBe(500);
    expect(driftForOrg[0].drift_cents).toBe(9499);
  }, 30_000);
});
