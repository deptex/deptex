// Real-Postgres tests for the billing pipeline.
//
// Gated by SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY env vars. Skipped in
// environments without DB credentials (e.g. fork PR CI). Covers:
//
//   1. AFTER-INSERT trigger (signup_grant idempotent via partial unique)
//   2. deduct_balance concurrent race — FOR UPDATE serializes
//   3. Per-org idempotency_key uniqueness
//   4. credit_balance soft-fail when organization_billing row missing
//   5. Ledger invariant — random credits + debits + assert_balance_matches_ledger
//
// The FOR UPDATE mutation anti-test (canonical "prove the lock is
// load-bearing") lives in backend/scripts/loadtest-deduct-balance.ts and
// runs manually pre-cutover; it requires ad-hoc DDL that the Supabase
// service-role client cannot issue safely.

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { randomUUID } from 'crypto';
import * as path from 'path';

require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const hasDb = Boolean(URL && KEY);
const liveDescribe = hasDb ? describe : describe.skip;

function newClient(): SupabaseClient {
  if (!URL || !KEY) {
    throw new Error('SUPABASE_URL/KEY missing — should never be called when hasDb=false');
  }
  return createClient(URL, KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

async function createTestOrg(client: SupabaseClient): Promise<string> {
  const name = `billing-test-${randomUUID()}`;
  const { data, error } = await client
    .from('organizations')
    .insert({ name })
    .select('id')
    .single();
  if (error || !data) throw new Error(`createTestOrg failed: ${error?.message}`);
  return data.id;
}

async function deleteTestOrg(client: SupabaseClient, orgId: string): Promise<void> {
  await client.from('organizations').delete().eq('id', orgId);
}

async function setBalance(client: SupabaseClient, orgId: string, cents: number): Promise<void> {
  await client.from('organization_billing').update({ balance_cents: cents }).eq('organization_id', orgId);
}

async function getBalance(client: SupabaseClient, orgId: string): Promise<number | null> {
  const { data } = await client
    .from('organization_billing')
    .select('balance_cents')
    .eq('organization_id', orgId)
    .single();
  return data?.balance_cents ?? null;
}

async function getSignupGrantCount(client: SupabaseClient, orgId: string): Promise<number> {
  const { count } = await client
    .from('billing_transactions')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId)
    .eq('kind', 'signup_grant');
  return count ?? 0;
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

liveDescribe('billing trigger trg_organizations_after_insert_billing', () => {
  let client: SupabaseClient;
  let orgId: string | null = null;

  beforeAll(() => {
    client = newClient();
  });

  afterEach(async () => {
    if (orgId) await deleteTestOrg(client, orgId);
    orgId = null;
  });

  test('happy path inserts organization_billing row + signup_grant ledger entry', async () => {
    orgId = await createTestOrg(client);

    expect(await getBalance(client, orgId)).toBe(500);
    expect(await getSignupGrantCount(client, orgId)).toBe(1);
  });

  test('partial unique index prevents double signup_grant', async () => {
    orgId = await createTestOrg(client);

    const { error } = await client.from('billing_transactions').insert({
      organization_id: orgId,
      kind: 'signup_grant',
      amount_cents: 500,
      description: 'attempted second grant',
    });

    expect(error).not.toBeNull();
    expect(error!.code).toBe('23505');
    expect(await getSignupGrantCount(client, orgId)).toBe(1);
  });

  test('credit_balance soft-fails to log+auto-create on missing billing row', async () => {
    orgId = await createTestOrg(client);
    await client.from('organization_billing').delete().eq('organization_id', orgId);

    const { data: newBalance, error } = await client.rpc('credit_balance', {
      p_organization_id: orgId,
      p_amount_cents: 1000,
      p_kind: 'topup',
      p_description: 'soft-fail recovery test',
      p_stripe_payment_intent_id: null,
      p_created_by_user_id: null,
    });
    expect(error).toBeNull();
    expect(newBalance).toBe(1000);
  });
});

liveDescribe('billing deduct_balance race safety', () => {
  let client: SupabaseClient;
  let orgId: string | null = null;

  beforeAll(() => {
    client = newClient();
  });

  afterEach(async () => {
    if (orgId) await deleteTestOrg(client, orgId);
    orgId = null;
  });

  test('FOR UPDATE prevents double-spend when balance covers exactly one deduct', async () => {
    orgId = await createTestOrg(client);
    await setBalance(client, orgId, 100);

    const c1 = newClient();
    const c2 = newClient();
    const meta1 = { ...baseMetadata, idempotency_key: `race-${orgId}-1` };
    const meta2 = { ...baseMetadata, idempotency_key: `race-${orgId}-2` };

    const [r1, r2] = await Promise.all([
      c1.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: 100,
        p_description: 'race-1',
        p_event_metadata: meta1,
      }),
      c2.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: 100,
        p_description: 'race-2',
        p_event_metadata: meta2,
      }),
    ]);

    const successes = [r1, r2].filter((r) => r.data !== null && r.error === null);
    expect(successes).toHaveLength(1);
    expect(await getBalance(client, orgId!)).toBe(0);
  }, 15_000);

  test('FOR UPDATE serializes; both succeed when balance covers both', async () => {
    orgId = await createTestOrg(client);
    await setBalance(client, orgId, 200);

    const c1 = newClient();
    const c2 = newClient();
    const meta1 = { ...baseMetadata, idempotency_key: `ser-${orgId}-1` };
    const meta2 = { ...baseMetadata, idempotency_key: `ser-${orgId}-2` };

    const [r1, r2] = await Promise.all([
      c1.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: 100,
        p_description: 'ser-1',
        p_event_metadata: meta1,
      }),
      c2.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: 100,
        p_description: 'ser-2',
        p_event_metadata: meta2,
      }),
    ]);

    expect(r1.error).toBeNull();
    expect(r2.error).toBeNull();
    expect(r1.data).not.toBeNull();
    expect(r2.data).not.toBeNull();
    expect(await getBalance(client, orgId!)).toBe(0);
  }, 15_000);

  test('per-org idempotency_key collision: only one deduction lands', async () => {
    orgId = await createTestOrg(client);
    await setBalance(client, orgId, 1000);

    const c1 = newClient();
    const c2 = newClient();
    const sharedKey = `shared-${orgId}`;

    const r1 = await c1.rpc('deduct_balance', {
      p_organization_id: orgId,
      p_amount_cents: 50,
      p_description: 'idem-1',
      p_event_metadata: { ...baseMetadata, idempotency_key: sharedKey },
    });
    expect(r1.error).toBeNull();
    expect(r1.data).toBe(950);

    const r2 = await c2.rpc('deduct_balance', {
      p_organization_id: orgId,
      p_amount_cents: 50,
      p_description: 'idem-2',
      p_event_metadata: { ...baseMetadata, idempotency_key: sharedKey },
    });
    expect(r2.error).not.toBeNull();
    expect(r2.error!.code).toBe('23505');
    expect(await getBalance(client, orgId!)).toBe(950);
  }, 15_000);
});

liveDescribe('billing ledger invariant', () => {
  let client: SupabaseClient;
  let orgId: string | null = null;

  beforeAll(() => {
    client = newClient();
  });

  afterEach(async () => {
    if (orgId) await deleteTestOrg(client, orgId);
    orgId = null;
  });

  test('after random credits + debits, drift is zero for the test org', async () => {
    orgId = await createTestOrg(client);
    await setBalance(client, orgId, 0);
    await client.from('billing_transactions').delete().eq('organization_id', orgId);

    for (let i = 0; i < 10; i++) {
      const credit = 100 + Math.floor(Math.random() * 100);
      const { error: creditErr } = await client.rpc('credit_balance', {
        p_organization_id: orgId,
        p_amount_cents: credit,
        p_kind: 'topup',
        p_description: `inv-credit-${i}`,
        p_stripe_payment_intent_id: `pi_inv_${orgId}_${i}`,
        p_created_by_user_id: null,
      });
      expect(creditErr).toBeNull();

      const debit = 50 + Math.floor(Math.random() * 50);
      const { error: debitErr } = await client.rpc('deduct_balance', {
        p_organization_id: orgId,
        p_amount_cents: debit,
        p_description: `inv-debit-${i}`,
        p_event_metadata: { ...baseMetadata, idempotency_key: `inv-${orgId}-${i}` },
      });
      expect(debitErr).toBeNull();
    }

    const { data: drift, error } = await client.rpc('assert_balance_matches_ledger');
    expect(error).toBeNull();
    const driftForOrg = (drift ?? []).filter((row: any) => row.organization_id === orgId);
    expect(driftForOrg).toEqual([]);
  }, 30_000);
});
