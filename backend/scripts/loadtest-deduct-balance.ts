// Load test for deduct_balance RPC. Validates p99 < 50ms gate.
//
//   npm run loadtest:deduct                 — 50 conns × 10k calls
//   npm run loadtest:deduct -- --conns=20   — fewer connections
//   npm run loadtest:deduct -- --calls=1000 — fewer calls per connection
//
// Creates a single test org with $1M balance, fires N×M concurrent deducts,
// reports p50 / p95 / p99 latency. Fails (exit 1) if p99 >= 50ms.
//
// IMPORTANT: this hits real Supabase. Don't run against prod during business
// hours. The script deletes the test org at the end.

import { createClient } from '@supabase/supabase-js';
import * as path from 'path';
import { randomUUID } from 'crypto';

require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!URL || !KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(2);
}

const ARG_CONNS = parseArg('--conns', 50);
const ARG_CALLS = parseArg('--calls', 10_000);
const P99_GATE_MS = 50;

function parseArg(name: string, defaultVal: number): number {
  const arg = process.argv.find((a) => a.startsWith(`${name}=`));
  if (!arg) return defaultVal;
  const v = Number(arg.split('=')[1]);
  if (!Number.isFinite(v) || v <= 0) return defaultVal;
  return v;
}

function newClient() {
  return createClient(URL!, KEY!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function main(): Promise<number> {
  const setup = newClient();
  const { data: org, error: orgErr } = await setup
    .from('organizations')
    .insert({ name: `loadtest-deduct-${randomUUID()}` })
    .select('id')
    .single();
  if (orgErr || !org) {
    console.error('Failed to create test org', orgErr);
    return 2;
  }
  const orgId = org.id;

  try {
    await setup
      .from('organization_billing')
      .update({ balance_cents: ARG_CONNS * ARG_CALLS * 10 })
      .eq('organization_id', orgId);
    console.log(
      `[loadtest] org=${orgId} balance=${(ARG_CONNS * ARG_CALLS * 10).toLocaleString()} conns=${ARG_CONNS} calls/conn=${ARG_CALLS}`,
    );

    const baseMetadata = {
      event_type: 'ai_tokens',
      provider: 'anthropic',
      feature: 'loadtest.deduct',
      quantity: 1,
      unit: 'mixed_tokens',
      cost_cents_cog: 1,
      model_id: 'claude-haiku-4-5-20251001',
    };

    const allDurations: number[] = [];
    const t0 = Date.now();

    await Promise.all(
      Array.from({ length: ARG_CONNS }, (_, i) => (async () => {
        const client = newClient();
        for (let j = 0; j < ARG_CALLS; j++) {
          const start = performance.now();
          const { error } = await client.rpc('deduct_balance', {
            p_organization_id: orgId,
            p_amount_cents: 1,
            p_description: 'loadtest',
            p_event_metadata: { ...baseMetadata, idempotency_key: `lt-${orgId}-${i}-${j}` },
          });
          const dur = performance.now() - start;
          allDurations.push(dur);
          if (error) {
            console.error(`[loadtest] conn=${i} call=${j} error`, error);
            break;
          }
        }
      })()),
    );

    const elapsedMs = Date.now() - t0;
    const sorted = allDurations.sort((a, b) => a - b);
    const p50 = percentile(sorted, 50);
    const p95 = percentile(sorted, 95);
    const p99 = percentile(sorted, 99);
    const throughput = (allDurations.length / elapsedMs) * 1000;

    console.log(`[loadtest] ${allDurations.length} calls in ${elapsedMs}ms (${throughput.toFixed(0)}/sec)`);
    console.log(`[loadtest] p50=${p50.toFixed(1)}ms  p95=${p95.toFixed(1)}ms  p99=${p99.toFixed(1)}ms`);
    console.log(`[loadtest] gate: p99 < ${P99_GATE_MS}ms`);

    if (p99 >= P99_GATE_MS) {
      console.error(`[loadtest] FAIL — p99 ${p99.toFixed(1)}ms exceeds ${P99_GATE_MS}ms`);
      return 1;
    }
    console.log('[loadtest] PASS');
    return 0;
  } finally {
    await setup.from('organizations').delete().eq('id', orgId);
    console.log(`[loadtest] cleaned up org ${orgId}`);
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[loadtest] unhandled error', err);
    process.exit(2);
  });
