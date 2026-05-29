// Manual billing reconciliation.
//
//   npm run reconcile:billing          — report drift; exit 0 always
//   npm run reconcile:billing -- --assert  — exit non-zero if any drift
//
// Two checks:
//   1. assert_balance_matches_ledger() — sum(billing_transactions.amount_cents)
//      must equal organization_billing.balance_cents for every org. Any drift
//      means a non-RPC write hit the balance OR a ledger insert was skipped.
//   2. (Future v1.1) scan_jobs LEFT JOIN billing_transactions on
//      attribution_resource_id — completed scans without a worker_minutes
//      event indicate worker meter-event POSTs that silently dropped. The
//      v1 stub flags counts only; emission left to v1.1 backlog.
//
// Wired into CI via `.github/workflows/test.yml` post-jest step so a prod-
// shape ledger drift fails the build.

import { createClient } from '@supabase/supabase-js';
import * as path from 'path';

require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!URL || !KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in backend/.env');
  process.exit(2);
}

const ASSERT = process.argv.includes('--assert');

interface DriftRow {
  organization_id: string;
  balance_cents: number;
  ledger_sum: number;
  drift_cents: number;
}

async function main(): Promise<number> {
  const supabase = createClient(URL!, KEY!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  console.log(`[reconcile-billing] running against ${URL}`);
  console.log(`[reconcile-billing] assert mode: ${ASSERT ? 'ON' : 'OFF'}`);

  const { data: drift, error } = await supabase.rpc('assert_balance_matches_ledger');
  if (error) {
    console.error('[reconcile-billing] RPC failed:', error.message);
    return 2;
  }

  const rows = (drift ?? []) as DriftRow[];
  if (rows.length === 0) {
    console.log('[reconcile-billing] OK — no drift detected across any org');
    return 0;
  }

  console.error(`[reconcile-billing] DRIFT — ${rows.length} org(s) have ledger mismatch:`);
  for (const r of rows) {
    console.error(
      `  org=${r.organization_id}  balance=${r.balance_cents}  ledger_sum=${r.ledger_sum}  drift=${r.drift_cents}`,
    );
  }

  const { data: missingScans, error: scanErr } = await supabase
    .from('scan_jobs')
    .select('id, organization_id, type, status, duration_seconds')
    .eq('status', 'completed')
    .not('duration_seconds', 'is', null)
    .limit(100);

  if (!scanErr && missingScans && missingScans.length > 0) {
    let withoutMeter = 0;
    for (const scan of missingScans) {
      const { count } = await supabase
        .from('billing_transactions')
        .select('id', { count: 'exact', head: true })
        .eq('attribution_resource_type', 'scan_job')
        .eq('attribution_resource_id', scan.id);
      if ((count ?? 0) === 0) withoutMeter++;
    }
    if (withoutMeter > 0) {
      console.warn(
        `[reconcile-billing] ${withoutMeter}/${missingScans.length} sampled completed scans have no worker_minutes meter event`,
      );
    }
  }

  return ASSERT ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[reconcile-billing] unhandled error', err);
    process.exit(2);
  });
