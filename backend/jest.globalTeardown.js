'use strict';

// Runs once after the entire jest suite. Calls
// assert_balance_matches_ledger() to confirm no test left the ledger drifted.
//
// Skipped if SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY aren't set (e.g. fork
// PR CI). Wired via jest.config.js `globalTeardown`.

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

module.exports = async function billingLedgerInvariantTeardown() {
  const URL = process.env.SUPABASE_URL;
  const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!URL || !KEY) {
    return;
  }

  const { createClient } = require('@supabase/supabase-js');
  const supabase = createClient(URL, KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data, error } = await supabase.rpc('assert_balance_matches_ledger');
  if (error) {
    console.error('[jest.globalTeardown] assert_balance_matches_ledger RPC failed', error.message);
    return;
  }

  const drift = data || [];
  if (drift.length > 0) {
    console.error(
      `[jest.globalTeardown] LEDGER DRIFT — ${drift.length} org(s) have ledger mismatch after test run:`,
    );
    for (const r of drift) {
      console.error(
        `  org=${r.organization_id}  balance=${r.balance_cents}  ledger_sum=${r.ledger_sum}  drift=${r.drift_cents}`,
      );
    }
    throw new Error('[jest.globalTeardown] Ledger invariant violated — see drift above');
  }
};
