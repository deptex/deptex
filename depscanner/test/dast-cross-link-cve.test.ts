/**
 * confirmPdvsFromDastRun wrapper tests.
 *
 * The RPC's SQL behavior is exhaustively covered by
 * test/dast-v2-1c-migration-pglite.ts. This file tests the TypeScript wrapper:
 * argument shape, result mapping, and the never-throw-on-error contract.
 *
 * Run: npx tsx test/dast-cross-link-cve.test.ts
 */

import { confirmPdvsFromDastRun } from '../src/dast/cross-link-cve';
import type { Storage } from '../src/storage';

let failures = 0;
let passed = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passed++;
  }
}

interface RpcCall {
  name: string;
  args: Record<string, unknown>;
}

/** Minimal Storage stub exposing only `.rpc()`, which is all the wrapper uses. */
function fakeStorage(response: { data: unknown; error: { message: string } | null }): {
  storage: Storage;
  calls: RpcCall[];
} {
  const calls: RpcCall[] = [];
  const storage = {
    rpc: async (name: string, args: Record<string, unknown>) => {
      calls.push({ name, args });
      return response;
    },
  } as unknown as Storage;
  return { storage, calls };
}

const FLIP_ROWS = [
  { pdv_id: 'p1', osv_id: 'CVE-2017-12615', prior_reachability_level: 'module', new_reachability_level: 'confirmed' },
  { pdv_id: 'p2', osv_id: 'CVE-2019-10744', prior_reachability_level: 'function', new_reachability_level: 'confirmed' },
];

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('confirmPdvsFromDastRun wrapper tests\n');

  console.log('[1] success — flips mapped, RPC called with the right args');
  {
    const { storage, calls } = fakeStorage({ data: FLIP_ROWS, error: null });
    const result = await confirmPdvsFromDastRun(storage, 'org-1', 'proj-1', 'dast_run_abc');
    assert(result.confirmed_count === 2, `[1] confirmed_count = 2 (got ${result.confirmed_count})`);
    assert(result.flips.length === 2, `[1] flips array length 2`);
    assert(result.flips[0].osv_id === 'CVE-2017-12615', `[1] flip osv_id mapped through`);
    assert(calls.length === 1 && calls[0].name === 'confirm_pdvs_from_dast_run', `[1] RPC name correct`);
    assert(
      calls[0].args.p_project_id === 'proj-1' && calls[0].args.p_dast_run_id === 'dast_run_abc',
      `[1] RPC args: p_project_id + p_dast_run_id passed`,
    );
  }

  console.log('\n[2] empty result — zero flips, no error');
  {
    const { storage } = fakeStorage({ data: [], error: null });
    const result = await confirmPdvsFromDastRun(storage, 'org-1', 'proj-1', 'dast_run_empty');
    assert(result.confirmed_count === 0 && result.flips.length === 0, `[2] empty data → zero result`);
    assert(result.rpc_failed === false, `[2] clean no-match → rpc_failed false`);
  }

  console.log('\n[3] RPC error — returns zero result, never throws');
  {
    const { storage } = fakeStorage({ data: null, error: { message: 'P0001: no Nuclei findings' } });
    let threw = false;
    let result;
    try {
      result = await confirmPdvsFromDastRun(storage, 'org-1', 'proj-1', 'dast_run_err');
    } catch {
      threw = true;
    }
    assert(!threw, `[3] wrapper does not throw on RPC error`);
    assert(
      result != null && result.confirmed_count === 0 && result.flips.length === 0,
      `[3] RPC error → zero result`,
    );
    assert(
      result != null && result.rpc_failed === true,
      `[3] RPC error → rpc_failed true (distinct from a clean no-match)`,
    );
  }

  console.log('\n[4] null data with no error — treated as zero, not a crash');
  {
    const { storage } = fakeStorage({ data: null, error: null });
    const result = await confirmPdvsFromDastRun(storage, 'org-1', 'proj-1', 'dast_run_null');
    assert(result.confirmed_count === 0, `[4] null data → confirmed_count 0`);
    assert(result.rpc_failed === false, `[4] null data with no error → rpc_failed false`);
  }

  console.log(
    `\nconfirmPdvsFromDastRun tests ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms ` +
      `(${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
