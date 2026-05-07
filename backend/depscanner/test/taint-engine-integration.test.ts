/**
 * End-to-end integration test for the Phase 26 taint-engine pipeline layer.
 *
 * Boots PGLite, loads schema.sql (which now includes the phase26 tables +
 * RPCs from the most recent npm run schema:dump), then exercises the
 * storage + circuit-breaker contracts directly:
 *
 *   1. Happy path: writeRun('completed') + writeFlows insert into the right
 *      tables with reachability_source='taint_engine', and the row is
 *      visible to a query.
 *   2. Initial circuit breaker state: shouldRun=true with no prior runs.
 *   3. Threshold trip: injecting 5 failed runs into the rolling window flips
 *      shouldRun to false with blockedReason='failure_rate'.
 *   4. Killswitch: maybeEngageKillswitch flips taint_engine_settings.killswitch_active
 *      and the breaker reports blockedReason='killswitch' on the next call.
 *   5. Idempotency: writeRun is upsert-safe on (project_id, extraction_run_id).
 *
 * This deliberately does NOT exercise the propagator (covered by the M2/M3
 * unit tests). The integration value here is proving the persistence
 * contract holds against a Postgres-shaped store.
 *
 * Run: npx tsx test/taint-engine-integration.test.ts
 */

import { createPGLiteStorage } from '../src/storage';
import {
  writeFlows,
  writeRun,
  checkCircuitBreaker,
  maybeEngageKillswitch,
  shouldRunForRollout,
} from '../src/taint-engine';
import type { Flow } from '../src/taint-engine';

let failures = 0;
let passes = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passes++;
  }
}

const ORG_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const PROJECT_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const RUN_ID = 'run_taint_engine_e2e_001';

function makeFlow(overrides: Partial<Flow> = {}): Flow {
  return {
    id: 'flow1',
    vuln_class: 'command_injection',
    taint_kind: 'http_input',
    entry_point_file: 'src/server.ts',
    entry_point_line: 4,
    entry_point_method: 'handler',
    entry_point_pattern: 'req.body.*',
    sink_file: 'src/server.ts',
    sink_line: 5,
    sink_method: 'child_process.exec',
    sink_pattern: 'child_process.exec(*)',
    sink_is_external: false,
    flow_nodes: [
      { filePath: 'src/server.ts', line: 4, column: 21, label: 'req.body.cmd', kind: 'source' },
      { filePath: 'src/server.ts', line: 5, column: 3, label: 'child_process.exec', kind: 'sink' },
    ],
    flow_length: 2,
    source_description: 'Express request body',
    sink_description: 'shell exec',
    engine_confidence: 0.9,
    ...overrides,
  };
}

async function seedOrgAndProject(storage: Awaited<ReturnType<typeof createPGLiteStorage>>) {
  await storage.from('organizations').insert({
    id: ORG_ID,
    name: 'taint-engine-test-org',
    created_at: new Date().toISOString(),
  });
  await storage.from('projects').insert({
    id: PROJECT_ID,
    organization_id: ORG_ID,
    name: 'taint-engine-test-project',
    active_extraction_run_id: RUN_ID,
    created_at: new Date().toISOString(),
  });
}

async function injectFailedRuns(
  storage: Awaited<ReturnType<typeof createPGLiteStorage>>,
  count: number,
): Promise<void> {
  for (let i = 0; i < count; i++) {
    const result = await writeRun(storage, {
      projectId: PROJECT_ID,
      organizationId: ORG_ID,
      extractionRunId: `run_failed_${i}`,
      status: 'failed',
      errorCode: 'unexpected',
      errorMessage: `synthetic failure ${i}`,
      totalMs: 100,
    });
    if (!result.ok) throw new Error(`failed seed ${i}: ${result.error}`);
  }
}

async function testHappyPath(storage: Awaited<ReturnType<typeof createPGLiteStorage>>) {
  console.log('\n[test] happy path: writeRun + writeFlows persist');
  const runResult = await writeRun(storage, {
    projectId: PROJECT_ID,
    organizationId: ORG_ID,
    extractionRunId: RUN_ID,
    status: 'completed',
    callgraphBuildMs: 1500,
    taintPropagationMs: 25,
    totalMs: 1700,
    flowsEmitted: 1,
    frameworksDetected: ['express'],
    isTypedJsProject: true,
    typedFilesPct: 95.5,
  });
  assert(runResult.ok, `writeRun returns ok (err=${runResult.error ?? 'none'})`);

  const flowResult = await writeFlows(storage, {
    projectId: PROJECT_ID,
    extractionRunId: RUN_ID,
    flows: [makeFlow()],
  });
  assert(flowResult.attempted === 1, 'writeFlows attempted=1');
  assert(flowResult.written === 1, `writeFlows written=1 (errors: ${flowResult.errors.join('; ') || 'none'})`);

  // Verify the run row exists with the expected status.
  const { data: runRows, error: runErr } = await storage
    .from('taint_engine_runs')
    .select('status, flows_emitted, frameworks_detected, is_typed_js_project')
    .eq('extraction_run_id', RUN_ID);
  assert(!runErr, `taint_engine_runs select ok (err=${runErr?.message ?? 'none'})`);
  const runRow = runRows?.[0] as {
    status: string;
    flows_emitted: number;
    frameworks_detected: string[];
    is_typed_js_project: boolean;
  } | undefined;
  assert(runRow?.status === 'completed', `run status persisted as 'completed' (got ${runRow?.status})`);
  assert(runRow?.flows_emitted === 1, `flows_emitted persisted = 1 (got ${runRow?.flows_emitted})`);
  assert(runRow?.is_typed_js_project === true, 'is_typed_js_project persisted = true');

  // Verify the flow landed with the right reachability_source.
  const { data: flowRows, error: flowErr } = await storage
    .from('project_reachable_flows')
    .select('reachability_source, sink_method, entry_point_tag')
    .eq('extraction_run_id', RUN_ID);
  assert(!flowErr, `project_reachable_flows select ok (err=${flowErr?.message ?? 'none'})`);
  const flowRow = flowRows?.[0] as {
    reachability_source: string;
    sink_method: string;
    entry_point_tag: string;
  } | undefined;
  assert(
    flowRow?.reachability_source === 'taint_engine',
    `flow has reachability_source='taint_engine' (got ${flowRow?.reachability_source})`,
  );
  assert(flowRow?.sink_method === 'child_process.exec', 'sink_method round-trips');
  assert(
    flowRow?.entry_point_tag === 'framework-input:PUBLIC_UNAUTH',
    `entry_point_tag set for EPD classifier (got ${flowRow?.entry_point_tag})`,
  );
}

async function testInitialBreaker(storage: Awaited<ReturnType<typeof createPGLiteStorage>>) {
  console.log('\n[test] initial circuit breaker: shouldRun=true (no failures yet)');
  // We have one completed run from the happy path. Breaker should still allow.
  const state = await checkCircuitBreaker(storage, ORG_ID);
  assert(state.shouldRun, 'breaker shouldRun=true');
  assert(!state.killswitchActive, 'killswitch initially inactive');
}

async function testThresholdTrip(storage: Awaited<ReturnType<typeof createPGLiteStorage>>) {
  console.log('\n[test] threshold trip: 5 failed runs flips shouldRun=false');
  await injectFailedRuns(storage, 5);
  const state = await checkCircuitBreaker(storage, ORG_ID);
  assert(state.recentRuns >= 5, `recentRuns >= 5 (got ${state.recentRuns})`);
  assert(state.recentFailures >= 5, `recentFailures >= 5 (got ${state.recentFailures})`);
  assert(state.failurePct > 5, `failurePct > 5% (got ${state.failurePct})`);
  assert(!state.shouldRun, 'breaker shouldRun=false');
  assert(state.blockedReason === 'failure_rate', `blockedReason=failure_rate (got ${state.blockedReason})`);
}

async function testKillswitchEngages(storage: Awaited<ReturnType<typeof createPGLiteStorage>>) {
  console.log('\n[test] maybeEngageKillswitch flips the switch when threshold tripped');
  const engaged = await maybeEngageKillswitch(storage, ORG_ID, 'test reason');
  assert(engaged, 'maybeEngageKillswitch returned true');

  const state = await checkCircuitBreaker(storage, ORG_ID);
  assert(state.killswitchActive, 'killswitch is now active');
  assert(state.blockedReason === 'killswitch', `blockedReason=killswitch (got ${state.blockedReason})`);

  // Calling again should be a no-op (already engaged).
  const engagedAgain = await maybeEngageKillswitch(storage, ORG_ID, 'test reason 2');
  assert(!engagedAgain, 'second maybeEngageKillswitch is a no-op');
}

async function testWriteRunIdempotent(storage: Awaited<ReturnType<typeof createPGLiteStorage>>) {
  console.log('\n[test] writeRun is upsert-idempotent on (project_id, extraction_run_id)');
  const r1 = await writeRun(storage, {
    projectId: PROJECT_ID,
    organizationId: ORG_ID,
    extractionRunId: 'idempotency_run',
    status: 'running',
  });
  assert(r1.ok, `first writeRun ok (err=${r1.error ?? 'none'})`);

  const r2 = await writeRun(storage, {
    projectId: PROJECT_ID,
    organizationId: ORG_ID,
    extractionRunId: 'idempotency_run',
    status: 'completed',
    totalMs: 200,
    flowsEmitted: 3,
  });
  assert(r2.ok, `second writeRun ok (err=${r2.error ?? 'none'})`);

  const { data: rows } = await storage
    .from('taint_engine_runs')
    .select('status, flows_emitted')
    .eq('extraction_run_id', 'idempotency_run');
  assert(rows?.length === 1, `exactly one row for the run id (got ${rows?.length})`);
  const row = rows?.[0] as { status: string; flows_emitted: number } | undefined;
  assert(row?.status === 'completed', `status overwritten to 'completed' (got ${row?.status})`);
  assert(row?.flows_emitted === 3, `flows_emitted overwritten to 3 (got ${row?.flows_emitted})`);
}

async function testFlowSignatureHashDeterminism(
  storage: Awaited<ReturnType<typeof createPGLiteStorage>>,
) {
  console.log('\n[test] flow_signature_hash is deterministic + osv_id round-trips');
  const HASH_RUN_A = 'run_hash_determinism_a';
  const HASH_RUN_B = 'run_hash_determinism_b';
  const CVE = 'CVE-2021-23337';
  const workspaceRoot = '/repo/work';
  // Same logical flow shape under different extraction_run_ids — the hash
  // must be stable across the two runs because writeFlows canonicalizes
  // file paths against workspaceRoot before hashing.
  const flow = makeFlow({
    osv_id: CVE,
    entry_point_file: `${workspaceRoot}/src/server.ts`,
    sink_file: `${workspaceRoot}/src/server.ts`,
  });

  await writeRun(storage, {
    projectId: PROJECT_ID,
    organizationId: ORG_ID,
    extractionRunId: HASH_RUN_A,
    status: 'completed',
  });
  await writeRun(storage, {
    projectId: PROJECT_ID,
    organizationId: ORG_ID,
    extractionRunId: HASH_RUN_B,
    status: 'completed',
  });

  const a = await writeFlows(storage, {
    projectId: PROJECT_ID,
    extractionRunId: HASH_RUN_A,
    flows: [flow],
    workspaceRoot,
  });
  const b = await writeFlows(storage, {
    projectId: PROJECT_ID,
    extractionRunId: HASH_RUN_B,
    flows: [flow],
    workspaceRoot,
  });
  assert(a.written === 1 && b.written === 1, 'both writeFlows calls succeeded');

  const { data: rowsA } = await storage
    .from('project_reachable_flows')
    .select('flow_signature_hash, osv_id')
    .eq('extraction_run_id', HASH_RUN_A);
  const { data: rowsB } = await storage
    .from('project_reachable_flows')
    .select('flow_signature_hash, osv_id')
    .eq('extraction_run_id', HASH_RUN_B);

  const hashA = (rowsA?.[0] as { flow_signature_hash: string } | undefined)?.flow_signature_hash;
  const hashB = (rowsB?.[0] as { flow_signature_hash: string } | undefined)?.flow_signature_hash;

  assert(typeof hashA === 'string' && /^[0-9a-f]{64}$/i.test(hashA), `hashA is 64-char hex (got: ${hashA})`);
  assert(typeof hashB === 'string' && /^[0-9a-f]{64}$/i.test(hashB), `hashB is 64-char hex (got: ${hashB})`);
  assert(hashA === hashB, `hashA == hashB (got: ${hashA} vs ${hashB})`);
  // osv_id round-trips so the classifier's confirmed-tier promotion can match.
  const osvA = (rowsA?.[0] as { osv_id: string } | undefined)?.osv_id;
  assert(osvA === CVE, `osv_id round-trips through the DB write (got: ${osvA})`);
}

async function testRolloutGate() {
  console.log('\n[test] shouldRunForRollout env var behavior');
  // Set explicitly to 0 — never run.
  assert(!shouldRunForRollout({ DEPTEX_TAINT_ENGINE_ROLLOUT_PCT: '0' }), 'pct=0 → false');
  // Set to 100 — always run.
  assert(shouldRunForRollout({ DEPTEX_TAINT_ENGINE_ROLLOUT_PCT: '100' }), 'pct=100 → true');
  // Production with no env var — off by default.
  assert(!shouldRunForRollout({ NODE_ENV: 'production' }), 'production + unset → false');
  // Non-production with no env var — on.
  assert(shouldRunForRollout({}), 'unset env → true (test/dev mode)');
}

async function main() {
  const t0 = Date.now();
  console.log('Booting PGLiteStorage...');
  const storage = await createPGLiteStorage();
  console.log(`  booted in ${Date.now() - t0}ms`);

  await seedOrgAndProject(storage);
  await testHappyPath(storage);
  await testInitialBreaker(storage);
  await testThresholdTrip(storage);
  await testKillswitchEngages(storage);
  await testWriteRunIdempotent(storage);
  await testFlowSignatureHashDeterminism(storage);
  await testRolloutGate();

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
