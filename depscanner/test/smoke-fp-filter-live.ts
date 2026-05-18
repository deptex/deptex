/**
 * Live smoke test for the FP filter against the real DeepInfra Qwen API.
 *
 * Drives the full filterFlow path on flows we KNOW the engine emits from the
 * SQL-injection validation fixture (express/sql-injection-vuln). Asserts:
 *   - the request actually went out (real fetch, not mocked)
 *   - the model returned a valid verdict (kept|rejected) with confidence
 *   - per-call cost is cents-fractions
 *   - ai_usage_logs row was written with provider='openai' + model=Qwen
 *
 * Reads DEEPINFRA_API_KEY from process.env. Exits non-zero on any failure.
 * Total spend per run: ≤$0.001.
 *
 * Run: tsx test/smoke-fp-filter-live.ts
 */

import * as path from 'path';
import { config as dotenv } from 'dotenv';
import { createPGLiteStorage } from '../src/storage';
import {
  filterFlow,
  createUsageLogger,
} from '../src/taint-engine/fp-filter';
import { loadSpec, propagate } from '../src/taint-engine';
import type { FrameworkSpec } from '../src/taint-engine';

dotenv({ path: path.resolve(__dirname, '../../backend/.env') });

const ORG_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const PROJECT_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const USER_ID = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const RUN_ID = 'smoke_fp_live_001';

let failures = 0;
function assert(cond: unknown, msg: string): void {
  if (cond) console.log(`  ok: ${msg}`);
  else { console.error(`  FAIL: ${msg}`); failures++; }
}

async function main(): Promise<void> {
  const apiKey = process.env.DEEPINFRA_API_KEY;
  if (!apiKey) {
    console.error('DEEPINFRA_API_KEY not in env; skipping live smoke');
    process.exit(2);
  }
  console.log('=== FP filter live smoke (DeepInfra Qwen) ===\n');

  // Step 1: get real flows from a known vuln fixture.
  const fixtureRoot = path.resolve(
    __dirname,
    './taint-engine/fixtures/express-vulns/sql-injection-vuln',
  );
  const expressSpec: FrameworkSpec = loadSpec(
    path.resolve(__dirname, '../src/taint-engine/framework-models/express.yaml'),
  );
  const stdlibSpec: FrameworkSpec = loadSpec(
    path.resolve(__dirname, '../src/taint-engine/framework-models/node-stdlib.yaml'),
  );
  const propagation = await propagate({
    rootDir: fixtureRoot,
    specs: [expressSpec, stdlibSpec],
    onWarn: (m) => console.error(`  [warn] ${m}`),
  });
  console.log(`  fixture emitted ${propagation.flows.length} flow(s)`);
  assert(propagation.flows.length > 0, 'fixture must emit ≥1 flow');
  if (propagation.flows.length === 0) process.exit(1);

  const flow = propagation.flows[0];
  console.log(`  flow vuln_class=${flow.vuln_class} engine_confidence=${flow.engine_confidence}`);

  // Step 2: PGLite storage so usage logs land somewhere.
  const storage = await createPGLiteStorage();
  await storage.from('organizations').insert({ id: ORG_ID, name: 'smoke', created_at: new Date().toISOString() });
  await storage.from('users').insert({ id: USER_ID, created_at: new Date().toISOString() });

  const logger = createUsageLogger(
    storage,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
    (m) => console.error(`  [logger warn] ${m}`),
  );

  // Step 3: real fetch to DeepInfra.
  console.log('\n  calling DeepInfra Qwen...');
  const t0 = Date.now();
  const result = await filterFlow(
    {
      flow,
      workspaceRoot: fixtureRoot,
      apiKey,
      specs: [expressSpec, stdlibSpec],
      onWarn: (m) => console.error(`  [filter warn] ${m}`),
    },
    logger,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
  );
  const elapsed = Date.now() - t0;
  console.log(`  call completed in ${elapsed}ms`);

  // Step 4: assertions.
  assert(
    result.verdict === 'kept' ||
      result.verdict === 'rejected' ||
      result.verdict === 'kept_on_error' ||
      result.verdict === 'ai_truncated',
    `verdict in {kept, rejected, kept_on_error, ai_truncated} (got ${result.verdict})`,
  );
  if (result.verdict === 'kept_on_error' || result.verdict === 'ai_truncated') {
    console.error(`  filter errored (${result.verdict}): ${(result as any).errorMessage}`);
    failures++;
  } else {
    console.log(`  verdict=${result.verdict}`);
    console.log(`  verdict_confidence=${result.verdict_confidence}`);
    console.log(`  verdict_reasoning="${result.verdict_reasoning}"`);
    console.log(`  sanitization=${JSON.stringify(result.sanitization)}`);
    console.log(`  endpoint=${JSON.stringify(result.endpoint)}`);
    console.log(`  inputTokens=${result.inputTokens} outputTokens=${result.outputTokens}`);
    console.log(`  costUsd=$${result.costUsd.toFixed(6)}`);
    assert(result.costUsd > 0, `costUsd > 0 (got ${result.costUsd})`);
    assert(result.costUsd < 0.01, `costUsd < $0.01 per call (got ${result.costUsd})`);
    assert(typeof result.verdict_reasoning === 'string', 'verdict_reasoning is a string');
  }

  // Step 5: confirm ai_usage_logs row landed.
  const { data: logRow } = await storage
    .from('ai_usage_logs')
    .select('feature, provider, model, input_tokens, output_tokens, estimated_cost, success')
    .eq('feature', 'taint_engine_fp_filter')
    .maybeSingle();
  console.log(`\n  ai_usage_logs row:`, logRow);
  assert(logRow !== null, 'ai_usage_logs row was written');
  if (logRow) {
    assert((logRow as any).provider === 'openai', `provider=openai (got ${(logRow as any).provider})`);
    assert(
      (logRow as any).model === 'Qwen/Qwen3-235B-A22B-Instruct-2507',
      `model=Qwen/Qwen3-235B-A22B-Instruct-2507 (got ${(logRow as any).model})`,
    );
    assert((logRow as any).input_tokens > 0, 'input_tokens > 0');
    assert((logRow as any).output_tokens > 0, 'output_tokens > 0');
  }

  console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'}: ${failures} failure(s)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('smoke threw:', err);
  process.exit(1);
});
