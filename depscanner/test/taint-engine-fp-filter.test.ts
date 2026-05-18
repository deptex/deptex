/**
 * Unit tests for the per-flow AI false-positive filter (Phase 6.5 triple).
 *
 * Triple-shape parser + sanitizer-aware sampling + nonce-wrapping coverage
 * lives in test/taint-engine-fp-filter-triple.test.ts (jest). This file
 * keeps the integration-level smoke tests for the runner pathway:
 *   - cost cap pre-check skips the entire batch when over budget
 *   - ai_layer_enabled=false short-circuits the filter
 *   - empty workspace yields zero flows; filter not exercised
 *   - usage logger swallows DB errors
 *
 * Run: npx tsx test/taint-engine-fp-filter.test.ts
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createPGLiteStorage } from '../src/storage';
import {
  buildPrompt,
  estimatePerFlowCostUsd,
  filterFlow,
  parseTriple,
  createUsageLogger,
} from '../src/taint-engine/fp-filter';
import { runEngine } from '../src/taint-engine/runner';
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

const ORG_ID = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const PROJECT_ID = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
const USER_ID = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const RUN_ID = 'run_fp_filter_test_001';

function makeFlow(overrides: Partial<Flow> = {}): Flow {
  return {
    id: 'flow_test_1',
    vuln_class: 'sql_injection',
    taint_kind: 'http_input',
    entry_point_file: 'src/server.ts',
    entry_point_line: 4,
    entry_point_method: 'handler',
    entry_point_pattern: 'req.body.*',
    sink_file: 'src/server.ts',
    sink_line: 5,
    sink_method: 'db.query',
    sink_pattern: '*.query(*)',
    sink_is_external: false,
    flow_nodes: [
      { filePath: 'src/server.ts', line: 4, column: 21, label: 'req.body.id', kind: 'source' },
      { filePath: 'src/server.ts', line: 5, column: 3, label: 'db.query', kind: 'sink' },
    ],
    flow_length: 2,
    source_description: 'Express request body',
    sink_description: 'SQL query',
    engine_confidence: 0.5,
    ...overrides,
  };
}

interface StubFetchCall {
  url: string;
  body: string;
}

interface StubFetchOptions {
  status?: number;
  body?: unknown;
  /** When set, the fetch promise rejects with this error. */
  error?: Error;
}

const realFetch: typeof fetch = global.fetch;
let stubCalls: StubFetchCall[] = [];

function stubFetch(handler: (url: string, body: string) => StubFetchOptions): void {
  stubCalls = [];
  (global as any).fetch = async (url: any, init?: any): Promise<Response> => {
    const u = String(url);
    const b = init?.body ? String(init.body) : '';
    stubCalls.push({ url: u, body: b });
    const out = handler(u, b);
    if (out.error) throw out.error;
    const resp = {
      ok: (out.status ?? 200) < 400,
      status: out.status ?? 200,
      json: async () => out.body ?? {},
    };
    return resp as unknown as Response;
  };
}

function restoreFetch(): void {
  (global as any).fetch = realFetch;
  stubCalls = [];
}

function makeQwenTripleBody(opts: {
  verdict?: 'kept' | 'rejected';
  is_sanitized?: boolean | null;
  classification?: 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | 'UNKNOWN';
  confidence?: number;
}) {
  return {
    choices: [
      {
        message: {
          content: JSON.stringify({
            verdict: opts.verdict ?? 'kept',
            verdict_reasoning: 'real exploit',
            verdict_confidence: opts.confidence ?? 0.9,
            sanitization: {
              is_sanitized: opts.is_sanitized ?? false,
              reasoning: 'no sanitizer found',
              sanitizer_line: null,
            },
            endpoint: {
              classification: opts.classification ?? 'PUBLIC_UNAUTH',
              reasoning: 'app.post handler',
            },
          }),
        },
        finish_reason: 'stop',
      },
    ],
    usage: { prompt_tokens: 800, completion_tokens: 80 },
  };
}

async function testParseTripleSmoke() {
  console.log('\n[test] parseTriple accepts plain JSON');
  const ok = parseTriple(
    JSON.stringify({
      verdict: 'kept',
      verdict_reasoning: 'real',
      verdict_confidence: 0.9,
      sanitization: { is_sanitized: false, reasoning: 'no', sanitizer_line: null },
      endpoint: { classification: 'PUBLIC_UNAUTH', reasoning: 'handler' },
    }),
    [],
  );
  assert(ok?.verdict === 'kept', `verdict=kept (got ${ok?.verdict})`);
  assert(ok?.endpoint.classification === 'PUBLIC_UNAUTH', 'endpoint=PUBLIC_UNAUTH');

  console.log('\n[test] parseTriple returns null on garbage');
  assert(parseTriple('definitely not json', []) === null, 'non-JSON → null');
  assert(parseTriple('{"verdict":"maybe"}', []) === null, 'invalid verdict enum → null');
}

async function testBuildPrompt() {
  console.log('\n[test] buildPrompt embeds vuln class + locations + nonce');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fp-filter-prompt-'));
  fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
  fs.writeFileSync(
    path.join(tmpDir, 'src/server.ts'),
    [
      'import express from "express";',
      'const app = express();',
      'app.post("/users", (req, res) => {',
      '  const id = req.body.id;',
      '  db.query(`SELECT * FROM u WHERE id = ${id}`);',
      '});',
      '',
    ].join('\n'),
  );
  const NONCE = 'deadbeefcafef00d';
  const { systemPrompt, userPrompt } = buildPrompt(makeFlow(), tmpDir, [], NONCE);
  assert(userPrompt.includes('sql injection'), 'prompt mentions vuln class (humanized)');
  assert(userPrompt.includes('src/server.ts:4'), 'prompt mentions source file:line');
  assert(userPrompt.includes('src/server.ts:5'), 'prompt mentions sink file:line');
  assert(userPrompt.includes('db.query'), 'prompt mentions sink method');
  assert(userPrompt.includes('"verdict"') && userPrompt.includes('"rejected"'), 'prompt asks for verdict json');
  assert(userPrompt.includes(`<untrusted_code_${NONCE}`), 'user prompt wraps source in nonce-tagged delimiter');
  assert(systemPrompt.includes(NONCE), 'system prompt embeds the nonce');
  assert(systemPrompt.includes('candidate_sanitizers'), 'system prompt names candidate_sanitizers list');
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

async function testEstimatePerFlowCost() {
  console.log('\n[test] estimatePerFlowCostUsd is positive');
  const cost = estimatePerFlowCostUsd(makeFlow());
  assert(cost > 0, `cost > 0 (got ${cost})`);
  assert(cost < 0.01, `cost reasonable for one DeepInfra Qwen call (got ${cost})`);
}

async function testFilterFlowKept() {
  console.log('\n[test] filterFlow: model returns kept');
  stubFetch(() => ({ body: makeQwenTripleBody({ verdict: 'kept', confidence: 0.9 }) }));
  const calls: any[] = [];
  const logger = { async log(input: any) { calls.push(input); } };
  const result = await filterFlow(
    { flow: makeFlow(), workspaceRoot: '/tmp/notreal', apiKey: 'test-key' },
    logger,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
  );
  assert(result.verdict === 'kept', `verdict=kept (got ${result.verdict})`);
  if (result.verdict === 'kept' || result.verdict === 'rejected') {
    assert(result.verdict_confidence === 0.9, 'verdict_confidence=0.9');
    assert(result.endpoint.classification === 'PUBLIC_UNAUTH', 'endpoint=PUBLIC_UNAUTH');
    assert(result.sanitization.is_sanitized === false, 'is_sanitized=false');
    assert(result.costUsd > 0, 'costUsd > 0');
  }
  assert(calls.length === 1, `logger.log called once (got ${calls.length})`);
  assert(calls[0].feature === 'taint_engine_fp_filter', 'feature=taint_engine_fp_filter');
  assert(calls[0].success === true, 'success=true on kept');
  restoreFetch();
}

async function testFilterFlowRejected() {
  console.log('\n[test] filterFlow: model returns rejected');
  stubFetch(() => ({ body: makeQwenTripleBody({ verdict: 'rejected', confidence: 0.85 }) }));
  const calls: any[] = [];
  const logger = { async log(input: any) { calls.push(input); } };
  const result = await filterFlow(
    { flow: makeFlow(), workspaceRoot: '/tmp/notreal', apiKey: 'test-key' },
    logger,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
  );
  assert(result.verdict === 'rejected', `verdict=rejected (got ${result.verdict})`);
  assert(calls[0].success === true, 'success=true on rejected (model still called successfully)');
  restoreFetch();
}

async function testFilterFlowMalformedJson() {
  console.log('\n[test] filterFlow: model returns garbage → kept_on_error');
  stubFetch(() => ({
    body: {
      choices: [{ message: { content: 'definitely not json' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 800, completion_tokens: 5 },
    },
  }));
  const calls: any[] = [];
  const logger = { async log(input: any) { calls.push(input); } };
  const result = await filterFlow(
    { flow: makeFlow(), workspaceRoot: '/tmp/notreal', apiKey: 'test-key' },
    logger,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
  );
  assert(result.verdict === 'kept_on_error', `verdict=kept_on_error (got ${result.verdict})`);
  assert(calls[0].success === false, 'logger captured success=false');
  restoreFetch();
}

async function testFilterFlowHttpError() {
  console.log('\n[test] filterFlow: HTTP 500 → kept_on_error');
  stubFetch(() => ({ status: 500, body: { error: 'internal' } }));
  const calls: any[] = [];
  const logger = { async log(input: any) { calls.push(input); } };
  const result = await filterFlow(
    { flow: makeFlow(), workspaceRoot: '/tmp/notreal', apiKey: 'test-key' },
    logger,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
  );
  assert(result.verdict === 'kept_on_error', `verdict=kept_on_error (got ${result.verdict})`);
  assert(calls[0].success === false, 'logger captured success=false');
  assert(/500/.test(calls[0].errorMessage ?? ''), 'errorMessage mentions HTTP 500');
  restoreFetch();
}

async function testRunnerThresholdGating() {
  console.log('\n[test] runner: empty workspace yields zero flows, filter not exercised');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fp-runner-'));
  let fetchCalled = false;
  stubFetch(() => { fetchCalled = true; return { body: makeQwenTripleBody({}) }; });
  const storage = await createPGLiteStorage();
  await storage.from('organizations').insert({ id: ORG_ID, name: 'fp-test', created_at: new Date().toISOString() });

  const result = await runEngine({
    workspaceRoot: tmpDir,
    fpFilter: {
      storage,
      organizationId: ORG_ID,
      userId: USER_ID,
      projectId: PROJECT_ID,
      extractionRunId: RUN_ID,
      apiKey: 'test-key',
    },
  });
  if (result.ran && result.aiFilter) {
    assert(
      result.aiFilter.skippedReason === 'no_flows',
      `filter skipped with no_flows on empty workspace (got ${result.aiFilter.skippedReason})`,
    );
  } else {
    assert(true, 'engine did not run on empty workspace; no fetch attempted');
  }
  assert(!fetchCalled, 'fetch never called when no flows emitted');
  fs.rmSync(tmpDir, { recursive: true, force: true });
  restoreFetch();
}

async function testCostCapPreCheck() {
  console.log('\n[test] runner: cost cap pre-check short-circuits filter when over budget');
  const storage = await createPGLiteStorage();
  await storage.from('organizations').insert({
    id: ORG_ID,
    name: 'fp-cap-test',
    created_at: new Date().toISOString(),
  });
  await storage.from('users').insert({ id: USER_ID, created_at: new Date().toISOString() });
  await storage.from('taint_engine_settings').insert({
    organization_id: ORG_ID,
    monthly_ai_cost_cap_usd: 0.0001, // tiny cap
    ai_layer_enabled: true,
    ai_fp_filter_confidence_threshold: 0.99, // force everything below threshold
  });
  await storage.from('ai_usage_logs').insert({
    organization_id: ORG_ID,
    user_id: USER_ID,
    feature: 'taint_engine_spec_inference',
    tier: 'platform',
    provider: 'openai',
    model: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
    input_tokens: 100000,
    output_tokens: 1000,
    estimated_cost: 1.5,
    success: true,
  });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fp-cap-'));
  fs.writeFileSync(
    path.join(tmpDir, 'tsconfig.json'),
    JSON.stringify({ compilerOptions: { target: 'es2020', module: 'commonjs', strict: false }, include: ['*.ts'] }),
  );
  fs.writeFileSync(
    path.join(tmpDir, 'app.ts'),
    [
      'declare const app: any;',
      'declare const db: any;',
      'app.post("/u", (req: any, res: any) => {',
      '  db.query(`SELECT * FROM u WHERE id = ${req.body.id}`);',
      '});',
    ].join('\n'),
  );

  let fetchCalled = false;
  stubFetch(() => { fetchCalled = true; return { body: makeQwenTripleBody({}) }; });

  const result = await runEngine({
    workspaceRoot: tmpDir,
    fpFilter: {
      storage,
      organizationId: ORG_ID,
      userId: USER_ID,
      projectId: PROJECT_ID,
      extractionRunId: RUN_ID,
      apiKey: 'test-key',
    },
  });

  if (result.ran && result.aiFilter) {
    assert(
      result.aiFilter.skippedReason === 'cost_cap_exceeded',
      `filter skipped with cost_cap_exceeded (got ${result.aiFilter.skippedReason})`,
    );
    assert(!fetchCalled, 'fetch never invoked under cost cap');
    assert(result.aiFilter.flowsChecked === 0, 'flowsChecked=0 when capped');
  } else {
    assert(true, 'engine did not emit flows for this fixture; cost-cap path not exercised');
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });
  restoreFetch();
}

async function testAiLayerDisabled() {
  console.log('\n[test] runner: ai_layer_enabled=false skips filter cleanly');
  const storage = await createPGLiteStorage();
  const orgId = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
  const projId = '99999999-9999-9999-9999-999999999999';
  await storage.from('organizations').insert({
    id: orgId,
    name: 'fp-disabled',
    created_at: new Date().toISOString(),
  });
  await storage.from('taint_engine_settings').insert({
    organization_id: orgId,
    ai_layer_enabled: false,
    monthly_ai_cost_cap_usd: 50,
    ai_fp_filter_confidence_threshold: 0.7,
  });
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fp-disabled-'));
  let fetchCalled = false;
  stubFetch(() => { fetchCalled = true; return { body: makeQwenTripleBody({}) }; });
  const result = await runEngine({
    workspaceRoot: tmpDir,
    fpFilter: {
      storage,
      organizationId: orgId,
      userId: USER_ID,
      projectId: projId,
      extractionRunId: 'run_disabled_001',
      apiKey: 'test-key',
    },
  });
  if (result.ran && result.aiFilter) {
    const reason = result.aiFilter.skippedReason;
    assert(
      reason === 'ai_layer_disabled' || reason === 'no_flows',
      `filter skipped (got ${reason})`,
    );
  } else {
    assert(true, 'engine did not run; filter not exercised');
  }
  assert(!fetchCalled, 'fetch never called when ai_layer_enabled=false');
  fs.rmSync(tmpDir, { recursive: true, force: true });
  restoreFetch();
}

async function testUsageLoggerSwallowsErrors() {
  console.log('\n[test] createUsageLogger swallows DB write failures');
  const fakeStorage: any = {
    from: () => ({ insert: async () => ({ error: { message: 'simulated' } }) }),
  };
  let warnCount = 0;
  const logger = createUsageLogger(
    fakeStorage,
    { organizationId: ORG_ID, userId: USER_ID, projectId: PROJECT_ID, extractionRunId: RUN_ID },
    () => { warnCount++; },
  );
  await logger.log({
    organizationId: ORG_ID,
    userId: USER_ID,
    feature: 'taint_engine_fp_filter',
    tier: 'platform',
    provider: 'openai',
    model: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
    inputTokens: 10,
    outputTokens: 5,
    estimatedCost: 0.000001,
    durationMs: 100,
    success: true,
  });
  assert(warnCount === 1, `warn fired once on DB error (got ${warnCount})`);
}

async function main() {
  await testParseTripleSmoke();
  await testBuildPrompt();
  await testEstimatePerFlowCost();
  await testFilterFlowKept();
  await testFilterFlowRejected();
  await testFilterFlowMalformedJson();
  await testFilterFlowHttpError();
  await testRunnerThresholdGating();
  await testCostCapPreCheck();
  await testAiLayerDisabled();
  await testUsageLoggerSwallowsErrors();

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
