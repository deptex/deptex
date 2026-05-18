/**
 * Unit tests for the cross-file taint engine's worklist propagator.
 *
 * Each test builds a synthetic mini-project on disk, runs propagate()
 * against an inlined FrameworkSpec, and asserts on the resulting flows.
 *
 * Coverage (per the M2 plan):
 *   (a) Direct same-file source → sink
 *   (b) Cross-file source → helper → sink
 *   (c) Source → sanitizer → sink (must NOT emit)
 *   (d) Source through await/promise (await unwraps)
 *   (e) Deep call chain (5+ hops)
 *   - Spec loader round-trip + validation
 *   - YAML loadSpec() reads a real file from disk
 *
 * Run: npx tsx test/taint-engine-propagator.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  loadSpec,
  propagate,
  validateSpec,
  SpecValidationError,
  type Flow,
  type FrameworkSpec,
} from '../src/taint-engine';

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

function makeWorkspace(name: string, files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `prop-${name}-`));
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf8');
  }
  return root;
}

const EXPRESS_LIKE_SPEC: FrameworkSpec = {
  framework: 'express-test',
  version: '*',
  sources: [
    { pattern: 'req.body.*', taint_kind: 'http_input', description: 'Express request body' },
    { pattern: 'req.query.*', taint_kind: 'http_input', description: 'Express request query' },
    { pattern: 'req.params.*', taint_kind: 'http_input', description: 'Express request params' },
  ],
  sinks: [
    { pattern: 'child_process.exec(*)', vuln_class: 'command_injection', argument_indices: [0], description: 'shell exec' },
    { pattern: 'db.query(*)', vuln_class: 'sql_injection', argument_indices: [0], description: 'sql query' },
    { pattern: 'res.location(*)', vuln_class: 'open_redirect', argument_indices: [0], description: 'Express res.location' },
    { pattern: '_.template(*)', vuln_class: 'code_injection', argument_indices: [0], description: 'lodash template' },
  ],
  sanitizers: [
    { pattern: 'validator.escape(*)', vuln_classes: ['xss', 'command_injection'], description: 'escape' },
    { pattern: 'sanitize(*)', vuln_classes: ['command_injection'], description: 'shell sanitize' },
  ],
};

function flowFromTo(flows: Flow[], entryFile: string, sinkFile: string): Flow | undefined {
  return flows.find((f) => f.entry_point_file === entryFile && f.sink_file === sinkFile);
}

async function testDirectFlow() {
  console.log('\n[test] (a) direct same-file source → sink');
  const root = makeWorkspace('direct', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      function handler(req: any) {
        const cmd = req.body.cmd;
        child_process.exec(cmd);
      }
      handler({ body: { cmd: 'ls' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length >= 1, `at least one flow emitted (got ${result.flows.length})`);
  const f = result.flows[0];
  assert(f?.vuln_class === 'command_injection', 'flow vuln_class = command_injection');
  assert(f?.entry_point_pattern === 'req.body.*', 'flow source pattern = req.body.*');
  assert(f?.sink_pattern.startsWith('child_process.exec'), 'flow sink pattern = child_process.exec');
  assert(f?.flow_length >= 2, `flow has at least 2 hops (got ${f?.flow_length})`);
  fs.rmSync(root, { recursive: true, force: true });
}

async function testCrossFileFlow() {
  console.log('\n[test] (b) cross-file source → helper → sink');
  const root = makeWorkspace('cross-file', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/util.ts': `
      export function runIt(cmd: string) {
        child_process.exec(cmd);
      }
    `,
    'src/server.ts': `
      import { runIt } from './util';
      function handler(req: any) {
        const cmd = req.query.cmd;
        runIt(cmd);
      }
      handler({ query: { cmd: 'ls' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length >= 1, `cross-file flow emitted (got ${result.flows.length})`);
  const flow = flowFromTo(result.flows, 'src/server.ts', 'src/util.ts');
  assert(flow != null, 'flow entry in server.ts, sink in util.ts');
  assert(flow?.vuln_class === 'command_injection', 'cross-file flow class = command_injection');
  // The path should include hops in both files.
  const files = new Set(flow?.flow_nodes.map((n) => n.filePath) ?? []);
  assert(files.has('src/server.ts') && files.has('src/util.ts'), 'flow path crosses both files');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testSanitizerSuppresses() {
  console.log('\n[test] (c) sanitizer in path suppresses flow');
  const root = makeWorkspace('sanitizer', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      function handler(req: any) {
        const raw = req.body.cmd;
        const safe = sanitize(raw);
        child_process.exec(safe);
      }
      handler({ body: { cmd: 'ls' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length === 0, `no flow emitted when sanitizer in path (got ${result.flows.length})`);
  // And the unsanitized version SHOULD emit.
  const root2 = makeWorkspace('sanitizer-bypass', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      function handler(req: any) {
        const raw = req.body.cmd;
        child_process.exec(raw);
      }
      handler({ body: { cmd: 'ls' } });
    `,
  });
  const result2 = await propagate({ rootDir: root2, specs: [EXPRESS_LIKE_SPEC] });
  assert(result2.flows.length >= 1, `unsanitized version DOES emit (got ${result2.flows.length})`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(root2, { recursive: true, force: true });
}

async function testAwaitPromise() {
  console.log('\n[test] (d) source through await unwraps to sink');
  const root = makeWorkspace('await', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      async function fetchUserCmd(req: any): Promise<string> {
        return req.body.cmd;
      }
      async function handler(req: any) {
        const cmd = await fetchUserCmd(req);
        child_process.exec(cmd);
      }
      handler({ body: { cmd: 'ls' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length >= 1, `flow through await emitted (got ${result.flows.length})`);
  const f = result.flows[0];
  assert(f?.vuln_class === 'command_injection', 'await-flow vuln_class = command_injection');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testDeepChain() {
  console.log('\n[test] (e) deep call chain (5+ hops)');
  const root = makeWorkspace('deep', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/level5.ts': `export function level5(x: string) { db.query(x); }`,
    'src/level4.ts': `import { level5 } from './level5'; export function level4(x: string) { level5(x); }`,
    'src/level3.ts': `import { level4 } from './level4'; export function level3(x: string) { level4(x); }`,
    'src/level2.ts': `import { level3 } from './level3'; export function level2(x: string) { level3(x); }`,
    'src/server.ts': `
      import { level2 } from './level2';
      function handler(req: any) {
        const id = req.params.id;
        level2(id);
      }
      handler({ params: { id: 'abc' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length >= 1, `deep chain flow emitted (got ${result.flows.length})`);
  const f = result.flows[0];
  assert(f?.vuln_class === 'sql_injection', 'deep chain vuln_class = sql_injection');
  assert(f != null && f.flow_length >= 5, `deep chain has ≥5 hops (got ${f?.flow_length})`);
  // Path should touch every file.
  const files = new Set(f?.flow_nodes.map((n) => n.filePath) ?? []);
  for (const expected of ['src/server.ts', 'src/level2.ts', 'src/level3.ts', 'src/level4.ts', 'src/level5.ts']) {
    assert(files.has(expected), `flow path includes ${expected}`);
  }
  fs.rmSync(root, { recursive: true, force: true });
}

async function testSpecLoader() {
  console.log('\n[test] spec loader: validate + load YAML round-trip');
  // Inline validation
  const ok = validateSpec({
    framework: 'demo',
    version: '*',
    sources: [{ pattern: 'req.body.*', taint_kind: 'http_input', description: 'd' }],
    sinks: [{ pattern: 'eval(*)', vuln_class: 'command_injection', argument_indices: [0], description: 'd' }],
    sanitizers: [],
  });
  assert(ok.framework === 'demo', 'validateSpec accepts well-formed spec');

  let threw = false;
  try {
    validateSpec({ framework: 'x', version: '*', sources: [], sinks: [{ pattern: 'p', vuln_class: 'NOT_REAL', argument_indices: [], description: 'd' }], sanitizers: [] });
  } catch (e) {
    threw = e instanceof SpecValidationError;
  }
  assert(threw, 'validateSpec rejects bogus vuln_class');

  // Round-trip via YAML file
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'spec-'));
  const yamlPath = path.join(root, 'demo.yaml');
  fs.writeFileSync(
    yamlPath,
    [
      'framework: demo',
      'version: "*"',
      'sources:',
      '  - pattern: req.body.*',
      '    taint_kind: http_input',
      '    description: d',
      'sinks:',
      '  - pattern: eval(*)',
      '    vuln_class: command_injection',
      '    argument_indices: [0]',
      '    description: d',
      'sanitizers: []',
      '',
    ].join('\n'),
    'utf8',
  );
  const loaded = loadSpec(yamlPath);
  assert(loaded.sources[0].pattern === 'req.body.*', 'YAML loaded source pattern preserved');
  assert(loaded.sinks[0].vuln_class === 'command_injection', 'YAML loaded vuln class preserved');
  fs.rmSync(root, { recursive: true, force: true });
}

async function testMethodChainSink() {
  console.log('\n[test] (f) method-chained inner-call sink fires');
  // `res.location(q).end()` — the inner call is the sink-bearing position
  // and was previously invisible because the engine only traced sinks at
  // the terminal call. IR lowerer now pre-walks the inner call.
  const root = makeWorkspace('method-chain', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      declare const res: any;
      function handler(req: any) {
        const q = req.query.next;
        res.location(q).end();
      }
      handler({ query: { next: 'x' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length >= 1, `method-chain sink flow emitted (got ${result.flows.length})`);
  const f = result.flows.find((x) => x.vuln_class === 'open_redirect');
  assert(f != null, 'flow vuln_class = open_redirect');
  assert(f?.sink_pattern === 'res.location(*)', 'sink pattern = res.location(*)');

  // Safe variant: constant key, no taint reaches inner call.
  const safeRoot = makeWorkspace('method-chain-safe', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      declare const res: any;
      function handler(_req: any) {
        res.location('/login').end();
      }
      handler({});
    `,
  });
  const safeResult = await propagate({ rootDir: safeRoot, specs: [EXPRESS_LIKE_SPEC] });
  assert(safeResult.flows.length === 0, `safe method-chain emits no flow (got ${safeResult.flows.length})`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(safeRoot, { recursive: true, force: true });
}

async function testComputedKeySource() {
  console.log('\n[test] (g) computed-key assignment taints the object');
  // `obj[req.query.x] = ...` should taint `obj` from the key expression,
  // so a downstream `_.template(obj)` sink fires. AI-fixture shape for
  // CVE-2026-4800 (lodash template injection).
  const root = makeWorkspace('computed-key', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      declare const _: any;
      function handler(req: any) {
        const obj: any = {};
        obj[req.query.x] = 'y';
        _.template(obj);
      }
      handler({ query: { x: 'k' } });
    `,
  });
  const result = await propagate({ rootDir: root, specs: [EXPRESS_LIKE_SPEC] });
  assert(result.flows.length >= 1, `computed-key flow emitted (got ${result.flows.length})`);
  const f = result.flows.find((x) => x.vuln_class === 'code_injection');
  assert(f != null, 'flow vuln_class = code_injection');
  assert(f?.sink_pattern === '_.template(*)', 'sink pattern = _.template(*)');

  // Safe variant: hard-coded key, obj never tainted.
  const safeRoot = makeWorkspace('computed-key-safe', {
    'tsconfig.json': JSON.stringify({ compilerOptions: { target: 'ES2020', strict: false } }),
    'src/server.ts': `
      declare const _: any;
      function handler(_req: any) {
        const obj: any = {};
        obj['hardcoded'] = 'y';
        _.template(obj);
      }
      handler({});
    `,
  });
  const safeResult = await propagate({ rootDir: safeRoot, specs: [EXPRESS_LIKE_SPEC] });
  assert(safeResult.flows.length === 0, `safe computed-key emits no flow (got ${safeResult.flows.length})`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(safeRoot, { recursive: true, force: true });
}

async function testReceiverTaintPassThrough() {
  console.log('\n[test] (h) receiver-taint propagation through 0-arg pass-through calls');
  // Exercises propagate-core.ts receiver-taint pass-through rule:
  // `req.body.cmd.toString().trim()` — both `.toString()` and `.trim()`
  // have zero positional args. Before the rule the temps lost taint; with
  // it the receiver's taint flows through each hop to fire the sink.
  // Fixture lives on disk at js-vulns/receiver-taint-{vuln,safe}/ so it's
  // independently runnable and visible to future validate-script extensions.
  const fixturesRoot = path.join(__dirname, 'taint-engine', 'fixtures', 'js-vulns');
  const vulnRoot = path.join(fixturesRoot, 'receiver-taint-vuln');
  const safeRoot = path.join(fixturesRoot, 'receiver-taint-safe');

  const vulnResult = await propagate({ rootDir: vulnRoot, specs: [EXPRESS_LIKE_SPEC] });
  const matching = vulnResult.flows.filter((f) => f.vuln_class === 'command_injection');
  assert(matching.length >= 1, `vuln fixture emits at least one command_injection flow (got ${matching.length}; total flows=${vulnResult.flows.length})`);
  const f = matching[0];
  assert(f?.entry_point_pattern === 'req.body.*', 'vuln flow source pattern = req.body.*');
  assert(f?.sink_pattern.startsWith('child_process.exec'), 'vuln flow sink pattern = child_process.exec');

  const safeResult = await propagate({ rootDir: safeRoot, specs: [EXPRESS_LIKE_SPEC] });
  const safeMatching = safeResult.flows.filter((f) => f.vuln_class === 'command_injection');
  assert(safeMatching.length === 0, `safe fixture emits zero command_injection flows (got ${safeMatching.length})`);
}

async function testJsonwebtokenSanitizerAbsence() {
  console.log('\n[test] (i) Phase F4 sanitizer-absence — jsonwebtoken jwt.verify without algorithms (CVE-2022-23539 shape)');
  // Loads jsonwebtoken.yaml (which carries the required_arguments contract)
  // and runs propagate() on the disk fixture. Asserts via the non-taint
  // detector on irFunctions, not via flows — `jwt.verify` is a non-taint
  // sink (argument_indices: []).
  const { detectSanitizerAbsence: detect, extractCallSitesFromIr: extract } = await import('../src/taint-engine/non-taint-detector');
  const { loadSpec } = await import('../src/taint-engine');
  const specPath = path.join(__dirname, '..', 'src', 'taint-engine', 'framework-models', 'jsonwebtoken.yaml');
  const spec = loadSpec(specPath);

  const fixturesRoot = path.join(__dirname, 'taint-engine', 'fixtures', 'jsonwebtoken-vulns');
  const vulnRoot = path.join(fixturesRoot, 'auth-bypass-vuln');
  const safeRoot = path.join(fixturesRoot, 'auth-bypass-safe');

  const vulnResult = await propagate({ rootDir: vulnRoot, specs: [spec] });
  const vulnCallsites = vulnResult.irFunctions ? extract(vulnResult.irFunctions, 'js') : [];
  const vulnFindings = detect(spec, vulnCallsites).filter((f) => f.vuln_class === 'auth_bypass');
  assert(vulnFindings.length >= 1, `vuln fixture surfaces ≥1 auth_bypass sanitizer-absence finding (got ${vulnFindings.length})`);

  const safeResult = await propagate({ rootDir: safeRoot, specs: [spec] });
  const safeCallsites = safeResult.irFunctions ? extract(safeResult.irFunctions, 'js') : [];
  const safeFindings = detect(spec, safeCallsites).filter((f) => f.vuln_class === 'auth_bypass');
  assert(safeFindings.length === 0, `safe fixture surfaces 0 auth_bypass sanitizer-absence findings (got ${safeFindings.length})`);
}

async function testFollowRedirectsSanitizerAbsence() {
  console.log('\n[test] (j) Phase F4 sanitizer-absence — follow-redirects http.request without beforeRedirect (CVE-2024-28849 shape)');
  const { detectSanitizerAbsence: detect, extractCallSitesFromIr: extract } = await import('../src/taint-engine/non-taint-detector');
  const { loadSpec } = await import('../src/taint-engine');
  const specPath = path.join(__dirname, '..', 'src', 'taint-engine', 'framework-models', 'follow-redirects.yaml');
  const spec = loadSpec(specPath);

  const fixturesRoot = path.join(__dirname, 'taint-engine', 'fixtures', 'follow-redirects-vulns');
  const vulnRoot = path.join(fixturesRoot, 'ssrf-vuln');
  const safeRoot = path.join(fixturesRoot, 'ssrf-safe');

  const vulnResult = await propagate({ rootDir: vulnRoot, specs: [spec] });
  const vulnCallsites = vulnResult.irFunctions ? extract(vulnResult.irFunctions, 'js') : [];
  const vulnFindings = detect(spec, vulnCallsites).filter((f) => f.vuln_class === 'ssrf');
  assert(vulnFindings.length >= 1, `vuln fixture surfaces ≥1 ssrf sanitizer-absence finding (got ${vulnFindings.length})`);

  const safeResult = await propagate({ rootDir: safeRoot, specs: [spec] });
  const safeCallsites = safeResult.irFunctions ? extract(safeResult.irFunctions, 'js') : [];
  const safeFindings = detect(spec, safeCallsites).filter((f) => f.vuln_class === 'ssrf');
  assert(safeFindings.length === 0, `safe fixture surfaces 0 ssrf sanitizer-absence findings (got ${safeFindings.length})`);
}

async function main() {
  console.log('=== taint-engine propagator tests ===');
  await testDirectFlow();
  await testCrossFileFlow();
  await testSanitizerSuppresses();
  await testAwaitPromise();
  await testDeepChain();
  await testMethodChainSink();
  await testComputedKeySource();
  await testReceiverTaintPassThrough();
  await testJsonwebtokenSanitizerAbsence();
  await testFollowRedirectsSanitizerAbsence();
  await testSpecLoader();
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
