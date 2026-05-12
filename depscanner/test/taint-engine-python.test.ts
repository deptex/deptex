/**
 * Validation tests for the Python substrate of the Deptex cross-file taint
 * engine.
 *
 * For each fixture pair (vuln + safe) we:
 *   1. Load the per-framework spec (django.yaml / flask.yaml).
 *   2. Build the Python callgraph for the fixture root.
 *   3. Run propagatePython() against the loaded spec.
 *   4. Assert that vuln fixtures emit ≥ 1 flow with the expected vuln_class
 *      and that safe fixtures emit 0 flows of the expected vuln_class.
 *
 * Run: npx tsx test/taint-engine-python.test.ts
 */

import * as path from 'path';
import { loadSpec } from '../src/taint-engine';
import type { FrameworkSpec, VulnClass, Flow } from '../src/taint-engine';
import { propagatePython } from '../src/taint-engine/python/propagate';

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

const FIXTURES_ROOT = path.resolve(__dirname, 'taint-engine/fixtures/python-vulns');
const FIXTURES_TOOLKIT_ROOT = path.resolve(__dirname, 'taint-engine/fixtures');
const SPECS_ROOT = path.resolve(__dirname, '../src/taint-engine/framework-models');

async function loadSpecsForFramework(framework: 'django' | 'flask' | 'fastapi'): Promise<FrameworkSpec[]> {
  const specPath = path.join(SPECS_ROOT, `${framework}.yaml`);
  return [loadSpec(specPath)];
}

async function loadSpecsByName(specs: string[]): Promise<FrameworkSpec[]> {
  return specs.map((s) => loadSpec(path.join(SPECS_ROOT, `${s}.yaml`)));
}

interface FixtureCase {
  name: string;
  vulnDir: string;
  safeDir: string;
  framework: 'django' | 'flask' | 'fastapi';
  expectedVulnClass: VulnClass;
}

/**
 * Sink-only library fixture cases — the vuln+safe pair lives under
 * `test/taint-engine/fixtures/python-<lib>/{vulnerable,safe}/` and exercises
 * a flask source flowing into a sink declared by the library's own spec
 * (urllib3.yaml, requests.yaml, jinja2.yaml, pillow.yaml). We load BOTH
 * flask.yaml (for the source) and the library spec (for the sink) per
 * case so cross-spec stitching wires them together — same shape the
 * production runner uses at extraction time.
 */
interface SinkOnlyFixtureCase {
  name: string;
  rootDir: string;
  specs: string[];
  expectedVulnClass: VulnClass;
}

const CASES: FixtureCase[] = [
  {
    name: 'Django SQL injection',
    vulnDir: 'django-sql-injection-vuln',
    safeDir: 'django-sql-injection-safe',
    framework: 'django',
    expectedVulnClass: 'sql_injection',
  },
  {
    name: 'Flask XSS',
    vulnDir: 'flask-xss-vuln',
    safeDir: 'flask-xss-safe',
    framework: 'flask',
    expectedVulnClass: 'xss',
  },
  {
    name: 'Flask command injection',
    vulnDir: 'flask-command-injection-vuln',
    safeDir: 'flask-command-injection-safe',
    framework: 'flask',
    expectedVulnClass: 'command_injection',
  },
  {
    name: 'Flask path traversal',
    vulnDir: 'flask-path-traversal-vuln',
    safeDir: 'flask-path-traversal-safe',
    framework: 'flask',
    expectedVulnClass: 'path_traversal',
  },
  {
    name: 'Django XSS',
    vulnDir: 'django-xss-vuln',
    safeDir: 'django-xss-safe',
    framework: 'django',
    expectedVulnClass: 'xss',
  },
  {
    name: 'Django path traversal',
    vulnDir: 'django-path-traversal-vuln',
    safeDir: 'django-path-traversal-safe',
    framework: 'django',
    expectedVulnClass: 'path_traversal',
  },
  {
    name: 'FastAPI XSS',
    vulnDir: 'fastapi-xss-vuln',
    safeDir: 'fastapi-xss-safe',
    framework: 'fastapi',
    expectedVulnClass: 'xss',
  },
  {
    name: 'FastAPI path traversal',
    vulnDir: 'fastapi-path-traversal-vuln',
    safeDir: 'fastapi-path-traversal-safe',
    framework: 'fastapi',
    expectedVulnClass: 'path_traversal',
  },
];

const SINK_ONLY_CASES: SinkOnlyFixtureCase[] = [
  {
    name: 'Flask -> urllib3 SSRF (CVE-2020-26137 / CVE-2023-43804 shape)',
    rootDir: 'python-urllib3',
    specs: ['flask', 'urllib3'],
    expectedVulnClass: 'ssrf',
  },
  {
    name: 'Flask -> requests SSRF (CVE-2023-32681 / CVE-2024-35195 shape)',
    rootDir: 'python-requests',
    specs: ['flask', 'requests'],
    expectedVulnClass: 'ssrf',
  },
  {
    name: 'Flask -> jinja2 SSTI (CVE-2019-10906 / CVE-2024-22195 shape)',
    rootDir: 'python-jinja2',
    specs: ['flask', 'jinja2'],
    expectedVulnClass: 'code_injection',
  },
  {
    name: 'Flask -> pillow ImageMath.eval (CVE-2022-22817 shape)',
    rootDir: 'python-pillow',
    specs: ['flask', 'pillow'],
    expectedVulnClass: 'code_injection',
  },
];

function summarizeFlows(flows: Flow[]): string {
  if (flows.length === 0) return '(none)';
  return flows
    .map((f) => `[${f.vuln_class}] ${f.entry_point_pattern}@${f.entry_point_file}:${f.entry_point_line} → ${f.sink_pattern}@${f.sink_file}:${f.sink_line}`)
    .join('\n      ');
}

async function runFixture(c: FixtureCase): Promise<void> {
  console.log(`\n[fixture] ${c.name}`);
  const specs = await loadSpecsForFramework(c.framework);

  // Vulnerable variant — must emit ≥ 1 flow of the expected class.
  const vulnRoot = path.join(FIXTURES_ROOT, c.vulnDir);
  const vulnResult = await propagatePython({ rootDir: vulnRoot, specs });
  const vulnFlowsOfClass = vulnResult.flows.filter((f) => f.vuln_class === c.expectedVulnClass);
  assert(
    vulnFlowsOfClass.length >= 1,
    `${c.vulnDir}: at least one ${c.expectedVulnClass} flow (got ${vulnFlowsOfClass.length}; total ${vulnResult.flows.length})`,
  );
  if (vulnFlowsOfClass.length === 0) {
    console.error(`      flows seen: ${summarizeFlows(vulnResult.flows)}`);
    console.error(`      stats: ${JSON.stringify(vulnResult.stats)}`);
  }

  // Safe variant — must emit 0 flows of the expected class.
  const safeRoot = path.join(FIXTURES_ROOT, c.safeDir);
  const safeResult = await propagatePython({ rootDir: safeRoot, specs });
  const safeFlowsOfClass = safeResult.flows.filter((f) => f.vuln_class === c.expectedVulnClass);
  assert(
    safeFlowsOfClass.length === 0,
    `${c.safeDir}: zero ${c.expectedVulnClass} flows (got ${safeFlowsOfClass.length})`,
  );
  if (safeFlowsOfClass.length > 0) {
    console.error(`      flows seen: ${summarizeFlows(safeFlowsOfClass)}`);
  }
}

async function runSinkOnlyFixture(c: SinkOnlyFixtureCase): Promise<void> {
  console.log(`\n[fixture] ${c.name}`);
  const specs = await loadSpecsByName(c.specs);

  const vulnRoot = path.join(FIXTURES_TOOLKIT_ROOT, c.rootDir, 'vulnerable');
  const vulnResult = await propagatePython({ rootDir: vulnRoot, specs });
  const vulnFlowsOfClass = vulnResult.flows.filter((f) => f.vuln_class === c.expectedVulnClass);
  assert(
    vulnFlowsOfClass.length >= 1,
    `${c.rootDir}/vulnerable: at least one ${c.expectedVulnClass} flow (got ${vulnFlowsOfClass.length}; total ${vulnResult.flows.length})`,
  );
  if (vulnFlowsOfClass.length === 0) {
    console.error(`      flows seen: ${summarizeFlows(vulnResult.flows)}`);
    console.error(`      stats: ${JSON.stringify(vulnResult.stats)}`);
  }

  const safeRoot = path.join(FIXTURES_TOOLKIT_ROOT, c.rootDir, 'safe');
  const safeResult = await propagatePython({ rootDir: safeRoot, specs });
  const safeFlowsOfClass = safeResult.flows.filter((f) => f.vuln_class === c.expectedVulnClass);
  assert(
    safeFlowsOfClass.length === 0,
    `${c.rootDir}/safe: zero ${c.expectedVulnClass} flows (got ${safeFlowsOfClass.length})`,
  );
  if (safeFlowsOfClass.length > 0) {
    console.error(`      flows seen: ${summarizeFlows(safeFlowsOfClass)}`);
  }
}

async function main(): Promise<void> {
  console.log('=== taint-engine python tests ===');
  for (const c of CASES) {
    await runFixture(c);
  }
  for (const c of SINK_ONLY_CASES) {
    await runSinkOnlyFixture(c);
  }
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
