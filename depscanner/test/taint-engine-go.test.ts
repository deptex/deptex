/**
 * End-to-end tests for the Go substrate of the cross-file taint engine.
 *
 * Each fixture pair (vuln + safe) lives under
 * `test/taint-engine/fixtures/go-vulns/`. We load the bundled YAML specs
 * (gin / echo / go-stdlib / net-http / go-jose) and run propagateGo()
 * against each fixture directory, asserting that vulns emit ≥1 flow with
 * the expected vuln_class and safe fixtures emit zero.
 *
 * Run: npx tsx test/taint-engine-go.test.ts
 */

import * as path from 'path';
import { propagateGo } from '../src/taint-engine/go/propagate';
import { loadSpec } from '../src/taint-engine/spec-loader';
import type { FrameworkSpec, Flow, VulnClass } from '../src/taint-engine';

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

const FIXTURE_ROOT = path.resolve(__dirname, 'taint-engine/fixtures/go-vulns');
const FRAMEWORK_MODELS = path.resolve(__dirname, '../src/taint-engine/framework-models');

function loadGoSpecs(): FrameworkSpec[] {
  const names = ['gin.yaml', 'echo.yaml', 'go-stdlib.yaml', 'net-http.yaml', 'go-jose.yaml'];
  return names.map((n) => loadSpec(path.join(FRAMEWORK_MODELS, n)));
}

interface FixtureCase {
  fixture: string;
  expectVulnClass: VulnClass | null; // null = expect zero flows
  description: string;
}

const CASES: FixtureCase[] = [
  {
    fixture: 'gin-sql-injection-vuln',
    expectVulnClass: 'sql_injection',
    description: 'Gin handler interpolates request param into SQL',
  },
  {
    fixture: 'gin-sql-injection-safe',
    expectVulnClass: null,
    description: 'Gin handler uses parameterized SQL',
  },
  {
    fixture: 'gin-command-injection-vuln',
    expectVulnClass: 'command_injection',
    description: 'Gin handler shells out with user input',
  },
  {
    fixture: 'gin-command-injection-safe',
    expectVulnClass: null,
    description: 'Gin handler coerces request param via strconv before exec',
  },
  {
    fixture: 'gin-path-traversal-vuln',
    expectVulnClass: 'path_traversal',
    description: 'Gin handler passes raw c.Query into cross-file os.ReadFile',
  },
  {
    fixture: 'gin-path-traversal-safe',
    expectVulnClass: null,
    description: 'Gin handler strips path components via filepath.Base before read',
  },
  {
    fixture: 'go-jose-deserialization-vuln',
    expectVulnClass: 'deserialization',
    description: 'net/http handler flows tainted JWE into go-jose Parse + Decrypt (CVE-2024-28180)',
  },
  {
    fixture: 'go-jose-deserialization-safe',
    expectVulnClass: null,
    description: 'net/http handler uses hardcoded JWE input — no taint reaches Parse',
  },
];

function summarizeFlows(flows: Flow[]): string {
  if (flows.length === 0) return '(no flows)';
  return flows
    .map(
      (f) =>
        `  - ${f.vuln_class} :: ${f.entry_point_file}:${f.entry_point_line} → ${f.sink_file}:${f.sink_line} [${f.sink_pattern}] (${f.flow_length} hops)`,
    )
    .join('\n');
}

async function runCase(c: FixtureCase, specs: FrameworkSpec[]): Promise<void> {
  const root = path.join(FIXTURE_ROOT, c.fixture);
  const result = await propagateGo({ rootDir: root, specs });
  const flows = result.flows;

  console.log(`\n[case] ${c.fixture} — ${c.description}`);
  console.log(`  flows emitted: ${flows.length}`);
  if (flows.length > 0) console.log(summarizeFlows(flows));

  if (c.expectVulnClass === null) {
    assert(flows.length === 0, `${c.fixture}: expects 0 flows, got ${flows.length}`);
  } else {
    const matching = flows.filter((f) => f.vuln_class === c.expectVulnClass);
    assert(
      matching.length >= 1,
      `${c.fixture}: expects ≥1 ${c.expectVulnClass} flow, got ${matching.length}`,
    );
  }
}

async function main() {
  console.log('=== taint-engine Go fixture tests ===');
  const specs = loadGoSpecs();
  console.log(`Loaded specs: ${specs.map((s) => s.framework).join(', ')}`);

  for (const c of CASES) {
    try {
      await runCase(c, specs);
    } catch (err) {
      failures++;
      console.error(`  FAIL: ${c.fixture} threw: ${(err as Error).stack ?? err}`);
    }
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
