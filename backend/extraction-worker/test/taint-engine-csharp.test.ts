/**
 * Validation tests for the C# substrate of the Deptex cross-file taint
 * engine. Mirrors test/taint-engine-python.test.ts.
 *
 * Run: npx tsx test/taint-engine-csharp.test.ts
 */

import * as path from 'path';
import { loadSpec } from '../src/taint-engine';
import type { FrameworkSpec, VulnClass, Flow } from '../src/taint-engine';
import { propagateCSharp } from '../src/taint-engine/csharp/propagate';

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

const FIXTURES_ROOT = path.resolve(__dirname, 'taint-engine/fixtures/csharp-vulns');
const SPECS_ROOT = path.resolve(__dirname, '../src/taint-engine/framework-models');

function loadSpecs(...names: string[]): FrameworkSpec[] {
  return names.map((n) => loadSpec(path.join(SPECS_ROOT, `${n}.yaml`)));
}

interface FixtureCase {
  name: string;
  vulnDir: string;
  safeDir: string;
  specs: string[];
  expectedVulnClass: VulnClass;
}

const CASES: FixtureCase[] = [
  {
    name: 'ASP.NET Core SQL injection',
    vulnDir: 'aspnet-sql-injection-vuln',
    safeDir: 'aspnet-sql-injection-safe',
    specs: ['aspnet-core', 'dotnet-stdlib'],
    expectedVulnClass: 'sql_injection',
  },
  {
    name: 'ASP.NET Core command injection',
    vulnDir: 'aspnet-command-injection-vuln',
    safeDir: 'aspnet-command-injection-safe',
    specs: ['aspnet-core', 'dotnet-stdlib'],
    expectedVulnClass: 'command_injection',
  },
];

function summarize(flows: Flow[]): string {
  if (flows.length === 0) return '(none)';
  return flows
    .map((f) => `[${f.vuln_class}] ${f.entry_point_pattern}@${f.entry_point_file}:${f.entry_point_line} → ${f.sink_pattern}@${f.sink_file}:${f.sink_line}`)
    .join('\n      ');
}

async function runFixture(c: FixtureCase): Promise<void> {
  console.log(`\n[fixture] ${c.name}`);
  const specs = loadSpecs(...c.specs);

  const vulnRoot = path.join(FIXTURES_ROOT, c.vulnDir);
  const vulnResult = await propagateCSharp({ rootDir: vulnRoot, specs });
  const vulnFlows = vulnResult.flows.filter((f) => f.vuln_class === c.expectedVulnClass);
  assert(
    vulnFlows.length >= 1,
    `${c.vulnDir}: at least one ${c.expectedVulnClass} flow (got ${vulnFlows.length}; total ${vulnResult.flows.length})`,
  );
  if (vulnFlows.length === 0) {
    console.error(`      flows seen: ${summarize(vulnResult.flows)}`);
    console.error(`      stats: ${JSON.stringify(vulnResult.stats)}`);
  }

  const safeRoot = path.join(FIXTURES_ROOT, c.safeDir);
  const safeResult = await propagateCSharp({ rootDir: safeRoot, specs });
  const safeFlows = safeResult.flows.filter((f) => f.vuln_class === c.expectedVulnClass);
  assert(
    safeFlows.length === 0,
    `${c.safeDir}: zero ${c.expectedVulnClass} flows (got ${safeFlows.length})`,
  );
  if (safeFlows.length > 0) {
    console.error(`      flows seen: ${summarize(safeFlows)}`);
  }
}

async function main(): Promise<void> {
  console.log('=== taint-engine csharp tests ===');
  for (const c of CASES) {
    await runFixture(c);
  }
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
