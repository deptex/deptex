/**
 * End-to-end tests for the Java cross-file taint engine.
 *
 * Each fixture pair is a small Spring Boot mini-project under
 * test/taint-engine/fixtures/java-vulns/. The vuln variants must emit
 * >= 1 flow of the expected vuln_class; the safe variants must emit 0.
 *
 * Run: npx tsx test/taint-engine-java.test.ts
 */

import * as path from 'path';
import { propagateJava } from '../src/taint-engine/java/propagate';
import { loadSpec } from '../src/taint-engine';
import type { FrameworkSpec, VulnClass } from '../src/taint-engine';

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

const FIXTURES_ROOT = path.join(__dirname, 'taint-engine', 'fixtures', 'java-vulns');
const SPECS_ROOT = path.join(__dirname, '..', 'src', 'taint-engine', 'framework-models');

let cachedSpecs: FrameworkSpec[] | null = null;
function loadJavaSpecs(): FrameworkSpec[] {
  if (cachedSpecs) return cachedSpecs;
  cachedSpecs = [
    loadSpec(path.join(SPECS_ROOT, 'spring-boot.yaml')),
    loadSpec(path.join(SPECS_ROOT, 'java-stdlib.yaml')),
  ];
  return cachedSpecs;
}

interface FixtureCase {
  name: string;
  expectVuln: VulnClass;
}

const FIXTURE_PAIRS: FixtureCase[] = [
  { name: 'spring-sql-injection', expectVuln: 'sql_injection' },
  { name: 'spring-command-injection', expectVuln: 'command_injection' },
];

async function runFixture(fixtureDir: string) {
  const specs = loadJavaSpecs();
  return await propagateJava({ rootDir: fixtureDir, specs });
}

async function testFixturePair(c: FixtureCase) {
  console.log(`\n[fixture] ${c.name}`);
  const vulnDir = path.join(FIXTURES_ROOT, `${c.name}-vuln`);
  const safeDir = path.join(FIXTURES_ROOT, `${c.name}-safe`);

  const vulnResult = await runFixture(vulnDir);
  const matchingVuln = vulnResult.flows.filter((f) => f.vuln_class === c.expectVuln);
  assert(
    matchingVuln.length >= 1,
    `${c.name}-vuln emits at least one ${c.expectVuln} flow (got ${matchingVuln.length}; total flows=${vulnResult.flows.length})`,
  );
  if (matchingVuln.length === 0 && vulnResult.flows.length > 0) {
    console.log('   debug: flows seen:', vulnResult.flows.map((f) => `${f.vuln_class} @ ${f.sink_file}:${f.sink_line}`));
  } else if (matchingVuln.length === 0) {
    console.log(
      '   debug: callgraph nodes=', vulnResult.callgraph.nodes.length,
      'edges=', vulnResult.callgraph.edges.length,
      'sources_found=', vulnResult.stats.sourcesFound,
    );
  }

  const safeResult = await runFixture(safeDir);
  const matchingSafe = safeResult.flows.filter((f) => f.vuln_class === c.expectVuln);
  assert(
    matchingSafe.length === 0,
    `${c.name}-safe emits zero ${c.expectVuln} flows (got ${matchingSafe.length})`,
  );
  if (matchingSafe.length > 0) {
    console.log('   debug: unexpected flows:', matchingSafe.map((f) => `${f.entry_point_pattern} -> ${f.sink_pattern} @ ${f.sink_file}:${f.sink_line}`));
  }
}

async function main() {
  console.log('=== java taint-engine fixture tests ===');
  for (const fixture of FIXTURE_PAIRS) {
    try {
      await testFixturePair(fixture);
    } catch (err) {
      console.error(`  THREW for ${fixture.name}:`, err);
      failures++;
    }
  }
  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('test run threw:', err);
  process.exit(2);
});
