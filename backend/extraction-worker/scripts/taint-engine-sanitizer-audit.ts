/**
 * Sanitizer audit — pin down that every `-safe` fixture is actually
 * exercising a sanitizer, not trivially passing.
 *
 * The validate harness only asserts `flowsOfClass === 0` for `-safe`
 * fixtures. That passes when:
 *   (a) a source is detected and the sanitizer cancels it before the sink, OR
 *   (b) no source is detected at all (fixture is silently broken — engine
 *       has no signal to evaluate the sanitizer)
 *
 * Case (b) is the silent failure mode. When a fixture is rewritten and the
 * source pattern stops matching (refactor, framework spec drift, lowerer
 * regression), the fixture keeps "passing" without ever testing the safe
 * path. Pinning sources >= 1 at audit time turns this into a hard fail.
 *
 * For each `-safe` fixture under test/taint-engine/fixtures/`<framework>`-vulns/:
 *   - PASS: stats.sourcesFound >= 1 AND flowsOfClass === 0
 *   - FAIL: anything else (no source ⇒ trivial pass; flow emitted ⇒ sanitizer
 *           didn't trigger and the fixture should have been -vuln)
 *
 * Currently scoped to JS frameworks (express/fastify/hono/nestjs/nextjs) since
 * `propagate()` is the JS driver. Per-language safe fixtures (django-*, gin-*,
 * spring-*, etc.) get the equivalent guard from their per-language test files.
 *
 * Run: npm run taint-engine:sanitizer-audit
 * Exit 0 = all sanitizers exercised, 1 = at least one trivial pass
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  loadSpec,
  propagate,
  type FrameworkSpec,
  type VulnClass,
} from '../src/taint-engine';

const VULN_CLASS_FROM_SLUG: Record<string, VulnClass> = {
  'command-injection': 'command_injection',
  'sql-injection': 'sql_injection',
  ssrf: 'ssrf',
  xss: 'xss',
  'path-traversal': 'path_traversal',
  'prototype-pollution': 'prototype_pollution',
  deserialization: 'deserialization',
  redos: 'redos',
  'file-upload': 'file_upload',
  'open-redirect': 'open_redirect',
  'log-injection': 'log_injection',
};

interface FixtureProbe {
  framework: string;
  fixtureName: string;
  fixtureDir: string;
  vulnClass: VulnClass;
  sourcesFound: number;
  sinksHit: number;
  flowsOfClass: number;
  pass: boolean;
  reason?: string;
}

function loadAllSpecs(repoRoot: string): FrameworkSpec[] {
  const dir = path.join(repoRoot, 'src', 'taint-engine', 'framework-models');
  if (!fs.existsSync(dir)) return [];
  const specs: FrameworkSpec[] = [];
  for (const entry of fs.readdirSync(dir)) {
    if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
    specs.push(loadSpec(path.join(dir, entry)));
  }
  return specs;
}

async function probe(
  specs: FrameworkSpec[],
  framework: string,
  fixtureName: string,
  fixtureDir: string,
): Promise<FixtureProbe | null> {
  const slug = fixtureName.slice(0, fixtureName.lastIndexOf('-'));
  const vulnClass = VULN_CLASS_FROM_SLUG[slug];
  if (!vulnClass) return null;
  const result = await propagate({ rootDir: fixtureDir, specs });
  const flowsOfClass = result.flows.filter((f) => f.vuln_class === vulnClass).length;
  const sourcesFound = result.stats.sourcesFound;
  let pass = true;
  let reason: string | undefined;
  if (sourcesFound === 0) {
    pass = false;
    reason = 'no source detected — sanitizer not exercised (trivial pass)';
  } else if (flowsOfClass !== 0) {
    pass = false;
    reason = `${flowsOfClass} flow(s) of class ${vulnClass} leaked through sanitizer`;
  }
  return {
    framework,
    fixtureName,
    fixtureDir,
    vulnClass,
    sourcesFound,
    sinksHit: result.stats.sinksHit,
    flowsOfClass,
    pass,
    reason,
  };
}

async function main(): Promise<void> {
  const repoRoot = path.resolve(__dirname, '..');
  const specs = loadAllSpecs(repoRoot);
  if (specs.length === 0) {
    process.stderr.write('no framework specs found\n');
    process.exit(2);
  }

  // JS frameworks only — per-language fixtures are guarded by their own test files.
  const jsFrameworks = ['express', 'fastify', 'hono', 'nestjs', 'nextjs'];
  process.stdout.write('=== Taint engine sanitizer audit ===\n');
  process.stdout.write(`scope: ${jsFrameworks.join(', ')}\n\n`);

  const probes: FixtureProbe[] = [];
  for (const framework of jsFrameworks) {
    const fixturesDir = path.join(repoRoot, 'test', 'taint-engine', 'fixtures', `${framework}-vulns`);
    if (!fs.existsSync(fixturesDir)) {
      process.stderr.write(`fixtures dir missing: ${fixturesDir}\n`);
      continue;
    }
    process.stdout.write(`-- ${framework} --\n`);
    const entries = fs.readdirSync(fixturesDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory() || !entry.name.endsWith('-safe')) continue;
      const result = await probe(
        specs,
        framework,
        entry.name,
        path.join(fixturesDir, entry.name),
      );
      if (!result) continue;
      probes.push(result);
      const tag = result.pass ? 'PASS' : 'FAIL';
      const detail = result.reason ? `  (${result.reason})` : '';
      process.stdout.write(
        `[${tag}] ${result.fixtureName.padEnd(32)} sources=${result.sourcesFound} flows_of_class=${result.flowsOfClass}${detail}\n`,
      );
    }
    process.stdout.write('\n');
  }

  const passed = probes.filter((p) => p.pass).length;
  const failed = probes.length - passed;
  process.stdout.write(`${passed}/${probes.length} -safe fixtures actually exercise their sanitizer\n`);
  if (failed > 0) {
    process.stdout.write('\nFailures:\n');
    for (const p of probes.filter((p) => !p.pass)) {
      process.stdout.write(`  - ${p.framework}/${p.fixtureName}: ${p.reason}\n`);
    }
  }
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`sanitizer audit crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(2);
});
