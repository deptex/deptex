/**
 * Validation harness for hand-written framework specs.
 *
 * Usage:
 *   npm run taint-engine:validate -- <framework> [--verbose]
 *
 * Looks up the spec at src/taint-engine/framework-models/<framework>.yaml
 * and the fixture suite at test/taint-engine/fixtures/<framework>-vulns/.
 *
 * Each fixture directory's name encodes the expected outcome via the
 * suffix `-vuln` or `-safe`, with the prefix being the vuln class:
 *
 *   command-injection-vuln/  → must produce ≥1 flow with vuln_class=command_injection
 *   command-injection-safe/  → must produce 0 flows with vuln_class=command_injection
 *
 * Fixtures with unrecognized names are skipped with a warning. Exit 0 if
 * all assertions pass, 1 otherwise; emits a summary table to stderr.
 */

import * as fs from 'fs';
import * as path from 'path';
import { loadSpec, propagate, type FrameworkSpec, type VulnClass } from '../src/taint-engine';

interface ParsedArgs {
  framework: string;
  verbose: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  let framework: string | undefined;
  let verbose = false;
  for (const a of args) {
    if (a === '--verbose') verbose = true;
    else if (!a.startsWith('--')) framework = a;
  }
  if (!framework) {
    process.stderr.write('Usage: npm run taint-engine:validate -- <framework> [--verbose]\n');
    process.exit(2);
  }
  return { framework, verbose };
}

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

interface Expectation {
  fixtureDir: string;
  fixtureName: string;
  vulnClass: VulnClass;
  expectFlow: boolean;
}

function parseFixtureName(name: string): Omit<Expectation, 'fixtureDir' | 'fixtureName'> | null {
  const expectFlow = name.endsWith('-vuln');
  const expectSafe = name.endsWith('-safe');
  if (!expectFlow && !expectSafe) return null;
  const slug = name.slice(0, name.lastIndexOf('-'));
  const vulnClass = VULN_CLASS_FROM_SLUG[slug];
  if (!vulnClass) return null;
  return { vulnClass, expectFlow };
}

interface RunResult {
  expectation: Expectation;
  flowsOfClass: number;
  flowsTotal: number;
  pass: boolean;
  totalMs: number;
}

async function runFixture(spec: FrameworkSpec, expectation: Expectation): Promise<RunResult> {
  const result = await propagate({
    rootDir: expectation.fixtureDir,
    specs: [spec],
  });
  const flowsOfClass = result.flows.filter((f) => f.vuln_class === expectation.vulnClass).length;
  const pass = expectation.expectFlow ? flowsOfClass >= 1 : flowsOfClass === 0;
  return { expectation, flowsOfClass, flowsTotal: result.flows.length, pass, totalMs: result.stats.totalMs };
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  const repoRoot = path.resolve(__dirname, '..');
  const specPath = path.join(repoRoot, 'src', 'taint-engine', 'framework-models', `${opts.framework}.yaml`);
  const fixturesDir = path.join(repoRoot, 'test', 'taint-engine', 'fixtures', `${opts.framework}-vulns`);

  if (!fs.existsSync(specPath)) {
    process.stderr.write(`spec not found: ${specPath}\n`);
    process.exit(2);
  }
  if (!fs.existsSync(fixturesDir)) {
    process.stderr.write(`fixtures dir not found: ${fixturesDir}\n`);
    process.exit(2);
  }

  const spec = loadSpec(specPath);
  process.stdout.write(`=== Validating ${opts.framework} spec ===\n`);
  process.stdout.write(`spec: ${specPath}\n`);
  process.stdout.write(`fixtures: ${fixturesDir}\n\n`);

  const entries = fs.readdirSync(fixturesDir, { withFileTypes: true });
  const expectations: Expectation[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const parsed = parseFixtureName(entry.name);
    if (!parsed) {
      process.stderr.write(`[skip] ${entry.name} — not a recognized fixture pattern\n`);
      continue;
    }
    expectations.push({
      ...parsed,
      fixtureName: entry.name,
      fixtureDir: path.join(fixturesDir, entry.name),
    });
  }
  expectations.sort((a, b) => a.fixtureName.localeCompare(b.fixtureName));

  const results: RunResult[] = [];
  for (const expectation of expectations) {
    const result = await runFixture(spec, expectation);
    results.push(result);
    const tag = result.pass ? 'PASS' : 'FAIL';
    const expectStr = expectation.expectFlow ? '≥1' : '0';
    process.stdout.write(
      `[${tag}] ${expectation.fixtureName.padEnd(32)} class=${expectation.vulnClass.padEnd(20)} expected=${expectStr}  got=${result.flowsOfClass}  (${result.totalMs}ms)\n`,
    );
    if (!result.pass && opts.verbose) {
      process.stdout.write(`       fixture dir: ${expectation.fixtureDir}\n`);
      process.stdout.write(`       total flows of any class: ${result.flowsTotal}\n`);
    }
  }

  const passed = results.filter((r) => r.pass).length;
  const failed = results.length - passed;
  process.stdout.write(`\n${passed}/${results.length} fixtures passed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`validate failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(2);
});
