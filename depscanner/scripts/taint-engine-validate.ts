/**
 * Validation harness for hand-written framework specs.
 *
 * Usage:
 *   npm run taint-engine:validate -- <framework>[,<framework>...] [--verbose]
 *   npm run taint-engine:validate -- all [--verbose]
 *
 * Loads ALL framework-models/*.yaml (mirroring the production runner) so a
 * fixture written against Express sources can hit a sink declared in
 * node-stdlib.yaml the same way it does at extraction time. The framework
 * argument selects which fixture suite at test/taint-engine/fixtures/
 * <framework>-vulns/ to assert against.
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
import {
  detectSanitizerAbsence,
  extractCallSitesFromIr,
} from '../src/taint-engine/non-taint-detector';

interface ParsedArgs {
  frameworks: string[];
  verbose: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  let frameworks: string[] = [];
  let verbose = false;
  for (const a of args) {
    if (a === '--verbose') verbose = true;
    else if (!a.startsWith('--')) frameworks = a.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (frameworks.length === 0) {
    process.stderr.write('Usage: npm run taint-engine:validate -- <framework>[,<framework>...] [--verbose]\n');
    process.exit(2);
  }
  return { frameworks, verbose };
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
  'code-injection': 'code_injection',
  'weak-crypto': 'weak_crypto',
  'auth-bypass': 'auth_bypass',
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

async function runFixture(specs: FrameworkSpec[], expectation: Expectation): Promise<RunResult> {
  const result = await propagate({
    rootDir: expectation.fixtureDir,
    specs,
  });
  let flowsOfClass = result.flows.filter((f) => f.vuln_class === expectation.vulnClass).length;
  // Phase F4 — also count non-taint detector findings for this class.
  if (result.irFunctions && result.irFunctions.length > 0) {
    const callsites = extractCallSitesFromIr(result.irFunctions, 'js');
    for (const spec of specs) {
      const hasReqArgs = spec.sinks.some(
        (s) => s.required_arguments && s.required_arguments.length > 0,
      );
      if (!hasReqArgs) continue;
      const findings = detectSanitizerAbsence(spec, callsites);
      flowsOfClass += findings.filter((f) => f.vuln_class === expectation.vulnClass).length;
    }
  }
  const pass = expectation.expectFlow ? flowsOfClass >= 1 : flowsOfClass === 0;
  return { expectation, flowsOfClass, flowsTotal: result.flows.length, pass, totalMs: result.stats.totalMs };
}

function loadAllSpecs(repoRoot: string): { specs: FrameworkSpec[]; loaded: string[] } {
  const dir = path.join(repoRoot, 'src', 'taint-engine', 'framework-models');
  if (!fs.existsSync(dir)) return { specs: [], loaded: [] };
  const specs: FrameworkSpec[] = [];
  const loaded: string[] = [];
  for (const entry of fs.readdirSync(dir)) {
    if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
    const spec = loadSpec(path.join(dir, entry));
    specs.push(spec);
    loaded.push(spec.framework);
  }
  return { specs, loaded };
}

function expandFrameworkArgs(args: string[], repoRoot: string): string[] {
  if (args.length === 1 && args[0] === 'all') {
    const fixturesRoot = path.join(repoRoot, 'test', 'taint-engine', 'fixtures');
    if (!fs.existsSync(fixturesRoot)) return [];
    return fs
      .readdirSync(fixturesRoot, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name.endsWith('-vulns'))
      .map((e) => e.name.replace(/-vulns$/, ''))
      .sort();
  }
  return args;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  const repoRoot = path.resolve(__dirname, '..');
  const { specs, loaded } = loadAllSpecs(repoRoot);
  if (specs.length === 0) {
    process.stderr.write('no framework specs found at src/taint-engine/framework-models/\n');
    process.exit(2);
  }

  const frameworks = expandFrameworkArgs(opts.frameworks, repoRoot);
  if (frameworks.length === 0) {
    process.stderr.write('no fixture suites resolved from --all\n');
    process.exit(2);
  }

  process.stdout.write(`=== Validating taint engine specs ===\n`);
  process.stdout.write(`loaded specs: ${loaded.join(', ')}\n`);
  process.stdout.write(`fixture suites: ${frameworks.join(', ')}\n\n`);

  const allResults: RunResult[] = [];

  for (const framework of frameworks) {
    const fixturesDir = path.join(repoRoot, 'test', 'taint-engine', 'fixtures', `${framework}-vulns`);
    if (!fs.existsSync(fixturesDir)) {
      process.stderr.write(`fixtures dir not found: ${fixturesDir}\n`);
      continue;
    }
    process.stdout.write(`-- ${framework} --\n`);

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

    for (const expectation of expectations) {
      const result = await runFixture(specs, expectation);
      allResults.push(result);
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
    process.stdout.write('\n');
  }

  const passed = allResults.filter((r) => r.pass).length;
  const failed = allResults.length - passed;
  process.stdout.write(`${passed}/${allResults.length} fixtures passed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`validate failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(2);
});
