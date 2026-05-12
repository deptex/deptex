#!/usr/bin/env node
/**
 * Cross-language fixture recall scoreboard for the taint engine.
 *
 * Walks every `test/taint-engine/fixtures/<framework>-vulns/<slug>-{vuln,safe}/`
 * pair, runs the appropriate per-language propagator, asserts the engine
 * emits ≥1 flow of the expected `vuln_class` on `-vuln` pairs and zero on
 * `-safe` pairs, and aggregates results into a single recall report:
 *
 *   - global recall % (passing fixtures / total fixtures)
 *   - per-language recall % (the headline number to drive against)
 *   - per-vuln-class recall %
 *   - per-framework recall % (within each framework dir)
 *
 * Differences from `taint-engine:validate`:
 *   - Recognizes framework-prefixed fixture names (`rails-sql-injection-vuln`,
 *     `sinatra-xss-vuln`) instead of skipping them. Strips the prefix by
 *     finding the longest suffix that maps to a known vuln-class slug.
 *   - Dispatches to the correct per-language propagator based on the
 *     framework dir name (java-vulns → propagateJava, ruby-vulns →
 *     propagateRuby, etc.) instead of running everything through the JS
 *     propagator and silently emitting zero flows on non-JS sources.
 *   - Emits structured JSON (--json) for CI consumption alongside the
 *     human-readable summary table.
 *
 * Usage:
 *   npm run taint-engine:recall                      # all fixtures, table output
 *   npm run taint-engine:recall -- --json out.json   # also write JSON to out.json
 *   npm run taint-engine:recall -- --verbose         # list every fixture
 *   npm run taint-engine:recall -- --language java   # filter by language
 *
 * Exit code 0 if every fixture passes, 1 otherwise. Intended as the
 * canonical recall stage in the preflight harness.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  loadSpec,
  propagate,
  type FrameworkSpec,
  type VulnClass,
} from '../src/taint-engine';
import { propagatePython } from '../src/taint-engine/python/propagate';
import { propagateJava } from '../src/taint-engine/java/propagate';
import { propagateGo } from '../src/taint-engine/go/propagate';
import { propagateRuby } from '../src/taint-engine/ruby/propagate';
import { propagatePhp } from '../src/taint-engine/php/propagate';
import { propagateRust } from '../src/taint-engine/rust/propagate';
import { propagateCSharp } from '../src/taint-engine/csharp/propagate';

type Language = 'js' | 'python' | 'java' | 'go' | 'ruby' | 'php' | 'rust' | 'csharp';

/**
 * Maps a `<framework>-vulns/` directory name to the engine language whose
 * propagator should run against fixtures inside it. JS frameworks all use
 * the default propagator; everything else dispatches to the per-language
 * driver.
 */
const FRAMEWORK_TO_LANGUAGE: Record<string, Language> = {
  express: 'js',
  fastify: 'js',
  hono: 'js',
  nestjs: 'js',
  nextjs: 'js',
  python: 'python',
  java: 'java',
  go: 'go',
  ruby: 'ruby',
  php: 'php',
  rust: 'rust',
  csharp: 'csharp',
};

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

interface ParsedArgs {
  json: string | null;
  verbose: boolean;
  languageFilter: Language | null;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  let json: string | null = null;
  let verbose = false;
  let languageFilter: Language | null = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--verbose') verbose = true;
    else if (a === '--json') json = args[++i] ?? '';
    else if (a === '--language') {
      const v = args[++i];
      if (!v || !(v in { js: 1, python: 1, java: 1, go: 1, ruby: 1, php: 1, rust: 1, csharp: 1 })) {
        process.stderr.write(`unknown --language value: ${v ?? '(missing)'}\n`);
        process.exit(2);
      }
      languageFilter = v as Language;
    } else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else if (a.startsWith('--')) {
      process.stderr.write(`unknown flag: ${a}\n`);
      process.exit(2);
    }
  }
  return { json, verbose, languageFilter };
}

function printHelp(): void {
  process.stdout.write(`Usage: npm run taint-engine:recall -- [options]

Options:
  --json <path>          Also write a structured JSON report to <path>.
  --language <name>      Restrict to one language (js|python|java|go|ruby|php|rust|csharp).
  --verbose              Print every fixture's pass/fail line.

Exit code 0 if every fixture passes, 1 otherwise.
`);
}

/**
 * Strip the trailing -vuln or -safe suffix and find the longest
 * remaining suffix that maps to a known vuln_class slug. Lets us handle
 * framework-prefixed fixture names like `rails-sql-injection-vuln` →
 * sql_injection without listing every prefix combination.
 */
function parseFixtureName(name: string): { vulnClass: VulnClass; expectFlow: boolean } | null {
  const expectFlow = name.endsWith('-vuln');
  const expectSafe = name.endsWith('-safe');
  if (!expectFlow && !expectSafe) return null;
  const lastDash = name.lastIndexOf('-');
  if (lastDash < 0) return null;
  const sansSuffix = name.slice(0, lastDash);
  const parts = sansSuffix.split('-');
  for (let start = 0; start < parts.length; start++) {
    const candidate = parts.slice(start).join('-');
    const vulnClass = VULN_CLASS_FROM_SLUG[candidate];
    if (vulnClass) return { vulnClass, expectFlow };
  }
  return null;
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

interface FixtureCase {
  framework: string;
  language: Language;
  fixtureName: string;
  fixtureDir: string;
  vulnClass: VulnClass;
  expectFlow: boolean;
}

function discoverFixtures(repoRoot: string, languageFilter: Language | null): FixtureCase[] {
  const fixturesRoot = path.join(repoRoot, 'test', 'taint-engine', 'fixtures');
  if (!fs.existsSync(fixturesRoot)) return [];
  const cases: FixtureCase[] = [];
  for (const entry of fs.readdirSync(fixturesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.endsWith('-vulns')) continue;
    const framework = entry.name.replace(/-vulns$/, '');
    const language = FRAMEWORK_TO_LANGUAGE[framework];
    if (!language) continue;
    if (languageFilter && language !== languageFilter) continue;
    const frameworkDir = path.join(fixturesRoot, entry.name);
    for (const sub of fs.readdirSync(frameworkDir, { withFileTypes: true })) {
      if (!sub.isDirectory()) continue;
      const parsed = parseFixtureName(sub.name);
      if (!parsed) continue;
      cases.push({
        framework,
        language,
        fixtureName: sub.name,
        fixtureDir: path.join(frameworkDir, sub.name),
        vulnClass: parsed.vulnClass,
        expectFlow: parsed.expectFlow,
      });
    }
  }
  cases.sort((a, b) =>
    `${a.framework}/${a.fixtureName}`.localeCompare(`${b.framework}/${b.fixtureName}`),
  );
  return cases;
}

interface CaseResult {
  case: FixtureCase;
  flowsOfClass: number;
  flowsTotal: number;
  pass: boolean;
  totalMs: number;
  errorMessage: string | null;
}

async function runCase(specs: FrameworkSpec[], c: FixtureCase): Promise<CaseResult> {
  const start = Date.now();
  try {
    let flows: { vuln_class: string }[];
    let propagationMs: number;
    switch (c.language) {
      case 'js': {
        const r = await propagate({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'python': {
        const r = await propagatePython({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'java': {
        const r = await propagateJava({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'go': {
        const r = await propagateGo({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'ruby': {
        const r = await propagateRuby({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'php': {
        const r = await propagatePhp({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'rust': {
        const r = await propagateRust({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
      case 'csharp': {
        const r = await propagateCSharp({ rootDir: c.fixtureDir, specs });
        flows = r.flows;
        propagationMs = r.stats.totalMs;
        break;
      }
    }
    const flowsOfClass = flows.filter((f) => f.vuln_class === c.vulnClass).length;
    const pass = c.expectFlow ? flowsOfClass >= 1 : flowsOfClass === 0;
    return {
      case: c,
      flowsOfClass,
      flowsTotal: flows.length,
      pass,
      totalMs: propagationMs,
      errorMessage: null,
    };
  } catch (err) {
    return {
      case: c,
      flowsOfClass: 0,
      flowsTotal: 0,
      pass: false,
      totalMs: Date.now() - start,
      errorMessage: err instanceof Error ? err.message : String(err),
    };
  }
}

interface RecallBucket {
  total: number;
  passed: number;
  failed: number;
}

function bucket(): RecallBucket {
  return { total: 0, passed: 0, failed: 0 };
}

function pct(b: RecallBucket): number {
  return b.total === 0 ? 0 : (b.passed / b.total) * 100;
}

function fmtPct(n: number): string {
  return `${n.toFixed(1)}%`;
}

interface RecallReport {
  generatedAt: string;
  global: RecallBucket;
  perLanguage: Record<string, RecallBucket>;
  perVulnClass: Record<string, RecallBucket>;
  perFramework: Record<string, RecallBucket>;
  failures: Array<{
    framework: string;
    language: Language;
    fixture: string;
    vulnClass: VulnClass;
    expectFlow: boolean;
    flowsOfClass: number;
    flowsTotal: number;
    errorMessage: string | null;
  }>;
}

function buildReport(results: CaseResult[]): RecallReport {
  const global = bucket();
  const perLanguage: Record<string, RecallBucket> = {};
  const perVulnClass: Record<string, RecallBucket> = {};
  const perFramework: Record<string, RecallBucket> = {};
  const failures: RecallReport['failures'] = [];
  for (const r of results) {
    global.total++;
    if (r.pass) global.passed++;
    else global.failed++;
    const lang = r.case.language;
    perLanguage[lang] ??= bucket();
    perLanguage[lang].total++;
    if (r.pass) perLanguage[lang].passed++;
    else perLanguage[lang].failed++;
    const vc = r.case.vulnClass;
    perVulnClass[vc] ??= bucket();
    perVulnClass[vc].total++;
    if (r.pass) perVulnClass[vc].passed++;
    else perVulnClass[vc].failed++;
    const fw = r.case.framework;
    perFramework[fw] ??= bucket();
    perFramework[fw].total++;
    if (r.pass) perFramework[fw].passed++;
    else perFramework[fw].failed++;
    if (!r.pass) {
      failures.push({
        framework: r.case.framework,
        language: r.case.language,
        fixture: r.case.fixtureName,
        vulnClass: r.case.vulnClass,
        expectFlow: r.case.expectFlow,
        flowsOfClass: r.flowsOfClass,
        flowsTotal: r.flowsTotal,
        errorMessage: r.errorMessage,
      });
    }
  }
  return {
    generatedAt: new Date().toISOString(),
    global,
    perLanguage,
    perVulnClass,
    perFramework,
    failures,
  };
}

function printSummary(report: RecallReport): void {
  process.stdout.write('\n=== Taint Engine Recall ===\n\n');
  const g = report.global;
  process.stdout.write(`global:    ${fmtPct(pct(g)).padStart(6)}  (${g.passed}/${g.total})\n\n`);

  const langs = Object.keys(report.perLanguage).sort();
  process.stdout.write('by language:\n');
  for (const k of langs) {
    const b = report.perLanguage[k];
    process.stdout.write(`  ${k.padEnd(8)} ${fmtPct(pct(b)).padStart(6)}  (${b.passed}/${b.total})\n`);
  }
  process.stdout.write('\n');

  const vcs = Object.keys(report.perVulnClass).sort();
  process.stdout.write('by vuln class:\n');
  for (const k of vcs) {
    const b = report.perVulnClass[k];
    process.stdout.write(`  ${k.padEnd(22)} ${fmtPct(pct(b)).padStart(6)}  (${b.passed}/${b.total})\n`);
  }
  process.stdout.write('\n');

  const fws = Object.keys(report.perFramework).sort();
  process.stdout.write('by framework dir:\n');
  for (const k of fws) {
    const b = report.perFramework[k];
    process.stdout.write(`  ${k.padEnd(10)} ${fmtPct(pct(b)).padStart(6)}  (${b.passed}/${b.total})\n`);
  }

  if (report.failures.length > 0) {
    process.stdout.write(`\n${report.failures.length} failure(s):\n`);
    for (const f of report.failures) {
      const tag = f.expectFlow ? `expected ≥1 ${f.vulnClass}, got ${f.flowsOfClass}` : `expected 0 ${f.vulnClass}, got ${f.flowsOfClass}`;
      process.stdout.write(`  [${f.framework}] ${f.fixture}  ${tag}`);
      if (f.errorMessage) process.stdout.write(`  err=${f.errorMessage}`);
      process.stdout.write('\n');
    }
  }
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);
  const repoRoot = path.resolve(__dirname, '..');
  const specs = loadAllSpecs(repoRoot);
  if (specs.length === 0) {
    process.stderr.write('no framework specs found at src/taint-engine/framework-models/\n');
    process.exit(2);
  }

  const cases = discoverFixtures(repoRoot, opts.languageFilter);
  if (cases.length === 0) {
    process.stderr.write('no fixture pairs discovered; check test/taint-engine/fixtures/\n');
    process.exit(2);
  }

  process.stdout.write(`Loaded ${specs.length} framework specs · running ${cases.length} fixtures\n`);
  if (opts.languageFilter) {
    process.stdout.write(`(filtered to language=${opts.languageFilter})\n`);
  }

  const results: CaseResult[] = [];
  for (const c of cases) {
    const r = await runCase(specs, c);
    results.push(r);
    if (opts.verbose || !r.pass) {
      const tag = r.pass ? 'PASS' : 'FAIL';
      const expectStr = c.expectFlow ? '≥1' : '0';
      const errPart = r.errorMessage ? `  err=${r.errorMessage}` : '';
      process.stdout.write(
        `[${tag}] ${c.framework.padEnd(10)} ${c.fixtureName.padEnd(40)} class=${c.vulnClass.padEnd(20)} expected=${expectStr}  got=${r.flowsOfClass}  (${r.totalMs}ms)${errPart}\n`,
      );
    }
  }

  const report = buildReport(results);
  printSummary(report);

  if (opts.json !== null) {
    const outPath = opts.json || path.join(repoRoot, 'taint-engine-recall.json');
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    process.stdout.write(`\nWrote ${outPath}\n`);
  }

  process.exit(report.global.failed === 0 ? 0 : 1);
}

main().catch((err) => {
  process.stderr.write(`recall failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(2);
});
