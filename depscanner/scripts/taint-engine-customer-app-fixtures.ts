/**
 * Phase 1.3a (reachability-90-percent) — customer-app fixture runner.
 *
 * Walks `test/customer-app-fixtures/<eco>-<framework>-<vuln-shape>/`
 * subdirectories and, for each fixture, runs the cross-file taint engine
 * over BOTH the `vuln/` and `safe/` sub-trees. Loads every bundled
 * framework_model (the runtime production setup), plus an optional
 * fixture-specific `spec.json` if one is supplied — and asserts:
 *
 *   - vuln/ produces ≥ meta.expected_vuln_flows_min flows whose
 *     `vuln_class === meta.expected_vuln_class`
 *   - safe/ produces ≤ meta.expected_safe_flows_max flows of the same
 *     vuln_class (default 0 — the patched source must look clean to the
 *     engine)
 *
 * Unlike `taint-engine-cve-targeted-fixtures.ts`, this suite uses bundled
 * framework_models — exactly the spec set the production engine loads in
 * `runner.ts`. The vuln-class assertion therefore proves the engine wires
 * up source/sink/sanitizer relations correctly on a real-customer-shaped
 * multi-file project, NOT just that osv_id round-trips on a single-file
 * fixture (which is what cve-targeted-flow-fixtures covers).
 *
 * Per-fixture result JSON is written to
 * `test/customer-app-fixtures/baseline-<gitsha>.json` after each run so we
 * can diff against earlier commits as the engine evolves.
 *
 * Run: npm run test:customer-app
 *
 * Exit 0 = all fixtures pass; exit 1 = at least one fixture failed.
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { loadSpec, loadSpecFromJson } from '../src/taint-engine/spec-loader';
import type { FrameworkLanguage, FrameworkSpec, VulnClass } from '../src/taint-engine/spec';
import type { Flow } from '../src/taint-engine/flow';
import type { PropagateResult } from '../src/taint-engine/propagator';
import { propagate } from '../src/taint-engine/propagator';
import { propagatePython } from '../src/taint-engine/python/propagate';
import { propagateJava } from '../src/taint-engine/java/propagate';
import { propagateGo } from '../src/taint-engine/go/propagate';
import { propagateRuby } from '../src/taint-engine/ruby/propagate';
import { propagatePhp } from '../src/taint-engine/php/propagate';
import { propagateRust } from '../src/taint-engine/rust/propagate';
import { propagateCSharp } from '../src/taint-engine/csharp/propagate';

export interface CustomerFixtureMeta {
  language: FrameworkLanguage;
  framework: string;
  expected_osv_id: string;
  expected_vuln_class: VulnClass;
  expected_vuln_flows_min: number;
  expected_safe_flows_max: number;
  package: string;
  description?: string;
}

export interface CustomerFixtureResult {
  name: string;
  language: FrameworkLanguage;
  expected_vuln_class: VulnClass;
  expected_vuln_flows_min: number;
  expected_safe_flows_max: number;
  pass: boolean;
  vuln_flows_count: number;
  safe_flows_count: number;
  duration_ms: number;
  failure_reason?: string;
}

export const CUSTOMER_FIXTURES_ROOT = path.resolve(__dirname, '../test/customer-app-fixtures');
const FRAMEWORK_MODELS_DIR = path.resolve(__dirname, '../src/taint-engine/framework-models');

function readJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
}

function loadBundledSpecs(): FrameworkSpec[] {
  if (!fs.existsSync(FRAMEWORK_MODELS_DIR)) return [];
  const specs: FrameworkSpec[] = [];
  for (const entry of fs.readdirSync(FRAMEWORK_MODELS_DIR)) {
    if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
    try {
      specs.push(loadSpec(path.join(FRAMEWORK_MODELS_DIR, entry)));
    } catch (err) {
      process.stderr.write(`warn: failed to load bundled spec ${entry}: ${(err as Error).message}\n`);
    }
  }
  return specs;
}

async function runPropagator(
  language: FrameworkLanguage,
  rootDir: string,
  specs: FrameworkSpec[],
): Promise<PropagateResult> {
  switch (language) {
    case 'python':
      return propagatePython({ rootDir, specs });
    case 'java':
      return propagateJava({ rootDir, specs });
    case 'go':
      return propagateGo({ rootDir, specs });
    case 'ruby':
      return propagateRuby({ rootDir, specs });
    case 'php':
      return propagatePhp({ rootDir, specs });
    case 'rust':
      return propagateRust({ rootDir, specs });
    case 'csharp':
      return propagateCSharp({ rootDir, specs });
    case 'js':
    default:
      return propagate({ rootDir, specs });
  }
}

export function listCustomerFixtureDirs(root: string = CUSTOMER_FIXTURES_ROOT): string[] {
  if (!fs.existsSync(root)) return [];
  return fs
    .readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => path.join(root, e.name))
    .sort();
}

export async function runOneCustomerFixture(
  fixtureDir: string,
  bundledSpecs: FrameworkSpec[],
): Promise<CustomerFixtureResult> {
  const name = path.basename(fixtureDir);
  const start = Date.now();

  const metaPath = path.join(fixtureDir, 'meta.json');
  if (!fs.existsSync(metaPath)) {
    return {
      name,
      language: 'js',
      expected_vuln_class: 'sql_injection',
      expected_vuln_flows_min: 1,
      expected_safe_flows_max: 0,
      pass: false,
      vuln_flows_count: 0,
      safe_flows_count: 0,
      duration_ms: Date.now() - start,
      failure_reason: `missing meta.json at ${fixtureDir}`,
    };
  }
  const meta = readJson<CustomerFixtureMeta>(metaPath);

  // Optional per-fixture spec.json — additive on top of bundled models so a
  // fixture can declare a CVE-specific sink that isn't in the bundled set
  // yet. Bundled-only fixtures leave spec.json absent.
  let extraSpec: FrameworkSpec | null = null;
  const specPath = path.join(fixtureDir, 'spec.json');
  if (fs.existsSync(specPath)) {
    try {
      extraSpec = loadSpecFromJson(readJson<unknown>(specPath), name);
    } catch (err) {
      return {
        name,
        language: meta.language,
        expected_vuln_class: meta.expected_vuln_class,
        expected_vuln_flows_min: meta.expected_vuln_flows_min,
        expected_safe_flows_max: meta.expected_safe_flows_max,
        pass: false,
        vuln_flows_count: 0,
        safe_flows_count: 0,
        duration_ms: Date.now() - start,
        failure_reason: `spec.json failed validation: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  const specsForFixture: FrameworkSpec[] = extraSpec ? [...bundledSpecs, extraSpec] : bundledSpecs;

  const vulnDir = path.join(fixtureDir, 'vuln');
  const safeDir = path.join(fixtureDir, 'safe');
  if (!fs.existsSync(vulnDir) || !fs.existsSync(safeDir)) {
    return {
      name,
      language: meta.language,
      expected_vuln_class: meta.expected_vuln_class,
      expected_vuln_flows_min: meta.expected_vuln_flows_min,
      expected_safe_flows_max: meta.expected_safe_flows_max,
      pass: false,
      vuln_flows_count: 0,
      safe_flows_count: 0,
      duration_ms: Date.now() - start,
      failure_reason: `fixture must contain both vuln/ and safe/ subdirectories`,
    };
  }

  let vulnResult: PropagateResult;
  let safeResult: PropagateResult;
  try {
    vulnResult = await runPropagator(meta.language, vulnDir, specsForFixture);
    safeResult = await runPropagator(meta.language, safeDir, specsForFixture);
  } catch (err) {
    return {
      name,
      language: meta.language,
      expected_vuln_class: meta.expected_vuln_class,
      expected_vuln_flows_min: meta.expected_vuln_flows_min,
      expected_safe_flows_max: meta.expected_safe_flows_max,
      pass: false,
      vuln_flows_count: 0,
      safe_flows_count: 0,
      duration_ms: Date.now() - start,
      failure_reason: `propagator threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const matchingVulnFlows = vulnResult.flows.filter(
    (f: Flow) => f.vuln_class === meta.expected_vuln_class,
  );
  const matchingSafeFlows = safeResult.flows.filter(
    (f: Flow) => f.vuln_class === meta.expected_vuln_class,
  );

  const vulnOk = matchingVulnFlows.length >= meta.expected_vuln_flows_min;
  const safeOk = matchingSafeFlows.length <= meta.expected_safe_flows_max;
  const pass = vulnOk && safeOk;

  let failureReason: string | undefined;
  if (!vulnOk) {
    failureReason = `vuln/ expected ≥${meta.expected_vuln_flows_min} ${meta.expected_vuln_class} flows; got ${matchingVulnFlows.length} (of ${vulnResult.flows.length} total)`;
  } else if (!safeOk) {
    failureReason = `safe/ expected ≤${meta.expected_safe_flows_max} ${meta.expected_vuln_class} flows; got ${matchingSafeFlows.length} (of ${safeResult.flows.length} total)`;
  }

  return {
    name,
    language: meta.language,
    expected_vuln_class: meta.expected_vuln_class,
    expected_vuln_flows_min: meta.expected_vuln_flows_min,
    expected_safe_flows_max: meta.expected_safe_flows_max,
    pass,
    vuln_flows_count: matchingVulnFlows.length,
    safe_flows_count: matchingSafeFlows.length,
    duration_ms: Date.now() - start,
    failure_reason: failureReason,
  };
}

function currentGitSha(): string {
  try {
    return execSync('git rev-parse --short HEAD', {
      cwd: path.resolve(__dirname, '..'),
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    }).trim();
  } catch {
    return 'unknown';
  }
}

async function main(): Promise<void> {
  if (!fs.existsSync(CUSTOMER_FIXTURES_ROOT)) {
    process.stderr.write(`fixtures root not found: ${CUSTOMER_FIXTURES_ROOT}\n`);
    process.exit(2);
  }
  const dirs = listCustomerFixtureDirs();
  if (dirs.length === 0) {
    process.stderr.write('no customer-app fixtures found\n');
    process.exit(2);
  }

  process.stdout.write('=== customer-app multi-file fixture runner (Phase 1.3a) ===\n');
  process.stdout.write(`fixtures: ${dirs.length}\n\n`);

  const bundledSpecs = loadBundledSpecs();
  process.stdout.write(`bundled framework-models loaded: ${bundledSpecs.length}\n\n`);

  const results: CustomerFixtureResult[] = [];
  for (const dir of dirs) {
    const r = await runOneCustomerFixture(dir, bundledSpecs);
    results.push(r);
    const tag = r.pass ? 'PASS' : 'FAIL';
    process.stdout.write(
      `[${tag}] ${r.name.padEnd(38)} lang=${r.language.padEnd(7)} class=${r.expected_vuln_class.padEnd(18)} vuln=${r.vuln_flows_count} safe=${r.safe_flows_count}  (${r.duration_ms}ms)\n`,
    );
    if (!r.pass && r.failure_reason) {
      process.stdout.write(`       ↳ ${r.failure_reason}\n`);
    }
  }

  const sha = currentGitSha();
  const baselinePath = path.join(CUSTOMER_FIXTURES_ROOT, `baseline-${sha}.json`);
  const baseline = {
    git_sha: sha,
    generated_at: new Date().toISOString(),
    fixtures: results.map((r) => ({
      name: r.name,
      pass: r.pass,
      vuln_flows_count: r.vuln_flows_count,
      safe_flows_count: r.safe_flows_count,
      duration_ms: r.duration_ms,
    })),
  };
  try {
    fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + '\n', 'utf8');
    process.stdout.write(`\nbaseline written to ${path.relative(process.cwd(), baselinePath)}\n`);
  } catch (err) {
    process.stderr.write(`warn: could not write baseline: ${(err as Error).message}\n`);
  }

  const passed = results.filter((r) => r.pass).length;
  process.stdout.write(`\n${passed}/${results.length} fixtures passed\n`);
  process.exit(passed === results.length ? 0 : 1);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`runner crashed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(2);
  });
}
