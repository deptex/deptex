#!/usr/bin/env node
/**
 * Cross-ecosystem smoke runner.
 *
 * Walks the four `deptex-test-*` reference repos (npm / python / java / go),
 * picks the production language dispatch for each, loads every framework spec
 * that matches, and runs the propagator end-to-end. Confirms that the engine
 * does NOT crash on a real-world project for any language — even when the
 * project is framework-less and is expected to emit zero flows.
 *
 * This is the cheapest possible "would the production runner survive?" check
 * before we let the engine off shadow into any real org.
 *
 * Usage:
 *   npm run taint-engine:smoke-cross-ecosystem
 *
 * Override repo locations:
 *   DEPTEX_TEST_REPOS_ROOT=/path/to/deptex-test-repos npm run ...
 *
 * Exit code:
 *   0  — every repo propagated without throwing
 *   1  — any repo crashed, or any expected-flow repo emitted zero flows
 *   2  — repo paths missing on disk (skipped, treated as setup error)
 */

import * as fs from 'fs';
import * as path from 'path';
import { loadSpec, propagate, type FrameworkSpec } from '../../../src/taint-engine';
import type { FrameworkLanguage } from '../../../src/taint-engine/spec';
import { propagatePython } from '../../../src/taint-engine/python/propagate';
import { propagateJava } from '../../../src/taint-engine/java/propagate';
import { propagateGo } from '../../../src/taint-engine/go/propagate';
import { propagateRuby } from '../../../src/taint-engine/ruby/propagate';
import { propagatePhp } from '../../../src/taint-engine/php/propagate';
import { propagateRust } from '../../../src/taint-engine/rust/propagate';
import { propagateCSharp } from '../../../src/taint-engine/csharp/propagate';
import type { PropagateResult } from '../../../src/taint-engine/propagator';

interface RepoCase {
  id: string;
  ecosystem: 'npm' | 'pypi' | 'maven' | 'gomod';
  /** Sub-path under DEPTEX_TEST_REPOS_ROOT. */
  dir: string;
  /** Whether we expect ≥1 flow to be emitted. False for framework-less smoke repos. */
  expectFlows: boolean;
  /** Brief explanation surfaced when expectations are violated. */
  rationale: string;
}

const CASES: RepoCase[] = [
  {
    id: 'deptex-test-npm',
    ecosystem: 'npm',
    dir: 'deptex-test-npm',
    expectFlows: true,
    rationale: 'Express handlers route req.* into vulnerable deps — engine should match via express.yaml + node-stdlib.yaml.',
  },
  {
    id: 'deptex-test-go',
    ecosystem: 'gomod',
    dir: 'deptex-test-go',
    expectFlows: false,
    rationale:
      'Gin handlers feed user input into x/text + x/net — those sinks live in long-tail third-party packages, ' +
      'which Phase 6 specs intentionally do not model (Phase 5 per-CVE rules cover them). Smoke confirms the ' +
      'gin source patterns + Go callgraph load without crashing; real Go recall measurement happens via the ' +
      'gin-source × go-stdlib-sink fixture matrix (Unit 2, Day 4).',
  },
  {
    id: 'deptex-test-python',
    ecosystem: 'pypi',
    dir: 'deptex-test-python',
    expectFlows: false,
    rationale: 'Plain Python script with no Flask/Django/FastAPI handler — no framework-recognized source.',
  },
  {
    id: 'deptex-test-java',
    ecosystem: 'maven',
    dir: 'deptex-test-java',
    expectFlows: false,
    rationale: 'Plain Java main() with no Spring controller — no framework-recognized source.',
  },
];

const FRAMEWORK_MODELS_DIR = path.resolve(__dirname, '..', '..', '..', 'src', 'taint-engine', 'framework-models');

function ecosystemToLanguage(eco: RepoCase['ecosystem']): FrameworkLanguage {
  switch (eco) {
    case 'pypi': return 'python';
    case 'maven': return 'java';
    case 'gomod': return 'go';
    case 'npm':
    default: return 'js';
  }
}

function loadSpecsForLanguage(language: FrameworkLanguage): { specs: FrameworkSpec[]; warnings: string[] } {
  const warnings: string[] = [];
  const specs: FrameworkSpec[] = [];
  if (!fs.existsSync(FRAMEWORK_MODELS_DIR)) {
    warnings.push(`framework-models dir missing: ${FRAMEWORK_MODELS_DIR}`);
    return { specs, warnings };
  }
  for (const entry of fs.readdirSync(FRAMEWORK_MODELS_DIR)) {
    if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
    const full = path.join(FRAMEWORK_MODELS_DIR, entry);
    try {
      const spec = loadSpec(full);
      if ((spec.language ?? 'js') === language) specs.push(spec);
    } catch (err) {
      warnings.push(`failed to load ${entry}: ${(err as Error).message}`);
    }
  }
  return { specs, warnings };
}

interface RepoResult {
  id: string;
  ecosystem: RepoCase['ecosystem'];
  language: FrameworkLanguage;
  workspace: string;
  specs: string[];
  status: 'ok' | 'crashed' | 'missing-workspace' | 'no-specs';
  flows: number;
  files: number;
  functions: number;
  edges: number;
  durationMs: number;
  expectFlows: boolean;
  expectationViolation: string | null;
  error?: string;
  warnings: string[];
}

async function runOne(repo: RepoCase, root: string): Promise<RepoResult> {
  const language = ecosystemToLanguage(repo.ecosystem);
  const workspace = path.resolve(root, repo.dir);

  if (!fs.existsSync(workspace)) {
    return {
      id: repo.id,
      ecosystem: repo.ecosystem,
      language,
      workspace,
      specs: [],
      status: 'missing-workspace',
      flows: 0,
      files: 0,
      functions: 0,
      edges: 0,
      durationMs: 0,
      expectFlows: repo.expectFlows,
      expectationViolation: null,
      warnings: [],
    };
  }

  const { specs, warnings } = loadSpecsForLanguage(language);
  if (specs.length === 0) {
    return {
      id: repo.id,
      ecosystem: repo.ecosystem,
      language,
      workspace,
      specs: [],
      status: 'no-specs',
      flows: 0,
      files: 0,
      functions: 0,
      edges: 0,
      durationMs: 0,
      expectFlows: repo.expectFlows,
      expectationViolation: repo.expectFlows ? 'expected flows but no specs registered for language' : null,
      warnings,
    };
  }

  const t0 = Date.now();
  try {
    const opts = { rootDir: workspace, specs, onWarn: (m: string) => warnings.push(m) };
    let result: PropagateResult;
    switch (language) {
      case 'python': result = await propagatePython(opts); break;
      case 'java': result = await propagateJava(opts); break;
      case 'go': result = await propagateGo(opts); break;
      case 'ruby': result = await propagateRuby(opts); break;
      case 'php': result = await propagatePhp(opts); break;
      case 'rust': result = await propagateRust(opts); break;
      case 'csharp': result = await propagateCSharp(opts); break;
      case 'js':
      default: result = await propagate(opts); break;
    }
    const durationMs = Date.now() - t0;
    const flows = result.flows.length;
    const violation = repo.expectFlows && flows === 0
      ? `expected ≥1 flow, got 0 — ${repo.rationale}`
      : null;
    return {
      id: repo.id,
      ecosystem: repo.ecosystem,
      language,
      workspace,
      specs: specs.map((s) => `${s.framework}@${s.version}`),
      status: 'ok',
      flows,
      files: result.callgraph.fileCount,
      functions: result.callgraph.nodes.length,
      edges: result.callgraph.edges.length,
      durationMs,
      expectFlows: repo.expectFlows,
      expectationViolation: violation,
      warnings,
    };
  } catch (err) {
    return {
      id: repo.id,
      ecosystem: repo.ecosystem,
      language,
      workspace,
      specs: specs.map((s) => `${s.framework}@${s.version}`),
      status: 'crashed',
      flows: 0,
      files: 0,
      functions: 0,
      edges: 0,
      durationMs: Date.now() - t0,
      expectFlows: repo.expectFlows,
      expectationViolation: null,
      error: err instanceof Error ? (err.stack ?? err.message) : String(err),
      warnings,
    };
  }
}

async function main(): Promise<void> {
  const root = process.env.DEPTEX_TEST_REPOS_ROOT ?? 'C:/Coding/deptex-test-repos';
  console.log(`Cross-ecosystem smoke — repo root: ${root}\n`);

  const results: RepoResult[] = [];
  for (const repo of CASES) {
    process.stdout.write(`— ${repo.id} (${repo.ecosystem}) ... `);
    const result = await runOne(repo, root);
    results.push(result);
    if (result.status === 'crashed') {
      console.log(`CRASH (${result.durationMs}ms)`);
    } else if (result.status === 'missing-workspace') {
      console.log(`MISSING (${result.workspace})`);
    } else if (result.status === 'no-specs') {
      console.log('NO SPECS');
    } else {
      const tag = result.expectationViolation ? 'WARN' : 'ok';
      console.log(`${tag} — ${result.flows} flow(s), ${result.functions} fn / ${result.edges} edge / ${result.files} file (${result.durationMs}ms)`);
    }
  }

  console.log('\n=== Summary ===');
  for (const r of results) {
    const status = r.status === 'ok' ? (r.expectationViolation ? '⚠ ' : '✓ ') : '✗ ';
    console.log(`${status}${r.id} (${r.language}, ${r.specs.length} spec${r.specs.length === 1 ? '' : 's'})`);
    if (r.specs.length > 0) console.log(`    specs: ${r.specs.join(', ')}`);
    if (r.expectationViolation) console.log(`    ${r.expectationViolation}`);
    if (r.error) console.log(`    error: ${r.error.split('\n').slice(0, 4).join('\n           ')}`);
    if (r.warnings.length > 0) console.log(`    warnings: ${r.warnings.length} (first: ${r.warnings[0]})`);
  }

  const crashes = results.filter((r) => r.status === 'crashed').length;
  const missing = results.filter((r) => r.status === 'missing-workspace').length;
  const violations = results.filter((r) => r.expectationViolation !== null).length;

  console.log('');
  if (missing > 0) {
    console.log(`${missing} repo(s) missing on disk — set DEPTEX_TEST_REPOS_ROOT or clone them under ${root}`);
    process.exit(2);
  }
  if (crashes > 0) {
    console.log(`${crashes} repo(s) crashed — investigate before merge.`);
    process.exit(1);
  }
  if (violations > 0) {
    console.log(`${violations} repo(s) violated flow expectations — engine is alive but recall is broken somewhere.`);
    process.exit(1);
  }
  console.log('All cross-ecosystem smokes passed.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
