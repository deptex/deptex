#!/usr/bin/env node
/**
 * CLI for the M8 atom-retirement gate evaluator.
 *
 * Combines:
 *   - production reliability stats (taint_engine_runs over the past N days)
 *   - benchmark report (engine vs atom recall, regressions)
 *   - AI cost
 *
 * into a single GO / NO_GO / EXTEND_SHADOW recommendation. Used at the end
 * of the M8 30-day shadow window to decide whether to retire atom (per the
 * locked retirement gates in the feature brief).
 *
 * Usage:
 *   npm run taint-engine:retirement-gates -- \
 *     --benchmark ./benchmark-output/report.json \
 *     [--shadow-period-days 30] \
 *     [--failure-pct-ceiling 1.0] \
 *     [--recall-delta-floor-pp 0] \
 *     [--ai-cost-ceiling 0.10]
 *
 * Reads SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY from env. Exit code 0 on
 * recommendation=GO, 1 otherwise (for CI gating).
 */

import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

import { createSupabaseStorage } from '../src/storage';
import { evaluateRetirementGates } from '../src/taint-engine/benchmark';
import type { BenchmarkReport } from '../src/taint-engine/benchmark';

interface CliOptions {
  benchmark: string;
  shadowPeriodDays: number;
  failurePctCeiling?: number;
  recallDeltaFloorPp?: number;
  aiCostCeilingUsd?: number;
}

function parseArgs(argv: string[]): CliOptions {
  let benchmark = '';
  let shadowPeriodDays = 30;
  let failurePctCeiling: number | undefined;
  let recallDeltaFloorPp: number | undefined;
  let aiCostCeilingUsd: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--benchmark') benchmark = argv[++i];
    else if (a === '--shadow-period-days') shadowPeriodDays = Number(argv[++i]);
    else if (a === '--failure-pct-ceiling') failurePctCeiling = Number(argv[++i]);
    else if (a === '--recall-delta-floor-pp') recallDeltaFloorPp = Number(argv[++i]);
    else if (a === '--ai-cost-ceiling') aiCostCeilingUsd = Number(argv[++i]);
    else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
    else if (a.startsWith('--')) {
      console.error(`unknown flag: ${a}`);
      process.exit(2);
    }
  }
  if (!benchmark) {
    console.error('error: --benchmark is required');
    printHelp();
    process.exit(2);
  }
  return { benchmark, shadowPeriodDays, failurePctCeiling, recallDeltaFloorPp, aiCostCeilingUsd };
}

function printHelp(): void {
  process.stdout.write(`Usage: taint-engine:retirement-gates --benchmark <report.json> [options]

Required:
  --benchmark <path>           Path to a benchmark report.json from the harness.

Options:
  --shadow-period-days <n>     Look-back window for taint_engine_runs (default 30).
  --failure-pct-ceiling <n>    Reliability gate threshold % (default 1.0).
  --recall-delta-floor-pp <n>  Recall floor in percentage points (engine ≥ atom − floor; default 0).
  --ai-cost-ceiling <n>        AI cost per completed run, USD (default 0.10).

Reads Supabase credentials from SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY env vars.
Exit code is 0 on recommendation=GO, 1 otherwise.
`);
}

function loadReport(p: string): BenchmarkReport {
  const raw = fs.readFileSync(path.resolve(p), 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || parsed.schemaVersion !== 1) {
    throw new Error(`benchmark report at ${p} is not a v1 schema`);
  }
  return parsed as BenchmarkReport;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const report = loadReport(opts.benchmark);
  const storage = createSupabaseStorage();
  const result = await evaluateRetirementGates({
    storage,
    shadowPeriodDays: opts.shadowPeriodDays,
    benchmarkReport: report,
    failurePctCeiling: opts.failurePctCeiling,
    recallDeltaFloorPp: opts.recallDeltaFloorPp,
    aiCostCeilingUsd: opts.aiCostCeilingUsd,
  });

  console.log(`\n=== Atom retirement gates (shadow window ${opts.shadowPeriodDays}d) ===\n`);
  console.log(`Reliability: ${result.shadowStats.failurePct.toFixed(2)}% failures over ${result.shadowStats.totalRuns} runs (${result.shadowStats.completedRuns} completed)`);
  console.log(`Mean AI cost: $${result.shadowStats.meanAiCostUsd.toFixed(4)} per completed run`);
  console.log(`Benchmark recall: engine ${result.benchmark.enginePct.toFixed(1)}% vs atom ${result.benchmark.atomPct.toFixed(1)}% (delta ${result.benchmark.deltaPp >= 0 ? '+' : ''}${result.benchmark.deltaPp.toFixed(1)}pp, ${result.benchmark.regressions} regression(s))`);
  console.log('');
  for (const g of result.gates) {
    const tag = g.outcome === 'pass' ? '  PASS' : g.outcome === 'fail' ? '  FAIL' : '  ----';
    console.log(`${tag}  ${g.label}`);
    console.log(`        ${g.detail}`);
  }
  console.log(`\nRecommendation: ${result.recommendation}`);
  if (result.blockers.length > 0) {
    console.log(`Blockers: ${result.blockers.join(', ')}`);
  }

  process.exit(result.recommendation === 'GO' ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
