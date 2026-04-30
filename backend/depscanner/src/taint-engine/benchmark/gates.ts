/**
 * Retirement-gate evaluator for the M8 atom→taint-engine cutover decision.
 *
 * Reads three signals:
 *   1. Production reliability — `taint_engine_runs` rows over the past N days,
 *      computing failure rate (target <1% per locked decision in the feature
 *      brief).
 *   2. Recall — a benchmark report.json (produced by `taint-engine:benchmark`),
 *      computing the engine-vs-atom percentage-point delta and the regression
 *      list.
 *   3. AI cost — average `ai_cost_usd` per completed run over the same window
 *      (we want this under the M7 acceptance bar of $0.10 per typical
 *      extraction).
 *
 * The output is a structured verdict per gate plus an overall
 * `recommendation` of 'GO' / 'NO_GO' / 'EXTEND_SHADOW' that the caller (CLI
 * or admin route) renders.
 */

import type { Storage } from '../../storage';
import type { BenchmarkReport } from './report';

export interface ShadowRunStats {
  totalRuns: number;
  completedRuns: number;
  failedRuns: number;
  abortedRuns: number;
  failurePct: number;
  /** Mean AI cost per completed run, USD. */
  meanAiCostUsd: number;
  /** P95 total_ms for completed runs, milliseconds. */
  p95TotalMs: number | null;
}

export type GateOutcome = 'pass' | 'fail' | 'inconclusive';

export interface GateResult {
  /** Stable id for the gate, used in CLI output and dashboards. */
  id: string;
  /** Human label. */
  label: string;
  outcome: GateOutcome;
  /** One-sentence explanation including the metric value. */
  detail: string;
}

export interface RetirementGateResult {
  shadowStats: ShadowRunStats;
  benchmark: { atomPct: number; enginePct: number; deltaPp: number; regressions: number };
  gates: GateResult[];
  recommendation: 'GO' | 'NO_GO' | 'EXTEND_SHADOW';
  /** When recommendation is NO_GO/EXTEND_SHADOW, the failing gate ids. */
  blockers: string[];
}

export interface RetirementGateInput {
  storage: Storage;
  /** Look-back window for taint_engine_runs aggregation. Plan default: 30. */
  shadowPeriodDays: number;
  /** Output of buildReport() (parse from report.json). */
  benchmarkReport: BenchmarkReport;
  /** Failure-rate ceiling. Plan default: 1%. */
  failurePctCeiling?: number;
  /** Recall delta floor (engine ≥ atom − floor). Plan: ±5pp during shadow, 0pp at retirement. */
  recallDeltaFloorPp?: number;
  /** AI cost ceiling per completed run. Plan default: $0.10. */
  aiCostCeilingUsd?: number;
}

const DEFAULT_FAILURE_PCT_CEILING = 1.0;
const DEFAULT_RECALL_DELTA_FLOOR = 0;
const DEFAULT_AI_COST_CEILING_USD = 0.10;
const MIN_SHADOW_RUNS_FOR_VERDICT = 30;

export async function evaluateRetirementGates(
  input: RetirementGateInput,
): Promise<RetirementGateResult> {
  const failureCeiling = input.failurePctCeiling ?? DEFAULT_FAILURE_PCT_CEILING;
  const recallFloor = input.recallDeltaFloorPp ?? DEFAULT_RECALL_DELTA_FLOOR;
  const costCeiling = input.aiCostCeilingUsd ?? DEFAULT_AI_COST_CEILING_USD;

  const shadowStats = await readShadowStats(input.storage, input.shadowPeriodDays);
  const { recall, regressions } = input.benchmarkReport.recall as unknown as {
    recall: { atom: { pct: number }; taintEngine: { pct: number }; deltaPp: number };
    regressions: unknown[];
  };
  // Type-safe access — the report shape we care about is the BenchmarkReport.
  const benchmark = {
    atomPct: input.benchmarkReport.recall.atom.pct,
    enginePct: input.benchmarkReport.recall.taintEngine.pct,
    deltaPp: input.benchmarkReport.recall.deltaPp,
    regressions: input.benchmarkReport.regressions.length,
  };

  const gates: GateResult[] = [];

  // Gate 1: failure rate
  if (shadowStats.totalRuns < MIN_SHADOW_RUNS_FOR_VERDICT) {
    gates.push({
      id: 'reliability',
      label: 'Reliability — failure rate < ceiling',
      outcome: 'inconclusive',
      detail: `only ${shadowStats.totalRuns} run(s) in the last ${input.shadowPeriodDays}d — need ≥${MIN_SHADOW_RUNS_FOR_VERDICT} for a verdict`,
    });
  } else {
    const ok = shadowStats.failurePct <= failureCeiling;
    gates.push({
      id: 'reliability',
      label: 'Reliability — failure rate ≤ ceiling',
      outcome: ok ? 'pass' : 'fail',
      detail: `${shadowStats.failurePct.toFixed(2)}% over ${shadowStats.totalRuns} runs (ceiling ${failureCeiling.toFixed(2)}%)`,
    });
  }

  // Gate 2: recall parity
  const recallOk = benchmark.deltaPp >= -recallFloor;
  gates.push({
    id: 'recall',
    label: 'Recall parity — engine ≥ atom − floor',
    outcome: recallOk ? 'pass' : 'fail',
    detail: `engine ${benchmark.enginePct.toFixed(1)}% vs atom ${benchmark.atomPct.toFixed(1)}% (delta ${benchmark.deltaPp >= 0 ? '+' : ''}${benchmark.deltaPp.toFixed(1)}pp; floor −${recallFloor.toFixed(1)}pp)`,
  });

  // Gate 3: zero regressions
  const noRegressions = benchmark.regressions === 0;
  gates.push({
    id: 'regressions',
    label: 'Zero regressions — atom hits the engine missed',
    outcome: noRegressions ? 'pass' : 'fail',
    detail: noRegressions
      ? 'no atom-only hits in the corpus'
      : `${benchmark.regressions} CVE(s) atom recovered but the engine missed`,
  });

  // Gate 4: AI cost
  if (shadowStats.completedRuns === 0) {
    gates.push({
      id: 'ai_cost',
      label: 'AI cost — mean ≤ ceiling',
      outcome: 'inconclusive',
      detail: 'no completed runs in the window',
    });
  } else {
    const ok = shadowStats.meanAiCostUsd <= costCeiling;
    gates.push({
      id: 'ai_cost',
      label: 'AI cost — mean ≤ ceiling',
      outcome: ok ? 'pass' : 'fail',
      detail: `$${shadowStats.meanAiCostUsd.toFixed(4)} / completed run (ceiling $${costCeiling.toFixed(4)})`,
    });
  }

  const blockers = gates.filter((g) => g.outcome === 'fail').map((g) => g.id);
  const inconclusive = gates.some((g) => g.outcome === 'inconclusive');

  let recommendation: RetirementGateResult['recommendation'];
  if (blockers.length > 0) recommendation = 'NO_GO';
  else if (inconclusive) recommendation = 'EXTEND_SHADOW';
  else recommendation = 'GO';

  return {
    shadowStats,
    benchmark,
    gates,
    recommendation,
    blockers,
  };
}

interface RawRunRow {
  status: string;
  ai_cost_usd: number | string | null;
  total_ms: number | string | null;
}

async function readShadowStats(
  storage: Storage,
  shadowPeriodDays: number,
): Promise<ShadowRunStats> {
  // Pull recent runs server-side via a small RPC. We could add gte() to the
  // storage abstraction, but a one-shot RPC keeps the worker side simple and
  // the SQL filter accurate (created_at >= now − interval).
  const { data, error } = await storage.rpc<RawRunRow[]>(
    'get_taint_engine_recent_runs',
    { p_days: shadowPeriodDays },
  );
  if (error || !Array.isArray(data)) {
    return {
      totalRuns: 0,
      completedRuns: 0,
      failedRuns: 0,
      abortedRuns: 0,
      failurePct: 0,
      meanAiCostUsd: 0,
      p95TotalMs: null,
    };
  }

  const total = data.length;
  let completed = 0;
  let failed = 0;
  let aborted = 0;
  let costSum = 0;
  const completedMs: number[] = [];

  for (const r of data) {
    const status = String(r.status ?? '');
    if (status === 'completed') {
      completed++;
      const cost = typeof r.ai_cost_usd === 'number' ? r.ai_cost_usd : Number(r.ai_cost_usd ?? 0);
      if (Number.isFinite(cost)) costSum += cost;
      const ms = typeof r.total_ms === 'number' ? r.total_ms : Number(r.total_ms ?? 0);
      if (Number.isFinite(ms) && ms > 0) completedMs.push(ms);
    } else if (status === 'failed') {
      failed++;
    } else if (status === 'aborted') {
      aborted++;
    }
  }

  const failurePct = total === 0 ? 0 : ((failed + aborted) / total) * 100;
  const meanAiCostUsd = completed === 0 ? 0 : costSum / completed;

  let p95TotalMs: number | null = null;
  if (completedMs.length > 0) {
    completedMs.sort((a, b) => a - b);
    const idx = Math.min(completedMs.length - 1, Math.floor(completedMs.length * 0.95));
    p95TotalMs = completedMs[idx];
  }

  return {
    totalRuns: total,
    completedRuns: completed,
    failedRuns: failed,
    abortedRuns: aborted,
    failurePct: Number(failurePct.toFixed(4)),
    meanAiCostUsd: Number(meanAiCostUsd.toFixed(6)),
    p95TotalMs,
  };
}
