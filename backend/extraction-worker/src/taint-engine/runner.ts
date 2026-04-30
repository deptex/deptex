/**
 * Pipeline-facing orchestrator for the cross-file taint engine.
 *
 * runEngine() is what pipeline.ts calls inside its `taint_engine` step. It:
 *   1. Loads the bundled hand-written framework specs from the dist /
 *      source tree (M3 ships Express; M5 will ship Fastify/NestJS/Next/Hono).
 *   2. Builds the whole-program callgraph (M1 substrate).
 *   3. Runs forward-propagation (M2 propagator) with all loaded specs.
 *   4. Returns the result to the caller; pipeline.ts is responsible for
 *      writing flows + telemetry via storage.ts (so failures in either
 *      stage are observable in taint_engine_runs).
 *
 * The runner does NOT itself check the circuit breaker, write telemetry,
 * or apply the rollout pct — those are pipeline-level concerns kept at
 * the caller so they're visible in the same code block as the rest of
 * the pipeline's hard-fail policy.
 *
 * Spec discovery: the bundled specs live next to this file at
 * `framework-models/*.yaml`. tsx (dev) reads from src/; tsc-built dist
 * needs the YAML copied — this runner uses __dirname to find them either
 * way, and Dockerfile mirrors the pattern that's worked for
 * tree-sitter-extractor's WASM grammars.
 */

import * as fs from 'fs';
import * as path from 'path';
import { propagate, type PropagateResult } from './propagator';
import { propagatePython } from './python/propagate';
import { propagateJava } from './java/propagate';
import { propagateGo } from './go/propagate';
import { propagateRuby } from './ruby/propagate';
import { propagatePhp } from './php/propagate';
import { propagateRust } from './rust/propagate';
import { propagateCSharp } from './csharp/propagate';
import { loadSpec } from './spec-loader';
import type { FrameworkSpec, FrameworkLanguage } from './spec';
import type { Flow } from './flow';
import {
  filterFlow,
  estimatePerFlowCostUsd,
  createUsageLogger,
  type FilterResult,
} from './fp-filter';
import type { Storage } from '../storage';

export interface RunEngineOptions {
  /** Absolute path to the cloned repo / workspace root. */
  workspaceRoot: string;
  /**
   * Project ecosystem. Drives language dispatch:
   *   npm        → JS/TS
   *   pypi       → Python
   *   maven      → Java
   *   gomod      → Go
   *   rubygems   → Ruby
   *   composer   → PHP
   *   cargo      → Rust
   *   nuget      → C#
   * Defaults to 'npm' (the original Phase 6 behavior) for backward compatibility.
   */
  ecosystem?:
    | 'npm'
    | 'pypi'
    | 'maven'
    | 'gomod'
    | 'rubygems'
    | 'composer'
    | 'cargo'
    | 'nuget'
    | string;
  /** Optional cap on iterations; default 50× function count. */
  maxIterations?: number;
  /**
   * Cancellation signal from withTimeout. Threaded into each per-language
   * propagator's worklist core, which checks signal.aborted between
   * iterations and bails out cleanly with whatever flows had aggregated.
   * Without this the engine could ignore checkCancelled for up to the full
   * 30-min hard timeout on a large monorepo.
   */
  signal?: AbortSignal;
  /** Optional warning sink. */
  onWarn?: (msg: string) => void;
  /**
   * AI false-positive filter context. When provided + ai_layer_enabled +
   * DEEPINFRA_API_KEY set, flows below the org's confidence threshold are
   * routed to DeepInfra Qwen for a per-flow check. Without it the engine
   * runs deterministic-only — safe for self-host without keys.
   */
  fpFilter?: FpFilterContext;
}

/** Map an SBOM-style ecosystem identifier to the framework spec language. */
function ecosystemToLanguage(ecosystem: string | undefined): FrameworkLanguage {
  switch (ecosystem) {
    case 'pypi':
      return 'python';
    case 'maven':
      return 'java';
    case 'gomod':
      return 'go';
    case 'rubygems':
      return 'ruby';
    case 'composer':
      return 'php';
    case 'cargo':
      return 'rust';
    case 'nuget':
      return 'csharp';
    case 'npm':
    default:
      return 'js';
  }
}

export interface FpFilterContext {
  storage: Storage;
  organizationId: string;
  /** Triggering user (system user when extraction is automated); audit-trail only. */
  userId: string;
  projectId: string;
  extractionRunId: string;
  /** Per-org settings — the runner re-reads in case the caller stale-reads. */
  apiKey?: string;
  /** Optional model override (defaults to Qwen/Qwen3-235B-A22B-Instruct-2507). */
  model?: string;
}

export interface AiFilterStats {
  invoked: boolean;
  /** Reason the filter did not run, when invoked=false. */
  skippedReason: string | null;
  /** Flows passed deterministically (engine_confidence ≥ threshold). */
  flowsAboveThreshold: number;
  /** Flows submitted to the model. */
  flowsChecked: number;
  /** Flows the model rejected as false positives. */
  flowsRejected: number;
  /** Flows the model kept. */
  flowsKept: number;
  /** Flows kept by default because the model call errored. */
  flowsKeptOnError: number;
  /** Aggregate USD spend across this run's filter calls. */
  costUsd: number;
  /** Per-flow verdict map keyed by Flow.id, for storage embedding. */
  verdicts: Map<string, FilterResult>;
  durationMs: number;
}

export interface RunEngineResult {
  /** Whether the engine ran successfully (false if no specs loaded). */
  ran: boolean;
  /** Reason the engine didn't run, when ran=false. */
  skippedReason: string | null;
  /** Names of framework specs loaded. */
  frameworksLoaded: string[];
  /** Engine output; null when ran=false. */
  propagation: PropagateResult | null;
  /**
   * Flows after the AI filter has dropped rejections. Same shape as
   * propagation.flows; identical when the filter didn't run.
   */
  flowsAfterFilter: Flow[] | null;
  /** AI filter telemetry; null when ran=false or filter not configured. */
  aiFilter: AiFilterStats | null;
}

const FRAMEWORK_MODELS_DIR = path.resolve(__dirname, 'framework-models');

export async function runEngine(options: RunEngineOptions): Promise<RunEngineResult> {
  const { workspaceRoot, onWarn } = options;
  const language = ecosystemToLanguage(options.ecosystem);

  const allSpecs: FrameworkSpec[] = [];
  if (fs.existsSync(FRAMEWORK_MODELS_DIR)) {
    const entries = fs.readdirSync(FRAMEWORK_MODELS_DIR);
    for (const entry of entries) {
      if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
      const full = path.join(FRAMEWORK_MODELS_DIR, entry);
      try {
        allSpecs.push(loadSpec(full));
      } catch (err) {
        onWarn?.(`failed to load spec ${entry}: ${(err as Error).message}`);
      }
    }
  }

  // Filter by language: a spec without an explicit language tag defaults to
  // 'js' (the original Phase 6 specs predate the field).
  const specs = allSpecs.filter((s) => (s.language ?? 'js') === language);
  const frameworksLoaded = specs.map((s) => s.framework);

  if (specs.length === 0) {
    return {
      ran: false,
      skippedReason: `no framework specs for language=${language}`,
      frameworksLoaded: [],
      propagation: null,
      flowsAfterFilter: null,
      aiFilter: null,
    };
  }

  // Dispatch to the right per-language propagator.
  let propagation: PropagateResult;
  switch (language) {
    case 'python':
      propagation = await propagatePython({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'java':
      propagation = await propagateJava({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'go':
      propagation = await propagateGo({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'ruby':
      propagation = await propagateRuby({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'php':
      propagation = await propagatePhp({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'rust':
      propagation = await propagateRust({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'csharp':
      propagation = await propagateCSharp({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
    case 'js':
    default:
      propagation = await propagate({
        rootDir: workspaceRoot,
        specs,
        maxIterations: options.maxIterations,
        onWarn,
        signal: options.signal,
      });
      break;
  }

  // Default: filter inactive, all flows pass through.
  let flowsAfterFilter: Flow[] = propagation.flows;
  let aiFilter: AiFilterStats | null = null;

  if (options.fpFilter) {
    const result = await runFpFilterStage(
      propagation.flows,
      options.fpFilter,
      workspaceRoot,
      onWarn,
    );
    aiFilter = result.stats;
    flowsAfterFilter = result.flowsAfterFilter;
  }

  return {
    ran: true,
    skippedReason: null,
    frameworksLoaded,
    propagation,
    flowsAfterFilter,
    aiFilter,
  };
}

interface FpFilterStageOutput {
  stats: AiFilterStats;
  flowsAfterFilter: Flow[];
}

/**
 * Resolve the org's filter settings, pre-check the cost cap, batch the
 * sub-threshold flows through Gemini Flash, and return the surviving
 * flows + telemetry.
 */
async function runFpFilterStage(
  flows: Flow[],
  fp: FpFilterContext,
  workspaceRoot: string,
  onWarn?: (msg: string) => void,
): Promise<FpFilterStageOutput> {
  const start = Date.now();

  const baseStats: AiFilterStats = {
    invoked: false,
    skippedReason: null,
    flowsAboveThreshold: 0,
    flowsChecked: 0,
    flowsRejected: 0,
    flowsKept: 0,
    flowsKeptOnError: 0,
    costUsd: 0,
    verdicts: new Map(),
    durationMs: 0,
  };

  if (flows.length === 0) {
    baseStats.skippedReason = 'no_flows';
    baseStats.durationMs = Date.now() - start;
    return { stats: baseStats, flowsAfterFilter: flows };
  }

  // Read settings.
  const { data: settingsRow } = await fp.storage
    .from('taint_engine_settings')
    .select('ai_layer_enabled, monthly_ai_cost_cap_usd, ai_fp_filter_confidence_threshold')
    .eq('organization_id', fp.organizationId)
    .maybeSingle();
  const settings = (settingsRow ?? null) as {
    ai_layer_enabled?: boolean;
    monthly_ai_cost_cap_usd?: number | string | null;
    ai_fp_filter_confidence_threshold?: number | string | null;
  } | null;

  if (settings && settings.ai_layer_enabled === false) {
    baseStats.skippedReason = 'ai_layer_disabled';
    baseStats.durationMs = Date.now() - start;
    return { stats: baseStats, flowsAfterFilter: flows };
  }

  // Resolve API key (caller may pass directly; otherwise use platform env).
  const apiKey = fp.apiKey ?? process.env.DEEPINFRA_API_KEY;
  if (!apiKey) {
    baseStats.skippedReason = 'no_platform_api_key';
    baseStats.durationMs = Date.now() - start;
    onWarn?.('fp-filter skipped: DEEPINFRA_API_KEY not configured');
    return { stats: baseStats, flowsAfterFilter: flows };
  }

  const threshold = clampThreshold(settings?.ai_fp_filter_confidence_threshold);
  const above: Flow[] = [];
  const below: Flow[] = [];
  for (const f of flows) {
    if (f.engine_confidence >= threshold) above.push(f);
    else below.push(f);
  }
  baseStats.flowsAboveThreshold = above.length;

  if (below.length === 0) {
    baseStats.skippedReason = 'all_flows_above_threshold';
    baseStats.durationMs = Date.now() - start;
    return { stats: baseStats, flowsAfterFilter: flows };
  }

  // Cost-cap pre-check: project the cost and bail (degrade to deterministic-only)
  // if running the batch would push the org over its monthly cap.
  const cap = Number(settings?.monthly_ai_cost_cap_usd ?? 50);
  const spendNow = await readMonthlySpend(fp.storage, fp.organizationId, onWarn);
  const projected = below.reduce((sum, f) => sum + estimatePerFlowCostUsd(f), 0);
  if (Number.isFinite(cap) && spendNow + projected > cap) {
    baseStats.skippedReason = 'cost_cap_exceeded';
    baseStats.durationMs = Date.now() - start;
    onWarn?.(
      `fp-filter skipped: projected $${projected.toFixed(4)} on top of $${spendNow.toFixed(4)} would exceed cap $${cap.toFixed(2)}`,
    );
    return { stats: baseStats, flowsAfterFilter: flows };
  }

  baseStats.invoked = true;
  const logger = createUsageLogger(fp.storage, {
    organizationId: fp.organizationId,
    userId: fp.userId,
    projectId: fp.projectId,
    extractionRunId: fp.extractionRunId,
  }, onWarn);

  // Sequential calls so we don't overwhelm the rate limit on huge batches.
  // ~25s timeout per call; for ≤100 flows the M7 perf budget allows this.
  const surviving: Flow[] = [...above];
  for (const f of below) {
    const result = await filterFlow(
      { flow: f, workspaceRoot, apiKey, model: fp.model, onWarn },
      logger,
      {
        organizationId: fp.organizationId,
        userId: fp.userId,
        projectId: fp.projectId,
        extractionRunId: fp.extractionRunId,
      },
    );
    baseStats.verdicts.set(f.id, result);
    if (result.verdict === 'kept_on_error') {
      baseStats.flowsKeptOnError++;
      baseStats.costUsd += result.costUsd;
      surviving.push(f);
      continue;
    }
    baseStats.flowsChecked++;
    baseStats.costUsd += result.costUsd;
    if (result.verdict === 'kept') {
      baseStats.flowsKept++;
      surviving.push(f);
    } else {
      baseStats.flowsRejected++;
    }
  }

  baseStats.durationMs = Date.now() - start;
  return { stats: baseStats, flowsAfterFilter: surviving };
}

function clampThreshold(raw: number | string | null | undefined): number {
  const v = raw === null || raw === undefined ? 0.7 : Number(raw);
  if (!Number.isFinite(v)) return 0.7;
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

async function readMonthlySpend(
  storage: Storage,
  organizationId: string,
  onWarn?: (msg: string) => void,
): Promise<number> {
  // Prefer the dedicated RPC (server-side SUM); fall back to 0 if it isn't
  // installed (older self-host migrations) — the cap will then defer to the
  // engine's deterministic output and the next admin migration will catch up.
  try {
    const { data, error } = await storage.rpc<number | string>(
      'get_taint_engine_monthly_spend',
      { p_organization_id: organizationId },
    );
    if (error) {
      onWarn?.(`get_taint_engine_monthly_spend rpc failed: ${error.message}`);
      return 0;
    }
    const v = typeof data === 'number' ? data : Number(data ?? 0);
    return Number.isFinite(v) ? v : 0;
  } catch (err) {
    onWarn?.(`get_taint_engine_monthly_spend rpc threw: ${(err as Error).message}`);
    return 0;
  }
}

/**
 * Staged rollout gate. Reads DEPTEX_TAINT_ENGINE_ROLLOUT_PCT (0-100); if
 * the env var is unset we default to 0 in production (engine off) and 100
 * elsewhere so the local CLI / tests always run the engine.
 *
 * The decision is randomized per-call so a single org's extractions get
 * roughly the configured percentage of engine runs over time. We bucket
 * on Math.random() rather than a deterministic hash because we want
 * variability across reruns of the same project during the canary period.
 */
export function shouldRunForRollout(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.DEPTEX_TAINT_ENGINE_ROLLOUT_PCT;
  if (raw === undefined) {
    // Off by default in production; on otherwise.
    return env.NODE_ENV !== 'production';
  }
  const pct = Math.max(0, Math.min(100, Number(raw)));
  if (Number.isNaN(pct)) return false;
  if (pct === 100) return true;
  if (pct === 0) return false;
  return Math.random() * 100 < pct;
}

/**
 * Per-org rollout decision (M8.4). When `taint_engine_settings.rollout_pct_override`
 * is set for the org, it wins outright over the env var — letting us canary
 * specific orgs to 100% during the shadow A/B without flipping the fleet
 * variable. NULL override falls back to `shouldRunForRollout(env)`.
 *
 * The settings read swallows errors and falls back to the env-based decision
 * so a transient DB hiccup never causes a "did the engine run?" mystery.
 */
export async function shouldRunForOrg(
  storage: Storage,
  organizationId: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  try {
    const { data, error } = await storage
      .from('taint_engine_settings')
      .select('rollout_pct_override')
      .eq('organization_id', organizationId)
      .maybeSingle();
    if (error) return shouldRunForRollout(env);
    const row = data as { rollout_pct_override?: number | null } | null;
    const override = row?.rollout_pct_override ?? null;
    if (override === null || override === undefined) return shouldRunForRollout(env);
    const pct = Math.max(0, Math.min(100, Number(override)));
    if (!Number.isFinite(pct)) return shouldRunForRollout(env);
    if (pct === 100) return true;
    if (pct === 0) return false;
    return Math.random() * 100 < pct;
  } catch {
    return shouldRunForRollout(env);
  }
}
