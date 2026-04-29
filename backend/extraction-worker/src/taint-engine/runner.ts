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
import { loadSpec } from './spec-loader';
import type { FrameworkSpec } from './spec';

export interface RunEngineOptions {
  /** Absolute path to the cloned repo / workspace root. */
  workspaceRoot: string;
  /** Optional cap on iterations; default 50× function count. */
  maxIterations?: number;
  /**
   * Cancellation signal from withTimeout. Long-running propagation
   * checks this after each pass via the worklist's natural break points.
   * (M4: not yet plumbed into propagate(); M5+ refinement.)
   */
  signal?: AbortSignal;
  /** Optional warning sink. */
  onWarn?: (msg: string) => void;
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
}

const FRAMEWORK_MODELS_DIR = path.resolve(__dirname, 'framework-models');

export async function runEngine(options: RunEngineOptions): Promise<RunEngineResult> {
  const { workspaceRoot, onWarn } = options;

  const specs: FrameworkSpec[] = [];
  const frameworksLoaded: string[] = [];

  if (fs.existsSync(FRAMEWORK_MODELS_DIR)) {
    const entries = fs.readdirSync(FRAMEWORK_MODELS_DIR);
    for (const entry of entries) {
      if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
      const full = path.join(FRAMEWORK_MODELS_DIR, entry);
      try {
        const spec = loadSpec(full);
        specs.push(spec);
        frameworksLoaded.push(spec.framework);
      } catch (err) {
        onWarn?.(`failed to load spec ${entry}: ${(err as Error).message}`);
      }
    }
  }

  if (specs.length === 0) {
    return {
      ran: false,
      skippedReason: 'no framework specs found',
      frameworksLoaded: [],
      propagation: null,
    };
  }

  const propagation = await propagate({
    rootDir: workspaceRoot,
    specs,
    maxIterations: options.maxIterations,
    onWarn,
  });

  return {
    ran: true,
    skippedReason: null,
    frameworksLoaded,
    propagation,
  };
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
