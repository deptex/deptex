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
import { createHash } from 'crypto';
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
import { detectSanitizerAbsence, extractCallSitesFromIr } from './non-taint-detector';
import { detectInsecureDefaults } from './insecure-default-detector';
import { detectUnsafeRegexLiterals } from './regex-literal-detector';
import { sanitizerAbsenceToFlow, insecureDefaultToFlow, regexLiteralToFlow } from './detector-flows';
import {
  filterFlow,
  estimatePerFlowCostUsd,
  createUsageLogger,
  type TripleResult,
} from './fp-filter';
import {
  assertWithinCostCap,
  refundReservation,
  CostCapExceededError,
  CostCapInfraError,
  DEFAULT_MONTHLY_AI_COST_CAP_USD,
} from './cost-cap';
import type { Storage } from '../storage';
import { checkScanJobCostCap, logScanJobCostCapExceeded, recordScanJobAiUsage } from '../ai-telemetry';
import { runEngineCoreInWorker } from './engine-worker-host';

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
  /**
   * Phase 6.5 — CVE-targeted FrameworkSpec rows loaded from
   * `organization_generated_rules` for this extraction (the caller
   * computed `detectedCves` from dep-scan output and ran
   * `loadCveSpecsForExtraction`). Merged alongside the bundled
   * framework-models/*.yaml before the language filter dispatch. Each
   * spec's sinks carry `osv_id`, which the propagator stamps onto
   * matched flows so the classifier can promote a PDV to `confirmed`.
   *
   * Empty / undefined → engine runs the Phase 6 framework-generic path
   * unchanged (no CVE-targeted rows for this org/extraction).
   */
  cveSpecs?: FrameworkSpec[];
  /**
   * Detected framework name(s) for the project (lowercased), e.g. ['react'].
   * Used to scope the engine for pure client-side SPAs: a React/Vue/etc.
   * browser bundle has no server request boundary, so loading server
   * application-framework specs (express/nestjs/nextjs/…) makes their bare
   * `params`/`body`/`query` request sources match ordinary local variables and
   * server-only sink classes (ssrf, deserialization, …) fire on browser code —
   * a large false-positive surface (observed: 56 phantom flows on a real SPA).
   *
   * When this names a pure client framework (and NO server/SSR framework),
   * server application-framework specs are dropped and only client-exploitable
   * vuln classes are emitted. Undefined / unrecognized → unchanged load-all
   * behavior (so the validation harness + CLI are unaffected).
   */
  projectFrameworks?: string[];
  /**
   * Called on a fixed interval while the engine core runs off-thread, with
   * elapsed ms. The pipeline wires this to pulse the worker heartbeat + emit a
   * progress log so a legitimately long callgraph build is never mistaken for a
   * stall and reaped. No-op in the inline (dev/CLI) path.
   */
  onKeepAlive?: (elapsedMs: number) => Promise<void> | void;
  /**
   * Hard wall-clock budget for the engine core (ms). Overrides the
   * DEPTEX_TAINT_ENGINE_TIMEOUT_MS env / default. Generous by design — a big
   * repo's build runs this long before it's treated as wedged.
   */
  timeoutMs?: number;
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

// ---------------------------------------------------------------------------
// Client-SPA scoping
//
// Server web-application frameworks model the HTTP request as the trust
// boundary; their specs declare request-object sources (`req.body.*`,
// `request.query.*`) and — for NestJS-style decorator binding — bare
// `params.*`/`body.*`/`query.*`. The engine loads EVERY same-language spec, so
// on a pure client-side SPA (React/Vue/Svelte/… with no server) these bare
// request sources match ordinary local variables and server-only sink classes
// (ssrf/deserialization/path_traversal/…) fire on browser code that can't
// reach them. We scope those out when the project is unambiguously a client
// SPA. This is opt-in (driven by detected frameworks) so server apps and the
// validation harness keep the full load-all behavior.
// ---------------------------------------------------------------------------

/** Spec `framework` names whose sources model a server HTTP request boundary. */
const SERVER_APP_FRAMEWORK_SPECS: ReadonlySet<string> = new Set([
  'express', 'fastify', 'nestjs', 'nextjs', 'hono',
  'django', 'flask', 'fastapi',
  'rails', 'sinatra', 'laravel', 'symfony',
  'spring-boot', 'micronaut', 'quarkus',
  'aspnet-core', 'gin', 'echo', 'axum', 'actix-web',
]);

/** Detected framework names that indicate a pure client-side SPA. */
const CLIENT_SPA_FRAMEWORKS: ReadonlySet<string> = new Set([
  'react', 'vue', 'vuejs', 'svelte', 'angular', 'angularjs',
  'preact', 'solid', 'solidjs', 'ember', 'emberjs', 'lit', 'alpine',
]);

/**
 * Frameworks that DISQUALIFY the pure-client verdict: a server framework, or a
 * meta-framework with a server/SSR runtime where the request sources DO apply.
 */
const SERVER_OR_SSR_FRAMEWORKS: ReadonlySet<string> = new Set([
  'nextjs', 'next', 'nuxt', 'nuxtjs', 'remix', 'gatsby', 'sveltekit', 'astro',
  'express', 'fastify', 'nestjs', 'koa', 'hapi', 'hono',
  'django', 'flask', 'fastapi', 'rails', 'sinatra', 'laravel', 'symfony',
  'spring-boot', 'spring', 'micronaut', 'quarkus', 'aspnet-core', 'aspnet',
  'gin', 'gin-gonic', 'echo', 'axum', 'actix-web',
]);

/** Vuln classes that are genuinely exploitable inside a browser bundle. */
const CLIENT_EXPLOITABLE_CLASSES: ReadonlySet<string> = new Set([
  'xss', 'open_redirect', 'prototype_pollution', 'code_injection', 'redos',
]);

/**
 * True when the detected frameworks name a client UI framework and NO server /
 * SSR framework. Empty / undefined / unrecognized → false (keep load-all).
 */
export function isPureClientSpa(frameworks: string[] | undefined): boolean {
  if (!frameworks || frameworks.length === 0) return false;
  const norm = frameworks.map((f) => f.toLowerCase().trim()).filter(Boolean);
  if (norm.some((f) => SERVER_OR_SSR_FRAMEWORKS.has(f))) return false;
  return norm.some((f) => CLIENT_SPA_FRAMEWORKS.has(f));
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
  /**
   * Phase 33: owning scan_jobs row id. When set, each fp-filter call
   * rolls token + cost telemetry into scan_jobs.ai_total_* + ai_per_model
   * and honours scan_jobs.ai_cost_cap_usd as a per-scan ceiling. Undefined
   * in CLI mode (no scan_jobs row) — fp-filter runs without per-scan
   * accounting in that case.
   */
  jobId?: string;
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
  verdicts: Map<string, TripleResult>;
  /** Flows the model truncated (Patch 7 / max_tokens overflow). */
  flowsTruncated: number;
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
  /**
   * Non-taint detector findings coerced to `Flow` shape:
   *   - Phase F4 sanitizer-absence (`required_arguments` on sinks).
   *   - Phase 3.3 insecure-default (`insecure_defaults` on the spec).
   *   - Phase 3.2 regex-literal (`unsafe_regex_patterns` on the spec).
   *
   * Engine_confidence sits just below the FP-filter threshold (0.65, see
   * detector-flows.ts) so these deterministic AST/text matches still get an
   * LLM re-check alongside sub-threshold taint flows — an over-broad detector
   * match can still false-positive. The pipeline caller merges these into the
   * write set alongside `flowsAfterFilter`.
   */
  detectorFlows: Flow[];
  /**
   * v3 (precision arc): set of dep package names the callgraph confirmed
   * are reached by at least one CallEdge from workspace code (npm `pkg` /
   * `@scope/name` for JS; per-language extractors populate this for their
   * own ecosystem in follow-up commits). The reachability classifier uses
   * this set to demote called-but-not-imported transitives from
   * `unreachable` to `module` (jackson-vs-idna fix). Undefined when the
   * callgraph for this language doesn't ship extraction yet — the
   * classifier treats undefined as "no signal" and stays on v2 behavior.
   */
  usedDependencies?: Set<string>;
  /**
   * Union of every `osv_id` carried by a loaded spec sink — both the bundled
   * framework-models/*.yaml (e.g. lodash `_.template` → CVE-2021-23337) and
   * the CVE-targeted specs from organization_generated_rules. The pipeline
   * folds this into `validOsvIds` so the reachability classifier's osv_id
   * drift guard treats a framework-model CVE attribution as a legitimately
   * loaded osv_id rather than rejecting it as data drift.
   */
  loadedOsvIds: Set<string>;
  /**
   * Per-CVE vulnerable call patterns from every loaded sink that carries an
   * `osv_id` (framework-models + CVE-targeted specs). The reachability
   * classifier reads this (as `cveSinkPatterns`) to run its M2 vulnerable-symbol
   * check: when a CVE's specific sink pattern (e.g. express `res.redirect(*)` →
   * CVE-2024-43796) names a symbol that appears on no call path, the finding is
   * downgraded to `unreachable` instead of the weaker `module` fallback.
   */
  loadedCveSinkPatterns: Map<string, string[]>;
}

const FRAMEWORK_MODELS_DIR = path.resolve(__dirname, 'framework-models');

// ---------------------------------------------------------------------------
// Engine core (IO-free) vs. full engine (core + AI fp-filter)
//
// runEngineCore does the pure CPU + filesystem work: load specs, build the
// callgraph, run forward-propagation, run the non-taint detectors, and apply
// client-SPA scoping. It touches NO database / network / Redis and every value
// it returns is structured-cloneable — so it is the unit we run inside a
// worker_thread (see engine-worker-host.ts) to keep the heavy, SYNCHRONOUS
// TS-compiler callgraph build off the main event loop. A blocked loop freezes
// the worker heartbeat → the backend reaps a still-working scan; that was the
// production bug bricking every large TS/Node scan (e.g. the Deptex backend).
//
// runEngine() runs the core (off-thread in the Fly worker, inline in dev/CLI/
// tests) and then the AI fp-filter — the one IO stage — on the main thread,
// where it has the Storage handle + cost-cap Redis.
// ---------------------------------------------------------------------------

/** Default engine wall-clock budget. Generous: a big repo's callgraph build is
 *  allowed to run this long before it's treated as wedged. Env-tunable via
 *  DEPTEX_TAINT_ENGINE_TIMEOUT_MS; sits under the worker's 2h absolute job cap. */
const DEFAULT_ENGINE_TIMEOUT_MS = 30 * 60_000;

function engineTimeoutMs(override?: number): number {
  if (override && override > 0) return override;
  const raw = process.env.DEPTEX_TAINT_ENGINE_TIMEOUT_MS;
  const n = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_ENGINE_TIMEOUT_MS;
}

export interface RunEngineCoreOptions {
  workspaceRoot: string;
  ecosystem?: RunEngineOptions['ecosystem'];
  maxIterations?: number;
  signal?: AbortSignal;
  onWarn?: (msg: string) => void;
  cveSpecs?: FrameworkSpec[];
  projectFrameworks?: string[];
}

export interface EngineCoreResult {
  ran: boolean;
  skippedReason: string | null;
  frameworksLoaded: string[];
  /** Engine output; null when ran=false. Structured-cloneable across threads. */
  propagation: PropagateResult | null;
  /** Non-taint detector findings (post client-SPA class filter), pre fp-filter. */
  detectorFlows: Flow[];
  /** Language-filtered + client-SPA-scoped specs that produced the flows —
   *  returned so the main-thread fp-filter sees the exact spec set. */
  specs: FrameworkSpec[];
  loadedOsvIds: Set<string>;
  loadedCveSinkPatterns: Map<string, string[]>;
}

export async function runEngineCore(options: RunEngineCoreOptions): Promise<EngineCoreResult> {
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

  // Phase 6.5 — merge CVE-targeted FrameworkSpec rows (loaded from
  // organization_generated_rules by the pipeline). Order doesn't matter for
  // the propagator (it's a flat list of patterns); the language filter below
  // drops any cve-spec whose language doesn't match the project ecosystem.
  if (options.cveSpecs && options.cveSpecs.length > 0) {
    allSpecs.push(...options.cveSpecs);
  }

  // Filter by language: a spec without an explicit language tag defaults to
  // 'js' (the original Phase 6 specs predate the field).
  let specs = allSpecs.filter((s) => (s.language ?? 'js') === language);

  // Client-SPA scoping: on a pure browser SPA, drop server application-framework
  // specs so their request-object sources (incl. NestJS-style bare
  // `params`/`body`/`query`) don't match ordinary local variables. CVE-targeted
  // specs (options.cveSpecs, which carry osv_id) are never dropped — they model
  // specific vulnerable library calls, not a server request boundary.
  const clientSpa = isPureClientSpa(options.projectFrameworks);
  if (clientSpa) {
    const before = specs.length;
    // Drop a spec only if it's a bundled server application-framework spec.
    // A CVE-targeted spec (any sink carries an osv_id) models a specific
    // vulnerable library call, never a server request boundary — keep it.
    specs = specs.filter((s) => {
      const isCveSpec = s.sinks.some((sink) => !!sink.osv_id);
      return isCveSpec || !SERVER_APP_FRAMEWORK_SPECS.has(s.framework);
    });
    if (specs.length !== before) {
      onWarn?.(
        `client-SPA scope: dropped ${before - specs.length} server-framework spec(s) ` +
        `for a pure-client project (frameworks: ${(options.projectFrameworks ?? []).join(', ')})`,
      );
    }
  }
  const frameworksLoaded = specs.map((s) => s.framework);

  // Union of osv_ids across every loaded sink (framework-model + CVE-targeted).
  // Surfaced so the pipeline can whitelist framework-model CVE attributions in
  // the classifier's osv_id drift guard.
  const loadedOsvIds = new Set<string>();
  const loadedCveSinkPatterns = new Map<string, string[]>();
  for (const s of specs) {
    for (const sink of s.sinks) {
      if (!sink.osv_id) continue;
      loadedOsvIds.add(sink.osv_id);
      if (sink.pattern) {
        const pats = loadedCveSinkPatterns.get(sink.osv_id) ?? [];
        if (!pats.includes(sink.pattern)) pats.push(sink.pattern);
        loadedCveSinkPatterns.set(sink.osv_id, pats);
      }
    }
  }

  if (specs.length === 0) {
    return {
      ran: false,
      skippedReason: `no framework specs for language=${language}`,
      frameworksLoaded: [],
      propagation: null,
      detectorFlows: [],
      specs: [],
      loadedOsvIds,
      loadedCveSinkPatterns,
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

  // Phase F4 + 3.3 — non-taint detector regimes. Walk IR callsites once and
  // dispatch every loaded spec at the same set. Each finding is coerced to
  // a single-hop Flow whose engine_confidence sits just below the FP-filter
  // threshold so it is LLM-checked alongside taint flows (an over-broad
  // detector sink can still false-positive).
  let detectorFlowsRaw: Flow[] = runDetectors(specs, propagation, language, workspaceRoot, onWarn);

  // Client-SPA scoping (class filter): a browser bundle can only be exploited
  // through client-reachable classes (DOM XSS, open redirect, prototype
  // pollution, eval-injection, ReDoS). Server-only classes (ssrf, sql/command
  // injection, path traversal, deserialization, file upload, log injection,
  // auth bypass) can't fire client-side — drop them so a tainted DOM/storage
  // read flowing to e.g. a same-origin `fetch` isn't reported as SSRF.
  if (clientSpa) {
    const keepClass = (f: Flow): boolean => CLIENT_EXPLOITABLE_CLASSES.has(f.vuln_class);
    const taintBefore = propagation.flows.length;
    const detBefore = detectorFlowsRaw.length;
    propagation.flows = propagation.flows.filter(keepClass);
    detectorFlowsRaw = detectorFlowsRaw.filter(keepClass);
    const dropped = (taintBefore - propagation.flows.length) + (detBefore - detectorFlowsRaw.length);
    if (dropped > 0) {
      onWarn?.(`client-SPA scope: dropped ${dropped} server-only-class flow(s) (ssrf/deserialization/…) on a pure-client project`);
    }
  }

  return {
    ran: true,
    skippedReason: null,
    frameworksLoaded,
    propagation,
    detectorFlows: detectorFlowsRaw,
    specs,
    loadedOsvIds,
    loadedCveSinkPatterns,
  };
}

export async function runEngine(options: RunEngineOptions): Promise<RunEngineResult> {
  const { workspaceRoot, onWarn } = options;

  const coreOptions: RunEngineCoreOptions = {
    workspaceRoot: options.workspaceRoot,
    ecosystem: options.ecosystem,
    maxIterations: options.maxIterations,
    signal: options.signal,
    onWarn,
    cveSpecs: options.cveSpecs,
    projectFrameworks: options.projectFrameworks,
  };

  // Run the CPU-bound core OFF the main event loop in the Fly worker, so a
  // multi-minute callgraph build on a large repo can't freeze the heartbeat and
  // get the scan reaped (see engine-worker-host.ts). Inline fallback in
  // dev/CLI/tests. onKeepAlive pulses the heartbeat + a progress log while the
  // build runs so a legitimately slow build is allowed to finish.
  const core = await runEngineCoreInWorker(coreOptions, {
    timeoutMs: engineTimeoutMs(options.timeoutMs),
    onKeepAlive: options.onKeepAlive,
    onWarn,
    inlineFallback: () => runEngineCore(coreOptions),
  });

  if (!core.ran || !core.propagation) {
    return {
      ran: false,
      skippedReason: core.skippedReason,
      frameworksLoaded: core.frameworksLoaded,
      propagation: null,
      flowsAfterFilter: null,
      aiFilter: null,
      detectorFlows: [],
      loadedOsvIds: core.loadedOsvIds,
      loadedCveSinkPatterns: core.loadedCveSinkPatterns,
    };
  }

  const propagation = core.propagation;
  const specs = core.specs;
  const detectorFlowsRaw = core.detectorFlows;

  // Default: filter inactive, all flows pass through.
  let flowsAfterFilter: Flow[] = propagation.flows;
  let detectorFlows: Flow[] = detectorFlowsRaw;
  let aiFilter: AiFilterStats | null = null;

  if (options.fpFilter) {
    // Run taint flows + detector flows through the SAME filter pass so
    // detector findings get the same LLM re-check. We tag detector flow ids
    // up front so the survivors can be split back into the two buckets the
    // pipeline writes separately.
    const detectorIds = new Set(detectorFlowsRaw.map((f) => f.id));
    const result = await runFpFilterStage(
      [...propagation.flows, ...detectorFlowsRaw],
      options.fpFilter,
      workspaceRoot,
      specs,
      onWarn,
    );
    aiFilter = result.stats;
    flowsAfterFilter = result.flowsAfterFilter.filter((f) => !detectorIds.has(f.id));
    detectorFlows = result.flowsAfterFilter.filter((f) => detectorIds.has(f.id));
  }

  return {
    ran: true,
    skippedReason: null,
    frameworksLoaded: core.frameworksLoaded,
    propagation,
    flowsAfterFilter,
    aiFilter,
    detectorFlows,
    // Lowercase npm package names the JS callgraph credited as reached.
    // For other languages this is undefined until their per-language
    // extractor lands (T3.2-Python / -Go / -Rust / -Java follow-ups).
    usedDependencies: lowercaseSet(propagation.callgraph.usedDependencies),
    loadedOsvIds: core.loadedOsvIds,
    loadedCveSinkPatterns: core.loadedCveSinkPatterns,
  };
}

/**
 * Pass through a Set lowercasing every entry. Returns undefined when input
 * is undefined so callers can distinguish "callgraph didn't run extraction"
 * (undefined) from "callgraph ran but found nothing called" (empty Set).
 */
function lowercaseSet(s: Set<string> | undefined): Set<string> | undefined {
  if (s === undefined) return undefined;
  const out = new Set<string>();
  for (const v of s) out.add(v.toLowerCase());
  return out;
}

function runDetectors(
  specs: FrameworkSpec[],
  propagation: PropagateResult,
  language: FrameworkLanguage,
  workspaceRoot: string,
  onWarn?: (msg: string) => void,
): Flow[] {
  const out: Flow[] = [];

  // Phase 3.2 — regex-literal detector. Fires on the PRESENCE of a known-bad
  // regex literal declared in a spec's `unsafe_regex_patterns`, independent of
  // any source→sink data flow (so it must run BEFORE the call-site early-outs
  // below — a module that only declares `const RE = /unsafe/` has zero
  // callsites but is exactly what this detector targets). Only specs that
  // declare patterns participate, so we skip the file read entirely when none
  // are loaded — the common case, where this stays free.
  const hasRegexSpecs = specs.some(
    (s) => !!(s.unsafe_regex_patterns && s.unsafe_regex_patterns.length > 0),
  );
  if (hasRegexSpecs) {
    try {
      const files = collectSourceFilesForRegex(propagation, workspaceRoot, onWarn);
      if (files.length > 0) {
        // Map framework → first sink osv_id so a CVE-targeted regex spec's
        // finding inherits its CVE attribution (bundled framework specs leave
        // osv_id undefined). Mirrors the per-spec osv attribution the call-site
        // detectors do below.
        const osvByFramework = new Map<string, string>();
        for (const spec of specs) {
          const osv = spec.sinks.find((s) => s.osv_id !== undefined)?.osv_id;
          if (osv && !osvByFramework.has(spec.framework)) osvByFramework.set(spec.framework, osv);
        }
        // detectUnsafeRegexLiterals dedups per (file, regex) across ALL specs
        // in one pass, so call it once with the full spec set rather than
        // per-spec (per-spec would lose the cross-spec dedup).
        const regexFindings = detectUnsafeRegexLiterals({ specs, files });
        for (const f of regexFindings) {
          out.push(regexLiteralToFlow(f, osvByFramework.get(f.framework)));
        }
      }
    } catch (err) {
      onWarn?.(`detector regime: detectUnsafeRegexLiterals failed: ${(err as Error).message}`);
    }
  }

  const irFunctions = propagation.irFunctions;
  if (!irFunctions || irFunctions.length === 0) return out;

  let callsites;
  try {
    callsites = extractCallSitesFromIr(irFunctions, language);
  } catch (err) {
    onWarn?.(`detector regime: extractCallSitesFromIr failed: ${(err as Error).message}`);
    return out;
  }
  if (callsites.length === 0) return out;

  for (const spec of specs) {
    // Use the first osv_id we find across the spec's sinks as the CVE
    // attribution for non-taint findings from THIS spec. CVE-targeted specs
    // (cve-specs from organization_generated_rules) ship one CVE per spec,
    // so this is a stable choice. Bundled framework specs leave it undefined.
    const specOsvId = spec.sinks.find((s) => s.osv_id !== undefined)?.osv_id;

    try {
      const sanitizerFindings = detectSanitizerAbsence(spec, callsites, language);
      for (const f of sanitizerFindings) {
        out.push(sanitizerAbsenceToFlow(f, spec.framework, specOsvId));
      }
    } catch (err) {
      onWarn?.(`detector regime: detectSanitizerAbsence(${spec.framework}) failed: ${(err as Error).message}`);
    }

    try {
      const insecureDefaultFindings = detectInsecureDefaults({ specs: [spec], callsites });
      for (const f of insecureDefaultFindings) {
        out.push(insecureDefaultToFlow(f, specOsvId));
      }
    } catch (err) {
      onWarn?.(`detector regime: detectInsecureDefaults(${spec.framework}) failed: ${(err as Error).message}`);
    }
  }
  return out;
}

/**
 * Build the `{ filePath, content }[]` the regex-literal detector consumes from
 * the workspace source files the engine already analysed. We source the file
 * set from the callgraph nodes (one `<module>` node per workspace source file,
 * so files that only DECLARE a regex const with no calls are still included)
 * unioned with IR step locations for cross-language robustness. node_modules is
 * excluded by the callgraph walk, so this scans user code only — matching the
 * detector's "is the unsafe literal present in the code that imports the
 * package?" question. Paths are workspace-relative POSIX (so the resulting
 * flow's file matches the rest of the engine's locations); content is read from
 * the resolved absolute path. Unreadable files are skipped, not fatal.
 */
function collectSourceFilesForRegex(
  propagation: PropagateResult,
  workspaceRoot: string,
  onWarn?: (msg: string) => void,
): Array<{ filePath: string; content: string }> {
  const relPaths = new Set<string>();
  for (const node of propagation.callgraph?.nodes ?? []) {
    if (node.filePath) relPaths.add(node.filePath);
  }
  for (const fn of propagation.irFunctions ?? []) {
    for (const step of fn.steps) {
      if (step.loc?.filePath) relPaths.add(step.loc.filePath);
    }
  }

  const files: Array<{ filePath: string; content: string }> = [];
  for (const rel of relPaths) {
    const abs = path.isAbsolute(rel) ? rel : path.join(workspaceRoot, rel);
    try {
      files.push({ filePath: rel, content: fs.readFileSync(abs, 'utf8') });
    } catch (err) {
      onWarn?.(`regex-literal detector: could not read ${rel}: ${(err as Error).message}`);
    }
  }
  return files;
}

interface FpFilterStageOutput {
  stats: AiFilterStats;
  flowsAfterFilter: Flow[];
}

/**
 * Resolve the org's filter settings, pre-check the cost cap, batch the
 * sub-threshold flows through DeepInfra Qwen (the model defaults to
 * `Qwen/Qwen3-235B-A22B-Instruct-2507`; see `runFpFilterStage` below), and
 * return the surviving flows + telemetry.
 */
async function runFpFilterStage(
  flows: Flow[],
  fp: FpFilterContext,
  workspaceRoot: string,
  specs: FrameworkSpec[],
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
    flowsTruncated: 0,
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

  // Per-call atomic cost-cap (Redis INCRBYFLOAT) replaces the old pre-batch
  // SUM-based precheck. The previous design read monthlySpend from the RPC,
  // projected the whole batch, and gated once — two concurrent extractions
  // could both pass and both burn the cap. Redis check-and-increment makes
  // each call serialized at the bucket key.
  //
  // Cap value comes from settings (with sane default); we read it once for
  // the warn message but the actual cap is read inside assertWithinCostCap
  // so a settings change mid-batch is honored on the next call.
  const cap = Number(settings?.monthly_ai_cost_cap_usd ?? DEFAULT_MONTHLY_AI_COST_CAP_USD);

  baseStats.invoked = true;
  const logger = createUsageLogger(fp.storage, {
    organizationId: fp.organizationId,
    userId: fp.userId,
    projectId: fp.projectId,
    extractionRunId: fp.extractionRunId,
  }, onWarn);

  // Sequential calls so we don't overwhelm the rate limit on huge batches.
  // ~60s timeout per call; for ≤100 flows the M7 perf budget allows this.
  const surviving: Flow[] = [...above];
  let capExhausted = false;
  let capInfraFailed = false;
  let scanCapExhausted = false;
  for (const f of below) {
    if (capExhausted || capInfraFailed || scanCapExhausted) {
      // Once we hit the cap (or Redis is down), the remaining flows pass
      // through unfiltered — same semantics as kept_on_error so they get
      // graded by the deterministic engine alone, not silently dropped.
      surviving.push(f);
      continue;
    }

    const perFlowEstimate = estimatePerFlowCostUsd(f);

    // Phase 33: per-scan cap check (scan_jobs.ai_cost_cap_usd). Sits BEFORE
    // the org-month Redis bucket so the operator's per-extraction ceiling
    // can clamp tighter than the monthly cap. The DB read is async but
    // cheap (~5ms); we only do it when fp.jobId is set, so CLI mode is
    // untouched.
    if (fp.jobId) {
      const capCheck = await checkScanJobCostCap(fp.storage, fp.jobId, perFlowEstimate);
      if (capCheck.wouldExceed && capCheck.cap !== null) {
        scanCapExhausted = true;
        baseStats.skippedReason ??= 'scan_cost_cap_exceeded';
        onWarn?.(
          `fp-filter per-scan cap exhausted at flow ${f.id}: $${capCheck.currentTotal.toFixed(4)} ` +
            `+ projected $${perFlowEstimate.toFixed(4)} > cap $${capCheck.cap.toFixed(4)}`,
        );
        await logScanJobCostCapExceeded(fp.storage, {
          jobId: fp.jobId,
          projectId: fp.projectId,
          step: 'taint_engine_fp_filter',
          cap: capCheck.cap,
          currentTotal: capCheck.currentTotal,
          projectedCost: perFlowEstimate,
          provider: 'openai',
          model: fp.model ?? 'Qwen/Qwen3-235B-A22B-Instruct-2507',
        });
        surviving.push(f);
        continue;
      }
    }

    // Atomic reservation against the per-org Redis bucket. The cap is
    // re-read inside assertWithinCostCap, so settings changes propagate.
    try {
      await assertWithinCostCap(fp.storage, fp.organizationId, perFlowEstimate);
    } catch (err) {
      if (err instanceof CostCapExceededError) {
        capExhausted = true;
        baseStats.skippedReason ??= 'cost_cap_exceeded_mid_batch';
        onWarn?.(
          `fp-filter cap exhausted at flow ${f.id}: $${err.spentUsd.toFixed(4)} of $${err.capUsd.toFixed(2)} (cap context $${cap.toFixed(2)})`,
        );
        surviving.push(f);
        continue;
      }
      if (err instanceof CostCapInfraError) {
        // Fail-closed on Redis outage. We surface a distinct skippedReason
        // so admins can tell the difference from "cap actually blown".
        capInfraFailed = true;
        baseStats.skippedReason ??= 'cost_cap_unavailable';
        onWarn?.(`fp-filter halted: cost-cap infrastructure unavailable: ${err.message}`);
        surviving.push(f);
        continue;
      }
      throw err;
    }

    // The reservation above is held against the per-org Redis bucket. If
    // filterFlow throws, the refund path below never runs and the full
    // perFlowEstimate leaks permanently — refund it on the throw path.
    let result;
    try {
      result = await filterFlow(
        { flow: f, workspaceRoot, apiKey, model: fp.model, specs, onWarn },
        logger,
        {
          organizationId: fp.organizationId,
          userId: fp.userId,
          projectId: fp.projectId,
          extractionRunId: fp.extractionRunId,
        },
      );
    } catch (err) {
      await refundReservation(fp.organizationId, perFlowEstimate);
      throw err;
    }

    // Phase 33: roll per-call telemetry into scan_jobs. No-op when fp.jobId
    // is undefined (CLI mode). filterFlow returns costUsd on every verdict
    // including ai_truncated / kept_on_error; we count the spend regardless.
    // FilterErrorVerdict has cost but no tokens — record cost only in that
    // case so the running total tracks reality.
    if (fp.jobId && result.costUsd > 0) {
      const hasTokens = result.verdict !== 'ai_truncated' && result.verdict !== 'kept_on_error';
      await recordScanJobAiUsage(fp.storage, {
        jobId: fp.jobId,
        organizationId: fp.organizationId,
        provider: 'openai',
        model: fp.model ?? 'Qwen/Qwen3-235B-A22B-Instruct-2507',
        promptTokens: hasTokens ? (result as { inputTokens: number }).inputTokens : 0,
        completionTokens: hasTokens ? (result as { outputTokens: number }).outputTokens : 0,
        costUsd: result.costUsd,
      });
    }
    baseStats.verdicts.set(f.id, result);

    // Refund the difference between projected and actual so the bucket
    // stays accurate when the call cost less than estimated (sanitizer
    // pre-pass found candidates → smaller prompt, etc).
    const overshoot = perFlowEstimate - result.costUsd;
    if (overshoot > 0) {
      await refundReservation(fp.organizationId, overshoot);
    }

    if (result.verdict === 'kept_on_error' || result.verdict === 'ai_truncated') {
      // Both error paths keep the flow but feed a synthetic ai_filter_verdict
      // node downstream so the M5 aggregator can EXCLUDE the flow from the
      // MAX vote (status precedence: ai_truncated > kept_on_error).
      if (result.verdict === 'ai_truncated') baseStats.flowsTruncated++;
      else baseStats.flowsKeptOnError++;
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

/**
 * Map an arbitrary key to a stable bucket in [0, 100). The same key always
 * lands in the same bucket, so a given org's run/skip decision never flaps
 * between scans (which would swing its depscore).
 */
function stableBucket(key: string): number {
  const hex = createHash('sha1').update(key).digest('hex').slice(0, 8);
  return (parseInt(hex, 16) % 10000) / 100;
}

/**
 * Staged rollout gate. Reads DEPTEX_TAINT_ENGINE_ROLLOUT_PCT (0-100); if
 * the env var is unset we default to 0 in production (engine off) and 100
 * elsewhere so the local CLI / tests always run the engine.
 *
 * The decision is bucketed on a STABLE hash of `bucketKey` (the org id) so a
 * single org always lands on the same side of the rollout cut — re-scanning
 * the same project never flips run↔skip, which would otherwise swing its
 * depscore between scans. When no bucketKey is supplied (CLI / tests) we
 * fall back to Math.random().
 */
export function shouldRunForRollout(
  env: NodeJS.ProcessEnv = process.env,
  bucketKey?: string,
): boolean {
  const raw = env.DEPTEX_TAINT_ENGINE_ROLLOUT_PCT;
  if (raw === undefined) {
    // Off by default in production; on otherwise.
    return env.NODE_ENV !== 'production';
  }
  const pct = Math.max(0, Math.min(100, Number(raw)));
  if (Number.isNaN(pct)) return false;
  if (pct === 100) return true;
  if (pct === 0) return false;
  const roll = bucketKey ? stableBucket(`rollout:${bucketKey}`) : Math.random() * 100;
  return roll < pct;
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
    if (error) return shouldRunForRollout(env, organizationId);
    const row = data as { rollout_pct_override?: number | null } | null;
    const override = row?.rollout_pct_override ?? null;
    if (override === null || override === undefined) return shouldRunForRollout(env, organizationId);
    const pct = Math.max(0, Math.min(100, Number(override)));
    if (!Number.isFinite(pct)) return shouldRunForRollout(env, organizationId);
    if (pct === 100) return true;
    if (pct === 0) return false;
    // Stable per-org bucket so re-scans never flip run↔skip.
    return stableBucket(`rollout:${organizationId}`) < pct;
  } catch {
    return shouldRunForRollout(env, organizationId);
  }
}
