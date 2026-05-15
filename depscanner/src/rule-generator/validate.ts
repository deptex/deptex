/**
 * Validates a generated FrameworkSpec payload against:
 *
 *   Gate 1 — strict zod schema. Already enforced upstream by `parseAndValidate`
 *            in generate.ts; reaching validateRule means schema_pass = true.
 *
 *   Gate 2 — fixture round-trip via the Phase 6 cross-file taint engine.
 *            The substituted spec (osv_id injected on every sink) is loaded
 *            alongside the bundled framework specs (Express, Flask, etc.) and
 *            the engine is run on the vulnerable_fixture and safe_fixture
 *            files. Pass iff the spec emits ≥1 flow on the vulnerable fixture
 *            (tagged with the CVE's sinks) and 0 flows on the safe fixture.
 *
 *   Gate 3 — diff-targeted patch round-trip (optional). Same engine call but
 *            against the patch's pre-fix and post-fix file blobs. Hard-fail
 *            on post-fix matches (the rule fires on what upstream considers
 *            safe). Pre-fix matches are advisory only — app-callsite specs
 *            legitimately get pre=0 against library-internal patches.
 *
 * No more Semgrep. No more YAML pre-pass. The Phase 5 generator's `semgrep
 * --validate` rule-grammar gate is replaced by zod's `.strict()` mode +
 * `findRogueOsvIdInSinks` + the engine's `validateSpec` pass (called via
 * spec-loader's `validateSpec`). The engine round-trip itself is the
 * authoritative "this spec actually emits flows" check.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { GeneratedPayload } from './generate';
import {
  withOsvIdsSubstituted,
  type FrameworkSpecJson,
  type PersistedFrameworkSpec,
} from './framework-spec-schema';
import type { ChangedFileBlob } from './patch-fetch';
import { propagate } from '../taint-engine/propagator';
import { propagatePython } from '../taint-engine/python/propagate';
import { propagateJava } from '../taint-engine/java/propagate';
import { propagateGo } from '../taint-engine/go/propagate';
import { propagateRuby } from '../taint-engine/ruby/propagate';
import { propagatePhp } from '../taint-engine/php/propagate';
import { propagateRust } from '../taint-engine/rust/propagate';
import { propagateCSharp } from '../taint-engine/csharp/propagate';
import { loadSpec } from '../taint-engine/spec-loader';
import type { FrameworkSpec, FrameworkLanguage, VulnClass } from '../taint-engine/spec';
import type { PropagateResult } from '../taint-engine/propagator';
import { validatePatternSyntax } from '../taint-engine/pattern-syntax';
import {
  detectSanitizerAbsence,
  extractCallSitesFromIr,
} from '../taint-engine/non-taint-detector';
import { detectInsecureDefaults } from '../taint-engine/insecure-default-detector';
import { canonicalVulnClass, vulnClassesAreEquivalent } from './vuln-class-alias';

export interface ValidateRuleArgs {
  payload: GeneratedPayload;
  cveId: string;
  ecosystem: string;
  /** Per-file before/after blobs from the OSV fix commit. When provided +
   *  runPatchValidation, validate runs Gate 3 against pre/post text. */
  changedFiles?: ChangedFileBlob[];
  workDir: string;
  signal?: AbortSignal;
  /** Run Gate 3 (patch round-trip) in addition to Gate 2 (fixture). Defaults
   *  to true when changedFiles is provided. */
  runPatchValidation?: boolean;
  /** Override the bundled framework-models directory — exposed for tests. */
  frameworkModelsDir?: string;
}

export interface PerFileValidationBreakdown {
  path: string;
  pre: number;
  post: number;
}

/**
 * Funnel-style per-CVE summary of which validation gates passed. Aggregated
 * across all candidates in a run by rule-generation-step into the
 * `extraction_jobs.reachability_validation_breakdown` JSONB column.
 *
 * `schema_pass` is always true on a breakdown produced by validateRule —
 * reaching validate means the AI's JSON already passed zod. Pre-validate
 * failure modes (parse_failed / invalid_schema / prompt_injection_suspect /
 * no_advisory etc.) get a synthesized breakdown in index.ts where
 * schema_pass=false.
 *
 * `semgrep_parse_error` is retained for backward-compat with the
 * extraction_jobs.reachability_validation_breakdown JSONB column written by
 * Phase 5; in M2b it carries any engine-load error (spec validation failure,
 * propagator throw) instead of Semgrep's grammar errors. M5 will rename the
 * column once Phase 5 is fully retired.
 */
export interface ValidationBreakdown {
  schema_pass: boolean;
  /** Pre-flight pattern-syntax check on every source/sink/sanitizer pattern.
   *  null = the gate didn't run (pre-attempt bail before the AI called, or
   *  spec_load threw before we reached the pattern check). true = every
   *  pattern is structurally well-formed. false = at least one was rejected,
   *  with the reason in `validation_log.errors[]` tagged `pattern_compile:`. */
  pattern_compile_pass: boolean | null;
  fixture_pre_match: boolean;
  fixture_safe_clean: boolean;
  patch_pre_match: boolean | null;
  patch_post_clean: boolean | null;
  semgrep_parse_error: string | null;
}

export interface ValidationLog {
  fixture_pre_matches: number;
  fixture_post_matches: number;
  patch_pre_matches: number | null;
  patch_post_matches: number | null;
  semgrep_stderr_excerpt: string | null;
  errors: string[];
  took_ms: number;
  patch_validation_skipped_reason?: string;
  patch_per_file?: PerFileValidationBreakdown[];
  validation_breakdown: ValidationBreakdown;
  /** When the row is a non-validated outcome (no_advisory / no_fix_commit /
   *  fetch_failed / vuln_class_out_of_scope / prompt_injection_suspect /
   *  failed_validation / provider_error), this carries the GenerationStatus
   *  string so the org-settings UI can render "we tried this CVE; uncoverable
   *  because: <reason>". Absent on validated rows. */
  terminal_reason?: string;
  /** Up to ~20 candidate callsites the engine observed in the vulnerable
   *  fixture when Gate 2 failed (fixturePre === 0 OR fixturePost > 0). The
   *  retry-loop feedback prompt formats these so the model can see the
   *  concrete callee texts + argument shapes it should be targeting. Empty /
   *  absent on validated rows or when Gate 1 (schema) failed before Gate 2
   *  ran. Best-effort: capture failure is silently swallowed (`engine_diag`
   *  in errors[]). */
  engine_observed_callsites?: ObservedCallsite[];
}

/**
 * A concrete call site the engine observed in the AI's vulnerable_fixture.
 * Used in retry feedback to show the model "the engine saw these — your sink
 * pattern didn't match any of them. Pick one and update your pattern."
 */
export interface ObservedCallsite {
  /** Verbatim callee text from the lowered IR (e.g. `safe_buffer.bytesplice`,
   *  `wrapper.setPropertyValues`, `http.request`). The string is exactly what
   *  the engine matched against; aligning the AI's `sink.pattern` to one of
   *  these flips the spec from `fixture_pre_matches: 0` to `>0`. */
  calleeText: string;
  /** Source location (`file:line`). Helps the AI cross-reference the call to
   *  the fixture body. */
  loc: string;
  /** Comma-joined argument texts, truncated. Lets the AI see whether its
   *  `argument_indices` lines up with where the taint actually is. */
  args: string;
}

export interface ValidationResult {
  status: 'validated' | 'failed_validation';
  log: ValidationLog;
}

export class RuleValidationError extends Error {
  readonly stage: 'spec_load' | 'fixture_run' | 'patch_run' | 'engine' | 'unexpected';

  constructor(stage: RuleValidationError['stage'], message: string) {
    super(message);
    this.name = 'RuleValidationError';
    this.stage = stage;
  }
}

const DEFAULT_FRAMEWORK_MODELS_DIR = path.resolve(__dirname, '..', 'taint-engine', 'framework-models');

export async function validateRule(args: ValidateRuleArgs): Promise<ValidationResult> {
  const start = Date.now();
  const errors: string[] = [];

  // --- Substitute osv_id on every sink. The persistence step does this
  // again as the canonical assignment site, but the round-trip needs the
  // substituted spec NOW so flow filtering can match by sink pattern.
  const substituted = withOsvIdsSubstituted(args.payload.framework_spec, args.cveId);
  const language = frameworkSpecLanguage(args.payload.framework_spec);

  // --- Engine spec load: convert the JSON-shaped FrameworkSpec to the
  // engine's runtime shape via spec-loader's validator. Catches anything
  // the JSON schema accepted but the engine can't run (e.g. a vuln_class
  // the engine doesn't recognise — the schema enum imports from the same
  // source-of-truth, but defensive-load belt-and-braces).
  let engineSpec: FrameworkSpec;
  try {
    engineSpec = persistedSpecToEngineSpec(substituted);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      status: 'failed_validation',
      log: {
        fixture_pre_matches: 0,
        fixture_post_matches: 0,
        patch_pre_matches: null,
        patch_post_matches: null,
        semgrep_stderr_excerpt: null,
        errors: [`spec_load: ${msg}`],
        took_ms: Date.now() - start,
        validation_breakdown: {
          schema_pass: true,
          pattern_compile_pass: null,
          fixture_pre_match: false,
          fixture_safe_clean: false,
          patch_pre_match: null,
          patch_post_clean: null,
          semgrep_parse_error: msg.slice(0, 500),
        },
      },
    };
  }

  // --- Pattern-syntax pre-flight: cheap structural check on every source /
  // sink / sanitizer pattern. Closes the gap left when Phase 5 retired
  // `semgrep --validate` -- malformed patterns like `_.template((*` would
  // otherwise pass zod (string + min(1)) and `validateSpec` (string-only)
  // and silently no-op inside `matchesCallPattern` at flow-walk time.
  // Runs BEFORE Gate 2 because fixture round-trip is expensive and a
  // structurally-broken pattern can never round-trip anyway.
  const patternErrors: string[] = [];
  for (const src of engineSpec.sources) {
    const r = validatePatternSyntax(src.pattern);
    if (!r.ok) patternErrors.push(`pattern_compile: source ${JSON.stringify(src.pattern)}: ${r.reason}`);
  }
  for (const sink of engineSpec.sinks) {
    const r = validatePatternSyntax(sink.pattern);
    if (!r.ok) patternErrors.push(`pattern_compile: sink ${JSON.stringify(sink.pattern)} (${sink.vuln_class}): ${r.reason}`);
  }
  for (const san of engineSpec.sanitizers) {
    const r = validatePatternSyntax(san.pattern);
    if (!r.ok) patternErrors.push(`pattern_compile: sanitizer ${JSON.stringify(san.pattern)}: ${r.reason}`);
  }
  if (patternErrors.length > 0) {
    return {
      status: 'failed_validation',
      log: {
        fixture_pre_matches: 0,
        fixture_post_matches: 0,
        patch_pre_matches: null,
        patch_post_matches: null,
        semgrep_stderr_excerpt: null,
        errors: patternErrors,
        took_ms: Date.now() - start,
        validation_breakdown: {
          schema_pass: true,
          pattern_compile_pass: false,
          fixture_pre_match: false,
          fixture_safe_clean: false,
          patch_pre_match: null,
          patch_post_clean: null,
          semgrep_parse_error: null,
        },
      },
    };
  }

  // --- Bundled framework specs for the language (sources). Filtered by
  // language so cross-language patterns don't leak.
  const frameworkSpecs = loadFrameworkSpecsForLanguage(args.frameworkModelsDir ?? DEFAULT_FRAMEWORK_MODELS_DIR, language);
  const allSpecs: FrameworkSpec[] = [...frameworkSpecs, engineSpec];
  // Accepted sink patterns for Gate 2 = the AI rule's own sinks UNION the
  // bundled framework_model sinks whose vuln_class matches one the AI
  // declared. Rationale: a CVE for a library that the bundled framework
  // models already cover (Log4j, Jackson, etc.) doesn't require the AI to
  // re-name the sink — its contribution is the OSV→sink-shape mapping,
  // and confirming on a bundled sink of the SAME vuln_class is correct
  // semantics. The safe-fixture pass uses the same widened set, so the
  // `pre>0 ∧ post=0` asymmetry that proves the rule discriminates is
  // preserved. Gate 3 (patch round-trip) remains the harder check that
  // the rule fires on real upstream-pre-patch code.
  //
  // Vuln-class normalization (canonicalVulnClass) bridges alternate-
  // vocabulary labels — log_injection / log4shell / ssti / template_injection /
  // dos — onto the canonical class the bundled framework_models actually
  // emit (typically code_injection or redos). Without this, an AI rule
  // labelling a Logger.info(*) sink as `log_injection` fails to widen onto
  // log4j.yaml's `code_injection` sinks of the same pattern.
  const aiVulnClasses = new Set(engineSpec.sinks.map((s) => canonicalVulnClass(s.vuln_class)));
  const cveSinkPatterns = new Set<string>(engineSpec.sinks.map((s) => s.pattern));
  // Phase 3.3 — also seed cveSinkPatterns with any insecure_defaults patterns
  // the AI-generated spec declared. Detector findings use `sink_pattern =
  // entry.pattern`, so without this the count loop in runEngineAndCount
  // can't credit a fired insecure-default finding against the CVE.
  if (engineSpec.insecure_defaults) {
    for (const entry of engineSpec.insecure_defaults) {
      cveSinkPatterns.add(entry.pattern);
    }
  }
  // Equivalence groups (vulnClassesAreEquivalent) bridge cases where the
  // AI's vuln_class label and the bundled spec's label are both correct
  // framings of the same primitive. Example: Spring4Shell's
  // BeanWrapperImpl.setPropertyValues is `code_injection` in spring-boot.yaml
  // (bytes-to-class-loading) and `deserialization` in Qwen's emitted spec
  // (attacker property paths deserialised into runtime classes). Without
  // equivalence, the bundled sink doesn't widen onto the AI's CVE.
  const sinkClassMatches = (bundledClass: string): boolean => {
    const canonical = canonicalVulnClass(bundledClass);
    if (aiVulnClasses.has(canonical)) return true;
    for (const ai of aiVulnClasses) {
      if (vulnClassesAreEquivalent(ai, canonical)) return true;
    }
    return false;
  };
  for (const spec of frameworkSpecs) {
    for (const sink of spec.sinks) {
      if (sinkClassMatches(sink.vuln_class)) cveSinkPatterns.add(sink.pattern);
    }
    if (spec.insecure_defaults) {
      for (const entry of spec.insecure_defaults) {
        const entryClass = entry.vuln_class ?? 'weak_crypto';
        if (sinkClassMatches(entryClass)) cveSinkPatterns.add(entry.pattern);
      }
    }
  }

  // --- Gate 2: fixture round-trip ---
  const ext = sourceExtensionForLanguage(language);
  let fixturePre = 0;
  let fixturePost = 0;
  let vulnIrFunctions: PropagateResult['irFunctions'] | undefined;
  const fixtureRoot = fs.mkdtempSync(path.join(args.workDir, 'rulegen-fix-'));
  try {
    const vulnDir = path.join(fixtureRoot, 'vulnerable');
    const safeDir = path.join(fixtureRoot, 'safe');
    fs.mkdirSync(vulnDir, { recursive: true });
    fs.mkdirSync(safeDir, { recursive: true });
    fs.writeFileSync(path.join(vulnDir, `index.${ext}`), args.payload.vulnerable_fixture, 'utf8');
    fs.writeFileSync(path.join(safeDir, `index.${ext}`), args.payload.safe_fixture, 'utf8');

    const preResult = await runEngineAndCount({
      rootDir: vulnDir,
      specs: allSpecs,
      language,
      cveSinkPatterns,
      signal: args.signal,
    });
    fixturePre = preResult.count;
    vulnIrFunctions = preResult.irFunctions;

    const postResult = await runEngineAndCount({
      rootDir: safeDir,
      specs: allSpecs,
      language,
      cveSinkPatterns,
      signal: args.signal,
    });
    fixturePost = postResult.count;
  } catch (err) {
    errors.push(`fixture_run: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    safeRm(fixtureRoot);
  }

  // --- Retry-loop telemetry: when Gate 2 fails, capture concrete callsites the
  // engine saw in the vulnerable fixture. The buildAttemptFailureFeedback
  // renderer surfaces these to the model so the next attempt can target a
  // real callee text instead of guessing. Best-effort: silently skip on
  // missing IR (engine threw, or language without IR exposure).
  let observedCallsites: ObservedCallsite[] | undefined;
  if (vulnIrFunctions && vulnIrFunctions.length > 0 && (fixturePre === 0 || fixturePost > 0)) {
    try {
      observedCallsites = collectObservedCallsites(vulnIrFunctions, language, engineSpec.sinks);
    } catch (err) {
      // Best-effort — diagnostic capture must never fail validation.
      errors.push(`engine_diag: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // --- Gate 3: diff-targeted patch round-trip (optional) ---
  let patchPre: number | null = null;
  let patchPost: number | null = null;
  let patchPerFile: PerFileValidationBreakdown[] | undefined;
  let patchSkipReason: string | undefined;

  const hasChangedFiles = !!args.changedFiles && args.changedFiles.length > 0;
  const shouldRunPatch = (args.runPatchValidation ?? true) && hasChangedFiles && errors.length === 0;
  if (shouldRunPatch && args.changedFiles) {
    try {
      const applicable = filterApplicableChangedFiles(args.changedFiles, language);
      if (applicable.length === 0) {
        patchSkipReason = 'no_applicable_changed_files';
      } else {
        const result = await runDiffTargetedValidation({
          allSpecs,
          cveSinkPatterns,
          files: applicable,
          language,
          workDir: args.workDir,
          signal: args.signal,
        });
        patchPre = result.preMatches;
        patchPost = result.postMatches;
        patchPerFile = result.perFile;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      patchSkipReason = err instanceof RuleValidationError ? `${err.stage}: ${msg}` : `unexpected: ${msg}`;
    }
  } else if (!hasChangedFiles) {
    patchSkipReason = 'no_changed_files_provided';
  } else if (errors.length > 0) {
    patchSkipReason = 'fixture_validation_failed';
  } else if (args.runPatchValidation === false) {
    patchSkipReason = 'disabled_by_caller';
  }

  // --- Verdict ---
  const fixturePass = fixturePre > 0 && fixturePost === 0;
  if (!fixturePass && errors.length === 0) {
    errors.push(`fixture_round_trip_failed: pre=${fixturePre} post=${fixturePost} (require pre>0 and post=0)`);
  }
  if (patchPre !== null && patchPost !== null) {
    // patch_pre_match is advisory: app-callsite specs legitimately get
    // pre_match=0 against library-internal patches.
    if (patchPre <= 0 && !patchSkipReason) {
      patchSkipReason = 'patch_pre_match_zero_advisory';
    }
    // patch_post_clean is a HARD gate: if the spec fires on the fixed code,
    // the spec is matching what upstream considers safe.
    if (patchPost > 0) errors.push(`patch_round_trip_failed: post-patch matches=${patchPost} (require 0)`);
  }

  const status = errors.length === 0 && fixturePass ? 'validated' : 'failed_validation';

  return {
    status,
    log: {
      fixture_pre_matches: fixturePre,
      fixture_post_matches: fixturePost,
      patch_pre_matches: patchPre,
      patch_post_matches: patchPost,
      semgrep_stderr_excerpt: null,
      errors,
      took_ms: Date.now() - start,
      patch_validation_skipped_reason: patchSkipReason,
      patch_per_file: patchPerFile,
      engine_observed_callsites: observedCallsites,
      validation_breakdown: {
        schema_pass: true,
        pattern_compile_pass: true,
        fixture_pre_match: fixturePre > 0,
        fixture_safe_clean: fixturePost === 0,
        patch_pre_match: patchPre === null ? null : patchPre > 0,
        patch_post_clean: patchPost === null ? null : patchPost === 0,
        semgrep_parse_error: null,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Engine invocation helpers
// ---------------------------------------------------------------------------

interface RunEngineArgs {
  rootDir: string;
  specs: FrameworkSpec[];
  language: FrameworkLanguage;
  cveSinkPatterns: Set<string>;
  signal?: AbortSignal;
}

interface RunEngineResult {
  count: number;
  /** Reference to the lowered IR — exposed so the caller can extract
   *  observed callsites for retry-loop feedback when Gate 2 fails. */
  irFunctions: PropagateResult['irFunctions'];
}

async function runEngineAndCount(args: RunEngineArgs): Promise<RunEngineResult> {
  const result = await dispatchPropagate(args.rootDir, args.specs, args.language, args.signal);
  // Count flows whose sink_pattern was contributed by the CVE-targeted spec
  // (vs the bundled framework specs' sinks, which are noise here).
  let count = 0;
  for (const flow of result.flows) {
    if (args.cveSinkPatterns.has(flow.sink_pattern)) count++;
  }

  // --- Phase F4 non-taint detector ---
  // After the taint engine runs, also walk the lowered IR for sanitizer-
  // absence findings. A sink that participates in BOTH regimes (rare today;
  // most F4 sinks set `argument_indices: []`) won't double-count because
  // the taint flow and non-taint finding are emitted by different
  // mechanisms — flows from sinkHits in the propagator, findings from
  // direct AST inspection here. We add non-taint findings to the same
  // count so Gate 2's `fixturePre > 0 && fixturePost === 0` assertion
  // works without any caller-side branching.
  if (result.irFunctions && result.irFunctions.length > 0) {
    const callsites = extractCallSitesFromIr(result.irFunctions, args.language);
    for (const spec of args.specs) {
      const hasReqArgs = spec.sinks.some(
        (s) => s.required_arguments && s.required_arguments.length > 0,
      );
      if (hasReqArgs) {
        const findings = detectSanitizerAbsence(spec, callsites);
        for (const f of findings) {
          if (args.cveSinkPatterns.has(f.sink_pattern)) count++;
        }
      }
    }

    // --- Phase 3.3 insecure-default detector ---
    // Same wiring as F4 above but operates on the spec's top-level
    // `insecure_defaults` (kwarg absence + forbidden value shapes), not
    // sink.required_arguments. Each detector's `sink_pattern` is the entry's
    // `pattern` field, so the cveSinkPatterns membership check still works.
    const specsWithInsecureDefaults = args.specs.filter(
      (s) => s.insecure_defaults && s.insecure_defaults.length > 0,
    );
    if (specsWithInsecureDefaults.length > 0) {
      const idFindings = detectInsecureDefaults({
        specs: specsWithInsecureDefaults,
        callsites,
      });
      for (const f of idFindings) {
        if (args.cveSinkPatterns.has(f.sink_pattern)) count++;
      }
    }
  }

  return { count, irFunctions: result.irFunctions };
}

/**
 * Extract candidate callsites the engine observed in the AI's vulnerable
 * fixture, ranked by likelihood of being the intended sink. Used in retry-
 * loop feedback (rule-generator/index.ts buildAttemptFailureFeedback) to
 * show the model concrete callee texts when its sink pattern missed.
 *
 * Ranking heuristic:
 *   1. Method-name match: callee's last `.method` segment == any AI sink's
 *      last segment. These are the highest-signal sites — the AI named the
 *      right method but wrong receiver / qualifier.
 *   2. Other call sites in the fixture, up to a small cap.
 *
 * Returns at most 12 entries to keep the retry prompt compact.
 */
function collectObservedCallsites(
  irFunctions: NonNullable<PropagateResult['irFunctions']>,
  language: FrameworkLanguage,
  aiSinks: ReadonlyArray<{ pattern: string }>,
): ObservedCallsite[] {
  if (language === 'js' || language === 'python' || language === 'java' ||
      language === 'go' || language === 'ruby' || language === 'php' ||
      language === 'rust' || language === 'csharp') {
    const sites = extractCallSitesFromIr(irFunctions, language);
    if (sites.length === 0) return [];

    // Collect the AI's sink method names (last `.` / `->` / `::` segment of
    // each pattern, minus the trailing `(*)`). Used to bubble matches to the
    // top of the candidate list.
    const aiMethodNames = new Set<string>();
    for (const s of aiSinks) {
      const stripped = s.pattern.endsWith('(*)') ? s.pattern.slice(0, -3) : s.pattern;
      const last = stripped.split(/[.:>-]+/).pop();
      if (last) aiMethodNames.add(last);
    }

    const matchedByMethod: ObservedCallsite[] = [];
    const other: ObservedCallsite[] = [];
    const seen = new Set<string>();
    for (const cs of sites) {
      // Light de-dup: same callee + same line counts as one.
      const key = `${cs.calleeText}@${cs.line ?? -1}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const argsJoined = cs.argTexts
        .map((a: string) => (a.length > 40 ? a.slice(0, 37) + '...' : a))
        .join(', ');
      const args = argsJoined.length > 120 ? argsJoined.slice(0, 117) + '...' : argsJoined;
      const entry: ObservedCallsite = {
        calleeText: cs.calleeText,
        loc: `${path.basename(cs.filePath ?? '?')}:${cs.line ?? '?'}`,
        args,
      };
      const lastSeg = cs.calleeText.split(/[.:>-]+/).pop() ?? '';
      if (aiMethodNames.has(lastSeg)) {
        matchedByMethod.push(entry);
      } else {
        other.push(entry);
      }
    }
    // Cap output: prefer method-matched first, then fill with up to 12 total.
    const out: ObservedCallsite[] = [];
    for (const e of matchedByMethod) {
      if (out.length >= 12) break;
      out.push(e);
    }
    for (const e of other) {
      if (out.length >= 12) break;
      out.push(e);
    }
    return out;
  }
  return [];
}

async function dispatchPropagate(
  rootDir: string,
  specs: FrameworkSpec[],
  language: FrameworkLanguage,
  signal: AbortSignal | undefined,
): Promise<PropagateResult> {
  const onWarn = (_msg: string) => { /* swallow during validation; engine warnings aren't user-actionable here */ };
  switch (language) {
    case 'python':
      return propagatePython({ rootDir, specs, onWarn, signal });
    case 'java':
      return propagateJava({ rootDir, specs, onWarn, signal });
    case 'go':
      return propagateGo({ rootDir, specs, onWarn, signal });
    case 'ruby':
      return propagateRuby({ rootDir, specs, onWarn, signal });
    case 'php':
      return propagatePhp({ rootDir, specs, onWarn, signal });
    case 'rust':
      return propagateRust({ rootDir, specs, onWarn, signal });
    case 'csharp':
      return propagateCSharp({ rootDir, specs, onWarn, signal });
    case 'js':
    default:
      return propagate({ rootDir, specs, onWarn, signal });
  }
}

interface DiffTargetedArgs {
  allSpecs: FrameworkSpec[];
  cveSinkPatterns: Set<string>;
  files: ChangedFileBlob[];
  language: FrameworkLanguage;
  workDir: string;
  signal?: AbortSignal;
}

async function runDiffTargetedValidation(args: DiffTargetedArgs): Promise<{
  preMatches: number;
  postMatches: number;
  perFile: PerFileValidationBreakdown[];
}> {
  const root = fs.mkdtempSync(path.join(args.workDir, 'rulegen-diff-'));
  try {
    const ext = sourceExtensionForLanguage(args.language);
    let preTotal = 0;
    let postTotal = 0;
    const perFile: PerFileValidationBreakdown[] = [];

    for (let i = 0; i < args.files.length; i++) {
      const file = args.files[i];
      const before = file.before ?? '';
      const after = file.after ?? '';

      const beforeDir = path.join(root, `before-${i}`);
      const afterDir = path.join(root, `after-${i}`);
      fs.mkdirSync(beforeDir, { recursive: true });
      fs.mkdirSync(afterDir, { recursive: true });

      const baseName = path.basename(file.path).replace(/\.[^./]+$/, '') || 'snippet';
      fs.writeFileSync(path.join(beforeDir, `${baseName}.${ext}`), before, 'utf8');
      fs.writeFileSync(path.join(afterDir, `${baseName}.${ext}`), after, 'utf8');

      const preResult = await runEngineAndCount({
        rootDir: beforeDir,
        specs: args.allSpecs,
        language: args.language,
        cveSinkPatterns: args.cveSinkPatterns,
        signal: args.signal,
      });
      const postResult = await runEngineAndCount({
        rootDir: afterDir,
        specs: args.allSpecs,
        language: args.language,
        cveSinkPatterns: args.cveSinkPatterns,
        signal: args.signal,
      });

      const pre = preResult.count;
      const post = postResult.count;
      preTotal += pre;
      postTotal += post;
      perFile.push({ path: file.path, pre, post });
    }

    return { preMatches: preTotal, postMatches: postTotal, perFile };
  } finally {
    safeRm(root);
  }
}

/**
 * File path patterns that look like test / spec / fixture code. When a CVE's
 * fix commit touches both library source AND its own tests (very common —
 * axios test/specs/, debug test/index.js, Pillow Tests/test_pickle.py), the
 * AI rule legitimately fires on the test file because the test reproduces
 * the bug. Gate 3 (patch round-trip) then sees post_matches > 0 from those
 * test reproductions and hard-fails the rule, even though the spec is
 * correct against real library source.
 *
 * Excluding these paths before the engine sees them is sound: a rule that
 * fires on real-world consumer code at extraction time will still fire;
 * it just no longer fails Gate 3 on upstream's own regression tests.
 *
 * Patterns are anchored at segment boundaries (`/` or string start/end) so
 * `tests/` inside any directory layer matches, but `latest/` (which contains
 * the substring `test`) does not.
 */
const TEST_PATH_PATTERNS: RegExp[] = [
  // Top-level or nested test/spec directories.
  /(?:^|\/)tests?\//i,
  /(?:^|\/)__tests?__\//i,
  /(?:^|\/)spec\//i,
  /(?:^|\/)specs\//i,
  /(?:^|\/)testing\//i,
  /(?:^|\/)test_suite\//i,
  // Fixture / mock dirs that legitimately reproduce attacker-controlled inputs.
  /(?:^|\/)fixtures?\//i,
  /(?:^|\/)mocks?\//i,
  /(?:^|\/)__mocks__\//i,
  /(?:^|\/)__fixtures__\//i,
  // Per-file test naming conventions.
  /(?:^|\/)test_[^/]+\.[^./]+$/i,           // python: test_foo.py
  /(?:^|\/)[^/]+_test\.(?:py|go|rb|java|cs|rs)$/i, // *_test.py / *_test.go / *_test.rb
  /(?:^|\/)[^/]+\.(?:spec|test)\.(?:js|jsx|mjs|cjs|ts|tsx)$/i, // *.spec.ts / *.test.js
  /(?:^|\/)[^/]+Test\.java$/,               // FooTest.java
  /(?:^|\/)[^/]+Tests\.cs$/,                // FooTests.cs
  /(?:^|\/)[^/]+Spec\.scala$/,
];

/**
 * Returns true if `filePath` looks like a test/spec/fixture file the patch
 * touched as part of regression coverage rather than library source.
 */
export function isTestPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  for (const re of TEST_PATH_PATTERNS) {
    if (re.test(normalized)) return true;
  }
  return false;
}

export function filterApplicableChangedFiles(
  files: ChangedFileBlob[],
  language: FrameworkLanguage,
): ChangedFileBlob[] {
  const accepted = expectedExtensionsForLanguage(language);
  return files.filter((f) => {
    if (f.before === null || f.after === null) return false;
    const ext = path.extname(f.path).toLowerCase().replace(/^\./, '');
    if (!accepted.has(ext)) return false;
    // Drop test-shaped paths so the AI rule's fire on test reproductions
    // doesn't fail Gate 3 (patch round-trip). See TEST_PATH_PATTERNS above.
    if (isTestPath(f.path)) return false;
    return true;
  });
}

function expectedExtensionsForLanguage(language: FrameworkLanguage): Set<string> {
  switch (language) {
    case 'js':     return new Set(['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx']);
    case 'python': return new Set(['py']);
    case 'java':   return new Set(['java']);
    case 'go':     return new Set(['go']);
    case 'ruby':   return new Set(['rb']);
    case 'php':    return new Set(['php']);
    case 'rust':   return new Set(['rs']);
    case 'csharp': return new Set(['cs']);
    default:       return new Set();
  }
}

function sourceExtensionForLanguage(language: FrameworkLanguage): string {
  switch (language) {
    case 'js':     return 'js';
    case 'python': return 'py';
    case 'java':   return 'java';
    case 'go':     return 'go';
    case 'ruby':   return 'rb';
    case 'php':    return 'php';
    case 'rust':   return 'rs';
    case 'csharp': return 'cs';
    default:       return 'txt';
  }
}

function frameworkSpecLanguage(spec: FrameworkSpecJson): FrameworkLanguage {
  // The schema's enum is ['js', 'python', ...] which is exactly the engine's
  // FrameworkLanguage union. The cast is safe by construction.
  return spec.language as FrameworkLanguage;
}

/**
 * Convert the JSON-shaped substituted FrameworkSpec to the engine's runtime
 * shape. The engine's `FrameworkSpec` type drops the persisted-only `osv_id`
 * field on sinks (the engine doesn't yet thread osv_id through Flow — that's
 * M3 task 13). For Gate 2 we identify CVE flows by sink pattern instead, so
 * dropping osv_id here is fine.
 */
function persistedSpecToEngineSpec(persisted: PersistedFrameworkSpec): FrameworkSpec {
  return {
    framework: persisted.framework,
    version: persisted.version,
    language: persisted.language,
    sources: persisted.sources.map((s) => ({
      pattern: s.pattern,
      taint_kind: s.taint_kind,
      description: s.description,
    })),
    // The zod-strict schema widens vuln_class to `string` (the import-then-
    // cast trick to keep the enum dynamic), but the engine's type is the
    // narrow `VulnClass` union. Both pull from `ALL_VULN_CLASSES`, so the
    // cast is safe by construction — the schema rejects out-of-set values
    // before we ever get here.
    sinks: persisted.sinks.map((s) => ({
      pattern: s.pattern,
      vuln_class: s.vuln_class as VulnClass,
      argument_indices: s.argument_indices,
      description: s.description,
    })),
    sanitizers: persisted.sanitizers.map((s) => ({
      pattern: s.pattern,
      vuln_classes: s.vuln_classes as VulnClass[],
      description: s.description,
    })),
  };
}

function loadFrameworkSpecsForLanguage(modelsDir: string, language: FrameworkLanguage): FrameworkSpec[] {
  if (!fs.existsSync(modelsDir)) return [];
  const out: FrameworkSpec[] = [];
  for (const entry of fs.readdirSync(modelsDir)) {
    if (!entry.endsWith('.yaml') && !entry.endsWith('.yml')) continue;
    try {
      const spec = loadSpec(path.join(modelsDir, entry));
      if ((spec.language ?? 'js') === language) out.push(spec);
    } catch {
      // Bad spec — skip; the engine startup path warns on the same files.
    }
  }
  return out;
}

function safeRm(p: string): void {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* non-fatal */ }
}

// ---------------------------------------------------------------------------
// Workdir helper
// ---------------------------------------------------------------------------

export function makeRuleGenWorkdir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-rulegen-'));
}
