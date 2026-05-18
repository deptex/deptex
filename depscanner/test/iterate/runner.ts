/**
 * Iteration harness for prompt-builder variants. Bypasses the docker
 * pipeline and the rule-generation-step orchestrator — runs the AI call
 * + validation directly per CVE, with cached OSV+patch data.
 *
 * One run = (variant prompt-builder) × (provider/model/baseUrl) × (the
 * 18-CVE corpus). Output: per-CVE result JSON + funnel summary table.
 *
 * A "variant" is a TypeScript module that exports `buildGenerationPrompt`
 * with the same signature as src/rule-generator/prompt-builder.ts. See
 * variants/v_base.ts for the reference shape.
 *
 * Optionally a variant can export `postProcessPayload(payload) => payload`
 * (e.g. server-side YAML quote-fixing) which runs between AI parse and
 * validation. This lets us A/B test deterministic fixes alongside prompt
 * changes.
 */

import * as fs from 'fs';
import * as path from 'path';
import pLimit from 'p-limit';
import { callProviderAndParse, GenerationError, type AiProviderName, type GeneratedPayload } from '../../src/rule-generator/generate';
import { validateRule, makeRuleGenWorkdir, type ValidationLog } from '../../src/rule-generator/validate';
import type { BuildPromptArgs } from '../../src/rule-generator/prompt-builder';
import { selectFrameworkSpecFewShots, type FrameworkSpecFewShot } from '../../src/rule-generator/few-shot-examples';
import { MAX_GENERATION_ATTEMPTS, buildRevisionPrompt, buildAttemptFailureFeedback } from '../../src/rule-generator';
import { CANDIDATES, type Candidate } from './candidates';
import { fetchAndCache, type CachedCveData } from './cache';

export interface VariantModule {
  NAME: string;
  VERSION: string;
  buildGenerationPrompt: (args: BuildPromptArgs) => string;
  postProcessPayload?: (payload: GeneratedPayload) => GeneratedPayload;
}

export interface RunVariantOptions {
  variant: VariantModule;
  provider: AiProviderName;
  model: string;
  apiKey: string;
  baseUrl?: string;
  candidates?: Candidate[];
  concurrency: number;
  outputDir: string;
  /** When true, skip the AI call and report only fetch state. Used to validate
   *  the cache populates correctly before burning tokens. */
  dryRun?: boolean;
  /** Per-CVE timeout in ms (covers AI + validate). Default 360s. */
  perCveTimeoutMs?: number;
  /** Optional override of the few-shot count. Default 3. */
  fewShotCount?: number;
  /** Optional override for the platform rules dir (few-shot source). */
  platformRulesDir?: string;
  /** Optional GitHub token; falls back to env. */
  githubToken?: string;
  /** Optional max output tokens passed to the provider call. */
  maxOutputTokens?: number;
  /** Optional provider-side sampling seed. When set, OpenAI-compatible
   *  providers produce reproducible generations across runs — the iterate
   *  measurement floor (currently ~3pp stddev across trials) drops to
   *  near-zero AI variance, so engine-change recall lifts become visible
   *  even at small magnitudes. Silently ignored by Anthropic/Google. */
  seed?: number;
  /** Optional sampling temperature override (default 0.1). 0 = greedy
   *  decoding; combined with `seed`, gives the closest approximation of
   *  deterministic per-CVE generation that DeepInfra Qwen3-235B offers. */
  temperature?: number;
}

export interface PerCveResult {
  cveId: string;
  packagePurl: string;
  status:
    | 'validated'
    | 'failed_validation'
    | 'no_advisory'
    | 'no_fix_commit'
    | 'fetch_failed'
    | 'parse_failed'
    | 'invalid_schema'
    | 'vuln_class_out_of_scope'
    | 'provider_error'
    | 'unexpected'
    | 'dry_run';
  errors: string[];
  costUsd: number;
  inputTokens: number;
  outputTokens: number;
  ruleYaml?: string;
  /** AI-generated framework_spec for the CVE. Persisted into report.json so
   *  post-hoc analysis can see exactly what sink/source/vuln_class the
   *  model picked — critical for debugging fixture_pre_miss cases where
   *  the engine SHOULD fire but doesn't (often a vuln_class or pattern-
   *  shape mismatch the bundled-spec union doesn't bridge). */
  frameworkSpec?: unknown;
  vulnerableFixture?: string;
  safeFixture?: string;
  validationLog?: ValidationLog;
  durationMs: number;
  /** AI calls made (1 = no retry; 2 = retry fired). Counts only successful
   *  calls — provider_error first attempts that don't retry stay at 1. */
  attempts: number;
}

export interface VariantRunReport {
  variant: { name: string; version: string };
  provider: AiProviderName;
  model: string;
  baseUrl?: string;
  startedAt: string;
  finishedAt: string;
  totalDurationMs: number;
  candidates: number;
  validated: number;
  byStatus: Record<string, number>;
  funnel: {
    schemaPass: number;
    fixturePre: number;
    fixtureSafe: number;
    patchPostClean: number;
    final: number;
  };
  totalCostUsd: number;
  perCve: PerCveResult[];
}

function withTimeoutWrap<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

async function runOne(args: {
  variant: VariantModule;
  cached: CachedCveData;
  candidate: Candidate;
  provider: AiProviderName;
  model: string;
  apiKey: string;
  baseUrl?: string;
  fewShotExamples: FrameworkSpecFewShot[];
  perCveTimeoutMs: number;
  maxOutputTokens?: number;
  seed?: number;
  temperature?: number;
}): Promise<PerCveResult> {
  const { variant, cached, candidate, provider, model, apiKey, baseUrl, fewShotExamples, perCveTimeoutMs, maxOutputTokens, seed, temperature } = args;
  const start = Date.now();
  const base: PerCveResult = {
    cveId: candidate.cveId,
    packagePurl: candidate.packagePurl,
    status: 'unexpected',
    errors: [],
    costUsd: 0,
    inputTokens: 0,
    outputTokens: 0,
    durationMs: 0,
    attempts: 0,
  };

  if (cached.status === 'no_advisory') return { ...base, status: 'no_advisory', durationMs: Date.now() - start };
  if (cached.status === 'no_fix_commit') return { ...base, status: 'no_fix_commit', durationMs: Date.now() - start };
  if (cached.status === 'fetch_failed') return { ...base, status: 'fetch_failed', errors: [cached.error ?? ''], durationMs: Date.now() - start };
  if (!cached.advisory || !cached.patchInfo) return { ...base, status: 'fetch_failed', errors: ['cache_missing'], durationMs: Date.now() - start };

  const prompt = variant.buildGenerationPrompt({
    cveId: candidate.cveId,
    packagePurl: candidate.packagePurl,
    packageName: candidate.packageName,
    ecosystem: candidate.ecosystem,
    affectedVersionRange: cached.affectedRange,
    osvSummary: cached.advisory.summary,
    osvDetails: cached.advisory.details,
    patchDiff: cached.patchInfo.diff,
    changedFiles: cached.patchInfo.changedFiles,
    fewShotExamples,
  });

  // Schema-fail retry loop. Mirrors generateRuleForCve() in src/rule-generator/index.ts
  // so the harness's validation rate reflects the production path. See the
  // export in that file for the full rationale.
  let cumulativeCost = 0;
  let cumulativeInputTokens = 0;
  let cumulativeOutputTokens = 0;
  let revisionFeedback: string | null = null;

  for (let attempt = 1; attempt <= MAX_GENERATION_ATTEMPTS; attempt++) {
    const attemptPrompt = revisionFeedback ? buildRevisionPrompt(prompt, revisionFeedback) : prompt;

    let providerResult;
    try {
      providerResult = await withTimeoutWrap(
        callProviderAndParse({
          prompt: attemptPrompt,
          provider,
          model,
          apiKey,
          baseUrl,
          maxOutputTokens,
          seed,
          temperature,
        }),
        perCveTimeoutMs,
        'provider_call',
      );
    } catch (err) {
      const code = err instanceof GenerationError ? err.code : 'provider_error';
      const status: PerCveResult['status'] = code === 'parse_failed'
        ? 'parse_failed'
        : code === 'invalid_schema' ? 'invalid_schema'
        : code === 'vuln_class_out_of_scope' ? 'vuln_class_out_of_scope'
        : 'provider_error';
      // vuln_class_out_of_scope is non-retryable — the model can't be coaxed
      // into rewriting a DoS / non-taint CVE as something the engine models.
      const retryable = status === 'parse_failed' || status === 'invalid_schema';
      if (retryable && attempt < MAX_GENERATION_ATTEMPTS) {
        revisionFeedback = buildAttemptFailureFeedback({
          payload: null,
          errorMessage: err instanceof Error ? err.message : String(err),
          validation: null,
        });
        continue;
      }
      return {
        ...base,
        status,
        errors: [err instanceof Error ? err.message : String(err)],
        costUsd: cumulativeCost,
        inputTokens: cumulativeInputTokens,
        outputTokens: cumulativeOutputTokens,
        durationMs: Date.now() - start,
        attempts: attempt,
      };
    }

    cumulativeCost += providerResult.estimatedCostUsd;
    cumulativeInputTokens += providerResult.inputTokens;
    cumulativeOutputTokens += providerResult.outputTokens;

    let payload = providerResult.payload;
    if (variant.postProcessPayload) {
      try {
        payload = variant.postProcessPayload(payload);
      } catch (err) {
        return {
          ...base,
          status: 'unexpected',
          errors: [`postProcessPayload: ${err instanceof Error ? err.message : String(err)}`],
          costUsd: cumulativeCost,
          inputTokens: cumulativeInputTokens,
          outputTokens: cumulativeOutputTokens,
          durationMs: Date.now() - start,
          attempts: attempt,
        };
      }
    }

    const workDir = makeRuleGenWorkdir();
    let validation;
    try {
      validation = await validateRule({
        payload,
        cveId: candidate.cveId,
        ecosystem: candidate.ecosystem,
        changedFiles: cached.patchInfo.changedFiles,
        workDir,
      });
    } catch (err) {
      return {
        ...base,
        status: 'unexpected',
        errors: [`validate_threw: ${err instanceof Error ? err.message : String(err)}`],
        costUsd: cumulativeCost,
        inputTokens: cumulativeInputTokens,
        outputTokens: cumulativeOutputTokens,
        ruleYaml: payload.rule_yaml,
        frameworkSpec: payload.framework_spec,
        vulnerableFixture: payload.vulnerable_fixture,
        safeFixture: payload.safe_fixture,
        durationMs: Date.now() - start,
        attempts: attempt,
      };
    } finally {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch { /* non-fatal */ }
    }

    if (validation.status === 'validated') {
      return {
        ...base,
        status: 'validated',
        errors: validation.log.errors,
        costUsd: cumulativeCost,
        inputTokens: cumulativeInputTokens,
        outputTokens: cumulativeOutputTokens,
        ruleYaml: payload.rule_yaml,
        frameworkSpec: payload.framework_spec,
        vulnerableFixture: payload.vulnerable_fixture,
        safeFixture: payload.safe_fixture,
        validationLog: validation.log,
        durationMs: Date.now() - start,
        attempts: attempt,
      };
    }

    if (attempt < MAX_GENERATION_ATTEMPTS) {
      revisionFeedback = buildAttemptFailureFeedback({
        payload,
        errorMessage: validation.log.errors.join(' | '),
        validation,
        patchDiff: cached.patchInfo.diff,
      });
      continue;
    }

    return {
      ...base,
      status: 'failed_validation',
      errors: validation.log.errors,
      costUsd: cumulativeCost,
      inputTokens: cumulativeInputTokens,
      outputTokens: cumulativeOutputTokens,
      ruleYaml: payload.rule_yaml,
      frameworkSpec: payload.framework_spec,
      vulnerableFixture: payload.vulnerable_fixture,
      safeFixture: payload.safe_fixture,
      validationLog: validation.log,
      durationMs: Date.now() - start,
      attempts: attempt,
    };
  }

  // Unreachable — every branch in the loop returns.
  return {
    ...base,
    status: 'unexpected',
    errors: ['retry_loop_exhausted_without_return'],
    costUsd: cumulativeCost,
    inputTokens: cumulativeInputTokens,
    outputTokens: cumulativeOutputTokens,
    durationMs: Date.now() - start,
    attempts: MAX_GENERATION_ATTEMPTS,
  };
}

export async function runVariant(opts: RunVariantOptions): Promise<VariantRunReport> {
  const startedAt = new Date();
  const candidates = opts.candidates ?? CANDIDATES;
  const githubToken = opts.githubToken ?? process.env.GITHUB_TOKEN ?? process.env.GITHUB_PAT;

  // Pre-fetch OSV + patch (cached on disk, sequential to avoid GitHub burst).
  process.stderr.write(`[${opts.variant.NAME}] Pre-fetching ${candidates.length} CVE(s)…\n`);
  const fetched: CachedCveData[] = [];
  for (const c of candidates) {
    fetched.push(await fetchAndCache(c, githubToken));
  }

  // Few-shot examples per ecosystem. Sourced from the hand-ported
  // FrameworkSpec library (`few-shot-examples.ts`) — same selection logic
  // production uses via `generateRuleForCve` so the iteration harness's
  // recall reflects what production sees on the corpus. (Phase 5's
  // legacy `reachability-rules/` Semgrep YAML loader has been retired
  // here; that directory doesn't exist in the depscanner tree any more
  // and silently returned [] before this fix, making every iterate run
  // execute with zero few-shots in the prompt.)
  const fewShotCount = opts.fewShotCount ?? 3;
  function fewShotsFor(eco: string, excludeCveId: string): FrameworkSpecFewShot[] {
    return selectFrameworkSpecFewShots(eco, fewShotCount + 1)
      .filter((ex) => ex.cveId !== excludeCveId)
      .slice(0, fewShotCount);
  }

  if (opts.dryRun) {
    const perCve: PerCveResult[] = fetched.map((f, i) => ({
      cveId: candidates[i].cveId,
      packagePurl: candidates[i].packagePurl,
      status: 'dry_run',
      errors: f.error ? [f.error] : [],
      costUsd: 0,
      inputTokens: 0,
      outputTokens: 0,
      durationMs: 0,
    }));
    return finalizeReport(opts, startedAt, perCve);
  }

  const limit = pLimit(opts.concurrency);
  const perCve = await Promise.all(
    fetched.map((cached, i) =>
      limit(async () => {
        const candidate = candidates[i];
        const fewShots = fewShotsFor(candidate.ecosystem, candidate.cveId);
        const result = await runOne({
          variant: opts.variant,
          cached,
          candidate,
          provider: opts.provider,
          model: opts.model,
          apiKey: opts.apiKey,
          baseUrl: opts.baseUrl,
          fewShotExamples: fewShots,
          perCveTimeoutMs: opts.perCveTimeoutMs ?? 360_000,
          maxOutputTokens: opts.maxOutputTokens,
          seed: opts.seed,
          temperature: opts.temperature,
        });
        const tag = result.status === 'validated' ? 'PASS' : 'fail';
        process.stderr.write(`[${opts.variant.NAME}] ${candidate.cveId} ${tag} (${result.status}) ${result.durationMs}ms $${result.costUsd.toFixed(4)}\n`);
        return result;
      }),
    ),
  );

  return finalizeReport(opts, startedAt, perCve);
}

function finalizeReport(opts: RunVariantOptions, startedAt: Date, perCve: PerCveResult[]): VariantRunReport {
  const finishedAt = new Date();
  const byStatus: Record<string, number> = {};
  for (const r of perCve) byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;

  let schemaPass = 0, fixturePre = 0, fixtureSafe = 0, patchPostClean = 0, finalPass = 0;
  let totalCost = 0;
  for (const r of perCve) {
    totalCost += r.costUsd;
    const vb = r.validationLog?.validation_breakdown;
    if (!vb) continue;
    if (vb.schema_pass) schemaPass++;
    if (vb.fixture_pre_match) fixturePre++;
    if (vb.fixture_safe_clean) fixtureSafe++;
    if (vb.patch_post_clean === true) patchPostClean++;
    if (r.status === 'validated') finalPass++;
  }

  const report: VariantRunReport = {
    variant: { name: opts.variant.NAME, version: opts.variant.VERSION },
    provider: opts.provider,
    model: opts.model,
    baseUrl: opts.baseUrl,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    totalDurationMs: finishedAt.getTime() - startedAt.getTime(),
    candidates: perCve.length,
    validated: finalPass,
    byStatus,
    funnel: { schemaPass, fixturePre, fixtureSafe, patchPostClean, final: finalPass },
    totalCostUsd: totalCost,
    perCve,
  };

  if (!fs.existsSync(opts.outputDir)) fs.mkdirSync(opts.outputDir, { recursive: true });
  fs.writeFileSync(path.join(opts.outputDir, 'report.json'), JSON.stringify(report, null, 2), 'utf8');
  fs.writeFileSync(path.join(opts.outputDir, 'summary.txt'), formatSummary(report), 'utf8');
  return report;
}

// ---------------------------------------------------------------------------
// Multi-trial support (Phase 1.1).
//
// Single-trial measurements have a ~3pp stddev floor on DeepInfra Qwen3-235B
// even at temp=0+seed, swamping engine/spec/prompt changes smaller than ~6pp.
// `runMultiTrial` runs each CVE N times, parallelizes the full (CVE × trial)
// product through the same pLimit gate, and aggregates per-CVE to majority /
// union / intersection. Per-trial seed is `seed + trialIndex` so the sequence
// is reproducible across runs.
// ---------------------------------------------------------------------------

export interface PerCveMultiTrialResult {
  cveId: string;
  packagePurl: string;
  trials: PerCveResult[];
  /** Status that appears in ≥ ⌈N/2⌉ trials. Ties broken by trial[0]. */
  majorityStatus: PerCveResult['status'];
  /** ≥1 trial validated. */
  unionPass: boolean;
  /** All N trials validated. */
  intersectionPass: boolean;
  /** ≥ ⌈N/2⌉ trials validated. */
  majorityPass: boolean;
  totalCostUsd: number;
  totalDurationMs: number;
}

export interface MultiTrialReport {
  variant: { name: string; version: string };
  provider: AiProviderName;
  model: string;
  baseUrl?: string;
  trials: number;
  startedAt: string;
  finishedAt: string;
  totalDurationMs: number;
  candidates: number;
  /** Per-trial validated counts. Useful for stddev / range inspection. */
  perTrialValidated: number[];
  perTrialFunnels: VariantRunReport['funnel'][];
  /** Mean of perTrialValidated. */
  singleTrialMean: number;
  /** Population stddev across trials (N=trials). */
  singleTrialStddev: number;
  aggregate: {
    union: number;
    intersection: number;
    majority: number;
  };
  totalCostUsd: number;
  perCve: PerCveMultiTrialResult[];
}

function aggregateCve(cveId: string, packagePurl: string, trials: PerCveResult[]): PerCveMultiTrialResult {
  const N = trials.length;
  const validatedCount = trials.filter((t) => t.status === 'validated').length;
  const majorityThreshold = Math.ceil(N / 2);

  const statusCounts: Record<string, number> = {};
  for (const t of trials) statusCounts[t.status] = (statusCounts[t.status] ?? 0) + 1;
  let majorityStatus: PerCveResult['status'] = trials[0].status;
  let maxCount = 0;
  for (const [s, c] of Object.entries(statusCounts)) {
    if (c > maxCount) {
      maxCount = c;
      majorityStatus = s as PerCveResult['status'];
    }
  }

  return {
    cveId,
    packagePurl,
    trials,
    majorityStatus,
    unionPass: validatedCount >= 1,
    intersectionPass: validatedCount === N,
    majorityPass: validatedCount >= majorityThreshold,
    totalCostUsd: trials.reduce((sum, t) => sum + t.costUsd, 0),
    totalDurationMs: trials.reduce((sum, t) => sum + t.durationMs, 0),
  };
}

function computeStddev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const sqDiffs = values.map((v) => (v - mean) ** 2);
  return Math.sqrt(sqDiffs.reduce((a, b) => a + b, 0) / values.length);
}

function emptyFunnel(): VariantRunReport['funnel'] {
  return { schemaPass: 0, fixturePre: 0, fixtureSafe: 0, patchPostClean: 0, final: 0 };
}

function tallyFunnel(perCve: PerCveResult[]): VariantRunReport['funnel'] {
  const f = emptyFunnel();
  for (const r of perCve) {
    const vb = r.validationLog?.validation_breakdown;
    if (!vb) continue;
    if (vb.schema_pass) f.schemaPass++;
    if (vb.fixture_pre_match) f.fixturePre++;
    if (vb.fixture_safe_clean) f.fixtureSafe++;
    if (vb.patch_post_clean === true) f.patchPostClean++;
    if (r.status === 'validated') f.final++;
  }
  return f;
}

export async function runMultiTrial(opts: RunVariantOptions & { trials: number }): Promise<MultiTrialReport> {
  if (opts.trials < 1) throw new Error(`trials must be >= 1, got ${opts.trials}`);
  const startedAt = new Date();
  const candidates = opts.candidates ?? CANDIDATES;
  const githubToken = opts.githubToken ?? process.env.GITHUB_TOKEN ?? process.env.GITHUB_PAT;

  process.stderr.write(`[${opts.variant.NAME}] multi-trial: ${opts.trials} trial(s) × ${candidates.length} CVE(s) = ${opts.trials * candidates.length} AI calls. Pre-fetching…\n`);
  const fetched: CachedCveData[] = [];
  for (const c of candidates) {
    fetched.push(await fetchAndCache(c, githubToken));
  }

  const fewShotCount = opts.fewShotCount ?? 3;
  function fewShotsFor(eco: string, excludeCveId: string): FrameworkSpecFewShot[] {
    return selectFrameworkSpecFewShots(eco, fewShotCount + 1)
      .filter((ex) => ex.cveId !== excludeCveId)
      .slice(0, fewShotCount);
  }

  // Dispatch all (CVE × trial) tuples through one shared pLimit gate so
  // concurrency caps apply uniformly. Each trial owns a distinct effective
  // seed (`seed + trialIndex`) so trial 0 reproduces the single-trial baseline
  // and trials >0 add independent samples.
  const limit = pLimit(opts.concurrency);
  const trialResults: PerCveResult[][] = Array.from({ length: opts.trials }, () => []);

  // Initialise indexed slots so out-of-order completion still lines up.
  for (let t = 0; t < opts.trials; t++) {
    trialResults[t] = new Array(candidates.length);
  }

  const tasks: Promise<void>[] = [];
  for (let t = 0; t < opts.trials; t++) {
    const trialIndex = t;
    const effectiveSeed = opts.seed != null ? opts.seed + trialIndex : undefined;
    for (let i = 0; i < candidates.length; i++) {
      const candIndex = i;
      const cached = fetched[candIndex];
      const candidate = candidates[candIndex];
      tasks.push(
        limit(async () => {
          const fewShots = fewShotsFor(candidate.ecosystem, candidate.cveId);
          const result = await runOne({
            variant: opts.variant,
            cached,
            candidate,
            provider: opts.provider,
            model: opts.model,
            apiKey: opts.apiKey,
            baseUrl: opts.baseUrl,
            fewShotExamples: fewShots,
            perCveTimeoutMs: opts.perCveTimeoutMs ?? 360_000,
            maxOutputTokens: opts.maxOutputTokens,
            seed: effectiveSeed,
            temperature: opts.temperature,
          });
          trialResults[trialIndex][candIndex] = result;
          const tag = result.status === 'validated' ? 'PASS' : 'fail';
          process.stderr.write(`[${opts.variant.NAME}] t${trialIndex} ${candidate.cveId} ${tag} (${result.status}) ${result.durationMs}ms $${result.costUsd.toFixed(4)}\n`);
        }),
      );
    }
  }
  await Promise.all(tasks);

  // Aggregate per-CVE across trials.
  const perCve: PerCveMultiTrialResult[] = candidates.map((c, i) =>
    aggregateCve(c.cveId, c.packagePurl, trialResults.map((trial) => trial[i])),
  );

  const perTrialValidated = trialResults.map((trial) => trial.filter((r) => r.status === 'validated').length);
  const perTrialFunnels = trialResults.map(tallyFunnel);
  const totalCostUsd = trialResults.reduce((sum, trial) => sum + trial.reduce((s, r) => s + r.costUsd, 0), 0);
  const singleTrialMean = perTrialValidated.reduce((a, b) => a + b, 0) / perTrialValidated.length;
  const singleTrialStddev = computeStddev(perTrialValidated);

  const aggregate = {
    union: perCve.filter((c) => c.unionPass).length,
    intersection: perCve.filter((c) => c.intersectionPass).length,
    majority: perCve.filter((c) => c.majorityPass).length,
  };

  const finishedAt = new Date();
  const report: MultiTrialReport = {
    variant: { name: opts.variant.NAME, version: opts.variant.VERSION },
    provider: opts.provider,
    model: opts.model,
    baseUrl: opts.baseUrl,
    trials: opts.trials,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    totalDurationMs: finishedAt.getTime() - startedAt.getTime(),
    candidates: candidates.length,
    perTrialValidated,
    perTrialFunnels,
    singleTrialMean,
    singleTrialStddev,
    aggregate,
    totalCostUsd,
    perCve,
  };

  if (!fs.existsSync(opts.outputDir)) fs.mkdirSync(opts.outputDir, { recursive: true });
  fs.writeFileSync(path.join(opts.outputDir, 'multi-trial.json'), JSON.stringify(report, null, 2), 'utf8');
  fs.writeFileSync(path.join(opts.outputDir, 'multi-trial-summary.txt'), formatMultiTrialSummary(report), 'utf8');

  // Also write each trial's individual report.json so per-trial inspection
  // tools (frameworkSpec dumps, status breakdowns) keep working unchanged.
  for (let t = 0; t < opts.trials; t++) {
    const trialReport = finalizeTrialReport(opts, startedAt, trialResults[t], t);
    const trialDir = path.join(opts.outputDir, `trial-${t}`);
    if (!fs.existsSync(trialDir)) fs.mkdirSync(trialDir, { recursive: true });
    fs.writeFileSync(path.join(trialDir, 'report.json'), JSON.stringify(trialReport, null, 2), 'utf8');
    fs.writeFileSync(path.join(trialDir, 'summary.txt'), formatSummary(trialReport), 'utf8');
  }

  return report;
}

function finalizeTrialReport(opts: RunVariantOptions, startedAt: Date, perCve: PerCveResult[], trialIndex: number): VariantRunReport {
  const finishedAt = new Date();
  const byStatus: Record<string, number> = {};
  for (const r of perCve) byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
  const funnel = tallyFunnel(perCve);
  let totalCost = 0;
  for (const r of perCve) totalCost += r.costUsd;

  return {
    variant: { name: `${opts.variant.NAME}#t${trialIndex}`, version: opts.variant.VERSION },
    provider: opts.provider,
    model: opts.model,
    baseUrl: opts.baseUrl,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    totalDurationMs: finishedAt.getTime() - startedAt.getTime(),
    candidates: perCve.length,
    validated: funnel.final,
    byStatus,
    funnel,
    totalCostUsd: totalCost,
    perCve,
  };
}

export function formatMultiTrialSummary(r: MultiTrialReport): string {
  const lines: string[] = [];
  const N = r.candidates;
  const pct = (n: number) => N > 0 ? `${((n / N) * 100).toFixed(1)}%` : '0.0%';
  lines.push(`# ${r.variant.name} (${r.variant.version}) — ${r.provider}/${r.model}`);
  if (r.baseUrl) lines.push(`baseUrl: ${r.baseUrl}`);
  lines.push(`run: ${r.startedAt} → ${r.finishedAt}  (${(r.totalDurationMs / 1000).toFixed(1)}s)`);
  lines.push(`trials: ${r.trials} × ${N} CVEs = ${r.trials * N} AI calls`);
  lines.push(`Total cost: $${r.totalCostUsd.toFixed(4)}`);
  lines.push(``);
  lines.push(`Per-trial validated: [${r.perTrialValidated.join(', ')}] / ${N}`);
  lines.push(`Single-trial mean:   ${r.singleTrialMean.toFixed(2)}/${N} (${pct(r.singleTrialMean)})`);
  lines.push(`Single-trial stddev: ${r.singleTrialStddev.toFixed(2)}pp`);
  lines.push(``);
  lines.push(`Aggregate verdict:`);
  lines.push(`  union (≥1 trial):           ${r.aggregate.union}/${N} (${pct(r.aggregate.union)})  ← ceiling`);
  lines.push(`  majority (≥⌈N/2⌉ trials):   ${r.aggregate.majority}/${N} (${pct(r.aggregate.majority)})  ← stable signal`);
  lines.push(`  intersection (all trials):  ${r.aggregate.intersection}/${N} (${pct(r.aggregate.intersection)})  ← floor`);
  lines.push(``);
  lines.push(`Per-trial funnels:`);
  for (let t = 0; t < r.perTrialFunnels.length; t++) {
    const f = r.perTrialFunnels[t];
    lines.push(`  trial ${t}: schema ${f.schemaPass} → pre ${f.fixturePre} → safe ${f.fixtureSafe} → post ${f.patchPostClean} → final ${f.final}`);
  }
  lines.push(``);
  lines.push(`Per-CVE verdict (M=majority-pass, U=union-only, F=fail):`);
  for (const c of r.perCve) {
    const validated = c.trials.filter((t) => t.status === 'validated').length;
    const tag = c.majorityPass ? 'M' : c.unionPass ? 'U' : 'F';
    lines.push(`  ${tag} ${c.cveId.padEnd(22)} ${validated}/${r.trials} validated  status=${c.majorityStatus}`);
  }
  return lines.join('\n') + '\n';
}

export function formatSummary(r: VariantRunReport): string {
  const rate = r.candidates > 0 ? ((r.validated / r.candidates) * 100).toFixed(1) : '0.0';
  const lines: string[] = [];
  lines.push(`# ${r.variant.name} (${r.variant.version}) — ${r.provider}/${r.model}`);
  if (r.baseUrl) lines.push(`baseUrl: ${r.baseUrl}`);
  lines.push(`run: ${r.startedAt} → ${r.finishedAt}  (${(r.totalDurationMs / 1000).toFixed(1)}s)`);
  lines.push(``);
  lines.push(`Final validation rate: ${r.validated}/${r.candidates} = ${rate}%`);
  lines.push(`Total cost: $${r.totalCostUsd.toFixed(4)}`);
  lines.push(``);
  lines.push(`Funnel:`);
  lines.push(`  schema_pass:      ${r.funnel.schemaPass}/${r.candidates}`);
  lines.push(`  fixture_pre:      ${r.funnel.fixturePre}/${r.candidates}`);
  lines.push(`  fixture_safe:     ${r.funnel.fixtureSafe}/${r.candidates}`);
  lines.push(`  patch_post_clean: ${r.funnel.patchPostClean}/${r.candidates}`);
  lines.push(`  validated:        ${r.funnel.final}/${r.candidates}`);
  lines.push(``);
  lines.push(`Status breakdown:`);
  for (const [k, v] of Object.entries(r.byStatus).sort((a, b) => b[1] - a[1])) {
    lines.push(`  ${k}: ${v}`);
  }
  lines.push(``);
  lines.push(`Per-CVE:`);
  for (const c of r.perCve) {
    const tag = c.status === 'validated' ? '✓' : '✗';
    const err = (c.errors[0] ?? '').slice(0, 80);
    lines.push(`  ${tag} ${c.cveId.padEnd(18)} ${c.status.padEnd(20)} $${c.costUsd.toFixed(4)} ${err}`);
  }
  return lines.join('\n') + '\n';
}
