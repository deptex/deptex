/**
 * Public entry: generate one Semgrep reachability rule for a CVE/package
 * pair using the org's chosen AI provider, validate it against fixtures and
 * (when possible) the upstream patch, and return a structured GenerationResult
 * the pipeline can persist into organization_generated_rules.
 *
 * Pure function — never writes to the database. The pipeline (M3) wraps this
 * with concurrency-limited Promise.all + per-CVE timeouts and persists results.
 *
 * Single-CVE failure modes are encoded in `GenerationResult.status` so callers
 * can decide whether to skip, log warn, or surface to the user. We never
 * throw out of generateRuleForCve — a thrown error means a programmer bug,
 * not a generation failure.
 */

import { fetchOsvAdvisory, extractFixCommits, summarizeAffectedRange, OsvFetchError } from './osv-fetch';
import { fetchPatchInfo, PatchFetchError } from './patch-fetch';
import { buildGenerationPrompt, getPromptVersion } from './prompt-builder';
import { callProviderAndParse, GenerationError, type GeneratedPayload, type AiProviderName } from './generate';
import { validateRule, makeRuleGenWorkdir, type ValidationLog, type ValidationBreakdown } from './validate';
import { loadFewShotExamples } from './few-shot-loader';

export type { GeneratedPayload, AiProviderName };
export type { ValidationLog, ValidationBreakdown };

export type GenerationStatus =
  | 'validated'
  | 'failed_validation'
  | 'no_advisory'
  | 'no_fix_commit'
  | 'fetch_failed'
  | 'parse_failed'
  | 'invalid_schema'
  | 'provider_error'
  | 'unexpected';

export interface GenerateRuleForCveArgs {
  cveId: string;
  packagePurl: string;
  packageName: string;
  ecosystem: string;
  organizationId: string;
  provider: AiProviderName;
  model: string;
  apiKey: string;
  signal?: AbortSignal;
  semgrepBin?: string;
  /** GitHub PAT or installation token, used to lift OSS rate limits when
   *  fetching commit metadata + diffs. Optional; falls back to anonymous. */
  githubToken?: string;
  /** Cap on output tokens — passed through to the provider. */
  maxOutputTokens?: number;
  /** Disable the heavier patch round-trip validation. Default: enabled. */
  runPatchValidation?: boolean;
  /** Override the working directory for clones + temp files. Default:
   *  fresh os.tmpdir() subdir. */
  workDir?: string;
  /** Path to the platform reachability-rules directory. When provided, the
   *  prompt is augmented with up to 3 hand-authored rules from this corpus
   *  matched on ecosystem (falls back to other ecosystems). Omit to skip the
   *  few-shot section. */
  platformRulesDir?: string;
  /** Override how many few-shot examples to inline. Default: 3. */
  fewShotCount?: number;
  /** OpenAI-compatible endpoint override. When provider='openai' and this is
   *  set, requests go to this URL — DeepInfra, OpenRouter, Alibaba, or any
   *  other drop-in OpenAI-compat host. Ignored for anthropic/google. */
  baseUrl?: string;
}

export interface GenerationResult {
  status: GenerationStatus;
  cveId: string;
  packagePurl: string;
  ecosystem: string;
  affectedVersionRange?: string;
  rule?: GeneratedPayload;
  validationLog?: ValidationLog;
  generatedWith: { provider: AiProviderName; model: string };
  costUsd: number;
  inputTokens: number;
  outputTokens: number;
  errors: string[];
  promptVersion: string;
  /** Per-CVE pass/fail at each validation gate. Populated for every result —
   *  for pre-schema bails (no_advisory / fetch_failed / no_fix_commit) all
   *  fields are false / null. Aggregated by rule-generation-step. */
  validationBreakdown: ValidationBreakdown;
  /** How many provider calls were made for this CVE. 1 on first-pass success,
   *  2 when the schema-fail retry loop fired. 0 for pre-attempt bails. Cost
   *  and token fields above are cumulative across all attempts. */
  attempts: number;
}

/** Breakdown for results that bailed before the AI call ever ran (no_advisory,
 *  fetch_failed, no_fix_commit). Schema can't have passed because we never
 *  asked the model. */
const PRE_ATTEMPT_BREAKDOWN: ValidationBreakdown = {
  schema_pass: false,
  fixture_pre_match: false,
  fixture_safe_clean: false,
  patch_pre_match: null,
  patch_post_clean: null,
  semgrep_parse_error: null,
};

const DEFAULT_RESULT_BASE = (args: GenerateRuleForCveArgs): Omit<GenerationResult, 'status' | 'errors'> => ({
  cveId: args.cveId,
  packagePurl: args.packagePurl,
  ecosystem: args.ecosystem,
  generatedWith: { provider: args.provider, model: args.model },
  costUsd: 0,
  inputTokens: 0,
  outputTokens: 0,
  promptVersion: getPromptVersion(),
  validationBreakdown: PRE_ATTEMPT_BREAKDOWN,
  attempts: 0,
});

/**
 * Cap on AI calls per CVE — first attempt + at most one retry. Two attempts
 * is the autogrep-paper sweet spot: lifts validation rate ~+10pp while only
 * costing ~1.15× tokens (retry only fires on the ~30% failure tail).
 *
 * Retry triggers: callProviderAndParse throws parse_failed/invalid_schema OR
 * validateRule emits a semgrep_parse_error. Fixture-round-trip failures
 * aren't retried — a single re-prompt rarely fixes "rule too narrow" /
 * "rule matches too broadly" without the agentic loop (Phase 5g territory).
 *
 * Exported so the iteration harness (test/iterate/runner.ts) can mirror the
 * same retry behaviour — otherwise harness numbers underreport production.
 */
export const MAX_GENERATION_ATTEMPTS = 2;

export function buildRevisionPrompt(originalPrompt: string, feedback: string): string {
  return [
    'Your previous attempt was rejected by automated validation. Read the error',
    'feedback below, fix the issue, and emit a fresh JSON object using the same',
    'schema as before. Do not apologize or explain — output ONLY the corrected',
    'JSON.',
    '',
    'Error feedback:',
    feedback,
    '',
    '---',
    '',
    originalPrompt,
  ].join('\n');
}

export async function generateRuleForCve(args: GenerateRuleForCveArgs): Promise<GenerationResult> {
  const errors: string[] = [];
  const ownsWorkdir = !args.workDir;
  const workDir = args.workDir ?? makeRuleGenWorkdir();

  try {
    // --- 1. Fetch OSV advisory ---
    let advisory: Awaited<ReturnType<typeof fetchOsvAdvisory>> = null;
    try {
      advisory = await fetchOsvAdvisory(args.cveId, args.signal);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`osv_fetch: ${msg}`);
      return {
        ...DEFAULT_RESULT_BASE(args),
        status: err instanceof OsvFetchError && err.code === 'not_found' ? 'no_advisory' : 'fetch_failed',
        errors,
      };
    }
    if (!advisory) {
      return { ...DEFAULT_RESULT_BASE(args), status: 'no_advisory', errors: ['osv_fetch: advisory not found'] };
    }

    const affectedRange = summarizeAffectedRange(advisory, args.packageName);
    const fixCommits = extractFixCommits(advisory);
    const fixCommit = fixCommits[0];
    if (!fixCommit) {
      return {
        ...DEFAULT_RESULT_BASE(args),
        status: 'no_fix_commit',
        affectedVersionRange: affectedRange,
        errors: ['osv_fetch: advisory has no GitHub fix-commit reference'],
      };
    }

    // --- 2. Fetch unified diff + per-file blobs ---
    let patchInfo;
    try {
      patchInfo = await fetchPatchInfo(fixCommit, { signal: args.signal, githubToken: args.githubToken });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`patch_fetch: ${msg}`);
      return {
        ...DEFAULT_RESULT_BASE(args),
        status: err instanceof PatchFetchError && err.code === 'not_found' ? 'no_fix_commit' : 'fetch_failed',
        affectedVersionRange: affectedRange,
        errors,
      };
    }

    // --- 3. Build prompt ---
    const fewShotK = args.fewShotCount ?? 3;
    // Request K+1 so we can drop the target CVE's own example (if it's in the
    // corpus) without dropping below the budget. rule-generation-step.ts
    // already filters out already-covered CVEs upstream so this should be
    // rare, but the leak guard is cheap.
    const fewShotExamples = args.platformRulesDir
      ? loadFewShotExamples(args.platformRulesDir, args.ecosystem, fewShotK + 1)
          .filter((ex) => ex.cveId !== args.cveId)
          .slice(0, fewShotK)
      : [];

    const prompt = buildGenerationPrompt({
      cveId: args.cveId,
      packagePurl: args.packagePurl,
      packageName: args.packageName,
      ecosystem: args.ecosystem,
      affectedVersionRange: affectedRange,
      osvSummary: advisory.summary,
      osvDetails: advisory.details,
      patchDiff: patchInfo.diff,
      changedFiles: patchInfo.changedFiles,
      fewShotExamples,
    });

    // --- 4 + 5. Call provider + validate, with a one-shot retry on schema /
    //            grammar-stage failures (parse_failed, invalid_schema, or a
    //            semgrep_parse_error from validateRule). ---
    let cumulativeCost = 0;
    let cumulativeInputTokens = 0;
    let cumulativeOutputTokens = 0;
    let revisionFeedback: string | null = null;

    for (let attempt = 1; attempt <= MAX_GENERATION_ATTEMPTS; attempt++) {
      const attemptPrompt = revisionFeedback
        ? buildRevisionPrompt(prompt, revisionFeedback)
        : prompt;

      let providerResult;
      try {
        providerResult = await callProviderAndParse({
          prompt: attemptPrompt,
          provider: args.provider,
          model: args.model,
          apiKey: args.apiKey,
          signal: args.signal,
          maxOutputTokens: args.maxOutputTokens,
          baseUrl: args.baseUrl,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        errors.push(`generate(attempt ${attempt}): ${msg}`);
        let status: GenerationStatus = 'provider_error';
        if (err instanceof GenerationError) {
          if (err.code === 'parse_failed') status = 'parse_failed';
          else if (err.code === 'invalid_schema') status = 'invalid_schema';
        }
        const retryable = status === 'parse_failed' || status === 'invalid_schema';
        if (retryable && attempt < MAX_GENERATION_ATTEMPTS) {
          revisionFeedback = msg;
          continue;
        }
        return {
          ...DEFAULT_RESULT_BASE(args),
          status,
          affectedVersionRange: affectedRange,
          costUsd: cumulativeCost,
          inputTokens: cumulativeInputTokens,
          outputTokens: cumulativeOutputTokens,
          errors,
          attempts: attempt,
        };
      }

      cumulativeCost += providerResult.estimatedCostUsd;
      cumulativeInputTokens += providerResult.inputTokens;
      cumulativeOutputTokens += providerResult.outputTokens;

      const validation = await validateRule({
        payload: providerResult.payload,
        cveId: args.cveId,
        ecosystem: args.ecosystem,
        changedFiles: patchInfo.changedFiles,
        workDir,
        signal: args.signal,
        semgrepBin: args.semgrepBin,
        runPatchValidation: args.runPatchValidation,
      });

      if (validation.status === 'validated') {
        return {
          ...DEFAULT_RESULT_BASE(args),
          status: 'validated',
          affectedVersionRange: affectedRange,
          rule: providerResult.payload,
          validationLog: validation.log,
          costUsd: cumulativeCost,
          inputTokens: cumulativeInputTokens,
          outputTokens: cumulativeOutputTokens,
          errors: validation.log.errors,
          validationBreakdown: validation.log.validation_breakdown,
          attempts: attempt,
        };
      }

      // Validation failed. Retry only if it's a Semgrep grammar/parse error —
      // those are recoverable with a re-prompt. Fixture-round-trip failures
      // (rule too narrow / matches safe fixture) need agentic iteration, not
      // a single re-prompt, so we let those propagate.
      const semgrepParseErr = validation.log.validation_breakdown.semgrep_parse_error;
      if (semgrepParseErr && attempt < MAX_GENERATION_ATTEMPTS) {
        revisionFeedback = `Your Semgrep rule failed to load: ${semgrepParseErr}`;
        continue;
      }

      return {
        ...DEFAULT_RESULT_BASE(args),
        status: 'failed_validation',
        affectedVersionRange: affectedRange,
        rule: providerResult.payload,
        validationLog: validation.log,
        costUsd: cumulativeCost,
        inputTokens: cumulativeInputTokens,
        outputTokens: cumulativeOutputTokens,
        errors: validation.log.errors,
        validationBreakdown: validation.log.validation_breakdown,
        attempts: attempt,
      };
    }

    // Loop exhausted without returning — shouldn't happen because every branch
    // in the loop returns, but TypeScript can't see that. Surface as a
    // programmer bug rather than silently dropping.
    return {
      ...DEFAULT_RESULT_BASE(args),
      status: 'unexpected',
      affectedVersionRange: affectedRange,
      costUsd: cumulativeCost,
      inputTokens: cumulativeInputTokens,
      outputTokens: cumulativeOutputTokens,
      errors: ['retry_loop_exhausted_without_return'],
      attempts: MAX_GENERATION_ATTEMPTS,
    };
  } catch (err) {
    // Programmer bug, not a generation failure — surface explicitly.
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ...DEFAULT_RESULT_BASE(args),
      status: 'unexpected',
      errors: [`unexpected: ${msg}`],
    };
  } finally {
    if (ownsWorkdir) {
      try {
        const fs = require('fs') as typeof import('fs');
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch { /* non-fatal */ }
    }
  }
}
