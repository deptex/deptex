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
 * Cap on AI calls per CVE. First attempt + up to N-1 retries. N=4 lets the
 * model see up to 3 distinct concrete failure cases — the autogrep paper's
 * agentic loop typically converges within 3-5 iterations.
 *
 * Retry triggers: any failed_validation result OR a parse_failed/invalid_schema
 * thrown by callProviderAndParse. Each retry includes the previous rule, both
 * fixtures, and the actual match counts, so the model can reason concretely
 * about why its rule was rejected. This is the Phase 5g extension of the
 * Phase 5f schema-only retry.
 *
 * Cost: retry only fires on the failure tail (~50% of CVEs after attempt 1
 * on Gemini Flash), so worst-case 18 CVEs × 4 attempts = 72 calls vs 18
 * single-shot — but in practice ~30 calls because validated CVEs short-circuit.
 * At Gemini Flash prices that's ~$0.50 per full corpus run.
 *
 * Exported so the iteration harness (test/iterate/runner.ts) can mirror the
 * same retry behaviour — otherwise harness numbers underreport production.
 */
export const MAX_GENERATION_ATTEMPTS = 4;

export function buildRevisionPrompt(originalPrompt: string, feedback: string): string {
  return [
    'Your previous attempt was rejected by automated validation. Read the',
    'concrete failure details below, identify what went wrong with your rule,',
    'and emit a fresh JSON object using the same schema as before. Do not',
    'apologize or explain — output ONLY the corrected JSON.',
    '',
    feedback,
    '',
    '--- ORIGINAL TASK BELOW (re-read for context) ---',
    '',
    originalPrompt,
  ].join('\n');
}

/**
 * Build rich diagnostic feedback for the model after a failed validation.
 * Includes the rule it emitted, both fixtures, the match counts, and a
 * targeted diagnosis ("rule too narrow", "matches safe fixture too", etc.).
 *
 * For pre-validation failures (parse_failed / invalid_schema) we don't have
 * a usable payload — fall back to the raw error string.
 */
export function buildAttemptFailureFeedback(args: {
  payload: GeneratedPayload | null;
  errorMessage: string;
  validation: { log: ValidationLog } | null;
}): string {
  if (!args.payload || !args.validation) {
    return [
      '-- Failure --',
      'Your previous response could not be parsed or did not match the required JSON schema.',
      '',
      `Error: ${args.errorMessage}`,
      '',
      'Re-emit a fresh JSON object using exactly the schema described in the original task. The schema requires fields: rule_yaml, vulnerable_fixture, safe_fixture, reachability_level, entry_point_class, rationale.',
    ].join('\n');
  }

  const log = args.validation.log;
  const vb = log.validation_breakdown;
  const lines: string[] = [];

  lines.push('-- Rule you emitted --');
  lines.push(args.payload.rule_yaml);
  lines.push('');
  lines.push('-- Vulnerable fixture (your rule SHOULD match this — at least 1 match required) --');
  lines.push(args.payload.vulnerable_fixture);
  lines.push('');
  lines.push('-- Safe fixture (your rule must NOT match this — 0 matches required) --');
  lines.push(args.payload.safe_fixture);
  lines.push('');
  lines.push('-- Actual match counts --');
  lines.push(`Vulnerable fixture matches: ${log.fixture_pre_matches} (need > 0)`);
  lines.push(`Safe fixture matches: ${log.fixture_post_matches} (need 0)`);
  if (log.patch_post_matches !== null) {
    lines.push(`Post-fix patched code matches: ${log.patch_post_matches} (need 0 — the fixed code must not match)`);
  }
  lines.push('');

  if (vb.semgrep_parse_error) {
    lines.push('-- Semgrep refused to load the rule --');
    lines.push(vb.semgrep_parse_error);
    lines.push('');
    lines.push('Diagnosis: rule grammar / schema is invalid. Common causes:');
    lines.push('- pattern-not given a list (it takes ONE pattern, not multiple)');
    lines.push('- focus-metavariable nested as sibling of pattern-either instead of inside the same patterns: block');
    lines.push('- referencing fields that do not exist (pattern-include, pattern-not-include, list-valued pattern-not-inside)');
    lines.push('- YAML scalar containing {}[]:,&*?!|> or "..." not single-quoted');
  } else if (log.fixture_pre_matches === 0 && log.fixture_post_matches === 0) {
    lines.push('Diagnosis: your rule is too NARROW — it matches neither fixture.');
    lines.push('Likely causes:');
    lines.push('- pattern is too specific (matches one exact form when the vuln has many)');
    lines.push('- wrong sink/source identifier name');
    lines.push('- the fixture you generated does not actually exercise the pattern');
    lines.push('Fix: broaden the pattern (use $X / $METHOD metavariables; make sure the vulnerable fixture clearly exercises the sink).');
  } else if (log.fixture_pre_matches > 0 && log.fixture_post_matches > 0) {
    lines.push('Diagnosis: your rule is too BROAD — it matches both the vulnerable AND the safe fixture.');
    lines.push('Fix: narrow the rule. Add a metavariable-pattern constraint that distinguishes vuln from safe (e.g. metavariable-pattern restricting $INPUT to a tainted source like req.body), or add pattern-not to exclude the safe form.');
  } else if (log.fixture_pre_matches === 0 && log.fixture_post_matches > 0) {
    lines.push('Diagnosis: your rule matches the SAFE fixture but not the VULNERABLE one. The pattern direction is inverted.');
    lines.push('Fix: re-read the vulnerability description. Ensure your pattern targets the unsafe form (the one in vulnerable_fixture).');
  } else if (log.patch_post_matches !== null && log.patch_post_matches > 0) {
    lines.push('Diagnosis: rule fires on the post-fix patched code. Whatever the upstream maintainers added to fix the bug must NOT match your rule.');
    lines.push('Fix: tighten the pattern so it excludes the maintainers\' fix (often requires recognizing the added sanitizer or check).');
  } else {
    lines.push(`Diagnosis: validation failed — errors=${(log.errors ?? []).join(' | ').slice(0, 240)}`);
  }

  return lines.join('\n');
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
          revisionFeedback = buildAttemptFailureFeedback({
            payload: null,
            errorMessage: msg,
            validation: null,
          });
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

      // Validation failed. Retry on ANY validation failure with rich
      // diagnostic feedback (rule + fixtures + match counts). The model gets
      // to see exactly why its rule was rejected and adjust. Caps at
      // MAX_GENERATION_ATTEMPTS to bound cost.
      if (attempt < MAX_GENERATION_ATTEMPTS) {
        revisionFeedback = buildAttemptFailureFeedback({
          payload: providerResult.payload,
          errorMessage: validation.log.errors.join(' | '),
          validation,
        });
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
