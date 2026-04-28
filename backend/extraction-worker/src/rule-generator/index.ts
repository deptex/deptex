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
import { validateRule, makeRuleGenWorkdir, type ValidationLog } from './validate';
import { loadFewShotExamples } from './few-shot-loader';

export type { GeneratedPayload, AiProviderName };
export type { ValidationLog };

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
}

const DEFAULT_RESULT_BASE = (args: GenerateRuleForCveArgs): Omit<GenerationResult, 'status' | 'errors'> => ({
  cveId: args.cveId,
  packagePurl: args.packagePurl,
  ecosystem: args.ecosystem,
  generatedWith: { provider: args.provider, model: args.model },
  costUsd: 0,
  inputTokens: 0,
  outputTokens: 0,
  promptVersion: getPromptVersion(),
});

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

    // --- 4. Call provider + Zod validate ---
    let providerResult;
    try {
      providerResult = await callProviderAndParse({
        prompt,
        provider: args.provider,
        model: args.model,
        apiKey: args.apiKey,
        signal: args.signal,
        maxOutputTokens: args.maxOutputTokens,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`generate: ${msg}`);
      let status: GenerationStatus = 'provider_error';
      if (err instanceof GenerationError) {
        if (err.code === 'parse_failed') status = 'parse_failed';
        else if (err.code === 'invalid_schema') status = 'invalid_schema';
      }
      return {
        ...DEFAULT_RESULT_BASE(args),
        status,
        affectedVersionRange: affectedRange,
        errors,
      };
    }

    // --- 5. Validate (fixtures + optional diff-targeted patch round-trip) ---
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

    return {
      ...DEFAULT_RESULT_BASE(args),
      status: validation.status,
      affectedVersionRange: affectedRange,
      rule: providerResult.payload,
      validationLog: validation.log,
      costUsd: providerResult.estimatedCostUsd,
      inputTokens: providerResult.inputTokens,
      outputTokens: providerResult.outputTokens,
      errors: validation.log.errors,
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
