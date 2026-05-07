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
import { loadFewShotExamples, type FewShotExample } from '../../src/rule-generator/few-shot-loader';
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
  fewShotExamples: FewShotExample[];
  perCveTimeoutMs: number;
  maxOutputTokens?: number;
}): Promise<PerCveResult> {
  const { variant, cached, candidate, provider, model, apiKey, baseUrl, fewShotExamples, perCveTimeoutMs, maxOutputTokens } = args;
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

  // Few-shot examples per ecosystem (deterministic on the corpus).
  const platformRulesDir = opts.platformRulesDir ?? path.resolve(__dirname, '..', '..', 'reachability-rules');
  const fewShotCount = opts.fewShotCount ?? 3;
  function fewShotsFor(eco: string, excludeCveId: string): FewShotExample[] {
    return loadFewShotExamples(platformRulesDir, eco, fewShotCount + 1)
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
