/**
 * Per-extraction rule generation pipeline step.
 *
 * Sits between vuln_scan and reachability_rules in pipeline.ts. Given the
 * scan's vulnerabilities, the org's trigger policy, and a platform AI key
 * (read from the worker environment), this step:
 *
 *   1. Loads organization_reachability_settings; bails fast when generation
 *      is disabled or the row is missing.
 *   2. Filters vulnerabilities against the trigger policy + asset tier rank.
 *   3. Subtracts CVEs already covered by platform-shipped rules and the
 *      org's existing generated rules (any validation_status).
 *   4. Estimates total cost; halts or downgrades to haiku per the org's
 *      `on_budget_exhaustion` setting if the running monthly spend would
 *      exceed `monthly_budget_usd`.
 *   5. In-process Promise.all with p-limit(5), each generation wrapped in
 *      withTimeout(90s). Failures of one CVE never block the others —
 *      they log to extraction_step_errors at warn and continue.
 *   6. Upserts validated rules into organization_generated_rules so the
 *      downstream reachability_rules step picks them up via
 *      loadOrgGeneratedRules and Semgrep matches them in this same scan.
 *   7. Persists telemetry (rules_matched, total_detectable, generated this
 *      scan, total cost) to extraction_jobs.
 *
 * The step is intentionally non-fatal: any error short-circuits to a warn
 * log and the pipeline continues with whatever rules existed before.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import pLimit from 'p-limit';
import type { Storage } from './storage';
import { withTimeout, logStepError, classifyError, StepTimeoutError } from './with-timeout';
import {
  generateRuleForCve,
  type AiProviderName,
  type GenerationResult,
  type ValidationBreakdown,
} from './rule-generator';
import {
  withOsvIdsSubstituted,
  FRAMEWORK_SPEC_PROMPT_VERSION,
} from './rule-generator/framework-spec-schema';

const STEP_NAME = 'rule_generation';
// Bumped from 90s to accommodate up to 4 in-provider rate-limit retries
// (each with up to 60s backoff) without timing out on a CVE that's only
// stuck because of a transient 429.
const PER_CVE_TIMEOUT_MS = 240_000;
// Per-provider concurrency. Anthropic dev/free orgs cap at 30K input tokens/min;
// with ~10K-token prompts even concurrency=3 saturates and the rest queue
// on 429s for the full minute window. Drop Anthropic to 1 (the retry-with-
// backoff in generate.ts smooths over the residual bursts). DeepInfra
// serverless on big models (Qwen3-235B / DeepSeek V3.1) returns "Model busy"
// when burst-loaded, so cap openai-compat at 2. Gemini handles bursts well.
const PROVIDER_CONCURRENCY_BY_NAME: Record<AiProviderName, number> = {
  anthropic: 1,
  openai: 2,
  google: 3,
};
function concurrencyFor(provider: AiProviderName): number {
  return PROVIDER_CONCURRENCY_BY_NAME[provider] ?? 2;
}
const FALLBACK_MODELS: Record<AiProviderName, string> = {
  anthropic: 'claude-haiku-4-5-20251001',
  openai: 'gpt-4o-mini',
  google: 'gemini-2.0-flash',
};

interface LogLike {
  info(step: string, msg: string, metadata?: Record<string, unknown>): Promise<void>;
  success(step: string, msg: string, durationMs?: number, metadata?: Record<string, unknown>): Promise<void>;
  warn(step: string, msg: string, metadata?: Record<string, unknown>): Promise<void>;
  error(step: string, msg: string, metadata?: Record<string, unknown>): Promise<void>;
}

interface OrgReachabilitySettings {
  organization_id: string;
  auto_generate_enabled: boolean;
  trigger_severities: string[];
  trigger_kev: boolean;
  trigger_asset_tier_max_rank: number;
  trigger_newly_discovered: boolean;
  trigger_reevaluate_existing: boolean;
  ai_provider: AiProviderName;
  ai_model: string;
  monthly_budget_usd: number;
  on_budget_exhaustion: 'skip' | 'fall_back_to_haiku';
  max_wait_seconds: number;
}

export interface RunRuleGenerationArgs {
  organizationId: string;
  projectId: string;
  runId: string;
  jobId: string | undefined;
  supabase: Storage;
  log: LogLike;
  signal?: AbortSignal;
  /** Override the platform-key resolver — exposed for tests. Production
   *  path reads from the worker environment (OPENAI_API_KEY /
   *  ANTHROPIC_API_KEY / GOOGLE_AI_API_KEY). */
  resolveApiKey?: (orgId: string, provider: AiProviderName) => Promise<string | null>;
}

export interface RunRuleGenerationResult {
  /** Whether generation actually ran (false = disabled / no settings / skipped). */
  ran: boolean;
  /** CVEs in scope of the trigger policy. */
  triggerMatched: number;
  /** CVEs already covered by an existing rule. */
  alreadyCovered: number;
  /** CVEs we attempted to generate. */
  attempted: number;
  /** CVEs that came back validated. */
  generated: number;
  /** Total estimated AI spend for this run. */
  costUsd: number;
  /** Aggregated reasons each candidate skipped (for the success line). */
  skipReasons: Record<string, number>;
}

/**
 * Lightweight shape passed in from pipeline.ts — only the fields the
 * trigger filter consumes. Avoids us importing pipeline's larger PdvRow.
 */
export interface PipelineVulnRow {
  osv_id: string | null;
  aliases: string[] | null;
  severity: string | null;
  cisa_kev: boolean | null;
  reachability_level: string | null;
  ecosystem: string | null;
  package_purl: string | null;
  package_name: string | null;
}

const ZERO_RESULT: RunRuleGenerationResult = {
  ran: false,
  triggerMatched: 0,
  alreadyCovered: 0,
  attempted: 0,
  generated: 0,
  costUsd: 0,
  skipReasons: {},
};

export async function runRuleGenerationStep(
  args: RunRuleGenerationArgs,
  pipelineVulns: PipelineVulnRow[],
): Promise<RunRuleGenerationResult> {
  const { organizationId, projectId, runId, jobId, supabase, log, signal } = args;
  const stepStart = Date.now();

  // --- 1. Load org settings ---
  let settings: OrgReachabilitySettings | null = null;
  try {
    const { data, error } = await supabase
      .from('organization_reachability_settings')
      .select('*')
      .eq('organization_id', organizationId)
      .maybeSingle();
    if (error) throw new Error(error.message);
    settings = data as OrgReachabilitySettings | null;
  } catch (err) {
    await log.warn(STEP_NAME, `Failed to load reachability settings: ${err instanceof Error ? err.message : String(err)}`);
    return ZERO_RESULT;
  }

  if (!settings || !settings.auto_generate_enabled) {
    return ZERO_RESULT;
  }

  // --- 2. Resolve provider asset tier rank for each project's vulns ---
  const assetTierRank = await fetchAssetTierRank(projectId, supabase);

  // --- 3. Apply trigger policy ---
  const triggerMatchedVulns: PipelineVulnRow[] = [];
  const skipReasons: Record<string, number> = {};
  const bumpReason = (reason: string) => {
    skipReasons[reason] = (skipReasons[reason] ?? 0) + 1;
  };

  for (const v of pipelineVulns) {
    if (!v.osv_id || !isCveLike(v.osv_id, v.aliases)) {
      bumpReason('not_cve_id');
      continue;
    }
    if (!v.severity || !settings.trigger_severities.includes(v.severity.toLowerCase())) {
      bumpReason('severity_filter');
      continue;
    }
    if (settings.trigger_kev && v.cisa_kev !== true) {
      bumpReason('not_kev');
      continue;
    }
    if (assetTierRank !== null && assetTierRank > settings.trigger_asset_tier_max_rank) {
      bumpReason('asset_tier_filter');
      continue;
    }
    if (!v.package_name || !v.package_purl || !v.ecosystem) {
      bumpReason('missing_purl_or_ecosystem');
      continue;
    }
    triggerMatchedVulns.push(v);
  }

  if (triggerMatchedVulns.length === 0) {
    await log.info(
      STEP_NAME,
      `No vulnerabilities match trigger policy; skipping generation`,
      { skip_reasons: skipReasons },
    );
    return { ...ZERO_RESULT, ran: true, skipReasons };
  }

  // --- 4. Subtract CVEs already covered (org-existing only) ---
  // Phase 6.5 / M5 — platform-shipped Semgrep rule packs were retired with
  // the `reachability_rules` step. The new generator path emits FrameworkSpec
  // (not Semgrep YAML), so the legacy "skip if a platform rule exists" guard
  // would never have suppressed a generation attempt regardless. Any CVE the
  // org has already validated stays in the skip set.
  const orgExistingCves = await loadOrgExistingRuleCves(organizationId, supabase);
  if (orgExistingCves === null) {
    // Fail-closed: a Supabase read failure here would have us treat every CVE
    // as uncovered and regenerate everything — runaway platform AI spend on a
    // transient outage. Skip the entire step and let the next scan retry.
    await log.warn(
      STEP_NAME,
      'Skipping rule generation: organization_generated_rules read failed; cannot determine existing coverage. Generation will resume when Supabase recovers.',
    );
    if (jobId) {
      await logStepError(supabase, {
        jobId,
        projectId,
        step: STEP_NAME,
        code: 'org_rules_read_failed',
        message: `Failed to read existing rules for organization ${organizationId}; skipping generation to avoid regenerating already-covered CVEs.`,
        severity: 'warn',
      });
    }
    bumpReason('org_rules_read_failed');
    return { ...ZERO_RESULT, ran: true, triggerMatched: triggerMatchedVulns.length, skipReasons };
  }
  const coveredCves = new Set([...orgExistingCves]);

  const candidates: PipelineVulnRow[] = [];
  let alreadyCovered = 0;
  for (const v of triggerMatchedVulns) {
    const cveId = canonicalCveId(v.osv_id!, v.aliases);
    if (cveId && coveredCves.has(cveId)) {
      alreadyCovered++;
      bumpReason('already_covered');
      continue;
    }
    if (cveId) candidates.push({ ...v, osv_id: cveId });
  }

  if (candidates.length === 0) {
    await log.info(
      STEP_NAME,
      `${alreadyCovered}/${triggerMatchedVulns.length} candidate(s) already covered by existing rules; nothing to generate`,
      { trigger_matched: triggerMatchedVulns.length, already_covered: alreadyCovered },
    );
    return { ...ZERO_RESULT, ran: true, triggerMatched: triggerMatchedVulns.length, alreadyCovered, skipReasons };
  }

  // --- 5. Resolve platform AI key for the chosen provider ---
  // After phase29_drop_byok the only key source is the worker's environment
  // (OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_AI_API_KEY). The test
  // override (args.resolveApiKey) lets tests inject a key without setting
  // env vars.
  const apiKey = args.resolveApiKey
    ? await args.resolveApiKey(organizationId, settings.ai_provider)
    : await defaultResolveApiKey(settings.ai_provider);
  if (!apiKey) {
    await log.warn(
      STEP_NAME,
      `No platform API key for ${settings.ai_provider}; skipping generation. Set ${envVarFor(settings.ai_provider)} on the worker.`,
    );
    if (jobId) {
      await logStepError(supabase, {
        jobId,
        projectId,
        step: STEP_NAME,
        code: 'platform_key_missing',
        message: `No ${settings.ai_provider} platform API key configured for organization ${organizationId}`,
        severity: 'warn',
      });
    }
    return { ...ZERO_RESULT, ran: true, triggerMatched: triggerMatchedVulns.length, alreadyCovered, skipReasons };
  }

  // --- 6. Budget cap (estimate vs cumulative monthly spend) ---
  const { effectiveModel, budgetSkipped } = await applyBudgetCap({
    settings,
    organizationId,
    candidateCount: candidates.length,
    supabase,
    log,
  });
  if (budgetSkipped) {
    return { ...ZERO_RESULT, ran: true, triggerMatched: triggerMatchedVulns.length, alreadyCovered, skipReasons };
  }

  // --- 7. Run generation with p-limit + per-CVE timeout ---
  const providerConcurrency = concurrencyFor(settings.ai_provider);
  await log.info(
    STEP_NAME,
    `Generating ${candidates.length} rule(s) via ${settings.ai_provider}/${effectiveModel} (p-limit ${providerConcurrency}, ${PER_CVE_TIMEOUT_MS / 1000}s/CVE)`,
    {
      candidate_count: candidates.length,
      provider: settings.ai_provider,
      model: effectiveModel,
      already_covered: alreadyCovered,
      trigger_matched: triggerMatchedVulns.length,
    },
  );

  const limit = pLimit(providerConcurrency);
  const overallStart = Date.now();
  const maxWaitMs = settings.max_wait_seconds * 1_000;

  // Per-CVE retry with exponential backoff for transient provider errors
  // (429, 5xx, network). Non-transient outcomes — schema failure, fixture
  // round-trip failure, prompt_injection_suspect — are NOT retried (the
  // model would deterministically return the same result). This sits OUTSIDE
  // generateRuleForCve's inner withRateLimitRetry so a sustained provider
  // outage that exhausts the inner 4-attempt loop still gets 3 fresh tries
  // here (with 30s of cool-down spread across all in-flight CVEs on 429).
  const PROVIDER_RETRY_DELAYS_MS = [1_000, 4_000, 16_000];
  const RATE_LIMIT_GLOBAL_COOL_DOWN_MS = 30_000;
  // Shared timestamp: when ANY in-flight candidate hits a 429, we bump this
  // to `Date.now() + cool_down` and every candidate that's about to fire
  // waits past it before issuing its next call. Keeps the bursts out of the
  // window the provider's already throttled.
  let globalRateLimitedUntil = 0;

  const isTransientProviderError = (status: GenerationResult['status'], errors: string[]): boolean => {
    if (status !== 'provider_error') return false;
    // Surface code lives in the error message string — `withRateLimitRetry`
    // exhausted prepends "Rate-limited after ..." and 5xx/network errors
    // prepend their own labels. Match conservatively so deterministic
    // failures don't slip into the retry path.
    const blob = errors.join(' | ').toLowerCase();
    return /rate.?limit|429|503|502|504|fetch failed|terminated|socket hang up|econnreset|network/.test(blob);
  };

  const isRateLimitErrors = (errors: string[]): boolean => {
    return /rate.?limit|429/i.test(errors.join(' | '));
  };

  // Per-CVE budget recheck. With pLimit(5), 5 concurrent CVEs can each pass
  // a single pre-flight summation and burn the cap together. Re-reading
  // monthlySpend before EACH pLimit task body picks up spend from sibling
  // tasks that already wrote ai_usage_logs rows, so the 6th CVE in a batch
  // sees 5 rows of new spend and bails. Same fail-closed semantics as
  // applyBudgetCap: read failure → skip CVE.
  const PER_CVE_PESSIMISTIC = 0.10;
  const monthlyBudget = settings.monthly_budget_usd;

  const results = await Promise.all(
    candidates.map((vuln) =>
      limit(async () => {
        // Bail if the overall step has already burned its budget.
        if (Date.now() - overallStart > maxWaitMs) {
          return {
            cveId: vuln.osv_id!,
            skipped: true as const,
            reason: 'overall_max_wait_exceeded',
          };
        }

        // Per-CVE cap recheck — fresh SUM read so concurrent slots converge.
        const spendNow = await readRuleGenMonthlySpend(supabase, organizationId);
        if (spendNow === null) {
          return {
            cveId: vuln.osv_id!,
            skipped: true as const,
            reason: 'budget_read_failed',
          };
        }
        if (spendNow + PER_CVE_PESSIMISTIC > monthlyBudget) {
          return {
            cveId: vuln.osv_id!,
            skipped: true as const,
            reason: 'budget_exhausted_mid_batch',
          };
        }

        let lastResult: GenerationResult | null = null;
        for (let attempt = 0; attempt <= PROVIDER_RETRY_DELAYS_MS.length; attempt++) {
          // Honour the global rate-limit cool-down so concurrent slots wait
          // out the same window instead of racing each other into 429s.
          if (Date.now() < globalRateLimitedUntil) {
            const waitMs = globalRateLimitedUntil - Date.now();
            await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
          }
          try {
            const result = await withTimeout(
              (innerSignal) =>
                generateRuleForCve({
                  cveId: vuln.osv_id!,
                  packagePurl: vuln.package_purl!,
                  packageName: vuln.package_name!,
                  ecosystem: vuln.ecosystem!,
                  organizationId,
                  provider: settings!.ai_provider,
                  model: effectiveModel,
                  apiKey,
                  signal: combinedSignal(signal, innerSignal),
                  githubToken: resolveGithubToken(),
                  baseUrl: resolveOpenAiCompatBaseUrl(settings!.ai_provider),
                }),
              PER_CVE_TIMEOUT_MS,
              STEP_NAME,
            );
            lastResult = result;
            if (!isTransientProviderError(result.status, result.errors)) break;
            if (attempt === PROVIDER_RETRY_DELAYS_MS.length) break;
            if (isRateLimitErrors(result.errors)) {
              globalRateLimitedUntil = Math.max(
                globalRateLimitedUntil,
                Date.now() + RATE_LIMIT_GLOBAL_COOL_DOWN_MS,
              );
            }
            await new Promise<void>((resolve) => setTimeout(resolve, PROVIDER_RETRY_DELAYS_MS[attempt]));
            continue;
          } catch (err) {
            if (err instanceof StepTimeoutError) {
              return { cveId: vuln.osv_id!, skipped: true as const, reason: 'timeout' };
            }
            if (jobId) {
              const { code, message, stack } = classifyError(err);
              await logStepError(supabase, {
                jobId,
                projectId,
                step: STEP_NAME,
                code,
                message: `${vuln.osv_id}: ${message}`,
                stack,
                severity: 'warn',
              });
            }
            return { cveId: vuln.osv_id!, skipped: true as const, reason: 'generation_threw' };
          }
        }
        if (lastResult) return { cveId: vuln.osv_id!, skipped: false as const, result: lastResult };
        return { cveId: vuln.osv_id!, skipped: true as const, reason: 'generation_threw' };
      }),
    ),
  );

  // Surface a partial-failure summary log if a non-trivial fraction of CVEs
  // ended in transient provider errors after retry — a systemic provider
  // outage should be operator-visible, not silently recorded as 'failed'.
  const errorClasses: Record<string, number> = {};
  let providerErrorCount = 0;
  for (const r of results) {
    if (r.skipped) continue;
    if (r.result.status === 'validated') continue;
    errorClasses[`status:${r.result.status}`] = (errorClasses[`status:${r.result.status}`] ?? 0) + 1;
    if (r.result.status === 'provider_error') providerErrorCount++;
  }
  if (providerErrorCount > 0 && providerErrorCount >= Math.max(3, Math.floor(candidates.length * 0.25))) {
    const pct = Math.round((providerErrorCount / candidates.length) * 100);
    await log.warn(
      STEP_NAME,
      `cve_spec_generation_partial: ${providerErrorCount}/${candidates.length} CVEs ended in provider_error after retries — likely a sustained provider outage`,
      { error_classes: errorClasses, provider: settings.ai_provider, model: effectiveModel },
    );
    // Surface to extraction_step_errors so a sustained provider outage shows
    // up in the extraction-failures admin UI and isn't only visible in stdout.
    if (jobId) {
      await logStepError(supabase, {
        jobId,
        projectId,
        step: STEP_NAME,
        code: 'provider_outage_suspect',
        message: `${pct}% of CVEs (${providerErrorCount}/${candidates.length}) failed with provider_error in this batch via ${settings.ai_provider}/${effectiveModel}`,
        severity: 'warn',
      });
    }
  }

  // --- 8. Persist validated rules + tally stats ---
  let generatedCount = 0;
  let totalCost = 0;
  const breakdownAccumulator: ValidationBreakdown[] = [];
  for (const r of results) {
    if (r.skipped) {
      bumpReason(r.reason);
      await log.warn(STEP_NAME, `${r.cveId}: skipped (${r.reason})`);
      continue;
    }
    totalCost += r.result.costUsd;
    breakdownAccumulator.push(r.result.validationBreakdown);
    // P0-A: persist platform AI spend to ai_usage_logs so the per-org monthly budget
    // cap (readRuleGenMonthlySpend / applyBudgetCap) actually sees the spend
    // we just incurred. Without this row, monthlySpend stays at $0 forever
    // and the cap is non-functional. Skip for pre-attempt bails (no token
    // usage recorded — costUsd=0 and inputTokens=0).
    if (r.result.inputTokens > 0 || r.result.outputTokens > 0 || r.result.costUsd > 0) {
      await logRuleGenAiUsage(supabase, log, {
        organizationId,
        provider: r.result.generatedWith.provider,
        model: r.result.generatedWith.model,
        inputTokens: r.result.inputTokens,
        outputTokens: r.result.outputTokens,
        costUsd: r.result.costUsd,
        cveId: r.cveId,
        jobId,
        success: r.result.status === 'validated',
        errorMessage: r.result.status === 'validated' ? null : r.result.status,
      });
    }
    if (r.result.status !== 'validated') {
      bumpReason(`status:${r.result.status}`);
      const errSummary = (r.result.errors ?? []).join(' | ').slice(0, 240);
      await log.warn(
        STEP_NAME,
        `${r.cveId}: status=${r.result.status}${errSummary ? ` errors=${errSummary}` : ''}`,
      );
      // P0-B: prompt_injection_suspect specifically also lands in
      // extraction_step_errors so the security signal is visible in the
      // admin extraction-failures UI, not just stdout.
      if (r.result.status === 'prompt_injection_suspect' && jobId) {
        await logStepError(supabase, {
          jobId,
          projectId,
          step: STEP_NAME,
          code: 'prompt_injection_suspect',
          message: `${r.cveId}: model emitted osv_id on a sink (prompt-injection guard tripped). Provider=${r.result.generatedWith.provider} model=${r.result.generatedWith.model}.`,
          severity: 'warn',
        });
      }
      // Persist the failed attempt too — gives the org a record they can
      // see in the Settings UI ("we tried this CVE, failed at validation").
      await persistGeneratedRule(supabase, organizationId, r.result, log, jobId, projectId);
      continue;
    }
    const persisted = await persistGeneratedRule(supabase, organizationId, r.result, log, jobId, projectId);
    if (persisted) generatedCount++;
  }

  const validationBreakdown = aggregateBreakdowns(breakdownAccumulator);

  const tookMs = Date.now() - stepStart;
  // Surface the same four counters we persist to extraction_jobs so a single
  // grep on the extraction log confirms the funnel: total_detectable → matched
  // → generated_this_scan → generation_cost. Names match the column names so
  // the log line and DB row are interchangeable.
  const rulesTotalDetectable = triggerMatchedVulns.length;
  const rulesMatched = alreadyCovered + generatedCount;
  await log.success(
    STEP_NAME,
    `Generated ${generatedCount}/${candidates.length} rule(s); rules_matched=${rulesMatched} rules_total_detectable=${rulesTotalDetectable} generated_this_scan=${generatedCount} generation_cost=$${totalCost.toFixed(4)}`,
    tookMs,
    {
      rules_matched: rulesMatched,
      rules_total_detectable: rulesTotalDetectable,
      generated_this_scan: generatedCount,
      generation_cost_usd: totalCost,
      candidate_count: candidates.length,
      already_covered: alreadyCovered,
      provider: settings.ai_provider,
      model: effectiveModel,
      skip_reasons: skipReasons,
      validation_breakdown: validationBreakdown,
    },
  );

  // --- 9. Persist telemetry to extraction_jobs ---
  await persistJobTelemetry({
    supabase,
    jobId,
    projectId,
    organizationId,
    triggerMatched: triggerMatchedVulns.length,
    alreadyCovered,
    generatedThisScan: generatedCount,
    costUsd: totalCost,
    validationBreakdown,
    log,
  });

  return {
    ran: true,
    triggerMatched: triggerMatchedVulns.length,
    alreadyCovered,
    attempted: candidates.length,
    generated: generatedCount,
    costUsd: totalCost,
    skipReasons,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fetchAssetTierRank(projectId: string, supabase: Storage): Promise<number | null> {
  try {
    const { data: project } = await supabase
      .from('projects')
      .select('asset_tier_id')
      .eq('id', projectId)
      .maybeSingle();
    const tierId = (project as { asset_tier_id?: string | null } | null)?.asset_tier_id;
    if (!tierId) return null;
    const { data: tier } = await supabase
      .from('organization_asset_tiers')
      .select('rank')
      .eq('id', tierId)
      .maybeSingle();
    const rank = (tier as { rank?: number } | null)?.rank;
    return typeof rank === 'number' ? rank : null;
  } catch {
    return null;
  }
}

function isCveLike(osvId: string, aliases: string[] | null): boolean {
  if (osvId.startsWith('CVE-')) return true;
  if (Array.isArray(aliases)) return aliases.some((a) => typeof a === 'string' && a.startsWith('CVE-'));
  return false;
}

function canonicalCveId(osvId: string, aliases: string[] | null): string | null {
  if (osvId.startsWith('CVE-')) return osvId;
  if (Array.isArray(aliases)) {
    for (const a of aliases) {
      if (typeof a === 'string' && a.startsWith('CVE-')) return a;
    }
  }
  return null;
}

/**
 * Read the org's already-generated CVE coverage set. Returns null on read
 * failure — callers MUST fail-closed (skip generation) rather than treat the
 * read failure as "no coverage", which would silently regenerate every CVE on
 * a Supabase blip and amplify platform AI spend. Mirrors readRuleGenMonthlySpend.
 */
async function loadOrgExistingRuleCves(orgId: string, supabase: Storage): Promise<Set<string> | null> {
  const { data, error } = await supabase
    .from('organization_generated_rules')
    .select('cve_id, validation_status')
    .eq('organization_id', orgId);
  if (error) return null;
  // Treat both validated and pending as "already covered" — we don't want to
  // re-fire generation for a CVE that's mid-regenerate or that previously
  // failed (the org admin can manually delete the row to retry).
  return new Set(((data ?? []) as Array<{ cve_id: string }>).map((r) => r.cve_id));
}

interface ApplyBudgetArgs {
  settings: OrgReachabilitySettings;
  organizationId: string;
  candidateCount: number;
  supabase: Storage;
  log: LogLike;
}

/**
 * Read this calendar month's `rule_generation` spend from ai_usage_logs.
 * Returns the SUM in USD, or `null` when the read failed — callers MUST
 * fail-closed on null (skip / error out) rather than fall back to $0,
 * which would silently disable the per-org cap during a Supabase outage.
 */
async function readRuleGenMonthlySpend(
  supabase: Storage,
  organizationId: string,
): Promise<number | null> {
  try {
    const monthStart = new Date();
    monthStart.setUTCDate(1);
    monthStart.setUTCHours(0, 0, 0, 0);
    // The Storage abstraction (used in PGLite local-mode) doesn't expose
    // .gte for non-string types, so cast here. PGLite's adapter does
    // support gte at runtime; this just sidesteps the narrowed type.
    const builder = supabase
      .from('ai_usage_logs')
      .select('estimated_cost')
      .eq('organization_id', organizationId)
      .eq('feature', 'rule_generation') as unknown as {
        gte: (col: string, val: string) => Promise<{ data: unknown; error: unknown }>;
      };
    const { data, error } = await builder.gte('created_at', monthStart.toISOString());
    if (error) return null;
    let sum = 0;
    for (const row of (data as Array<{ estimated_cost?: number | string }> | null) ?? []) {
      const v = typeof row.estimated_cost === 'string' ? parseFloat(row.estimated_cost) : row.estimated_cost ?? 0;
      sum += Number(v) || 0;
    }
    return sum;
  } catch {
    return null;
  }
}

interface RuleGenAiUsageEntry {
  organizationId: string;
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  cveId: string;
  jobId: string | undefined;
  success: boolean;
  errorMessage: string | null;
}

/**
 * P0-A: persist a single rule-generation AI call to ai_usage_logs so the
 * monthly platform AI budget cap (readRuleGenMonthlySpend / applyBudgetCap) sees
 * the spend on the next iteration. Without this the cap is non-functional —
 * monthlySpend stays $0 and runaway platform AI spend is possible. ai_usage_logs
 * was originally schema'd around an end-user-driven call (`user_id NOT
 * NULL`), but the user_id column has no FK so a system sentinel is safe.
 * Failures here are non-fatal: a Supabase blip on the analytics insert
 * shouldn't abort the rule-generation step. The error bubbles to extraction
 * step errors only when jobId is in scope.
 */
const RULE_GEN_SYSTEM_USER_ID = '00000000-0000-0000-0000-000000000000';
async function logRuleGenAiUsage(
  supabase: Storage,
  log: LogLike,
  entry: RuleGenAiUsageEntry,
): Promise<void> {
  try {
    const { error } = await supabase.from('ai_usage_logs').insert({
      organization_id: entry.organizationId,
      // user_id is NOT NULL but has no FK; a sentinel UUID flags this as a
      // system-driven (worker) call so per-user analytics queries can filter
      // it out via WHERE user_id != '00000000-...'.
      user_id: RULE_GEN_SYSTEM_USER_ID,
      feature: 'rule_generation',
      tier: 'platform',
      provider: entry.provider,
      model: entry.model,
      input_tokens: entry.inputTokens,
      output_tokens: entry.outputTokens,
      estimated_cost: entry.costUsd,
      // context_type/context_id give the analytics layer a join path back to
      // the originating CVE + scan. context_id is text, so cveId fits.
      context_type: 'cve',
      context_id: entry.cveId,
      duration_ms: null,
      success: entry.success,
      error_message: entry.errorMessage,
    });
    if (error) {
      await log.warn(
        STEP_NAME,
        `ai_usage_logs insert failed for ${entry.cveId}: ${(error as { message?: string }).message ?? String(error)}. Monthly budget cap may understate spend until next successful write.`,
      );
    }
  } catch (err) {
    await log.warn(
      STEP_NAME,
      `ai_usage_logs insert threw for ${entry.cveId}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

async function applyBudgetCap(args: ApplyBudgetArgs): Promise<{ effectiveModel: string; budgetSkipped: boolean }> {
  const { settings, organizationId, candidateCount, supabase, log } = args;

  // Fail-closed on read error: previously we fell back to monthlySpend=0 on
  // a Supabase outage, which silently disabled the per-org cap — the only
  // thing standing between us and a runaway platform AI bill. Now: skip generation.
  const monthlySpend = await readRuleGenMonthlySpend(supabase, organizationId);
  if (monthlySpend === null) {
    await log.warn(
      STEP_NAME,
      'Skipping rule generation: ai_usage_logs read failed; cannot enforce monthly budget cap. Generation will resume when Supabase recovers.',
    );
    return { effectiveModel: settings.ai_model, budgetSkipped: true };
  }

  const remaining = Math.max(0, settings.monthly_budget_usd - monthlySpend);
  // Coarse pre-flight: a sonnet-4-6 generation averages ~$0.05 input + $0.04
  // output ≈ $0.09. Use $0.10 as our pessimistic per-CVE estimate.
  const PER_CVE_PESSIMISTIC = 0.10;
  const projected = candidateCount * PER_CVE_PESSIMISTIC;

  if (projected <= remaining) {
    return { effectiveModel: settings.ai_model, budgetSkipped: false };
  }

  if (settings.on_budget_exhaustion === 'fall_back_to_haiku') {
    const fallback = FALLBACK_MODELS[settings.ai_provider];
    await log.warn(
      STEP_NAME,
      `Projected cost ($${projected.toFixed(2)}) exceeds remaining monthly budget ($${remaining.toFixed(2)}); falling back to ${fallback}`,
      { spent: monthlySpend, budget: settings.monthly_budget_usd, projected, fallback },
    );
    return { effectiveModel: fallback, budgetSkipped: false };
  }

  await log.warn(
    STEP_NAME,
    `Projected cost ($${projected.toFixed(2)}) exceeds remaining monthly budget ($${remaining.toFixed(2)}); skipping generation`,
    { spent: monthlySpend, budget: settings.monthly_budget_usd, projected },
  );
  return { effectiveModel: settings.ai_model, budgetSkipped: true };
}

function envVarFor(provider: AiProviderName): string {
  if (provider === 'anthropic') return 'ANTHROPIC_API_KEY';
  if (provider === 'google') return 'GOOGLE_AI_API_KEY';
  return 'OPENAI_API_KEY';
}

async function defaultResolveApiKey(provider: AiProviderName): Promise<string | null> {
  // After phase29_drop_byok, the only key source is the worker's environment.
  // For provider='openai' the actual host may be DeepInfra / OpenRouter /
  // Alibaba via DEPTEX_RULE_BASE_URL; pick the matching key env-var by
  // hostname so a single .env file with all three keys works without
  // forcing the user to also juggle OPENAI_API_KEY.
  if (provider === 'openai') {
    const baseUrl = process.env.DEPTEX_RULE_BASE_URL ?? '';
    if (baseUrl.includes('deepinfra')) {
      if (process.env.DEEPINFRA_API_KEY) return process.env.DEEPINFRA_API_KEY;
    } else if (baseUrl.includes('openrouter')) {
      if (process.env.OPENROUTER_API_KEY) return process.env.OPENROUTER_API_KEY;
    } else if (baseUrl.includes('aliyuncs') || baseUrl.includes('dashscope')) {
      if (process.env.DASHSCOPE_API_KEY) return process.env.DASHSCOPE_API_KEY;
    }
    return process.env.OPENAI_API_KEY ?? null;
  }
  if (provider === 'anthropic') {
    return process.env.ANTHROPIC_API_KEY ?? null;
  }
  if (provider === 'google') {
    // Accept GOOGLE_AI_API_KEY (the Tier-1 platform key name in
    // CLAUDE.md / backend/.env) as a fallback for plain GOOGLE_API_KEY so
    // operators don't have to duplicate the same value into two env vars.
    return process.env.GOOGLE_API_KEY ?? process.env.GOOGLE_AI_API_KEY ?? null;
  }
  return null;
}

/**
 * Pull a GitHub token out of the worker's environment so patch-fetch can hit
 * the api.github.com 5000/hr authenticated rate limit instead of the 60/hr
 * anonymous one. Recognises GITHUB_TOKEN (standard for cloud workers wired
 * with installation tokens), GITHUB_PAT (personal-access fallback used by
 * the local CLI). Returns undefined if neither is set; the patch fetcher
 * gracefully falls back to anonymous in that case, but a busy local dev loop
 * burns through the 60/hr cap fast and surfaces as 403s on every CVE.
 */
function resolveGithubToken(): string | undefined {
  const t = process.env.GITHUB_TOKEN || process.env.GITHUB_PAT;
  return t && t.trim().length > 0 ? t.trim() : undefined;
}

/**
 * In local-CLI mode, allow routing the OpenAI-compatible call to a third-party
 * host (DeepInfra, OpenRouter, Alibaba) via DEPTEX_RULE_BASE_URL. Cloud workers
 * never set this — they speak directly to api.openai.com. Returns undefined
 * outside CLI mode or when no override is configured. Only meaningful for
 * provider='openai' (anthropic/google ignore the field).
 */
function resolveOpenAiCompatBaseUrl(provider: AiProviderName): string | undefined {
  if (provider !== 'openai') return undefined;
  if (process.env.DEPTEX_LOCAL_CLI !== '1') return undefined;
  const url = process.env.DEPTEX_RULE_BASE_URL?.trim();
  return url && url.length > 0 ? url : undefined;
}

async function persistGeneratedRule(
  supabase: Storage,
  organizationId: string,
  result: GenerationResult,
  log: LogLike,
  jobId: string | undefined,
  projectId: string,
): Promise<boolean> {
  // Look up an existing pending row (the regenerate endpoint marks rows
  // pending; the next scan picks those up). If found, update in place to
  // preserve previous_versions; else insert a fresh row.
  const { data: existing } = await supabase
    .from('organization_generated_rules')
    .select('id, previous_versions')
    .eq('organization_id', organizationId)
    .eq('cve_id', result.cveId)
    .eq('package_purl', result.packagePurl)
    .maybeSingle();

  // Server-side osv_id substitution (Patch 5 / E1) — the persistence step is
  // the SINGLE canonical assignment site for osv_id on a sink. The model
  // never gets to set this; the DB-side framework_spec_osv_match_chk
  // constraint (phase27a) enforces server-side as defense-in-depth.
  const substitutedSpec = result.rule
    ? withOsvIdsSubstituted(result.rule.framework_spec, result.cveId)
    : null;

  if (result.promptInjectionSuspect) {
    await log.warn(
      STEP_NAME,
      `prompt_injection_suspect: ${result.cveId} model emitted osv_id on a sink. Row rejected.`,
      {
        cve_id: result.cveId,
        provider: result.generatedWith.provider,
        model: result.generatedWith.model,
        attempts: result.attempts,
      },
    );
  }

  // P0-B / P1-C: previously dropped any non-validated, ruleless result. That
  // silenced prompt_injection_suspect and pre-attempt bail outcomes
  // (no_advisory / no_fix_commit / fetch_failed / vuln_class_out_of_scope) —
  // the org-settings UI has no way to render "we tried CVE-X; uncoverable
  // because: <reason>". Now we persist a stub row for those statuses too,
  // tagged with terminal_reason=<status> in validation_log so the UI can
  // disambiguate. Other ruleless statuses still drop (defensive default).
  const PERSIST_RULELESS_STATUSES = new Set<GenerationResult['status']>([
    'failed_validation',
    'prompt_injection_suspect',
    'no_advisory',
    'no_fix_commit',
    'fetch_failed',
    'vuln_class_out_of_scope',
  ]);
  if (!result.rule && !PERSIST_RULELESS_STATUSES.has(result.status)) {
    return false;
  }

  // For ruleless-but-persistable rows the spec_shape_chk CHECK constraint
  // requires framework_spec NOT NULL when spec_format='framework_spec'. Use
  // {} as a stub — osv_match_chk returns true when the spec lacks a
  // well-formed sinks array, so the constraint is satisfied.
  const frameworkSpecForRow: unknown = result.rule ? substitutedSpec : {};

  const validationLogForRow: Record<string, unknown> = {
    ...(result.validationLog ?? { errors: result.errors }),
    prompt_version: FRAMEWORK_SPEC_PROMPT_VERSION,
    attempts: result.attempts,
  };
  if (result.status !== 'validated') {
    // P0-B / P1-C tag: the UI keys on validation_log.terminal_reason to
    // render "uncoverable because <reason>".
    validationLogForRow.terminal_reason = result.status;
  }

  const baseRow = {
    organization_id: organizationId,
    cve_id: result.cveId,
    package_purl: result.packagePurl,
    ecosystem: result.ecosystem,
    affected_version_range: result.affectedVersionRange ?? null,
    // M2b: write FrameworkSpec JSONB. Leave rule_yaml NULL on new rows —
    // the phase27a migration dropped the NOT NULL on rule_yaml so we no
    // longer need an empty-string placeholder. spec_format='framework_spec'
    // is what the loader keys on; legacy 'semgrep_yaml' rows continue to
    // load via the old path until M5 retires Phase 5 entirely.
    rule_yaml: null,
    framework_spec: frameworkSpecForRow,
    spec_format: 'framework_spec',
    vulnerable_fixture: result.rule?.vulnerable_fixture ?? '',
    safe_fixture: result.rule?.safe_fixture ?? '',
    reachability_level: result.rule?.reachability_level ?? 'function',
    entry_point_class: result.rule?.entry_point_class ?? null,
    generated_with_provider: result.generatedWith.provider,
    generated_with_model: result.generatedWith.model,
    generation_cost_usd: result.costUsd,
    validation_status: result.status === 'validated' ? 'validated' : 'failed_validation',
    // prompt_version doesn't have a dedicated column on organization_generated_rules
    // (the table predates Phase 5h's prompt-version tracking) — fold it into
    // validation_log so the row still carries enough metadata to forensically
    // disambiguate which generator authored it.
    validation_log: validationLogForRow,
    enabled: result.status === 'validated',
    generated_at: new Date().toISOString(),
  };

  try {
    if (existing) {
      const { error } = await supabase
        .from('organization_generated_rules')
        .update(baseRow)
        // Belt-and-braces tenant filter: existing.id was returned from a
        // tenant-scoped read above, so this is already correct in practice.
        // The redundant org filter survives future refactors that change how
        // `existing` is sourced.
        .eq('id', (existing as { id: string }).id)
        .eq('organization_id', organizationId);
      if (error) throw new Error(error.message);
    } else {
      const { error } = await supabase
        .from('organization_generated_rules')
        .insert(baseRow);
      if (error) throw new Error(error.message);
    }
    return result.status === 'validated';
  } catch (err) {
    await log.warn(
      STEP_NAME,
      `persistGeneratedRule upsert failed; generated rule lost for ${result.cveId}: ${err instanceof Error ? err.message : String(err)}`,
    );
    if (jobId) {
      const { code, message, stack } = classifyError(err);
      await logStepError(supabase, {
        jobId,
        projectId,
        step: STEP_NAME,
        code,
        message,
        stack,
        severity: 'warn',
      });
    }
    return false;
  }
}

export interface AggregatedValidationBreakdown {
  candidates: number;
  schema_pass: number;
  /** Count of candidates whose pattern-syntax pre-flight passed. null
   *  per-candidate (pre-attempt bail / spec_load throw) is not counted. */
  pattern_compile_pass: number;
  fixture_pre_pass: number;
  fixture_safe_pass: number;
  patch_pre_pass: number;
  patch_post_pass: number;
}

/**
 * Roll up per-CVE breakdowns into a step-level funnel: how many candidates
 * passed each successive gate. `patch_*_pass` only counts CVEs where patch
 * validation actually ran (null means skipped, e.g. no applicable changed
 * files), so a low count there is informational, not a regression signal.
 */
export function aggregateBreakdowns(breakdowns: ValidationBreakdown[]): AggregatedValidationBreakdown {
  let schema = 0, patternCompile = 0, fixturePre = 0, fixtureSafe = 0, patchPre = 0, patchPost = 0;
  for (const b of breakdowns) {
    if (b.schema_pass) schema++;
    if (b.pattern_compile_pass === true) patternCompile++;
    if (b.fixture_pre_match) fixturePre++;
    if (b.fixture_safe_clean) fixtureSafe++;
    if (b.patch_pre_match === true) patchPre++;
    if (b.patch_post_clean === true) patchPost++;
  }
  return {
    candidates: breakdowns.length,
    schema_pass: schema,
    pattern_compile_pass: patternCompile,
    fixture_pre_pass: fixturePre,
    fixture_safe_pass: fixtureSafe,
    patch_pre_pass: patchPre,
    patch_post_pass: patchPost,
  };
}

interface JobTelemetryArgs {
  supabase: Storage;
  jobId: string | undefined;
  projectId: string;
  organizationId: string;
  triggerMatched: number;
  alreadyCovered: number;
  generatedThisScan: number;
  costUsd: number;
  validationBreakdown: AggregatedValidationBreakdown;
  log: LogLike;
}

async function persistJobTelemetry(args: JobTelemetryArgs): Promise<void> {
  if (!args.jobId) return;
  try {
    await args.supabase
      .from('scan_jobs')
      .update({
        // total_detectable counts the candidates we saw (trigger-matched).
        // matched is the count of CVEs where a rule already exists OR was
        // generated this scan; useful for the autogrep coverage funnel chart.
        reachability_rules_total_detectable: args.triggerMatched,
        reachability_rules_matched: args.alreadyCovered + args.generatedThisScan,
        reachability_rules_generated_this_scan: args.generatedThisScan,
        reachability_generation_cost_usd: args.costUsd,
        reachability_validation_breakdown: args.validationBreakdown,
      })
      .eq('id', args.jobId)
      // Belt-and-braces: jobId is the worker's own claimed job and ambient to
      // this org's run, so this is correct in practice. The redundant
      // organization_id filter prevents a future refactor that ever sources
      // jobId externally from cross-tenant overwriting telemetry.
      .eq('organization_id', args.organizationId);
  } catch (err) {
    await args.log.warn(STEP_NAME, `Failed to persist telemetry on scan_jobs: ${err instanceof Error ? err.message : String(err)}`);
    // Telemetry persistence is correctness-critical (cost tracking, CVE
    // coverage metrics). Surface the failure to extraction_step_errors
    // so ops can detect breakage like the extraction_jobs→scan_jobs rename
    // that silently dropped 100% of telemetry writes pre-PR-#39.
    const { code, message, stack } = classifyError(err);
    await logStepError(args.supabase, {
      jobId: args.jobId,
      projectId: args.projectId,
      step: STEP_NAME,
      code,
      message,
      stack,
      severity: 'error',
    });
  }
}

function combinedSignal(outer: AbortSignal | undefined, inner: AbortSignal): AbortSignal {
  if (!outer) return inner;
  if (outer.aborted) {
    const c = new AbortController();
    c.abort();
    return c.signal;
  }
  const c = new AbortController();
  outer.addEventListener('abort', () => c.abort(), { once: true });
  inner.addEventListener('abort', () => c.abort(), { once: true });
  return c.signal;
}


export function makeStepWorkdir(prefix: string = 'deptex-rulegen-step-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
