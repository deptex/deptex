/**
 * Per-extraction rule generation pipeline step.
 *
 * Sits between vuln_scan and reachability_rules in pipeline.ts. Given the
 * scan's vulnerabilities, the org's trigger policy, and the org's BYOK key,
 * this step:
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
import { loadAllRulesWithSkipped } from './reachability-rules';
import {
  generateRuleForCve,
  type AiProviderName,
  type GenerationResult,
  type ValidationBreakdown,
} from './rule-generator';

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
  /** Resolved at the call site so tests can pass a fake. */
  platformRulesDir: string;
  /** Override the BYOK key resolver — exposed for tests. Production path
   *  reads from organization_ai_providers + AI_ENCRYPTION_KEY. */
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

  // --- 4. Subtract CVEs already covered (platform + org-existing) ---
  const platformCves = await loadPlatformRuleCves(args.platformRulesDir, log);
  const orgExistingCves = await loadOrgExistingRuleCves(organizationId, supabase);
  const coveredCves = new Set([...platformCves, ...orgExistingCves]);

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

  // --- 5. Resolve BYOK key for the chosen provider ---
  const apiKey = await (args.resolveApiKey ?? defaultResolveApiKey)(organizationId, settings.ai_provider);
  if (!apiKey) {
    await log.warn(
      STEP_NAME,
      `No BYOK key for ${settings.ai_provider}; skipping generation. Configure one in Organization Settings → AI Configuration.`,
    );
    if (jobId) {
      await logStepError(supabase, {
        jobId,
        projectId,
        step: STEP_NAME,
        code: 'byok_missing',
        message: `No ${settings.ai_provider} BYOK key configured for organization ${organizationId}`,
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

  const results = await Promise.all(
    candidates.map((vuln) =>
      limit(async () => {
        // Bail if the overall step has already burned its budget — the
        // outer pipeline timeout would have done this anyway, but bailing
        // here lets us still write whatever finished.
        if (Date.now() - overallStart > maxWaitMs) {
          return {
            cveId: vuln.osv_id!,
            skipped: true as const,
            reason: 'overall_max_wait_exceeded',
          };
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
                platformRulesDir: args.platformRulesDir,
                githubToken: resolveGithubToken(),
                baseUrl: resolveOpenAiCompatBaseUrl(settings!.ai_provider),
              }),
            PER_CVE_TIMEOUT_MS,
            STEP_NAME,
          );
          return { cveId: vuln.osv_id!, skipped: false as const, result };
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
      }),
    ),
  );

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
    if (r.result.status !== 'validated') {
      bumpReason(`status:${r.result.status}`);
      const errSummary = (r.result.errors ?? []).join(' | ').slice(0, 240);
      await log.warn(
        STEP_NAME,
        `${r.cveId}: status=${r.result.status}${errSummary ? ` errors=${errSummary}` : ''}`,
      );
      // Persist the failed attempt too — gives the org a record they can
      // see in the Settings UI ("we tried this CVE, failed at validation").
      await persistGeneratedRule(supabase, organizationId, r.result, log);
      continue;
    }
    const persisted = await persistGeneratedRule(supabase, organizationId, r.result, log);
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

async function loadPlatformRuleCves(rulesDir: string, log: LogLike): Promise<Set<string>> {
  try {
    const { loaded } = await loadAllRulesWithSkipped(rulesDir);
    return new Set(loaded.map((r) => r.metadata.cve));
  } catch (err) {
    await log.warn(STEP_NAME, `Could not enumerate platform-shipped rules at ${rulesDir}: ${err instanceof Error ? err.message : String(err)}`);
    return new Set();
  }
}

async function loadOrgExistingRuleCves(orgId: string, supabase: Storage): Promise<Set<string>> {
  const { data, error } = await supabase
    .from('organization_generated_rules')
    .select('cve_id, validation_status')
    .eq('organization_id', orgId);
  if (error) return new Set();
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

async function applyBudgetCap(args: ApplyBudgetArgs): Promise<{ effectiveModel: string; budgetSkipped: boolean }> {
  const { settings, organizationId, candidateCount, supabase, log } = args;

  // Pull this calendar month's spend on rule_generation from ai_usage_logs.
  // Best-effort — failure to read defaults to "no spend yet".
  let monthlySpend = 0;
  try {
    const monthStart = new Date();
    monthStart.setUTCDate(1);
    monthStart.setUTCHours(0, 0, 0, 0);
    // The Storage abstraction (used in PGLite local-mode) doesn't expose
    // .gte for non-string types, so cast to any here. PGLite's adapter
    // does support gte at runtime; this just sidesteps the narrowed type.
    // Failure is non-fatal — we'll fall back to zero spend and rely on
    // the per-CVE budget heuristic alone.
    const builder = supabase
      .from('ai_usage_logs')
      .select('estimated_cost')
      .eq('organization_id', organizationId)
      .eq('feature', 'rule_generation') as unknown as {
        gte: (col: string, val: string) => Promise<{ data: unknown; error: unknown }>;
      };
    const { data } = await builder.gte('created_at', monthStart.toISOString());
    for (const row of (data as Array<{ estimated_cost?: number | string }> | null) ?? []) {
      const v = typeof row.estimated_cost === 'string' ? parseFloat(row.estimated_cost) : row.estimated_cost ?? 0;
      monthlySpend += Number(v) || 0;
    }
  } catch {
    /* read failure is non-fatal */
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

async function defaultResolveApiKey(orgId: string, provider: AiProviderName): Promise<string | null> {
  // Mirror the same env-var escape EPD uses for the local CLI / self-host
  // path: when DEPTEX_LOCAL_CLI=1 and the matching env key is set, prefer
  // it. Cloud workers ignore this branch.
  if (process.env.DEPTEX_LOCAL_CLI === '1') {
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
      if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;
      return null;
    }
    const envKey = provider === 'anthropic' ? process.env.ANTHROPIC_API_KEY
      // Accept GOOGLE_AI_API_KEY (the Tier-1 platform key name in
      // CLAUDE.md / backend/.env) as a fallback for plain GOOGLE_API_KEY.
      // A self-host operator who already wired the platform AI key in
      // shouldn't have to duplicate it.
      : provider === 'google' ? (process.env.GOOGLE_API_KEY || process.env.GOOGLE_AI_API_KEY)
      : null;
    if (envKey) return envKey;
  }

  // Cloud path: pull from organization_ai_providers and decrypt with
  // AI_ENCRYPTION_KEY (same envelope as Aegis + EPD).
  const { createClient } = await import('@supabase/supabase-js');
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  const sb = createClient(url, key);
  const { data } = await sb
    .from('organization_ai_providers')
    .select('encrypted_api_key, encryption_key_version')
    .eq('organization_id', orgId)
    .eq('provider', provider)
    .maybeSingle();
  const row = data as { encrypted_api_key?: string; encryption_key_version?: number } | null;
  if (!row?.encrypted_api_key) return null;
  try {
    return decryptApiKey(row.encrypted_api_key, Number(row.encryption_key_version ?? 1));
  } catch {
    return null;
  }
}

function decryptApiKey(encrypted: string, storedVersion: number): string {
  const crypto = require('crypto') as typeof import('crypto');
  const parts = encrypted.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted key format');
  const keyHex = process.env.AI_ENCRYPTION_KEY;
  if (!keyHex) throw new Error('AI_ENCRYPTION_KEY is not configured');
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) throw new Error('AI_ENCRYPTION_KEY must be 32-byte hex');
  const nonce = Buffer.from(parts[0], 'base64');
  const ciphertext = Buffer.from(parts[1], 'base64');
  const authTag = Buffer.from(parts[2], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(authTag);
  try {
    return decipher.update(ciphertext) + decipher.final('utf8');
  } catch {
    const prevHex = process.env.AI_ENCRYPTION_KEY_PREV;
    const currentVersion = Number(process.env.AI_ENCRYPTION_KEY_VERSION || '1');
    if (prevHex && storedVersion < currentVersion) {
      const prevKey = Buffer.from(prevHex, 'hex');
      const prevDecipher = crypto.createDecipheriv('aes-256-gcm', prevKey, nonce, { authTagLength: 16 });
      prevDecipher.setAuthTag(authTag);
      return prevDecipher.update(ciphertext) + prevDecipher.final('utf8');
    }
    throw new Error('Unable to decrypt BYOK key');
  }
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

  const baseRow = {
    organization_id: organizationId,
    cve_id: result.cveId,
    package_purl: result.packagePurl,
    ecosystem: result.ecosystem,
    affected_version_range: result.affectedVersionRange ?? null,
    rule_yaml: result.rule?.rule_yaml ?? '',
    vulnerable_fixture: result.rule?.vulnerable_fixture ?? '',
    safe_fixture: result.rule?.safe_fixture ?? '',
    reachability_level: result.rule?.reachability_level ?? 'function',
    entry_point_class: result.rule?.entry_point_class ?? null,
    generated_with_provider: result.generatedWith.provider,
    generated_with_model: result.generatedWith.model,
    generation_cost_usd: result.costUsd,
    validation_status: result.status === 'validated' ? 'validated' : 'failed_validation',
    validation_log: result.validationLog ?? { errors: result.errors },
    enabled: result.status === 'validated',
    generated_at: new Date().toISOString(),
  };

  // Drop empty-rule rows when there's nothing useful to persist (e.g.
  // status=no_advisory) — the row would just be noise in the UI.
  if (!result.rule && result.status !== 'failed_validation') {
    return false;
  }

  try {
    if (existing) {
      const { error } = await supabase
        .from('organization_generated_rules')
        .update(baseRow)
        .eq('id', (existing as { id: string }).id);
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
      `Failed to persist rule for ${result.cveId}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }
}

export interface AggregatedValidationBreakdown {
  candidates: number;
  schema_pass: number;
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
  let schema = 0, fixturePre = 0, fixtureSafe = 0, patchPre = 0, patchPost = 0;
  for (const b of breakdowns) {
    if (b.schema_pass) schema++;
    if (b.fixture_pre_match) fixturePre++;
    if (b.fixture_safe_clean) fixtureSafe++;
    if (b.patch_pre_match === true) patchPre++;
    if (b.patch_post_clean === true) patchPost++;
  }
  return {
    candidates: breakdowns.length,
    schema_pass: schema,
    fixture_pre_pass: fixturePre,
    fixture_safe_pass: fixtureSafe,
    patch_pre_pass: patchPre,
    patch_post_pass: patchPost,
  };
}

interface JobTelemetryArgs {
  supabase: Storage;
  jobId: string | undefined;
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
      .from('extraction_jobs')
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
      .eq('id', args.jobId);
  } catch (err) {
    await args.log.warn(STEP_NAME, `Failed to persist telemetry on extraction_jobs: ${err instanceof Error ? err.message : String(err)}`);
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

export function makePlatformRulesDir(): string {
  // Allow self-host / local-CLI testing to point at an empty dir so an
  // already-shipped platform rule doesn't shadow the AI-generation path
  // we're trying to exercise.
  const override = process.env.DEPTEX_RULE_GENERATION_PLATFORM_RULES_DIR;
  if (override && override.length > 0) return override;
  return path.resolve(__dirname, '..', 'reachability-rules');
}

export function makeStepWorkdir(prefix: string = 'deptex-rulegen-step-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
