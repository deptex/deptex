#!/usr/bin/env node
/**
 * Shadow-run health monitor for the cross-file taint engine.
 *
 * Henry runs this daily during the 30-day shadow window after rolling the
 * engine out to his dogfood org. It queries `taint_engine_runs` and
 * `taint_engine_settings` and prints the metrics that matter:
 *   - failure rate over the look-back window (default 7d)
 *   - mean AI cost / propagation_ms / total_ms per completed run
 *   - killswitch state (auto + manual)
 *   - typed-JS quality breakdown (so npm projects with poor typing
 *     surface as a separate bucket — these are the projects most likely
 *     to over-/under-emit flows)
 *   - last 5 failed runs with error_code + truncated message
 *
 * This is a read-only operational tool — it never writes back. Failure
 * thresholds are hardcoded to the same numbers the circuit breaker uses
 * (5% failure / 5+ runs / 60min) so daily watch and auto-engagement stay
 * aligned.
 *
 * Usage:
 *   npm run taint-engine:shadow-monitor                         # all orgs, 7d window
 *   npm run taint-engine:shadow-monitor -- --org <uuid>         # single org
 *   npm run taint-engine:shadow-monitor -- --days 30            # 30d window
 *   npm run taint-engine:shadow-monitor -- --json               # JSON output for piping
 *
 * Reads SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY from env. Exit code is
 * 0 unless --strict is set, in which case it exits 1 if any threshold
 * is breached (use this to wire into CI / cron alerts).
 */

import * as path from 'path';
import * as dotenv from 'dotenv';
dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

import { createSupabaseStorage } from '../src/storage';
import type { Storage } from '../src/storage';

interface CliOptions {
  orgId?: string;
  days: number;
  json: boolean;
  strict: boolean;
}

interface RunRow {
  id: string;
  organization_id: string;
  project_id: string;
  status: string;
  total_ms: number | null;
  taint_propagation_ms: number | null;
  ai_cost_usd: number | null;
  flows_emitted: number | null;
  is_typed_js_project: boolean | null;
  typed_files_pct: number | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
}

interface SettingsRow {
  organization_id: string;
  killswitch_active: boolean | null;
  killswitch_reason: string | null;
  killswitch_activated_at: string | null;
  rollout_pct_override: number | null;
}

interface OrgSummary {
  organizationId: string;
  windowDays: number;
  totalRuns: number;
  completedRuns: number;
  failedRuns: number;
  skippedRuns: number;
  failurePct: number;
  meanAiCostUsd: number;
  meanPropagationMs: number;
  meanTotalMs: number;
  killswitchActive: boolean;
  killswitchReason: string | null;
  rolloutPctOverride: number | null;
  typedJsBreakdown: {
    typed: number;
    untyped: number;
    typedPct: number;
  };
  recentFailures: Array<{
    createdAt: string;
    errorCode: string | null;
    errorMessage: string | null;
  }>;
  thresholdsBreached: string[];
}

const FAILURE_PCT_CEILING = 5.0; // matches circuit-breaker default
const AI_COST_CEILING_USD = 0.10; // per-run mean — flag for tuning
const MIN_RUNS_FOR_FAILURE_GATE = 5; // matches circuit-breaker MIN_SAMPLE_SIZE

function parseArgs(argv: string[]): CliOptions {
  let orgId: string | undefined;
  let days = 7;
  let json = false;
  let strict = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--org') orgId = argv[++i];
    else if (a === '--days') days = Number(argv[++i]);
    else if (a === '--json') json = true;
    else if (a === '--strict') strict = true;
    else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
    else if (a.startsWith('--')) {
      console.error(`unknown flag: ${a}`);
      process.exit(2);
    }
  }
  if (!Number.isFinite(days) || days <= 0 || days > 365) {
    console.error('--days must be 1..365');
    process.exit(2);
  }
  return { orgId, days, json, strict };
}

function printHelp(): void {
  process.stdout.write(`Usage: taint-engine:shadow-monitor [options]

Reports taint_engine_runs health for the past N days. Default: all orgs,
7d window, human-readable output.

Options:
  --org <uuid>     Restrict to one organization (default: all orgs with runs)
  --days <n>       Look-back window in days (default 7, max 365)
  --json           Emit one JSON object per org instead of formatted text
  --strict         Exit 1 if any monitored threshold is breached

Reads SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY from env.

Threshold defaults (kept aligned with circuit-breaker):
  - failure_pct > ${FAILURE_PCT_CEILING}% over ≥${MIN_RUNS_FOR_FAILURE_GATE} runs   -> breach
  - mean ai_cost_usd > $${AI_COST_CEILING_USD.toFixed(2)} per completed run -> breach
  - killswitch_active = true                       -> breach
`);
}

async function fetchRuns(storage: Storage, sinceIso: string, orgId?: string): Promise<RunRow[]> {
  const select = 'id, organization_id, project_id, status, total_ms, taint_propagation_ms, ai_cost_usd, flows_emitted, is_typed_js_project, typed_files_pct, error_code, error_message, created_at';
  let q = storage.from<RunRow>('taint_engine_runs').select(select).gte('created_at', sinceIso);
  if (orgId) q = q.eq('organization_id', orgId);
  const { data, error } = await q.order('created_at', { ascending: false });
  if (error) throw new Error(`taint_engine_runs query failed: ${error.message ?? error}`);
  return data ?? [];
}

async function fetchSettings(storage: Storage, orgIds: string[]): Promise<Map<string, SettingsRow>> {
  if (orgIds.length === 0) return new Map();
  const { data, error } = await storage
    .from<SettingsRow>('taint_engine_settings')
    .select('organization_id, killswitch_active, killswitch_reason, killswitch_activated_at, rollout_pct_override')
    .in('organization_id', orgIds);
  if (error) throw new Error(`taint_engine_settings query failed: ${error.message ?? error}`);
  const map = new Map<string, SettingsRow>();
  for (const row of data ?? []) map.set(row.organization_id, row);
  return map;
}

function summarize(orgId: string, runs: RunRow[], settings: SettingsRow | undefined, days: number): OrgSummary {
  const totalRuns = runs.length;
  const completedRuns = runs.filter((r) => r.status === 'completed').length;
  const failedRuns = runs.filter((r) => r.status === 'failed').length;
  const skippedRuns = runs.filter((r) => r.status === 'skipped').length;
  const denom = completedRuns + failedRuns;
  const failurePct = denom > 0 ? (failedRuns / denom) * 100 : 0;

  const completed = runs.filter((r) => r.status === 'completed');
  const meanAiCostUsd =
    completed.length > 0
      ? completed.reduce((acc, r) => acc + Number(r.ai_cost_usd ?? 0), 0) / completed.length
      : 0;
  const meanPropagationMs =
    completed.length > 0
      ? completed.reduce((acc, r) => acc + (r.taint_propagation_ms ?? 0), 0) / completed.length
      : 0;
  const meanTotalMs =
    completed.length > 0
      ? completed.reduce((acc, r) => acc + (r.total_ms ?? 0), 0) / completed.length
      : 0;

  const typedSamples = completed.filter((r) => r.is_typed_js_project !== null);
  const typedRuns = typedSamples.filter((r) => r.is_typed_js_project === true).length;
  const typedJsBreakdown = {
    typed: typedRuns,
    untyped: typedSamples.length - typedRuns,
    typedPct: typedSamples.length > 0 ? (typedRuns / typedSamples.length) * 100 : 0,
  };

  const recentFailures = runs
    .filter((r) => r.status === 'failed')
    .slice(0, 5)
    .map((r) => ({
      createdAt: r.created_at,
      errorCode: r.error_code,
      errorMessage: r.error_message ? r.error_message.slice(0, 200) : null,
    }));

  const thresholdsBreached: string[] = [];
  if (denom >= MIN_RUNS_FOR_FAILURE_GATE && failurePct > FAILURE_PCT_CEILING) {
    thresholdsBreached.push(`failure_pct ${failurePct.toFixed(2)}% > ${FAILURE_PCT_CEILING}%`);
  }
  if (completed.length > 0 && meanAiCostUsd > AI_COST_CEILING_USD) {
    thresholdsBreached.push(`mean_ai_cost $${meanAiCostUsd.toFixed(4)} > $${AI_COST_CEILING_USD.toFixed(2)}`);
  }
  if (settings?.killswitch_active) {
    thresholdsBreached.push(`killswitch_active (${settings.killswitch_reason ?? 'no reason recorded'})`);
  }

  return {
    organizationId: orgId,
    windowDays: days,
    totalRuns,
    completedRuns,
    failedRuns,
    skippedRuns,
    failurePct,
    meanAiCostUsd,
    meanPropagationMs,
    meanTotalMs,
    killswitchActive: settings?.killswitch_active ?? false,
    killswitchReason: settings?.killswitch_reason ?? null,
    rolloutPctOverride: settings?.rollout_pct_override ?? null,
    typedJsBreakdown,
    recentFailures,
    thresholdsBreached,
  };
}

function printHumanSummary(s: OrgSummary): void {
  const breach = s.thresholdsBreached.length > 0 ? '!! BREACH !!' : 'ok';
  console.log(`\n=== org ${s.organizationId} (${s.windowDays}d window) [${breach}] ===`);
  console.log(`  runs:        ${s.totalRuns}  (completed=${s.completedRuns}, failed=${s.failedRuns}, skipped=${s.skippedRuns})`);
  console.log(`  failure_pct: ${s.failurePct.toFixed(2)}%  ${s.failedRuns + s.completedRuns < MIN_RUNS_FOR_FAILURE_GATE ? `(below min sample ${MIN_RUNS_FOR_FAILURE_GATE} — gate not active)` : ''}`);
  console.log(`  mean cost:   $${s.meanAiCostUsd.toFixed(4)} per completed run`);
  console.log(`  mean prop:   ${s.meanPropagationMs.toFixed(0)}ms (total ${s.meanTotalMs.toFixed(0)}ms)`);
  console.log(`  rollout:     ${s.rolloutPctOverride === null ? '(env default)' : `override=${s.rolloutPctOverride}%`}`);
  console.log(`  killswitch:  ${s.killswitchActive ? `ENGAGED — ${s.killswitchReason ?? '(no reason)'}` : 'inactive'}`);
  console.log(`  typed_js:    ${s.typedJsBreakdown.typedPct.toFixed(1)}% typed (${s.typedJsBreakdown.typed}/${s.typedJsBreakdown.typed + s.typedJsBreakdown.untyped})`);
  if (s.recentFailures.length > 0) {
    console.log(`  recent failures (last ${s.recentFailures.length}):`);
    for (const f of s.recentFailures) {
      console.log(`    - ${f.createdAt}  ${f.errorCode ?? '(no code)'}  ${f.errorMessage ?? ''}`);
    }
  }
  if (s.thresholdsBreached.length > 0) {
    console.log(`  thresholds breached:`);
    for (const t of s.thresholdsBreached) console.log(`    - ${t}`);
  }
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const sinceIso = new Date(Date.now() - opts.days * 86_400_000).toISOString();
  const storage = createSupabaseStorage();

  const runs = await fetchRuns(storage, sinceIso, opts.orgId);
  const orgIds = Array.from(new Set(runs.map((r) => r.organization_id)));
  if (orgIds.length === 0) {
    if (opts.json) console.log('[]');
    else console.log(`No taint_engine_runs in the past ${opts.days}d${opts.orgId ? ` for org ${opts.orgId}` : ''}.`);
    return;
  }
  const settingsByOrg = await fetchSettings(storage, orgIds);

  const summaries = orgIds.map((orgId) => {
    const orgRuns = runs.filter((r) => r.organization_id === orgId);
    return summarize(orgId, orgRuns, settingsByOrg.get(orgId), opts.days);
  });

  if (opts.json) {
    console.log(JSON.stringify(summaries, null, 2));
  } else {
    for (const s of summaries) printHumanSummary(s);
    const breachedOrgs = summaries.filter((s) => s.thresholdsBreached.length > 0);
    console.log(`\nSummary: ${summaries.length} org(s), ${breachedOrgs.length} with breached threshold(s).`);
  }

  if (opts.strict && summaries.some((s) => s.thresholdsBreached.length > 0)) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('shadow-monitor failed:', err);
  process.exit(2);
});
