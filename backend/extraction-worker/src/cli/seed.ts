/**
 * Minimal DB seed for local-mode CLI runs.
 *
 * A freshly-booted PGLite has the full schema but no rows. The pipeline
 * assumes org/project/project_repositories exist (updateStep() writes to
 * project_repositories immediately). This helper inserts just enough state
 * to let runPipeline() succeed.
 *
 * Keep this narrow — we only seed what the pipeline reads/writes before
 * finalize_extraction. Anything else (teams, statuses, policies) is out of
 * scope for CLI mode.
 */

import type { Storage } from '../storage';

export interface SeedResult {
  organizationId: string;
  projectId: string;
  projectName: string;
  /** Synthetic extraction_jobs row id, only populated when rule generation
   *  is enabled — gives the rule_generation step a target for telemetry
   *  persistence in CLI mode. Cloud workers fill this in from QStash. */
  jobId?: string;
}

export interface SeedOptions {
  /** Identifier used in the project name + project_repositories.repo_full_name. */
  repoLabel: string;
  /** Ecosystem for project_repositories.ecosystem (npm/pypi/maven/golang). */
  ecosystem: string;
  /** Default branch to record (cosmetic for local mode). */
  defaultBranch?: string;
}

const LOCAL_ORG_ID = '00000000-0000-0000-0000-00000000000a';

export async function seedLocalDb(
  storage: Storage,
  opts: SeedOptions,
): Promise<SeedResult> {
  const { repoLabel, ecosystem, defaultBranch = 'main' } = opts;

  // 1) Organization — upsert-by-id so re-seeding the same PGLite is idempotent.
  const { error: orgErr } = await storage.from('organizations').upsert(
    { id: LOCAL_ORG_ID, name: 'local-cli-org' },
    { onConflict: 'id', ignoreDuplicates: true },
  );
  if (orgErr) throw new Error(`seed org failed: ${orgErr.message}`);

  // 2) Project — generated UUID; keep one per CLI invocation so outputs
  //    from repeated runs don't collide in a persisted PGLite.
  const projectId = generateUuid();
  const { error: projErr } = await storage.from('projects').insert({
    id: projectId,
    organization_id: LOCAL_ORG_ID,
    name: repoLabel,
    active_extraction_run_id: null,
    previous_extraction_run_id: null,
  });
  if (projErr) throw new Error(`seed project failed: ${projErr.message}`);

  // 3) project_repositories — updateStep() targets this row every pipeline
  //    step, so it must exist before runPipeline is called.
  const { error: repoErr } = await storage.from('project_repositories').insert({
    project_id: projectId,
    installation_id: 'local',
    repo_id: 0,
    repo_full_name: `local/${repoLabel}`,
    default_branch: defaultBranch,
    status: 'pending',
    ecosystem,
    provider: 'local',
  });
  if (repoErr) throw new Error(`seed project_repositories failed: ${repoErr.message}`);

  // 4) organization_reachability_settings — only seeded when the user opts in
  //    via DEPTEX_RULE_GENERATION_ENABLED=1. Defaults are tuned for local
  //    testing (KEV not required, matches everything reachable, no asset
  //    tier means the rank filter passes). The provider/model can be tuned
  //    via DEPTEX_RULE_PROVIDER / DEPTEX_RULE_MODEL.
  let jobId: string | undefined;
  if (process.env.DEPTEX_RULE_GENERATION_ENABLED === '1') {
    const provider = (process.env.DEPTEX_RULE_PROVIDER ?? 'anthropic') as
      | 'anthropic' | 'openai' | 'google';
    // For openai-compat third parties (DeepInfra / OpenRouter / Alibaba) the
    // host is selected via DEPTEX_RULE_BASE_URL; the user MUST pass a model
    // id understood by that host (e.g. Qwen/Qwen3-235B-A22B-Instruct-2507).
    // Don't default — fall back to gpt-4o-mini for plain OpenAI only.
    const baseUrl = process.env.DEPTEX_RULE_BASE_URL ?? '';
    const isOpenAiCompatThirdParty = provider === 'openai' && baseUrl.length > 0;
    const model = process.env.DEPTEX_RULE_MODEL
      ?? (isOpenAiCompatThirdParty ? 'Qwen/Qwen3-235B-A22B-Instruct-2507'
        : provider === 'anthropic' ? 'claude-sonnet-4-6'
        : provider === 'openai' ? 'gpt-4o-mini'
        : 'gemini-2.0-flash');
    const { error: rgErr } = await storage
      .from('organization_reachability_settings')
      .insert({
        organization_id: LOCAL_ORG_ID,
        auto_generate_enabled: true,
        trigger_severities: ['critical', 'high', 'medium'],
        trigger_kev: false,
        trigger_asset_tier_max_rank: 5,
        trigger_newly_discovered: true,
        trigger_reevaluate_existing: false,
        ai_provider: provider,
        ai_model: model,
        monthly_budget_usd: Number(process.env.DEPTEX_RULE_BUDGET_USD ?? '5.00'),
        on_budget_exhaustion: 'skip',
        max_wait_seconds: 600,
      });
    if (rgErr) throw new Error(`seed reachability settings failed: ${rgErr.message}`);

    // 5) extraction_jobs — synthetic row so persistJobTelemetry can write the
    //    four reachability_* counters. The pipeline uses job.jobId as the WHERE
    //    target; without this row in CLI mode telemetry is silently dropped.
    jobId = generateUuid();
    const { error: jobErr } = await storage.from('extraction_jobs').insert({
      id: jobId,
      project_id: projectId,
      organization_id: LOCAL_ORG_ID,
      status: 'processing',
      payload: { source: 'local-cli', label: repoLabel },
    });
    if (jobErr) throw new Error(`seed extraction_jobs failed: ${jobErr.message}`);
  }

  return {
    organizationId: LOCAL_ORG_ID,
    projectId,
    projectName: repoLabel,
    jobId,
  };
}

function generateUuid(): string {
  // node:crypto.randomUUID is in core; avoids a dep.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require('node:crypto').randomUUID();
}
