/**
 * Tests covering the new persistence + fail-closed paths added in
 * fix-agent #2 commits ee72cb2 + 65b96da:
 *
 *   TG-1: ai_usage_logs row written per successful rule generation so the
 *         monthly BYOK budget cap actually sees the spend.
 *   TG-2: prompt_injection_suspect lands in BOTH extraction_step_errors
 *         (security signal) AND organization_generated_rules (UI surface).
 *   TG-5: loadOrgExistingRuleCves null-return triggers fail-closed early-skip
 *         + extraction_step_errors row.
 *
 * Mocks `generateRuleForCve` so we can shape the result deterministically.
 * Sibling file rule-generation-step.test.ts deliberately does NOT mock it
 * (relies on real fetch throwing) — keeping these in a separate file lets
 * both styles coexist without colliding.
 */

import type { Storage } from '../storage';
import type {
  GenerationResult,
  ValidationBreakdown,
  GeneratedPayload,
  AiProviderName,
} from '../rule-generator';

// IMPORTANT: jest.mock must be declared before importing the module under test
// so the mock is hoisted ahead of the runRuleGenerationStep import below.
jest.mock('../rule-generator', () => {
  const actual = jest.requireActual('../rule-generator');
  return {
    ...actual,
    generateRuleForCve: jest.fn(),
  };
});

import { runRuleGenerationStep, type PipelineVulnRow } from '../rule-generation-step';
import { generateRuleForCve } from '../rule-generator';

const mockedGenerate = generateRuleForCve as jest.MockedFunction<typeof generateRuleForCve>;

interface SelectOverride {
  data: any;
  error: any;
}

interface TableState {
  rows: any[];
  /** Override the terminal `then`/`maybeSingle`/`gte` resolution for selects on
   *  this table — return value lands as { data, error }. */
  selectOverride?: SelectOverride;
}

class FakeStorage {
  tables: Record<string, TableState> = {};
  inserts: Array<{ table: string; row: any }> = [];
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

  setSelectError(table: string, override: SelectOverride) {
    this.tables[table] = { ...(this.tables[table] ?? { rows: [] }), selectOverride: override };
  }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const inFilters: Array<{ col: string; vals: readonly unknown[] }> = [];
    let cols = '*';

    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) {
        rows = rows.filter((r) => r[f.col] === f.val);
      }
      for (const f of inFilters) {
        rows = rows.filter((r) => f.vals.includes(r[f.col]));
      }
      return rows;
    };

    const resolve = () => {
      if (state.selectOverride) return Promise.resolve(state.selectOverride);
      return Promise.resolve({ data: filterRows(), error: null });
    };
    const resolveMaybeSingle = () => {
      if (state.selectOverride) return Promise.resolve(state.selectOverride);
      const rows = filterRows();
      return Promise.resolve({ data: rows[0] ?? null, error: null });
    };

    const builder: any = {
      select(c?: string) {
        if (c) cols = c;
        return builder;
      },
      eq(col: string, val: unknown) {
        filters.push({ col, val });
        return builder;
      },
      in(col: string, vals: readonly unknown[]) {
        inFilters.push({ col, vals });
        return builder;
      },
      gte() { return resolve(); },
      maybeSingle() { return resolveMaybeSingle(); },
      single() {
        if (state.selectOverride) return Promise.resolve(state.selectOverride);
        const rows = filterRows();
        return Promise.resolve({ data: rows[0] ?? null, error: rows.length === 0 ? new Error('not found') : null });
      },
      insert: (rows: any) => {
        const inserted = Array.isArray(rows) ? rows : [rows];
        for (const r of inserted) this.inserts.push({ table, row: r });
        return Promise.resolve({ data: null, error: null });
      },
      update: (values: any) => {
        const currentFilters: Record<string, unknown> = {};
        for (const f of filters) currentFilters[f.col] = f.val;
        const upBuilder: any = {
          eq: (col: string, val: unknown) => {
            currentFilters[col] = val;
            return upBuilder;
          },
          in: () => upBuilder,
          then: (onFulfilled: any) => {
            this.updates.push({ table, filter: { ...currentFilters }, values });
            return Promise.resolve({ data: null, error: null }).then(onFulfilled);
          },
        };
        return upBuilder;
      },
      then(onFulfilled: any) {
        return resolve().then(onFulfilled);
      },
    };
    return builder;
  }
}

const log = {
  info: jest.fn().mockResolvedValue(undefined),
  success: jest.fn().mockResolvedValue(undefined),
  warn: jest.fn().mockResolvedValue(undefined),
  error: jest.fn().mockResolvedValue(undefined),
};

beforeEach(() => {
  jest.clearAllMocks();
});

const ORG_ID = 'org-1';
const PROJECT_ID = 'proj-1';
const RUN_ID = 'run-1';
const JOB_ID = 'job-1';

function makeStorage(overrides: Partial<{
  auto_generate_enabled: boolean;
  trigger_severities: string[];
  trigger_kev: boolean;
  monthly_budget_usd: number;
  on_budget_exhaustion: 'skip' | 'fall_back_to_haiku';
  ai_provider: AiProviderName;
  ai_model: string;
}> = {}): FakeStorage {
  const fs = new FakeStorage();
  fs.set('organization_reachability_settings', [
    {
      organization_id: ORG_ID,
      auto_generate_enabled: true,
      trigger_severities: ['critical', 'high'],
      trigger_kev: false,
      trigger_asset_tier_max_rank: 5,
      trigger_newly_discovered: true,
      trigger_reevaluate_existing: false,
      ai_provider: 'anthropic',
      ai_model: 'claude-sonnet-4-6',
      monthly_budget_usd: 10.0,
      on_budget_exhaustion: 'skip',
      max_wait_seconds: 300,
      ...overrides,
    },
  ]);
  fs.set('organization_generated_rules', []);
  fs.set('ai_usage_logs', []);
  fs.set('scan_jobs', [{ id: JOB_ID }]);
  fs.set('projects', [{ id: PROJECT_ID, asset_tier_id: null }]);
  fs.set('extraction_step_errors', []);
  return fs;
}

const sampleVuln: PipelineVulnRow = {
  osv_id: 'CVE-9999-9999',
  aliases: [],
  severity: 'critical',
  cisa_kev: false,
  reachability_level: 'function',
  ecosystem: 'npm',
  package_purl: 'pkg:npm/example@1.0.0',
  package_name: 'example',
};

const PASSING_BREAKDOWN: ValidationBreakdown = {
  schema_pass: true,
  pattern_compile_pass: true,
  fixture_pre_match: true,
  fixture_safe_clean: true,
  patch_pre_match: true,
  patch_post_clean: true,
  semgrep_parse_error: null,
};

const PRE_ATTEMPT_BREAKDOWN: ValidationBreakdown = {
  schema_pass: false,
  pattern_compile_pass: null,
  fixture_pre_match: false,
  fixture_safe_clean: false,
  patch_pre_match: null,
  patch_post_clean: null,
  semgrep_parse_error: null,
};

function makePayload(): GeneratedPayload {
  // Minimal shape; the persist path only reads vulnerable_fixture / safe_fixture /
  // reachability_level / entry_point_class / framework_spec from .rule, and
  // withOsvIdsSubstituted accepts any object.
  return {
    framework_spec: { sinks: [] },
    vulnerable_fixture: 'vuln',
    safe_fixture: 'safe',
    reachability_level: 'function',
    entry_point_class: null,
  } as unknown as GeneratedPayload;
}

function makeValidatedResult(cveId: string): GenerationResult {
  return {
    status: 'validated',
    cveId,
    packagePurl: 'pkg:npm/example@1.0.0',
    ecosystem: 'npm',
    rule: makePayload(),
    generatedWith: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
    costUsd: 0.0123,
    inputTokens: 1500,
    outputTokens: 600,
    errors: [],
    promptVersion: 'test',
    validationBreakdown: PASSING_BREAKDOWN,
    attempts: 1,
  };
}

function makePromptInjectionResult(cveId: string): GenerationResult {
  return {
    status: 'prompt_injection_suspect',
    cveId,
    packagePurl: 'pkg:npm/example@1.0.0',
    ecosystem: 'npm',
    rule: undefined,
    generatedWith: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
    costUsd: 0.005,
    inputTokens: 800,
    outputTokens: 200,
    errors: ['model emitted osv_id on a sink'],
    promptVersion: 'test',
    validationBreakdown: PRE_ATTEMPT_BREAKDOWN,
    attempts: 1,
    promptInjectionSuspect: true,
  };
}

describe('TG-1 — ai_usage_logs insert after successful generation', () => {
  it('writes one ai_usage_logs row per successful CVE with feature/tier/context fields set', async () => {
    const fs = makeStorage();
    mockedGenerate.mockImplementation(async (args) => makeValidatedResult(args.cveId));

    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    expect(result.ran).toBe(true);
    expect(result.generated).toBe(1);

    const usageRows = fs.inserts.filter((i) => i.table === 'ai_usage_logs');
    expect(usageRows.length).toBe(1);
    const row = usageRows[0].row;
    expect(row).toMatchObject({
      organization_id: ORG_ID,
      feature: 'rule_generation',
      tier: 'byok',
      provider: 'anthropic',
      model: 'claude-sonnet-4-6',
      context_type: 'cve',
      context_id: 'CVE-9999-9999',
      success: true,
      input_tokens: 1500,
      output_tokens: 600,
    });
    expect(Number(row.estimated_cost)).toBeGreaterThan(0);
    // Sentinel system user id — present so per-user analytics queries can
    // filter worker-driven calls out.
    expect(row.user_id).toBe('00000000-0000-0000-0000-000000000000');
  });

  it('writes ai_usage_logs row with success=false when generation came back non-validated but spent tokens', async () => {
    const fs = makeStorage();
    mockedGenerate.mockImplementation(async (args) => makePromptInjectionResult(args.cveId));

    await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    const usageRows = fs.inserts.filter((i) => i.table === 'ai_usage_logs');
    expect(usageRows.length).toBe(1);
    expect(usageRows[0].row).toMatchObject({
      feature: 'rule_generation',
      tier: 'byok',
      success: false,
      error_message: 'prompt_injection_suspect',
    });
  });

  it('does NOT write ai_usage_logs for pre-attempt bails (zero token usage)', async () => {
    // status:no_advisory comes back with 0 tokens / $0 — there's no spend to
    // log, so we must skip the insert. Without this guard ai_usage_logs would
    // accumulate noise rows that distort the budget cap.
    const fs = makeStorage();
    mockedGenerate.mockImplementation(async (args) => ({
      status: 'no_advisory',
      cveId: args.cveId,
      packagePurl: args.packagePurl,
      ecosystem: args.ecosystem,
      rule: undefined,
      generatedWith: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
      costUsd: 0,
      inputTokens: 0,
      outputTokens: 0,
      errors: ['osv_fetch: advisory not found'],
      promptVersion: 'test',
      validationBreakdown: PRE_ATTEMPT_BREAKDOWN,
      attempts: 0,
    }));

    await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    const usageRows = fs.inserts.filter((i) => i.table === 'ai_usage_logs');
    expect(usageRows).toEqual([]);
  });
});

describe('TG-2 — prompt_injection_suspect lands in BOTH tables', () => {
  it('writes extraction_step_errors row with code=prompt_injection_suspect, severity=warn', async () => {
    const fs = makeStorage();
    mockedGenerate.mockImplementation(async (args) => makePromptInjectionResult(args.cveId));

    await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    const errorRows = fs.inserts.filter((i) => i.table === 'extraction_step_errors');
    const piRow = errorRows.find((r) => r.row.code === 'prompt_injection_suspect');
    expect(piRow).toBeDefined();
    expect(piRow!.row).toMatchObject({
      step: 'rule_generation',
      code: 'prompt_injection_suspect',
      severity: 'warn',
      extraction_job_id: JOB_ID,
      project_id: PROJECT_ID,
    });
    expect(String(piRow!.row.message)).toContain('CVE-9999-9999');
  });

  it('writes organization_generated_rules stub row with terminal_reason=prompt_injection_suspect and framework_spec={}', async () => {
    const fs = makeStorage();
    mockedGenerate.mockImplementation(async (args) => makePromptInjectionResult(args.cveId));

    await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    const ruleRows = fs.inserts.filter((i) => i.table === 'organization_generated_rules');
    expect(ruleRows.length).toBe(1);
    const stub = ruleRows[0].row;
    expect(stub).toMatchObject({
      organization_id: ORG_ID,
      cve_id: 'CVE-9999-9999',
      validation_status: 'failed_validation',
      enabled: false,
      spec_format: 'framework_spec',
    });
    // P0-B / P1-C: ruleless-but-persistable rows need framework_spec={} so the
    // spec_shape_chk CHECK constraint passes.
    expect(stub.framework_spec).toEqual({});
    expect(stub.validation_log).toMatchObject({
      terminal_reason: 'prompt_injection_suspect',
    });
  });

  it('persists stub rows for OTHER ruleless-but-persistable statuses (no_advisory) tagged with terminal_reason', async () => {
    // Pins the broader contract: PERSIST_RULELESS_STATUSES includes
    // no_advisory / no_fix_commit / fetch_failed / vuln_class_out_of_scope.
    // Without this the org-settings UI has no record that we tried the CVE.
    const fs = makeStorage();
    mockedGenerate.mockImplementation(async (args) => ({
      status: 'no_advisory',
      cveId: args.cveId,
      packagePurl: args.packagePurl,
      ecosystem: args.ecosystem,
      rule: undefined,
      generatedWith: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
      costUsd: 0,
      inputTokens: 0,
      outputTokens: 0,
      errors: ['osv_fetch: advisory not found'],
      promptVersion: 'test',
      validationBreakdown: PRE_ATTEMPT_BREAKDOWN,
      attempts: 0,
    }));

    await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    const ruleRows = fs.inserts.filter((i) => i.table === 'organization_generated_rules');
    expect(ruleRows.length).toBe(1);
    expect(ruleRows[0].row).toMatchObject({
      validation_status: 'failed_validation',
      enabled: false,
    });
    expect(ruleRows[0].row.framework_spec).toEqual({});
    expect(ruleRows[0].row.validation_log).toMatchObject({
      terminal_reason: 'no_advisory',
    });
  });
});

describe('TG-5 — loadOrgExistingRuleCves null fail-closed early-skip', () => {
  it('returns ran=true with no attempts and writes org_rules_read_failed when the SELECT errors', async () => {
    const fs = makeStorage();
    // Force the organization_generated_rules SELECT (used by
    // loadOrgExistingRuleCves) to return an error. The fail-closed contract
    // says: skip the entire step rather than re-fire generation for every CVE.
    fs.setSelectError('organization_generated_rules', {
      data: null,
      error: { message: 'simulated outage' },
    });

    // generateRuleForCve must NOT be called — the step must bail before
    // reaching candidate dispatch. Configure the mock so a stray call would
    // cause an obvious failure if the contract regresses.
    mockedGenerate.mockImplementation(() => {
      throw new Error('generateRuleForCve should not be called when org rules read fails');
    });

    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: JOB_ID,
        supabase: fs as unknown as Storage,
        log,
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );

    // Step ran (we entered past the settings check) but bailed at the
    // org-rules read with no attempts.
    expect(result.ran).toBe(true);
    expect(result.attempted).toBe(0);
    expect(result.generated).toBe(0);
    expect(result.alreadyCovered).toBe(0);
    // bumpReason('org_rules_read_failed') was hit.
    expect(result.skipReasons.org_rules_read_failed).toBe(1);

    // extraction_step_errors row written with code=org_rules_read_failed.
    const errRow = fs.inserts
      .filter((i) => i.table === 'extraction_step_errors')
      .find((r) => r.row.code === 'org_rules_read_failed');
    expect(errRow).toBeDefined();
    expect(errRow!.row).toMatchObject({
      step: 'rule_generation',
      code: 'org_rules_read_failed',
      severity: 'warn',
      extraction_job_id: JOB_ID,
      project_id: PROJECT_ID,
    });

    // No mid-batch generation — generator was never called.
    expect(mockedGenerate).not.toHaveBeenCalled();
    // No ai_usage_logs spend was incurred either.
    expect(fs.inserts.filter((i) => i.table === 'ai_usage_logs')).toEqual([]);

    // And the operator-visible warn line was emitted.
    const warnMessages = log.warn.mock.calls.map((c) => c[1]);
    expect(warnMessages.some((m: string) => /organization_generated_rules read failed/.test(m))).toBe(true);
  });
});

// SKIPPED — stretch test for provider_outage_suspect aggregate logStepError.
//   Blocker: the per-CVE retry loop in rule-generation-step.ts uses real
//   setTimeout backoffs of [1s, 4s, 16s] = 21s/CVE on transient provider_error.
//   With provider='anthropic' concurrency=1, three failing CVEs serialize for
//   ~63s before the aggregate threshold check fires — exceeds the default
//   60s jest timeout AND the existing test file uses real timers throughout
//   (jest.useFakeTimers() would also need fake-timer-aware withTimeout in
//   with-timeout.ts to not race the AbortController). Skipping rather than
//   pushing test runtime to >60s on every CI run.
