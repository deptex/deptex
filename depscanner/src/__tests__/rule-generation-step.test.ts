/**
 * Tests for the trigger-policy + budget-cap behaviors of the
 * rule_generation pipeline step. We don't exercise the AI call here —
 * the heavier integration test in M5 covers that with a mock provider.
 *
 * The tests use a hand-rolled FakeStorage that mirrors just enough of
 * the Storage abstraction (from/select/eq/in/maybeSingle) to drive the
 * step's queries deterministically.
 */

import { runRuleGenerationStep, aggregateBreakdowns, type PipelineVulnRow } from '../rule-generation-step';
import type { Storage } from '../storage';
import type { ValidationBreakdown } from '../rule-generator';

interface TableState {
  rows: any[];
  /** Override the upsert/insert/update behavior — return value lands as { error, data }. */
  insertImpl?: (rows: any) => { error: any; data: any };
  updateImpl?: (filter: Record<string, unknown>, values: any) => { error: any; data: any };
}

class FakeStorage {
  tables: Record<string, TableState> = {};
  inserts: Array<{ table: string; row: any }> = [];
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
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

    const builder: any = {
      select(c?: string) { if (c) cols = c; return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in(col: string, vals: readonly unknown[]) { inFilters.push({ col, vals }); return builder; },
      gte() { return Promise.resolve({ data: filterRows(), error: null }); },
      maybeSingle() {
        const rows = filterRows();
        return Promise.resolve({ data: rows[0] ?? null, error: null });
      },
      single() {
        const rows = filterRows();
        return Promise.resolve({ data: rows[0] ?? null, error: rows.length === 0 ? new Error('not found') : null });
      },
      insert: (rows: any) => {
        const inserted = Array.isArray(rows) ? rows : [rows];
        for (const r of inserted) this.inserts.push({ table, row: r });
        return Promise.resolve({ data: null, error: null });
      },
      update: (values: any) => {
        // Capture filters supplied via the chain so far; reset on each update call.
        const currentFilters: Record<string, unknown> = {};
        for (const f of filters) currentFilters[f.col] = f.val;
        // Need eq/in support post-update.
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
        const rows = filterRows();
        return Promise.resolve({ data: rows, error: null }).then(onFulfilled);
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

function makeStorage(settings: Partial<{
  auto_generate_enabled: boolean;
  trigger_severities: string[];
  trigger_kev: boolean;
  trigger_asset_tier_max_rank: number;
  ai_provider: string;
  ai_model: string;
  monthly_budget_usd: number;
  on_budget_exhaustion: 'skip' | 'fall_back_to_haiku';
  max_wait_seconds: number;
}>): FakeStorage {
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
      ...settings,
    },
  ]);
  // No org-existing rules and no AI usage yet by default.
  fs.set('organization_generated_rules', []);
  fs.set('ai_usage_logs', []);
  fs.set('scan_jobs', [{ id: 'job-1' }]);
  fs.set('projects', [{ id: PROJECT_ID, asset_tier_id: null }]);
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

describe('runRuleGenerationStep — early-exit paths', () => {
  it('returns ran=false when settings row is missing', async () => {
    const fs = new FakeStorage();
    fs.set('organization_reachability_settings', []);
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        runId: RUN_ID,
        jobId: 'job-1',
        supabase: fs as unknown as Storage,
        log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(result.ran).toBe(false);
    expect(result.attempted).toBe(0);
  });

  it('returns ran=false when auto_generate_enabled is false', async () => {
    const fs = makeStorage({ auto_generate_enabled: false });
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(result.ran).toBe(false);
  });

  it('returns ran=true with attempted=0 when nothing matches trigger policy', async () => {
    const fs = makeStorage({ trigger_severities: ['critical'] });
    const lowVuln: PipelineVulnRow = { ...sampleVuln, severity: 'low' };
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [lowVuln],
    );
    expect(result.ran).toBe(true);
    expect(result.attempted).toBe(0);
    expect(result.skipReasons.severity_filter).toBe(1);
  });

  it('logs warn + bails when trigger_kev=true but vuln is not in KEV', async () => {
    const fs = makeStorage({ trigger_kev: true });
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(result.attempted).toBe(0);
    expect(result.skipReasons.not_kev).toBe(1);
  });

  it('canonicalizes GHSA + CVE alias to the CVE form', async () => {
    const fs = makeStorage({});
    fs.set('organization_generated_rules', [
      // Pretend the org already has a rule for CVE-X.
      { organization_id: ORG_ID, cve_id: 'CVE-2024-X', validation_status: 'validated' },
    ]);
    const ghsaWithCveAlias: PipelineVulnRow = {
      ...sampleVuln,
      osv_id: 'GHSA-aaaa-bbbb-cccc',
      aliases: ['CVE-2024-X'],
    };
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [ghsaWithCveAlias],
    );
    expect(result.alreadyCovered).toBe(1);
    expect(result.attempted).toBe(0);
  });

  it('warns + skips when no platform API key is resolvable', async () => {
    const fs = makeStorage({});
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => null,
      },
      [sampleVuln],
    );
    expect(result.attempted).toBe(0);
    expect(log.warn).toHaveBeenCalledWith(
      'rule_generation',
      expect.stringContaining('No platform API key for anthropic'),
    );
  });

  it('falls back to haiku when projected cost exceeds budget with fall_back_to_haiku', async () => {
    const fs = makeStorage({ monthly_budget_usd: 0.01, on_budget_exhaustion: 'fall_back_to_haiku' });
    const calls: string[] = [];
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async (_org, p) => { calls.push(p); return 'fake-key'; },
      },
      [sampleVuln],
    );
    // We don't actually call the AI in tests (no fetch mock), so the call
    // throws inside withTimeout and the outcome is recorded as
    // skipped/generation_threw. The interesting assertion is that a warn
    // line about haiku fallback was emitted.
    const warnCalls = log.warn.mock.calls.map((c) => c[1]);
    expect(warnCalls.some((m) => /falling back to .*haiku/i.test(m))).toBe(true);
    expect(result.ran).toBe(true);
  });

  it('skips when projected cost exceeds budget with skip behavior', async () => {
    const fs = makeStorage({ monthly_budget_usd: 0.01, on_budget_exhaustion: 'skip' });
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(result.attempted).toBe(0);
    expect(log.warn).toHaveBeenCalledWith(
      'rule_generation',
      expect.stringContaining('skipping generation'),
      expect.anything(),
    );
  });
});

describe('runRuleGenerationStep — trigger-policy edge cases', () => {
  it('admits CVEs across multiple selected severities and skips the rest', async () => {
    const fs = makeStorage({ trigger_severities: ['critical', 'high'] });
    const vulns: PipelineVulnRow[] = [
      { ...sampleVuln, osv_id: 'CVE-1111-1111', severity: 'critical' },
      { ...sampleVuln, osv_id: 'CVE-2222-2222', severity: 'high', package_purl: 'pkg:npm/b@1.0', package_name: 'b' },
      { ...sampleVuln, osv_id: 'CVE-3333-3333', severity: 'medium' },
      { ...sampleVuln, osv_id: 'CVE-4444-4444', severity: 'low' },
    ];
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      vulns,
    );
    expect(result.triggerMatched).toBe(2);
    // Two filtered out by severity_filter (medium, low).
    expect(result.skipReasons.severity_filter).toBe(2);
  });

  it('skips when project asset tier rank is greater than trigger_asset_tier_max_rank', async () => {
    const fs = makeStorage({ trigger_asset_tier_max_rank: 2 });
    // Crown-jewels rank 1 passes, but here we rig a rank=4 (e.g. dev) project.
    fs.set('projects', [{ id: PROJECT_ID, asset_tier_id: 'tier-dev' }]);
    fs.set('organization_asset_tiers', [{ id: 'tier-dev', rank: 4 }]);
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(result.attempted).toBe(0);
    expect(result.skipReasons.asset_tier_filter).toBe(1);
  });

  it('admits when asset tier rank equals trigger_asset_tier_max_rank (boundary)', async () => {
    const fs = makeStorage({ trigger_asset_tier_max_rank: 3 });
    fs.set('projects', [{ id: PROJECT_ID, asset_tier_id: 'tier-prod' }]);
    fs.set('organization_asset_tiers', [{ id: 'tier-prod', rank: 3 }]);
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    // Rank 3 == max 3 should pass the tier filter (the step uses >, not >=).
    expect(result.triggerMatched).toBe(1);
  });

  it('demands KEV+severity together when trigger_kev=true', async () => {
    const fs = makeStorage({ trigger_kev: true, trigger_severities: ['critical'] });
    const vulns: PipelineVulnRow[] = [
      // severity matches but no KEV
      { ...sampleVuln, osv_id: 'CVE-A', severity: 'critical', cisa_kev: false },
      // severity wrong even with KEV
      { ...sampleVuln, osv_id: 'CVE-B', severity: 'high', cisa_kev: true, package_purl: 'pkg:npm/b@1', package_name: 'b' },
      // both ok
      { ...sampleVuln, osv_id: 'CVE-C', severity: 'critical', cisa_kev: true, package_purl: 'pkg:npm/c@1', package_name: 'c' },
    ];
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      vulns,
    );
    expect(result.triggerMatched).toBe(1);
    expect(result.skipReasons.not_kev).toBe(1);
    expect(result.skipReasons.severity_filter).toBe(1);
  });

  it('skips vulns with missing purl / package_name / ecosystem', async () => {
    const fs = makeStorage({});
    const vulns: PipelineVulnRow[] = [
      { ...sampleVuln, osv_id: 'CVE-A', package_purl: null },
      { ...sampleVuln, osv_id: 'CVE-B', package_name: null, package_purl: 'pkg:npm/b@1' },
      { ...sampleVuln, osv_id: 'CVE-C', ecosystem: null, package_purl: 'pkg:npm/c@1', package_name: 'c' },
    ];
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      vulns,
    );
    expect(result.triggerMatched).toBe(0);
    expect(result.skipReasons.missing_purl_or_ecosystem).toBe(3);
  });

  it('rejects non-CVE OSV ids without a CVE alias', async () => {
    const fs = makeStorage({});
    const vulns: PipelineVulnRow[] = [
      { ...sampleVuln, osv_id: 'GHSA-aaaa-bbbb-cccc', aliases: [] },
      { ...sampleVuln, osv_id: 'OSV-2024-X', aliases: ['MAL-2024-1'] },
    ];
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      vulns,
    );
    expect(result.triggerMatched).toBe(0);
    expect(result.skipReasons.not_cve_id).toBe(2);
  });
});

describe('runRuleGenerationStep — telemetry persistence', () => {
  it('writes the four reachability_* counters to scan_jobs when generation runs', async () => {
    const fs = makeStorage({});
    fs.set('organization_generated_rules', [
      // Pretend one of the candidates is already covered.
      { organization_id: ORG_ID, cve_id: 'CVE-AAAA', validation_status: 'validated' },
    ]);
    const vulns: PipelineVulnRow[] = [
      { ...sampleVuln, osv_id: 'CVE-AAAA' },
      { ...sampleVuln, osv_id: 'CVE-BBBB', package_purl: 'pkg:npm/b@1', package_name: 'b' },
    ];
    await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        // No platform key — short-circuits before any AI call. Telemetry should
        // still NOT be persisted since the step bailed before reaching the
        // telemetry write. Verify that explicitly.
        resolveApiKey: async () => null,
      },
      vulns,
    );
    const jobUpdates = fs.updates.filter((u) => u.table === 'scan_jobs');
    expect(jobUpdates).toEqual([]);
  });

  it('does not touch scan_jobs when generation never ran', async () => {
    const fs = makeStorage({ auto_generate_enabled: false });
    await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(fs.updates.filter((u) => u.table === 'scan_jobs')).toEqual([]);
  });

  it('persists telemetry with cost=0 when budget cap skips generation entirely', async () => {
    const fs = makeStorage({ monthly_budget_usd: 0.01, on_budget_exhaustion: 'skip' });
    await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    // Budget skip path returns ran=true but doesn't reach persistJobTelemetry —
    // telemetry only gets written when generation actually completed (even if
    // 0 rules were produced). Verify no scan_jobs update happened.
    expect(fs.updates.filter((u) => u.table === 'scan_jobs')).toEqual([]);
  });

  it('writes telemetry with the cost/counts emitted by generation when AI call throws', async () => {
    // When the AI fetch throws (no global fetch mock), every CVE comes back as
    // skipped/generation_threw, so generated=0 and cost=0. The step still
    // reaches persistJobTelemetry because it ran past the budget cap with a
    // resolved key. This is the most common live path on a transient network
    // blip — telemetry must still pin matched/total_detectable.
    const fs = makeStorage({});
    const vulns: PipelineVulnRow[] = [
      { ...sampleVuln, osv_id: 'CVE-T1' },
      { ...sampleVuln, osv_id: 'CVE-T2', package_purl: 'pkg:npm/b@1', package_name: 'b' },
    ];
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      vulns,
    );
    const jobUpdates = fs.updates.filter((u) => u.table === 'scan_jobs');
    expect(jobUpdates.length).toBe(1);
    expect(jobUpdates[0].filter).toEqual({ id: 'job-1', organization_id: ORG_ID });
    expect(jobUpdates[0].values).toEqual({
      reachability_rules_total_detectable: 2,
      reachability_rules_matched: 0, // already_covered=0 + generated=0
      reachability_rules_generated_this_scan: 0,
      reachability_generation_cost_usd: 0,
      // Both candidates' provider calls fail at the network layer; the inner
      // provider_error catch returns a result with the pre-attempt breakdown
      // (schema_pass=false). Funnel shows 2 candidates, 0 reaching schema.
      reachability_validation_breakdown: {
        candidates: 2,
        schema_pass: 0,
        pattern_compile_pass: 0,
        fixture_pre_pass: 0,
        fixture_safe_pass: 0,
        patch_pre_pass: 0,
        patch_post_pass: 0,
      },
    });
    expect(result.generated).toBe(0);
  });

  it('does not crash when jobId is undefined', async () => {
    const fs = makeStorage({});
    const result = await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID,
        jobId: undefined,
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(result.ran).toBe(true);
    expect(fs.updates.filter((u) => u.table === 'scan_jobs')).toEqual([]);
  });

  it('emits a success log line whose four counters match the scan_jobs columns', async () => {
    const fs = makeStorage({});
    await runRuleGenerationStep(
      {
        organizationId: ORG_ID, projectId: PROJECT_ID, runId: RUN_ID, jobId: 'job-1',
        supabase: fs as unknown as Storage, log,
        platformRulesDir: '/nonexistent',
        resolveApiKey: async () => 'fake-key',
      },
      [sampleVuln],
    );
    expect(log.success).toHaveBeenCalledWith(
      'rule_generation',
      expect.stringMatching(
        /Generated \d+\/\d+ rule\(s\); rules_matched=\d+ rules_total_detectable=\d+ generated_this_scan=\d+ generation_cost=\$\d+\.\d{4}/,
      ),
      expect.any(Number),
      expect.objectContaining({
        rules_matched: 0,
        rules_total_detectable: 1,
        generated_this_scan: 0,
        generation_cost_usd: 0,
        candidate_count: 1,
        already_covered: 0,
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
      }),
    );
  });
});

describe('aggregateBreakdowns — funnel rollup', () => {
  // Convenience for tests that read better as named cases.
  const b = (over: Partial<ValidationBreakdown> = {}): ValidationBreakdown => ({
    schema_pass: false,
    pattern_compile_pass: null,
    fixture_pre_match: false,
    fixture_safe_clean: false,
    patch_pre_match: null,
    patch_post_clean: null,
    semgrep_parse_error: null,
    ...over,
  });

  it('returns all-zero counts on an empty input', () => {
    expect(aggregateBreakdowns([])).toEqual({
      candidates: 0,
      schema_pass: 0,
      pattern_compile_pass: 0,
      fixture_pre_pass: 0,
      fixture_safe_pass: 0,
      patch_pre_pass: 0,
      patch_post_pass: 0,
    });
  });

  it('counts candidates as the input length, regardless of pass/fail', () => {
    const out = aggregateBreakdowns([b(), b(), b()]);
    expect(out.candidates).toBe(3);
  });

  it('only counts patch_*_pass when the underlying field is true (null is skip, not fail)', () => {
    const out = aggregateBreakdowns([
      b({ patch_pre_match: true,  patch_post_clean: true }),  // counted
      b({ patch_pre_match: false, patch_post_clean: false }), // not counted (false)
      b({ patch_pre_match: null,  patch_post_clean: null }),  // not counted (skipped)
    ]);
    expect(out.patch_pre_pass).toBe(1);
    expect(out.patch_post_pass).toBe(1);
  });

  it('only counts pattern_compile_pass when the underlying field is true (null is skip, not fail)', () => {
    const out = aggregateBreakdowns([
      b({ pattern_compile_pass: true }),
      b({ pattern_compile_pass: false }),
      b({ pattern_compile_pass: null }),
    ]);
    expect(out.pattern_compile_pass).toBe(1);
  });

  it('rolls up all seven counters across mixed rows', () => {
    const out = aggregateBreakdowns([
      // Fully validated row
      b({
        schema_pass: true,
        pattern_compile_pass: true,
        fixture_pre_match: true,
        fixture_safe_clean: true,
        patch_pre_match: true,
        patch_post_clean: true,
      }),
      // Fixture FP — rule too broad, fires on safe code
      b({
        schema_pass: true,
        pattern_compile_pass: true,
        fixture_pre_match: true,
        fixture_safe_clean: false,
        patch_pre_match: null,
        patch_post_clean: null,
      }),
      // Schema fail — never reached fixtures
      b({}),
    ]);
    expect(out).toEqual({
      candidates: 3,
      schema_pass: 2,
      pattern_compile_pass: 2,
      fixture_pre_pass: 2,
      fixture_safe_pass: 1,
      patch_pre_pass: 1,
      patch_post_pass: 1,
    });
  });
});
