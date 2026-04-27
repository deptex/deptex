/**
 * Tests for the trigger-policy + budget-cap behaviors of the
 * rule_generation pipeline step. We don't exercise the AI call here —
 * the heavier integration test in M5 covers that with a mock provider.
 *
 * The tests use a hand-rolled FakeStorage that mirrors just enough of
 * the Storage abstraction (from/select/eq/in/maybeSingle) to drive the
 * step's queries deterministically.
 */

import { runRuleGenerationStep, type PipelineVulnRow } from '../rule-generation-step';
import type { Storage } from '../storage';

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
  fs.set('extraction_jobs', [{ id: 'job-1' }]);
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

  it('warns + skips when no BYOK key is resolvable', async () => {
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
      expect.stringContaining('No BYOK key for anthropic'),
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
