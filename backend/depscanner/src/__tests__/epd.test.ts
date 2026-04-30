process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

import { ENTRY_WEIGHT_BY_CLASS, applyEpdScoringFallback } from '../epd';
import type { EntryPointClassification } from '../epd';
import type { Storage } from '../storage';

describe('ENTRY_WEIGHT_BY_CLASS', () => {
  it('matches the EPD spec (framework-rule-pack-guide)', () => {
    expect(ENTRY_WEIGHT_BY_CLASS.PUBLIC_UNAUTH).toBe(1.0);
    expect(ENTRY_WEIGHT_BY_CLASS.AUTH_INTERNAL).toBe(0.5);
    expect(ENTRY_WEIGHT_BY_CLASS.OFFLINE_WORKER).toBe(0.2);
    expect(ENTRY_WEIGHT_BY_CLASS.UNKNOWN).toBe(1.0);
  });

  it('covers every EntryPointClassification value', () => {
    const classifications: EntryPointClassification[] = [
      'PUBLIC_UNAUTH',
      'AUTH_INTERNAL',
      'OFFLINE_WORKER',
      'UNKNOWN',
    ];
    for (const c of classifications) {
      expect(typeof ENTRY_WEIGHT_BY_CLASS[c]).toBe('number');
      expect(ENTRY_WEIGHT_BY_CLASS[c]).toBeGreaterThan(0);
      expect(ENTRY_WEIGHT_BY_CLASS[c]).toBeLessThanOrEqual(1);
    }
  });

  it('conservative-default: UNKNOWN assumed worst-case (weight 1.0) when AI cannot classify', () => {
    expect(ENTRY_WEIGHT_BY_CLASS.UNKNOWN).toBe(ENTRY_WEIGHT_BY_CLASS.PUBLIC_UNAUTH);
  });

  it('OFFLINE_WORKER under-weighted vs PUBLIC_UNAUTH (offline path deprioritized)', () => {
    expect(ENTRY_WEIGHT_BY_CLASS.OFFLINE_WORKER).toBeLessThan(ENTRY_WEIGHT_BY_CLASS.PUBLIC_UNAUTH);
    expect(ENTRY_WEIGHT_BY_CLASS.OFFLINE_WORKER).toBeLessThan(ENTRY_WEIGHT_BY_CLASS.AUTH_INTERNAL);
  });
});

/**
 * Budget cap resolution: org.epd_max_run_cost_usd (phase24) must win
 * over the EPD_MAX_RUN_COST_USD env var, which itself wins over the
 * built-in $3 default. Regression guard for the change at epd.ts
 * where `getRunBudgetCapUsd()` became `orgRunBudgetCapUsd ?? env ?? default`.
 *
 * We drive applyEpdScoringFallback with no BYOK and one unreachable
 * PDV so the AI path never runs — the only thing we need to assert
 * is the `budget_cap_usd` that lands in the summary log.
 */
describe('applyEpdScoringFallback budget cap resolution', () => {
  /** Returns a minimal Storage that routes reads by table name. */
  function makeStorage(responses: Record<string, { data: unknown; error: unknown } | null>): Storage {
    const chain = (table: string): any => {
      const resp = responses[table] ?? { data: null, error: null };
      const builder: any = {
        select: () => builder,
        eq: () => builder,
        in: () => builder,
        limit: () => builder,
        update: () => builder,
        insert: () => builder,
        upsert: () => builder,
        delete: () => builder,
        single: () => Promise.resolve(resp),
        maybeSingle: () => Promise.resolve(resp),
        then: (resolve: (v: unknown) => void) => {
          resolve(resp);
          return Promise.resolve(resp);
        },
      };
      return builder;
    };
    return {
      from: (t: string) => chain(t),
      rpc: async () => ({ data: null, error: null }),
      storage: { from: () => ({ upload: async () => ({ data: null, error: null }) }) } as any,
    } as unknown as Storage;
  }

  function makeLogger() {
    const calls: Array<{ level: 'info' | 'warn'; step: string; msg: string; meta?: Record<string, unknown> }> = [];
    return {
      calls,
      info: async (step: string, msg: string, meta?: Record<string, unknown>) => {
        calls.push({ level: 'info', step, msg, meta });
      },
      warn: async (step: string, msg: string, meta?: Record<string, unknown>) => {
        calls.push({ level: 'warn', step, msg, meta });
      },
    };
  }

  function makeResponses(orgRow: { epd_max_run_cost_usd: number | null; epd_budget_exceeded_behavior: string | null } | null) {
    return {
      projects: { data: { organization_id: 'org-1' }, error: null },
      organizations: { data: orgRow, error: null },
      organization_ai_providers: { data: null, error: null }, // no BYOK
      project_dependency_vulnerabilities: {
        data: [
          {
            id: 'pdv-1',
            project_dependency_id: 'pd-1',
            is_reachable: false,
            reachability_level: 'unreachable',
            depscore: 10,
            base_depscore_no_reachability: 10,
            severity: 'low',
            summary: 'test',
          },
        ],
        error: null,
      },
      project_dependencies: { data: [], error: null },
      project_reachable_flows: { data: [], error: null },
    };
  }

  // Sandbox env so the tests don't pollute each other.
  const prevCap = process.env.EPD_MAX_RUN_COST_USD;
  const prevBehavior = process.env.EPD_BUDGET_EXCEEDED_BEHAVIOR;
  afterEach(() => {
    if (prevCap === undefined) delete process.env.EPD_MAX_RUN_COST_USD;
    else process.env.EPD_MAX_RUN_COST_USD = prevCap;
    if (prevBehavior === undefined) delete process.env.EPD_BUDGET_EXCEEDED_BEHAVIOR;
    else process.env.EPD_BUDGET_EXCEEDED_BEHAVIOR = prevBehavior;
  });

  function summaryMeta(calls: Array<{ step: string; meta?: Record<string, unknown> }>): Record<string, unknown> | undefined {
    return calls.find((c) => c.step === 'epd' && c.meta?.epd_phase === 'summary')?.meta;
  }

  it('uses org.epd_max_run_cost_usd when set (overrides env)', async () => {
    process.env.EPD_MAX_RUN_COST_USD = '10';
    const storage = makeStorage(makeResponses({ epd_max_run_cost_usd: 7.5, epd_budget_exceeded_behavior: null }));
    const logger = makeLogger();
    await applyEpdScoringFallback(storage, 'proj-1', '/tmp/repo', logger);
    const meta = summaryMeta(logger.calls);
    expect(meta?.budget_cap_usd).toBe(7.5);
  });

  it('falls back to env var when org.epd_max_run_cost_usd is NULL', async () => {
    process.env.EPD_MAX_RUN_COST_USD = '2.5';
    const storage = makeStorage(makeResponses({ epd_max_run_cost_usd: null, epd_budget_exceeded_behavior: null }));
    const logger = makeLogger();
    await applyEpdScoringFallback(storage, 'proj-1', '/tmp/repo', logger);
    const meta = summaryMeta(logger.calls);
    expect(meta?.budget_cap_usd).toBe(2.5);
  });

  it('falls back to built-in $3 default when org and env are both absent', async () => {
    delete process.env.EPD_MAX_RUN_COST_USD;
    const storage = makeStorage(makeResponses({ epd_max_run_cost_usd: null, epd_budget_exceeded_behavior: null }));
    const logger = makeLogger();
    await applyEpdScoringFallback(storage, 'proj-1', '/tmp/repo', logger);
    const meta = summaryMeta(logger.calls);
    expect(meta?.budget_cap_usd).toBe(3.0);
  });

  it('ignores non-finite / non-positive org values and falls back to env', async () => {
    process.env.EPD_MAX_RUN_COST_USD = '4';
    const storage = makeStorage(makeResponses({ epd_max_run_cost_usd: -1, epd_budget_exceeded_behavior: null }));
    const logger = makeLogger();
    await applyEpdScoringFallback(storage, 'proj-1', '/tmp/repo', logger);
    const meta = summaryMeta(logger.calls);
    expect(meta?.budget_cap_usd).toBe(4);
  });

  it('handles org row missing entirely (maybeSingle returns null data)', async () => {
    process.env.EPD_MAX_RUN_COST_USD = '6';
    const storage = makeStorage(makeResponses(null));
    const logger = makeLogger();
    await applyEpdScoringFallback(storage, 'proj-1', '/tmp/repo', logger);
    const meta = summaryMeta(logger.calls);
    expect(meta?.budget_cap_usd).toBe(6);
  });
});
