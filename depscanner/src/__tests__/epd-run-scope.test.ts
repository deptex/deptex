process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

/**
 * R2 — EPD must be run-scoped. The reachability classifier writes PDVs per
 * extraction_run_id; project_dependency_vulnerabilities / project_reachable_flows
 * rows from PRIOR runs are not deleted, so without an extraction_run_id filter
 * the EPD pass aggregates stale-run rows into the current run's scores. These
 * tests pin that, when a runId is threaded, only the current run's PDVs are
 * read and written.
 */

import { applyEpdScoringFallback } from '../epd';
import type { Storage } from '../storage';

interface TableState { rows: any[] }

class FilteringStorage {
  tables: Record<string, TableState> = {};
  upserts: Array<{ table: string; rows: any[] }> = [];

  set(table: string, rows: any[]) { this.tables[table] = { rows }; }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) rows = rows.filter((r) => r[f.col] === f.val);
      return rows;
    };
    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in() { return builder; },
      limit() { return builder; },
      maybeSingle() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      single() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      insert: () => Promise.resolve({ data: null, error: null }),
      upsert: (rows: any) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        this.upserts.push({ table, rows: arr });
        return Promise.resolve({ data: null, error: null });
      },
      update() {
        const up: any = { eq: () => up, then: (f: any) => Promise.resolve({ data: null, error: null }).then(f) };
        return up;
      },
      then(onFulfilled: any) { return Promise.resolve({ data: filterRows(), error: null }).then(onFulfilled); },
    };
    return builder;
  }

  rpc() { return Promise.resolve({ data: null, error: null }); }
  storage = { from: () => ({ upload: async () => ({ data: null, error: null }) }) };
}

function makeLogger() {
  const calls: Array<{ level: string; step: string; msg: string; meta?: Record<string, unknown> }> = [];
  return {
    calls,
    info: async (step: string, msg: string, meta?: Record<string, unknown>) => { calls.push({ level: 'info', step, msg, meta }); },
    warn: async (step: string, msg: string, meta?: Record<string, unknown>) => { calls.push({ level: 'warn', step, msg, meta }); },
  };
}

const PROJECT_ID = 'proj-1';
const CURRENT_RUN = 'run-current';
const STALE_RUN = 'run-stale';

function seed(storage: FilteringStorage) {
  storage.set('projects', [{ id: PROJECT_ID, organization_id: 'org-1', importance: 1.0, framework: null }]);
  storage.set('organizations', [{ id: 'org-1', epd_max_run_cost_usd: null, epd_budget_exceeded_behavior: null }]);
  storage.set('taint_engine_settings', []);
  storage.set('project_dependency_vulnerabilities', [
    {
      id: 'pdv-current', project_id: PROJECT_ID, project_dependency_id: 'pd-1', osv_id: 'CVE-2024-1111',
      extraction_run_id: CURRENT_RUN, is_reachable: true, reachability_level: 'module',
      depscore: 50, base_depscore_no_reachability: 50, severity: 'high', summary: 'cur',
    },
    {
      id: 'pdv-stale', project_id: PROJECT_ID, project_dependency_id: 'pd-1', osv_id: 'CVE-2020-9999',
      extraction_run_id: STALE_RUN, is_reachable: true, reachability_level: 'confirmed',
      depscore: 90, base_depscore_no_reachability: 90, severity: 'critical', summary: 'stale',
    },
  ]);
  storage.set('project_dependencies', [
    { id: 'pd-1', project_id: PROJECT_ID, dependency_id: 'dep-1', last_seen_extraction_run_id: CURRENT_RUN },
  ]);
  storage.set('project_reachable_flows', []);
  storage.set('project_reachable_flow_suppressions', []);
}

beforeEach(() => { delete process.env.ANTHROPIC_API_KEY; });

describe('applyEpdScoringFallback — R2 run-scope', () => {
  it('writes ONLY the current run PDV when runId is threaded', async () => {
    const storage = new FilteringStorage();
    seed(storage);
    const logger = makeLogger();
    await applyEpdScoringFallback(storage as unknown as Storage, PROJECT_ID, '/tmp/repo', logger, 0, undefined, CURRENT_RUN);

    const writtenIds = storage.upserts
      .filter((u) => u.table === 'project_dependency_vulnerabilities')
      .flatMap((u) => u.rows.map((r) => r.id));
    expect(writtenIds).toContain('pdv-current');
    expect(writtenIds).not.toContain('pdv-stale');

    const summary = logger.calls.find((c) => c.step === 'epd' && c.meta?.epd_phase === 'summary');
    expect(summary?.meta?.vulnerabilities_updated).toBe(1);
  });

  it('without a runId (legacy), reads every run (back-compat)', async () => {
    const storage = new FilteringStorage();
    seed(storage);
    const logger = makeLogger();
    await applyEpdScoringFallback(storage as unknown as Storage, PROJECT_ID, '/tmp/repo', logger);

    const summary = logger.calls.find((c) => c.step === 'epd' && c.meta?.epd_phase === 'summary');
    // Both runs' PDVs aggregate when run-scope is not threaded.
    expect(summary?.meta?.vulnerabilities_updated).toBe(2);
  });

  it('threads run-scope into the upsert rows (carries project_id + osv_id)', async () => {
    const storage = new FilteringStorage();
    seed(storage);
    const logger = makeLogger();
    await applyEpdScoringFallback(storage as unknown as Storage, PROJECT_ID, '/tmp/repo', logger, 0, undefined, CURRENT_RUN);
    const row = storage.upserts
      .flatMap((u) => u.rows)
      .find((r) => r.id === 'pdv-current');
    expect(row?.project_id).toBe(PROJECT_ID);
    expect(row?.osv_id).toBe('CVE-2024-1111');
  });
});
