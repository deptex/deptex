/**
 * v3 precision arc — taint-engine callgraph demotes called-but-not-imported
 * transitives.
 *
 * Pins the jackson-vs-idna behavior end-to-end through `updateReachabilityLevels`:
 *   - jackson-style: transitive dep that the source never `import`s but the
 *     callgraph traced a CallEdge into (Spring's request handler calls it).
 *     Must demote from `unreachable` to `module` with
 *     `verdict: 'callgraph_reached_transitive'`.
 *   - idna-style: transitive dep neither imported nor reached by callgraph.
 *     Must stay `unreachable` with the standard
 *     `verdict: 'orphan_transitive_unreachable'`.
 *
 * Also pins the OFF-state contract (the rollback safety promise): when
 * `usedTransitives` is undefined or empty, every transitive must behave
 * identically to the v2 heuristic — both jackson AND idna stay unreachable.
 *
 * Plus the Gate-3 PDV shapes: dev-scope still wins over a callgraph signal;
 * direct deps don't collapse to unreachable; framework-embedded runtimes
 * still floor at module independently; case-insensitive name match.
 */

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';

// --- FakeStorage (mirrors the dev-scope.test.ts pattern, slim variant) ---

interface TableState { rows: any[] }

class FakeStorage {
  tables: Record<string, TableState> = {};
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

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
      maybeSingle() {
        return Promise.resolve({ data: filterRows()[0] ?? null, error: null });
      },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: () => Promise.resolve({ data: null, error: null }),
      // R3: classifier flushes verdicts via a batched upsert — record each row
      // in the same `updates` shape (keyed on id) so verdictFor() is unchanged.
      upsert: (rows: any) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const r of arr) FakeStorage.lastUpdateInsert(this, table, { id: r.id }, r);
        return Promise.resolve({ data: null, error: null });
      },
      update: (values: any) => {
        const currentFilters: Record<string, unknown> = {};
        for (const f of filters) currentFilters[f.col] = f.val;
        const upBuilder: any = {
          eq: (col: string, val: unknown) => { currentFilters[col] = val; return upBuilder; },
          then: (onFulfilled: any) => {
            FakeStorage.lastUpdateInsert(this, table, { ...currentFilters }, values);
            return Promise.resolve({ data: null, error: null }).then(onFulfilled);
          },
        };
        return upBuilder;
      },
      then(onFulfilled: any) {
        return Promise.resolve({ data: filterRows(), error: null }).then(onFulfilled);
      },
    };
    return builder;
  }

  static lastUpdateInsert(
    fsk: FakeStorage,
    table: string,
    filter: Record<string, unknown>,
    values: any,
  ) {
    fsk.updates.push({ table, filter, values });
  }
}

const log = {
  info: jest.fn().mockResolvedValue(undefined),
  success: jest.fn().mockResolvedValue(undefined),
  warn: jest.fn().mockResolvedValue(undefined),
  error: jest.fn().mockResolvedValue(undefined),
};

const PROJECT_ID = 'proj-1';
const RUN_ID = 'run-1';

interface PdvShape {
  pdvId: string;
  pdId: string;
  depId: string;
  depName: string;
  isDirect: boolean;
  filesImporting: number;
  environment?: string | null;
  osvId?: string;
}

function seedMulti(fsk: FakeStorage, pdvs: PdvShape[], usageStrings: string[] = []) {
  fsk.set(
    'project_dependency_findings',
    pdvs.map((p) => ({
      id: p.pdvId,
      project_dependency_id: p.pdId,
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: p.osvId ?? 'CVE-2024-0001',
    })),
  );
  fsk.set(
    'project_dependencies',
    pdvs.map((p) => ({
      id: p.pdId,
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: p.depId,
      dependency_version_id: `dv-${p.depId}`,
      is_direct: p.isDirect,
      files_importing_count: p.filesImporting,
      environment: p.environment ?? null,
      // name/namespace live on project_dependencies — the classifier resolves
      // depName from here (the dependencies table has no namespace column).
      name: p.depName,
      namespace: null,
    })),
  );
  // Dedup by depId so a callgraph-matching jackson-style dep is registered
  // only once in the dependencies table.
  const depRows = Array.from(
    new Map(pdvs.map((p) => [p.depId, { id: p.depId, name: p.depName }])).values(),
  );
  fsk.set('dependencies', depRows);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set(
    'project_usage_slices',
    usageStrings.map((s, i) => ({
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: `src/f${i}.js`,
      line_number: i + 1,
      target_name: s,
      target_type: s,
      resolved_method: s,
    })),
  );
}

function verdictFor(fsk: FakeStorage, pdvId: string) {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_findings' && x.filter.id === pdvId,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('callgraph precision lever — jackson-style demote, idna-style stay', () => {
  it('demotes jackson-style transitive from unreachable to module when callgraph traced it', async () => {
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        // jackson-style: transitive, no first-party import, but the
        // taint-engine callgraph traced a CallEdge into it (Spring's
        // request handler calls jackson).
        {
          pdvId: 'pdv-jackson',
          pdId: 'pd-jackson',
          depId: 'dep-jackson',
          depName: 'jackson-core',
          isDirect: false,
          filesImporting: 0,
        },
      ],
      // Some usage strings present so the AST fail-open guard passes.
      ['someApp.routes.handle'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      { usedTransitives: new Set(['jackson-core']) },
    );
    const v = verdictFor(fsk, 'pdv-jackson');
    expect(v.level).toBe('module');
    expect(v.details?.verdict).toBe('callgraph_reached_transitive');
    expect(v.details?.callgraph_evidence?.dep_name).toBe('jackson-core');
  });

  it('keeps idna-style transitive unreachable when callgraph found nothing', async () => {
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-idna',
          pdId: 'pd-idna',
          depId: 'dep-idna',
          depName: 'idna',
          isDirect: false,
          filesImporting: 0,
        },
      ],
      ['someApp.cat'],
    );
    // Empty set or undefined produces the same behavior (no signal).
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      { usedTransitives: new Set() },
    );
    const v = verdictFor(fsk, 'pdv-idna');
    expect(v.level).toBe('unreachable');
    expect(v.details?.verdict).toBe('orphan_transitive_unreachable');
  });

  it('still demotes idna-style transitive to unreachable when callgraph has other deps but not this one', async () => {
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-idna',
          pdId: 'pd-idna',
          depId: 'dep-idna',
          depName: 'idna',
          isDirect: false,
          filesImporting: 0,
        },
      ],
      ['someApp.cat'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      // Callgraph reached lodash and chalk, but not idna.
      { usedTransitives: new Set(['lodash', 'chalk']) },
    );
    const v = verdictFor(fsk, 'pdv-idna');
    expect(v.level).toBe('unreachable');
    expect(v.details?.verdict).toBe('orphan_transitive_unreachable');
  });

  it('case-insensitive match — depName Jackson-Core matches set entry jackson-core', async () => {
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-jc',
          pdId: 'pd-jc',
          depId: 'dep-jc',
          depName: 'Jackson-Core',
          isDirect: false,
          filesImporting: 0,
        },
      ],
      ['app.handle'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      { usedTransitives: new Set(['jackson-core']) },
    );
    expect(verdictFor(fsk, 'pdv-jc').level).toBe('module');
  });
});

describe('OFF-state byte-stability — v2 behavior recovers when usedTransitives is missing/empty', () => {
  // The plan's main rollback safety claim. Two parallel PDVs (jackson-style
  // + idna-style) get classified twice: once with usedTransitives populated,
  // once with it undefined. The OFF run must produce v2-identical verdicts.

  async function classify(usedTransitives: Set<string> | undefined) {
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-j',
          pdId: 'pd-j',
          depId: 'dep-j',
          depName: 'jackson-core',
          isDirect: false,
          filesImporting: 0,
        },
        {
          pdvId: 'pdv-i',
          pdId: 'pd-i',
          depId: 'dep-i',
          depName: 'idna',
          isDirect: false,
          filesImporting: 0,
        },
      ],
      ['app.handle'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      { usedTransitives },
    );
    return {
      jackson: verdictFor(fsk, 'pdv-j').level,
      idna: verdictFor(fsk, 'pdv-i').level,
    };
  }

  it('OFF (undefined): both stay unreachable — v2 baseline', async () => {
    const v = await classify(undefined);
    expect(v.jackson).toBe('unreachable');
    expect(v.idna).toBe('unreachable');
  });

  it('OFF (empty Set): same as undefined — empty == "no signal"', async () => {
    const v = await classify(new Set());
    expect(v.jackson).toBe('unreachable');
    expect(v.idna).toBe('unreachable');
  });

  it('ON: jackson demotes, idna stays — proves the lever moves only the right one', async () => {
    const v = await classify(new Set(['jackson-core']));
    expect(v.jackson).toBe('module');
    expect(v.idna).toBe('unreachable');
  });
});

describe('Gate-3 PDV shapes — precision lever never produces false negatives', () => {
  it('dev-scope still wins over callgraph signal (precision does not override dev floor)', async () => {
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-dev',
          pdId: 'pd-dev',
          depId: 'dep-dev',
          depName: 'lodash',
          isDirect: false,
          filesImporting: 0,
          environment: 'dev',
        },
      ],
      ['app.handle'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      // Even if callgraph reached lodash, dev-scope keeps it unreachable.
      // dev-scope's intent is "not on prod call path"; a callgraph edge from
      // a test helper does not contradict that.
      { usedTransitives: new Set(['lodash']) },
    );
    const v = verdictFor(fsk, 'pdv-dev');
    expect(v.level).toBe('unreachable');
    expect(v.details?.verdict).toBe('dev_scope_unreachable');
  });

  it('direct deps never collapse to unreachable regardless of callgraph signal', async () => {
    // express-the-direct-dep can never be "unreachable" — it's literally
    // in package.json's dependencies block. The heuristic preconditions
    // exclude it via !meta.isDirect.
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-direct',
          pdId: 'pd-direct',
          depId: 'dep-direct',
          depName: 'express',
          isDirect: true,
          filesImporting: 1,
        },
      ],
      ['app.express'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      { usedTransitives: new Set() },
    );
    const v = verdictFor(fsk, 'pdv-direct');
    // Direct + imported → at least module, never unreachable.
    expect(['module', 'function', 'data_flow', 'confirmed']).toContain(v.level);
    expect(v.level).not.toBe('unreachable');
  });

  it('transitive WITH non-zero filesImporting bypasses heuristicUnreachable entirely', async () => {
    // The heuristicUnreachable predicate requires filesImporting === 0.
    // A transitive that source code imports somewhere does NOT enter the
    // unreachable branch at all — falls through to module via isDepUsed.
    const fsk = new FakeStorage();
    seedMulti(
      fsk,
      [
        {
          pdvId: 'pdv-imp',
          pdId: 'pd-imp',
          depId: 'dep-imp',
          depName: 'request',
          isDirect: false,
          filesImporting: 3,
        },
      ],
      ['app.request', 'requestSync'],
    );
    await updateReachabilityLevels(
      PROJECT_ID,
      RUN_ID,
      fsk as unknown as Storage,
      log,
      undefined,
      // Even with no callgraph signal, this stays module (or function via
      // isDepUsed). Never unreachable.
      { usedTransitives: new Set() },
    );
    const v = verdictFor(fsk, 'pdv-imp');
    expect(v.level).not.toBe('unreachable');
  });
});
