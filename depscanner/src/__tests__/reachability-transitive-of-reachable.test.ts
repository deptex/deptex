/**
 * R1 — transitive-of-reachable floor + R5 — token-boundary isDepUsed.
 *
 * R1: a prod transitive that nothing in the source imports
 * (files_importing_count === 0) is collapsed to `unreachable` by the
 * import-absence heuristic even though it executes via its parent
 * (form-data←axios, qs←express). When the global `dependency_version_edges`
 * graph shows a reachable parent, the classifier floors it at `module`
 * (verdict `transitive_of_reachable`) instead. A genuine orphan (no reachable
 * parent / no edges) and a dev-scope dep are NEVER promoted.
 *
 * R5: the usage-heuristic name match is token-boundary, not raw substring, so
 * a short/generic dep name (`ms`) no longer fuzzy-matches the middle of an
 * unrelated identifier (`params`), while a real package-segment match
 * (`log4j-core`→`log4j`) still lands.
 */

import { updateReachabilityLevels, tokenBoundaryIncludes } from '../reachability';
import type { Storage } from '../storage';

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
      maybeSingle() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: () => Promise.resolve({ data: null, error: null }),
      upsert: (rows: any) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const r of arr) this.updates.push({ table, filter: { id: r.id }, values: r });
        return Promise.resolve({ data: null, error: null });
      },
      update: (values: any) => {
        const currentFilters: Record<string, unknown> = {};
        for (const f of filters) currentFilters[f.col] = f.val;
        const upBuilder: any = {
          eq: (col: string, val: unknown) => { currentFilters[col] = val; return upBuilder; },
          then: (onFulfilled: any) => {
            this.updates.push({ table, filter: { ...currentFilters }, values });
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
}

const log = {
  info: jest.fn().mockResolvedValue(undefined),
  success: jest.fn().mockResolvedValue(undefined),
  warn: jest.fn().mockResolvedValue(undefined),
  error: jest.fn().mockResolvedValue(undefined),
};

const PROJECT_ID = 'proj-1';
const RUN_ID = 'run-1';

interface DepSpec {
  pdvId?: string;       // present ⇒ seed a PDV on this dep
  pdId: string;
  depId: string;
  name: string;
  versionId: string;
  isDirect: boolean;
  filesImporting: number;
  environment?: string | null;
}

function seed(
  fsk: FakeStorage,
  deps: DepSpec[],
  edges: Array<[string, string]>,        // [parentVersionId, childVersionId]
  usageStrings: string[] = ['someApp.handler'],
) {
  fsk.set(
    'project_dependency_vulnerabilities',
    deps.filter((d) => d.pdvId).map((d) => ({
      id: d.pdvId,
      project_dependency_id: d.pdId,
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: `CVE-2024-${d.pdId}`,
    })),
  );
  fsk.set(
    'project_dependencies',
    deps.map((d) => ({
      id: d.pdId,
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: d.depId,
      dependency_version_id: d.versionId,
      is_direct: d.isDirect,
      files_importing_count: d.filesImporting,
      environment: d.environment ?? null,
      name: d.name,
      namespace: null,
    })),
  );
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set(
    'dependency_version_edges',
    edges.map(([parent, child]) => ({ parent_version_id: parent, child_version_id: child })),
  );
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

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_vulnerabilities' && x.filter.id === pdvId,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('R1 — transitive-of-reachable floor', () => {
  it('floors a transitive at `module` when its parent version is reachable (form-data←axios)', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [
        // axios: direct + imported ⇒ a reachable seed (>= module on its own merits).
        { pdId: 'pd-axios', depId: 'dep-axios', name: 'axios', versionId: 'dv-axios', isDirect: true, filesImporting: 1 },
        // form-data: transitive, imported by no file ⇒ would be `unreachable`.
        { pdvId: 'pdv-formdata', pdId: 'pd-formdata', depId: 'dep-formdata', name: 'form-data', versionId: 'dv-formdata', isDirect: false, filesImporting: 0 },
      ],
      [['dv-axios', 'dv-formdata']],
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    const { level, details } = verdictOf(fsk, 'pdv-formdata');
    expect(level).toBe('module');
    expect(details?.verdict).toBe('transitive_of_reachable');
  });

  it('promotes a deeper transitive through a chain of reachable parents', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [
        { pdId: 'pd-express', depId: 'dep-express', name: 'express', versionId: 'dv-express', isDirect: true, filesImporting: 2 },
        { pdId: 'pd-bodyparser', depId: 'dep-bp', name: 'body-parser', versionId: 'dv-bp', isDirect: false, filesImporting: 0 },
        { pdvId: 'pdv-qs', pdId: 'pd-qs', depId: 'dep-qs', name: 'qs', versionId: 'dv-qs', isDirect: false, filesImporting: 0 },
      ],
      [['dv-express', 'dv-bp'], ['dv-bp', 'dv-qs']],
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    // qs is two hops from the reachable root express, via body-parser.
    expect(verdictOf(fsk, 'pdv-qs').level).toBe('module');
  });

  it('leaves a genuine orphan transitive `unreachable` (no reachable parent / no edge)', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [
        { pdId: 'pd-axios', depId: 'dep-axios', name: 'axios', versionId: 'dv-axios', isDirect: true, filesImporting: 1 },
        { pdvId: 'pdv-orphan', pdId: 'pd-orphan', depId: 'dep-orphan', name: 'left-pad', versionId: 'dv-orphan', isDirect: false, filesImporting: 0 },
      ],
      [], // no edges at all → do-not-guess gate keeps current behaviour
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    const { level, details } = verdictOf(fsk, 'pdv-orphan');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('orphan_transitive_unreachable');
  });

  it('does NOT promote when the only parent is itself unreachable (orphan parent)', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [
        // parent is itself a transitive orphan (not imported) → not a seed.
        { pdId: 'pd-parent', depId: 'dep-parent', name: 'unused-parent', versionId: 'dv-parent', isDirect: false, filesImporting: 0 },
        { pdvId: 'pdv-child', pdId: 'pd-child', depId: 'dep-child', name: 'unused-child', versionId: 'dv-child', isDirect: false, filesImporting: 0 },
      ],
      [['dv-parent', 'dv-child']],
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    expect(verdictOf(fsk, 'pdv-child').level).toBe('unreachable');
  });

  it('NEVER promotes a dev-scope transitive even with a reachable parent edge', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [
        { pdId: 'pd-axios', depId: 'dep-axios', name: 'axios', versionId: 'dv-axios', isDirect: true, filesImporting: 1 },
        { pdvId: 'pdv-dev', pdId: 'pd-dev', depId: 'dep-dev', name: 'form-data', versionId: 'dv-dev', isDirect: false, filesImporting: 0, environment: 'dev' },
      ],
      [['dv-axios', 'dv-dev']],
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    const { level, details } = verdictOf(fsk, 'pdv-dev');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('dev_scope_unreachable');
  });

  it('R3 batch: two PDVs in one run each get their own value via the batched upsert', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [
        { pdId: 'pd-axios', depId: 'dep-axios', name: 'axios', versionId: 'dv-axios', isDirect: true, filesImporting: 1 },
        { pdvId: 'pdv-formdata', pdId: 'pd-formdata', depId: 'dep-formdata', name: 'form-data', versionId: 'dv-formdata', isDirect: false, filesImporting: 0 },
        { pdvId: 'pdv-orphan', pdId: 'pd-orphan', depId: 'dep-orphan', name: 'left-pad', versionId: 'dv-orphan', isDirect: false, filesImporting: 0 },
      ],
      [['dv-axios', 'dv-formdata']], // form-data reachable, left-pad not
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    expect(verdictOf(fsk, 'pdv-formdata').level).toBe('module');
    expect(verdictOf(fsk, 'pdv-formdata').details?.verdict).toBe('transitive_of_reachable');
    expect(verdictOf(fsk, 'pdv-orphan').level).toBe('unreachable');
    expect(verdictOf(fsk, 'pdv-orphan').details?.verdict).toBe('orphan_transitive_unreachable');
  });
});

describe('R5 — token-boundary isDepUsed (via updateReachabilityLevels)', () => {
  it('still promotes a real package-segment match (log4j-core → log4j) to `function`', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [{ pdvId: 'pdv-log4j', pdId: 'pd-log4j', depId: 'dep-log4j', name: 'log4j-core', versionId: 'dv-log4j', isDirect: true, filesImporting: 1 }],
      [],
      ['org.apache.logging.log4j.logger'],
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'maven',
    });
    expect(verdictOf(fsk, 'pdv-log4j').level).toBe('function');
  });

  it('drops a spurious substring hit (dep `ms` inside `params`) — stays `module`, not `function`', async () => {
    const fsk = new FakeStorage();
    seed(
      fsk,
      [{ pdvId: 'pdv-ms', pdId: 'pd-ms', depId: 'dep-ms', name: 'ms', versionId: 'dv-ms', isDirect: true, filesImporting: 1 }],
      [],
      ['params.format'],
    );
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'npm',
    });
    // Old raw-substring match would have lifted this to `function`.
    expect(verdictOf(fsk, 'pdv-ms').level).toBe('module');
  });
});

describe('tokenBoundaryIncludes', () => {
  it('matches on package-segment boundaries only', () => {
    expect(tokenBoundaryIncludes('org.apache.logging.log4j.logger', 'log4j')).toBe(true);
    expect(tokenBoundaryIncludes('com.fasterxml.jackson.databind.objectmapper', 'jackson.databind')).toBe(true);
    expect(tokenBoundaryIncludes('lodash.merge', 'lodash')).toBe(true);
    expect(tokenBoundaryIncludes('lodash', 'lodash')).toBe(true);
  });

  it('rejects matches buried inside a larger identifier token', () => {
    expect(tokenBoundaryIncludes('params.format', 'ms')).toBe(false);
    expect(tokenBoundaryIncludes('log4j2.logger', 'log4j')).toBe(false); // log4j ≠ log4j2
    expect(tokenBoundaryIncludes('reactrouter', 'react')).toBe(false);
    expect(tokenBoundaryIncludes('', 'react')).toBe(false);
    expect(tokenBoundaryIncludes('react', '')).toBe(false);
  });
});
