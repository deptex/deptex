/**
 * Function-tier vulnerable-symbol matching.
 *
 * When a CVE-targeted FrameworkSpec sink loaded for a PDV's CVE, the
 * reachability classifier verifies whether that CVE's *specific* vulnerable
 * symbol is on a call path — rather than the weaker "package name appears
 * somewhere" heuristic. These tests pin:
 *
 *   - `extractSymbolTokens` — pattern → match tokens.
 *   - symbol present in usage  → `function`.
 *   - symbol absent + dep imported + usage produced output → `unreachable`.
 *   - symbol absent + no usage output → `module` (fail-safe floor).
 *   - no CVE spec for the osv_id → unchanged package-name heuristic.
 *   - graphTrusted=false floors the transitive-unreachable verdict at `module`.
 */

import { updateReachabilityLevels, extractSymbolTokens } from '../reachability';
import type { Storage } from '../storage';

interface TableState {
  rows: any[];
}

class FakeStorage {
  tables: Record<string, TableState> = {};
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const inFilters: Array<{ col: string; vals: readonly unknown[] }> = [];

    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) rows = rows.filter((r) => r[f.col] === f.val);
      for (const f of inFilters) rows = rows.filter((r) => f.vals.includes(r[f.col]));
      return rows;
    };

    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in(col: string, vals: readonly unknown[]) { inFilters.push({ col, vals }); return builder; },
      maybeSingle() {
        const rows = filterRows();
        return Promise.resolve({ data: rows[0] ?? null, error: null });
      },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: () => Promise.resolve({ data: null, error: null }),
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
const DEP_ID = 'dep-jsyaml';
const PD_ID = 'pd-1';
const PDV_ID = 'pdv-1';
const CVE = 'CVE-2020-14343';

/** Seed a PDV + its project_dependency + dependency name. No flows — the
 *  classifier falls through to the heuristic / symbol-match branch. */
function seed(
  fs: FakeStorage,
  opts: { isDirect?: boolean; filesImporting?: number; usageStrings?: string[] } = {},
) {
  fs.set('project_dependency_vulnerabilities', [
    { id: PDV_ID, project_dependency_id: PD_ID, project_id: PROJECT_ID, extraction_run_id: RUN_ID, osv_id: CVE },
  ]);
  fs.set('project_dependencies', [
    {
      id: PD_ID,
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: DEP_ID,
      is_direct: opts.isDirect ?? true,
      files_importing_count: opts.filesImporting ?? 1,
    },
  ]);
  fs.set('dependencies', [{ id: DEP_ID, name: 'js-yaml' }]);
  fs.set('project_reachable_flows', []);
  fs.set('project_reachable_flow_suppressions', []);
  fs.set(
    'project_usage_slices',
    (opts.usageStrings ?? []).map((s, i) => ({
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

function levelOf(fs: FakeStorage): string | undefined {
  return fs.updates.find((u) => u.table === 'project_dependency_vulnerabilities' && u.filter.id === PDV_ID)
    ?.values.reachability_level;
}

beforeEach(() => jest.clearAllMocks());

describe('extractSymbolTokens', () => {
  it('strips the (*) call placeholder and yields dotted + last-segment tokens', () => {
    expect(extractSymbolTokens('yaml.load(*)').sort()).toEqual(['load', 'yaml.load']);
  });
  it('handles a bare callee with no namespace', () => {
    expect(extractSymbolTokens('eval(*)')).toEqual(['eval']);
  });
  it('strips a trailing .* prefix-match marker', () => {
    expect(extractSymbolTokens('lodash.template.*').sort()).toEqual(['lodash.template', 'template']);
  });
  it('drops segments shorter than 3 chars as too generic', () => {
    // last segment `go` is 2 chars — only the full dotted token survives.
    expect(extractSymbolTokens('pkg.go')).toEqual(['pkg.go']);
  });
});

describe('updateReachabilityLevels — CVE-targeted symbol matching', () => {
  it('assigns `function` when the vulnerable symbol is present in usage', async () => {
    const fs = new FakeStorage();
    seed(fs, { usageStrings: ['yaml.load', 'console.log'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      cveSinkPatterns: new Map([[CVE, ['yaml.load(*)']]]),
    });
    expect(levelOf(fs)).toBe('function');
  });

  it('demotes to `unreachable` when the dep is imported but the symbol is absent', async () => {
    const fs = new FakeStorage();
    // usage produced output (non-empty) and the dep is imported (filesImporting>0),
    // but no usage string contains the vulnerable symbol.
    seed(fs, { filesImporting: 2, usageStrings: ['express.get', 'console.log'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      cveSinkPatterns: new Map([[CVE, ['yaml.load(*)']]]),
    });
    expect(levelOf(fs)).toBe('unreachable');
  });

  it('floors at `module` when usage analysis produced no output', async () => {
    const fs = new FakeStorage();
    seed(fs, { filesImporting: 2, usageStrings: [] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      cveSinkPatterns: new Map([[CVE, ['yaml.load(*)']]]),
    });
    expect(levelOf(fs)).toBe('module');
  });

  it('falls back to the package-name heuristic when no CVE spec loaded for the osv_id', async () => {
    const fs = new FakeStorage();
    // No cveSinkPatterns entry → name-match path. `js-yaml` appears in usage
    // → legacy `function` tier (package used, symbol unverified).
    seed(fs, { usageStrings: ['js-yaml.safeLoad'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      cveSinkPatterns: new Map(),
    });
    expect(levelOf(fs)).toBe('function');
  });

  it('floors at `module` when graphTrusted is false even for a transitive unused dep', async () => {
    const fs = new FakeStorage();
    // Transitive, zero imports, usage produced output → would be `unreachable`,
    // but an untrusted dependency graph must floor it at `module`.
    seed(fs, { isDirect: false, filesImporting: 0, usageStrings: ['console.log'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      graphTrusted: false,
    });
    expect(levelOf(fs)).toBe('module');
  });

  it('marks a transitive unused dep `unreachable` when the graph is trusted', async () => {
    const fs = new FakeStorage();
    seed(fs, { isDirect: false, filesImporting: 0, usageStrings: ['console.log'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      graphTrusted: true,
    });
    expect(levelOf(fs)).toBe('unreachable');
  });
});
