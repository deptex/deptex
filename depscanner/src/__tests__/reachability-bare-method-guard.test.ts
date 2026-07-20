/**
 * Bare-common-method guard for the usage-heuristic `function` tier.
 *
 * The name-match heuristic in `updateReachabilityLevels` promotes a CVE to
 * `function` when the vulnerable dependency's name appears (by substring) in a
 * project usage slice. That over-promotes when the CVE's vulnerable surface is
 * a bare, extremely-common method name (`error`, `get`, `handle`, …): ANY
 * like-named call anywhere in the project — even on a totally unrelated class —
 * lifts the finding to a visible, "reachable" verdict.
 *
 * The canonical miss: symfony/demo CVE-2020-5274 (real sink = TwigBundle
 * `ExceptionController::showAction`) was promoted to `function` because its
 * generated sink method `error` substring-matched the Console
 * `Symfony\Component\Console\Style\SymfonyStyle->error()` call at
 * `CheckRequirementsSubscriber.php:67` — an arbitrary same-named call. The live
 * scan's `reachability_details` were
 * `{ methods_called: ["error"], usage_count: 1, impacted_paths: 1,
 *    locations: [{ line: 67, method: "error" }] }`.
 *
 * These tests pin the guard: a bare common method alone no longer promotes,
 * while a distinctive method OR a receiver/class that names the dependency
 * still does.
 */

import { updateReachabilityLevels, bareMethodName, COMMON_BARE_METHODS } from '../reachability';
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

interface UsageSpec {
  target_type: string;
  resolved_method: string;
}

/**
 * Seed one direct, imported PDV (no flows, no CVE sink spec) so the classifier
 * falls through to the usage-name-match heuristic, plus the given usage slices.
 */
function seed(fs: FakeStorage, depName: string, usages: UsageSpec[]) {
  const CVE = `CVE-2020-${depName}`;
  fs.set('project_dependency_findings', [
    { id: 'pdv-1', project_dependency_id: 'pd-1', project_id: PROJECT_ID, extraction_run_id: RUN_ID, osv_id: CVE },
  ]);
  fs.set('project_dependencies', [
    {
      id: 'pd-1',
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: 'dep-1',
      dependency_version_id: 'dv-1',
      is_direct: true,
      files_importing_count: 1,
      environment: null,
      name: depName,
      namespace: null,
    },
  ]);
  fs.set('dependencies', [{ id: 'dep-1', name: depName }]);
  fs.set('project_reachable_flows', []);
  fs.set('project_reachable_flow_suppressions', []);
  fs.set('dependency_version_edges', []);
  fs.set(
    'project_usage_slices',
    usages.map((u, i) => ({
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: `src/f${i}.php`,
      line_number: i + 67,
      target_name: u.target_type,
      target_type: u.target_type,
      resolved_method: u.resolved_method,
    })),
  );
}

function verdict(fs: FakeStorage): { level?: string; details?: any } {
  const row = fs.updates.find(
    (u) => u.table === 'project_dependency_findings' && u.filter.id === 'pdv-1',
  );
  return { level: row?.values.reachability_level, details: row?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('bareMethodName', () => {
  it('reduces dotted / :: / -> / bare callees to the trailing method', () => {
    expect(bareMethodName('org.apache.logging.log4j.Logger.error')).toBe('error');
    expect(bareMethodName('Symfony\\Component\\Console\\Style\\SymfonyStyle::error')).toBe('error');
    expect(bareMethodName('mapper->readValue')).toBe('readvalue');
    expect(bareMethodName('error')).toBe('error');
    expect(bareMethodName('')).toBe('');
    expect(bareMethodName(null)).toBe('');
  });
  it('lists ambiguous verbs but not distinctive/deserialization ones', () => {
    for (const m of ['error', 'warn', 'get', 'set', 'handle', 'send', 'render']) {
      expect(COMMON_BARE_METHODS.has(m)).toBe(true);
    }
    for (const m of ['readvalue', 'load', 'unserialize', 'deserialize', 'template', 'safeload', 'query']) {
      expect(COMMON_BARE_METHODS.has(m)).toBe(false);
    }
  });
});

describe('updateReachabilityLevels — bare-common-method guard', () => {
  it('does NOT promote when the only match is a bare `error` on an unrelated class (symfony/demo CVE-2020-5274)', async () => {
    const fs = new FakeStorage();
    // `error-handler`'s first segment `error` substring-matches the bare Console
    // `error()` method — the exact live-scan collision. Receiver is SymfonyStyle
    // (Console), which does not name the dependency.
    seed(fs, 'error-handler', [
      { target_type: 'Symfony\\Component\\Console\\Style\\SymfonyStyle', resolved_method: 'error' },
    ]);
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {});
    const v = verdict(fs);
    expect(v.level).toBe('module');
    expect(v.level).not.toBe('function');
    // No invented function-tier details from the ambiguous collision.
    expect(v.details?.methods_called).toBeUndefined();
  });

  it('still promotes when the matched call has a distinctive method (jackson readValue)', async () => {
    const fs = new FakeStorage();
    seed(fs, 'jackson-databind', [
      { target_type: 'com.fasterxml.jackson.databind.ObjectMapper', resolved_method: 'readValue' },
    ]);
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {});
    expect(verdict(fs).level).toBe('function');
  });

  it('still promotes a bare `error` when the receiver/class names the dependency (log4j Logger.error)', async () => {
    const fs = new FakeStorage();
    seed(fs, 'log4j-core', [
      { target_type: 'org.apache.logging.log4j.Logger', resolved_method: 'error' },
    ]);
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      ecosystem: 'maven',
    });
    expect(verdict(fs).level).toBe('function');
  });

  it('still promotes a deserialization verb (`load`) — not on the denylist (snakeyaml)', async () => {
    const fs = new FakeStorage();
    seed(fs, 'snakeyaml', [
      { target_type: 'org.yaml.snakeyaml.Yaml', resolved_method: 'load' },
    ]);
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {
      ecosystem: 'maven',
    });
    expect(verdict(fs).level).toBe('function');
  });

  it('does NOT promote when the dep-name first segment IS a bare common verb colliding with an unrelated call (`send-mail` → `send`)', async () => {
    const fs = new FakeStorage();
    // `send-mail` first segment `send` (a denylisted bare verb) substring-matches
    // the app's own `Transport->send()`. The dep-name token `send` is itself a
    // common word, so it cannot self-qualify — the receiver `App\Mailer\Transport`
    // does not name the dependency. Guard keeps this at `module`.
    seed(fs, 'send-mail', [
      { target_type: 'App\\Mailer\\Transport', resolved_method: 'send' },
    ]);
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fs as unknown as Storage, log as any, undefined, {});
    expect(verdict(fs).level).toBe('module');
  });
});
