/**
 * Dependency-scope reachability classification.
 *
 * A dev/test/build-scope dependency's vulnerable code is, by definition, not
 * on the production call path. The classifier floors such a dependency at
 * `unreachable` (depscore weight 0.0), out-ranking the usage heuristic. Scope
 * travels via `project_dependencies.environment` ('dev' | 'prod' | null),
 * derived from the manifest and from transitive dev-only propagation.
 *
 * These tests pin:
 *   - `isDevScoped` — the environment → dev-scope predicate.
 *   - `patchDevDependencies` — cargo `[dev-dependencies]` collection and the
 *     maven `groupId:artifactId` name match.
 *   - `updateReachabilityLevels` — a dev-scope PDV classifies `unreachable`
 *     even with no usage slices, and out-ranks a usage-heuristic `function`
 *     hit; a prod-scope dep is unaffected; an orphan transitive carries the
 *     structured `orphan_transitive_unreachable` verdict.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { updateReachabilityLevels, isDevScoped, DEV_SCOPES } from '../reachability';
import { patchDevDependencies, collectPyprojectDevNames, type ParsedSbomDep } from '../sbom';
import type { Storage } from '../storage';

// --- FakeStorage (self-contained, mirrors reachability-symbol-match.test.ts) -

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
      // R3: the classifier now flushes verdicts via a batched upsert. Record
      // each row in the same `updates` shape (keyed on id) the per-row update
      // path used, so verdictOf() keeps working unchanged.
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
const DEP_ID = 'dep-1';
const PD_ID = 'pd-1';
const PDV_ID = 'pdv-1';

/**
 * Seed a PDV + its project_dependency + dependency name. No flows — the
 * classifier falls through to the scope / heuristic branch.
 */
function seed(
  fsk: FakeStorage,
  opts: {
    environment?: string | null;
    isDirect?: boolean;
    filesImporting?: number;
    depName?: string;
    usageStrings?: string[];
  } = {},
) {
  fsk.set('project_dependency_findings', [
    { id: PDV_ID, project_dependency_id: PD_ID, project_id: PROJECT_ID, extraction_run_id: RUN_ID, osv_id: 'CVE-2024-0001' },
  ]);
  fsk.set('project_dependencies', [
    {
      id: PD_ID,
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: DEP_ID,
      dependency_version_id: 'dv-1',
      is_direct: opts.isDirect ?? true,
      files_importing_count: opts.filesImporting ?? 1,
      environment: opts.environment ?? null,
      // name/namespace live on project_dependencies (dependencies has no
      // namespace) — the classifier resolves depName from here.
      name: opts.depName ?? 'mocha',
      namespace: null,
    },
  ]);
  fsk.set('dependencies', [{ id: DEP_ID, name: opts.depName ?? 'mocha' }]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set(
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

function verdictOf(fsk: FakeStorage): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_findings' && x.filter.id === PDV_ID,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

function mkDep(over: Partial<ParsedSbomDep>): ParsedSbomDep {
  return {
    name: 'x', version: '1.0.0', namespace: null, license: null,
    is_direct: true, source: 'dependencies', devScoped: false, bomRef: 'ref',
    ...over,
  };
}

beforeEach(() => jest.clearAllMocks());

describe('isDevScoped', () => {
  it('is true for the worker\'s "dev" value and false for prod/null/empty (unchanged on real data)', () => {
    expect(isDevScoped('dev')).toBe(true);
    expect(isDevScoped('prod')).toBe(false);
    expect(isDevScoped(null)).toBe(false);
    expect(isDevScoped(undefined)).toBe(false);
    expect(isDevScoped('')).toBe(false);
  });

  // R4 — centralized DEV_SCOPES set: case/whitespace-insensitive + the
  // documented dev/test/build family (none of which the worker writes today,
  // so real-data behaviour is identical).
  it('is robust to case + whitespace variants of "dev"', () => {
    expect(isDevScoped('DEV')).toBe(true);
    expect(isDevScoped(' dev ')).toBe(true);
    expect(isDevScoped('Dev')).toBe(true);
  });

  it('recognizes the documented dev/test/build scope family', () => {
    expect(isDevScoped('development')).toBe(true);
    expect(isDevScoped('test')).toBe(true);
    expect(isDevScoped('build')).toBe(true);
    expect(DEV_SCOPES.has('dev')).toBe(true);
  });

  it('still rejects production-ish scopes', () => {
    expect(isDevScoped('production')).toBe(false);
    expect(isDevScoped('runtime')).toBe(false);
    expect(isDevScoped('optional')).toBe(false);
  });
});

describe('patchDevDependencies — scope detection', () => {
  function withTmpRepo(files: Record<string, string>, run: (dir: string) => void) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'devscope-'));
    try {
      for (const [name, content] of Object.entries(files)) {
        fs.writeFileSync(path.join(dir, name), content);
      }
      run(dir);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  it('flags cargo [dev-dependencies] and [build-dependencies] crates', () => {
    withTmpRepo(
      {
        'Cargo.toml': [
          '[package]',
          'name = "app"',
          '',
          '[dependencies]',
          'serde = "1"',
          '',
          '[dev-dependencies]',
          'assert_cmd = "2"',
          'predicates = { version = "3" }',
          '',
          "[target.'cfg(unix)'.dev-dependencies]",
          'rexpect = "0.5"',
          '',
          '[build-dependencies]',
          'cc = "1"',
        ].join('\n'),
      },
      (dir) => {
        const deps = [
          mkDep({ name: 'serde', is_direct: true }),
          mkDep({ name: 'assert_cmd', is_direct: true }),
          mkDep({ name: 'predicates', is_direct: true }),
          mkDep({ name: 'rexpect', is_direct: true }),
          mkDep({ name: 'cc', is_direct: true }),
        ];
        patchDevDependencies(deps, dir, 'cargo');
        const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
        expect(byName.serde.devScoped).toBe(false);
        expect(byName.assert_cmd.devScoped).toBe(true);
        expect(byName.predicates.devScoped).toBe(true);
        expect(byName.rexpect.devScoped).toBe(true);
        expect(byName.cc.devScoped).toBe(true);
      },
    );
  });

  // O3: modern Python tooling — PEP 735 dependency-groups, PDM, uv, Hatch,
  // Poetry 1.2+ groups. cdxgen can't tell these are dev scope, so the manifest
  // parser must.
  it('flags dev deps across the modern pyproject tool matrix (not just poetry-classic)', () => {
    const pyproject = [
      '[project]',
      'name = "app"',
      'dependencies = ["requests", "flask"]',
      '',
      '[project.optional-dependencies]',
      '# extras are NOT dev — must stay prod-eligible',
      'plotting = ["matplotlib"]',
      '',
      '[dependency-groups]',                      // PEP 735
      'dev = ["pytest>=7.0", "ruff"]',
      'test = [',                                 // multi-line array
      '  "coverage[toml]",',
      '  "pytest-cov",',
      '  { include-group = "dev" },',             // group ref, not a package
      ']',
      '',
      '[tool.pdm.dev-dependencies]',              // PDM
      'lint = ["mypy", "black"]',
      '',
      '[tool.uv]',                                // uv legacy
      'dev-dependencies = ["pre-commit"]',
      'package = true',                           // non-array key — ignored
      '',
      '[tool.hatch.envs.test]',                   // Hatch
      'dependencies = ["tox", "nox"]',
      '',
      '[tool.poetry.group.docs.dependencies]',    // Poetry 1.2+ group
      'sphinx = "^7"',
      '',
      '[tool.poetry.dev-dependencies]',           // Poetry classic
      'flake8 = "^6"',
      'python = "^3.11"',                         // constraint, not a package
    ].join('\n');

    const devNames = new Set<string>();
    collectPyprojectDevNames(pyproject, devNames);

    for (const expected of [
      'pytest', 'ruff', 'coverage', 'pytest-cov', 'mypy', 'black',
      'pre-commit', 'tox', 'nox', 'sphinx', 'flake8',
    ]) {
      expect(devNames.has(expected)).toBe(true);
    }
    // Prod deps + extras + group-include refs must NOT be flagged dev.
    for (const notDev of ['requests', 'flask', 'matplotlib', 'python', 'include-group', 'dev', 'test']) {
      expect(devNames.has(notDev)).toBe(false);
    }
  });

  it('marks PEP 735 / PDM dev groups via patchDevDependencies (end-to-end)', () => {
    withTmpRepo(
      {
        'pyproject.toml': [
          '[project]',
          'name = "app"',
          'dependencies = ["requests"]',
          '[dependency-groups]',
          'dev = ["pytest"]',
        ].join('\n'),
      },
      (dir) => {
        const deps = [
          mkDep({ name: 'requests', is_direct: true }),
          mkDep({ name: 'pytest', is_direct: true }),
        ];
        patchDevDependencies(deps, dir, 'pypi');
        const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
        expect(byName.requests.devScoped).toBe(false);
        expect(byName.pytest.devScoped).toBe(true);
        expect(byName.pytest.source).toBe('devDependencies');
      },
    );
  });

  it('matches maven test-scope deps on the namespaced groupId:artifactId key', () => {
    withTmpRepo(
      {
        'pom.xml': [
          '<project><dependencies>',
          '<dependency><groupId>org.junit.jupiter</groupId>',
          '<artifactId>junit-jupiter</artifactId>',
          '<scope>test</scope></dependency>',
          '</dependencies></project>',
        ].join('\n'),
      },
      (dir) => {
        // dep.name is the bare artifactId; namespace carries the groupId.
        const deps = [
          mkDep({ name: 'junit-jupiter', namespace: 'org.junit.jupiter', is_direct: true }),
          mkDep({ name: 'spring-core', namespace: 'org.springframework', is_direct: true }),
        ];
        patchDevDependencies(deps, dir, 'maven');
        expect(deps[0].devScoped).toBe(true);
        expect(deps[0].source).toBe('devDependencies');
        expect(deps[1].devScoped).toBe(false);
      },
    );
  });
});

describe('updateReachabilityLevels — dependency scope', () => {
  it('classifies a dev-scope dep `unreachable` with zero usage slices', async () => {
    const fsk = new FakeStorage();
    seed(fsk, { environment: 'dev', usageStrings: [] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any);
    const { level, details } = verdictOf(fsk);
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('dev_scope_unreachable');
  });

  it('dev scope out-ranks a usage-heuristic `function` hit', async () => {
    const fsk = new FakeStorage();
    // The dep name is present in usage — the heuristic alone would say
    // `function`. Dev scope must still win.
    seed(fsk, { environment: 'dev', depName: 'mocha', usageStrings: ['mocha.describe'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any);
    expect(verdictOf(fsk).level).toBe('unreachable');
  });

  it('leaves a prod-scope imported dep at `module` (no over-firing)', async () => {
    const fsk = new FakeStorage();
    seed(fsk, { environment: 'prod', isDirect: true, filesImporting: 2, usageStrings: ['console.log'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any);
    expect(verdictOf(fsk).level).toBe('module');
  });

  it('stamps an orphan transitive `unreachable` with the structured verdict', async () => {
    const fsk = new FakeStorage();
    seed(fsk, { environment: null, isDirect: false, filesImporting: 0, usageStrings: ['console.log'] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any, undefined, {
      graphTrusted: true,
    });
    const { level, details } = verdictOf(fsk);
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('orphan_transitive_unreachable');
  });
});

describe('updateReachabilityLevels — framework-driven app (zero usage slices)', () => {
  // A Next.js `app/` page that only renders JSX makes zero direct dep calls, so
  // usage extraction produces no slices — but the AST still parsed. Import
  // absence is then real evidence, not an extraction failure: a declared dep no
  // file imports is `unreachable`, while the framework runtime (used by
  // convention, never imported) must stay `module` so its CVEs aren't buried.

  it('classifies a genuinely-unused direct npm dep `unreachable` even with zero usage slices', async () => {
    const fsk = new FakeStorage();
    // The dompurify case: in package.json, imported by no file, app calls no deps.
    seed(fsk, { environment: 'prod', isDirect: true, filesImporting: 0, depName: 'dompurify', usageStrings: [] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any, undefined, {
      ecosystem: 'npm',
    });
    const { level, details } = verdictOf(fsk);
    expect(level).toBe('unreachable');
    expect(details?.reason).toContain('imported by no source file');
  });

  it('never buries the framework runtime: `next` with zero imports stays `module`', async () => {
    const fsk = new FakeStorage();
    seed(fsk, { environment: 'prod', isDirect: true, filesImporting: 0, depName: 'next', usageStrings: [] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any, undefined, {
      ecosystem: 'npm',
    });
    expect(verdictOf(fsk).level).toBe('module');
  });

  it('exempts `react`/`react-dom` (JSX runtime used without an explicit import)', async () => {
    const fsk = new FakeStorage();
    seed(fsk, { environment: 'prod', isDirect: true, filesImporting: 0, depName: 'react-dom', usageStrings: [] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any, undefined, {
      ecosystem: 'npm',
    });
    expect(verdictOf(fsk).level).toBe('module');
  });

  it('preserves the fail-open: an extraction crash (astParsedSuccessfully=false) floors at `module`', async () => {
    const fsk = new FakeStorage();
    seed(fsk, { environment: 'prod', isDirect: true, filesImporting: 0, depName: 'dompurify', usageStrings: [] });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log as any, undefined, {
      ecosystem: 'npm',
      astParsedSuccessfully: false,
    });
    expect(verdictOf(fsk).level).toBe('module');
  });
});
