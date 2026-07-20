import {
  resolveProject,
  resolveTeam,
  resolveProjectDependency,
  resolveProjectVulnerability,
} from '../lib/aegis/chat-tools/resolvers';

const ORG_ID = '00000000-0000-0000-0000-000000000001';

// Per-table response queues. Each call to from(table)... resolves against the
// next queued response for that table. This is a tighter mock than the shared
// supabaseSingleton because resolvers chain multiple selects per call.
type Resp = { data: any; error?: any };
type Queue = Record<string, Resp[]>;

function makeFakeSupabase(queues: Queue) {
  // Real PostgrestQueryBuilder is a thenable — every method returns the builder,
  // and the request only fires when awaited. Mirror that here so callers can do
  // `query = query.limit(2)` then `query = query.contains(...)` then `await query`.
  const builder = (table: string) => {
    const chain: any = {};
    const passthrough = ['select', 'eq', 'ilike', 'is', 'contains', 'order', 'limit'];
    for (const m of passthrough) chain[m] = () => chain;
    chain.then = (resolve: any) =>
      resolve(queues[table]?.shift() ?? { data: [], error: null });
    // getActiveExtractionId terminates with .single(); an empty queue resolves
    // to data:null → NO_ACTIVE_RUN, which is what these tests want (the mock
    // ignores filters anyway).
    chain.single = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
    return chain;
  };
  return { from: builder } as any;
}

describe('resolveProject', () => {
  it('resolves on exact name match', async () => {
    const supabase = makeFakeSupabase({
      projects: [{ data: [{ id: 'p1', name: 'deptex-test-npm' }], error: null }],
    });
    const result = await resolveProject('deptex-test-npm', ORG_ID, supabase);
    expect(result).toEqual({ id: 'p1', name: 'deptex-test-npm' });
  });

  it('falls through to fuzzy match when exact misses', async () => {
    const supabase = makeFakeSupabase({
      projects: [
        { data: [], error: null }, // exact miss
        { data: [{ id: 'p1', name: 'deptex-test-npm' }], error: null }, // fuzzy hit
      ],
    });
    const result = await resolveProject('deptex npm', ORG_ID, supabase);
    expect(result).toEqual({ id: 'p1', name: 'deptex-test-npm' });
  });

  it('returns multi-match error with names when fuzzy hits multiple', async () => {
    const supabase = makeFakeSupabase({
      projects: [
        { data: [], error: null },
        {
          data: [
            { id: 'p1', name: 'deptex-test-npm' },
            { id: 'p2', name: 'deptex-test-go' },
          ],
          error: null,
        },
      ],
    });
    const result = await resolveProject('deptex', ORG_ID, supabase);
    expect('error' in result).toBe(true);
    expect((result as { error: string }).error).toContain('Multiple projects match "deptex"');
    expect((result as { error: string }).error).toContain('deptex-test-npm');
    expect((result as { error: string }).error).toContain('deptex-test-go');
  });

  it('returns no-match error with available names when nothing fuzzy-matches', async () => {
    const supabase = makeFakeSupabase({
      projects: [
        { data: [], error: null }, // exact miss
        { data: [], error: null }, // fuzzy miss
        {
          data: [{ name: 'deptex-test-npm' }, { name: 'deptex-test-go' }],
          error: null,
        }, // available list
      ],
    });
    const result = await resolveProject('nonexistent', ORG_ID, supabase);
    expect('error' in result).toBe(true);
    expect((result as { error: string }).error).toContain('No project matches "nonexistent"');
    expect((result as { error: string }).error).toContain('deptex-test-npm');
  });

  it('returns "no projects exist" when org is empty', async () => {
    const supabase = makeFakeSupabase({
      projects: [
        { data: [], error: null },
        { data: [], error: null },
        { data: [], error: null },
      ],
    });
    const result = await resolveProject('anything', ORG_ID, supabase);
    expect((result as { error: string }).error).toContain('No projects exist');
  });

  it('rejects empty input early without hitting the DB', async () => {
    const supabase = makeFakeSupabase({});
    const result = await resolveProject('   ', ORG_ID, supabase);
    expect((result as { error: string }).error).toContain('required');
  });
});

describe('resolveTeam', () => {
  it('resolves on exact match', async () => {
    const supabase = makeFakeSupabase({
      teams: [{ data: [{ id: 't1', name: 'platform' }], error: null }],
    });
    const result = await resolveTeam('platform', ORG_ID, supabase);
    expect(result).toEqual({ id: 't1', name: 'platform' });
  });

  it('returns no-team-exists when org has no teams', async () => {
    const supabase = makeFakeSupabase({
      teams: [{ data: [], error: null }, { data: [], error: null }, { data: [], error: null }],
    });
    const result = await resolveTeam('foo', ORG_ID, supabase);
    expect((result as { error: string }).error).toContain('No teams exist');
  });
});

describe('resolveProjectDependency', () => {
  it('resolves project then dependency by exact name', async () => {
    const supabase = makeFakeSupabase({
      projects: [{ data: [{ id: 'p1', name: 'deptex-test-npm' }], error: null }],
      project_dependencies: [
        { data: [{ id: 'd1', name: 'lodash', version: '4.17.21' }], error: null },
      ],
    });
    const result = await resolveProjectDependency(
      'deptex-test-npm',
      'lodash',
      ORG_ID,
      supabase,
    );
    expect(result).toEqual({
      id: 'd1',
      name: 'lodash',
      version: '4.17.21',
      projectId: 'p1',
      projectName: 'deptex-test-npm',
    });
  });

  it('propagates project-not-found error', async () => {
    const supabase = makeFakeSupabase({
      projects: [
        { data: [], error: null },
        { data: [], error: null },
        { data: [], error: null },
      ],
    });
    const result = await resolveProjectDependency('nope', 'lodash', ORG_ID, supabase);
    expect((result as { error: string }).error).toContain('No projects exist');
  });

  it('returns no-dep-match error when package missing from project', async () => {
    const supabase = makeFakeSupabase({
      projects: [{ data: [{ id: 'p1', name: 'deptex-test-npm' }], error: null }],
      project_dependencies: [
        { data: [], error: null }, // exact miss
        { data: [], error: null }, // fuzzy miss
      ],
    });
    const result = await resolveProjectDependency('deptex-test-npm', 'foo', ORG_ID, supabase);
    expect((result as { error: string }).error).toContain('No dependency matches "foo"');
  });
});

describe('resolveProjectVulnerability', () => {
  it('resolves CVE id within a project', async () => {
    const supabase = makeFakeSupabase({
      projects: [{ data: [{ id: 'p1', name: 'deptex-test-npm' }], error: null }],
      project_dependency_findings: [
        { data: [{ id: 'v1', osv_id: 'GHSA-xxx' }], error: null },
      ],
    });
    const result = await resolveProjectVulnerability(
      'deptex-test-npm',
      'CVE-2021-44906',
      ORG_ID,
      supabase,
    );
    expect(result).toEqual({
      vulnerabilityId: 'v1',
      osvId: 'GHSA-xxx',
      projectId: 'p1',
      projectName: 'deptex-test-npm',
    });
  });

  it('returns not-found error with project name when vuln missing', async () => {
    const supabase = makeFakeSupabase({
      projects: [{ data: [{ id: 'p1', name: 'deptex-test-npm' }], error: null }],
      project_dependency_findings: [{ data: [], error: null }],
    });
    const result = await resolveProjectVulnerability(
      'deptex-test-npm',
      'CVE-9999-9999',
      ORG_ID,
      supabase,
    );
    expect((result as { error: string }).error).toContain('Vulnerability "CVE-9999-9999" not found');
    expect((result as { error: string }).error).toContain('deptex-test-npm');
  });
});
