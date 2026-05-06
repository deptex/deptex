import { loadTargetOrDeny, isLoadTargetDeny } from '../dast-tenant-guard';

const PROJECT_A = '11111111-1111-1111-1111-111111111111';
const PROJECT_B = '22222222-2222-2222-2222-222222222222';
const ORG_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const TARGET_X = 'cccccccc-cccc-cccc-cccc-cccccccccccc';

function makeMockSupabase(rowResolver: (targetId: string) => any) {
  const builder: any = {
    _table: '',
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn(),
  };
  builder.maybeSingle.mockImplementation(async () => {
    return rowResolver(builder._lastId);
  });
  builder.eq.mockImplementation((_col: string, val: string) => {
    builder._lastId = val;
    return builder;
  });
  return {
    from: jest.fn().mockImplementation((table: string) => {
      builder._table = table;
      return builder;
    }),
  } as any;
}

describe('loadTargetOrDeny — happy path', () => {
  it('returns the target when project + org match', async () => {
    const supabase = makeMockSupabase(() => ({
      data: {
        id: TARGET_X,
        project_id: PROJECT_A,
        organization_id: ORG_A,
        target_url: 'https://app.example.com',
        detected_runtime: 'unknown',
        detected_runtime_at: null,
        detected_runtime_ttl_at: null,
        enabled: true,
      },
      error: null,
    }));

    const r = await loadTargetOrDeny(supabase, TARGET_X, PROJECT_A, ORG_A);
    expect(isLoadTargetDeny(r)).toBe(false);
    if (isLoadTargetDeny(r)) throw new Error('unreachable');
    expect(r.target.id).toBe(TARGET_X);
    expect(r.target.target_url).toBe('https://app.example.com');
  });
});

describe('loadTargetOrDeny — cross-tenant denial', () => {
  it('returns 404 target_not_found when project mismatches', async () => {
    const supabase = makeMockSupabase(() => ({
      data: {
        id: TARGET_X,
        project_id: PROJECT_B, // different project
        organization_id: ORG_A,
        target_url: 'https://app.example.com',
        detected_runtime: 'unknown',
        detected_runtime_at: null,
        detected_runtime_ttl_at: null,
        enabled: true,
      },
      error: null,
    }));

    const r = await loadTargetOrDeny(supabase, TARGET_X, PROJECT_A, ORG_A);
    expect(isLoadTargetDeny(r)).toBe(true);
    if (!isLoadTargetDeny(r)) throw new Error('unreachable');
    expect(r.status).toBe(404);
    expect(r.reason).toBe('target_not_found');
  });

  it('returns 404 target_not_found when organization mismatches', async () => {
    const supabase = makeMockSupabase(() => ({
      data: {
        id: TARGET_X,
        project_id: PROJECT_A,
        organization_id: ORG_B, // different org (cross-tenant)
        target_url: 'https://app.example.com',
        detected_runtime: 'unknown',
        detected_runtime_at: null,
        detected_runtime_ttl_at: null,
        enabled: true,
      },
      error: null,
    }));

    const r = await loadTargetOrDeny(supabase, TARGET_X, PROJECT_A, ORG_A);
    expect(isLoadTargetDeny(r)).toBe(true);
  });

  it('returns 404 target_not_found when row missing entirely', async () => {
    const supabase = makeMockSupabase(() => ({ data: null, error: null }));
    const r = await loadTargetOrDeny(supabase, TARGET_X, PROJECT_A, ORG_A);
    expect(isLoadTargetDeny(r)).toBe(true);
  });

  it('returns 404 (and logs) on supabase error rather than leaking 500', async () => {
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const supabase = makeMockSupabase(() => ({
      data: null,
      error: { message: 'connection refused' },
    }));
    const r = await loadTargetOrDeny(supabase, TARGET_X, PROJECT_A, ORG_A);
    expect(isLoadTargetDeny(r)).toBe(true);
    if (!isLoadTargetDeny(r)) throw new Error('unreachable');
    expect(r.status).toBe(404);
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });
});

describe('loadTargetOrDeny — timing parity', () => {
  // The dominant cost is the Supabase round-trip, which is mocked here as
  // an immediately-resolving Promise. We add a synthetic delay to the mock
  // so we can measure that the JS path itself doesn't add timing skew
  // between hit / cross-tenant / missing branches greater than 50ms.
  function makeDelayedMock(rowResolver: (targetId: string) => any, delayMs = 5) {
    const builder: any = {
      _table: '',
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockImplementation((_c: string, v: string) => {
        builder._lastId = v;
        return builder;
      }),
      maybeSingle: jest.fn().mockImplementation(async () => {
        await new Promise((r) => setTimeout(r, delayMs));
        return rowResolver(builder._lastId);
      }),
    };
    return {
      from: jest.fn().mockImplementation((table: string) => {
        builder._table = table;
        return builder;
      }),
    } as any;
  }

  async function timeIt(fn: () => Promise<unknown>): Promise<number> {
    const t0 = Date.now();
    await fn();
    return Date.now() - t0;
  }

  it('elapsed time is within 50ms regardless of hit / cross-tenant / missing', async () => {
    const hit = makeDelayedMock(() => ({
      data: {
        id: TARGET_X,
        project_id: PROJECT_A,
        organization_id: ORG_A,
        target_url: 'https://app.example.com',
        detected_runtime: 'unknown',
        detected_runtime_at: null,
        detected_runtime_ttl_at: null,
        enabled: true,
      },
      error: null,
    }));
    const crossTenant = makeDelayedMock(() => ({
      data: {
        id: TARGET_X,
        project_id: PROJECT_B,
        organization_id: ORG_B,
        target_url: 'https://app.example.com',
        detected_runtime: 'unknown',
        detected_runtime_at: null,
        detected_runtime_ttl_at: null,
        enabled: true,
      },
      error: null,
    }));
    const missing = makeDelayedMock(() => ({ data: null, error: null }));

    // Warm up to avoid first-run JIT skew.
    await loadTargetOrDeny(hit, TARGET_X, PROJECT_A, ORG_A);
    await loadTargetOrDeny(crossTenant, TARGET_X, PROJECT_A, ORG_A);
    await loadTargetOrDeny(missing, TARGET_X, PROJECT_A, ORG_A);

    const tHit = await timeIt(() => loadTargetOrDeny(hit, TARGET_X, PROJECT_A, ORG_A));
    const tCross = await timeIt(() =>
      loadTargetOrDeny(crossTenant, TARGET_X, PROJECT_A, ORG_A),
    );
    const tMiss = await timeIt(() =>
      loadTargetOrDeny(missing, TARGET_X, PROJECT_A, ORG_A),
    );

    const max = Math.max(tHit, tCross, tMiss);
    const min = Math.min(tHit, tCross, tMiss);
    expect(max - min).toBeLessThanOrEqual(50);
  });
});
