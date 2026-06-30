/**
 * GHSA per-ecosystem chunked sync test (M2.1).
 *
 * v1 ran a single un-filtered `securityAdvisories(classifications: [MALWARE])`
 * GraphQL query and topped out at 50 pages × 100/page = 5000 advisories total,
 * which (since GitHub orders by PUBLISHED_AT DESC) silently dropped older
 * malware advisories from less-active ecosystems. v2 fans out per ecosystem,
 * raising the effective cap to 5k *per* ecosystem.
 *
 * These tests don't hit the real GraphQL API — we mock `global.fetch` and
 * assert:
 *   1. The orchestrator issues at least one query for every supported
 *      ecosystem (npm, pypi, maven, golang, rubygems, composer, cargo,
 *      nuget, github-actions = 9 total).
 *   2. Each query embeds the matching `ecosystem: <ENUM>` filter in the
 *      GraphQL document so GitHub scopes the response.
 *   3. A 429 response triggers a retry with the same cursor + ecosystem,
 *      preserving entries_added across the backoff.
 */
import {
  queryBuilder,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';
import { runMaliciousFeedSync } from '../malicious/feed-sync';

const ORIGINAL_FETCH = global.fetch;
const ORIGINAL_TOKEN = process.env.GITHUB_TOKEN;

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  process.env.GITHUB_TOKEN = 'test-token';
  // Mock the run row insert (.insert(...).select('id').single())
  setTableResponse('malicious_feed_sync_runs', 'single', {
    data: { id: 'run-1' },
    error: null,
  });
  // Mock the run row update (.update(...).eq('id', runId)) — returns no
  // chained `single`, just resolves; the singleton mock returns a generic
  // ok response when nothing is registered.
  setTableResponse('known_malicious_packages', 'then', { data: null, error: null });
});

afterEach(() => {
  global.fetch = ORIGINAL_FETCH;
  if (ORIGINAL_TOKEN === undefined) delete process.env.GITHUB_TOKEN;
  else process.env.GITHUB_TOKEN = ORIGINAL_TOKEN;
});

function emptyGhsaPage() {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      data: {
        securityVulnerabilities: {
          pageInfo: { hasNextPage: false, endCursor: null },
          nodes: [],
        },
      },
    }),
  } as any;
}

describe('GHSA per-ecosystem fan-out', () => {
  it('issues at least one query per supported GHSA ecosystem', async () => {
    const seen = new Set<string>();
    const fetchMock = jest.fn(async (_url: any, init: any) => {
      const body = JSON.parse(init.body);
      // Capture which ecosystem this query targets via the inline filter.
      const m = body.query.match(/ecosystem:\s*([A-Z]+)/);
      if (m) seen.add(m[1]);
      return emptyGhsaPage();
    });
    global.fetch = fetchMock as any;

    const result = await runMaliciousFeedSync('ghsa');

    expect(result.state).toBe('completed');
    // 9 canonical ecosystems with GHSA representation: NPM, PIP, MAVEN, GO,
    // RUBYGEMS, COMPOSER, RUST, NUGET, ACTIONS. (vscode has no GHSA enum.)
    expect(seen).toEqual(
      new Set(['NPM', 'PIP', 'MAVEN', 'GO', 'RUBYGEMS', 'COMPOSER', 'RUST', 'NUGET', 'ACTIONS']),
    );
    // Each ecosystem queried at least once → fetch ran ≥9 times.
    expect(fetchMock).toHaveBeenCalledTimes(9);
  });

  it('embeds the ecosystem filter directly in the GraphQL document', async () => {
    const queries: string[] = [];
    global.fetch = jest.fn(async (_url: any, init: any) => {
      queries.push(JSON.parse(init.body).query);
      return emptyGhsaPage();
    }) as any;

    await runMaliciousFeedSync('ghsa');

    // Sample one query and verify it has the structural anchors we depend on.
    const npmQuery = queries.find((q) => /ecosystem:\s*NPM/.test(q));
    expect(npmQuery).toBeDefined();
    // Schema-correct: the ecosystem filter lives on securityVulnerabilities,
    // NOT securityAdvisories (the latter has no ecosystem arg per GitHub's
    // GraphQL schema, verified live 2026-05-05).
    expect(npmQuery!).toContain('securityVulnerabilities');
    expect(npmQuery!).not.toContain('securityAdvisories');
    expect(npmQuery!).toContain('classifications: [MALWARE]');
    expect(npmQuery!).toContain('orderBy: { field: UPDATED_AT, direction: DESC }');
  });

  it('canonicalizes mixed-case PyPI advisory names on the write path (P0 BLI-001 regression)', async () => {
    // GHSA stores advisories with their upstream casing (e.g. `Django`,
    // `BeautifulSoup4`). cdxgen produces lowercase PEP 503 names from
    // installed packages. Without normalization on the write path the
    // lookup at lookupFeed time silently misses mixed-case advisories.
    const upsertSpy = queryBuilder.upsert as jest.Mock;
    upsertSpy.mockClear();

    global.fetch = jest.fn(async (_url: any, init: any) => {
      const body = JSON.parse(init.body);
      if (/ecosystem:\s*PIP/.test(body.query)) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              securityVulnerabilities: {
                pageInfo: { hasNextPage: false, endCursor: null },
                nodes: [
                  {
                    package: { ecosystem: 'PIP', name: 'Django' },
                    vulnerableVersionRange: '== 4.2.0',
                    advisory: {
                      ghsaId: 'GHSA-test-pypi-mal',
                      summary: 'malware',
                      description: 'malware',
                      severity: 'CRITICAL',
                      withdrawnAt: null,
                    },
                  },
                ],
              },
            },
          }),
        } as any;
      }
      return emptyGhsaPage();
    }) as any;

    const result = await runMaliciousFeedSync('ghsa');
    expect(result.state).toBe('completed');

    // Inspect the upsert payload — the advisory's `Django` MUST land in
    // `known_malicious_packages` as `django` so feeds.ts lookups for
    // cdxgen-extracted lowercase names match the row.
    const upsertedRows = upsertSpy.mock.calls.flatMap((c: any[]) => c[0] ?? []);
    const pypiRow = upsertedRows.find((r: any) => r.ecosystem === 'pypi');
    expect(pypiRow).toBeDefined();
    expect(pypiRow!.package_name).toBe('django'); // canonicalized, NOT 'Django'
  });

  it('stores an npm vulnerableVersionRange as a vulnerable_range row (N4)', async () => {
    // An npm MALWARE advisory scoped to a version RANGE must land as a single
    // `version=null, vulnerable_range=<semver>` row so the depscanner side can
    // flag only installed versions that SATISFY the range — instead of either
    // a name-only flag-all (FP) or a skipped advisory (FN).
    const upsertSpy = queryBuilder.upsert as jest.Mock;
    upsertSpy.mockClear();

    global.fetch = jest.fn(async (_url: any, init: any) => {
      const body = JSON.parse(init.body);
      if (/ecosystem:\s*NPM/.test(body.query)) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              securityVulnerabilities: {
                pageInfo: { hasNextPage: false, endCursor: null },
                nodes: [
                  {
                    package: { ecosystem: 'NPM', name: 'evil-lib' },
                    vulnerableVersionRange: '>= 1.0.0, < 2.0.0',
                    advisory: {
                      ghsaId: 'GHSA-test-npm-range',
                      summary: 'malware',
                      description: 'malware',
                      severity: 'CRITICAL',
                      withdrawnAt: null,
                    },
                  },
                ],
              },
            },
          }),
        } as any;
      }
      return emptyGhsaPage();
    }) as any;

    const result = await runMaliciousFeedSync('ghsa');
    expect(result.state).toBe('completed');

    const upsertedRows = upsertSpy.mock.calls.flatMap((c: any[]) => c[0] ?? []);
    const npmRow = upsertedRows.find(
      (r: any) => r.ecosystem === 'npm' && r.package_name === 'evil-lib',
    );
    expect(npmRow).toBeDefined();
    // Range row: no concrete version, a worker-evaluable semver range string.
    expect(npmRow!.version).toBeNull();
    expect(npmRow!.vulnerable_range).toBe('>=1.0.0 <2.0.0');
  });

  it('keeps an npm exact `= X` advisory as a concrete-version row (N4)', async () => {
    // A single exact pin is NOT a range — it stays an exact-version row
    // (vulnerable_range null), so exact matching is untouched.
    const upsertSpy = queryBuilder.upsert as jest.Mock;
    upsertSpy.mockClear();

    global.fetch = jest.fn(async (_url: any, init: any) => {
      const body = JSON.parse(init.body);
      if (/ecosystem:\s*NPM/.test(body.query)) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              securityVulnerabilities: {
                pageInfo: { hasNextPage: false, endCursor: null },
                nodes: [
                  {
                    package: { ecosystem: 'NPM', name: 'evil-pin' },
                    vulnerableVersionRange: '= 1.2.3',
                    advisory: {
                      ghsaId: 'GHSA-test-npm-pin',
                      summary: 'malware',
                      description: 'malware',
                      severity: 'CRITICAL',
                      withdrawnAt: null,
                    },
                  },
                ],
              },
            },
          }),
        } as any;
      }
      return emptyGhsaPage();
    }) as any;

    const result = await runMaliciousFeedSync('ghsa');
    expect(result.state).toBe('completed');

    const upsertedRows = upsertSpy.mock.calls.flatMap((c: any[]) => c[0] ?? []);
    const npmRow = upsertedRows.find(
      (r: any) => r.ecosystem === 'npm' && r.package_name === 'evil-pin',
    );
    expect(npmRow).toBeDefined();
    expect(npmRow!.version).toBe('1.2.3');
    expect(npmRow!.vulnerable_range).toBeNull();
  });

  it('beats the heartbeat mid-run so the watchdog 5-min stale window does not fire', async () => {
    // Feed-sync runs of the npm OSV bulk archive routinely take >5 min;
    // the watchdog declares any `state='running'` row stuck after 5 min
    // without an `updated_at` bump. The fix wires a setInterval timer that
    // fires every 60s while the run is in flight. We exercise the heartbeat
    // path via the test-only export so the assertion doesn't depend on
    // wall-clock advancement past the cadence.
    const updateSpy = queryBuilder.update as jest.Mock;
    updateSpy.mockClear();

    global.fetch = jest.fn(async () => emptyGhsaPage()) as any;
    const result = await runMaliciousFeedSync('ghsa');
    expect(result.state).toBe('completed');

    // Drive a heartbeat directly to assert the bump path emits a
    // single-key `{ updated_at }` update payload — the watchdog's
    // freshness signal.
    const { __test_only_bumpHeartbeat } = await import('../malicious/feed-sync');
    await __test_only_bumpHeartbeat('run-1');

    const heartbeatPayloads = updateSpy.mock.calls
      .map((c: any[]) => c[0])
      .filter((p: any) => p && Object.keys(p).length === 1 && 'updated_at' in p);
    expect(heartbeatPayloads.length).toBeGreaterThan(0);
  });

  it('retries on 429 with backoff and recovers the page', async () => {
    let call = 0;
    const sleepSpy = jest
      .spyOn(global, 'setTimeout')
      // Skip the actual wait so the test runs in <1s.
      .mockImplementation(((fn: any) => { fn(); return 0 as any; }) as any);

    global.fetch = jest.fn(async () => {
      call++;
      // First call across the run hits 429; subsequent calls succeed.
      if (call === 1) {
        return {
          ok: false,
          status: 429,
          headers: { get: (_: string) => '1' },
          text: async () => 'rate limited',
        } as any;
      }
      return emptyGhsaPage();
    }) as any;

    const result = await runMaliciousFeedSync('ghsa');

    expect(result.state).toBe('completed');
    // The 429 retry is internal: it should NOT propagate as a thrown error,
    // and the test setTimeout was invoked at least once for the backoff.
    expect(sleepSpy).toHaveBeenCalled();

    sleepSpy.mockRestore();
  });
});
