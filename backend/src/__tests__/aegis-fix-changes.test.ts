/**
 * GET /api/aegis/fix/:fixId/changes — the NET change-set for a fix's PR
 * ("initial vs now", one entry per file), sourced from GitHub's cumulative
 * PR files list (authoritative across all commits, amends included).
 *
 * Pins:
 *   - same auth guard as GET /:fixId (404 unknown fix, 403 non-member)
 *   - no pr_number yet -> { prNumber: null, prUrl: null, files: [] }, no
 *     GitHub call
 *   - happy path maps filename/status/counts/patch; lockfile-ish paths keep
 *     stats but get patch: null; missing patch (large/binary) passes null
 *     through; >12k-char patches are truncated
 *   - two-page cap: a full first page (100) triggers exactly one more fetch
 *   - GitHub non-ok -> 502 with the stable error the frontend keys on
 */
import express from 'express';
import request from 'supertest';

import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const PROJECT_ID = '00000000-0000-0000-0000-000000000002';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const FIX_ID = '00000000-0000-0000-0000-0000000000ab';

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
    next();
  },
}));

jest.mock('../lib/github', () => ({
  createInstallationToken: jest.fn().mockResolvedValue('tok-123'),
  getBranchSha: jest.fn(),
}));

import aegisFixRouter from '../routes/aegis-fix';
import { createInstallationToken } from '../lib/github';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/aegis/fix', aegisFixRouter);
  return app;
}

const realFetch = (global as any).fetch;
let fetchMock: jest.Mock;

function setMember(isMember: boolean) {
  setTableResponse('organization_members', 'maybeSingle', {
    data: isMember ? { user_id: USER_ID } : null,
    error: null,
  });
}

function setFixRow(row: any) {
  setTableResponse('project_security_fixes', 'maybeSingle', { data: row, error: null });
}

function prFixRow(overrides: Record<string, any> = {}) {
  return {
    id: FIX_ID,
    organization_id: ORG_ID,
    project_id: PROJECT_ID,
    pr_number: 7,
    pr_url: 'https://github.com/acme/app/pull/7',
    pr_repo_full_name: 'acme/app',
    ...overrides,
  };
}

function ghOk(files: any[]) {
  return { ok: true, json: async () => files };
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  jest.clearAllMocks();
  fetchMock = jest.fn();
  (global as any).fetch = fetchMock;
  setTableResponse('project_repositories', 'maybeSingle', {
    data: { installation_id: 42 },
    error: null,
  });
});

afterAll(() => {
  (global as any).fetch = realFetch;
});

describe('GET /api/aegis/fix/:fixId/changes', () => {
  it('returns 404 for an unknown fix', async () => {
    setFixRow(null);
    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns 403 for a non-member (same rejection as GET /:fixId)', async () => {
    setFixRow(prFixRow());
    setMember(false);
    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Not a member of this organization');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns an empty change-set (and makes no GitHub call) before a PR exists', async () => {
    setFixRow(prFixRow({ pr_number: null, pr_url: null, pr_repo_full_name: null }));
    setMember(true);
    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ prNumber: null, prUrl: null, files: [] });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('maps the PR files list: patch kept, lockfile patch nulled, long patch truncated, missing patch null', async () => {
    setFixRow(prFixRow());
    setMember(true);
    const longPatch = 'x'.repeat(13000);
    fetchMock.mockResolvedValueOnce(
      ghOk([
        { filename: 'src/index.ts', status: 'modified', additions: 3, deletions: 1, patch: '@@ -1 +1 @@' },
        { filename: 'package-lock.json', status: 'modified', additions: 512, deletions: 209, patch: 'thousands of lines' },
        { filename: 'src/big.ts', status: 'modified', additions: 900, deletions: 2, patch: longPatch },
        { filename: 'logo.png', status: 'added', additions: 0, deletions: 0 }, // GitHub omits patch for binaries
      ]),
    );

    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(200);
    expect(res.body.prNumber).toBe(7);
    expect(res.body.prUrl).toBe('https://github.com/acme/app/pull/7');
    expect(res.body.files).toHaveLength(4);

    expect(res.body.files[0]).toEqual({
      path: 'src/index.ts',
      status: 'modified',
      additions: 3,
      deletions: 1,
      patch: '@@ -1 +1 @@',
      lockfile: false,
    });
    // Lockfile: stats survive, diff body dropped, flagged so the Changes tab
    // can hide it (machine-regenerated, not an authored change).
    expect(res.body.files[1]).toEqual({
      path: 'package-lock.json',
      status: 'modified',
      additions: 512,
      deletions: 209,
      patch: null,
      lockfile: true,
    });
    // Oversized patch: capped + marked.
    expect(res.body.files[2].patch.endsWith('\n… (truncated)')).toBe(true);
    expect(res.body.files[2].patch.length).toBe(12000 + '\n… (truncated)'.length);
    // Binary/large file with no patch from GitHub.
    expect(res.body.files[3].patch).toBeNull();

    // One page was enough (fewer than 100 entries), authed with the app token.
    expect(createInstallationToken).toHaveBeenCalledWith('42');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.github.com/repos/acme/app/pulls/7/files?per_page=100&page=1');
    expect(init.headers.Authorization).toBe('Bearer tok-123');
  });

  it('fetches a second page when the first is full, capped at 2 pages', async () => {
    setFixRow(prFixRow());
    setMember(true);
    const page = (n: number, count: number) =>
      Array.from({ length: count }, (_, i) => ({
        filename: `f${n}-${i}.ts`,
        status: 'modified',
        additions: 1,
        deletions: 0,
        patch: 'p',
      }));
    fetchMock
      .mockResolvedValueOnce(ghOk(page(1, 100)))
      .mockResolvedValueOnce(ghOk(page(2, 100))); // still full: must stop anyway

    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(200);
    expect(res.body.files).toHaveLength(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).toContain('&page=2');
  });

  it('returns 502 when GitHub responds non-ok', async () => {
    setFixRow(prFixRow());
    setMember(true);
    fetchMock.mockResolvedValueOnce({ ok: false, status: 500, json: async () => ({}) });

    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(502);
    expect(res.body).toEqual({ error: 'Could not load the change set from GitHub' });
  });

  it('returns 502 when the token mint throws', async () => {
    setFixRow(prFixRow());
    setMember(true);
    (createInstallationToken as jest.Mock).mockRejectedValueOnce(new Error('app key missing'));

    const res = await request(makeApp()).get(`/api/aegis/fix/${FIX_ID}/changes`);
    expect(res.status).toBe(502);
    expect(res.body).toEqual({ error: 'Could not load the change set from GitHub' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
