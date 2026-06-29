import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// findings-tab-perf: the project-sidebar status pill (useRealtimeStatus) used to
// call GET /repositories, which lists EVERY repo from the org's GitHub/GitLab
// integration on every request (~seconds) even though the pill only reads the
// connected-repo row. `?status_only=1` returns just that row and skips the
// integrations/listRepositories block. These tests pin the fast path: it returns
// the connected repo, returns [] for repositories, and never reaches the
// integrations block (which 400s when no integration is connected).
const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const projectId = 'proj-1';
const baseUrl = `/api/organizations/${orgId}/projects/${projectId}/repositories`;

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
  setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
  // The connected repo row (single). 'ready' + step 'completed' so effectiveStatus stays ready.
  setTableResponse('project_repositories', 'single', {
    data: {
      repo_full_name: 'acme/app',
      default_branch: 'main',
      status: 'ready',
      extraction_step: 'completed',
      last_extracted_at: '2026-06-29T00:00:00Z',
      provider: 'github',
    },
    error: null,
  });
  // The ready→active-job recheck reads scan_jobs (maybeSingle) — no active job.
  setTableResponse('scan_jobs', 'maybeSingle', { data: null, error: null });
});

describe('GET /repositories?status_only=1 (Phase: findings-tab-perf)', () => {
  it('returns the connected repo and an empty repositories list, skipping the GitHub listing', async () => {
    const res = await request(app)
      .get(`${baseUrl}?status_only=1`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.connectedRepository).toMatchObject({
      repo_full_name: 'acme/app',
      status: 'ready',
      last_extracted_at: '2026-06-29T00:00:00Z',
    });
    expect(res.body.repositories).toEqual([]);
  });

  it('the default (non-status-only) path still reaches the integrations block', async () => {
    // No integrations are mocked, so the integrations listing the status-only
    // path skips makes the default path 400 ("no source code integrations").
    // That contrast proves status_only returns BEFORE that block (i.e. before
    // the provider.listRepositories() GitHub call).
    const res = await request(app)
      .get(baseUrl)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/integration/i);
  });
});
