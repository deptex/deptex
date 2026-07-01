import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, pushTableResponse, setRpcResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));
// Rate limiter uses real Upstash Redis when env vars are set, which would
// throttle the 11+ POST /:id/projects tests below against shared per-user
// quota. Mock it to always allow for the test suite.
jest.mock('../../lib/rate-limit', () => ({
  checkRateLimit: jest.fn(async () => ({ allowed: true, remaining: 999 })),
}));

const mockGetCached = jest.fn().mockResolvedValue(null);
const mockSetCached = jest.fn().mockResolvedValue(undefined);
const mockGetDependencyVersionsCacheKey = jest.fn((org: string, project: string, pd: string) => `dependency-versions:${org}:${project}:${pd}`);
const mockInvalidateDependencyVersionsCacheByDependencyId = jest.fn().mockResolvedValue(undefined);
jest.mock('../../lib/cache', () => ({
  getCached: (...args: unknown[]) => mockGetCached(...args),
  setCached: (...args: unknown[]) => mockSetCached(...args),
  getDependenciesCacheKey: jest.fn((org: string, project: string) => `deps:v1:${org}:${project}`),
  getDependencyVersionsCacheKey: (...args: unknown[]) => mockGetDependencyVersionsCacheKey(...args),
  CACHE_TTL_SECONDS: { VERSIONS: 300, DEPENDENCIES: 43200 },
  invalidateDependenciesCache: jest.fn().mockResolvedValue(undefined),
  invalidateLatestSafeVersionCacheByDependencyId: jest.fn().mockResolvedValue(undefined),
  invalidateDependencyVersionsCacheByDependencyId: (...args: unknown[]) => mockInvalidateDependencyVersionsCacheByDependencyId(...args),
  invalidateAllProjectCachesInOrg: jest.fn().mockResolvedValue(undefined),
  invalidateProjectCachesForTeam: jest.fn().mockResolvedValue(undefined),
}));

describe('Project Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    mockGetCached.mockResolvedValue(null);
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    // Default: org owner with manage so most tests get access
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });
    // checkProjectAccess / checkProjectManagePermission's project↔org bind.
    setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
  });

  describe('GET /api/organizations/:id/projects', () => {
    it('should list all projects for org owner', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });
      const mockProjects = [
        { id: 'proj-1', name: 'Project X', organization_id: orgId, health_score: 100, status: 'compliant' }
      ];
      const mockProjectTeams = [
        { project_id: 'proj-1', is_owner: true, teams: { id: 'team-1', name: 'Team A' } }
      ];
      setTableResponse('projects', 'then', { data: mockProjects, error: null });
      setTableResponse('project_teams', 'then', { data: mockProjectTeams, error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].name).toBe('Project X');
      expect(res.body[0].role).toBe('owner');
      expect(res.body[0].owner_team_name).toBe('Team A');
    });
  });

  describe('POST /api/organizations/:id/projects', () => {
    it('should create a project', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });
      const newProject = {
        id: 'proj-new',
        name: 'New Project',
        health_score: 0,
        status: 'compliant'
      };
      setTableResponse('projects', 'single', { data: newProject, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'New Project' });

      expect(res.status).toBe(201);
      expect(res.body.name).toBe('New Project');
      expect(queryBuilder.insert).toHaveBeenCalledWith(expect.objectContaining({
        name: 'New Project',
        organization_id: orgId
      }));
    });

    it('rejects a project name that is whitespace-only', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: '   ' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });

    it('rejects a project name longer than 200 characters', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'a'.repeat(201) });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/200 characters/i);
    });

    it('rejects a member who lacks manage_teams_and_projects', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'Forbidden Project' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission/i);
    });

    it('does NOT accept the legacy role==="admin" check as proof of authority', async () => {
      // The dropped legacy check used to authorize any member whose role
      // was literally named "admin", regardless of permissions JSONB.
      // With the audit fix it requires manage_teams_and_projects too.
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'Still Forbidden' });

      expect(res.status).toBe(403);
    });

    it('rejects a repo block whose package_json_path traverses outside the repo', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          name: 'Traversal Attempt',
          repo: {
            repo_full_name: 'acme/api',
            integration_id: 'integ-1',
            package_json_path: '../../etc/passwd',
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/package_json_path/i);
    });

    it('rejects a repo block with a leading slash in package_json_path', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          name: 'Bad Path',
          repo: {
            repo_full_name: 'acme/api',
            integration_id: 'integ-1',
            package_json_path: '/etc/passwd',
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/package_json_path/i);
    });

    it('requires integration_id when a repo block is sent', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          name: 'Missing Integration',
          repo: {
            repo_full_name: 'acme/api',
            integration_id: '',
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/integration_id/i);
    });
  });

  describe('POST /api/organizations/:id/projects/:projectId/repositories/connect', () => {
    const projectId = 'proj-1';

    it('rejects an invalid package_json_path (traversal)', async () => {
      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/repositories/connect`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          repo_full_name: 'acme/api',
          integration_id: 'integ-1',
          package_json_path: '../../secrets',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/package_json_path/i);
    });

    it('rejects when repo_full_name is missing', async () => {
      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/repositories/connect`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          integration_id: 'integ-1',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/repo_full_name/i);
    });

    it('rejects when integration_id is missing', async () => {
      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/repositories/connect`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          repo_full_name: 'acme/api',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/integration_id/i);
    });
  });

  describe('GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/overview', () => {
    const projectId = 'proj-1';
    const projectDependencyId = 'pd-1';
    const dependencyVersionId = 'dv-1';
    const dependencyId = 'dep-1';

    it('returns 403 when user has no project access', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .get(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/overview`
        )
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access|denied/i);
    });

    it('returns 404 when project dependency is not found', async () => {
      setTableResponse('project_dependencies', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .get(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/overview`
        )
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Project dependency not found');
    });

    it('returns 200 and full overview when all data exists', async () => {
      setTableResponse('project_dependencies', 'single', {
        data: {
          dependency_version_id: dependencyVersionId,
          files_importing_count: 2,
          ai_usage_summary: null,
          ai_usage_analyzed_at: null,
        },
        error: null,
      });
      setTableResponse('dependency_versions', 'single', {
        data: { dependency_id: dependencyId, version: '1.2.3' },
        error: null,
      });
      setTableResponse('dependencies', 'single', {
        data: {
          name: 'lodash',
          github_url: 'https://github.com/lodash/lodash',
          license: 'MIT',
          weekly_downloads: 1e6,
          latest_release_date: '2024-01-01',
          latest_version: '1.2.3',
          last_published_at: null,
          score: 80,
          releases_last_12_months: 12,
          description: 'Utility library',
          openssf_score: 80,
          openssf_penalty: null,
          popularity_penalty: null,
          maintenance_penalty: null,
        },
        error: null,
      });
      setTableResponse('organization_deprecations', 'single', { data: null, error: { message: 'PGRST116' } });
      setTableResponse('project_dependency_functions', 'then', { data: [{ function_name: 'debounce' }], error: null });
      setTableResponse('project_dependencies', 'then', { data: [], error: null });
      setTableResponse('dependency_prs', 'maybeSingle', { data: null, error: null } as any);

      const res = await request(app)
        .get(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/overview`
        )
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('lodash');
      expect(res.body.version).toBe('1.2.3');
      expect(res.body.score).toBe(80);
      expect(res.body.files_importing_count).toBe(2);
      expect(Array.isArray(res.body.imported_functions)).toBe(true);
      expect(res.body.deprecation).toBeNull();
      expect(res.body.remove_pr_url).toBeNull();
    });
  });


  describe('GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/versions', () => {
    const projectId = 'proj-1';
    const projectDependencyId = 'pd-1';

    it('returns cached response when cache hit', async () => {
      const cached = {
        versions: [
          {
            version: '1.0.0',
            vulnCount: 0,
            vulnerabilities: [],
            transitiveVulnCount: 1,
            transitiveVulnerabilities: [{ osv_id: 'GHSA-xxx', severity: 'high', summary: null, aliases: [], from_package: 'some-dep' }],
            totalVulnCount: 1,
          },
        ],
        currentVersion: '1.0.0',
        latestVersion: '2.0.0',
        prs: [],
        bannedVersions: [],
      };
      mockGetCached.mockResolvedValueOnce(cached);

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/versions`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual(cached);
      expect(res.body.versions[0].transitiveVulnCount).toBe(1);
      expect(res.body.versions[0].transitiveVulnerabilities).toHaveLength(1);
      expect(res.body.versions[0].transitiveVulnerabilities[0].from_package).toBe('some-dep');
      expect(mockGetCached).toHaveBeenCalled();
    });
  });

  describe('POST /api/organizations/:id/ban-version', () => {
    it('invalidates dependency versions cache when ban succeeds', async () => {
      const dependencyId = 'dep-1';
      setTableResponse('banned_versions', 'single', {
        data: { id: 'ban-1', dependency_id: dependencyId, banned_version: '1.0.0', bump_to_version: '2.0.0', banned_by: mockUser.id, created_at: new Date().toISOString() },
        error: null,
      });
      setTableResponse('organization_watchlist', 'then', { data: [], error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/ban-version`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ dependency_id: dependencyId, banned_version: '1.0.0', bump_to_version: '2.0.0' });

      expect(res.status).toBe(200);
      expect(mockInvalidateDependencyVersionsCacheByDependencyId).toHaveBeenCalledWith(dependencyId);
    });
  });

  describe('DELETE /api/organizations/:id/projects/:projectId', () => {
    const projectId = 'proj-1';

    it('returns 200 and deletes project when user is org owner', async () => {
      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ message: 'Project deleted' });
      expect(queryBuilder.delete).toHaveBeenCalled();
    });

    it('returns 403 when user lacks access or permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission|delete|access/i);
    });
  });

  describe('POST /api/organizations/:id/projects/:projectId/transfer-ownership', () => {
    const projectId = 'proj-1';
    const newOwnerTeamId = 'team-2';

    it('returns 200 and transfers project ownership when user has permission', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project', organization_id: orgId }, error: null });
      setTableResponse('teams', 'single', { data: { id: newOwnerTeamId, name: 'Team B', description: null, avatar_url: null }, error: null });
      setTableResponse('project_teams', 'single', { data: { id: 'pt-1', team_id: 'team-1' }, error: null });
      setTableResponse('team_roles', 'single', { data: { name: 'Team A' }, error: null });
      setTableResponse('project_teams', 'then', { data: null, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/transfer-ownership`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ new_owner_team_id: newOwnerTeamId });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Project ownership transferred successfully');
      expect(res.body.owner_team).toEqual({
        id: newOwnerTeamId,
        name: 'Team B',
        description: null,
        avatar_url: null,
      });
    });

    it('returns 400 when new_owner_team_id is missing', async () => {
      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/transfer-ownership`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/new_owner_team_id|required/i);
    });
  });

  // ─── General: update project ──────────────────────────────────────────────

  describe('PUT /api/organizations/:id/projects/:projectId', () => {
    const projectId = 'proj-1';

    it('returns 200 and updates project name when user is org owner', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Renamed', organization_id: orgId }, error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/projects/${projectId}`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'Renamed' });

      expect(res.status).toBe(200);
      expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ name: 'Renamed' }));
    });

    it('returns 403 when non-owner tries to rename', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/projects/${projectId}`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'Hacked Name' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission|access/i);
    });
  });

  // ─── Repository settings ──────────────────────────────────────────────────

  describe('PATCH /api/organizations/:id/projects/:projectId/repositories/settings', () => {
    const projectId = 'proj-1';

    it('returns 200 and updates sync_frequency when user is org owner', async () => {
      setTableResponse('project_repositories', 'single', { data: { id: 'repo-1' }, error: null });
      setTableResponse('project_repositories', 'then', { data: { id: 'repo-1', sync_frequency: 'weekly' }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ sync_frequency: 'weekly' });

      expect(res.status).toBe(200);
      expect(queryBuilder.update).toHaveBeenCalled();
    });

    it('returns 400 for invalid sync_frequency value', async () => {
      setTableResponse('project_repositories', 'single', { data: { id: 'repo-1' }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ sync_frequency: 'every_hour' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Invalid sync_frequency/i);
    });

    it('returns 200 and updates scan_on_commit when user is org owner', async () => {
      setTableResponse('project_repositories', 'single', { data: { id: 'repo-1' }, error: null });
      setTableResponse('project_repositories', 'then', { data: { id: 'repo-1', scan_on_commit: true, sync_frequency: 'daily' }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ scan_on_commit: true });

      expect(res.status).toBe(200);
      expect(queryBuilder.update).toHaveBeenCalled();
    });

    it('returns 400 for a retired sync_frequency value (on_commit)', async () => {
      setTableResponse('project_repositories', 'single', { data: { id: 'repo-1' }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ sync_frequency: 'on_commit' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Invalid sync_frequency/i);
    });

    it('returns 400 when scan_on_commit is not a boolean', async () => {
      setTableResponse('project_repositories', 'single', { data: { id: 'repo-1' }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ scan_on_commit: 'yes' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/scan_on_commit must be a boolean/i);
    });

    it('returns 404 when no repository is connected', async () => {
      setTableResponse('project_repositories', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ sync_frequency: 'daily' });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/No repository connected/i);
    });

    it('returns 403 when user lacks permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ sync_frequency: 'daily' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission|access/i);
    });

    it('returns 200 and updates pull_request_comments_enabled', async () => {
      setTableResponse('project_repositories', 'single', { data: { id: 'repo-1' }, error: null });
      setTableResponse('project_repositories', 'then', { data: { id: 'repo-1', pull_request_comments_enabled: false }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/repositories/settings`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ pull_request_comments_enabled: false });

      expect(res.status).toBe(200);
    });
  });

  // ─── Access: members ──────────────────────────────────────────────────────

  describe('GET /api/organizations/:id/projects/:projectId/members', () => {
    const projectId = 'proj-1';

    it('returns 200 with direct and team members', async () => {
      setTableResponse('project_members', 'then', {
        data: [{ id: 'pm-1', user_id: 'user-2', role_id: 'role-1', created_at: new Date().toISOString(), project_roles: { name: 'viewer', display_name: 'Viewer', permissions: {} } }],
        error: null,
      });
      setTableResponse('user_profiles', 'then', {
        data: [{ user_id: 'user-2', full_name: 'Jane Doe', avatar_url: null }],
        error: null,
      });
      (supabase.auth.admin.listUsers as jest.Mock).mockResolvedValue({
        data: { users: [{ id: 'user-2', email: 'jane@test.com', user_metadata: {} }] },
        error: null,
      });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/members`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('direct_members');
      expect(res.body).toHaveProperty('team_members');
    });

    it('returns 403 when user has no project access', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/members`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
    });
  });

  describe('POST /api/organizations/:id/projects/:projectId/members', () => {
    const projectId = 'proj-1';

    it('returns 400 when user_id is missing', async () => {
      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/members`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/user_id/i);
    });

    it('returns 400 when target user is not an org member', async () => {
      // second call to organization_members (target user lookup) returns null
      setTableResponse('organization_members', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/members`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ user_id: 'outsider-99' });

      expect([400, 403, 404]).toContain(res.status);
    });

    it('returns 200 and adds member when user is org owner', async () => {
      setTableResponse('organization_members', 'single', { data: { user_id: 'user-2' }, error: null });
      setTableResponse('project_roles', 'single', { data: { id: 'role-viewer' }, error: null });
      setTableResponse('project_members', 'single', {
        data: { id: 'pm-new', user_id: 'user-2', role_id: 'role-viewer', created_at: new Date().toISOString(), project_roles: { name: 'viewer', display_name: 'Viewer', permissions: {} } },
        error: null,
      });
      setTableResponse('user_profiles', 'single', { data: { user_id: 'user-2', full_name: 'New Member', avatar_url: null }, error: null });
      (supabase.auth.admin.listUsers as jest.Mock).mockResolvedValue({
        data: { users: [{ id: 'user-2', email: 'new@test.com', user_metadata: {} }] },
        error: null,
      });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/members`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ user_id: 'user-2' });

      expect([200, 201]).toContain(res.status);
    });

    it('returns 403 when user lacks manage permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/members`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ user_id: 'user-2' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission|access/i);
    });
  });

  describe('DELETE /api/organizations/:id/projects/:projectId/members/:memberId', () => {
    const projectId = 'proj-1';
    const memberId = 'user-2';

    it('returns 200 and removes member when user is org owner', async () => {
      setTableResponse('project_roles', 'single', { data: { id: 'role-owner' }, error: null });
      setTableResponse('project_members', 'then', { data: [{ user_id: 'user-3' }, { user_id: memberId }], error: null });
      setTableResponse('project_members', 'then', { data: null, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/members/${memberId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/removed/i);
    });

    it('returns 403 when user lacks permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/members/${memberId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
    });
  });

  // ─── Access: contributing teams ───────────────────────────────────────────

  describe('POST /api/organizations/:id/projects/:projectId/contributing-teams', () => {
    const projectId = 'proj-1';
    const teamId = 'team-2';

    it('returns 400 when team_id is missing', async () => {
      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/team_id/i);
    });

    it('returns 200 and adds contributing team when user is org owner', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project', organization_id: orgId }, error: null });
      setTableResponse('teams', 'single', { data: { id: teamId, name: 'Team B', description: null, avatar_url: null }, error: null });
      // Queue: first call checks for existing assoc (null = not found), second call is insert result
      pushTableResponse('project_teams', { data: null, error: null });
      pushTableResponse('project_teams', { data: { id: 'pt-new', project_id: projectId, team_id: teamId, is_owner: false, created_at: new Date().toISOString() }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ team_id: teamId });

      expect([200, 201]).toContain(res.status);
    });

    it('returns 403 when user lacks manage_teams_and_projects permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ team_id: teamId });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission|access/i);
    });

    it('returns 404 when team is not in the org', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project', organization_id: orgId }, error: null });
      setTableResponse('teams', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ team_id: 'foreign-team' });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/Team not found/i);
    });
  });

  describe('DELETE /api/organizations/:id/projects/:projectId/contributing-teams/:teamId', () => {
    const projectId = 'proj-1';
    const teamId = 'team-2';

    it('returns 200 and removes contributing team', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project', organization_id: orgId }, error: null });
      setTableResponse('project_teams', 'single', { data: { id: 'pt-1', is_owner: false }, error: null });
      setTableResponse('teams', 'single', { data: { name: 'Team B' }, error: null });
      setTableResponse('project_teams', 'then', { data: null, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams/${teamId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/removed/i);
    });

    it('returns 400 when trying to remove the owner team', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project', organization_id: orgId }, error: null });
      setTableResponse('project_teams', 'single', { data: { id: 'pt-1', is_owner: true }, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams/${teamId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/owner/i);
    });

    it('returns 404 when team is not associated with the project', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project', organization_id: orgId }, error: null });
      setTableResponse('project_teams', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams/${teamId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/not associated/i);
    });

    it('returns 403 when user lacks permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
      setTableResponse('project_members', 'single', { data: null, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams/${teamId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
    });
  });

  describe('GET /api/organizations/:id/projects/:projectId/stats (truncation guard)', () => {
    it('drives counts from the project_stats_counts RPC, never an unbounded row fetch', async () => {
      const projectId = 'proj-stats-1';
      setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
      // projects.single is consumed twice in order: getActiveExtractionId, then the projectRow lookup.
      pushTableResponse('projects', { data: { active_extraction_run_id: 'run-1' }, error: null });
      pushTableResponse('projects', { data: { health_score: 90, status_id: null, importance: 1.0 }, error: null });
      // No direct deps → the bounded graph-severity fetch is skipped.
      setTableResponse('project_dependencies', 'then', { data: [], error: null });
      // bigint columns arrive as strings over JSON — assert the handler coerces them.
      setRpcResponse('project_stats_counts', { data: [{
        vuln_total: '1500', vuln_critical: '40', vuln_high: '60', vuln_medium: '900', vuln_low: '500', reachable_count: '120',
        sla_on_track: '0', sla_warning: '0', sla_breached: '0', sla_exempt: '0', sla_met: '0', sla_resolved_late: '0',
        deps_total: '1200', deps_direct: '10', deps_transitive: '1190', deps_outdated: '4',
        deps_compliant: '8', deps_failing: '2', deps_vulnerable: '37',
      }], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/stats`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(supabase.rpc).toHaveBeenCalledWith('project_stats_counts', { p_project_id: projectId, p_active_run_id: 'run-1' });
      expect(res.body.vulnerabilities.total).toBe(1500);
      expect(res.body.vulnerabilities.critical).toBe(40);
      expect(res.body.dependencies.total).toBe(1200);
      expect(res.body.dependencies.transitive).toBe(1190);
      // Regression guard: the old code fetched every pdv/dep row and counted in JS, truncating at
      // PostgREST's 1000-row cap. Neither old unbounded-select signature may reappear.
      const selectArgs = queryBuilder.select.mock.calls.map((c: any[]) => String(c[0] ?? ''));
      expect(selectArgs.some((s: string) => s.includes('sla_status'))).toBe(false);
      expect(selectArgs.some((s: string) => s.includes('policy_result'))).toBe(false);
    });
  });

  describe('PDV mutations recompute the denormalized summary', () => {
    it('suppressing a vulnerability fires recompute_project_summary', async () => {
      const projectId = 'proj-recompute-1';
      // getActiveExtractionId reads projects.single.
      pushTableResponse('projects', { data: { active_extraction_run_id: 'run-1' }, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${orgId}/projects/${projectId}/vulnerabilities/CVE-2024-1/suppress`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      // This is the #1 drift guard: the mutation MUST refresh the stored summary so the overview
      // reflects the change on the next load.
      expect(supabase.rpc).toHaveBeenCalledWith('recompute_project_summary', { p_project_id: projectId });
    });
  });

  describe('GET /api/organizations/:id/security-summary reads the denormalized table', () => {
    it('serves counts from project_security_summaries, not the live aggregation RPC', async () => {
      const summaryRow = {
        project_id: 'proj-a', organization_id: orgId, vuln_count: 10, critical_count: 2, reachable_count: 5,
        worst_depscore: 88, band_critical: 2, band_high: 3, band_medium: 1, band_low: 0, ignored_count: 4,
        semgrep_count: 1, secret_count: 0, verified_secret_count: 0, has_container: true, has_dast: false,
        last_scan_at: '2026-06-01T00:00:00.000Z',
      };
      setTableResponse('projects', 'then', { data: [{ id: 'proj-a', name: 'Proj A', active_extraction_run_id: 'r1', infra_types: [] }], error: null });
      setTableResponse('project_teams', 'then', { data: [{ project_id: 'proj-a', team_id: 'team-1', is_owner: true }], error: null });
      setTableResponse('project_security_summaries', 'then', { data: [summaryRow], error: null });
      setTableResponse('project_repositories', 'then', { data: [], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/security-summary`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      const proj = res.body.projects.find((p: any) => p.project_id === 'proj-a');
      expect(proj).toBeDefined();
      expect(proj.vuln_count).toBe(10);
      expect(proj.band_critical).toBe(2);
      expect(proj.has_container).toBe(true);
      expect(proj.last_scan_at).toBe('2026-06-01T00:00:00.000Z');
      // The whole point of PR-B: the live 10-LATERAL aggregation RPC is no longer on the read path.
      expect(supabase.rpc).not.toHaveBeenCalledWith('security_summary_counts', expect.anything());
    });

    it('lazily recomputes a project that has no stored summary row yet', async () => {
      setTableResponse('projects', 'then', { data: [{ id: 'proj-new', name: 'New', active_extraction_run_id: 'r1', infra_types: [] }], error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });
      // No stored row → the lazy fallback must compute it on the spot.
      setTableResponse('project_security_summaries', 'then', { data: [], error: null });
      setTableResponse('project_repositories', 'then', { data: [], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/security-summary`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(supabase.rpc).toHaveBeenCalledWith('recompute_project_summary', { p_project_id: 'proj-new' });
    });
  });

  describe('GET /api/organizations/:id/overview bundles the 4 mount calls', () => {
    // Mocks sufficient for ALL four builders (teams, projects, statuses, security-summary)
    // so the bundle and the individual endpoints run against identical data.
    const seedBundleMocks = () => {
      const projectRow = {
        id: 'proj-1', name: 'Proj One', organization_id: orgId, health_score: 90, status_id: null,
        importance: 1.0, framework: 'react', active_extraction_run_id: 'r1', infra_types: [],
        is_compliant: true, created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z',
      };
      const teamRow = {
        id: 'team-1', name: 'Team A', organization_id: orgId,
        created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z',
      };
      // One row that satisfies all three project_teams consumers (projects embed teams:{id,name};
      // security-summary reads team_id+is_owner; teams counts by team_id).
      const projectTeamRow = { project_id: 'proj-1', team_id: 'team-1', is_owner: true, teams: { id: 'team-1', name: 'Team A' } };
      const statusRow = {
        id: 's1', organization_id: orgId, name: 'Open', color: null, rank: 1, is_passing: false,
        is_system: false, description: null, created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z',
      };
      const summaryRow = {
        project_id: 'proj-1', organization_id: orgId, vuln_count: 7, critical_count: 1, reachable_count: 2,
        worst_depscore: 80, band_critical: 1, band_high: 2, band_medium: 0, band_low: 0, ignored_count: 0,
        semgrep_count: 0, secret_count: 0, verified_secret_count: 0, has_container: false, has_dast: false,
        last_scan_at: '2026-06-01T00:00:00.000Z',
      };
      setTableResponse('teams', 'then', { data: [teamRow], error: null });
      setTableResponse('projects', 'then', { data: [projectRow], error: null });
      setTableResponse('project_teams', 'then', { data: [projectTeamRow], error: null });
      setTableResponse('project_security_summaries', 'then', { data: [summaryRow], error: null });
      setTableResponse('project_repositories', 'then', { data: [], error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });
      setTableResponse('team_roles', 'then', { data: [], error: null });
      setTableResponse('scan_jobs', 'then', { data: [], error: null });
      setTableResponse('organization_statuses', 'then', { data: [statusRow], error: null });
      setTableResponse('project_dependencies', 'then', { data: [], error: null });
    };

    it('returns teams/projects/statuses/securitySummary identical to the 4 individual endpoints', async () => {
      seedBundleMocks();
      const auth = (r: request.Test) => r.set('Authorization', `Bearer ${mockToken}`) as request.Test;

      const [bundle, projects, teams, statuses, security] = await Promise.all([
        auth(request(app).get(`/api/organizations/${orgId}/overview`)),
        auth(request(app).get(`/api/organizations/${orgId}/projects`)),
        auth(request(app).get(`/api/organizations/${orgId}/teams`)),
        auth(request(app).get(`/api/organizations/${orgId}/statuses`)),
        auth(request(app).get(`/api/organizations/${orgId}/security-summary`)),
      ]);

      expect(bundle.status).toBe(200);
      expect(projects.status).toBe(200);
      expect(teams.status).toBe(200);
      expect(statuses.status).toBe(200);
      expect(security.status).toBe(200);

      // The core guarantee: the bundle is exactly the union of the 4 endpoints, with no drift.
      expect(bundle.body.projects).toEqual(projects.body);
      expect(bundle.body.teams).toEqual(teams.body);
      expect(bundle.body.statuses).toEqual(statuses.body);
      expect(bundle.body.securitySummary).toEqual(security.body);

      // Sanity that the seeded data actually flowed through (not 4 empty arrays).
      expect(bundle.body.projects[0].name).toBe('Proj One');
      expect(bundle.body.teams[0].id).toBe('team-1');
      expect(bundle.body.securitySummary.projects[0].vuln_count).toBe(7);
    });

    it('propagates a 404 when the caller is not a member of the org', async () => {
      seedBundleMocks();
      // statuses builder is the membership gate — a missing membership row 404s it,
      // and the bundle surfaces that.
      setTableResponse('organization_members', 'single', { data: null, error: { message: 'no rows' } });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/overview`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
    });
  });
});
