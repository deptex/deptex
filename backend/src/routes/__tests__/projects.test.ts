import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, pushTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
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
            registry_integrity_status: 'pass',
            registry_integrity_reason: null,
            install_scripts_status: 'pass',
            install_scripts_reason: null,
            entropy_analysis_status: 'pass',
            entropy_analysis_reason: null,
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
      expect(res.body.versions[0].registry_integrity_status).toBe('pass');
      expect(res.body.versions[0].install_scripts_status).toBe('pass');
      expect(res.body.versions[0].entropy_analysis_status).toBe('pass');
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
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project' }, error: null });
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
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project' }, error: null });
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
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project' }, error: null });
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
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project' }, error: null });
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
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project' }, error: null });
      setTableResponse('project_teams', 'single', { data: { id: 'pt-1', is_owner: true }, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/projects/${projectId}/contributing-teams/${teamId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/owner/i);
    });

    it('returns 404 when team is not associated with the project', async () => {
      setTableResponse('projects', 'single', { data: { id: projectId, name: 'Test Project' }, error: null });
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
});
