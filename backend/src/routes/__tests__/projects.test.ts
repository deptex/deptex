import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder } from '../../test/mocks/supabaseSingleton';

// Mock dependencies
jest.mock('../../lib/supabase');

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
  invalidateWatchtowerSummaryCache: jest.fn().mockResolvedValue(undefined),
  invalidateLatestSafeVersionCacheByDependencyId: jest.fn().mockResolvedValue(undefined),
  invalidateDependencyVersionsCacheByDependencyId: (...args: unknown[]) => mockInvalidateDependencyVersionsCacheByDependencyId(...args),
  invalidateAllProjectCachesInOrg: jest.fn().mockResolvedValue(undefined),
  invalidateProjectCachesForTeam: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../lib/watchtower-queue', () => ({
  queueWatchtowerJob: jest.fn().mockResolvedValue({ success: true }),
}));

describe('Project Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetCached.mockResolvedValue(null);
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    // Restore default implementations
    queryBuilder.single.mockResolvedValue({ data: {}, error: null });
    queryBuilder.maybeSingle.mockResolvedValue({ data: {}, error: null });
    queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: [], error: null }));
  });

  describe('GET /api/organizations/:id/projects', () => {
    it('should list all projects for org owner', async () => {
      // 1. Check membership
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null
      });

      // 2. Check org role permissions
      queryBuilder.single.mockResolvedValueOnce({
        data: { permissions: { manage_teams_and_projects: true } },
        error: null
      });

      // 3. Get projects
      const mockProjects = [
        {
          id: 'proj-1',
          name: 'Project X',
          organization_id: orgId,
          health_score: 100,
          status: 'compliant'
        }
      ];
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ data: mockProjects, error: null }));

      // 4. Get team associations
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({
        data: [
          {
            project_id: 'proj-1',
            is_owner: true,
            teams: { id: 'team-1', name: 'Team A' }
          }
        ],
        error: null
      }));

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].name).toBe('Project X');
      expect(res.body[0].role).toBe('owner'); // Org owners get owner role
      expect(res.body[0].owner_team_name).toBe('Team A');
    });
  });

  describe('POST /api/organizations/:id/projects', () => {
    it('should create a project', async () => {
      // 1. Check membership
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null
      });

      // 2. Check permissions
      queryBuilder.single.mockResolvedValueOnce({
        data: { permissions: { manage_teams_and_projects: true } },
        error: null
      });

      // 3. Create project
      const newProject = {
        id: 'proj-new',
        name: 'New Project',
        health_score: 0,
        status: 'compliant'
      };
      queryBuilder.single.mockResolvedValueOnce({ data: newProject, error: null });

      // No teams associated in this request, so no extra queries for teams

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
      // checkProjectAccess: org member exists but not owner, no manage permission, not project member, no team
      queryBuilder.single
        .mockResolvedValueOnce({ data: { role: 'member' }, error: null })
        .mockResolvedValueOnce({ data: { permissions: { manage_teams_and_projects: false } }, error: null })
        .mockResolvedValueOnce({ data: null, error: { message: 'Not found' } });
      queryBuilder.then.mockImplementationOnce((resolve: any) =>
        resolve({ data: [], error: null })
      ); // team_members empty

      const res = await request(app)
        .get(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/overview`
        )
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access|denied/i);
    });

    it('returns 404 when project dependency is not found', async () => {
      queryBuilder.single
        .mockResolvedValueOnce({ data: { role: 'owner' }, error: null })
        .mockResolvedValueOnce({ data: { permissions: { manage_teams_and_projects: true } }, error: null })
        .mockResolvedValueOnce({ data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .get(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/overview`
        )
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Project dependency not found');
    });

    it('returns 200 and full overview when all data exists', async () => {
      queryBuilder.single
        .mockResolvedValueOnce({ data: { role: 'owner' }, error: null })
        .mockResolvedValueOnce({ data: { permissions: { manage_teams_and_projects: true } }, error: null })
        .mockResolvedValueOnce({
          data: {
            dependency_version_id: dependencyVersionId,
            files_importing_count: 2,
            ai_usage_summary: null,
            ai_usage_analyzed_at: null,
          },
          error: null,
        })
        .mockResolvedValueOnce({
          data: {
            dependency_id: dependencyId,
            version: '1.2.3',
          },
          error: null,
        })
        .mockResolvedValueOnce({
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
        })
        .mockResolvedValueOnce({ data: null, error: { message: 'PGRST116' } }); // no deprecation
      queryBuilder.then
        .mockImplementationOnce((resolve: any) =>
          resolve({ data: [{ function_name: 'debounce' }], error: null })
        )
        .mockImplementationOnce((resolve: any) => resolve({ data: [], error: null })); // other projects
      queryBuilder.maybeSingle.mockResolvedValueOnce({ data: null, error: null }); // no remove PR

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
      expect(res.body.imported_functions).toEqual(['debounce']);
      expect(res.body.deprecation).toBeNull();
      expect(res.body.remove_pr_url).toBeNull();
    });
  });

  describe('PATCH /api/organizations/:id/projects/:projectId/dependencies/:dependencyId/watching', () => {
    const projectId = 'proj-1';
    const projectDependencyId = 'pd-1';
    const packageDependencyId = 'dep-1';

    function setupAccessAndManage() {
      // checkProjectAccess: org member owner, org role with manage
      queryBuilder.single
        .mockResolvedValueOnce({ data: { role: 'owner' }, error: null })
        .mockResolvedValueOnce({ data: { permissions: { manage_teams_and_projects: true } }, error: null });
      // checkWatchtowerManagePermission: org member single -> owner (returns true immediately)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
    }

    it('returns 400 when is_watching is not a boolean', async () => {
      setupAccessAndManage();
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: projectDependencyId, name: 'lodash', version: '4.17.21', dependency_version_id: 'dv-1' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({ data: { dependency_id: packageDependencyId }, error: null });

      const res = await request(app)
        .patch(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/watching`
        )
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ is_watching: 'true' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/boolean/);
    });

    it('returns 404 when user has no org membership', async () => {
      queryBuilder.single.mockResolvedValueOnce({ data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .patch(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/watching`
        )
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ is_watching: false });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/Organization not found|access denied/i);
    });

    it('returns 200 and disables watching when is_watching is false', async () => {
      setupAccessAndManage();
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: projectDependencyId, name: 'lodash', version: '4.17.21', dependency_version_id: 'dv-1' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({ data: { dependency_id: packageDependencyId }, error: null });
      queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: null, error: null }));
      queryBuilder.maybeSingle.mockResolvedValue({ data: null, error: null });
      // count organization_watchlist (for "any other orgs still watching")
      let thenCallCount = 0;
      queryBuilder.then.mockImplementation((resolve: any) => {
        thenCallCount++;
        return Promise.resolve({ data: [], error: null, count: 0 }).then(resolve);
      });

      const res = await request(app)
        .patch(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/watching`
        )
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ is_watching: false });

      expect(res.status).toBe(200);
      expect(res.body.is_watching).toBe(false);
    });

    it('returns 200 and enables watching when is_watching is true', async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            'dist-tags': { latest: '4.18.0' },
            time: { '4.18.0': '2025-01-01T00:00:00.000Z' },
          }),
      }) as any;

      queryBuilder.single.mockReset();
      setupAccessAndManage();
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: projectDependencyId, name: 'lodash', version: '4.17.21', dependency_version_id: 'dv-1' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({ data: { dependency_id: packageDependencyId }, error: null });
      // dependencies by name+version single -> null (no existing)
      queryBuilder.single.mockResolvedValueOnce({ data: null, error: { code: 'PGRST116' } });
      queryBuilder.single.mockResolvedValueOnce({ data: { id: packageDependencyId }, error: null });
      // watched_packages select single -> no existing (PGRST116)
      queryBuilder.single.mockResolvedValueOnce({ data: null, error: { code: 'PGRST116' } });
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: 'wp-1' },
        error: null,
      });

      const res = await request(app)
        .patch(
          `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/watching`
        )
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ is_watching: true });

      globalThis.fetch = originalFetch;

      expect(res.status).toBe(200);
      expect(res.body.is_watching).toBe(true);
    });
  });

  describe('GET /api/organizations/:id/projects/:projectId/dependencies/:projectDependencyId/versions', () => {
    const projectId = 'proj-1';
    const projectDependencyId = 'pd-1';

    it('returns cached response when cache hit', async () => {
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { permissions: { manage_teams_and_projects: true } }, error: null });

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
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { permissions: { manage_teams_and_projects: true } }, error: null });
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: 'ban-1', dependency_id: dependencyId, banned_version: '1.0.0', bump_to_version: '2.0.0', banned_by: mockUser.id, created_at: new Date().toISOString() },
        error: null,
      });
      queryBuilder.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ data: [], error: null }));

      const res = await request(app)
        .post(`/api/organizations/${orgId}/ban-version`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ dependency_id: dependencyId, banned_version: '1.0.0', bump_to_version: '2.0.0' });

      expect(res.status).toBe(200);
      expect(mockInvalidateDependencyVersionsCacheByDependencyId).toHaveBeenCalledWith(dependencyId);
    });
  });
});
