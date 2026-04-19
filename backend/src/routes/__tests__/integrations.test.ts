import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder } from '../../test/mocks/supabaseSingleton';

// Mock dependencies
jest.mock('../../lib/supabase');

describe('Integration Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';

  beforeEach(() => {
    jest.clearAllMocks();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    // Restore default implementations
    queryBuilder.single.mockResolvedValue({ data: {}, error: null });
    queryBuilder.maybeSingle.mockResolvedValue({ data: {}, error: null });
    queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: [], error: null }));
  });

  describe('POST /api/integrations/github/connect-installation', () => {
    it('should connect a GitHub installation', async () => {
      const installationId = 'inst-123';
      const accountLogin = 'test-github-user';

      // 1. Check membership
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null
      });

      // 2. Check for existing connection (double-install prevention)
      // .from('organizations').select(...).eq('github_installation_id', ...).single()
      queryBuilder.single.mockResolvedValueOnce({
        data: null,
        error: { code: 'PGRST116' } // Not found (good)
      });

      // 3. Update organization
      // Returns builder, awaited -> then
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ error: null }));

      // 4. Upsert integration
      // Returns builder, awaited -> then
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ error: null }));

      const res = await request(app)
        .post('/api/integrations/github/connect-installation')
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          org_id: orgId,
          installation_id: installationId,
          account_login: accountLogin,
          account_type: 'User'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Verify update call
      expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({
        github_installation_id: installationId
      }));
    });

    it('should return 409 if installation is already connected to another org', async () => {
      const installationId = 'inst-123';

      // 1. Check membership
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null
      });

      // 2. Check for existing connection
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: 'other-org', name: 'Other Org' },
        error: null
      });

      const res = await request(app)
        .post('/api/integrations/github/connect-installation')
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          org_id: orgId,
          installation_id: installationId,
          account_login: 'test',
          account_type: 'User'
        });

      expect(res.status).toBe(409);
      expect(res.body.code).toBe('ALREADY_CONNECTED');
    });
  });

  describe('GET /api/integrations/github/install', () => {
    it('should return 400 when org_id is missing', async () => {
      const res = await request(app)
        .get('/api/integrations/github/install')
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Organization ID');
    });

    it('should return 403 when user is not a member of the organization', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({
        data: null,
        error: { code: 'PGRST116' },
      }));
      const res = await request(app)
        .get('/api/integrations/github/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(403);
    });

    it('should return 200 with redirectUrl when member', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({
        data: { role: 'owner' },
        error: null,
      }));
      const res = await request(app)
        .get('/api/integrations/github/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(200);
      expect(res.body.redirectUrl).toBeDefined();
      expect(res.body.redirectUrl).toContain('github.com/apps/');
      expect(res.body.redirectUrl).toContain('installations/new');
    });
  });

  describe('GET /api/integrations/gitlab/install', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv, GITLAB_CLIENT_ID: 'test-client-id', GITLAB_URL: 'https://gitlab.com' };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should return 400 when org_id is missing', async () => {
      const res = await request(app)
        .get('/api/integrations/gitlab/install')
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(400);
    });

    it('should return 403 when not a member', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({ data: null, error: {} }));
      const res = await request(app)
        .get('/api/integrations/gitlab/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(403);
    });

    it('should return 200 with redirectUrl when member and GITLAB_CLIENT_ID set', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({ data: { role: 'owner' }, error: null }));
      const res = await request(app)
        .get('/api/integrations/gitlab/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(200);
      expect(res.body.redirectUrl).toBeDefined();
      expect(res.body.redirectUrl).toContain('gitlab.com');
      expect(res.body.redirectUrl).toContain('oauth/authorize');
    });
  });

  describe('GET /api/integrations/gitlab/install without GITLAB_CLIENT_ID', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
      delete process.env.GITLAB_CLIENT_ID;
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should return 500 when GITLAB_CLIENT_ID not set', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({ data: { role: 'owner' }, error: null }));
      const res = await request(app)
        .get('/api/integrations/gitlab/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/integrations/bitbucket/install', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv, BITBUCKET_CLIENT_ID: 'test-bitbucket-client' };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should return 400 when org_id is missing', async () => {
      const res = await request(app)
        .get('/api/integrations/bitbucket/install')
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(400);
    });

    it('should return 403 when not a member', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({ data: null, error: {} }));
      const res = await request(app)
        .get('/api/integrations/bitbucket/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(403);
    });

    it('should return 200 with redirectUrl when member and BITBUCKET_CLIENT_ID set', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({ data: { role: 'owner' }, error: null }));
      const res = await request(app)
        .get('/api/integrations/bitbucket/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(200);
      expect(res.body.redirectUrl).toBeDefined();
      expect(res.body.redirectUrl).toContain('bitbucket.org');
      expect(res.body.redirectUrl).toContain('oauth2/authorize');
    });
  });

  describe('GET /api/integrations/bitbucket/install without BITBUCKET_CLIENT_ID', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
      delete process.env.BITBUCKET_CLIENT_ID;
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should return 500 when BITBUCKET_CLIENT_ID not set', async () => {
      queryBuilder.single.mockImplementation(() => Promise.resolve({ data: { role: 'owner' }, error: null }));
      const res = await request(app)
        .get('/api/integrations/bitbucket/install')
        .query({ org_id: orgId })
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(500);
    });
  });

  describe('DELETE /api/integrations/organizations/:orgId/connections/:connectionId', () => {
    const connectionId = 'conn-123';

    it('should return 403 when user is not a member', async () => {
      let callCount = 0;
      queryBuilder.single.mockImplementation(() => {
        callCount++;
        if (callCount === 1) return Promise.resolve({ data: null, error: {} });
        return Promise.resolve({ data: {}, error: null });
      });
      const res = await request(app)
        .delete(`/api/integrations/organizations/${orgId}/connections/${connectionId}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(403);
    });

    it('should return 404 when connection not found', async () => {
      let singleCallCount = 0;
      queryBuilder.single.mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount === 1) return Promise.resolve({ data: { role: 'owner' }, error: null });
        return Promise.resolve({ data: null, error: { code: 'PGRST116' } });
      });
      const res = await request(app)
        .delete(`/api/integrations/organizations/${orgId}/connections/${connectionId}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(404);
    });

    it('should return 200 with provider and installationId for GitHub connection', async () => {
      let singleCallCount = 0;
      queryBuilder.single.mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount === 1) return Promise.resolve({ data: { role: 'owner' }, error: null });
        return Promise.resolve({
          data: { id: connectionId, provider: 'github', installation_id: '456', organization_id: orgId },
          error: null,
        });
      });
      let thenCallCount = 0;
      queryBuilder.then.mockImplementation((resolve: any) => {
        thenCallCount++;
        return Promise.resolve({ error: null }).then(resolve);
      });
      const res = await request(app)
        .delete(`/api/integrations/organizations/${orgId}/connections/${connectionId}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.provider).toBe('github');
      expect(res.body.installationId).toBe('456');
    });

    it('should return 200 with revokeUrl for GitLab connection', async () => {
      let singleCallCount = 0;
      queryBuilder.single.mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount === 1) return Promise.resolve({ data: { role: 'owner' }, error: null });
        return Promise.resolve({
          data: { id: connectionId, provider: 'gitlab', organization_id: orgId },
          error: null,
        });
      });
      queryBuilder.then.mockImplementation((resolve: any) => Promise.resolve({ error: null }).then(resolve));
      const res = await request(app)
        .delete(`/api/integrations/organizations/${orgId}/connections/${connectionId}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.provider).toBe('gitlab');
      expect(res.body.installationId).toBeUndefined();
      expect(res.body.revokeUrl).toBe('https://gitlab.com/-/user_settings/applications');
    });

    it('should return 200 with revokeUrl for Bitbucket connection', async () => {
      let singleCallCount = 0;
      queryBuilder.single.mockImplementation(() => {
        singleCallCount++;
        if (singleCallCount === 1) return Promise.resolve({ data: { role: 'owner' }, error: null });
        return Promise.resolve({
          data: { id: connectionId, provider: 'bitbucket', organization_id: orgId },
          error: null,
        });
      });
      queryBuilder.then.mockImplementation((resolve: any) => Promise.resolve({ error: null }).then(resolve));
      const res = await request(app)
        .delete(`/api/integrations/organizations/${orgId}/connections/${connectionId}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.provider).toBe('bitbucket');
      expect(res.body.revokeUrl).toBe('https://bitbucket.org/account/settings/applications/');
    });
  });
});
