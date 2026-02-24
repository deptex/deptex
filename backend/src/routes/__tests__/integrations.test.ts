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
});
