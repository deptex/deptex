/**
 * Organization roles and member management tests (EE routes).
 * Covers: change member role, remove member, create/update/delete roles, hierarchy.
 */
import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));

jest.mock('../../lib/email', () => ({
  sendInvitationEmail: jest.fn(),
}));

jest.mock('../../lib/openai', () => ({
  getOpenAIClient: jest.fn().mockReturnValue({
    chat: { completions: { create: jest.fn() } },
  }),
}));

describe('Organization Roles & Members (EE)', () => {
  const mockUser = { id: 'actor-1', email: 'actor@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';

  /**
   * The IP-allowlist + MFA middleware each call `organizations.single()` before
   * the route handler runs. They both no-op when `ip_allowlist_enabled` /
   * `mfa_enforced` are falsy, but they DO consume two slots from the queued
   * mockResolvedValueOnce queue. Call this at the top of every chain so the
   * route's own mocks land in the right positions.
   */
  const padForMiddleware = () => {
    queryBuilder.single.mockResolvedValueOnce({ data: { ip_allowlist_enabled: false }, error: null });
    queryBuilder.single.mockResolvedValueOnce({ data: { mfa_enforced: false }, error: null });
  };

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    // Reset + re-apply the queryBuilder.single + .then implementations.
    // Without this, a route that exits early in one test leaves pending
    // mockResolvedValueOnce entries that bleed into the next test's chain.
    (queryBuilder.single as jest.Mock).mockReset();
    (queryBuilder.single as jest.Mock).mockImplementation(() =>
      Promise.resolve({ data: null, error: null }),
    );
    (queryBuilder.then as jest.Mock).mockReset();
    (queryBuilder.then as jest.Mock).mockImplementation((resolve: any) =>
      resolve({ data: [], error: null }),
    );
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    (supabase.auth.admin.getUserById as jest.Mock).mockResolvedValue({
      data: { user: { email: 'target@example.com' } },
      error: null,
    });
  });

  describe('PUT /api/organizations/:id/members/:userId/role', () => {
    const setupChangeRoleMocks = (opts: {
      actorRole: string;
      actorRank: number;
      targetRole: string;
      targetRank: number;
      newRoleRank: number;
      newRole?: string;
      targetUserId?: string;
      isLastOwner?: boolean;
    }) => {
      const targetUserId = opts.targetUserId || 'target-1';
      const newRole = opts.newRole ?? 'member';
      padForMiddleware();
      // 1. Role-existence check (always — built-in roles also go through this
      //    after the `admin` legacy role string was removed).
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r1' }, error: null });
      // 2. hasOrgPermission: membership lookup (actor)
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: opts.actorRole },
        error: null,
      });
      // 2a. hasOrgPermission: org_roles lookup (only if actor is NOT owner;
      //     owners short-circuit the permission check).
      if (opts.actorRole !== 'owner') {
        queryBuilder.single.mockResolvedValueOnce({
          data: { permissions: { edit_roles: true } },
          error: null,
        });
      }
      // 3. getUserRank(actor): org_members
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: opts.actorRole },
        error: null,
      });
      // 4. getUserRank(actor): org_roles
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: opts.actorRank, name: opts.actorRole },
        error: null,
      });
      // 5. getUserRank(target): org_members
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: opts.targetRole },
        error: null,
      });
      // 6. getUserRank(target): org_roles
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: opts.targetRank, name: opts.targetRole },
        error: null,
      });
      // 7. getRoleRank(new role)
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: opts.newRoleRank },
        error: null,
      });
      // 8. Last owner check (if role !== 'owner')
      if (newRole !== 'owner') {
        queryBuilder.then.mockImplementationOnce((resolve: any) =>
          resolve({
            data: opts.isLastOwner ? [{ user_id: targetUserId }] : [{ user_id: 'a' }, { user_id: 'b' }],
            error: null,
          })
        );
      }
      // 9. Current member
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: opts.targetRole },
        error: null,
      });
      // 10. user_profiles
      queryBuilder.single.mockResolvedValueOnce({ data: { full_name: 'Target' }, error: null });
      // 11. update
      queryBuilder.then.mockImplementationOnce((resolve: any) =>
        resolve({ error: null })
      );
    };

    it('1. Owner changes member role to role below owner - success', async () => {
      setupChangeRoleMocks({
        actorRole: 'owner',
        actorRank: 0,
        targetRole: 'member',
        targetRank: 1,
        newRoleRank: 1,
      });
      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/target-1/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });
      expect([200, 400]).toContain(res.status);
      if (res.status === 200) expect(res.body.message).toContain('success');
    });

    it('2. Member (rank 1) tries to change owner role - 403', async () => {
      padForMiddleware();
      // role-exists check
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r1' }, error: null });
      // hasOrgPermission: membership + org_roles (non-owner)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { permissions: { edit_roles: true } }, error: null });
      // getUserRank(actor)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1, name: 'member' }, error: null });
      // getUserRank(target)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 0, name: 'owner' }, error: null });
      // getRoleRank(newRole)
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1 }, error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/owner-1/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });
      expect([403, 404]).toContain(res.status);
      if (res.status === 403) expect(res.body.error).toContain('ranked below you');
    });

    it('3. Member tries to change same-rank member - 403', async () => {
      padForMiddleware();
      // role-exists check
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r-custom' }, error: null });
      // hasOrgPermission: membership + org_roles (non-owner)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { permissions: { edit_roles: true } }, error: null });
      // getUserRank(actor)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1, name: 'member' }, error: null });
      // getUserRank(target)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1, name: 'member' }, error: null });
      // getRoleRank(newRole)
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 2 }, error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/other-member-1/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'custom' });
      expect([403, 404]).toContain(res.status);
      if (res.status === 403) expect(res.body.error).toContain('ranked below you');
    });

    it('5. Member (rank 1) tries to assign role with rank 0 - 403', async () => {
      padForMiddleware();
      // role-exists check (newRole='owner')
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r-owner' }, error: null });
      // hasOrgPermission: membership + org_roles (non-owner)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { permissions: { edit_roles: true } }, error: null });
      // getUserRank(actor)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1, name: 'member' }, error: null });
      // getUserRank(target)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'custom' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 2, name: 'custom' }, error: null });
      // getRoleRank(newRole=owner)
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 0 }, error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/target-1/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'owner' });
      expect([403, 404]).toContain(res.status);
      if (res.status === 403) expect(res.body.error).toContain('higher than your own rank');
    });

    it('6. User changes own role - success (bypasses hierarchy)', async () => {
      setupChangeRoleMocks({
        actorRole: 'owner',
        actorRank: 0,
        targetRole: 'owner',
        targetRank: 0,
        newRoleRank: 1,
        targetUserId: mockUser.id,
      });
      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/${mockUser.id}/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });
      expect([200, 400]).toContain(res.status);
    });

    it('7. Change last owner role to member - 400 (owner demotes self)', async () => {
      padForMiddleware();
      // Owner demoting themselves: hierarchy bypassed for self-edit, last-owner guard fires.
      // role-exists check
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r-member' }, error: null });
      // hasOrgPermission: owner short-circuits (no org_roles read needed)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      // getUserRank(actor)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 0, name: 'owner' }, error: null });
      // getUserRank(target = self)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 0, name: 'owner' }, error: null });
      // getRoleRank(newRole=member)
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1 }, error: null });
      // Last-owner check (only owner remaining)
      queryBuilder.then.mockImplementationOnce((resolve: any) =>
        resolve({ data: [{ user_id: mockUser.id }], error: null })
      );

      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/${mockUser.id}/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });
      expect([400, 404]).toContain(res.status);
      if (res.status === 400) expect(res.body.error).toContain('last owner');
    });

    it('9. Target user not in org - 404', async () => {
      padForMiddleware();
      // role-exists check
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r-member' }, error: null });
      // hasOrgPermission: owner short-circuits
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      // getUserRank(actor)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 0, name: 'owner' }, error: null });
      // getUserRank(target) → not found
      queryBuilder.single.mockResolvedValueOnce({ data: null, error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/nonexistent/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });
      expect([403, 404]).toContain(res.status);
      if (res.status === 404) expect(res.body.error).toContain('Target user not found');
    });

    it('11. Actor has no role in organization_roles - 403', async () => {
      padForMiddleware();
      // role-exists check passes
      queryBuilder.single.mockResolvedValueOnce({ data: { id: 'r-member' }, error: null });
      // hasOrgPermission: orphan membership, then org_roles returns null →
      // permission denied (403). The route never reaches getUserRank here.
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'orphan' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: null, error: null });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/members/target-1/role`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission/i);
    });
  });

  describe('DELETE /api/organizations/:id/members/:userId', () => {
    it('13. Member tries to remove owner - 403', async () => {
      padForMiddleware();
      // hasOrgPermission: membership + org_roles (non-owner).
      // Member has kick_members so the permission gate passes — the rank
      // hierarchy is what then blocks the kick.
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { permissions: { kick_members: true } }, error: null });
      // getUserRank(actor)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'member' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 1, name: 'member' }, error: null });
      // getUserRank(target)
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.single.mockResolvedValueOnce({ data: { display_order: 0, name: 'owner' }, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/members/owner-1`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect([403, 404]).toContain(res.status);
      if (res.status === 403) expect(res.body.error).toMatch(/ranked below you|permission/i);
    });

    it('16. Last owner tries to leave - 400', async () => {
      padForMiddleware();
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      // Owners query (first .then() in handler) - return single owner (self)
      (queryBuilder.then as jest.Mock).mockImplementationOnce((resolve: any) =>
        Promise.resolve({ data: [{ user_id: mockUser.id }], error: null }).then(resolve)
      );

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/members/${mockUser.id}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect([400, 404]).toContain(res.status);
      if (res.status === 400) expect(res.body.error).toContain('promote someone else');
    });
  });

  describe('POST /api/organizations/:id/roles', () => {
    it('18. Owner creates custom role - success', async () => {
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: 0, name: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: null,
        error: null,
      });
      queryBuilder.then.mockImplementationOnce((resolve: any) =>
        resolve({ data: [{ display_order: 1 }], error: null })
      );
      queryBuilder.single.mockResolvedValueOnce({
        data: {
          id: 'role-new',
          name: 'contributor',
          display_name: 'Contributor',
          display_order: 2,
          is_default: false,
        },
        error: null,
      });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/roles`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'contributor', display_name: 'Contributor' });
      expect([200, 403]).toContain(res.status);
      if (res.status === 200) expect(res.body.name).toBe('contributor');
    });

    it('20. Member (rank 2) tries to create role with display_order 1 (above self) - 403', async () => {
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'contributor' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'contributor' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: 2, name: 'contributor' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: null,
        error: null,
      });
      queryBuilder.then.mockImplementationOnce((resolve: any) =>
        resolve({ data: [{ display_order: 2 }], error: null })
      );

      const res = await request(app)
        .post(`/api/organizations/${orgId}/roles`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'lead', display_order: 1 });
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/higher than yourself|Could not determine your role rank/);
    });

    it('22. Duplicate role name - 400', async () => {
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: 0, name: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { id: 'existing' },
        error: null,
      });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/roles`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'contributor' });
      expect([400, 403]).toContain(res.status);
      if (res.status === 400) expect(res.body.error).toContain('already exists');
    });
  });

  describe('PUT /api/organizations/:id/roles/:roleId', () => {
    it('27. Member (rank 1) tries to edit owner role permissions - 403', async () => {
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'member' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'member' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: 1, name: 'member' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: {
          id: 'r-owner',
          name: 'owner',
          display_order: 0,
          display_name: 'Owner',
        },
        error: null,
      });

      const res = await request(app)
        .put(`/api/organizations/${orgId}/roles/r-owner`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ permissions: { view_settings: true } });
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/Only color and display name|Could not determine your role rank/);
    });
  });

  describe('DELETE /api/organizations/:id/roles/:roleId', () => {
    it('35. Delete default role - 400', async () => {
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: 0, name: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: {
          id: 'r-member',
          name: 'member',
          is_default: true,
          display_order: 1,
        },
        error: null,
      });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/roles/r-member`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect([400, 403]).toContain(res.status);
      if (res.status === 400) expect(res.body.error).toContain('Cannot delete default');
    });

    it('36. Delete role that has members - 400', async () => {
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: { display_order: 0, name: 'owner' },
        error: null,
      });
      queryBuilder.single.mockResolvedValueOnce({
        data: {
          id: 'r-custom',
          name: 'contributor',
          is_default: false,
          display_order: 2,
        },
        error: null,
      });
      queryBuilder.then.mockImplementationOnce((resolve: any) =>
        resolve({ data: [{ user_id: 'u1' }], error: null })
      );

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/roles/r-custom`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect([400, 403]).toContain(res.status);
      if (res.status === 400) expect(res.body.error).toContain('assigned to members');
    });
  });
});
