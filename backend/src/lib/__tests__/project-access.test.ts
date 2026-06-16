/**
 * Regression tests for the legacy `role === 'admin'` bypass (P0).
 *
 * Roles are permission bundles: `owner` is the only structural role. A custom
 * role literally NAMED "admin" must earn access through its permissions JSONB,
 * never through its name — the old check granted full project-manage and
 * integrations-manage rights to any role named "admin" with zero permissions.
 *
 * The jest moduleNameMapper routes `../lib/supabase` to the shared singleton
 * mock, so these tests drive `setTableResponse` directly (no jest.mock here).
 */
import { checkProjectManagePermission, checkOrgManageIntegrationsPermission } from '../project-access';
import { setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

const orgId = 'org-1';
const projectId = 'proj-1';
const userId = 'user-1';

describe('lib/project-access — role-name "admin" bypass removed', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    // checkProjectManagePermission's project↔org bind.
    setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
    // No owner team for the project → the team-level fallback denies.
    setTableResponse('project_teams', 'then', { data: [], error: null });
  });

  describe('checkProjectManagePermission', () => {
    it('denies a member whose custom role is named "admin" but whose permissions JSONB lacks the key', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });

      await expect(checkProjectManagePermission(userId, orgId, projectId)).resolves.toBe(false);
    });

    it('allows a role named "admin" when its bundle actually carries manage_teams_and_projects', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', {
        data: { permissions: { manage_teams_and_projects: true } },
        error: null,
      });

      await expect(checkProjectManagePermission(userId, orgId, projectId)).resolves.toBe(true);
    });

    it('still short-circuits for the structural owner role', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });

      await expect(checkProjectManagePermission(userId, orgId, projectId)).resolves.toBe(true);
    });
  });

  describe('checkOrgManageIntegrationsPermission', () => {
    it('denies a member whose custom role is named "admin" without manage_integrations', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });

      await expect(checkOrgManageIntegrationsPermission(userId, orgId)).resolves.toBe(false);
    });

    it('allows when the bundle carries manage_integrations', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', {
        data: { permissions: { manage_integrations: true } },
        error: null,
      });

      await expect(checkOrgManageIntegrationsPermission(userId, orgId)).resolves.toBe(true);
    });

    it('still short-circuits for owner', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });

      await expect(checkOrgManageIntegrationsPermission(userId, orgId)).resolves.toBe(true);
    });
  });
});
