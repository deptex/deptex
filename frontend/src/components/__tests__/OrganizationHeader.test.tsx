import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../test/utils';
import OrganizationHeader from '../OrganizationHeader';
import { Organization, RolePermissions } from '../../lib/api';
import { api } from '../../lib/api';

// Mock dependencies
vi.mock('../../lib/api', () => ({
  api: {
    getOrganizationRoles: vi.fn(),
  },
}));

vi.mock('../OrganizationTabs', () => ({
  default: ({ userPermissions }: any) => (
    <div data-testid="org-tabs">
      Tabs Permissions: {userPermissions ? 'Loaded' : 'Null'}
    </div>
  ),
}));

vi.mock('../OrganizationSwitcher', () => ({
  default: () => <div>OrgSwitcher</div>,
}));

vi.mock('../AppHeader', () => ({
  default: ({ customLeftContent }: any) => <div>AppHeader: {customLeftContent}</div>,
}));

vi.mock('../RoleBadge', () => ({
  RoleBadge: () => <div>RoleBadge</div>,
}));

describe('OrganizationHeader', () => {
  const mockOrg: Organization = {
    id: 'org-1',
    name: 'Test Org',
    plan: 'free',
    created_at: '2023-01-01',
    updated_at: '2023-01-01',
    role: 'admin',
    permissions: undefined, // Let it fetch
  };

  const mockPermissions: RolePermissions = {
    view_settings: true,
    manage_billing: true,
    view_activity: true,
    manage_compliance: true,
    interact_with_security_agent: true,
    manage_aegis: true,
    view_members: true,
    add_members: true,
    edit_roles: true,
    edit_permissions: true,
    kick_members: true,
    manage_teams_and_projects: true,
    manage_integrations: true,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('fetches permissions if not present on organization object', async () => {
    (api.getOrganizationRoles as any).mockResolvedValue([
      { name: 'admin', permissions: mockPermissions }
    ]);

    render(<OrganizationHeader organization={mockOrg} />);

    // Check if API was called
    await waitFor(() => {
      expect(api.getOrganizationRoles).toHaveBeenCalledWith('org-1');
    });

    // Check if tabs received permissions (via our mock)
    expect(screen.getByTestId('org-tabs')).toHaveTextContent('Tabs Permissions: Loaded');
  });

  it('uses permissions from organization object if present', async () => {
    const orgWithPerms = { ...mockOrg, permissions: mockPermissions };

    render(<OrganizationHeader organization={orgWithPerms} />);

    // Tabs should have permissions immediately
    expect(screen.getByTestId('org-tabs')).toHaveTextContent('Tabs Permissions: Loaded');

    // Note: The component currently fetches roles again even if permissions are present,
    // likely to refresh data. So we don't assert that api is not called.
  });

  it('uses cached permissions from localStorage if available', async () => {
    localStorage.setItem('org_permissions_org-1', JSON.stringify(mockPermissions));

    render(<OrganizationHeader organization={mockOrg} />);

    // Should use cache immediately (API might still be called in background, checking implementation)
    // Implementation says:
    /*
      useEffect(() => {
        const loadUserPermissions = async () => {
             ...
             const roles = await api.getOrganizationRoles(organization.id);
             ...
        }
        loadUserPermissions();
      }, ...);
    */
    // So API IS called even if cache exists?
    // Let's check the code:
    /*
      // Initialize permissions from localStorage cache first
      const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(() => { ... });

      useEffect(() => {
        // ... loadUserPermissions ...
      }, ...);
    */
    // Yes, it initializes from cache, but then fetches fresh data.

    // We expect "Tabs Permissions: Loaded" immediately.
    expect(screen.getByTestId('org-tabs')).toHaveTextContent('Tabs Permissions: Loaded');

    // API is eventually called to refresh
    await waitFor(() => {
      expect(api.getOrganizationRoles).toHaveBeenCalledWith('org-1');
    });
  });
});
