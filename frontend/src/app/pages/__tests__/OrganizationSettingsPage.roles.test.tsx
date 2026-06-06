import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import { useOutletContext } from 'react-router-dom';
import { api } from '../../../lib/api';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockGetOrganizationRoles = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockCreateOrganizationRole = vi.fn();
const mockUpdateOrganizationRole = vi.fn();
const mockDeleteOrganizationRole = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadOrganization = vi.fn().mockResolvedValue(undefined);

const ownerOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'owner',
    user_rank: 0,
    permissions: { view_settings: true, edit_roles: true, view_members: true },
  },
  reloadOrganization: mockReloadOrganization,
};

const defaultRoles = [
  { id: 'r1', name: 'owner', display_name: 'Owner', display_order: 0, is_default: true, color: null, permissions: { edit_roles: true } },
  { id: 'r2', name: 'member', display_name: 'Member', display_order: 1, is_default: true, color: null, permissions: {} },
  { id: 'r3', name: 'contributor', display_name: 'Contributor', display_order: 2, is_default: false, color: '#3b82f6', permissions: {} },
];

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1', section: 'roles' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => ownerOrgContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizationRoles: (...args: unknown[]) => mockGetOrganizationRoles(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    createOrganizationRole: (...args: unknown[]) => mockCreateOrganizationRole(...args),
    updateOrganizationRole: (...args: unknown[]) => mockUpdateOrganizationRole(...args),
    deleteOrganizationRole: (...args: unknown[]) => mockDeleteOrganizationRole(...args),
    getOrganizationConnections: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast, toasts: [] }),
}));

vi.mock('../../../lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({
        data: { session: { access_token: 'token' } },
        error: null,
      }),
    },
    from: vi.fn(() => ({
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({ data: null, error: null }),
    })),
  },
}));

describe('OrganizationSettingsPage – Roles', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useOutletContext).mockReturnValue(ownerOrgContext as never);
    mockGetOrganizationRoles.mockResolvedValue(defaultRoles);
    mockGetOrganizationMembers.mockResolvedValue([
      { user_id: 'user-1', role: 'owner', rank: 0, email: 'owner@test.com' },
      { user_id: 'user-2', role: 'member', rank: 1, email: 'member@test.com' },
      { user_id: 'user-3', role: 'contributor', rank: 2, email: 'contrib@test.com' },
    ]);
    mockCreateOrganizationRole.mockResolvedValue({
      id: 'r-new',
      name: 'lead',
      display_name: 'Lead',
      display_order: 3,
      is_default: false,
      color: '#22c55e',
      permissions: {},
    });
    mockUpdateOrganizationRole.mockResolvedValue({
      id: 'r3',
      name: 'contributor',
      display_name: 'Contributor',
      display_order: 2,
      is_default: false,
      color: '#3b82f6',
      permissions: {},
    });
    mockDeleteOrganizationRole.mockResolvedValue({ message: 'Role deleted successfully' });
  });

  describe('Permissions and visibility', () => {
    it('hides Add Role button when user lacks edit_roles', async () => {
      vi.mocked(useOutletContext).mockReturnValue({
        organization: {
          id: 'org-1',
          name: 'Test Org',
          role: 'member',
          user_rank: 1,
          permissions: { view_settings: true, edit_roles: false, view_members: true },
        },
        reloadOrganization: mockReloadOrganization,
      } as never);
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
      });
      expect(screen.queryByRole('button', { name: /Add Role/i })).not.toBeInTheDocument();
    });

    it('shows Add Role button when user has edit_roles', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
      });
    });

    it('renders all roles in display_order', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Owner').length).toBeGreaterThan(0);
        expect(screen.getAllByText('Member').length).toBeGreaterThan(0);
        expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
      });
    });

    it('shows member counts per role', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        // Each role row shows "N members" — three roles each with exactly 1 member here.
        const oneMember = screen.getAllByText(/1 member/);
        expect(oneMember.length).toBeGreaterThanOrEqual(3);
      });
    });
  });

  describe('Add Role panel', () => {
    it('opens with the Create Role button disabled until a name is typed', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
      });
      await userEvent.click(screen.getByRole('button', { name: /Add Role/i }));

      const createBtn = await screen.findByRole('button', { name: 'Create Role' });
      expect(createBtn).toBeDisabled();
    });

    it('enables Create Role once the name input has content', async () => {
      render(<OrganizationSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: /Add Role/i }));

      const nameInput = await screen.findByRole('textbox');
      await userEvent.type(nameInput, 'Lead');

      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Create Role' })).toBeEnabled();
      });
    });

    it('calls createOrganizationRole with name, display_name, color, permissions, display_order on submit', async () => {
      render(<OrganizationSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: /Add Role/i }));

      const nameInput = await screen.findByRole('textbox');
      await userEvent.type(nameInput, 'Lead');
      await userEvent.click(screen.getByRole('button', { name: 'Create Role' }));

      await waitFor(() => {
        expect(mockCreateOrganizationRole).toHaveBeenCalledTimes(1);
      });
      const [orgArg, payload] = mockCreateOrganizationRole.mock.calls[0] as [string, Record<string, unknown>];
      expect(orgArg).toBe('org-1');
      expect(payload.name).toBe('lead');
      expect(payload.display_name).toBe('Lead');
      expect(payload.display_order).toBe(defaultRoles.length);
      expect(payload).toHaveProperty('permissions');
      expect(payload).toHaveProperty('color');
    });

    it('blocks creating a role with a name that already exists and never calls the API', async () => {
      render(<OrganizationSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: /Add Role/i }));

      const nameInput = await screen.findByRole('textbox');
      await userEvent.type(nameInput, 'Contributor');
      await userEvent.click(screen.getByRole('button', { name: 'Create Role' }));

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
          title: 'Role exists',
          variant: 'destructive',
        }));
      });
      expect(mockCreateOrganizationRole).not.toHaveBeenCalled();
    });

    it('surfaces a toast when createOrganizationRole rejects', async () => {
      mockCreateOrganizationRole.mockRejectedValueOnce(new Error('boom'));
      render(<OrganizationSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: /Add Role/i }));

      const nameInput = await screen.findByRole('textbox');
      await userEvent.type(nameInput, 'Lead');
      await userEvent.click(screen.getByRole('button', { name: 'Create Role' }));

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
          title: 'Failed to create role',
          variant: 'destructive',
        }));
      });
    });

    it('shows Cancel button alongside Create Role in the panel footer', async () => {
      render(<OrganizationSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: /Add Role/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Create Role' })).toBeInTheDocument();
      });
    });
  });

  describe('Role row affordances', () => {
    it('does not render a delete button for default roles (member / owner)', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Member').length).toBeGreaterThan(0);
      });

      // Member row delete button must not exist — only Settings is rendered for it.
      // We check by title attribute since the delete button has title="Delete".
      const deleteButtons = screen.queryAllByTitle('Delete');
      // contributor (custom, below owner) is the only one that can be deleted.
      expect(deleteButtons.length).toBe(1);
    });

    it('deleting a custom role calls deleteOrganizationRole and surfaces success toast', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
      });

      const deleteBtn = screen.getByTitle('Delete');
      await userEvent.click(deleteBtn);

      await waitFor(() => {
        expect(mockDeleteOrganizationRole).toHaveBeenCalledWith('org-1', 'r3');
        expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
          title: 'Role deleted',
        }));
      });
    });

    it('shows the "Your Role" badge on the row matching the actor', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText(/Your Role/i)).toBeInTheDocument();
      });
    });
  });

  describe('Role Settings panel', () => {
    it('opens with the role name + color seeded when Settings is clicked', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
      });

      const settingsBtns = screen.getAllByTitle('Settings');
      // Find the Contributor settings button by walking up to find the row text — pick the last one.
      await userEvent.click(settingsBtns[settingsBtns.length - 1]);

      await waitFor(() => {
        // Heading is "Contributor Settings"
        expect(screen.getByRole('heading', { name: /Contributor Settings/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Save Changes' })).toBeInTheDocument();
      });
    });

    it('Save Changes calls updateOrganizationRole with display_name + color + permissions', async () => {
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
      });

      const settingsBtns = screen.getAllByTitle('Settings');
      await userEvent.click(settingsBtns[settingsBtns.length - 1]);

      await screen.findByRole('button', { name: 'Save Changes' });
      await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

      await waitFor(() => {
        expect(mockUpdateOrganizationRole).toHaveBeenCalled();
      });
      const call = mockUpdateOrganizationRole.mock.calls[0] as [string, string, Record<string, unknown>];
      expect(call[0]).toBe('org-1');
      expect(call[1]).toBe('r3');
      expect(call[2]).toHaveProperty('display_name', 'Contributor');
      expect(call[2]).toHaveProperty('color');
      expect(call[2]).toHaveProperty('permissions');
    });

    it('shows the read-only Lock notice when the actor views their own role', async () => {
      vi.mocked(useOutletContext).mockReturnValue({
        organization: {
          id: 'org-1',
          name: 'Test Org',
          role: 'contributor',
          user_rank: 2,
          permissions: { view_settings: true, edit_roles: true, view_members: true },
        },
        reloadOrganization: mockReloadOrganization,
      } as never);
      // The contributor row's loaded permissions are what gate the Settings button visibility,
      // so the actor needs edit_roles in the role record itself, not just the cached org permissions.
      mockGetOrganizationRoles.mockResolvedValue([
        defaultRoles[0],
        defaultRoles[1],
        { ...defaultRoles[2], permissions: { edit_roles: true } },
      ]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
      });

      const settingsBtns = await screen.findAllByTitle('Settings');
      await userEvent.click(settingsBtns[settingsBtns.length - 1]);

      await waitFor(() => {
        expect(screen.getByText(/You cannot edit your own role\./i)).toBeInTheDocument();
        // Footer collapses to single Close button (Cancel + Save Changes hidden).
        expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Save Changes' })).not.toBeInTheDocument();
      });
    });

    it('shows the read-only notice when a non-owner opens the owner role panel', async () => {
      // A non-owner with edit_roles can still view the owner row; the panel should warn
      // that the owner role cannot be modified by anyone other than the org owner.
      vi.mocked(useOutletContext).mockReturnValue({
        organization: {
          id: 'org-1',
          name: 'Test Org',
          role: 'contributor',
          user_rank: 2,
          permissions: { view_settings: true, edit_roles: true, view_members: true },
        },
        reloadOrganization: mockReloadOrganization,
      } as never);
      mockGetOrganizationRoles.mockResolvedValue([
        defaultRoles[0],
        defaultRoles[1],
        { ...defaultRoles[2], permissions: { edit_roles: true } },
      ]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Owner').length).toBeGreaterThan(0);
      });

      const settingsBtns = await screen.findAllByTitle('Settings');
      // Owner is the first row; its Settings button is the first one rendered.
      await userEvent.click(settingsBtns[0]);

      await waitFor(() => {
        expect(screen.getByText(/owner role cannot be modified/i)).toBeInTheDocument();
      });
    });

    it('surfaces a toast when updateOrganizationRole rejects', async () => {
      mockUpdateOrganizationRole.mockRejectedValueOnce(new Error('boom'));
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
      });

      const settingsBtns = screen.getAllByTitle('Settings');
      await userEvent.click(settingsBtns[settingsBtns.length - 1]);

      await screen.findByRole('button', { name: 'Save Changes' });
      await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
          title: 'Failed to update role',
          variant: 'destructive',
        }));
      });
    });
  });

  describe('Lazy load', () => {
    it('does not fetch roles when the active section is not Roles', async () => {
      // Override useParams persistently for this test (mockReturnValueOnce
      // only intercepts the first of many useParams calls during render).
      const rrd = await import('react-router-dom');
      vi.mocked(rrd.useParams).mockReturnValue({ id: 'org-1', section: 'general' });

      try {
        render(<OrganizationSettingsPage />);
        // Wait for the page to settle on General.
        await waitFor(() => {
          expect(screen.queryByRole('heading', { name: 'Roles' })).not.toBeInTheDocument();
        });

        // The cache-seed effect reads localStorage; only loadRoles() hits the API.
        expect(mockGetOrganizationRoles).not.toHaveBeenCalled();
      } finally {
        // Restore default mock so later tests in the suite see section: 'roles' again.
        vi.mocked(rrd.useParams).mockReturnValue({ id: 'org-1', section: 'roles' });
      }
    });
  });

  describe('Empty state', () => {
    it('shows the iconed empty state when no roles are returned', async () => {
      mockGetOrganizationRoles.mockResolvedValue([]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('No roles found')).toBeInTheDocument();
      });
      expect(
        screen.getByText(/doesn't have any roles configured/i)
      ).toBeInTheDocument();
    });
  });
});
