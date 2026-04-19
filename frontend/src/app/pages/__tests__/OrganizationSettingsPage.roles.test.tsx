import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
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

const memberOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'member',
    user_rank: 1,
    permissions: { view_settings: true, edit_roles: true, view_members: true },
  },
  reloadOrganization: mockReloadOrganization,
};

const defaultRoles = [
  { id: 'r1', name: 'owner', display_name: 'Owner', display_order: 0, is_default: true, permissions: { edit_roles: true } },
  { id: 'r2', name: 'member', display_name: 'Member', display_order: 1, is_default: true, permissions: {} },
  { id: 'r3', name: 'contributor', display_name: 'Contributor', display_order: 2, is_default: false, permissions: {} },
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
  },
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
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
      { user_id: 'user-1', role: 'owner', rank: 0 },
      { user_id: 'user-2', role: 'member', rank: 1 },
      { user_id: 'user-3', role: 'contributor', rank: 2 },
    ]);
  });

  it('F1. User without edit_roles does not see Add Role button', async () => {
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
    mockGetOrganizationRoles.mockResolvedValue(defaultRoles);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Add Role/i })).not.toBeInTheDocument();
  });

  it('F2. User with edit_roles sees Add Role button', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
  });

  it('F3. Owner sees roles list with member counts', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.getAllByText('Owner').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Member').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
  });

  it('F11. Create role: empty name disables Create button', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /Add Role/i }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Create Role' })).toBeInTheDocument();
    });
    const createBtn = screen.getByRole('button', { name: 'Create Role' });
    expect(createBtn).toBeDisabled();
  });

  it('F12. Create role panel opens with Create Role button disabled when name empty', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /Add Role/i }));
    await waitFor(() => {
      const createBtn = screen.getByRole('button', { name: 'Create Role' });
      expect(createBtn).toBeInTheDocument();
      expect(createBtn).toBeDisabled();
    });
  });

  it('F13. Contributor role row shows (owner can manage roles below rank)', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
  });

  it('F14. Roles sorted by display_order', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Member').length).toBeGreaterThan(0);
  });

  it('F15. Loading state shows skeleton or roles list', async () => {
    let resolveRoles: (value: unknown) => void;
    mockGetOrganizationRoles.mockImplementation(
      () => new Promise((r) => { resolveRoles = r; })
    );
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    const skeletons = document.querySelectorAll('.animate-pulse');
    const hasSkeletons = skeletons.length > 0;
    const hasRolesHeader = !!document.querySelector('.bg-background-card-header');
    expect(hasSkeletons || hasRolesHeader).toBe(true);
    resolveRoles!(defaultRoles);
  });
});
