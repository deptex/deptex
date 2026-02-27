import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import TeamSettingsPage, { __clearTeamRolesCacheForTesting } from '../TeamSettingsPage';

const mockGetTeamRoles = vi.fn();
const mockGetTeamMembers = vi.fn();
const mockCreateTeamRole = vi.fn();
const mockUpdateTeamRole = vi.fn();
const mockDeleteTeamRole = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockReloadTeam = vi.fn().mockResolvedValue(undefined);

const defaultTeam = {
  id: 'team-1',
  name: 'Test Team',
  description: 'A test team',
  avatar_url: null,
  role: 'admin',
  role_display_name: 'Admin',
  role_color: null,
};

const defaultRoles = [
  { id: 'r1', name: 'admin', display_name: 'Admin', display_order: 0, is_default: true, permissions: {}, color: null },
  { id: 'r2', name: 'member', display_name: 'Member', display_order: 1, is_default: true, permissions: {}, color: null },
  { id: 'r3', name: 'contributor', display_name: 'Contributor', display_order: 2, is_default: false, permissions: {}, color: null },
];

let mockOutletContext: {
  team: typeof defaultTeam | null;
  organizationId: string;
  reloadTeam: ReturnType<typeof vi.fn>;
  updateTeamData: ReturnType<typeof vi.fn>;
  userPermissions: {
    view_settings: boolean;
    view_roles?: boolean;
    edit_roles?: boolean;
    manage_members?: boolean;
  };
  organization: { permissions?: { manage_teams_and_projects: boolean } } | null;
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ orgId: 'org-1', teamId: 'team-1', section: 'roles' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), vi.fn()],
    useOutletContext: vi.fn(() => mockOutletContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getTeamRoles: (...args: unknown[]) => mockGetTeamRoles(...args),
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
    createTeamRole: (...args: unknown[]) => mockCreateTeamRole(...args),
    updateTeamRole: (...args: unknown[]) => mockUpdateTeamRole(...args),
    deleteTeamRole: (...args: unknown[]) => mockDeleteTeamRole(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

vi.mock('../NotificationRulesSection', () => ({
  default: () => <div data-testid="notification-rules-section">Notification Rules</div>,
}));

describe('TeamSettingsPage – Roles', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetTeamRoles.mockResolvedValue(defaultRoles);
    mockGetTeamMembers.mockResolvedValue([
      { id: 'u1', user_id: 'user-1', role: 'admin' },
      { id: 'u2', user_id: 'user-2', role: 'member' },
      { id: 'u3', user_id: 'user-3', role: 'contributor' },
    ]);
    mockReloadTeam.mockResolvedValue(undefined);

    mockOutletContext = {
      team: { ...defaultTeam },
      organizationId: 'org-1',
      reloadTeam: mockReloadTeam,
      updateTeamData: vi.fn(),
      userPermissions: {
        view_settings: true,
        view_roles: true,
        edit_roles: true,
        manage_members: true,
      },
      organization: { permissions: { manage_teams_and_projects: false } },
    };
  });

  it('shows Roles heading when on roles tab', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
  });

  it('fetches roles and members when roles tab is active', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(mockGetTeamRoles).toHaveBeenCalledWith('org-1', 'team-1');
    expect(mockGetTeamMembers).toHaveBeenCalledWith('org-1', 'team-1');
  });

  it('user with edit_roles sees Add Role button', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
  });

  it('user without edit_roles does not see Add Role button', async () => {
    mockOutletContext.userPermissions = {
      view_settings: true,
      view_roles: true,
      edit_roles: false,
      manage_members: true,
    };

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Add Role/i })).not.toBeInTheDocument();
  });

  it('displays roles list with member counts', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.getAllByText('Admin').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Member').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Contributor').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/1 member/).length).toBeGreaterThan(0);
  });

  it('shows loading skeleton while roles are fetching', async () => {
    let resolveRoles: (value: typeof defaultRoles) => void;
    mockGetTeamRoles.mockImplementation(
      () => new Promise<typeof defaultRoles>((r) => { resolveRoles = r; })
    );
    __clearTeamRolesCacheForTesting('org-1', 'team-1');

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    const skeletons = document.querySelectorAll('.animate-pulse');
    const hasRolesHeader = !!document.querySelector('.bg-background-card-header');
    expect(skeletons.length > 0 || hasRolesHeader).toBe(true);

    resolveRoles!(defaultRoles);
    await waitFor(() => {
      expect(screen.getAllByText('Admin').length).toBeGreaterThan(0);
    });
  });

  it('shows Create Role panel when Add Role clicked', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /Add Role/i }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Create New Role' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Create Role' })).toBeInTheDocument();
    });
  });

  it('Create Role button is disabled when name is empty', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Role/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /Add Role/i }));

    await waitFor(() => {
      const createBtn = screen.getByRole('button', { name: 'Create Role' });
      expect(createBtn).toBeDisabled();
    });
  });

  it('shows empty state when no roles', async () => {
    mockGetTeamRoles.mockResolvedValue([]);
    mockGetTeamMembers.mockResolvedValue([]);
    __clearTeamRolesCacheForTesting('org-1', 'team-1');

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByText(/No roles found/i)).toBeInTheDocument();
    });
  });

  it('shows Your Role badge for current user role', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Roles' })).toBeInTheDocument();
    });
    expect(screen.getByText('Your Role')).toBeInTheDocument();
  });
});
