import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import TeamMembersPage from '../TeamMembersPage';

const mockGetTeamMembers = vi.fn();
const mockGetTeamRoles = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockAddTeamMember = vi.fn();
const mockUpdateTeamMemberRole = vi.fn();
const mockRemoveTeamMember = vi.fn();
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
  user_org_rank: 0,
  permissions: { manage_members: true, add_members: true, edit_roles: true, kick_members: true },
};

const defaultMembers: { user_id: string; email: string; full_name?: string; role: string; rank?: number; org_rank?: number }[] = [
  { user_id: 'user-1', email: 'admin@example.com', full_name: 'Admin User', role: 'admin', rank: 0, org_rank: 0 },
  { user_id: 'user-2', email: 'member@example.com', full_name: 'Member User', role: 'member', rank: 1, org_rank: 1 },
];

const defaultRoles = [
  { id: 'r1', name: 'admin', display_name: 'Admin', display_order: 0, is_default: true, permissions: {}, color: null },
  { id: 'r2', name: 'member', display_name: 'Member', display_order: 1, is_default: true, permissions: {}, color: null },
];

const defaultOrgMembers = [
  { user_id: 'user-1', email: 'admin@example.com', full_name: 'Admin User', role: 'owner', created_at: new Date().toISOString() },
  { user_id: 'user-2', email: 'member@example.com', full_name: 'Member User', role: 'member', created_at: new Date().toISOString() },
  { user_id: 'user-3', email: 'new@example.com', full_name: 'New User', role: 'member', created_at: new Date().toISOString() },
];

let mockOutletContext: {
  team: typeof defaultTeam | null;
  organizationId: string;
  reloadTeam: ReturnType<typeof vi.fn>;
  organization: { permissions?: { manage_teams_and_projects?: boolean } } | null;
  userPermissions: { manage_members?: boolean; add_members?: boolean; edit_roles?: boolean; kick_members?: boolean } | null;
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useOutletContext: vi.fn(() => mockOutletContext),
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
    getTeamRoles: (...args: unknown[]) => mockGetTeamRoles(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    addTeamMember: (...args: unknown[]) => mockAddTeamMember(...args),
    updateTeamMemberRole: (...args: unknown[]) => mockUpdateTeamMemberRole(...args),
    removeTeamMember: (...args: unknown[]) => mockRemoveTeamMember(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'admin@example.com' } }),
}));

describe('TeamMembersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetTeamMembers.mockResolvedValue(defaultMembers);
    mockGetTeamRoles.mockResolvedValue(defaultRoles);
    mockGetOrganizationMembers.mockResolvedValue(defaultOrgMembers);
    mockReloadTeam.mockResolvedValue(undefined);

    mockOutletContext = {
      team: { ...defaultTeam },
      organizationId: 'org-1',
      reloadTeam: mockReloadTeam,
      organization: { permissions: { manage_teams_and_projects: false } },
      userPermissions: {
        manage_members: true,
        add_members: true,
        edit_roles: true,
        kick_members: true,
      },
    };
  });

  describe('Initial load and rendering', () => {
    it('renders members list when data loads', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => {
        expect(screen.getByText('admin@example.com')).toBeInTheDocument();
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
      });
      expect(screen.getByText('Admin User')).toBeInTheDocument();
      expect(screen.getByText('Member User')).toBeInTheDocument();
      expect(screen.getByText('Admin')).toBeInTheDocument();
      expect(screen.getAllByText('Member').length).toBeGreaterThanOrEqual(1);
    });

    it('fetches team members, roles, and org members on mount', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      expect(mockGetTeamMembers).toHaveBeenCalledWith('org-1', 'team-1');
      expect(mockGetTeamRoles).toHaveBeenCalledWith('org-1', 'team-1');
      expect(mockGetOrganizationMembers).toHaveBeenCalledWith('org-1');
    });

    it('shows loading skeleton while data is loading', async () => {
      let resolveMembers: (value: typeof defaultMembers) => void;
      mockGetTeamMembers.mockImplementation(
        () => new Promise<typeof defaultMembers>((r) => { resolveMembers = r; })
      );
      mockGetTeamRoles.mockResolvedValue(defaultRoles);
      mockGetOrganizationMembers.mockResolvedValue(defaultOrgMembers);

      render(<TeamMembersPage />);
      const skeletons = document.querySelectorAll('.animate-pulse');
      expect(skeletons.length).toBeGreaterThan(0);

      resolveMembers!(defaultMembers);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
    });

    it('shows empty state when load fails', async () => {
      mockGetTeamMembers.mockRejectedValue(new Error('Network error'));
      mockGetTeamRoles.mockResolvedValue(defaultRoles);
      render(<TeamMembersPage />);
      await waitFor(() => {
        expect(screen.getByText('This team is empty')).toBeInTheDocument();
      }, { timeout: 3000 });
    });

    it('does not load when team or organizationId is missing', async () => {
      mockOutletContext.team = null;
      mockOutletContext.organizationId = 'org-1';
      render(<TeamMembersPage />);
      await waitFor(() => expect(mockGetTeamMembers).not.toHaveBeenCalled());
    });
  });

  describe('Search filter', () => {
    it('filters members by email when typing in search', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      const filterInput = screen.getByPlaceholderText('Filter members...');
      await userEvent.type(filterInput, 'member');
      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
        expect(screen.queryByText('admin@example.com')).not.toBeInTheDocument();
      });
    });

    it('filters members by full name', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('Admin User')).toBeInTheDocument());
      const filterInput = screen.getByPlaceholderText('Filter members...');
      await userEvent.type(filterInput, 'Member User');
      await waitFor(() => {
        expect(screen.getByText('member@example.com')).toBeInTheDocument();
        expect(screen.queryByText('admin@example.com')).not.toBeInTheDocument();
      });
    });

    it('shows "No members found" when filter matches nothing', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      const filterInput = screen.getByPlaceholderText('Filter members...');
      await userEvent.type(filterInput, 'nonexistent');
      await waitFor(() => {
        expect(screen.getByText('No members found')).toBeInTheDocument();
        expect(screen.getByText('No members match your search criteria. Press Esc to clear.')).toBeInTheDocument();
      });
    });

    it('clears search when Esc is pressed', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      const filterInput = screen.getByPlaceholderText('Filter members...');
      await userEvent.type(filterInput, 'member');
      await waitFor(() => expect(screen.queryByText('admin@example.com')).not.toBeInTheDocument());
      await userEvent.keyboard('{Escape}');
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
    });
  });

  describe('Add Member panel', () => {
    it('opens Add Member sidebar when Add Member button is clicked', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Add Member/i }));
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Add Team Member' })).toBeInTheDocument();
        expect(screen.getByPlaceholderText('Search organization members...')).toBeInTheDocument();
        expect(screen.getByText('Select Member')).toBeInTheDocument();
        expect(screen.getAllByText('Role').length).toBeGreaterThanOrEqual(1);
      });
    });

    it('hides Add Member button when user lacks add_members and manage_members permission', async () => {
      mockOutletContext.userPermissions = { add_members: false, manage_members: false };
      mockOutletContext.organization = { permissions: { manage_teams_and_projects: false } };
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      expect(screen.queryByRole('button', { name: /Add Member/i })).not.toBeInTheDocument();
    });

    it('shows org members available to add (excludes current team members)', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Add Member/i }));
      await waitFor(() => {
        expect(screen.getByText('New User')).toBeInTheDocument();
        expect(screen.getByText('new@example.com')).toBeInTheDocument();
      });
      const panel = screen.getByRole('heading', { name: 'Add Team Member' }).closest('div[class*="max-w-[420px]"]');
      expect(panel).toBeTruthy();
      expect(within(panel!).queryByText('Admin User')).not.toBeInTheDocument();
      expect(within(panel!).queryByText('Member User')).not.toBeInTheDocument();
    });

    it('adds selected member to team when Add Member is clicked', async () => {
      mockAddTeamMember.mockResolvedValue({ id: 'tm-1', team_id: 'team-1', user_id: 'user-3' });
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Add Member/i }));
      await waitFor(() => expect(screen.getByText('New User')).toBeInTheDocument());
      await userEvent.click(screen.getByText('New User'));
      const panel = screen.getByRole('heading', { name: 'Add Team Member' }).closest('div[class*="fixed"]');
      const addBtn = within(panel!).getByRole('button', { name: /^Add Member$/i });
      await userEvent.click(addBtn);
      await waitFor(() => {
        expect(mockAddTeamMember).toHaveBeenCalledWith('org-1', 'team-1', 'user-3', expect.anything());
        expect(mockReloadTeam).toHaveBeenCalled();
      });
    });

    it('Add Member button is disabled when no users selected', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Add Member/i }));
      await waitFor(() => expect(screen.getByText('New User')).toBeInTheDocument());
      const panel = screen.getByRole('heading', { name: 'Add Team Member' }).closest('div[class*="fixed"]');
      const addBtn = within(panel!).getByRole('button', { name: /^Add Member$/i });
      expect(addBtn).toBeDisabled();
    });

    it('closes Add Member panel when Cancel is clicked', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Add Member/i }));
      await waitFor(() => expect(screen.getByRole('heading', { name: 'Add Team Member' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Add Team Member' })).not.toBeInTheDocument();
      });
    });
  });

  describe('Change Role', () => {
    const getMemberRowMenuButton = () => {
      const row = screen.getByText('member@example.com').closest('div[class*="hover:bg-table-hover"]');
      return row ? within(row).getByRole('button') : null;
    };

    it('opens Change Role dialog when Change Role is selected from dropdown', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const menuTrigger = getMemberRowMenuButton();
      expect(menuTrigger).toBeTruthy();
      await userEvent.click(menuTrigger!);
      const changeRoleItem = await screen.findByRole('menuitem', { name: 'Change Role' }, { timeout: 2000 });
      await userEvent.click(changeRoleItem);
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Change Role' })).toBeInTheDocument();
        expect(screen.getAllByText(/Member User|member@example.com/).length).toBeGreaterThanOrEqual(1);
      }, { timeout: 2000 });
    });

    it('calls updateTeamMemberRole when Update Role is clicked', async () => {
      mockUpdateTeamMemberRole.mockResolvedValue({});
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const menuTrigger = getMemberRowMenuButton();
      expect(menuTrigger).toBeTruthy();
      await userEvent.click(menuTrigger!);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Change Role' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('menuitem', { name: 'Change Role' }));
      await waitFor(() => expect(screen.getByRole('button', { name: /Update Role/i })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Update Role/i }));
      await waitFor(() => {
        expect(mockUpdateTeamMemberRole).toHaveBeenCalledWith('org-1', 'team-1', 'user-2', 'r2');
      });
    });
  });

  describe('Remove / Leave member', () => {
    const getMemberRowMenuButton = () => {
      const row = screen.getByText('member@example.com').closest('div[class*="hover:bg-table-hover"]');
      return row ? within(row).getByRole('button') : null;
    };

    it('opens confirmation modal when Remove from Team is clicked', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const menuTrigger = getMemberRowMenuButton();
      expect(menuTrigger).toBeTruthy();
      await userEvent.click(menuTrigger!);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Remove from Team' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('menuitem', { name: 'Remove from Team' }));
      await waitFor(() => {
        expect(screen.getByText('Remove Member')).toBeInTheDocument();
        expect(screen.getByText('Are you sure you want to remove this member from the team?')).toBeInTheDocument();
      });
    });

    it('calls removeTeamMember when Remove is confirmed', async () => {
      mockRemoveTeamMember.mockResolvedValue({ message: 'ok' });
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const menuTrigger = getMemberRowMenuButton();
      expect(menuTrigger).toBeTruthy();
      await userEvent.click(menuTrigger!);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Remove from Team' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('menuitem', { name: 'Remove from Team' }));
      await waitFor(() => expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: 'Remove' }));
      await waitFor(() => {
        expect(mockRemoveTeamMember).toHaveBeenCalledWith('org-1', 'team-1', 'user-2');
        expect(mockReloadTeam).toHaveBeenCalled();
      });
    });

    it('current user sees Leave Team option in dropdown', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      const ownerRow = screen.getByText('(You)').closest('div[class*="hover:bg-table-hover"]');
      expect(ownerRow).toBeTruthy();
      const menuTrigger = within(ownerRow!).getByRole('button');
      await userEvent.click(menuTrigger);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Leave Team' })).toBeInTheDocument());
    });
  });

  describe('Empty state', () => {
    it('shows "This team is empty" when team has no members', async () => {
      mockGetTeamMembers.mockResolvedValue([]);
      render(<TeamMembersPage />);
      await waitFor(() => {
        expect(screen.getByText('This team is empty')).toBeInTheDocument();
        expect(screen.getByText(/Get started by adding members/)).toBeInTheDocument();
      });
    });

    it('shows Add members and Join this team buttons in empty state when user has permission', async () => {
      mockGetTeamMembers.mockResolvedValue([]);
      mockOutletContext.userPermissions = { add_members: true, manage_members: true };
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('This team is empty')).toBeInTheDocument());
      expect(screen.getByRole('button', { name: /Add members/i })).toBeInTheDocument();
    });

    it('shows "No members available to add" in Add panel when all org members are already in team', async () => {
      mockGetTeamMembers.mockResolvedValue(defaultMembers);
      mockGetOrganizationMembers.mockResolvedValue([
        { user_id: 'user-1', email: 'admin@example.com', full_name: 'Admin', role: 'owner', created_at: new Date().toISOString() },
        { user_id: 'user-2', email: 'member@example.com', full_name: 'Member', role: 'member', created_at: new Date().toISOString() },
      ]);
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Add Member/i }));
      await waitFor(() => expect(screen.getByText('No members available to add')).toBeInTheDocument());
    });
  });

  describe('Current user indicator', () => {
    it('shows (You) next to current user name', async () => {
      render(<TeamMembersPage />);
      await waitFor(() => expect(screen.getByText('admin@example.com')).toBeInTheDocument());
      expect(screen.getByText('(You)')).toBeInTheDocument();
    });
  });
});
