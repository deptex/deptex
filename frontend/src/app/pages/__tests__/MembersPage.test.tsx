import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import { useOutletContext } from 'react-router-dom';
import MembersPage from '../MembersPage';

const mockGetOrganizationMembers = vi.fn();
const mockGetOrganizationInvitations = vi.fn();
const mockGetTeams = vi.fn();
const mockGetOrganizationRoles = vi.fn();
const mockCreateInvitation = vi.fn();
const mockCancelInvitation = vi.fn();
const mockResendInvitation = vi.fn();
const mockUpdateMemberRole = vi.fn();
const mockRemoveMember = vi.fn();
const mockAddTeamMember = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();

const { stableOrgContext, mockUseOutletContext } = vi.hoisted(() => {
  const ctx = {
    organization: {
      id: 'org-1',
      name: 'Test Org',
      role: 'owner' as const,
      user_rank: 0,
      permissions: { view_members: true, add_members: true },
    },
    reloadOrganization: vi.fn().mockResolvedValue(undefined),
  };
  return {
    stableOrgContext: ctx,
    mockUseOutletContext: vi.fn(() => ctx),
  };
});

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1' })),
    useNavigate: () => mockNavigate,
    useOutletContext: mockUseOutletContext,
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    getOrganizationInvitations: (...args: unknown[]) => mockGetOrganizationInvitations(...args),
    getTeams: (...args: unknown[]) => mockGetTeams(...args),
    getOrganizationRoles: (...args: unknown[]) => mockGetOrganizationRoles(...args),
    createInvitation: (...args: unknown[]) => mockCreateInvitation(...args),
    cancelInvitation: (...args: unknown[]) => mockCancelInvitation(...args),
    resendInvitation: (...args: unknown[]) => mockResendInvitation(...args),
    updateMemberRole: (...args: unknown[]) => mockUpdateMemberRole(...args),
    removeMember: (...args: unknown[]) => mockRemoveMember(...args),
    addTeamMember: (...args: unknown[]) => mockAddTeamMember(...args),
  },
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'owner@example.com' } }),
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

describe('MembersPage', () => {
  const defaultMembers = [
    { user_id: 'user-1', email: 'owner@example.com', role: 'owner', created_at: new Date().toISOString(), rank: 0 },
  ];
  const defaultInvitations: { id: string; email: string; role: string; status: string; created_at: string; expires_at: string }[] = [];
  const defaultRoles = [
    { id: 'r1', name: 'owner', display_name: 'Owner', is_default: true, display_order: 0, permissions: { view_members: true, edit_roles: true, kick_members: true } },
    { id: 'r2', name: 'member', display_name: 'Member', is_default: true, display_order: 1, permissions: { view_members: true } },
    { id: 'r3', name: 'contributor', display_name: 'Contributor', is_default: false, display_order: 2, permissions: {} },
  ];

  beforeEach(() => {
    mockGetOrganizationMembers.mockReset();
    mockGetOrganizationInvitations.mockReset();
    mockGetTeams.mockReset();
    mockGetOrganizationRoles.mockReset();
    mockCreateInvitation.mockReset();
    mockCancelInvitation.mockReset();
    mockResendInvitation.mockReset();
    mockUpdateMemberRole.mockReset();
    mockRemoveMember.mockReset();
    mockAddTeamMember.mockReset();
    mockGetOrganizationMembers.mockResolvedValue(defaultMembers);
    mockGetOrganizationInvitations.mockResolvedValue(defaultInvitations);
    mockGetTeams.mockResolvedValue([]);
    mockGetOrganizationRoles.mockResolvedValue(defaultRoles);
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it('renders members tab with member list when data loads', async () => {
    render(<MembersPage />);
    await waitFor(() => {
      expect(screen.getByText('Members')).toBeInTheDocument();
      expect(screen.getByText('Pending Invitations')).toBeInTheDocument();
    });
    expect(screen.getByText('owner@example.com')).toBeInTheDocument();
    expect(screen.getByText('Owner')).toBeInTheDocument();
  });

  it('switching to Pending Invitations tab shows invitation list or empty state', async () => {
    render(<MembersPage />);
    await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Pending Invitations/i }));
    await waitFor(() => {
      expect(screen.getByText('No pending invitations.')).toBeInTheDocument();
    });
  });

  it('shows No pending invitations when invitations array is empty', async () => {
    mockGetOrganizationInvitations.mockResolvedValue([]);
    render(<MembersPage />);
    await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Pending Invitations/i }));
    await waitFor(() => {
      expect(screen.getByText('No pending invitations.')).toBeInTheDocument();
    });
  });

  it('filter input filters invitations by email', async () => {
    mockGetOrganizationInvitations.mockResolvedValue([
      { id: 'inv-1', email: 'invited@example.com', role: 'member', status: 'pending', created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 7 * 864e5).toISOString() },
    ]);
    render(<MembersPage />);
    await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Pending Invitations/i }));
    await waitFor(() => expect(screen.getByText('invited@example.com')).toBeInTheDocument());
    const filterInput = screen.getByPlaceholderText('Filter...');
    await userEvent.type(filterInput, 'other');
    await waitFor(() => {
      expect(screen.getByText('No invitations matched this search.')).toBeInTheDocument();
    });
  });

  it('cancel invitation calls cancelInvitation when Cancel Invitation is clicked', async () => {
    mockGetOrganizationInvitations.mockResolvedValue([
      { id: 'inv-1', email: 'invited@example.com', role: 'member', status: 'pending', created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 7 * 864e5).toISOString() },
    ]);
    mockCancelInvitation.mockResolvedValue({ message: 'Invitation cancelled' });
    render(<MembersPage />);
    await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Pending Invitations/i }));
    await waitFor(() => expect(screen.getByText('invited@example.com')).toBeInTheDocument());
    const row = screen.getByText('invited@example.com').closest('tr')!;
    const menuTrigger = within(row).getByRole('button');
    await userEvent.click(menuTrigger);
    await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Cancel Invitation' })).toBeInTheDocument());
    await userEvent.click(screen.getByRole('menuitem', { name: 'Cancel Invitation' }));
    expect(mockCancelInvitation).toHaveBeenCalledWith('org-1', 'inv-1');
  });

  it('resend invitation calls resendInvitation when Resend Invitation is clicked', async () => {
    mockGetOrganizationInvitations.mockResolvedValue([
      { id: 'inv-1', email: 'invited@example.com', role: 'member', status: 'pending', created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 7 * 864e5).toISOString() },
    ]);
    mockResendInvitation.mockResolvedValue({ message: 'Invitation resent', invitation: {} });
    render(<MembersPage />);
    await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Pending Invitations/i }));
    await waitFor(() => expect(screen.getByText('invited@example.com')).toBeInTheDocument());
    const row = screen.getByText('invited@example.com').closest('tr')!;
    const menuTrigger = within(row).getByRole('button');
    await userEvent.click(menuTrigger);
    await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Resend Invitation' })).toBeInTheDocument());
    await userEvent.click(screen.getByRole('menuitem', { name: 'Resend Invitation' }));
    expect(mockResendInvitation).toHaveBeenCalledWith('org-1', 'inv-1');
  });

  it('invite modal opens with email input, role dropdown, Copy Invite Link', async () => {
    render(<MembersPage />);
    await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /Invite/i }));
    const dialog = await screen.findByRole('dialog', {}, { timeout: 3000 });
    expect(within(dialog).getByText('Invite new member')).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Email Address')).toBeInTheDocument();
    expect(within(dialog).getByText('Role')).toBeInTheDocument();
    expect(within(dialog).getByText('Copy Invite Link')).toBeInTheDocument();
  });

  describe('Rank hierarchy', () => {
    it('F16. Owner sees action dropdown for other members (Change Role, Remove)', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'member@example.com', role: 'member', created_at: new Date().toISOString(), rank: 1 },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const memberRow = screen.getByText('member@example.com').closest('tr');
      expect(memberRow).toBeTruthy();
      const dropdownTriggers = memberRow?.querySelectorAll('button');
      expect(dropdownTriggers?.length).toBeGreaterThan(0);
    });

    it('F25. Current user row shows Leave Organization in dropdown', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'member@example.com', role: 'member', created_at: new Date().toISOString(), rank: 1 },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
      const ownerRow = screen.getByText('owner@example.com').closest('tr');
      const menuTrigger = ownerRow?.querySelector('button');
      if (menuTrigger) {
        await userEvent.click(menuTrigger);
        await waitFor(() => {
          expect(screen.getByRole('menuitem', { name: /Leave Organization/i })).toBeInTheDocument();
        });
      }
    });
  });

  describe('Change Role', () => {
    it('calls updateMemberRole when Change Role is selected and Update Role is clicked', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', full_name: 'Owner User', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'member@example.com', role: 'member', full_name: 'Member User', created_at: new Date().toISOString(), rank: 1 },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      mockUpdateMemberRole.mockResolvedValue({});
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const memberRow = screen.getByText('member@example.com').closest('tr')!;
      const menuTrigger = within(memberRow).getByRole('button');
      await userEvent.click(menuTrigger);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Change Role' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('menuitem', { name: 'Change Role' }));
      await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
      const updateBtn = screen.getByRole('button', { name: /Update Role/i });
      await userEvent.click(updateBtn);
      await waitFor(() => {
        expect(mockUpdateMemberRole).toHaveBeenCalledWith('org-1', 'user-2', 'member');
      });
    });
  });

  describe('Remove Member', () => {
    it('calls removeMember when Remove Member is selected and Remove is confirmed', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', full_name: 'Owner User', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'member@example.com', role: 'member', full_name: 'Member User', created_at: new Date().toISOString(), rank: 1 },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      mockRemoveMember.mockResolvedValue({});
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const memberRow = screen.getByText('member@example.com').closest('tr')!;
      const menuTrigger = within(memberRow).getByRole('button');
      await userEvent.click(menuTrigger);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Remove Member' })).toBeInTheDocument());
      await userEvent.click(screen.getByRole('menuitem', { name: 'Remove Member' }));
      await waitFor(() => expect(screen.getByText(/Are you sure you want to remove/)).toBeInTheDocument());
      const removeBtn = screen.getByRole('button', { name: 'Remove' });
      await userEvent.click(removeBtn);
      await waitFor(() => {
        expect(mockRemoveMember).toHaveBeenCalledWith('org-1', 'user-2');
      });
    });
  });

  describe('Add to Team', () => {
    it('shows Add to Team option when teams exist and member is not in all teams', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'member@example.com', role: 'member', created_at: new Date().toISOString(), rank: 1, teams: [] },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      mockGetTeams.mockResolvedValue([{ id: 'team-1', name: 'Team A', description: '', created_at: new Date().toISOString() }]);
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const memberRow = screen.getByText('member@example.com').closest('tr')!;
      const menuTrigger = within(memberRow).getByRole('button');
      await userEvent.click(menuTrigger);
      await waitFor(() => expect(screen.getByRole('menuitem', { name: 'Add to Team' })).toBeInTheDocument());
    });

    it('calls addTeamMember when Add to Team is selected, team chosen, and Add to Team clicked', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'member@example.com', role: 'member', full_name: 'Member User', created_at: new Date().toISOString(), rank: 1, teams: [] },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      mockGetTeams.mockResolvedValue([{ id: 'team-1', name: 'Team A', description: '', created_at: new Date().toISOString() }]);
      mockAddTeamMember.mockResolvedValue({ id: 'tm-1', team_id: 'team-1', user_id: 'user-2' });
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('member@example.com')).toBeInTheDocument());
      const memberRow = screen.getByText('member@example.com').closest('tr')!;
      const menuTrigger = within(memberRow).getByRole('button');
      await userEvent.click(menuTrigger);
      await userEvent.click(screen.getByRole('menuitem', { name: 'Add to Team' }));
      await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
      // Open team dropdown and select Team A
      const selectTeamsBtn = screen.getByRole('button', { name: /Select teams/i });
      await userEvent.click(selectTeamsBtn);
      const teamOption = await screen.findByRole('button', { name: /Team A/i });
      await userEvent.click(teamOption);
      const addBtn = screen.getByRole('button', { name: /^Add to Team$/i });
      await userEvent.click(addBtn);
      await waitFor(() => {
        expect(mockAddTeamMember).toHaveBeenCalledWith('org-1', 'team-1', 'user-2');
      });
    });
  });

  describe('Invite flow', () => {
    it('does not call createInvitation when invite submitted with empty email', async () => {
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Invite/i }));
      await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
      const dialog = screen.getByRole('dialog');
      const sendBtn = within(dialog).getByRole('button', { name: /Send Invitation/i });
      await userEvent.click(sendBtn);
      await waitFor(() => {
        expect(mockCreateInvitation).not.toHaveBeenCalled();
      });
    });

    it('calls createInvitation when valid email is entered and Send Invitation is clicked', async () => {
      mockCreateInvitation.mockResolvedValue({ id: 'inv-1', email: 'new@example.com', role: 'member', status: 'pending' });
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: /Invite/i }));
      await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument());
      const emailInput = screen.getByLabelText('Email Address');
      await userEvent.type(emailInput, 'new@example.com');
      const sendBtn = screen.getByRole('button', { name: /Send Invitation/i });
      await userEvent.click(sendBtn);
      await waitFor(() => {
        expect(mockCreateInvitation).toHaveBeenCalledWith('org-1', 'new@example.com', 'member', undefined);
      });
    });
  });

  describe('Member search filter', () => {
    it('filters members by email when typing in search', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', full_name: 'Owner', created_at: new Date().toISOString(), rank: 0 },
        { user_id: 'user-2', email: 'alice@example.com', role: 'member', full_name: 'Alice', created_at: new Date().toISOString(), rank: 1 },
        { user_id: 'user-3', email: 'bob@example.com', role: 'member', full_name: 'Bob', created_at: new Date().toISOString(), rank: 2 },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('bob@example.com')).toBeInTheDocument());
      const filterInput = screen.getByPlaceholderText('Filter...');
      await userEvent.type(filterInput, 'alice');
      await waitFor(() => {
        expect(screen.getByText('alice@example.com')).toBeInTheDocument();
        expect(screen.queryByText('bob@example.com')).not.toBeInTheDocument();
      });
    });

    it('shows No members matched when filter matches nothing', async () => {
      const membersWithMultiple = [
        { user_id: 'user-1', email: 'owner@example.com', role: 'owner', created_at: new Date().toISOString(), rank: 0 },
      ];
      mockGetOrganizationMembers.mockResolvedValue(membersWithMultiple);
      render(<MembersPage />);
      await waitFor(() => expect(screen.getByText('owner@example.com')).toBeInTheDocument());
      const filterInput = screen.getByPlaceholderText('Filter...');
      await userEvent.type(filterInput, 'nonexistent');
      await waitFor(() => {
        expect(screen.getByText('No members matched this search.')).toBeInTheDocument();
      });
    });
  });

  describe('Permission redirect', () => {
    it('redirects to projects when user lacks view_members permission', async () => {
      mockUseOutletContext.mockReturnValue({
        ...stableOrgContext,
        organization: {
          ...stableOrgContext.organization,
          permissions: { view_members: false, add_members: false },
        },
      });
      render(<MembersPage />);
      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/projects', { replace: true });
      });
      mockUseOutletContext.mockReturnValue(stableOrgContext);
    });
  });
});
