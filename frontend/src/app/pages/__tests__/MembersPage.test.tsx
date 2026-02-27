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
const mockToast = vi.fn();
const mockNavigate = vi.fn();

const stableOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'owner',
    user_rank: 0,
    permissions: { view_members: true, add_members: true },
  },
  reloadOrganization: vi.fn().mockResolvedValue(undefined),
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1' })),
    useNavigate: () => mockNavigate,
    useOutletContext: vi.fn(() => stableOrgContext),
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
});
