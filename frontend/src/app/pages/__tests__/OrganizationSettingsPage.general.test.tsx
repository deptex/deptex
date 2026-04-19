import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockGetOrganizationRoles = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockUpdateOrganization = vi.fn();
const mockDeleteOrganization = vi.fn();
const mockTransferOrganizationOwnership = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadOrganization = vi.fn().mockResolvedValue(undefined);

const defaultRoles = [
  { id: 'r1', name: 'owner', display_name: 'Owner', display_order: 0, is_default: false, permissions: { view_settings: true, edit_roles: true } },
  { id: 'r2', name: 'admin', display_name: 'Admin', display_order: 1, is_default: true, permissions: { view_settings: true } },
  { id: 'r3', name: 'member', display_name: 'Member', display_order: 2, is_default: false, permissions: {} },
];

const ownerMember = { user_id: 'user-1', email: 'owner@test.com', full_name: 'Owner', role: 'owner' };
const otherMember = { user_id: 'user-2', email: 'other@test.com', full_name: 'Other User', role: 'admin' };

let mockOrgContext: {
  organization: { id: string; name: string; role: string; permissions: { view_settings: boolean } };
  reloadOrganization: ReturnType<typeof vi.fn>;
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1', section: 'general' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => mockOrgContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizationRoles: (...args: unknown[]) => mockGetOrganizationRoles(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    updateOrganization: (...args: unknown[]) => mockUpdateOrganization(...args),
    deleteOrganization: (...args: unknown[]) => mockDeleteOrganization(...args),
    transferOrganizationOwnership: (...args: unknown[]) => mockTransferOrganizationOwnership(...args),
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

describe('OrganizationSettingsPage – General', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrganizationRoles.mockResolvedValue(defaultRoles);
    mockGetOrganizationMembers.mockResolvedValue([ownerMember]);
    mockUpdateOrganization.mockResolvedValue({});
    mockDeleteOrganization.mockResolvedValue({ message: 'Deleted' });
    mockTransferOrganizationOwnership.mockResolvedValue({ message: 'Transferred' });
    mockReloadOrganization.mockResolvedValue(undefined);

    mockOrgContext = {
      organization: {
        id: 'org-1',
        name: 'Test Org',
        role: 'owner',
        permissions: { view_settings: true },
      },
      reloadOrganization: mockReloadOrganization,
    };
  });

  it('shows General heading when on general tab', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
  });

  it('owner sees organization details card with editable name and Save button', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.getByText('Organization details')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter organization name')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    const nameInput = screen.getByPlaceholderText('Enter organization name');
    expect(nameInput).not.toBeDisabled();
  });

  it('non-owner sees read-only org details and lock message', async () => {
    mockOrgContext.organization = {
      id: 'org-1',
      name: 'Test Org',
      role: 'admin',
      permissions: { view_settings: true },
    };
    mockGetOrganizationMembers.mockResolvedValue([ownerMember, { ...otherMember, user_id: 'user-2' }]);

    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.getByPlaceholderText('Enter organization name')).toBeDisabled();
    expect(screen.getByText('Only the organization owner can edit these settings.')).toBeInTheDocument();
  });

  it('owner sees Transfer Ownership card', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Transfer Ownership')).toBeInTheDocument();
    });
  });

  it('non-owner does not see Transfer Ownership card', async () => {
    mockOrgContext.organization = {
      id: 'org-1',
      name: 'Test Org',
      role: 'admin',
      permissions: { view_settings: true },
    };
    mockGetOrganizationMembers.mockResolvedValue([ownerMember, otherMember]);

    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.queryByText('Transfer Ownership')).not.toBeInTheDocument();
  });

  it('owner sees Danger Zone', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    expect(screen.getByText('Delete Organization')).toBeInTheDocument();
  });

  it('non-owner does not see Danger Zone', async () => {
    mockOrgContext.organization = {
      id: 'org-1',
      name: 'Test Org',
      role: 'admin',
      permissions: { view_settings: true },
    };
    mockGetOrganizationMembers.mockResolvedValue([ownerMember, otherMember]);

    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.queryByText('Danger Zone')).not.toBeInTheDocument();
  });

  it('Transfer button is disabled when no member selected', async () => {
    mockGetOrganizationMembers.mockResolvedValue([ownerMember, otherMember]);

    render(<OrganizationSettingsPage />);
    const transferBtn = await screen.findByRole('button', { name: 'Transfer' }, { timeout: 5000 });
    expect(transferBtn).toBeDisabled();
  });

  it('no other members shows invite message', async () => {
    mockGetOrganizationMembers.mockResolvedValue([ownerMember]);

    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Transfer Ownership')).toBeInTheDocument();
    });
    expect(screen.getByText(/No other members available to transfer ownership to/)).toBeInTheDocument();
  });

  it('Delete Forever is disabled until org name is typed', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Delete Forever' })).toBeInTheDocument();
    });
    const deleteForeverBtn = screen.getByRole('button', { name: 'Delete Forever' });
    expect(deleteForeverBtn).toBeDisabled();
  });

  it('Delete Forever keeps text during loading', async () => {
    let resolveDelete: (value: unknown) => void;
    mockDeleteOrganization.mockImplementation(() => new Promise((r) => { resolveDelete = r; }));

    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Org')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Org'), 'Test Org');
    const deleteForeverBtn = screen.getByRole('button', { name: 'Delete Forever' });
    await userEvent.click(deleteForeverBtn);

    await waitFor(() => {
      expect(deleteForeverBtn).toHaveTextContent('Delete Forever');
    });
    resolveDelete!({});
  });

  it('Transfer button keeps text during loading', async () => {
    let resolveTransfer: (value: unknown) => void;
    mockTransferOrganizationOwnership.mockImplementation(() => new Promise((r) => { resolveTransfer = r; }));

    mockGetOrganizationMembers.mockResolvedValue([ownerMember, otherMember]);

    render(<OrganizationSettingsPage />);
    const transferBtn = await screen.findByRole('button', { name: 'Transfer' }, { timeout: 5000 });

    const memberDropdown = screen.getByRole('button', { name: /Select a member/ });
    await userEvent.click(memberDropdown);
    await waitFor(() => {
      expect(screen.getByText('Other User')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Other User'));

    await userEvent.click(transferBtn);

    await waitFor(() => {
      expect(transferBtn).toHaveTextContent('Transfer');
    });
    resolveTransfer!({ message: 'Transferred' });
  });

  it('Delete Forever calls api.deleteOrganization when confirmed', async () => {
    mockDeleteOrganization.mockResolvedValue({ message: 'Deleted' });

    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Org')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Org'), 'Test Org');
    await userEvent.click(screen.getByRole('button', { name: 'Delete Forever' }));

    await waitFor(() => {
      expect(mockDeleteOrganization).toHaveBeenCalledWith('org-1');
    });
  });

  it('Transfer calls api.transferOrganizationOwnership with correct params when member selected', async () => {
    mockGetOrganizationMembers.mockResolvedValue([ownerMember, otherMember]);

    render(<OrganizationSettingsPage />);
    const transferBtn = await screen.findByRole('button', { name: 'Transfer' }, { timeout: 5000 });

    const memberDropdown = screen.getByRole('button', { name: /Select a member/ });
    await userEvent.click(memberDropdown);
    await waitFor(() => {
      expect(screen.getByText('Other User')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Other User'));

    await userEvent.click(transferBtn);

    await waitFor(() => {
      expect(mockTransferOrganizationOwnership).toHaveBeenCalledWith('org-1', 'user-2', expect.any(String));
    });
  });
});
