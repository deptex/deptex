import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import OrganizationsLanding from '../OrganizationsLanding';

const mockGetOrganizations = vi.fn();
const mockGetUserProfile = vi.fn();
const mockGetInvitations = vi.fn();
const mockCreateOrganization = vi.fn();
const mockAcceptInvitation = vi.fn();
const mockDeclineInvitation = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return { ...mod, useNavigate: () => mockNavigate };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizations: (...a: unknown[]) => mockGetOrganizations(...a),
    getUserProfile: (...a: unknown[]) => mockGetUserProfile(...a),
    getInvitations: (...a: unknown[]) => mockGetInvitations(...a),
    createOrganization: (...a: unknown[]) => mockCreateOrganization(...a),
    acceptInvitation: (...a: unknown[]) => mockAcceptInvitation(...a),
    declineInvitation: (...a: unknown[]) => mockDeclineInvitation(...a),
  },
}));

vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast, toasts: [] }),
}));

const pendingInvite = {
  id: 'inv-1',
  organization_id: 'org-9',
  organization_name: 'Gamma Inc',
  organization_avatar_url: null,
  role: 'member',
  status: 'pending',
};

describe('OrganizationsLanding', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    // No orgs → the page stays on the create-first-org landing instead of redirecting.
    mockGetOrganizations.mockResolvedValue([]);
    mockGetUserProfile.mockResolvedValue({ default_organization_id: null });
    mockGetInvitations.mockResolvedValue([]);
    mockCreateOrganization.mockResolvedValue({ id: 'new-org' });
    mockAcceptInvitation.mockResolvedValue({ organization_id: 'org-9' });
    mockDeclineInvitation.mockResolvedValue({});
  });

  it('shows the create-first-organization card when the user has no orgs', async () => {
    render(<OrganizationsLanding />);
    expect(await screen.findByText('Create your first organization')).toBeInTheDocument();
  });

  it('the create button is disabled until a name is typed', async () => {
    render(<OrganizationsLanding />);
    await screen.findByText('Create your first organization');

    const create = screen.getByRole('button', { name: 'Create organization' });
    expect(create).toBeDisabled();

    await userEvent.type(screen.getByLabelText('Organization Name'), 'My Org');
    expect(create).not.toBeDisabled();
  });

  it('creating an organization navigates into the new org', async () => {
    render(<OrganizationsLanding />);
    await screen.findByText('Create your first organization');

    await userEvent.type(screen.getByLabelText('Organization Name'), 'My Org');
    await userEvent.click(screen.getByRole('button', { name: 'Create organization' }));

    await waitFor(() => {
      expect(mockCreateOrganization).toHaveBeenCalledWith('My Org');
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/new-org', { replace: true });
    });
  });

  it('shows the error when creation fails', async () => {
    mockCreateOrganization.mockRejectedValueOnce(new Error('Name already taken'));
    render(<OrganizationsLanding />);
    await screen.findByText('Create your first organization');

    await userEvent.type(screen.getByLabelText('Organization Name'), 'My Org');
    await userEvent.click(screen.getByRole('button', { name: 'Create organization' }));

    await waitFor(() => {
      expect(screen.getByText('Name already taken')).toBeInTheDocument();
    });
  });

  it('renders only pending invitations', async () => {
    mockGetInvitations.mockResolvedValue([
      pendingInvite,
      { ...pendingInvite, id: 'inv-2', organization_name: 'Declined Org', status: 'declined' },
    ]);
    render(<OrganizationsLanding />);

    await waitFor(() => {
      expect(screen.getByText('Pending invitations')).toBeInTheDocument();
    });
    expect(screen.getByText('Gamma Inc')).toBeInTheDocument();
    expect(screen.queryByText('Declined Org')).not.toBeInTheDocument();
  });

  it('accepting an invitation calls the API and navigates', async () => {
    mockGetInvitations.mockResolvedValue([pendingInvite]);
    render(<OrganizationsLanding />);
    await screen.findByText('Gamma Inc');

    await userEvent.click(screen.getByRole('button', { name: 'Accept' }));

    await waitFor(() => {
      expect(mockAcceptInvitation).toHaveBeenCalledWith('org-9', 'inv-1');
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-9', { replace: true });
    });
  });

  it('declining an invitation calls the API and removes it from the list', async () => {
    mockGetInvitations.mockResolvedValue([pendingInvite]);
    render(<OrganizationsLanding />);
    await screen.findByText('Gamma Inc');

    await userEvent.click(screen.getByRole('button', { name: 'Decline invitation' }));

    await waitFor(() => {
      expect(mockDeclineInvitation).toHaveBeenCalledWith('org-9', 'inv-1');
    });
    await waitFor(() => {
      expect(screen.queryByText('Gamma Inc')).not.toBeInTheDocument();
    });
  });
});
