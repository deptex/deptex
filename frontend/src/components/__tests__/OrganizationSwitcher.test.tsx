import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../test/utils';
import userEvent from '@testing-library/user-event';
import OrganizationSwitcher from '../OrganizationSwitcher';

const mockGetOrganizations = vi.fn();
const mockGetInvitations = vi.fn();
const mockAcceptInvitation = vi.fn();
const mockDeclineInvitation = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return { ...mod, useNavigate: () => mockNavigate };
});

// Radix DropdownMenu gates its content on pointer-driven open state jsdom can't
// drive — render trigger and content inline so the switcher logic is reachable.
vi.mock('../ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: any) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: any) => <>{children}</>,
  DropdownMenuContent: ({ children }: any) => <div>{children}</div>,
}));

vi.mock('../CreateOrganizationModal', () => ({
  default: ({ isOpen }: any) => (isOpen ? <div>create-org-modal</div> : null),
}));

vi.mock('../../lib/api', () => ({
  api: {
    getOrganizations: (...a: unknown[]) => mockGetOrganizations(...a),
    getInvitations: (...a: unknown[]) => mockGetInvitations(...a),
    acceptInvitation: (...a: unknown[]) => mockAcceptInvitation(...a),
    declineInvitation: (...a: unknown[]) => mockDeclineInvitation(...a),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast, toasts: [] }),
}));

const orgs = [
  { id: 'org-1', name: 'Acme Corp', role: 'owner', avatar_url: null },
  { id: 'org-2', name: 'Beta LLC', role: 'member', avatar_url: null },
];

function renderSwitcher() {
  return render(
    <OrganizationSwitcher
      currentOrganizationId="org-1"
      currentOrganizationName="Acme Corp"
    />,
  );
}

describe('OrganizationSwitcher', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The switcher keeps a 30s module-level cache; the component nulls it on
    // this event, so fire it to stop one test's data leaking into the next.
    window.dispatchEvent(new Event('auth:signedOut'));
    mockGetOrganizations.mockResolvedValue(orgs);
    mockGetInvitations.mockResolvedValue([]);
    mockAcceptInvitation.mockResolvedValue({ organization_id: 'org-9' });
    mockDeclineInvitation.mockResolvedValue({});
  });

  it('renders the trigger with the current organization name', () => {
    renderSwitcher();
    expect(screen.getByRole('button', { name: /Acme Corp/ })).toBeInTheDocument();
  });

  it('loads the org list when the trigger is hovered', async () => {
    renderSwitcher();
    await userEvent.hover(screen.getByRole('button', { name: /Acme Corp/ }));

    await waitFor(() => {
      expect(mockGetOrganizations).toHaveBeenCalled();
      expect(screen.getByText('Beta LLC')).toBeInTheDocument();
    });
  });

  it('filters the list by the search query', async () => {
    renderSwitcher();
    await userEvent.hover(screen.getByRole('button', { name: /Acme Corp/ }));
    await screen.findByText('Beta LLC');

    await userEvent.type(screen.getByPlaceholderText('Find organization...'), 'zzz');
    await waitFor(() => {
      expect(screen.getByText('No organizations match your search.')).toBeInTheDocument();
    });
  });

  it('selecting another organization navigates to it', async () => {
    renderSwitcher();
    await userEvent.hover(screen.getByRole('button', { name: /Acme Corp/ }));
    const betaRow = await screen.findByRole('button', { name: /Beta LLC/ });

    await userEvent.click(betaRow);
    expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-2');
  });

  it('accepting an invitation calls the API and navigates', async () => {
    mockGetInvitations.mockResolvedValue([
      { id: 'inv-1', organization_id: 'org-9', organization_name: 'Gamma Inc', role: 'member' },
    ]);
    renderSwitcher();
    await userEvent.hover(screen.getByRole('button', { name: /Acme Corp/ }));
    await screen.findByText('Gamma Inc');

    await userEvent.click(screen.getByRole('button', { name: 'Accept' }));

    await waitFor(() => {
      expect(mockAcceptInvitation).toHaveBeenCalledWith('org-9', 'inv-1');
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-9');
    });
  });

  it('declining an invitation calls the API and removes it', async () => {
    mockGetInvitations.mockResolvedValue([
      { id: 'inv-1', organization_id: 'org-9', organization_name: 'Gamma Inc', role: 'member' },
    ]);
    renderSwitcher();
    await userEvent.hover(screen.getByRole('button', { name: /Acme Corp/ }));
    await screen.findByText('Gamma Inc');

    await userEvent.click(screen.getByRole('button', { name: 'Decline invitation' }));

    await waitFor(() => {
      expect(mockDeclineInvitation).toHaveBeenCalledWith('org-9', 'inv-1');
    });
    await waitFor(() => {
      expect(screen.queryByText('Gamma Inc')).not.toBeInTheDocument();
    });
  });

  it('opens the create-organization modal from the New organization button', async () => {
    renderSwitcher();
    await userEvent.click(screen.getByRole('button', { name: /New organization/ }));
    expect(screen.getByText('create-org-modal')).toBeInTheDocument();
  });
});
