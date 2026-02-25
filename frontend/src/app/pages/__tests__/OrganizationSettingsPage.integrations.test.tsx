import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockGetOrganizationConnections = vi.fn();
const mockDeleteOrganizationConnection = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadOrganization = vi.fn().mockResolvedValue(undefined);
const mockWindowOpen = vi.fn();

const stableOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'owner',
    permissions: { view_settings: true, manage_integrations: true },
  },
  reloadOrganization: mockReloadOrganization,
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1', section: 'integrations' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => stableOrgContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizationConnections: (...args: unknown[]) => mockGetOrganizationConnections(...args),
    deleteOrganizationConnection: (...args: unknown[]) => mockDeleteOrganizationConnection(...args),
    connectSlackOrg: vi.fn().mockResolvedValue({ redirectUrl: 'https://slack.com/oauth' }),
    connectDiscordOrg: vi.fn().mockResolvedValue({ redirectUrl: 'https://discord.com/oauth' }),
    getOrganizationRoles: vi.fn().mockResolvedValue([
      {
        id: 'r1',
        name: 'owner',
        display_name: 'Owner',
        display_order: 0,
        permissions: { view_settings: true, manage_integrations: true },
      },
    ]),
    getOrganizationMembers: vi.fn().mockResolvedValue([]),
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

describe('OrganizationSettingsPage – Integrations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrganizationConnections.mockResolvedValue([]);
    mockDeleteOrganizationConnection.mockResolvedValue({ success: true, provider: 'github' });
    Object.defineProperty(window, 'open', { value: mockWindowOpen, writable: true });
    window.confirm = vi.fn(() => true);
  });

  it('shows Integrations heading and CI/CD section', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Integrations' })).toBeInTheDocument();
    });
    expect(screen.getByText('Connect external tools and services to your organization.')).toBeInTheDocument();
    expect(screen.getByText('CI/CD')).toBeInTheDocument();
    expect(screen.getByText('Source code & repositories')).toBeInTheDocument();
  });

  it('when connections are loading, shows table with column headers and skeleton rows', async () => {
    let resolveConnections: (value: unknown[]) => void;
    mockGetOrganizationConnections.mockImplementation(() => new Promise((r) => { resolveConnections = r; }));
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('CI/CD')).toBeInTheDocument();
    });
    const tables = screen.getAllByRole('table', { name: undefined });
    expect(tables.length).toBeGreaterThanOrEqual(1);
    const firstTable = tables[0];
    expect(within(firstTable).getByText('Provider')).toBeInTheDocument();
    expect(within(firstTable).getByText('Account')).toBeInTheDocument();
    const skeletonRows = document.querySelectorAll('.animate-pulse');
    expect(skeletonRows.length).toBeGreaterThan(0);
    resolveConnections!([]);
  });

  it('when connections loaded empty, shows No source code connections and Add buttons', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('No source code connections')).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Add GitHub/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add GitLab/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add Bitbucket/i })).toBeInTheDocument();
  });

  it('when connections loaded with one connection, shows table row and Disconnect button', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      {
        id: 'conn-1',
        provider: 'github',
        display_name: 'My Org',
        status: 'connected',
        installation_id: '123',
        metadata: {},
      },
    ]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('GitHub')).toBeInTheDocument();
    });
    expect(screen.getByText('My Org')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Disconnect' })).toBeInTheDocument();
  });

  it('Disconnect with GitHub opens GitHub installations page', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      {
        id: 'conn-1',
        provider: 'github',
        display_name: 'My Org',
        status: 'connected',
        installation_id: '123',
        metadata: {},
      },
    ]);
    mockDeleteOrganizationConnection.mockResolvedValue({
      success: true,
      provider: 'github',
      installationId: '456',
    });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Disconnect' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    await waitFor(() => {
      expect(mockDeleteOrganizationConnection).toHaveBeenCalledWith('org-1', 'conn-1');
    });
    expect(mockWindowOpen).toHaveBeenCalledWith('https://github.com/settings/installations/456', '_blank');
  });

  it('Disconnect with GitLab opens GitLab revoke URL', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      {
        id: 'conn-2',
        provider: 'gitlab',
        display_name: 'GitLab Group',
        status: 'connected',
        metadata: {},
      },
    ]);
    mockDeleteOrganizationConnection.mockResolvedValue({
      success: true,
      provider: 'gitlab',
      revokeUrl: 'https://gitlab.com/-/user_settings/applications',
    });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Disconnect' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    await waitFor(() => {
      expect(mockDeleteOrganizationConnection).toHaveBeenCalledWith('org-1', 'conn-2');
    });
    expect(mockWindowOpen).toHaveBeenCalledWith('https://gitlab.com/-/user_settings/applications', '_blank');
  });

  it('Disconnect with Bitbucket opens Bitbucket revoke URL', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      {
        id: 'conn-3',
        provider: 'bitbucket',
        display_name: 'My Workspace',
        status: 'connected',
        metadata: {},
      },
    ]);
    mockDeleteOrganizationConnection.mockResolvedValue({
      success: true,
      provider: 'bitbucket',
      revokeUrl: 'https://bitbucket.org/account/settings/applications/',
    });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Disconnect' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    await waitFor(() => {
      expect(mockDeleteOrganizationConnection).toHaveBeenCalledWith('org-1', 'conn-3');
    });
    expect(mockWindowOpen).toHaveBeenCalledWith('https://bitbucket.org/account/settings/applications/', '_blank');
  });
});
