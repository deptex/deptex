import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import { useOutletContext } from 'react-router-dom';
import { api } from '../../../lib/api';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockGetOrganizationConnections = vi.fn();
const mockDeleteOrganizationConnection = vi.fn();
const mockConnectJiraOrg = vi.fn();
const mockConnectLinearOrg = vi.fn();
const mockConnectAsanaOrg = vi.fn();
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
    connectJiraOrg: (...args: unknown[]) => mockConnectJiraOrg(...args),
    connectJiraPatOrg: vi.fn().mockResolvedValue({ success: true }),
    connectLinearOrg: (...args: unknown[]) => mockConnectLinearOrg(...args),
    connectAsanaOrg: (...args: unknown[]) => mockConnectAsanaOrg(...args),
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
    vi.mocked(useOutletContext).mockReturnValue(stableOrgContext as never);
    mockGetOrganizationConnections.mockResolvedValue([]);
    mockDeleteOrganizationConnection.mockResolvedValue({ success: true, provider: 'github' });
    mockConnectJiraOrg.mockResolvedValue({ redirectUrl: 'https://atlassian.com/oauth' });
    mockConnectLinearOrg.mockResolvedValue({ redirectUrl: 'https://linear.app/oauth' });
    mockConnectAsanaOrg.mockResolvedValue({ redirectUrl: 'https://asana.com/oauth' });
    Object.defineProperty(window, 'open', { value: mockWindowOpen, writable: true });
    window.confirm = vi.fn(() => true);
  });

  it('shows Integrations heading and CI/CD section', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Integrations' })).toBeInTheDocument();
    });
    expect(screen.getByText('CI/CD')).toBeInTheDocument();
    expect(screen.getByText(/Source code|repositories/)).toBeInTheDocument();
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

  it('when connections loaded empty, shows No source code integrations and Add buttons', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No source code integrations/)).toBeInTheDocument();
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

  it('integrations skeleton shows CI/CD, Notifications, and Ticketing sections when loading', async () => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: null,
      reloadOrganization: mockReloadOrganization,
    } as never);
    render(<OrganizationSettingsPage />);
    expect(screen.getByRole('heading', { name: 'Integrations' })).toBeInTheDocument();
    expect(screen.getByText('CI/CD')).toBeInTheDocument();
    expect(screen.getByText('Notifications')).toBeInTheDocument();
    expect(screen.getByText('Ticketing')).toBeInTheDocument();
  });

  it('when connections loaded empty, Ticketing shows No ticketing integrations message', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No ticketing integrations/)).toBeInTheDocument();
    });
  });

  it('Ticketing section has Add Jira dropdown with Jira Cloud and Jira Data Center options', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    mockConnectJiraOrg.mockResolvedValue({ redirectUrl: 'https://atlassian.com/oauth' });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Add Jira')).toBeInTheDocument();
    });
    const addJiraButton = screen.getByRole('button', { name: /Add Jira/i });
    await userEvent.click(addJiraButton);
    await waitFor(() => {
      expect(screen.getByRole('menuitem', { name: 'Jira Cloud (OAuth)' })).toBeInTheDocument();
    });
    expect(screen.getByRole('menuitem', { name: 'Jira Data Center (PAT)' })).toBeInTheDocument();
  });

  it('Add Linear triggers OAuth redirect', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    const mockLocation = { href: '', assign: vi.fn() };
    Object.defineProperty(window, 'location', { value: mockLocation, writable: true });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Linear/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /Add Linear/i }));
    await waitFor(() => {
      expect(mockConnectLinearOrg).toHaveBeenCalledWith('org-1');
    });
    expect(mockLocation.href).toBe('https://linear.app/oauth');
  });

  it('Add Asana triggers OAuth redirect', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    const mockLocation = { href: '', assign: vi.fn() };
    Object.defineProperty(window, 'location', { value: mockLocation, writable: true });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Asana/i })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: /Add Asana/i }));
    await waitFor(() => {
      expect(mockConnectAsanaOrg).toHaveBeenCalledWith('org-1');
    });
    expect(mockLocation.href).toBe('https://asana.com/oauth');
  });

  it('when ticketing connections exist, shows provider labels and Disconnect', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      {
        id: 'conn-jira',
        provider: 'jira',
        display_name: 'My Jira',
        status: 'connected',
        metadata: {},
      },
      {
        id: 'conn-linear',
        provider: 'linear',
        display_name: 'Linear Workspace',
        status: 'connected',
        metadata: {},
      },
    ]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Jira')).toBeInTheDocument();
    });
    expect(screen.getByText('Linear')).toBeInTheDocument();
    const disconnectButtons = screen.getAllByRole('button', { name: 'Disconnect' });
    expect(disconnectButtons.length).toBeGreaterThanOrEqual(2);
  });

  it('Disconnect ticketing integration calls deleteOrganizationConnection', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      {
        id: 'conn-jira',
        provider: 'jira',
        display_name: 'My Jira',
        status: 'connected',
        metadata: {},
      },
    ]);
    mockDeleteOrganizationConnection.mockResolvedValue({ success: true, provider: 'jira' });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Jira')).toBeInTheDocument();
    });
    const disconnectBtn = screen.getByRole('button', { name: 'Disconnect' });
    await userEvent.click(disconnectBtn);
    await waitFor(() => {
      expect(mockDeleteOrganizationConnection).toHaveBeenCalledWith('org-1', 'conn-jira');
    });
  });

  it('Notifications section has Add Email, Add Slack, Add Discord, Add Custom buttons', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Slack/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Add Email/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add Discord/i })).toBeInTheDocument();
    const addCustomButtons = screen.getAllByRole('button', { name: /Add Custom/i });
    expect(addCustomButtons.length).toBeGreaterThanOrEqual(1);
  });

  it('user without manage_integrations sees Access Denied on integrations tab', async () => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: {
        id: 'org-1',
        name: 'Test Org',
        role: 'member',
        permissions: { view_settings: true, manage_integrations: false },
      },
      reloadOrganization: mockReloadOrganization,
    } as never);
    vi.mocked(api.getOrganizationRoles).mockResolvedValueOnce([
      {
        id: 'r2',
        name: 'member',
        display_name: 'Member',
        display_order: 1,
        permissions: { view_settings: true, manage_integrations: false },
      },
    ]);
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
    });
    expect(screen.getByText(/don't have permission to manage integrations/i)).toBeInTheDocument();
  });

  it('API error on getOrganizationConnections shows empty state without crash', async () => {
    mockGetOrganizationConnections.mockRejectedValue(new Error('Network error'));
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(mockGetOrganizationConnections).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(screen.getByText(/No source code integrations/)).toBeInTheDocument();
    });
  });
});
