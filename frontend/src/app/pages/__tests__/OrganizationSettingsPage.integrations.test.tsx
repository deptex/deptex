import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import { useOutletContext } from 'react-router-dom';
import { api, type RolePermissions, type OrganizationRole } from '../../../lib/api';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockGetOrganizationConnections = vi.fn();
const mockDeleteOrganizationConnection = vi.fn();
const mockConnectJiraOrg = vi.fn();
const mockConnectJiraPatOrg = vi.fn();
const mockConnectLinearOrg = vi.fn();
const mockConnectPagerDutyOrg = vi.fn();
const mockCreateEmailNotification = vi.fn();
const mockStartCicdInstall = vi.fn();
const mockUpdateCustomIntegration = vi.fn();
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
    connectJiraPatOrg: (...args: unknown[]) => mockConnectJiraPatOrg(...args),
    connectLinearOrg: (...args: unknown[]) => mockConnectLinearOrg(...args),
    connectAsanaOrg: vi.fn(),
    connectPagerDutyOrg: (...args: unknown[]) => mockConnectPagerDutyOrg(...args),
    createEmailNotification: (...args: unknown[]) => mockCreateEmailNotification(...args),
    startCicdInstall: (...args: unknown[]) => mockStartCicdInstall(...args),
    updateCustomIntegration: (...args: unknown[]) => mockUpdateCustomIntegration(...args),
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

vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast, toasts: [] }),
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
    mockConnectJiraPatOrg.mockResolvedValue({ success: true });
    mockConnectPagerDutyOrg.mockResolvedValue({ success: true });
    mockCreateEmailNotification.mockResolvedValue({ success: true, id: 'email-1' });
    mockStartCicdInstall.mockResolvedValue({ redirectUrl: 'https://github.com/apps/deptex/installations/new' });
    mockUpdateCustomIntegration.mockResolvedValue({ success: true, secret: 'whsec_new' });
    Object.defineProperty(window, 'open', { value: mockWindowOpen, writable: true });
  });

  it('shows Integrations heading + Docs + Add buttons', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Integrations' })).toBeInTheDocument();
    });
    expect(screen.getByRole('link', { name: /Docs/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument();
  });

  it('connections resolve to the empty state when no integrations exist', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No integrations yet/)).toBeInTheDocument();
    });
    // Both Docs + Add buttons remain in the header during the empty state
    expect(screen.getByRole('link', { name: /Docs/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument();
  });

  it('empty state surfaces an Add CTA that opens the Add Integration sidebar', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No integrations yet/)).toBeInTheDocument();
    });

    // Both header Add and inline Add-integration CTA should open the sidebar
    await userEvent.click(screen.getByRole('button', { name: /Add integration/i }));
    const dialog = await screen.findByRole('dialog');
    // Sidebar shows category headers and a couple of representative items
    expect(within(dialog).getByText('CI/CD')).toBeInTheDocument();
    expect(within(dialog).getByText('Notifications')).toBeInTheDocument();
    expect(within(dialog).getByText('Ticketing')).toBeInTheDocument();
    expect(within(dialog).getByText('Custom')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: /GitHub/ })).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: /Slack/ })).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: /Linear/ })).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: /Custom notification/ })).toBeInTheDocument();
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
    // Row button opens the two-tone confirmation dialog
    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disconnect' }));
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
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disconnect' }));
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
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disconnect' }));
    await waitFor(() => {
      expect(mockDeleteOrganizationConnection).toHaveBeenCalledWith('org-1', 'conn-3');
    });
    expect(mockWindowOpen).toHaveBeenCalledWith('https://bitbucket.org/account/settings/applications/', '_blank');
  });

  it('the unified table has Type pills that bucket each connection (CI/CD, Notification, Ticketing, Custom)', async () => {
    mockGetOrganizationConnections.mockResolvedValue([
      { id: 'c-gh', provider: 'github', display_name: 'My Org', status: 'connected', installation_id: '123', metadata: {} },
      { id: 'c-slk', provider: 'slack', display_name: 'My Workspace', status: 'connected', metadata: { team_name: 'My Workspace' } },
      { id: 'c-jira', provider: 'jira', display_name: 'acme.atlassian.net', status: 'connected', metadata: {} },
      { id: 'c-cust', provider: 'custom_notification', display_name: 'My Webhook', status: 'connected', metadata: { custom_name: 'My Webhook', webhook_url: 'https://hooks.example.com/x' } },
    ]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('GitHub')).toBeInTheDocument();
    });
    // All four Type-column labels render
    expect(screen.getByText('CI/CD')).toBeInTheDocument();
    expect(screen.getByText('Notification')).toBeInTheDocument();
    expect(screen.getByText('Ticketing')).toBeInTheDocument();
    expect(screen.getByText('Custom')).toBeInTheDocument();
  });

  it('Add sidebar → Jira Data Center hands off to the PAT dialog', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: /^Add$/i }));
    const sidebar = await screen.findByRole('dialog');
    await userEvent.click(within(sidebar).getByRole('button', { name: /Jira Data Center/i }));

    // PAT dialog opens
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Jira Data Center/i })).toBeInTheDocument();
    });
  });

  it('Add sidebar → Linear triggers OAuth redirect', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      writable: true,
      value: new Proxy({} as Location, {
        get: () => '',
        set: (_t, k, v) => { if (k === 'href') hrefSetter(v); return true; },
      }),
    });
    try {
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

      await userEvent.click(screen.getByRole('button', { name: /^Add$/i }));
      const sidebar = await screen.findByRole('dialog');
      await userEvent.click(within(sidebar).getByRole('button', { name: /Linear/i }));

      await waitFor(() => expect(mockConnectLinearOrg).toHaveBeenCalledWith('org-1'));
      expect(hrefSetter).toHaveBeenCalledWith('https://linear.app/oauth');
    } finally {
      Object.defineProperty(window, 'location', { writable: true, value: originalLocation });
    }
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
    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disconnect' }));
    await waitFor(() => {
      expect(mockDeleteOrganizationConnection).toHaveBeenCalledWith('org-1', 'conn-jira');
    });
  });

  it('Add sidebar exposes every notification destination (Slack, Discord, Email, PagerDuty) + custom rows', async () => {
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: /^Add$/i }));
    const sidebar = await screen.findByRole('dialog');
    expect(within(sidebar).getByRole('button', { name: /Slack/ })).toBeInTheDocument();
    expect(within(sidebar).getByRole('button', { name: /Discord/ })).toBeInTheDocument();
    expect(within(sidebar).getByRole('button', { name: /^Email/ })).toBeInTheDocument();
    expect(within(sidebar).getByRole('button', { name: /PagerDuty/ })).toBeInTheDocument();
    expect(within(sidebar).getByRole('button', { name: /Custom notification/ })).toBeInTheDocument();
    expect(within(sidebar).getByRole('button', { name: /Custom ticketing/ })).toBeInTheDocument();
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
        organization_id: 'org-1',
        is_default: false,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        permissions: { view_settings: true, manage_integrations: false } as RolePermissions,
      } as OrganizationRole,
    ]);
    mockGetOrganizationConnections.mockResolvedValue([]);
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('No access to integrations')).toBeInTheDocument();
    });
    expect(screen.getByText(/Ask an organization admin for the/i)).toBeInTheDocument();
  });

  it('API error on getOrganizationConnections shows empty state without crash', async () => {
    mockGetOrganizationConnections.mockRejectedValue(new Error('Network error'));
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(mockGetOrganizationConnections).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(screen.getByText(/No integrations yet/)).toBeInTheDocument();
    });
  });

  describe('Disconnect confirmation dialog', () => {
    it('Cancel in the disconnect dialog leaves the connection intact', async () => {
      mockGetOrganizationConnections.mockResolvedValue([
        { id: 'conn-1', provider: 'github', display_name: 'My Org', status: 'connected', installation_id: '123', metadata: {} },
      ]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Disconnect' })).toBeInTheDocument());

      await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
      const dialog = await screen.findByRole('dialog');
      await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

      expect(mockDeleteOrganizationConnection).not.toHaveBeenCalled();
    });

    it('Disconnect dialog title and body adapt to provider', async () => {
      mockGetOrganizationConnections.mockResolvedValue([
        { id: 'conn-email', provider: 'email', display_name: 'team@x.com', status: 'connected', metadata: { email: 'team@x.com' } },
      ]);
      render(<OrganizationSettingsPage />);
      // The Provider column renders the email address as the label; the Type pill says "Notification".
      await waitFor(() => expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument());

      await userEvent.click(screen.getByRole('button', { name: 'Remove' }));
      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByText(/Remove team@x\.com\?/)).toBeInTheDocument();
      expect(within(dialog).getByText(/stops receiving notification emails/)).toBeInTheDocument();
    });
  });

  describe('CI/CD install via the Add sidebar', () => {
    it('GitHub row routes through api.startCicdInstall and redirects', async () => {
      const originalLocation = window.location;
      const hrefSetter = vi.fn();
      Object.defineProperty(window, 'location', {
        writable: true,
        value: new Proxy({} as Location, {
          get: () => '',
          set: (_t, k, v) => { if (k === 'href') hrefSetter(v); return true; },
        }),
      });
      try {
        mockGetOrganizationConnections.mockResolvedValue([]);
        render(<OrganizationSettingsPage />);
        await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

        await userEvent.click(screen.getByRole('button', { name: /^Add$/i }));
        const sidebar = await screen.findByRole('dialog');
        await userEvent.click(within(sidebar).getByRole('button', { name: /GitHub/ }));
        await waitFor(() => expect(mockStartCicdInstall).toHaveBeenCalledWith('github', 'org-1'));
        expect(hrefSetter).toHaveBeenCalledWith('https://github.com/apps/deptex/installations/new');
      } finally {
        Object.defineProperty(window, 'location', { writable: true, value: originalLocation });
      }
    });

    it('GitLab row failure surfaces a generic toast, never the raw error', async () => {
      mockStartCicdInstall.mockRejectedValueOnce(new Error('Boom: internal database leak'));
      mockGetOrganizationConnections.mockResolvedValue([]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

      await userEvent.click(screen.getByRole('button', { name: /^Add$/i }));
      const sidebar = await screen.findByRole('dialog');
      await userEvent.click(within(sidebar).getByRole('button', { name: /GitLab/ }));
      await waitFor(() => expect(mockToast).toHaveBeenCalled());
      const errorToast = mockToast.mock.calls.find((call) => (call[0] as { variant?: string }).variant === 'destructive');
      expect((errorToast?.[0] as { description?: string } | undefined)?.description).not.toMatch(/Boom|internal database/);
    });
  });

  describe('Email + PagerDuty + Jira PAT dialogs (opened from Add sidebar)', () => {
    async function openAddSidebar() {
      await userEvent.click(screen.getByRole('button', { name: /^Add$/i }));
      return await screen.findByRole('dialog');
    }

    it('Email row opens the email dialog and submission calls api.createEmailNotification', async () => {
      mockGetOrganizationConnections.mockResolvedValue([]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

      const sidebar = await openAddSidebar();
      await userEvent.click(within(sidebar).getByRole('button', { name: /Email/ }));
      // Email dialog opens; addressing it by the new active dialog
      const emailDialog = await screen.findByRole('dialog');
      await userEvent.type(within(emailDialog).getByLabelText(/Email address/i), 'team@x.com');
      await userEvent.click(within(emailDialog).getByRole('button', { name: 'Add' }));
      await waitFor(() => expect(mockCreateEmailNotification).toHaveBeenCalledWith('org-1', 'team@x.com'));
    });

    it('Email dialog Add is disabled until input is a valid address', async () => {
      mockGetOrganizationConnections.mockResolvedValue([]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

      const sidebar = await openAddSidebar();
      await userEvent.click(within(sidebar).getByRole('button', { name: /Email/ }));
      const emailDialog = await screen.findByRole('dialog');
      const addBtn = within(emailDialog).getByRole('button', { name: 'Add' });
      expect(addBtn).toBeDisabled();

      await userEvent.type(within(emailDialog).getByLabelText(/Email address/i), 'not-an-email');
      expect(addBtn).toBeDisabled();
    });

    it('PagerDuty row opens the PD dialog; submission routes through the api wrapper', async () => {
      mockGetOrganizationConnections.mockResolvedValue([]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

      const sidebar = await openAddSidebar();
      await userEvent.click(within(sidebar).getByRole('button', { name: /PagerDuty/ }));
      const pdDialog = await screen.findByRole('dialog');
      await userEvent.type(within(pdDialog).getByLabelText(/Service name/i), 'Critical Alerts');
      await userEvent.type(within(pdDialog).getByLabelText(/Routing key/i), 'R0UT1NG_K3Y');
      await userEvent.click(within(pdDialog).getByRole('button', { name: 'Connect' }));

      await waitFor(() => expect(mockConnectPagerDutyOrg).toHaveBeenCalledWith('org-1', {
        serviceName: 'Critical Alerts',
        routingKey: 'R0UT1NG_K3Y',
      }));
    });

    it('Jira Data Center row opens the PAT dialog; submission routes through api.connectJiraPatOrg', async () => {
      mockGetOrganizationConnections.mockResolvedValue([]);
      render(<OrganizationSettingsPage />);
      await waitFor(() => expect(screen.getByRole('button', { name: /^Add$/i })).toBeInTheDocument());

      const sidebar = await openAddSidebar();
      await userEvent.click(within(sidebar).getByRole('button', { name: /Jira Data Center/i }));
      const patDialog = await screen.findByRole('dialog');
      await userEvent.type(within(patDialog).getByLabelText(/Server URL/i), 'https://jira.acme.com');
      await userEvent.type(within(patDialog).getByLabelText(/Personal Access Token/i), 'pat_xyz');
      await userEvent.click(within(patDialog).getByRole('button', { name: 'Create connection' }));

      await waitFor(() => expect(mockConnectJiraPatOrg).toHaveBeenCalledWith('org-1', 'https://jira.acme.com', 'pat_xyz'));
    });
  });
});
