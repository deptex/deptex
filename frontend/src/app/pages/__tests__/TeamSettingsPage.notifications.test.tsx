import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import TeamSettingsPage from '../TeamSettingsPage';

const mockGetTeamConnections = vi.fn();
const mockGetTeamRoles = vi.fn();
const mockGetTeamMembers = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadTeam = vi.fn().mockResolvedValue(undefined);

let mockTeamContext: {
  team: { id: string; name: string; description?: string; avatar_url?: string | null };
  reloadTeam: ReturnType<typeof vi.fn>;
  updateTeamData: ReturnType<typeof vi.fn>;
  organizationId: string;
  userPermissions: { view_settings: boolean; manage_notification_settings?: boolean };
  organization: { permissions?: { manage_teams_and_projects?: boolean } } | null;
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ orgId: 'org-1', teamId: 'team-1', section: 'notifications' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useLocation: () => ({ pathname: '/organizations/org-1/teams/team-1/settings/notifications' }),
    useOutletContext: vi.fn(() => mockTeamContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getTeamConnections: (...args: unknown[]) => mockGetTeamConnections(...args),
    getTeamRoles: (...args: unknown[]) => mockGetTeamRoles(...args),
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../NotificationRulesSection', () => ({
  default: ({ createHandlerRef }: { createHandlerRef?: React.MutableRefObject<(() => void) | null> }) => {
    // Register create handler so parent's Create Rule button works
    if (createHandlerRef) {
      createHandlerRef.current = () => {}; // no-op for test
    }
    return <div data-testid="notification-rules-section">Notification Rules</div>;
  },
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

describe('TeamSettingsPage – Notifications', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetTeamConnections.mockResolvedValue({ inherited: [], team: [] });
    mockGetTeamRoles.mockResolvedValue([]);
    mockGetTeamMembers.mockResolvedValue([]);
    mockReloadTeam.mockResolvedValue(undefined);

    mockTeamContext = {
      team: { id: 'team-1', name: 'Test Team', description: '', avatar_url: null },
      reloadTeam: mockReloadTeam,
      updateTeamData: vi.fn(),
      organizationId: 'org-1',
      userPermissions: { view_settings: true, manage_notification_settings: true },
      organization: { permissions: { manage_teams_and_projects: false } },
    };
  });

  it('shows Notifications heading when on notifications tab', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
  });

  it('shows Notifications and Destinations sub-tabs', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    expect(screen.getAllByRole('button', { name: 'Notifications' }).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('button', { name: 'Destinations' })).toBeInTheDocument();
  });

  it('shows Create Rule button on Notifications sub-tab', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Create Rule/ })).toBeInTheDocument();
    });
  });

  it('renders NotificationRulesSection when on Notifications sub-tab', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('notification-rules-section')).toBeInTheDocument();
    });
  });

  it('loads team connections when notifications tab is active', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    await waitFor(
      () => {
        expect(mockGetTeamConnections).toHaveBeenCalledWith('org-1', 'team-1');
      },
      { timeout: 2000 }
    );
  });

  it('Destinations sub-tab shows Inherited from organization and Team-specific', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Destinations'));
    await waitFor(() => {
      expect(screen.getByText('Inherited from organization')).toBeInTheDocument();
      expect(screen.getByText('Team-specific')).toBeInTheDocument();
    });
  });

  it('Destinations sub-tab shows empty inherited integrations message when none', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Destinations'));
    await waitFor(() => {
      expect(screen.getByText(/No inherited integrations/)).toBeInTheDocument();
    });
  });
});
