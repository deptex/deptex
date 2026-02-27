import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import ProjectSettingsPage from '../ProjectSettingsPage';

const mockGetProjectRepositories = vi.fn();
const mockGetCachedProjectRepositories = vi.fn();
const mockGetTeams = vi.fn();
const mockGetProjectTeams = vi.fn();
const mockGetProjectConnections = vi.fn();
const mockGetProjectNotificationRules = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadProject = vi.fn().mockResolvedValue(undefined);

let mockProjectContext: {
  project: { id: string; name: string; asset_tier: string };
  reloadProject: ReturnType<typeof vi.fn>;
  organizationId: string;
  userPermissions: { view_settings: boolean; edit_settings: boolean };
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ orgId: 'org-1', projectId: 'proj-1', section: 'notifications' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => mockProjectContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getProjectRepositories: (...args: unknown[]) => mockGetProjectRepositories(...args),
    getCachedProjectRepositories: () => mockGetCachedProjectRepositories() ?? null,
    getTeams: (...args: unknown[]) => mockGetTeams(...args),
    getProjectTeams: (...args: unknown[]) => mockGetProjectTeams(...args),
    getProjectConnections: (...args: unknown[]) => mockGetProjectConnections(...args),
    getProjectNotificationRules: (...args: unknown[]) => mockGetProjectNotificationRules(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../NotificationRulesSection', () => ({
  default: () => <div data-testid="notification-rules-section">Notification Rules</div>,
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

vi.mock('../../hooks/useUserProfile', () => ({
  useUserProfile: () => ({ fullName: 'Test User' }),
}));

describe('ProjectSettingsPage – Notifications', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetProjectRepositories.mockResolvedValue({ repositories: [], connectedRepository: null });
    mockGetCachedProjectRepositories.mockReturnValue(null);
    mockGetTeams.mockResolvedValue([]);
    mockGetProjectTeams.mockResolvedValue({ owner_team: null, contributing_teams: [] });
    mockGetProjectConnections.mockResolvedValue({
      inherited: [],
      project: [],
      team: [],
    });
    mockGetProjectNotificationRules.mockResolvedValue([]);
    mockGetOrganizationMembers.mockResolvedValue([]);
    mockReloadProject.mockResolvedValue(undefined);

    mockProjectContext = {
      project: { id: 'proj-1', name: 'Test Project', asset_tier: 'EXTERNAL' },
      reloadProject: mockReloadProject,
      organizationId: 'org-1',
      userPermissions: { view_settings: true, edit_settings: true },
    };
  });

  it('shows Notifications heading when on notifications tab', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
  });

  it('shows Notifications and Destinations sub-tabs', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    expect(screen.getAllByRole('button', { name: 'Notifications' }).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('button', { name: 'Destinations' })).toBeInTheDocument();
  });

  it('shows Create Rule button on Notifications sub-tab', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Create Rule/ })).toBeInTheDocument();
    });
  });

  it('renders NotificationRulesSection when on Notifications sub-tab', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('notification-rules-section')).toBeInTheDocument();
    });
  });

  it('Destinations sub-tab shows Inherited from organization and Project-specific', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Destinations'));
    await waitFor(() => {
      expect(screen.getByText('Inherited from organization')).toBeInTheDocument();
      expect(screen.getByText('Project-specific')).toBeInTheDocument();
    });
  });

  it('Destinations sub-tab shows empty inherited integrations message when none', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Destinations'));
    await waitFor(() => {
      expect(screen.getByText(/No inherited integrations/)).toBeInTheDocument();
    });
  });

  it('Destinations sub-tab shows empty project-specific message when none', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Destinations'));
    await waitFor(() => {
      expect(screen.getByText(/No project-specific integrations/)).toBeInTheDocument();
    });
  });
});
