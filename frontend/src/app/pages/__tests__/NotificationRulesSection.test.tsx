import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import NotificationRulesSection from '../NotificationRulesSection';

const mockGetTeamNotificationRules = vi.fn();
const mockGetProjectNotificationRules = vi.fn();
const mockGetOrganizationNotificationRules = vi.fn();
const mockGetTeamConnections = vi.fn();
const mockGetProjectConnections = vi.fn();
const mockGetOrganizationConnections = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockCreateTeamNotificationRule = vi.fn();
const mockCreateProjectNotificationRule = vi.fn();
const mockCreateOrganizationNotificationRule = vi.fn();
const mockUpdateTeamNotificationRule = vi.fn();
const mockUpdateProjectNotificationRule = vi.fn();
const mockUpdateOrganizationNotificationRule = vi.fn();
const mockDeleteTeamNotificationRule = vi.fn();
const mockDeleteProjectNotificationRule = vi.fn();
const mockDeleteOrganizationNotificationRule = vi.fn();
const mockToast = vi.fn();

vi.mock('../../../lib/api', () => ({
  api: {
    getUserProfile: vi.fn().mockResolvedValue({ full_name: 'Test User' }),
    getTeamNotificationRules: (...args: unknown[]) => mockGetTeamNotificationRules(...args),
    getProjectNotificationRules: (...args: unknown[]) => mockGetProjectNotificationRules(...args),
    getOrganizationNotificationRules: (...args: unknown[]) => mockGetOrganizationNotificationRules(...args),
    getTeamConnections: (...args: unknown[]) => mockGetTeamConnections(...args),
    getProjectConnections: (...args: unknown[]) => mockGetProjectConnections(...args),
    getOrganizationConnections: (...args: unknown[]) => mockGetOrganizationConnections(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    createTeamNotificationRule: (...args: unknown[]) => mockCreateTeamNotificationRule(...args),
    createProjectNotificationRule: (...args: unknown[]) => mockCreateProjectNotificationRule(...args),
    createOrganizationNotificationRule: (...args: unknown[]) => mockCreateOrganizationNotificationRule(...args),
    updateTeamNotificationRule: (...args: unknown[]) => mockUpdateTeamNotificationRule(...args),
    updateProjectNotificationRule: (...args: unknown[]) => mockUpdateProjectNotificationRule(...args),
    updateOrganizationNotificationRule: (...args: unknown[]) => mockUpdateOrganizationNotificationRule(...args),
    deleteTeamNotificationRule: (...args: unknown[]) => mockDeleteTeamNotificationRule(...args),
    deleteProjectNotificationRule: (...args: unknown[]) => mockDeleteProjectNotificationRule(...args),
    deleteOrganizationNotificationRule: (...args: unknown[]) => mockDeleteOrganizationNotificationRule(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1', user_metadata: { full_name: 'Test User' } } }),
}));

vi.mock('../../hooks/useUserProfile', () => ({
  useUserProfile: () => ({ fullName: 'Test User' }),
}));

vi.mock('../../components/PolicyCodeEditor', () => ({
  PolicyCodeEditor: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea data-testid="policy-editor" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
}));

vi.mock('../../components/NotificationAIAssistant', () => ({
  NotificationAIAssistant: () => null,
}));

const mockConnections = [
  {
    id: 'conn-1',
    provider: 'slack' as const,
    display_name: 'Slack Workspace',
    metadata: { channel: '#general' },
  },
  {
    id: 'conn-2',
    provider: 'email' as const,
    display_name: 'Email',
    metadata: { email: 'alerts@example.com' },
  },
];

const mockRule = {
  id: 'rule-1',
  name: 'Test Rule',
  triggerType: 'custom_code_pipeline',
  customCode: 'return true;',
  destinations: [{ integrationType: 'slack', targetId: 'conn-1' }],
  createdByName: 'Test User',
  createdByUserId: 'user-1',
};

describe('NotificationRulesSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrganizationNotificationRules.mockResolvedValue([]);
    mockGetTeamNotificationRules.mockResolvedValue([]);
    mockGetProjectNotificationRules.mockResolvedValue([]);
    mockGetOrganizationConnections.mockResolvedValue([]);
    mockGetTeamConnections.mockResolvedValue({ inherited: [], team: [] });
    mockGetProjectConnections.mockResolvedValue({ inherited: [], team: [], project: [] });
    mockGetOrganizationMembers.mockResolvedValue([]);
  });

  describe('organization context', () => {
    it('fetches organization notification rules and connections in parallel', async () => {
      mockGetOrganizationNotificationRules.mockResolvedValue([mockRule]);
      mockGetOrganizationConnections.mockResolvedValue(mockConnections);

      render(<NotificationRulesSection organizationId="org-1" />);

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument();
      });

      expect(mockGetOrganizationNotificationRules).toHaveBeenCalledWith('org-1');
      expect(mockGetOrganizationConnections).toHaveBeenCalledWith('org-1');
      expect(mockGetOrganizationMembers).toHaveBeenCalledWith('org-1');
    });

    it('shows empty state when no rules', async () => {
      render(<NotificationRulesSection organizationId="org-1" />);

      await waitFor(() => {
        expect(screen.getByText('None')).toBeInTheDocument();
      });
    });

    it('shows loading skeleton initially', () => {
      mockGetOrganizationNotificationRules.mockImplementation(() => new Promise(() => {}));

      render(<NotificationRulesSection organizationId="org-1" />);

      expect(document.querySelector('.animate-pulse')).toBeInTheDocument();
    });
  });

  describe('team context', () => {
    it('fetches team notification rules when teamId provided', async () => {
      mockGetTeamNotificationRules.mockResolvedValue([mockRule]);

      render(
        <NotificationRulesSection organizationId="org-1" teamId="team-1" connections={mockConnections} />
      );

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument();
      });

      expect(mockGetTeamNotificationRules).toHaveBeenCalledWith('org-1', 'team-1');
      expect(mockGetOrganizationNotificationRules).not.toHaveBeenCalled();
    });

    it('uses parent-provided connections when teamId set', async () => {
      mockGetTeamNotificationRules.mockResolvedValue([mockRule]);

      render(
        <NotificationRulesSection organizationId="org-1" teamId="team-1" connections={mockConnections} />
      );

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument();
      });

      expect(mockGetTeamConnections).not.toHaveBeenCalled();
      expect(mockGetOrganizationConnections).not.toHaveBeenCalled();
    });
  });

  describe('project context', () => {
    it('fetches project notification rules when projectId provided', async () => {
      mockGetProjectNotificationRules.mockResolvedValue([mockRule]);

      render(
        <NotificationRulesSection organizationId="org-1" projectId="proj-1" connections={mockConnections} />
      );

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument();
      });

      expect(mockGetProjectNotificationRules).toHaveBeenCalledWith('org-1', 'proj-1');
      expect(mockGetOrganizationNotificationRules).not.toHaveBeenCalled();
    });
  });

  describe('create rule', () => {
    it('opens create sidebar when Create Rule clicked', async () => {
      render(<NotificationRulesSection organizationId="org-1" />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Create Rule/ })).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: /Create Rule/ }));

      await waitFor(() => {
        expect(screen.getByText('Create Notification Rule')).toBeInTheDocument();
      });

      expect(screen.getByRole('heading', { name: 'Create Notification Rule' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
    });

    it('closes sidebar when Cancel clicked', async () => {
      render(<NotificationRulesSection organizationId="org-1" />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Create Rule/ })).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: /Create Rule/ }));

      await waitFor(() => {
        expect(screen.getByText('Create Notification Rule')).toBeInTheDocument();
      });

      await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

      await waitFor(() => {
        expect(screen.queryByText('Create Notification Rule')).not.toBeInTheDocument();
      });
    });
  });

  describe('error handling', () => {
    it('shows toast when rules fail to load', async () => {
      mockGetOrganizationNotificationRules.mockRejectedValueOnce(new Error('Network error'));

      render(<NotificationRulesSection organizationId="org-1" />);

      await waitFor(
        () => {
          expect(mockToast).toHaveBeenCalled();
          expect(mockToast).toHaveBeenCalledWith(
            expect.objectContaining({
              title: 'Failed to load rules',
              variant: 'destructive',
            })
          );
        },
        { timeout: 3000 }
      );
    });
  });
});
