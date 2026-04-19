import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import { useOutletContext } from 'react-router-dom';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockGetOrganizationConnections = vi.fn();
const mockGetOrganizationNotificationRules = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadOrganization = vi.fn().mockResolvedValue(undefined);

const stableOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'owner',
    permissions: {
      view_settings: true,
      manage_integrations: true,
      manage_notifications: true,
    },
  },
  reloadOrganization: mockReloadOrganization,
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1', section: 'notifications' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => stableOrgContext),
  };
});

vi.mock('../../../contexts/PlanContext', () => ({
  usePlan: () => ({
    getPlanGate: () => ({
      allowed: true,
      requiredTier: 'pro',
      currentTier: 'pro',
      upgradeUrl: '/organizations/org-1/settings/plan',
    }),
  }),
  usePlanGate: () => ({
    allowed: true,
    requiredTier: 'pro',
    currentTier: 'pro',
    upgradeUrl: '/organizations/org-1/settings/plan',
  }),
  TIER_DISPLAY: { pro: 'Pro', team: 'Team', enterprise: 'Enterprise', free: 'Free' },
}));

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizationConnections: (...args: unknown[]) => mockGetOrganizationConnections(...args),
    getOrganizationNotificationRules: (...args: unknown[]) => mockGetOrganizationNotificationRules(...args),
    getOrganizationRoles: vi.fn().mockResolvedValue([
      {
        id: 'r1',
        name: 'owner',
        display_name: 'Owner',
        display_order: 0,
        permissions: { view_settings: true, manage_integrations: true, manage_notifications: true },
      },
    ]),
    getOrganizationMembers: vi.fn().mockResolvedValue([]),
    deleteOrganizationConnection: vi.fn(),
    connectSlackOrg: vi.fn(),
    connectDiscordOrg: vi.fn(),
    connectJiraOrg: vi.fn(),
    connectJiraPatOrg: vi.fn(),
    connectLinearOrg: vi.fn(),
    connectAsanaOrg: vi.fn(),
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

vi.mock('../NotificationRulesSection', () => ({
  default: function MockNotificationRulesSection({ organizationId }: { organizationId: string }) {
    return <div data-testid="notification-rules-section">rules-{organizationId}</div>;
  },
}));

vi.mock('../NotificationHistorySection', () => ({
  default: function MockNotificationHistorySection() {
    return <div data-testid="notification-history-section">history</div>;
  },
}));

describe('OrganizationSettingsPage – Notifications', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useOutletContext).mockReturnValue(stableOrgContext as never);
    mockGetOrganizationConnections.mockResolvedValue([]);
    mockGetOrganizationNotificationRules.mockResolvedValue([]);
  });

  it('shows Notifications heading when on notifications section', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications', level: 2 })).toBeInTheDocument();
    });
  });

  it('shows Create Rule button', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Create Rule' })).toBeInTheDocument();
    });
  });

  it('shows Rules and History sub-tabs', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Notifications', level: 2 })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Rules' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'History' })).toBeInTheDocument();
  });

  it('mounts NotificationRulesSection with organizationId', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('notification-rules-section')).toBeInTheDocument();
    });
    expect(screen.getByTestId('notification-rules-section')).toHaveTextContent('rules-org-1');
  });
});
