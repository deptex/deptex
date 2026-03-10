import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '../../../test/utils';
import { useOutletContext } from 'react-router-dom';
import OrganizationSettingsPage from '../OrganizationSettingsPage';

const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadOrganization = vi.fn().mockResolvedValue(undefined);

const memberOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'member',
    permissions: { view_settings: true },
  },
  reloadOrganization: mockReloadOrganization,
};

const hoisted = vi.hoisted(() => ({
  mockUseParams: vi.fn(() => ({ id: 'org-1', section: 'policies' })),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: () => hoisted.mockUseParams(),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => memberOrgContext),
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
    getOrganizationRoles: vi.fn().mockResolvedValue([
      {
        id: 'r3',
        name: 'member',
        display_name: 'Member',
        display_order: 2,
        permissions: { view_settings: true },
      },
    ]),
    getOrganizationMembers: vi.fn().mockResolvedValue([]),
    getOrganizationConnections: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
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

describe('OrganizationSettingsPage – permission redirects', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.mockUseParams.mockReturnValue({ id: 'org-1', section: 'policies' });
    vi.mocked(useOutletContext).mockReturnValue(memberOrgContext as never);
  });

  it('redirects to general when opening policies without manage_compliance', async () => {
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/settings/general', { replace: true });
    });
  });

  it('redirects to general when opening sso without manage_security', async () => {
    hoisted.mockUseParams.mockReturnValue({ id: 'org-1', section: 'sso' });
    render(<OrganizationSettingsPage />);
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/settings/general', { replace: true });
    });
  });
});
