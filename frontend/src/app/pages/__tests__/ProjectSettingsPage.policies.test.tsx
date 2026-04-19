import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import ProjectSettingsPage from '../ProjectSettingsPage';

const mockGetProjectRepositories = vi.fn();
const mockGetCachedProjectRepositories = vi.fn();
const mockGetOrganizationAssetTiers = vi.fn();
const mockGetTeams = vi.fn();
const mockGetProjectTeams = vi.fn();
const mockGetProjectMembers = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockGetTeamMembers = vi.fn();
const mockGetOrganizationPolicies = vi.fn();
const mockGetProjectPolicies = vi.fn();
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

const defaultProjectPolicies = {
  effective_policy_code: `function pullRequestCheck(context) {\n  return { passed: true };\n}\n\nfunction projectCompliance(context) {\n  return { compliant: true };\n}`,
  pending_exceptions: [],
  accepted_exceptions: [],
};

const hoisted = vi.hoisted(() => ({
  mockSectionRef: { current: 'policies' },
  mockUseParams: vi.fn(() => ({ orgId: 'org-1', projectId: 'proj-1', section: 'policies' })),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: hoisted.mockUseParams,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => mockProjectContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getProjectRepositories: (...args: unknown[]) => mockGetProjectRepositories(...args),
    getCachedProjectRepositories: () => mockGetCachedProjectRepositories() ?? null,
    getOrganizationAssetTiers: (...args: unknown[]) => mockGetOrganizationAssetTiers(...args),
    getTeams: (...args: unknown[]) => mockGetTeams(...args),
    getProjectTeams: (...args: unknown[]) => mockGetProjectTeams(...args),
    getProjectMembers: (...args: unknown[]) => mockGetProjectMembers(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
    getOrganizationPolicies: (...args: unknown[]) => mockGetOrganizationPolicies(...args),
    getProjectPolicies: (...args: unknown[]) => mockGetProjectPolicies(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../components/PolicyCodeEditor', () => ({
  PolicyCodeEditor: ({ value }: { value: string }) => (
    <pre data-testid="policy-code-editor">{value}</pre>
  ),
}));

vi.mock('../../components/PolicyAIAssistant', () => ({
  PolicyAIAssistant: () => null,
}));

vi.mock('../../components/PolicyExceptionSidebar', () => ({
  PolicyExceptionSidebar: () => null,
}));

describe('ProjectSettingsPage – Policies', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.mockSectionRef.current = 'policies';
    hoisted.mockUseParams.mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', section: 'policies' });
    mockGetProjectRepositories.mockResolvedValue({ repositories: [], connectedRepository: null });
    mockGetCachedProjectRepositories.mockReturnValue(null);
    mockGetOrganizationAssetTiers.mockResolvedValue([
      { id: 't1', organization_id: 'org-1', name: 'External', color: '#888', rank: 0, environmental_multiplier: 1, is_default: true },
    ]);
    mockGetTeams.mockResolvedValue([]);
    mockGetProjectTeams.mockResolvedValue({ owner_team: null, contributing_teams: [] });
    mockGetProjectMembers.mockResolvedValue({ direct_members: [], team_members: [] });
    mockGetOrganizationMembers.mockResolvedValue([]);
    mockGetTeamMembers.mockResolvedValue([]);
    mockGetOrganizationPolicies.mockResolvedValue({ policy_code: '' });
    mockGetProjectPolicies.mockResolvedValue(defaultProjectPolicies);
    mockReloadProject.mockResolvedValue(undefined);

    mockProjectContext = {
      project: { id: 'proj-1', name: 'Test Project', asset_tier: 'EXTERNAL' },
      reloadProject: mockReloadProject,
      organizationId: 'org-1',
      userPermissions: { view_settings: true, edit_settings: true },
    };
  });

  it('shows Policies heading when on policies tab', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
  });

  it('shows Policy and Exception applications sub-tabs', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
    expect(screen.getByText('Policy')).toBeInTheDocument();
    expect(screen.getByText('Exception applications')).toBeInTheDocument();
  });

  it('shows Docs and AI Assistant buttons', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /AI Assistant/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Docs/ })).toBeInTheDocument();
  });

  it('shows Project Compliance and Pull Request Check sections when policies loaded', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Project Compliance')).toBeInTheDocument();
      expect(screen.getByText('Pull Request Check')).toBeInTheDocument();
    });
  });

  it('shows Inherited from org badge when no project override', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      const badges = screen.getAllByText('Inherited from org');
      expect(badges.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('shows Failed to load policies on API error', async () => {
    mockGetProjectPolicies.mockRejectedValue(new Error('Failed'));

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Failed to load policies.')).toBeInTheDocument();
    });
  });

  it('Exception applications sub-tab shows table', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Exception applications'));
    await waitFor(() => {
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Type')).toBeInTheDocument();
      expect(screen.getByText('Reason')).toBeInTheDocument();
    });
  });

  it('does not refetch policies when navigating away and back (cached)', async () => {
    const { rerender } = render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Project Compliance')).toBeInTheDocument();
    });
    expect(mockGetProjectPolicies).toHaveBeenCalledTimes(1);

    hoisted.mockSectionRef.current = 'access';
    hoisted.mockUseParams.mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', section: 'access' });
    rerender(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument();
    });

    hoisted.mockSectionRef.current = 'policies';
    hoisted.mockUseParams.mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', section: 'policies' });
    rerender(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Project Compliance')).toBeInTheDocument();
    });
    expect(mockGetProjectPolicies).toHaveBeenCalledTimes(1);
  });
});
