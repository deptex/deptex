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
const mockGetProjectPolicyChanges = vi.fn();
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

const pkg = 'function packagePolicy(context) {\n  return { allowed: true, reasons: [] };\n}';
const status = 'function projectStatus(context) {\n  return { status: \'Compliant\', violations: [] };\n}';
const pr = 'function pullRequestCheck(context) {\n  return { passed: true, violations: [] };\n}';

/** Phase 4 shape so ProjectSettingsPage uses split tabs (Package Policy, Project Status, Pull Request). */
const phase4ProjectPolicies = {
  inherited_package_policy_code: pkg,
  inherited_project_status_code: status,
  inherited_pr_check_code: pr,
  effective_package_policy_code: pkg,
  effective_project_status_code: status,
  effective_pr_check_code: pr,
  pending_exceptions: [],
  accepted_exceptions: [],
  inherited: { accepted_licenses: [], slsa_enforcement: 'none' as const, slsa_level: null },
  effective: { accepted_licenses: [], slsa_enforcement: 'none' as const, slsa_level: null },
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
    getProjectPolicyChanges: (...args: unknown[]) => mockGetProjectPolicyChanges(...args),
  },
}));

vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../../components/PolicyCodeEditor', () => ({
  PolicyCodeEditor: ({ value }: { value: string }) => (
    <pre data-testid="policy-code-editor">{value}</pre>
  ),
}));

vi.mock('../../../components/PolicyAIAssistant', () => ({
  PolicyAIAssistant: () => null,
}));

vi.mock('../../../components/PolicyExceptionSidebar', () => ({
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
    mockGetProjectPolicies.mockResolvedValue(phase4ProjectPolicies);
    mockGetProjectPolicyChanges.mockResolvedValue([]);
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

  it('shows Phase 4 sub-tabs Package Policy, Project Status, Pull Request, Change requests', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Package Policy' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Project Status' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Pull Request' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change requests' })).toBeInTheDocument();
  });

  it('shows Policies docs link and AI Assistant button', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /AI Assistant/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Policies docs/ })).toBeInTheDocument();
  });

  it('shows packagePolicy editor and Inherited from org when aligned with org', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('packagePolicy')).toBeInTheDocument();
    });
    const inherited = screen.queryAllByText('Inherited from org');
    expect(inherited.length).toBeGreaterThanOrEqual(1);
  });

  it('shows Failed to load policies on API error', async () => {
    mockGetProjectPolicies.mockRejectedValue(new Error('Failed'));

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Failed to load policies.')).toBeInTheDocument();
    });
  });

  it('Change requests tab is clickable', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies' })).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Change requests' }));
    // Tab switch only; no table columns from legacy Exception applications
    expect(screen.getByRole('button', { name: 'Change requests' })).toBeInTheDocument();
  });

  it('does not refetch policies when navigating away and back (cached)', async () => {
    const { rerender } = render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('packagePolicy')).toBeInTheDocument();
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
      expect(screen.getByText('packagePolicy')).toBeInTheDocument();
    });
    expect(mockGetProjectPolicies).toHaveBeenCalledTimes(1);
  });
});
