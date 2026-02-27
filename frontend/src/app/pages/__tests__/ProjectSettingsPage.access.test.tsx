import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import ProjectSettingsPage from '../ProjectSettingsPage';

const mockGetProjectRepositories = vi.fn();
const mockGetCachedProjectRepositories = vi.fn();
const mockGetTeams = vi.fn();
const mockGetProjectTeams = vi.fn();
const mockGetProjectMembers = vi.fn();
const mockGetOrganizationMembers = vi.fn();
const mockGetTeamMembers = vi.fn();
const mockAddProjectContributingTeam = vi.fn();
const mockAddProjectMember = vi.fn();
const mockRemoveProjectContributingTeam = vi.fn();
const mockRemoveProjectMember = vi.fn();
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
    useParams: vi.fn(() => ({ orgId: 'org-1', projectId: 'proj-1', section: 'access' })),
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
    getProjectMembers: (...args: unknown[]) => mockGetProjectMembers(...args),
    getOrganizationMembers: (...args: unknown[]) => mockGetOrganizationMembers(...args),
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
    addProjectContributingTeam: (...args: unknown[]) => mockAddProjectContributingTeam(...args),
    addProjectMember: (...args: unknown[]) => mockAddProjectMember(...args),
    removeProjectContributingTeam: (...args: unknown[]) => mockRemoveProjectContributingTeam(...args),
    removeProjectMember: (...args: unknown[]) => mockRemoveProjectMember(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

describe('ProjectSettingsPage – Access', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetProjectRepositories.mockResolvedValue({ repositories: [], connectedRepository: null });
    mockGetCachedProjectRepositories.mockReturnValue(null);
    mockGetTeams.mockResolvedValue([]);
    mockGetProjectTeams.mockResolvedValue({
      owner_team: { id: 'team-1', name: 'Owner Team', description: 'Owns the project' },
      contributing_teams: [
        { id: 'team-2', name: 'Contrib Team', description: 'Contributor', avatar_url: null },
      ],
    });
    mockGetProjectMembers.mockResolvedValue({
      direct_members: [
        { user_id: 'user-1', full_name: 'Direct Member', email: 'direct@test.com', avatar_url: null },
      ],
      team_members: [],
    });
    mockGetOrganizationMembers.mockResolvedValue([]);
    mockGetTeamMembers.mockResolvedValue([]);
    mockAddProjectContributingTeam.mockResolvedValue({});
    mockAddProjectMember.mockResolvedValue({});
    mockRemoveProjectContributingTeam.mockResolvedValue({});
    mockRemoveProjectMember.mockResolvedValue({});
    mockReloadProject.mockResolvedValue(undefined);

    mockProjectContext = {
      project: { id: 'proj-1', name: 'Test Project', asset_tier: 'EXTERNAL' },
      reloadProject: mockReloadProject,
      organizationId: 'org-1',
      userPermissions: { view_settings: true, edit_settings: true },
    };
  });

  it('shows Access heading when on access tab', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument();
    });
  });

  it('shows Owner Team card with team name', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Owner Team')).toBeInTheDocument();
    });
    expect(screen.getByText('Full Control')).toBeInTheDocument();
  });

  it('shows No owner team assigned when owner_team is null', async () => {
    mockGetProjectTeams.mockResolvedValue({
      owner_team: null,
      contributing_teams: [],
    });

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('No owner team assigned.')).toBeInTheDocument();
    });
  });

  it('shows Contributing Teams with Add Team button', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Contributing Teams')).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Add Team/ })).toBeInTheDocument();
  });

  it('shows contributing team name in list', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Contrib Team')).toBeInTheDocument();
    });
  });

  it('shows No contributing teams yet when list is empty', async () => {
    mockGetProjectTeams.mockResolvedValue({
      owner_team: { id: 'team-1', name: 'Owner', description: '' },
      contributing_teams: [],
    });

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No contributing teams yet/)).toBeInTheDocument();
    });
  });

  it('shows Additional Members with Add Member button', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Additional Members')).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Add Member/ })).toBeInTheDocument();
  });

  it('shows direct member in list', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Direct Member')).toBeInTheDocument();
      expect(screen.getByText('direct@test.com')).toBeInTheDocument();
    });
  });

  it('shows No direct members yet when list is empty', async () => {
    mockGetProjectMembers.mockResolvedValue({ direct_members: [], team_members: [] });
    mockGetProjectTeams.mockResolvedValue({
      owner_team: { id: 'team-1', name: 'Owner', description: '' },
      contributing_teams: [],
    });

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No direct members yet/)).toBeInTheDocument();
    });
  });

  it('Add Team button opens sidepanel', async () => {
    mockGetTeams.mockResolvedValue([
      { id: 'team-3', name: 'Other Team', description: '', avatar_url: null },
    ]);
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Contributing Teams')).toBeInTheDocument();
    });
    const addTeamBtn = screen.getByRole('button', { name: /Add Team/ });
    await userEvent.click(addTeamBtn);
    await waitFor(() => {
      expect(screen.getByText(/Select teams to give them access/)).toBeInTheDocument();
    });
  });

  it('Add Member button opens sidepanel', async () => {
    mockGetOrganizationMembers.mockResolvedValue([
      { user_id: 'user-2', full_name: 'Other User', email: 'other@test.com', avatar_url: null },
    ]);
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Additional Members')).toBeInTheDocument();
    });
    const addMemberBtn = screen.getByRole('button', { name: /Add Member/ });
    await userEvent.click(addMemberBtn);
    await waitFor(() => {
      expect(screen.getByText(/Select members to give them direct access/)).toBeInTheDocument();
    });
  });

  it('remove contributing team calls api and refreshes list', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Contrib Team')).toBeInTheDocument();
    });
    const removeBtn = screen.getByRole('button', { name: /Remove team Contrib Team/i });
    await userEvent.click(removeBtn);

    await waitFor(() => {
      expect(mockRemoveProjectContributingTeam).toHaveBeenCalledWith('org-1', 'proj-1', 'team-2');
    });
  });

  it('remove direct member calls api and refreshes list', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Direct Member')).toBeInTheDocument();
    });
    const removeBtn = screen.getByRole('button', { name: /Remove member Direct Member/i });
    await userEvent.click(removeBtn);

    await waitFor(() => {
      expect(mockRemoveProjectMember).toHaveBeenCalledWith('org-1', 'proj-1', 'user-1');
    });
  });
});
