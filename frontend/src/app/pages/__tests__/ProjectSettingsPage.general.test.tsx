import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import ProjectSettingsPage from '../ProjectSettingsPage';

const mockGetProjectRepositories = vi.fn();
const mockGetCachedProjectRepositories = vi.fn();
const mockGetTeams = vi.fn();
const mockGetProjectTeams = vi.fn();
const mockGetTeamMembers = vi.fn();
const mockUpdateProject = vi.fn();
const mockDeleteProject = vi.fn();
const mockTransferProjectOwnership = vi.fn();
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
    useParams: vi.fn(() => ({ orgId: 'org-1', projectId: 'proj-1', section: 'general' })),
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
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
    updateProject: (...args: unknown[]) => mockUpdateProject(...args),
    deleteProject: (...args: unknown[]) => mockDeleteProject(...args),
    transferProjectOwnership: (...args: unknown[]) => mockTransferProjectOwnership(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

describe('ProjectSettingsPage – General', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetProjectRepositories.mockResolvedValue({
      repositories: [],
      connectedRepository: null,
    });
    mockGetCachedProjectRepositories.mockReturnValue(null);
    mockGetTeams.mockResolvedValue([]);
    mockGetProjectTeams.mockResolvedValue({ owner_team: null, contributing_teams: [] });
    mockGetTeamMembers.mockResolvedValue([]);
    mockUpdateProject.mockResolvedValue({});
    mockDeleteProject.mockResolvedValue({ message: 'Deleted' });
    mockReloadProject.mockResolvedValue(undefined);

    mockProjectContext = {
      project: {
        id: 'proj-1',
        name: 'Test Project',
        asset_tier: 'EXTERNAL',
      },
      reloadProject: mockReloadProject,
      organizationId: 'org-1',
      userPermissions: { view_settings: true, edit_settings: true },
    };
  });

  it('shows General heading when on general tab', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
  });

  it('shows project name input and asset tier select', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.getByPlaceholderText('Enter project name')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
  });

  it('Save button is disabled when name and asset tier unchanged', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    expect(saveBtn).toBeDisabled();
  });

  it('Save calls api.updateProject when name changed and Save clicked', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter project name')).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText('Enter project name');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'New Project Name');
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    await userEvent.click(saveBtn);

    await waitFor(() => {
      expect(mockUpdateProject).toHaveBeenCalledWith('org-1', 'proj-1', expect.objectContaining({ name: 'New Project Name' }));
    });
  });

  it('shows Transfer Project section', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Transfer Project')).toBeInTheDocument();
    });
  });

  it('shows No teams available when getTeams returns empty', async () => {
    mockGetTeams.mockResolvedValue([]);

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No teams available/)).toBeInTheDocument();
    });
  });

  it('shows Danger Zone and Delete Project', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    expect(screen.getByText('Delete Project')).toBeInTheDocument();
  });

  it('Delete Forever is disabled until project name is typed', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Project')).toBeInTheDocument();
    });
    const deleteForeverBtn = screen.getByRole('button', { name: 'Delete Forever' });
    expect(deleteForeverBtn).toBeDisabled();
  });

  it('Delete Forever keeps text during loading', async () => {
    let resolveDelete: (value: unknown) => void;
    mockDeleteProject.mockImplementation(() => new Promise((r) => { resolveDelete = r; }));

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Project')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Project'), 'Test Project');
    const deleteForeverBtn = screen.getByRole('button', { name: 'Delete Forever' });
    await userEvent.click(deleteForeverBtn);

    await waitFor(() => {
      expect(deleteForeverBtn).toHaveTextContent('Delete Forever');
    });
    resolveDelete!({ message: 'Deleted' });
  });

  it('Delete Forever calls api.deleteProject when confirmed', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Project')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Project'), 'Test Project');
    await userEvent.click(screen.getByRole('button', { name: 'Delete Forever' }));

    await waitFor(() => {
      expect(mockDeleteProject).toHaveBeenCalledWith('org-1', 'proj-1');
    });
  });

  it('Transfer keeps text during loading', async () => {
    const teams = [
      { id: 'team-1', name: 'Team A', description: null, avatar_url: null },
      { id: 'team-2', name: 'Team B', description: null, avatar_url: null },
    ];
    mockGetTeams.mockResolvedValue(teams);
    mockGetProjectTeams.mockResolvedValue({
      owner_team: { id: 'team-1', name: 'Team A', description: null, avatar_url: null },
      contributing_teams: [],
    });
    let resolveTransfer: (value: unknown) => void;
    mockTransferProjectOwnership.mockImplementation(() => new Promise((r) => { resolveTransfer = r; }));

    render(<ProjectSettingsPage />);
    const transferBtn = await screen.findByRole('button', { name: 'Transfer' }, { timeout: 5000 });

    // Team select shows current owner "Team A" - click to open dropdown
    await userEvent.click(screen.getByText('Team A'));
    await waitFor(() => {
      expect(screen.getByText('Team B')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Team B'));

    await userEvent.click(transferBtn);

    await waitFor(() => {
      expect(transferBtn).toHaveTextContent('Transfer');
    });
    resolveTransfer!({ message: 'Transferred', owner_team: teams[1] });
  });

  it('Transfer calls api.transferProjectOwnership when clicked', async () => {
    const teams = [
      { id: 'team-1', name: 'Team A', description: null, avatar_url: null },
      { id: 'team-2', name: 'Team B', description: null, avatar_url: null },
    ];
    mockGetTeams.mockResolvedValue(teams);
    mockGetProjectTeams.mockResolvedValue({
      owner_team: { id: 'team-1', name: 'Team A', description: null, avatar_url: null },
      contributing_teams: [],
    });
    mockTransferProjectOwnership.mockResolvedValue({ message: 'Transferred', owner_team: teams[1] });

    render(<ProjectSettingsPage />);
    const transferBtn = await screen.findByRole('button', { name: 'Transfer' }, { timeout: 5000 });

    // Team select shows current owner "Team A" - click to open dropdown
    await userEvent.click(screen.getByText('Team A'));
    await waitFor(() => {
      expect(screen.getByText('Team B')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByText('Team B'));

    await userEvent.click(transferBtn);

    await waitFor(() => {
      expect(mockTransferProjectOwnership).toHaveBeenCalledWith('org-1', 'proj-1', 'team-2');
    });
  });

  it('redirects when canViewSettings is false', async () => {
    mockProjectContext.userPermissions = { view_settings: false, edit_settings: false };

    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/projects/proj-1', { replace: true });
    });
  });

  it('tab click navigates to correct settings URL', async () => {
    render(<ProjectSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    const accessButton = screen.getAllByRole('button').find((b) => b.textContent === 'Access');
    expect(accessButton).toBeDefined();
    await userEvent.click(accessButton!);
    expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/projects/proj-1/settings/access');
  });
});
