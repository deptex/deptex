import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import ProjectSettingsPage from '../ProjectSettingsContent';

const mockGetProjectRepositories = vi.fn();
const mockGetCachedProjectRepositories = vi.fn();
const mockGetTeams = vi.fn();
const mockGetProjectTeams = vi.fn();
const mockGetTeamMembers = vi.fn();
const mockGetExtractionRuns = vi.fn();
const mockUpdateProjectRepositorySettings = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSetSearchParams = vi.fn();
const mockReloadProject = vi.fn().mockResolvedValue(undefined);

let mockProjectContext: {
  project: { id: string; name: string; importance: number };
  reloadProject: ReturnType<typeof vi.fn>;
  organizationId: string;
  organization: null;
  userPermissions: { view_settings: boolean; edit_settings: boolean };
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ orgId: 'org-1', projectId: 'proj-1', section: 'repository' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), mockSetSearchParams],
    useOutletContext: vi.fn(() => mockProjectContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getProjectRepositories: (...args: unknown[]) => mockGetProjectRepositories(...args),
    // The Repository settings tab now loads via the status-only endpoint (connected repo only,
    // no slow provider.listRepositories()). Derive it from the same fixture the tests already
    // set on getProjectRepositories so each beforeEach keeps working unchanged.
    getProjectRepositoryStatus: async (...args: unknown[]) => {
      const full = (await mockGetProjectRepositories(...args)) as { connectedRepository?: unknown } | undefined;
      return { connectedRepository: full?.connectedRepository ?? null };
    },
    getCachedProjectRepositories: () => mockGetCachedProjectRepositories() ?? null,
    getTeams: (...args: unknown[]) => mockGetTeams(...args),
    getProjectTeams: (...args: unknown[]) => mockGetProjectTeams(...args),
    getTeamMembers: (...args: unknown[]) => mockGetTeamMembers(...args),
    getExtractionRuns: (...args: unknown[]) => mockGetExtractionRuns(...args),
    updateProjectRepositorySettings: (...args: unknown[]) => mockUpdateProjectRepositorySettings(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

const connectedRepo = {
  id: 'repo-1',
  repo_full_name: 'org/my-repo',
  default_branch: 'main',
  package_json_path: 'packages/api',
  status: 'connected',
  scan_on_commit: false,
  sync_frequency: 'daily',
  provider: 'github',
};

describe('ProjectSettingsPage – Repository', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetCachedProjectRepositories.mockReturnValue(null);
    mockGetTeams.mockResolvedValue([]);
    mockGetProjectTeams.mockResolvedValue({ owner_team: null, contributing_teams: [] });
    mockGetTeamMembers.mockResolvedValue([]);
    mockGetExtractionRuns.mockResolvedValue([]);
    mockUpdateProjectRepositorySettings.mockResolvedValue({});
    mockReloadProject.mockResolvedValue(undefined);

    mockProjectContext = {
      project: { id: 'proj-1', name: 'Test Project', importance: 1.0 },
      reloadProject: mockReloadProject,
      organizationId: 'org-1',
      organization: null,
      userPermissions: { view_settings: true, edit_settings: true },
    };
  });

  describe('no repository connected', () => {
    beforeEach(() => {
      mockGetProjectRepositories.mockResolvedValue({ repositories: [], connectedRepository: null });
    });

    it('shows Not connected state', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Not connected')).toBeInTheDocument();
      });
    });

    it('does not show sync frequency section when not connected', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Not connected')).toBeInTheDocument();
      });
      expect(screen.queryByText('Sync Frequency')).not.toBeInTheDocument();
    });

    it('does not show Recent Activity when not connected', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Not connected')).toBeInTheDocument();
      });
      expect(screen.queryByText('Source')).not.toBeInTheDocument();
    });
  });

  describe('repository connected', () => {
    beforeEach(() => {
      mockGetProjectRepositories.mockResolvedValue({
        repositories: [connectedRepo],
        connectedRepository: connectedRepo,
      });
    });

    it('shows connected repo full name', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('org/my-repo')).toBeInTheDocument();
      });
    });

    it('shows the project path within the repository as ./<path>', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('./packages/api')).toBeInTheDocument();
      });
    });

    it('hides the path subtext when the project is at the repo root', async () => {
      mockGetProjectRepositories.mockResolvedValue({
        repositories: [],
        connectedRepository: { ...connectedRepo, package_json_path: '' },
      });
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('org/my-repo')).toBeInTheDocument();
      });
      // At the repo root the manifest sub-path line is hidden entirely (no "./..." text).
      expect(screen.queryByText(/^\.\//)).not.toBeInTheDocument();
    });

    it('shows Sync Frequency section with the commit toggle and floor options', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Sync Frequency')).toBeInTheDocument();
      });
      expect(screen.getByRole('checkbox', { name: /scan on every commit/i })).toBeInTheDocument();
      expect(screen.getByText('Daily')).toBeInTheDocument();
      expect(screen.getByText('Weekly')).toBeInTheDocument();
      expect(screen.queryByText('Manual only')).not.toBeInTheDocument();
    });

    it('Save button is disabled when sync frequency unchanged', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Sync Frequency')).toBeInTheDocument();
      });
      const saveBtn = screen.getByRole('button', { name: 'Save' });
      expect(saveBtn).toBeDisabled();
    });

    it('Save button enables after selecting a different frequency', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Weekly')).toBeInTheDocument();
      });
      await userEvent.click(screen.getByText('Weekly'));
      const saveBtn = screen.getByRole('button', { name: 'Save' });
      expect(saveBtn).not.toBeDisabled();
    });

    it('Save calls api.updateProjectRepositorySettings with selected frequency', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Weekly')).toBeInTheDocument();
      });
      await userEvent.click(screen.getByText('Weekly'));
      await userEvent.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => {
        expect(mockUpdateProjectRepositorySettings).toHaveBeenCalledWith(
          'org-1',
          'proj-1',
          expect.objectContaining({ sync_frequency: 'weekly' })
        );
      });
    });

    it('Save button disabled again after saving', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Weekly')).toBeInTheDocument();
      });
      await userEvent.click(screen.getByText('Weekly'));
      await userEvent.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => {
        expect(mockUpdateProjectRepositorySettings).toHaveBeenCalled();
      });
      const saveBtn = screen.getByRole('button', { name: 'Save' });
      expect(saveBtn).toBeDisabled();
    });

    it('scan-on-commit toggle is functional and enables Save', async () => {
      render(<ProjectSettingsPage />);
      const toggle = await screen.findByRole('checkbox', { name: /scan on every commit/i });
      expect(toggle).not.toBeDisabled();
      await userEvent.click(toggle);
      expect(screen.getByRole('button', { name: 'Save' })).not.toBeDisabled();
    });

    it('Save sends scan_on_commit when the toggle is flipped', async () => {
      render(<ProjectSettingsPage />);
      const toggle = await screen.findByRole('checkbox', { name: /scan on every commit/i });
      await userEvent.click(toggle);
      await userEvent.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => {
        expect(mockUpdateProjectRepositorySettings).toHaveBeenCalledWith(
          'org-1',
          'proj-1',
          expect.objectContaining({ scan_on_commit: true })
        );
      });
    });

    it('normalizes a legacy on_commit sync_frequency to the Daily floor on load', async () => {
      mockGetProjectRepositories.mockResolvedValue({
        repositories: [],
        connectedRepository: { ...connectedRepo, sync_frequency: 'on_commit' },
      });
      render(<ProjectSettingsPage />);
      const dailyRadio = await screen.findByRole('radio', { name: /daily/i });
      expect(dailyRadio).toHaveAttribute('aria-checked', 'true');
    });

    it('shows Recent Activity table when connected', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText('Source')).toBeInTheDocument();
      });
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Time')).toBeInTheDocument();
    });

    it('shows no extraction runs empty state', async () => {
      render(<ProjectSettingsPage />);
      await waitFor(() => {
        expect(screen.getByText(/No extraction runs yet/)).toBeInTheDocument();
      });
    });

    it('shows extraction run rows when runs exist', async () => {
      mockGetExtractionRuns.mockResolvedValue([
        {
          run_id: 'run-1',
          status: 'completed',
          attempts: 1,
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          error: null,
          trigger_type: 'manual',
        },
      ]);
      render(<ProjectSettingsPage />);
      // completed renders as "Ready" in RunRow
      await waitFor(() => {
        expect(screen.getByText('Ready')).toBeInTheDocument();
      });
    });

    it('Save button remains enabled after a failed save (API rejected)', async () => {
      mockUpdateProjectRepositorySettings.mockRejectedValue(new Error('Network error'));
      render(<ProjectSettingsPage />);
      await waitFor(() => expect(screen.getByText('Weekly')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Weekly'));
      await userEvent.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => {
        expect(mockUpdateProjectRepositorySettings).toHaveBeenCalled();
      });
      // connectedRepository.sync_frequency wasn't updated on failure, so hasChange stays true
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Save' })).not.toBeDisabled();
      });
    });
  });
});
