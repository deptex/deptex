import { describe, it, expect, vi, beforeEach } from 'vitest';
import userEvent from '@testing-library/user-event';
import { render, screen } from '../../../test/utils';
import DependencyWatchtowerPage from '../DependencyWatchtowerPage';
import { api } from '../../../lib/api';

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(),
    useOutletContext: vi.fn(),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getWatchtowerSummary: vi.fn(),
    getWatchtowerCommits: vi.fn(),
    updateDependencyWatching: vi.fn(),
    consumePrefetchedWatchtower: vi.fn(),
    getProjectRepositories: vi.fn(),
    clearWatchtowerCommits: vi.fn(),
    clearWatchtowerCommit: vi.fn(),
    patchWatchlistQuarantine: vi.fn(),
    createWatchtowerBumpPR: vi.fn(),
    createWatchtowerDecreasePR: vi.fn(),
    getProjectDependencies: vi.fn(),
    cacheDependency: vi.fn(),
    analyzeCommit: vi.fn(),
  },
}));

import { useOutletContext } from 'react-router-dom';

const baseDependency = {
  id: 'pd-1',
  name: 'lodash',
  version: '4.17.21',
  is_watching: false,
  watchtower_cleared_at: null as string | null,
  github_url: null as string | null,
};

describe('DependencyWatchtowerPage', () => {
  beforeEach(() => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: { permissions: { manage_teams_and_projects: true } } as any,
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: baseDependency,
      userPermissions: { can_manage_watchtower: true },
    });
    vi.mocked(api.consumePrefetchedWatchtower).mockReturnValue(null);
    vi.mocked(api.getWatchtowerSummary).mockResolvedValue({
      status: 'ready',
      bump_pr_url: null,
      decrease_pr_url: null,
      latest_allowed_version: '4.17.21',
      latest_version: '4.18.0',
      commits_count: 10,
      contributors_count: 2,
      anomalies_count: 0,
      registry_integrity_status: 'pass',
      install_scripts_status: 'pass',
      entropy_analysis_status: 'pass',
    } as any);
    vi.mocked(api.getWatchtowerCommits).mockResolvedValue({
      commits: [],
      total: 0,
      limit: 50,
      offset: 0,
    });
    vi.mocked(api.getProjectRepositories).mockResolvedValue({ connectedRepository: null } as any);
  });

  it('renders skeleton when dependency is null', () => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: null,
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: null,
      userPermissions: null,
    });

    render(<DependencyWatchtowerPage />);

    expect(document.querySelector('[class*="animate-pulse"]')).toBeInTheDocument();
  });

  it('renders not-watching state with Enable Watchtower and feature cards when is_watching is false', () => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: { permissions: { manage_teams_and_projects: true } } as any,
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: { ...baseDependency, is_watching: false },
      userPermissions: { can_manage_watchtower: true },
    });

    render(<DependencyWatchtowerPage />);

    expect(screen.getByRole('heading', { name: /Watchtower Forensics/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Enable Watchtower/i })).toBeInTheDocument();
    expect(screen.getByText(/Registry Integrity/i)).toBeInTheDocument();
    expect(screen.getByText(/Install Script Analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/Entropy Analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/Commit Anomaly Detection/i)).toBeInTheDocument();
  });

  it('calls updateDependencyWatching with true when Enable Watchtower is clicked', async () => {
    vi.mocked(api.updateDependencyWatching).mockResolvedValue({ id: 'pd-1', is_watching: true });
    vi.mocked(api.getProjectDependencies).mockResolvedValue([{ ...baseDependency, is_watching: true }] as any);

    render(<DependencyWatchtowerPage />);

    const enableBtn = screen.getByRole('button', { name: /Enable Watchtower/i });
    await userEvent.click(enableBtn);

    expect(api.updateDependencyWatching).toHaveBeenCalledWith('org-1', 'proj-1', 'pd-1', true);
  });

  it('when watching, fetches summary and commits and shows dashboard', async () => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: { permissions: { manage_teams_and_projects: true } } as any,
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: { ...baseDependency, is_watching: true },
      userPermissions: { can_manage_watchtower: true },
    });

    render(<DependencyWatchtowerPage />);

    await screen.findByText(/lodash/i);
    expect(api.getWatchtowerSummary).toHaveBeenCalledWith('lodash', 'pd-1', expect.any(Object));
    expect(api.getWatchtowerCommits).toHaveBeenCalled();
  });

  it('calls updateDependencyWatching with false when Disable is clicked (watching state)', async () => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: { permissions: { manage_teams_and_projects: true } } as any,
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: { ...baseDependency, is_watching: true },
      userPermissions: { can_manage_watchtower: true },
    });
    vi.mocked(api.updateDependencyWatching).mockResolvedValue({ id: 'pd-1', is_watching: false });
    vi.mocked(api.getProjectDependencies).mockResolvedValue([{ ...baseDependency, is_watching: false }] as any);

    render(<DependencyWatchtowerPage />);

    await screen.findByText(/lodash/i);
    const disableBtn = await screen.findByRole('button', { name: /^Disable$/i });
    await userEvent.click(disableBtn);

    expect(api.updateDependencyWatching).toHaveBeenCalledWith('org-1', 'proj-1', 'pd-1', false);
  });
});
