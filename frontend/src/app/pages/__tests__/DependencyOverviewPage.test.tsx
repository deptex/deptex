import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/utils';
import DependencyOverviewPage from '../DependencyOverviewPage';
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
    getDependencyOverview: vi.fn(),
    getProjectPolicies: vi.fn(),
    getLatestSafeVersion: vi.fn(),
    getWatchtowerSummary: vi.fn(),
    consumePrefetchedOverview: vi.fn(),
    getBumpScope: vi.fn(),
  },
}));

import { useParams, useOutletContext } from 'react-router-dom';

const mockOverviewResponse = {
  name: 'lodash',
  version: '1.2.3',
  score: 75,
  critical_vulns: 0,
  high_vulns: 0,
  medium_vulns: 0,
  low_vulns: 0,
  github_url: null,
  license: 'MIT',
  weekly_downloads: null,
  latest_release_date: null,
  latest_version: '1.2.3',
  last_published_at: null,
  releases_last_12_months: null,
  openssf_score: null,
  openssf_penalty: null,
  popularity_penalty: null,
  maintenance_penalty: null,
  dependency_id: 'dep-id',
  dependency_version_id: 'ver-id',
  files_importing_count: 0,
  imported_functions: [],
  ai_usage_summary: null,
  ai_usage_analyzed_at: null,
  other_projects_using_count: 0,
  other_projects_using_names: [],
  description: null,
  deprecation: null,
  remove_pr_url: null,
  remove_pr_number: null,
};

const mockPoliciesResponse = {
  inherited: {
    accepted_licenses: [],
    slsa_enforcement: 'none' as const,
    slsa_level: null,
  },
  effective: {
    accepted_licenses: [],
    slsa_enforcement: 'none' as const,
    slsa_level: null,
  },
  accepted_exceptions: [],
  pending_exceptions: [],
};

describe('DependencyOverviewPage', () => {
  beforeEach(() => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: { permissions: { manage_teams_and_projects: false } },
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: null,
      userPermissions: null,
    });
    vi.mocked(api.consumePrefetchedOverview).mockReturnValue(null);
    vi.mocked(api.getBumpScope).mockResolvedValue({ scope: 'project' as const });
    vi.mocked(api.getLatestSafeVersion).mockResolvedValue({
      safeVersion: '1.2.3',
      isCurrent: true,
      summary: null,
    });
    vi.mocked(api.getWatchtowerSummary).mockResolvedValue({
      bump_pr_url: null,
      latest_allowed_version: null,
    });
  });

  it('renders missing params message when orgId, projectId, or dependencyId is missing', () => {
    vi.mocked(useParams).mockReturnValue({ orgId: undefined, projectId: 'proj-1', dependencyId: 'dep-1' });

    render(<DependencyOverviewPage />);

    expect(screen.getByText('Missing org, project, or dependency in URL.')).toBeInTheDocument();
    expect(api.getDependencyOverview).not.toHaveBeenCalled();
  });

  it('renders missing params when projectId is missing', () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: undefined, dependencyId: 'dep-1' });

    render(<DependencyOverviewPage />);

    expect(screen.getByText('Missing org, project, or dependency in URL.')).toBeInTheDocument();
    expect(api.getDependencyOverview).not.toHaveBeenCalled();
  });

  it('renders missing params when dependencyId is missing', () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: undefined });

    render(<DependencyOverviewPage />);

    expect(screen.getByText('Missing org, project, or dependency in URL.')).toBeInTheDocument();
    expect(api.getDependencyOverview).not.toHaveBeenCalled();
  });

  it('shows loading skeleton when params are present and API is pending', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'dep-1' });
    vi.mocked(api.getDependencyOverview).mockReturnValue(new Promise(() => {}));
    vi.mocked(api.getProjectPolicies).mockReturnValue(new Promise(() => {}));

    render(<DependencyOverviewPage />);

    expect(document.querySelector('.animate-pulse')).toBeInTheDocument();
    expect(screen.queryByText('lodash')).not.toBeInTheDocument();
    expect(screen.queryByText('Missing org, project, or dependency in URL.')).not.toBeInTheDocument();
  });

  it('renders error message when getDependencyOverview rejects', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'dep-1' });
    vi.mocked(api.getDependencyOverview).mockRejectedValue(new Error('Network error'));
    vi.mocked(api.getProjectPolicies).mockResolvedValue(mockPoliciesResponse);

    render(<DependencyOverviewPage />);

    expect(await screen.findByText(/Network error|Failed to load dependency/)).toBeInTheDocument();
  });

  it('renders overview when getProjectPolicies rejects (policies loaded after overview, non-blocking)', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'dep-1' });
    vi.mocked(api.getDependencyOverview).mockResolvedValue(mockOverviewResponse);
    vi.mocked(api.getProjectPolicies).mockRejectedValue(new Error('Policies failed'));

    render(<DependencyOverviewPage />);

    // Overview renders first; policies failure does not block or show error
    expect(await screen.findByText('lodash')).toBeInTheDocument();
  });

  it('renders PackageOverview with dependency name when both API calls succeed', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'dep-1' });
    vi.mocked(api.getDependencyOverview).mockResolvedValue(mockOverviewResponse);
    vi.mocked(api.getProjectPolicies).mockResolvedValue(mockPoliciesResponse);

    render(<DependencyOverviewPage />);

    expect(await screen.findByText('lodash')).toBeInTheDocument();
    expect(screen.getByText(/@1\.2\.3/)).toBeInTheDocument();
  });

  it('uses prefetched overview when consumePrefetchedOverview returns a promise', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'dep-1' });
    const prefetchedOverview = { ...mockOverviewResponse, name: 'prefetched-pkg', version: '2.0.0' };
    vi.mocked(api.consumePrefetchedOverview).mockReturnValue(
      Promise.resolve([prefetchedOverview, mockPoliciesResponse]) as any
    );

    render(<DependencyOverviewPage />);

    expect(await screen.findByText('prefetched-pkg')).toBeInTheDocument();
    expect(screen.getByText(/@2\.0\.0/)).toBeInTheDocument();
    // Prefetched path was used (prefetched name/version shown); getDependencyOverview may still run in Strict Mode or from other effects
  });
});
