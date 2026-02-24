import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/utils';
import DependencySupplyChainPage from '../DependencySupplyChainPage';
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
    consumePrefetchedSupplyChain: vi.fn(),
    getDependencySupplyChain: vi.fn(),
    getProjectPolicies: vi.fn(),
    getDependencyVersions: vi.fn(),
    getLatestSafeVersion: vi.fn(),
    getBannedVersions: vi.fn(),
    getBumpScope: vi.fn(),
    getSupplyChainForVersion: vi.fn(),
    createWatchtowerBumpPR: vi.fn(),
    bumpAllProjects: vi.fn(),
  },
}));

// Mock ReactFlow to avoid ResizeObserver and canvas issues in jsdom
vi.mock('@xyflow/react', () => {
  const React = require('react');
  return {
    ReactFlow: ({ children }: any) => React.createElement('div', { 'data-testid': 'react-flow-mock' }, children),
    Background: () => null,
    useNodesState: (initial: any) => [initial, vi.fn(), vi.fn()],
    useEdgesState: (initial: any) => [initial, vi.fn(), vi.fn()],
    BackgroundVariant: { Dots: 'dots' },
  };
});

import { useParams, useOutletContext } from 'react-router-dom';

const mockSupplyChainResponse = {
  parent: {
    name: 'lodash',
    version: '4.17.21',
    dependency_id: 'dep-1',
    dependency_version_id: 'dv-1',
    is_direct: true,
    license: 'MIT',
    vulnerabilities: [],
    vulnerabilities_affecting_current_version: [],
  },
  children: [],
  ancestors: [],
  availableVersions: [{ dependency_version_id: 'dv-1', version: '4.17.21' }],
  bumpPrs: [],
};

const mockVersionsResponse = {
  versions: [
    {
      version: '4.17.21',
      vulnCount: 0,
      vulnerabilities: [],
      transitiveVulnCount: 0,
      transitiveVulnerabilities: [],
      totalVulnCount: 0,
      registry_integrity_status: 'pass' as const,
      registry_integrity_reason: null,
      install_scripts_status: 'pass' as const,
      install_scripts_reason: null,
      entropy_analysis_status: 'pass' as const,
      entropy_analysis_reason: null,
    },
  ],
  currentVersion: '4.17.21',
  latestVersion: '4.17.21',
  prs: [],
  bannedVersions: [],
  total: 1,
};

describe('DependencySupplyChainPage', () => {
  beforeEach(() => {
    vi.mocked(useOutletContext).mockReturnValue({
      organization: { permissions: { manage_teams_and_projects: false } },
      organizationId: 'org-1',
      projectId: 'proj-1',
      project: null,
      dependency: null,
      userPermissions: null,
    } as any);
    vi.mocked(api.consumePrefetchedSupplyChain).mockReturnValue(null);
    vi.mocked(api.getDependencySupplyChain).mockResolvedValue(mockSupplyChainResponse);
    vi.mocked(api.getProjectPolicies).mockResolvedValue(null);
    vi.mocked(api.getDependencyVersions).mockResolvedValue(mockVersionsResponse);
    vi.mocked(api.getLatestSafeVersion).mockResolvedValue({
      safeVersion: '4.17.21',
      safeVersionId: 'dv-1',
      isCurrent: true,
      severity: 'high',
      versionsChecked: 5,
      message: null,
    });
    vi.mocked(api.getBannedVersions).mockResolvedValue({ banned_versions: [] });
    vi.mocked(api.getBumpScope).mockResolvedValue({ scope: 'project' });
  });

  it('renders missing params message when orgId, projectId, or dependencyId is missing', () => {
    vi.mocked(useParams).mockReturnValue({ orgId: undefined, projectId: 'proj-1', dependencyId: 'pd-1' });

    render(<DependencySupplyChainPage />);

    expect(screen.getByText(/Missing org, project, or dependency/)).toBeInTheDocument();
    expect(api.getDependencySupplyChain).not.toHaveBeenCalled();
  });

  it('shows loading skeleton when params are present and API is pending', () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'pd-1' });
    vi.mocked(api.consumePrefetchedSupplyChain).mockReturnValue(null);
    vi.mocked(api.getDependencySupplyChain).mockReturnValue(new Promise(() => {}));

    render(<DependencySupplyChainPage />);

    expect(screen.getByTestId('react-flow-mock')).toBeInTheDocument();
  });

  it('renders error when getDependencySupplyChain rejects', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'pd-1' });
    vi.mocked(api.getDependencySupplyChain).mockRejectedValue(new Error('Network error'));

    render(<DependencySupplyChainPage />);

    expect(await screen.findByText(/Network error|Failed to load supply chain/)).toBeInTheDocument();
  });

  it('calls getDependencySupplyChain and getDependencyVersions when params are present', async () => {
    vi.mocked(useParams).mockReturnValue({ orgId: 'org-1', projectId: 'proj-1', dependencyId: 'pd-1' });

    render(<DependencySupplyChainPage />);

    // Wait for API calls to be made (they run on mount)
    await vi.waitFor(() => {
      expect(api.getDependencySupplyChain).toHaveBeenCalledWith('org-1', 'proj-1', 'pd-1');
      expect(api.getDependencyVersions).toHaveBeenCalledWith('org-1', 'proj-1', 'pd-1', { limit: 10, offset: 0 });
    });
  });
});
