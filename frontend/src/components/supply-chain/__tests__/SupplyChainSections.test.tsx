import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/utils';
import { SupplyChainSections } from '../SupplyChainSections';
import { api } from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  api: {
    consumePrefetchedSupplyChain: vi.fn(),
    getDependencySupplyChain: vi.fn(),
    getProjectPolicies: vi.fn(),
    getLatestSafeVersion: vi.fn().mockResolvedValue({ safeVersion: null, isCurrent: true }),
    createDependencyBumpPR: vi.fn(),
    getCachedProject: vi.fn().mockReturnValue(null),
    getProject: vi.fn().mockResolvedValue({ importance: 1.0 }),
  },
}));

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

describe('SupplyChainSections', () => {
  beforeEach(() => {
    vi.mocked(api.consumePrefetchedSupplyChain).mockReturnValue(null);
    vi.mocked(api.getDependencySupplyChain).mockResolvedValue(mockSupplyChainResponse);
    vi.mocked(api.getProjectPolicies).mockResolvedValue({
      inherited: { accepted_licenses: [], slsa_enforcement: 'none', slsa_level: null },
      effective: { accepted_licenses: [], slsa_enforcement: 'none', slsa_level: null },
      accepted_exceptions: [],
      pending_exceptions: [],
    } as any);
    vi.mocked(api.getLatestSafeVersion).mockResolvedValue({
      safeVersion: '4.17.21',
      safeVersionId: 'dv-1',
      isCurrent: true,
      severity: 'high',
      versionsChecked: 5,
      message: null,
    });
  });

  it('shows loading skeleton while the API is pending', () => {
    vi.mocked(api.getDependencySupplyChain).mockReturnValue(new Promise(() => {}));

    render(<SupplyChainSections orgId="org-1" projectId="proj-1" dependencyId="pd-1" />);

    expect(screen.getByTestId('supply-chain-skeleton')).toBeInTheDocument();
  });

  it('renders the merged packages table with the package pinned as the first row', async () => {
    render(<SupplyChainSections orgId="org-1" projectId="proj-1" dependencyId="pd-1" />);

    expect(await screen.findByText('Brings in (0)')).toBeInTheDocument();
    expect(screen.getByText('lodash')).toBeInTheDocument();
    expect(screen.getByText('This package')).toBeInTheDocument();
    expect(screen.getByText(/doesn't pull in any other packages/)).toBeInTheDocument();
  });

  it('expands a row to show its findings (shared FindingRow) and links them to the Findings tab', async () => {
    vi.mocked(api.getDependencySupplyChain).mockResolvedValue({
      ...mockSupplyChainResponse,
      children: [
        {
          name: 'qs',
          version: '6.11.0',
          dependency_version_id: 'dv-qs',
          score: null,
          license: 'BSD-3-Clause',
          critical_vulns: 0,
          high_vulns: 1,
          medium_vulns: 0,
          low_vulns: 0,
          vulnerabilities: [
            { osv_id: 'GHSA-aaaa-bbbb-cccc', severity: 'high', summary: 'Prototype pollution in qs', aliases: ['CVE-2026-12345'] },
          ],
        },
      ],
    } as any);

    const onOpenFinding = vi.fn();
    render(<SupplyChainSections orgId="org-1" projectId="proj-1" dependencyId="pd-1" onOpenFinding={onOpenFinding} />);

    const row = (await screen.findByText('qs')).closest('tr')!;
    expect(row).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(row);
    expect(row).toHaveAttribute('aria-expanded', 'true');
    // FindingRow renders the advisory summary as the title and the osv_id in the description line.
    const findingTitle = screen.getByText('Prototype pollution in qs');
    expect(findingTitle).toBeInTheDocument();
    expect(screen.getByText(/GHSA-aaaa-bbbb-cccc/)).toBeInTheDocument();
    // Clicking the finding row routes the user to the Findings tab for that finding.
    fireEvent.click(findingTitle.closest('tr')!);
    expect(onOpenFinding).toHaveBeenCalledWith('GHSA-aaaa-bbbb-cccc');
  });

  it('renders the minimal error card with Try again when the fetch rejects', async () => {
    vi.mocked(api.getDependencySupplyChain).mockRejectedValue(new Error('Network error'));

    render(<SupplyChainSections orgId="org-1" projectId="proj-1" dependencyId="pd-1" />);

    expect(await screen.findByText(/Couldn't load supply chain/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    // Recipe: no raw error message in the UI
    expect(screen.queryByText(/Network error/)).not.toBeInTheDocument();
  });

  it('shows the Bump button when a newer safe version exists and opens the PR on click', async () => {
    vi.mocked(api.getLatestSafeVersion).mockResolvedValue({
      safeVersion: '5.2.1',
      safeVersionId: 'dv-5',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 5,
      message: null,
    });
    vi.mocked(api.createDependencyBumpPR).mockResolvedValue({ pr_url: 'https://github.com/x/y/pull/7', pr_number: 7 });

    render(<SupplyChainSections orgId="org-1" projectId="proj-1" dependencyId="pd-1" />);

    const btn = await screen.findByRole('button', { name: /Bump to 5\.2\.1/ });
    fireEvent.click(btn);
    await vi.waitFor(() => {
      expect(api.createDependencyBumpPR).toHaveBeenCalledWith('org-1', 'proj-1', 'pd-1', '5.2.1');
    });
    expect(await screen.findByText(/View PR #7/)).toBeInTheDocument();
  });

  it('calls getDependencySupplyChain with the provided ids', async () => {
    render(<SupplyChainSections orgId="org-1" projectId="proj-1" dependencyId="pd-1" />);

    await vi.waitFor(() => {
      expect(api.getDependencySupplyChain).toHaveBeenCalledWith('org-1', 'proj-1', 'pd-1');
    });
  });
});
