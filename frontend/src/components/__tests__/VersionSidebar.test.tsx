import { describe, it, expect, vi, beforeEach } from 'vitest';
import userEvent from '@testing-library/user-event';
import { render, screen } from '../../test/utils';
import { VersionSidebar } from '../VersionSidebar';
import { api } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    getDependencyVersions: vi.fn(),
    createWatchtowerBumpPR: vi.fn(),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const baseResponse = {
  currentVersion: '1.0.0',
  latestVersion: '2.0.0',
  versions: [
    {
      version: '2.0.0',
      vulnCount: 0,
      vulnerabilities: [],
      registry_integrity_status: 'pass' as const,
      registry_integrity_reason: null,
      install_scripts_status: 'pass' as const,
      install_scripts_reason: null,
      entropy_analysis_status: 'pass' as const,
      entropy_analysis_reason: null,
    },
    {
      version: '1.0.0',
      vulnCount: 0,
      vulnerabilities: [],
      registry_integrity_status: 'pass' as const,
      registry_integrity_reason: null,
      install_scripts_status: 'pass' as const,
      install_scripts_reason: null,
      entropy_analysis_status: 'pass' as const,
      entropy_analysis_reason: null,
    },
  ],
  prs: [],
};

describe('VersionSidebar', () => {
  beforeEach(() => {
    vi.mocked(api.getDependencyVersions).mockResolvedValue({
      ...baseResponse,
      prs: [],
      bannedVersions: [],
    });
  });

  it('shows Banned badge for versions in bannedVersions', async () => {
    vi.mocked(api.getDependencyVersions).mockResolvedValue({
      ...baseResponse,
      bannedVersions: ['2.0.0'],
      prs: [],
    });
    render(
      <VersionSidebar
        packageName="lodash"
        currentVersion="1.0.0"
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        versionsInQuarantine={[]}
        onClose={vi.fn()}
      />
    );
    await screen.findByText('2.0.0');
    expect(screen.getByText('Banned')).toBeInTheDocument();
  });

  it('shows In quarantine badge when versionsInQuarantine includes version', async () => {
    vi.mocked(api.getDependencyVersions).mockResolvedValue(baseResponse);
    render(
      <VersionSidebar
        packageName="lodash"
        currentVersion="1.0.0"
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        versionsInQuarantine={['2.0.0']}
        onClose={vi.fn()}
      />
    );
    await screen.findByText('2.0.0');
    expect(screen.getByText('In quarantine')).toBeInTheDocument();
  });

  it('shows at most one View PR link when prs has one bump PR', async () => {
    vi.mocked(api.getDependencyVersions).mockResolvedValue({
      ...baseResponse,
      prs: [{ target_version: '2.0.0', pr_url: 'https://github.com/org/repo/pull/5', pr_number: 5 }],
    });
    render(
      <VersionSidebar
        packageName="lodash"
        currentVersion="1.0.0"
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        onClose={vi.fn()}
      />
    );
    await screen.findByText('2.0.0');
    const viewPrLinks = screen.getAllByRole('link', { name: /View PR #5/i });
    expect(viewPrLinks.length).toBeLessThanOrEqual(1);
  });

  describe('variant="supply-chain"', () => {
    it('shows Preview button instead of Create PR / View PR for non-current, non-banned versions', async () => {
      vi.mocked(api.getDependencyVersions).mockResolvedValue({
        ...baseResponse,
        prs: [{ target_version: '2.0.0', pr_url: 'https://github.com/org/repo/pull/5', pr_number: 5 }],
        bannedVersions: [],
      });
      const onPreviewVersion = vi.fn();
      render(
        <VersionSidebar
          packageName="lodash"
          currentVersion="1.0.0"
          organizationId="org-1"
          projectId="proj-1"
          dependencyId="dep-1"
          onClose={vi.fn()}
          variant="supply-chain"
          onPreviewVersion={onPreviewVersion}
        />
      );
      await screen.findByText('2.0.0');
      expect(screen.queryByRole('link', { name: /View PR #5/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Create PR/i })).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Preview/i })).toBeInTheDocument();
    });

    it('calls onPreviewVersion with version when Preview is clicked', async () => {
      vi.mocked(api.getDependencyVersions).mockResolvedValue({
        ...baseResponse,
        bannedVersions: [],
        prs: [],
      });
      const onPreviewVersion = vi.fn();
      render(
        <VersionSidebar
          packageName="lodash"
          currentVersion="1.0.0"
          organizationId="org-1"
          projectId="proj-1"
          dependencyId="dep-1"
          onClose={vi.fn()}
          variant="supply-chain"
          onPreviewVersion={onPreviewVersion}
        />
      );
      await screen.findByText('2.0.0');
      const previewBtn = screen.getByRole('button', { name: /Preview/i });
      await userEvent.click(previewBtn);
      expect(onPreviewVersion).toHaveBeenCalledTimes(1);
      expect(onPreviewVersion).toHaveBeenCalledWith('2.0.0');
    });

    it('shows "Current version" label and no Preview for current version', async () => {
      vi.mocked(api.getDependencyVersions).mockResolvedValue({
        ...baseResponse,
        bannedVersions: [],
        prs: [],
      });
      render(
        <VersionSidebar
          packageName="lodash"
          currentVersion="1.0.0"
          organizationId="org-1"
          projectId="proj-1"
          dependencyId="dep-1"
          onClose={vi.fn()}
          variant="supply-chain"
          onPreviewVersion={vi.fn()}
        />
      );
      await screen.findByText('1.0.0');
      expect(screen.getByText('Current version')).toBeInTheDocument();
      const previewButtons = screen.getAllByRole('button', { name: /Preview/i });
      expect(previewButtons.length).toBe(1);
    });
  });
});
