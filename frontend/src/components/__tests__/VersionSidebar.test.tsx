import { describe, it, expect, vi, beforeEach } from 'vitest';
import userEvent from '@testing-library/user-event';
import { render, screen } from '../../test/utils';
import { VersionSidebar } from '../VersionSidebar';
import { api } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    getDependencyVersions: vi.fn(),
  },
}));

const baseResponse = {
  currentVersion: '1.0.0',
  latestVersion: '2.0.0',
  versions: [
    {
      version: '2.0.0',
      vulnCount: 0,
      vulnerabilities: [],
    },
    {
      version: '1.0.0',
      vulnCount: 0,
      vulnerabilities: [],
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
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        onClose={vi.fn()}
      />
    );
    await screen.findByText('2.0.0');
    expect(screen.getAllByText('Banned').length).toBeGreaterThan(0);
  });

  it('shows Preview button for non-current, non-banned versions', async () => {
    vi.mocked(api.getDependencyVersions).mockResolvedValue({
      ...baseResponse,
      bannedVersions: [],
      prs: [],
    });
    const onPreviewVersion = vi.fn();
    render(
      <VersionSidebar
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        onClose={vi.fn()}
        onPreviewVersion={onPreviewVersion}
      />
    );
    await screen.findByText('2.0.0');
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
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        onClose={vi.fn()}
        onPreviewVersion={onPreviewVersion}
      />
    );
    await screen.findByText('2.0.0');
    const previewBtn = screen.getByRole('button', { name: /Preview/i });
    await userEvent.click(previewBtn);
    expect(onPreviewVersion).toHaveBeenCalledTimes(1);
    expect(onPreviewVersion).toHaveBeenCalledWith('2.0.0');
  });

  it('shows "Current version" label for current version', async () => {
    vi.mocked(api.getDependencyVersions).mockResolvedValue({
      ...baseResponse,
      bannedVersions: [],
      prs: [],
    });
    render(
      <VersionSidebar
        organizationId="org-1"
        projectId="proj-1"
        dependencyId="dep-1"
        onClose={vi.fn()}
        onPreviewVersion={vi.fn()}
      />
    );
    await screen.findByText('1.0.0');
    expect(screen.getByText('Current version')).toBeInTheDocument();
  });
});
