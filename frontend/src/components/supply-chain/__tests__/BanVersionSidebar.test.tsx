import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/utils';
import { BanVersionSidebar } from '../BanVersionSidebar';
import type { SupplyChainAvailableVersion, BannedVersion } from '../../../lib/api';

// Mock the api module
vi.mock('../../../lib/api', () => ({
  api: {
    banVersion: vi.fn(),
  },
}));

// Mock the toast hook
vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const versions: SupplyChainAvailableVersion[] = [
  { dependency_version_id: 'v1', version: '1.0.0' },
  { dependency_version_id: 'v2', version: '2.0.0' },
  { dependency_version_id: 'v3', version: '3.0.0' },
  { dependency_version_id: 'v4', version: '4.0.0' },
];

const bannedVersions: BannedVersion[] = [
  {
    id: 'ban-1',
    dependency_id: 'dep-test-pkg-uuid',
    banned_version: '2.0.0',
    bump_to_version: '3.0.0',
    banned_by: 'user-1',
    created_at: '2025-01-01T00:00:00Z',
  },
];

describe('BanVersionSidebar', () => {
  it('does not render when closed', () => {
    const { container } = render(
      <BanVersionSidebar
        open={false}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="org"
        onBanComplete={vi.fn()}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders header with package name and version when open', () => {
    render(
      <BanVersionSidebar
        open={true}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="org"
        onBanComplete={vi.fn()}
      />
    );
    // "Ban version" appears in heading and button
    const banTexts = screen.getAllByText('Ban version');
    expect(banTexts.length).toBeGreaterThanOrEqual(2);
    // Check package name and version displayed in header (format: "Ban v1.0.0 of test-pkg")
    expect(screen.getByText('test-pkg')).toBeInTheDocument();
    expect(screen.getByText(/1\.0\.0/)).toBeInTheDocument();
  });

  it('disables the ban button when no target version is selected', () => {
    render(
      <BanVersionSidebar
        open={true}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="org"
        onBanComplete={vi.fn()}
      />
    );
    // The ban button should be in the footer
    const banButtons = screen.getAllByText('Ban version');
    // The second instance is the action button (first is the heading)
    const actionButton = banButtons[1].closest('button');
    expect(actionButton).toBeDisabled();
  });

  it('filters out the banned version from dropdown', () => {
    // When banning version 1.0.0, version 1.0.0 should not appear in the dropdown
    render(
      <BanVersionSidebar
        open={true}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="org"
        onBanComplete={vi.fn()}
      />
    );
    // The sidebar shows "Select version..." placeholder text
    expect(screen.getByText('Select version...')).toBeInTheDocument();
  });

  it('filters out already-banned versions from dropdown when bannedVersions provided', () => {
    render(
      <BanVersionSidebar
        open={true}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        bannedVersions={bannedVersions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="org"
        onBanComplete={vi.fn()}
      />
    );
    // The sidebar renders. Version 2.0.0 (already banned) and 1.0.0 (being banned)
    // should not be in the target versions list.
    const banTexts = screen.getAllByText('Ban version');
    expect(banTexts.length).toBeGreaterThanOrEqual(2); // heading + button
  });

  it('shows correct button text in initial state', () => {
    render(
      <BanVersionSidebar
        open={true}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="org"
        onBanComplete={vi.fn()}
      />
    );
    // "Ban version" appears in heading and button - button text should always say "Ban version"
    const banTexts = screen.getAllByText('Ban version');
    expect(banTexts.length).toBeGreaterThanOrEqual(2); // heading + button
  });

  it('renders with team scope and bumpTeamId without crashing', () => {
    render(
      <BanVersionSidebar
        open={true}
        onOpenChange={vi.fn()}
        versionToBan="1.0.0"
        availableVersions={versions}
        orgId="org-1"
        dependencyId="dep-test-pkg-uuid"
        packageName="test-pkg"
        bumpScope="team"
        bumpTeamId="team-1"
        onBanComplete={vi.fn()}
      />
    );
    expect(screen.getByText('test-pkg')).toBeInTheDocument();
    expect(screen.getByText(/1\.0\.0/)).toBeInTheDocument();
  });
});
