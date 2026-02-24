import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../test/utils';
import PackageOverview from '../PackageOverview';
import type { ProjectDependency } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    createRemoveDependencyPR: vi.fn(),
    analyzeDependencyUsage: vi.fn(),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

import { api } from '../../lib/api';

function minimalDependency(overrides: Partial<ProjectDependency> = {}): ProjectDependency {
  return {
    id: 'dep-1',
    project_id: 'proj-1',
    name: 'lodash',
    version: '1.2.3',
    license: 'MIT',
    github_url: null,
    is_direct: true,
    source: 'dependencies',
    is_watching: false,
    files_importing_count: 1,
    imported_functions: [],
    ai_usage_summary: null,
    ai_usage_analyzed_at: null,
    other_projects_using_count: 0,
    other_projects_using_names: [],
    description: null,
    created_at: new Date().toISOString(),
    analysis: {
      status: 'ready',
      score: null,
      score_breakdown: undefined,
      critical_vulns: 0,
      high_vulns: 0,
      medium_vulns: 0,
      low_vulns: 0,
      openssf_score: null,
      weekly_downloads: null,
      last_published_at: null,
      analyzed_at: new Date().toISOString(),
    },
    ...overrides,
  };
}

const defaultProps = {
  organizationId: 'org-1',
  projectId: 'proj-1',
};

describe('PackageOverview', () => {
  beforeEach(() => {
    vi.mocked(api.createRemoveDependencyPR).mockResolvedValue({
      pr_url: 'https://example.com/pr/1',
      pr_number: 1,
    });
    vi.mocked(api.analyzeDependencyUsage).mockResolvedValue({
      ai_usage_summary: 'Summary',
      ai_usage_analyzed_at: new Date().toISOString(),
    });
  });

  it('renders package name and version', () => {
    const dep = minimalDependency({ name: 'lodash', version: '1.2.3' });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText('lodash')).toBeInTheDocument();
    expect(screen.getByText(/@1\.2\.3/)).toBeInTheDocument();
  });

  it('renders score when present (e.g. 75/100)', () => {
    const dep = minimalDependency({
      analysis: {
        status: 'ready',
        score: 75,
        critical_vulns: 0,
        high_vulns: 0,
        medium_vulns: 0,
        low_vulns: 0,
        openssf_score: null,
        weekly_downloads: null,
        last_published_at: null,
        analyzed_at: new Date().toISOString(),
      },
    });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText(/75/)).toBeInTheDocument();
    expect(screen.getByText(/\/100/)).toBeInTheDocument();
  });

  it('shows —/100 when score is null', () => {
    const dep = minimalDependency();
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText(/\/100/)).toBeInTheDocument();
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('renders license text when provided', () => {
    const dep = minimalDependency({ license: 'MIT' });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText('MIT')).toBeInTheDocument();
  });

  it('shows deprecation banner with recommended alternative when deprecation is set', () => {
    const dep = minimalDependency({ name: 'old-pkg' });
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        deprecation={{
          recommended_alternative: 'new-pkg',
          deprecated_by: null,
          created_at: new Date().toISOString(),
        }}
      />
    );

    expect(screen.getByText('Deprecated by your organization')).toBeInTheDocument();
    expect(screen.getAllByText('new-pkg').length).toBeGreaterThanOrEqual(1);
  });

  it('does not show Remove Deprecation button when canManageDeprecations is false', () => {
    const dep = minimalDependency();
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        deprecation={{
          recommended_alternative: 'other-pkg',
          deprecated_by: null,
          created_at: new Date().toISOString(),
        }}
        canManageDeprecations={false}
        onRemoveDeprecation={async () => {}}
      />
    );

    expect(screen.getByText('Deprecated by your organization')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Remove Deprecation/i })).not.toBeInTheDocument();
  });

  it('shows Remove Deprecation button when canManageDeprecations is true and onRemoveDeprecation provided', () => {
    const dep = minimalDependency();
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        deprecation={{
          recommended_alternative: 'other-pkg',
          deprecated_by: null,
          created_at: new Date().toISOString(),
        }}
        canManageDeprecations={true}
        onRemoveDeprecation={async () => {}}
      />
    );

    expect(screen.getByRole('button', { name: /Remove Deprecation/i })).toBeInTheDocument();
  });

  it('renders NPM link', () => {
    const dep = minimalDependency({ name: 'lodash' });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    const npmLink = screen.getByRole('link', { name: /NPM/i });
    expect(npmLink).toBeInTheDocument();
    expect(npmLink).toHaveAttribute('href', 'https://www.npmjs.com/package/lodash');
  });

  it('does not render GitHub link when github_url is null', () => {
    const dep = minimalDependency({ github_url: null });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.queryByRole('link', { name: /GitHub/i })).not.toBeInTheDocument();
  });

  it('renders GitHub link when github_url is set', () => {
    const dep = minimalDependency({
      github_url: 'https://github.com/lodash/lodash',
    });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    const githubLink = screen.getByRole('link', { name: /GitHub/i });
    expect(githubLink).toBeInTheDocument();
    expect(githubLink).toHaveAttribute('href', 'https://github.com/lodash/lodash');
  });

  it('shows Zombie Package and Create PR to Remove when direct with 0 files importing', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: 0,
    });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText('Zombie Package')).toBeInTheDocument();
    expect(screen.getByText('Not imported in any file')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Create PR to Remove/i })).toBeInTheDocument();
  });

  it('shows View removal PR link when direct zombie and removePrUrlFromOverview is set', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: 0,
    });
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        removePrUrlFromOverview="https://github.com/org/repo/pull/1"
      />
    );

    expect(screen.getByText('Zombie Package')).toBeInTheDocument();
    const viewPrLink = screen.getByRole('link', { name: /View removal PR/i });
    expect(viewPrLink).toBeInTheDocument();
    expect(viewPrLink).toHaveAttribute('href', 'https://github.com/org/repo/pull/1');
  });

  it('shows imported files count when direct with files_importing_count > 0', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: 5,
      other_projects_using_count: 2,
    });
    const { container } = render(<PackageOverview dependency={dep} {...defaultProps} />);

    const paragraph = Array.from(container.querySelectorAll('p')).find(
      (p) => p.textContent?.includes('Imported in') && p.textContent?.includes('files')
    );
    expect(paragraph?.textContent).toMatch(/Imported in 5 files/);
    expect(paragraph?.textContent).toMatch(/Used in 2 other projects/);
  });

  it('shows transitive dependency message when not direct', () => {
    const dep = minimalDependency({ is_direct: false });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText(/Transitive dependency — not directly imported/)).toBeInTheDocument();
  });

  it('shows "Using latest safe version" when safeVersionData.isCurrent is true', () => {
    const dep = minimalDependency();
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        safeVersionData={{
          safeVersion: '1.2.3',
          isCurrent: true,
          summary: null,
        }}
      />
    );

    expect(screen.getByText('Using latest safe version')).toBeInTheDocument();
  });

  it('shows version bump and Bump button when safe version available and not current', () => {
    const dep = minimalDependency({ version: '1.0.0' });
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        safeVersionData={{
          safeVersion: '1.2.3',
          isCurrent: false,
          summary: null,
        }}
        onBumpVersion={async () => {}}
      />
    );

    expect(screen.getByText(/v1\.0\.0 → v1\.2\.3/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Bump/i })).toBeInTheDocument();
  });

  it('shows View PR button when bumpPrUrl is set', () => {
    const dep = minimalDependency({ version: '1.0.0' });
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        safeVersionData={{
          safeVersion: '1.2.3',
          isCurrent: false,
          summary: null,
        }}
        bumpPrUrl="https://github.com/org/repo/pull/42"
        onBumpVersion={async () => {}}
      />
    );

    expect(screen.getByRole('button', { name: /View PR/i })).toBeInTheDocument();
  });

  it('shows "No safe version" when safeVersionData has no safeVersion', () => {
    const dep = minimalDependency();
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        safeVersionData={{
          safeVersion: null,
          isCurrent: false,
          summary: null,
        }}
      />
    );

    expect(screen.getByText('No safe version')).toBeInTheDocument();
  });

  it('hides Suggestion block for zombie package', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: 0,
    });
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        safeVersionData={{
          safeVersion: '1.2.3',
          isCurrent: true,
          summary: null,
        }}
      />
    );

    expect(screen.getByText('Zombie Package')).toBeInTheDocument();
    expect(screen.queryByText('Using latest safe version')).not.toBeInTheDocument();
    expect(screen.queryByText('Suggestion')).not.toBeInTheDocument();
  });

  it('shows Deprecate button when canManageDeprecations and not deprecated', () => {
    const dep = minimalDependency();
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        canManageDeprecations={true}
        onDeprecate={async () => {}}
      />
    );

    expect(screen.getByRole('button', { name: /Deprecate/i })).toBeInTheDocument();
  });

  it('does not show Deprecate button when already deprecated', () => {
    const dep = minimalDependency();
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
        canManageDeprecations={true}
        onDeprecate={async () => {}}
        deprecation={{
          recommended_alternative: 'new-pkg',
          deprecated_by: null,
          created_at: new Date().toISOString(),
        }}
      />
    );

    expect(screen.queryByRole('button', { name: /^Deprecate$/i })).not.toBeInTheDocument();
  });
});
