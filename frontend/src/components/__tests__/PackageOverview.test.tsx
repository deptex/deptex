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

  it('shows the Analyze usage action for direct dependencies without a summary', () => {
    const dep = minimalDependency({ is_direct: true });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByRole('button', { name: /Analyze usage/i })).toBeInTheDocument();
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

  it('shows Unused Package when direct with 0 files importing', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: 0,
    });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.getByText('Unused Package')).toBeInTheDocument();
    expect(screen.getByText('Not imported in any file')).toBeInTheDocument();
  });

  it('shows Unused Package label for direct dependency with zero imports', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: 0,
    });
    render(
      <PackageOverview
        dependency={dep}
        {...defaultProps}
      />
    );

    expect(screen.getByText('Unused Package')).toBeInTheDocument();
  });

  it('does not show Unused Package when files_importing_count is null (non-JS ecosystem, not analyzed)', () => {
    const dep = minimalDependency({
      is_direct: true,
      files_importing_count: null,
    });
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.queryByText('Unused Package')).not.toBeInTheDocument();
    expect(screen.queryByText('Not imported in any file')).not.toBeInTheDocument();
    // Should not show "Imported in N files" either
    expect(screen.queryByText(/Imported in/)).not.toBeInTheDocument();
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

  it('does not render any deprecation surface (custom deprecations parked)', () => {
    const dep = minimalDependency();
    render(<PackageOverview dependency={dep} {...defaultProps} />);

    expect(screen.queryByText(/Deprecated by your/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Deprecate/i })).not.toBeInTheDocument();
  });
});
