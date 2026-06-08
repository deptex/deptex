import { describe, it, expect } from 'vitest';
import { render, screen } from '../test/utils';
import { ProjectsAssetTable } from '../components/ProjectsAssetTable';
import type { Project, ProjectSecuritySummary } from '../lib/api';

const summary = (over: Partial<ProjectSecuritySummary> & { project_id: string; project_name: string }): ProjectSecuritySummary =>
  ({
    team_id: null,
    vuln_count: 0, critical_count: 0, reachable_count: 0, worst_depscore: 0,
    band_critical: 0, band_high: 0, band_medium: 0, band_low: 0,
    semgrep_count: 0, secret_count: 0, verified_secret_count: 0,
    ...over,
  } as ProjectSecuritySummary);

const project = (over: Partial<Project> & { id: string; name: string }): Project =>
  ({ framework: 'express', owner_team_name: 'Payments', ...over } as Project);

const summaries = [summary({ project_id: '1', project_name: 'checkout-svc', band_high: 2 })];
const projects = [project({ id: '1', name: 'checkout-svc' })];

describe('ProjectsAssetTable', () => {
  it('renders a row per summary with the project name', () => {
    render(<ProjectsAssetTable summaries={summaries} projects={projects} loading={false} />);
    expect(screen.getByText('checkout-svc')).toBeTruthy();
  });

  it('shows the Team column when showTeamColumn is on (org context)', () => {
    render(<ProjectsAssetTable summaries={summaries} projects={projects} loading={false} showTeamColumn />);
    expect(screen.getByText('Team')).toBeTruthy();
  });

  it('hides the Team column when showTeamColumn is off (team context)', () => {
    render(<ProjectsAssetTable summaries={summaries} projects={projects} loading={false} showTeamColumn={false} />);
    expect(screen.queryByText('Team')).toBeNull();
  });

  it('renders the empty state with the supplied hint when there are no projects', () => {
    render(<ProjectsAssetTable summaries={[]} projects={[]} loading={false} emptyHint="This team doesn't have any projects yet." />);
    expect(screen.getByText('No projects yet')).toBeTruthy();
    expect(screen.getByText("This team doesn't have any projects yet.")).toBeTruthy();
  });

  it('renders the error state + retry when error is set', () => {
    render(<ProjectsAssetTable summaries={[]} projects={[]} loading={false} error errorContext="this team's projects" onRetry={() => {}} />);
    expect(screen.getByText("Couldn't load projects")).toBeTruthy();
    expect(screen.getByText('Try again')).toBeTruthy();
  });
});
