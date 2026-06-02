import { describe, it, expect } from 'vitest';
import { render, screen } from '../../test/utils';
import { ProjectStatusBadge } from '../ProjectStatusBadge';
import type { Project } from '../../lib/api';

function makeProject(overrides: Partial<Project>): Project {
  return {
    id: 'p-1',
    organization_id: 'o-1',
    name: 'demo',
    health_score: 0,
    is_compliant: true,
    created_at: '2026-06-01',
    updated_at: '2026-06-01',
    importance: 1.0,
    repo_status: 'ready',
    last_extracted_at: '2026-06-02',
    ...overrides,
  } as Project;
}

describe('ProjectStatusBadge — Scan incomplete chip', () => {
  it('shows the amber "Scan incomplete" chip next to a terminal status when scan_degraded', () => {
    render(<ProjectStatusBadge project={makeProject({ scan_degraded: true })} />);
    expect(screen.getByText('COMPLIANT')).toBeInTheDocument();
    expect(screen.getByText('Scan incomplete')).toBeInTheDocument();
  });

  it('does NOT show the chip when scan_degraded is false', () => {
    render(<ProjectStatusBadge project={makeProject({ scan_degraded: false })} />);
    expect(screen.getByText('COMPLIANT')).toBeInTheDocument();
    expect(screen.queryByText('Scan incomplete')).not.toBeInTheDocument();
  });

  it('shows ONLY the spinner for an in-progress scan, never the chip (even if scan_degraded)', () => {
    // Never-extracted project that is currently extracting → inProgress.
    render(
      <ProjectStatusBadge
        project={makeProject({ repo_status: 'extracting', extraction_step: 'cloning', last_extracted_at: null, scan_degraded: true })}
      />,
    );
    expect(screen.getByText('Creating')).toBeInTheDocument();
    expect(screen.queryByText('Scan incomplete')).not.toBeInTheDocument();
  });

  it('shows ONLY the Failed badge for an errored scan, never the chip (even if scan_degraded)', () => {
    render(
      <ProjectStatusBadge
        project={makeProject({ repo_status: 'error', extraction_error: 'clone failed', scan_degraded: true })}
      />,
    );
    expect(screen.getByText('Failed')).toBeInTheDocument();
    expect(screen.queryByText('Scan incomplete')).not.toBeInTheDocument();
  });
});
