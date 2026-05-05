import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../test/utils';
import { MaliciousFindingCard } from '../security/MaliciousFindingCard';
import type { MaliciousFinding } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    maliciousFindings: {
      explain: vi.fn(),
      updateStatus: vi.fn(),
    },
  },
}));

function makeFinding(overrides: Partial<MaliciousFinding>): MaliciousFinding {
  return {
    id: 'f-1',
    project_id: 'p-1',
    organization_id: 'o-1',
    extraction_run_id: 'maintainer-cron:2026-05-05',
    project_dependency_id: 'pd-1',
    dependency_id: 'd-1',
    rule_id: 'maintainer:new_account_with_install_script',
    scanner: 'guarddog',
    severity: 'critical',
    message: 'New maintainer account ships an install hook.',
    depscore: null,
    suppressed: false,
    suppressed_by: null,
    suppressed_at: null,
    suppressed_reason: null,
    risk_accepted: false,
    risk_accepted_by: null,
    risk_accepted_at: null,
    risk_accepted_reason: null,
    created_at: '2026-05-05',
    package_name: 'evil-pkg',
    package_version: '1.0.0',
    ecosystem: 'npm',
    reachability_level: null,
    reachability_details: null,
    ...overrides,
  } as unknown as MaliciousFinding;
}

describe('MaliciousFindingCard scanner badge', () => {
  it('renders "Maintainer signal" badge when scanner=maintainer', () => {
    render(
      <MaliciousFindingCard
        organizationId="o-1"
        projectId="p-1"
        finding={makeFinding({ scanner: 'maintainer' as any })}
        canManage={true}
      />,
    );

    expect(screen.getByText('Maintainer signal')).toBeInTheDocument();
    expect(screen.queryByText('GuardDog')).not.toBeInTheDocument();
    expect(screen.queryByText('Feed match')).not.toBeInTheDocument();
  });

  it('renders "Feed match" when scanner=feed', () => {
    render(
      <MaliciousFindingCard
        organizationId="o-1"
        projectId="p-1"
        finding={makeFinding({ scanner: 'feed' as any })}
        canManage={true}
      />,
    );

    expect(screen.getByText('Feed match')).toBeInTheDocument();
  });

  it('falls back to "GuardDog" for non-feed non-maintainer scanners', () => {
    render(
      <MaliciousFindingCard
        organizationId="o-1"
        projectId="p-1"
        finding={makeFinding({ scanner: 'guarddog' })}
        canManage={true}
      />,
    );

    expect(screen.getByText('GuardDog')).toBeInTheDocument();
  });
});
