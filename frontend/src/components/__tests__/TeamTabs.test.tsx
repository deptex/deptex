import { describe, it, expect } from 'vitest';
import { render, screen } from '../../test/utils';
import TeamTabs from '../TeamTabs';
import { TeamPermissions } from '../../lib/api';

describe('TeamTabs', () => {
  const mockOrgId = 'org-123';
  const mockTeamId = 'team-456';

  it('renders no tabs when permissions are not loaded', () => {
    render(<TeamTabs organizationId={mockOrgId} teamId={mockTeamId} userPermissions={null} />);

    expect(screen.queryByText('Overview')).not.toBeInTheDocument();
    expect(screen.queryByText('Projects')).not.toBeInTheDocument();
  });

  it('renders standard tabs when permissions object is provided', () => {
    const permissions = {
      view_overview: true,
      // other permissions...
    } as TeamPermissions;

    render(<TeamTabs organizationId={mockOrgId} teamId={mockTeamId} userPermissions={permissions} />);

    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Projects')).toBeInTheDocument();
  });

  it('renders Settings tab when view_settings permission is true', () => {
    const permissions = {
      view_settings: true,
    } as TeamPermissions;

    render(<TeamTabs organizationId={mockOrgId} teamId={mockTeamId} userPermissions={permissions} />);

    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('does not render Settings tab when view_settings permission is false', () => {
    const permissions = {
      view_settings: false,
    } as TeamPermissions;

    render(<TeamTabs organizationId={mockOrgId} teamId={mockTeamId} userPermissions={permissions} />);

    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
  });
});
