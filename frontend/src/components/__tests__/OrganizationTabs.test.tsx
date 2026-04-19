import { describe, it, expect } from 'vitest';
import { render, screen } from '../../test/utils';
import OrganizationTabs from '../OrganizationTabs';
import { RolePermissions } from '../../lib/api';

describe('OrganizationTabs', () => {
  const mockOrgId = 'org-123';

  it('renders default tabs when permissions are not loaded', () => {
    render(<OrganizationTabs organizationId={mockOrgId} userPermissions={null} />);

    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Projects')).toBeInTheDocument();

    // Restricted tabs should not be visible
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
  });

  it('renders Settings tab when view_settings permission is true', () => {
    const permissions = {
      view_settings: true,
    } as RolePermissions;

    render(<OrganizationTabs organizationId={mockOrgId} userPermissions={permissions} />);

    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('does not render Settings tab when view_settings permission is false', () => {
    const permissions = {
      view_settings: false,
    } as RolePermissions;

    render(<OrganizationTabs organizationId={mockOrgId} userPermissions={permissions} />);

    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
  });
});
