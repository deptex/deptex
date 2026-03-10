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

    // Settings is visible to all org members (no view_settings gate)
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('renders Settings tab regardless of view_settings (org settings open to all members)', () => {
    const permissions = {
      view_settings: false,
    } as RolePermissions;

    render(<OrganizationTabs organizationId={mockOrgId} userPermissions={permissions} />);

    expect(screen.getByText('Settings')).toBeInTheDocument();
  });
});
