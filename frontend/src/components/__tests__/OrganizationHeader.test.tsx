import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../test/utils';
import OrganizationHeader from '../OrganizationHeader';
import { Organization } from '../../lib/api';
import { api } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    getOrganizationRoles: vi.fn(),
  },
}));

vi.mock('../OrganizationSwitcher', () => ({
  default: () => null,
}));

vi.mock('../AppHeader', () => ({
  default: ({ customLeftContent }: any) => <div data-testid="app-header">{customLeftContent}</div>,
}));

vi.mock('../RoleBadge', () => ({
  RoleBadge: () => <div data-testid="role-badge">RoleBadge</div>,
}));

describe('OrganizationHeader', () => {
  const mockOrg: Organization = {
    id: 'org-1',
    name: 'Test Org',
    plan: 'free',
    created_at: '2023-01-01',
    updated_at: '2023-01-01',
    role: 'admin',
    permissions: undefined,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('returns null when organization is null', () => {
    const { container } = render(<OrganizationHeader organization={null} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders org name and RoleBadge', () => {
    render(<OrganizationHeader organization={mockOrg} />);

    expect(screen.getByText('Test Org')).toBeInTheDocument();
    expect(screen.getByTestId('role-badge')).toBeInTheDocument();
  });

  it('fetches role info when organization has role', async () => {
    (api.getOrganizationRoles as any).mockResolvedValue([
      {
        name: 'admin',
        display_name: 'Admin',
        color: '#3b82f6',
        permissions: {},
      },
    ]);

    render(<OrganizationHeader organization={mockOrg} />);

    await waitFor(() => {
      expect(api.getOrganizationRoles).toHaveBeenCalledWith('org-1');
    });
  });

  it('uses role_display_name from organization when present', () => {
    const orgWithDisplayName = { ...mockOrg, role_display_name: 'Custom Admin' };
    render(<OrganizationHeader organization={orgWithDisplayName} />);

    expect(screen.getByText('Test Org')).toBeInTheDocument();
    expect(screen.getByTestId('role-badge')).toBeInTheDocument();
  });
});
