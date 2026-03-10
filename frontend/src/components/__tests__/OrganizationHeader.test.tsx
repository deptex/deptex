import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../test/utils';
import OrganizationHeader from '../OrganizationHeader';
import { Organization } from '../../lib/api';

vi.mock('../OrganizationSwitcher', () => ({
  default: ({ currentOrganizationName }: { currentOrganizationName: string }) => (
    <span data-testid="org-switcher">{currentOrganizationName}</span>
  ),
}));

vi.mock('../AppHeader', () => ({
  default: ({ customLeftContent }: any) => <div data-testid="app-header">{customLeftContent}</div>,
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

  it('renders org name via OrganizationSwitcher', () => {
    render(<OrganizationHeader organization={mockOrg} />);

    expect(screen.getByText('Test Org')).toBeInTheDocument();
    expect(screen.getByTestId('org-switcher')).toBeInTheDocument();
  });
});
