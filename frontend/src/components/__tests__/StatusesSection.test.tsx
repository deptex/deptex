import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../test/utils';
import StatusesSection from '../StatusesSection';

const mockGetOrganizationStatuses = vi.fn();
const mockGetOrganizationAssetTiers = vi.fn();
const mockGetOrganizationPolicyCode = vi.fn();

const mockOrgContext = {
  organization: {
    id: 'org-1',
    role: 'owner',
    permissions: { manage_compliance: true },
  },
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1' })),
    useOutletContext: vi.fn(() => mockOrgContext),
  };
});

vi.mock('@/lib/api', () => ({
  api: {
    getOrganizationStatuses: (...args: unknown[]) => mockGetOrganizationStatuses(...args),
    getOrganizationAssetTiers: (...args: unknown[]) => mockGetOrganizationAssetTiers(...args),
    getOrganizationPolicyCode: (...args: unknown[]) => mockGetOrganizationPolicyCode(...args),
    getOrganizationPolicyChanges: vi.fn().mockResolvedValue([]),
    getOrganizationPolicyChangeRequests: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock('@/components/PolicyCodeEditor', () => ({
  PolicyCodeEditor: ({ value }: { value: string }) => (
    <pre data-testid="policy-code-editor">{value}</pre>
  ),
}));

vi.mock('@/components/PolicyAIAssistant', () => ({
  PolicyAIAssistant: () => null,
}));

vi.mock('@/components/PolicyDiffCodeEditor', () => ({
  PolicyDiffCodeEditor: () => null,
}));

vi.mock('@/components/PolicyDiffViewer', () => ({
  getDiffLineCounts: () => ({ added: 0, removed: 0 }),
}));

describe('StatusesSection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrganizationStatuses.mockResolvedValue([
      { id: 's1', organization_id: 'org-1', name: 'Compliant', color: '#22c55e', rank: 0, is_system: true, is_passing: true },
    ]);
    mockGetOrganizationAssetTiers.mockResolvedValue([
      { id: 't1', organization_id: 'org-1', name: 'External', color: '#888', rank: 0, environmental_multiplier: 1, is_default: true },
    ]);
    mockGetOrganizationPolicyCode.mockResolvedValue({
      package_policy: { package_policy_code: '' },
      pr_check: { pr_check_code: '' },
      status_code: { project_status_code: '' },
    });
  });

  it('renders Statuses heading after load', async () => {
    render(<StatusesSection />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Statuses', level: 2 })).toBeInTheDocument();
    });
  });

  it('loads statuses and asset tiers from api', async () => {
    render(<StatusesSection />);
    await waitFor(() => {
      expect(mockGetOrganizationStatuses).toHaveBeenCalledWith('org-1');
      expect(mockGetOrganizationAssetTiers).toHaveBeenCalledWith('org-1');
      expect(mockGetOrganizationPolicyCode).toHaveBeenCalledWith('org-1');
    });
  });

  it('shows sub-tab buttons', async () => {
    render(<StatusesSection />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Statuses', level: 2 })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Statuses' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Asset Tiers' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Status Code' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change History' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change requests' })).toBeInTheDocument();
  });

  it('shows status name from loaded data', async () => {
    render(<StatusesSection />);
    await waitFor(() => {
      const compliant = screen.getAllByText('Compliant');
      expect(compliant.length).toBeGreaterThanOrEqual(1);
    });
  });
});
