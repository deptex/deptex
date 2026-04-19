import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import PoliciesPage from '../PoliciesPage';

const mockGetOrganizationPolicyCode = vi.fn();
const mockGetOrganizationPolicyExceptions = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();

const pkgCode = `function packagePolicy(context) {\n  return { allowed: true, reasons: [] };\n}`;
const prCode = `function pullRequestCheck(context) {\n  return { passed: true, violations: [] };\n}`;

const mockOrgContext = {
  organization: {
    id: 'org-1',
    name: 'Test Org',
    role: 'owner',
    permissions: { manage_compliance: true },
  },
  reloadOrganization: vi.fn().mockResolvedValue(undefined),
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ id: 'org-1' })),
    useNavigate: () => mockNavigate,
    useOutletContext: vi.fn(() => mockOrgContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizationPolicyCode: (...args: unknown[]) => mockGetOrganizationPolicyCode(...args),
    getOrganizationPolicyExceptions: (...args: unknown[]) => mockGetOrganizationPolicyExceptions(...args),
    getOrganizationPolicyChanges: vi.fn().mockResolvedValue([]),
    getOrganizationPolicyChangeRequests: vi.fn().mockResolvedValue([]),
    getOrganizationRoles: vi.fn().mockResolvedValue([]),
    validatePolicyCode: vi.fn(),
    updateOrganizationPolicyCode: vi.fn(),
  },
}));

// Paths relative to this file (__tests__) so Vitest aliases match PoliciesPage imports
vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../../components/PolicyCodeEditor', () => ({
  PolicyCodeEditor: ({ value }: { value: string }) => (
    <pre data-testid="policy-code-editor">{value}</pre>
  ),
}));

vi.mock('../../../components/PolicyAIAssistant', () => ({
  PolicyAIAssistant: () => null,
}));

vi.mock('../../../components/PolicyExceptionSidebar', () => ({
  PolicyExceptionSidebar: () => null,
}));

vi.mock('../../../components/PolicyDiffCodeEditor', () => ({
  PolicyDiffCodeEditor: () => null,
}));

vi.mock('../../../components/PolicyDiffViewer', () => ({
  getDiffLineCounts: () => ({ added: 0, removed: 0 }),
}));

describe('PoliciesPage – settings subpage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrganizationPolicyCode.mockResolvedValue({
      package_policy: { package_policy_code: pkgCode },
      pr_check: { pr_check_code: prCode },
      status_code: { project_status_code: '' },
    });
    mockGetOrganizationPolicyExceptions.mockResolvedValue([]);
  });

  it('renders h2 Policies when isSettingsSubpage is true', async () => {
    render(<PoliciesPage isSettingsSubpage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies', level: 2 })).toBeInTheDocument();
    });
  });

  it('shows Package Policy and Pull Request Check sub-tabs after load', async () => {
    render(<PoliciesPage isSettingsSubpage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies', level: 2 })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Package Policy' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Pull Request Check' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change History' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change requests' })).toBeInTheDocument();
  });

  it('shows AI Assistant button', async () => {
    render(<PoliciesPage isSettingsSubpage />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /AI Assistant/ })).toBeInTheDocument();
    });
  });

  it('getOrganizationPolicyCode failure still renders page after load finishes', async () => {
    mockGetOrganizationPolicyCode.mockRejectedValue(new Error('Network error'));

    render(<PoliciesPage isSettingsSubpage />);
    await waitFor(() => {
      expect(mockGetOrganizationPolicyCode).toHaveBeenCalledWith('org-1');
    });
    // loadPolicyCode catch calls toast; if toast mock applies, it was called
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Policies', level: 2 })).toBeInTheDocument();
    });
    expect(mockToast).toHaveBeenCalled();
  });
});
