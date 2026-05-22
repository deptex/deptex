import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import AccountSettingsPage from '../AccountSettingsPage';

const mockGetOrganizations = vi.fn();
const mockGetUserProfile = vi.fn();
const mockUpdateUserProfile = vi.fn();
const mockDeleteAccount = vi.fn();
const mockUpdateUser = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockSignOut = vi.fn().mockResolvedValue(undefined);

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useLocation: () => ({ pathname: '/organizations/org-1/account/general' }),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), vi.fn()],
  };
});

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'user-1', email: 'me@test.com', identities: [] },
    signOut: mockSignOut,
  }),
}));

vi.mock('../../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast, toasts: [] }),
}));

// Name/avatar resolution has its own unit test (userIdentity.test.ts); pin it
// here so the page test does not depend on the resolution internals.
vi.mock('../../../lib/userIdentity', () => ({
  getDisplayNameOrNull: () => 'Test User',
  getAvatarUrl: () => 'https://example.com/avatar.png',
}));

vi.mock('../../../lib/api', () => ({
  api: {
    getOrganizations: (...a: unknown[]) => mockGetOrganizations(...a),
    getUserProfile: (...a: unknown[]) => mockGetUserProfile(...a),
    updateUserProfile: (...a: unknown[]) => mockUpdateUserProfile(...a),
    deleteAccount: (...a: unknown[]) => mockDeleteAccount(...a),
  },
}));

vi.mock('../../../lib/supabase', () => ({
  supabase: {
    auth: {
      updateUser: (...a: unknown[]) => mockUpdateUser(...a),
      refreshSession: vi.fn(),
      linkIdentity: vi.fn().mockResolvedValue({ error: null }),
    },
    storage: {
      from: () => ({
        upload: vi.fn().mockResolvedValue({ error: null }),
        getPublicUrl: () => ({ data: { publicUrl: 'https://example.com/new.png' } }),
        remove: vi.fn().mockResolvedValue({ error: null }),
      }),
    },
  },
}));

// Radix Select relies on pointer APIs jsdom lacks — render a native <select>
// so the Default Organization dirty-check can be exercised.
vi.mock('../../../components/ui/select', () => ({
  Select: ({ value, onValueChange, children, disabled }: any) => (
    <select
      data-testid="org-select"
      value={value ?? ''}
      disabled={disabled}
      onChange={(e) => onValueChange(e.target.value)}
    >
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => <>{children}</>,
  SelectItem: ({ value }: any) => <option value={value}>{value}</option>,
}));

const orgs = [
  { id: 'org-1', name: 'First Org', avatar_url: null },
  { id: 'org-2', name: 'Second Org', avatar_url: null },
];

/** The page renders two "Save" buttons — General first, Default Organization second. */
function generalSave() {
  return screen.getAllByRole('button', { name: 'Save' })[0];
}
function defaultOrgSave() {
  return screen.getAllByRole('button', { name: 'Save' })[1];
}

describe('AccountSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrganizations.mockResolvedValue(orgs);
    mockGetUserProfile.mockResolvedValue({ default_organization_id: 'org-1' });
    mockUpdateUserProfile.mockResolvedValue({});
    mockDeleteAccount.mockResolvedValue({});
    mockUpdateUser.mockResolvedValue({ error: null });
    mockSignOut.mockResolvedValue(undefined);
  });

  describe('General — display name', () => {
    it('Save is disabled when the name is unchanged', async () => {
      render(<AccountSettingsPage />);
      const input = await screen.findByPlaceholderText('Enter your display name');
      expect(input).toHaveValue('Test User');
      expect(generalSave()).toBeDisabled();
    });

    it('editing the name enables Save', async () => {
      render(<AccountSettingsPage />);
      const input = await screen.findByPlaceholderText('Enter your display name');
      await userEvent.clear(input);
      await userEvent.type(input, 'New Name');
      expect(generalSave()).not.toBeDisabled();
    });

    it('an empty name keeps Save disabled', async () => {
      render(<AccountSettingsPage />);
      const input = await screen.findByPlaceholderText('Enter your display name');
      await userEvent.clear(input);
      expect(generalSave()).toBeDisabled();
    });

    it('Save persists the trimmed name via updateUser', async () => {
      render(<AccountSettingsPage />);
      const input = await screen.findByPlaceholderText('Enter your display name');
      await userEvent.clear(input);
      await userEvent.type(input, '  New Name  ');
      await userEvent.click(generalSave());

      await waitFor(() => {
        expect(mockUpdateUser).toHaveBeenCalledWith({ data: { custom_full_name: 'New Name' } });
      });
    });
  });

  describe('Default Organization', () => {
    it('Save is disabled until a different org is picked', async () => {
      render(<AccountSettingsPage />);
      await waitFor(() => {
        expect(mockGetOrganizations).toHaveBeenCalled();
      });
      await waitFor(() => {
        expect(defaultOrgSave()).toBeDisabled();
      });
    });

    it('picking a different org enables Save and persists it', async () => {
      render(<AccountSettingsPage />);
      const select = await screen.findByTestId('org-select');
      await waitFor(() => {
        expect(within(select).getByText('org-2')).toBeInTheDocument();
      });

      await userEvent.selectOptions(select, 'org-2');
      await waitFor(() => {
        expect(defaultOrgSave()).not.toBeDisabled();
      });

      await userEvent.click(defaultOrgSave());
      await waitFor(() => {
        expect(mockUpdateUserProfile).toHaveBeenCalledWith({ default_organization_id: 'org-2' });
      });
    });
  });

  describe('Delete account', () => {
    it('clicking Delete reveals the confirmation input', async () => {
      render(<AccountSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
      expect(screen.getByPlaceholderText('me@test.com')).toBeInTheDocument();
    });

    it('Delete Forever is disabled until the exact email is typed', async () => {
      render(<AccountSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));

      const deleteForever = screen.getByRole('button', { name: 'Delete Forever' });
      expect(deleteForever).toBeDisabled();

      await userEvent.type(screen.getByPlaceholderText('me@test.com'), 'wrong@test.com');
      expect(deleteForever).toBeDisabled();

      await userEvent.clear(screen.getByPlaceholderText('me@test.com'));
      await userEvent.type(screen.getByPlaceholderText('me@test.com'), 'me@test.com');
      expect(deleteForever).not.toBeDisabled();
    });

    it('confirming deletes the account, signs out, and redirects', async () => {
      render(<AccountSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
      await userEvent.type(screen.getByPlaceholderText('me@test.com'), 'me@test.com');
      await userEvent.click(screen.getByRole('button', { name: 'Delete Forever' }));

      await waitFor(() => {
        expect(mockDeleteAccount).toHaveBeenCalled();
      });
      await waitFor(() => {
        expect(mockSignOut).toHaveBeenCalled();
        expect(mockNavigate).toHaveBeenCalledWith('/');
      });
    });

    it('shows the blocking organizations when deletion is refused', async () => {
      mockDeleteAccount.mockRejectedValueOnce({
        responseBody: { organizations: [{ id: 'o1', name: 'Acme Inc' }] },
      });

      render(<AccountSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
      await userEvent.type(screen.getByPlaceholderText('me@test.com'), 'me@test.com');
      await userEvent.click(screen.getByRole('button', { name: 'Delete Forever' }));

      await waitFor(() => {
        expect(screen.getByText('Acme Inc')).toBeInTheDocument();
      });
      expect(mockNavigate).not.toHaveBeenCalled();
    });

    it('Cancel closes the confirmation without deleting', async () => {
      render(<AccountSettingsPage />);
      await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
      expect(screen.getByPlaceholderText('me@test.com')).toBeInTheDocument();

      await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      expect(screen.queryByPlaceholderText('me@test.com')).not.toBeInTheDocument();
      expect(mockDeleteAccount).not.toHaveBeenCalled();
    });
  });
});
