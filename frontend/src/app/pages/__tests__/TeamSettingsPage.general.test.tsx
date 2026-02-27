import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../../test/utils';
import userEvent from '@testing-library/user-event';
import TeamSettingsPage from '../TeamSettingsPage';

const mockUpdateTeam = vi.fn();
const mockDeleteTeam = vi.fn();
const mockToast = vi.fn();
const mockNavigate = vi.fn();
const mockUpdateTeamData = vi.fn();
const mockReloadTeam = vi.fn().mockResolvedValue(undefined);

const defaultTeam = {
  id: 'team-1',
  name: 'Test Team',
  description: 'A test team',
  avatar_url: null,
  role: 'admin',
  role_display_name: 'Admin',
  role_color: null,
};

let mockOutletContext: {
  team: typeof defaultTeam | null;
  organizationId: string;
  reloadTeam: ReturnType<typeof vi.fn>;
  updateTeamData: ReturnType<typeof vi.fn>;
  userPermissions: { view_settings: boolean };
  organization: { permissions?: { manage_teams_and_projects: boolean } } | null;
};

vi.mock('react-router-dom', async (importOriginal) => {
  const mod = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...mod,
    useParams: vi.fn(() => ({ orgId: 'org-1', teamId: 'team-1', section: 'general' })),
    useNavigate: () => mockNavigate,
    useSearchParams: () => [new URLSearchParams(), vi.fn()],
    useOutletContext: vi.fn(() => mockOutletContext),
  };
});

vi.mock('../../../lib/api', () => ({
  api: {
    updateTeam: (...args: unknown[]) => mockUpdateTeam(...args),
    deleteTeam: (...args: unknown[]) => mockDeleteTeam(...args),
  },
}));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1' } }),
}));

describe('TeamSettingsPage – General', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUpdateTeam.mockResolvedValue({ ...defaultTeam });
    mockDeleteTeam.mockResolvedValue({ message: 'Deleted' });
    mockReloadTeam.mockResolvedValue(undefined);

    mockOutletContext = {
      team: { ...defaultTeam },
      organizationId: 'org-1',
      reloadTeam: mockReloadTeam,
      updateTeamData: mockUpdateTeamData,
      userPermissions: { view_settings: true },
      organization: { permissions: { manage_teams_and_projects: true } },
    };
  });

  it('shows General heading when on general tab', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
  });

  it('shows Team Name input with placeholder', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.getByPlaceholderText('Enter team name')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter team name')).toHaveValue('Test Team');
  });

  it('shows Team Description textarea with placeholder', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText("Describe the team's purpose...")).toBeInTheDocument();
    });
    expect(screen.getByPlaceholderText("Describe the team's purpose...")).toHaveValue('A test team');
  });

  it('Save button is disabled when name and description unchanged', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    expect(saveBtn).toBeDisabled();
  });

  it('Save button is enabled when name changed', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter team name')).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText('Enter team name');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'New Team Name');
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    expect(saveBtn).toBeEnabled();
  });

  it('Save button is enabled when description changed', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText("Describe the team's purpose...")).toBeInTheDocument();
    });
    const descInput = screen.getByPlaceholderText("Describe the team's purpose...");
    await userEvent.clear(descInput);
    await userEvent.type(descInput, 'Updated description');
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    expect(saveBtn).toBeEnabled();
  });

  it('Save calls api.updateTeam when name changed and Save clicked', async () => {
    mockUpdateTeam.mockResolvedValue({ ...defaultTeam, name: 'New Team Name' });

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter team name')).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText('Enter team name');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'New Team Name');
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    await userEvent.click(saveBtn);

    await waitFor(() => {
      expect(mockUpdateTeam).toHaveBeenCalledWith('org-1', 'team-1', expect.objectContaining({ name: 'New Team Name' }));
    });
  });

  it('Save calls updateTeamData after successful update', async () => {
    mockUpdateTeam.mockResolvedValue({ ...defaultTeam, name: 'New Team Name', description: 'A test team' });

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter team name')).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText('Enter team name');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'New Team Name');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(mockUpdateTeamData).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'New Team Name' }),
      );
    });
  });

  it('successful save updates team and calls updateTeamData', async () => {
    const user = userEvent.setup();
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter team name')).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText('Enter team name');
    await user.clear(nameInput);
    await user.type(nameInput, 'New Name');
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    await waitFor(() => expect(saveBtn).toBeEnabled());
    await user.click(saveBtn);

    await waitFor(() => {
      expect(mockUpdateTeam).toHaveBeenCalledWith('org-1', 'team-1', expect.objectContaining({ name: 'New Name' }));
      expect(mockUpdateTeamData).toHaveBeenCalled();
    });
  });

  it('Save with empty name does not call updateTeam', async () => {
    const user = userEvent.setup();
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Enter team name')).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText('Enter team name');
    await user.clear(nameInput);
    const saveBtn = screen.getByRole('button', { name: 'Save' });
    await waitFor(() => expect(saveBtn).toBeEnabled());
    await user.click(saveBtn);

    expect(mockUpdateTeam).not.toHaveBeenCalled();
  });

  it('shows Danger Zone when user has manage_teams_and_projects permission', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    expect(screen.getByText('Delete Team')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
  });

  it('does not show Danger Zone when user lacks manage_teams_and_projects permission', async () => {
    mockOutletContext.organization = { permissions: { manage_teams_and_projects: false } };

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.queryByText('Danger Zone')).not.toBeInTheDocument();
  });

  it('Delete Forever is disabled until team name is typed', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Team')).toBeInTheDocument();
    });
    const deleteForeverBtn = screen.getByRole('button', { name: 'Delete Forever' });
    expect(deleteForeverBtn).toBeDisabled();
  });

  it('Delete Forever is enabled when team name is typed correctly', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Team')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Team'), 'Test Team');
    const deleteForeverBtn = screen.getByRole('button', { name: 'Delete Forever' });
    expect(deleteForeverBtn).toBeEnabled();
  });

  it('Delete Forever calls api.deleteTeam when confirmed', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Team')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Team'), 'Test Team');
    await userEvent.click(screen.getByRole('button', { name: 'Delete Forever' }));

    await waitFor(() => {
      expect(mockDeleteTeam).toHaveBeenCalledWith('org-1', 'team-1');
    });
  });

  it('navigates to teams list after successful delete', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Team')).toBeInTheDocument();
    });
    await userEvent.type(screen.getByPlaceholderText('Test Team'), 'Test Team');
    await userEvent.click(screen.getByRole('button', { name: 'Delete Forever' }));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/teams');
    });
  });

  it('Cancel button hides delete confirmation', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Danger Zone')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Test Team')).toBeInTheDocument();
    });
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(screen.queryByPlaceholderText('Test Team')).not.toBeInTheDocument();
    });
  });

  it('redirects when view_settings permission is false', async () => {
    mockOutletContext.userPermissions = { view_settings: false };

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/teams/team-1/projects', { replace: true });
    });
  });

  it('shows "Changes will be visible to all team members" helper text', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByText('Changes will be visible to all team members.')).toBeInTheDocument();
    });
  });

  it('shows Team Name and Team Description section headings', async () => {
    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    expect(screen.getByText('Team Name')).toBeInTheDocument();
    expect(screen.getByText('Team Description')).toBeInTheDocument();
  });

  it('tab click navigates to correct settings URL', async () => {
    mockOutletContext.userPermissions = {
      view_settings: true,
      manage_notification_settings: true,
      view_roles: true,
      edit_roles: true,
      manage_members: true,
    } as any;

    render(<TeamSettingsPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'General' })).toBeInTheDocument();
    });
    const notificationsButton = screen.getAllByRole('button').find((b) => b.textContent === 'Notifications');
    if (notificationsButton) {
      await userEvent.click(notificationsButton);
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/org-1/teams/team-1/settings/notifications');
    }
  });
});
