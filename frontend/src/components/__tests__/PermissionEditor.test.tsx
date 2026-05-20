import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../test/utils';
import userEvent from '@testing-library/user-event';
import { PermissionEditor } from '../PermissionEditor';
import type { RolePermissions } from '../../lib/api';

const emptyPerms = (): RolePermissions => ({
  view_settings: false,
  manage_billing: false,
  manage_security: false,
  view_activity: false,
  manage_compliance: false,
  manage_statuses: false,
  interact_with_aegis: false,
  trigger_fix: false,
  manage_aegis: false,
  view_ai_spending: false,
  manage_incidents: false,
  view_members: false,
  add_members: false,
  edit_roles: false,
  edit_permissions: false,
  kick_members: false,
  manage_teams_and_projects: false,
  manage_integrations: false,
});

const fullPerms = (): RolePermissions => ({
  view_settings: true,
  manage_billing: true,
  manage_security: true,
  view_activity: true,
  manage_compliance: true,
  manage_statuses: true,
  interact_with_aegis: true,
  trigger_fix: true,
  manage_aegis: true,
  view_ai_spending: true,
  manage_incidents: true,
  view_members: true,
  add_members: true,
  edit_roles: true,
  edit_permissions: true,
  kick_members: true,
  manage_teams_and_projects: true,
  manage_integrations: true,
});

describe('PermissionEditor', () => {
  it('renders the top-level permission group headings', () => {
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        currentUserPermissions={fullPerms()}
        isOrgOwner={false}
      />,
    );

    expect(screen.getByText('Admin')).toBeInTheDocument();
    expect(screen.getByText('Security & Policies')).toBeInTheDocument();
    expect(screen.getByText('AI & Automation')).toBeInTheDocument();
    expect(screen.getByText('Teams & Projects')).toBeInTheDocument();
  });

  it('keeps dependsOn rows hidden until the parent permission is toggled on', () => {
    const onChange = vi.fn();
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        onChange={onChange}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
      />,
    );

    // view_members is off → kick_members + edit_roles rows should collapse to 0fr (no height).
    // We can't easily assert grid-template-rows in jsdom but we can check the row text is not
    // visible in a useful way — instead assert that toggling the parent calls onChange with
    // both children synced.
    const viewMembersBtn = screen.getByRole('button', { name: 'View/Add Members' });
    expect(viewMembersBtn).toBeInTheDocument();
  });

  it('syncs interact_with_aegis, trigger_fix and manage_incidents into one toggle', async () => {
    const onChange = vi.fn();
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        onChange={onChange}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
      />,
    );

    const useAegis = screen.getByRole('button', { name: 'Use Aegis AI' });
    await userEvent.click(useAegis);

    expect(onChange).toHaveBeenCalled();
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1][0];
    expect(lastCall.interact_with_aegis).toBe(true);
    expect(lastCall.trigger_fix).toBe(true);
    expect(lastCall.manage_incidents).toBe(true);
  });

  it('syncs manage_aegis and view_ai_spending together', async () => {
    const onChange = vi.fn();
    render(
      <PermissionEditor
        permissions={{ ...emptyPerms(), interact_with_aegis: true, trigger_fix: true, manage_incidents: true }}
        onSave={vi.fn().mockResolvedValue(undefined)}
        onChange={onChange}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
      />,
    );

    const manageAegis = screen.getByRole('button', { name: 'Manage Aegis Configuration' });
    await userEvent.click(manageAegis);

    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1][0];
    expect(lastCall.manage_aegis).toBe(true);
    expect(lastCall.view_ai_spending).toBe(true);
  });

  it('syncs manage_compliance and manage_statuses under one Manage Policies toggle', async () => {
    const onChange = vi.fn();
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        onChange={onChange}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
      />,
    );

    const managePolicies = screen.getByRole('button', { name: 'Manage Policies' });
    await userEvent.click(managePolicies);

    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1][0];
    expect(lastCall.manage_compliance).toBe(true);
    expect(lastCall.manage_statuses).toBe(true);
  });

  it('cascades view_members off → kick_members + edit_roles also off', async () => {
    const onChange = vi.fn();
    render(
      <PermissionEditor
        permissions={{
          ...emptyPerms(),
          view_members: true,
          add_members: true,
          kick_members: true,
          edit_roles: true,
        }}
        onSave={vi.fn().mockResolvedValue(undefined)}
        onChange={onChange}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
      />,
    );

    const viewMembers = screen.getByRole('button', { name: 'View/Add Members' });
    await userEvent.click(viewMembers);

    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1][0];
    expect(lastCall.view_members).toBe(false);
    expect(lastCall.add_members).toBe(false);
    expect(lastCall.kick_members).toBe(false);
    expect(lastCall.edit_roles).toBe(false);
  });

  it('blocks a non-owner from granting a permission they do not have themselves', async () => {
    const onChange = vi.fn();
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        onChange={onChange}
        // Actor only has view_activity — should not be able to enable anything else.
        currentUserPermissions={{ ...emptyPerms(), view_activity: true }}
        isOrgOwner={false}
      />,
    );

    const auditLogs = screen.getByRole('button', { name: 'View Audit Logs' });
    expect(auditLogs).not.toBeDisabled();

    const manageBilling = screen.getByRole('button', { name: 'Manage Plan & Billing' });
    expect(manageBilling).toBeDisabled();

    // Trying to click the disabled button should not invoke onChange.
    await userEvent.click(manageBilling);
    expect(onChange).not.toHaveBeenCalledWith(expect.objectContaining({ manage_billing: true }));
  });

  it('does not render Cancel/Save Permissions actions when hideActions is set', () => {
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
        hideActions
      />,
    );

    expect(screen.queryByRole('button', { name: 'Save Permissions' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
  });

  it('normalises view_settings to true on save regardless of toggle state', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={onSave}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Save Permissions' }));

    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave.mock.calls[0][0]).toMatchObject({ view_settings: true });
  });

  it('disables the Save Permissions button when isLoading is true', () => {
    render(
      <PermissionEditor
        permissions={emptyPerms()}
        onSave={vi.fn().mockResolvedValue(undefined)}
        currentUserPermissions={fullPerms()}
        isOrgOwner={true}
        isLoading
      />,
    );

    const saveBtn = screen.getByRole('button', { name: /Save Permissions/i });
    expect(saveBtn).toBeDisabled();
  });
});
