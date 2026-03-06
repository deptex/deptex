import { useState, useEffect } from 'react';
import { Check, Link as LinkIcon, Loader2 } from 'lucide-react';
import { api } from '../lib/api';
import type { Organization, OrganizationMember, OrganizationInvitation, OrganizationRole, RolePermissions, Team } from '../lib/api';
import { useToast } from '../hooks/use-toast';
import { Button } from './ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from './ui/dialog';
import { RoleDropdown } from './RoleDropdown';
import { ProjectTeamMultiSelect } from './ProjectTeamMultiSelect';

interface InviteForm {
  email: string;
  role: string;
  team_ids?: string[];
}

export interface InviteMemberDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  organization: Organization | null;
  /** When provided, dialog uses this data instead of fetching (e.g. from MembersPage) */
  sharedMembers?: OrganizationMember[];
  sharedInvitations?: OrganizationInvitation[];
  sharedTeams?: Team[];
  sharedRoles?: OrganizationRole[];
  onSuccess?: () => void;
}

export function InviteMemberDialog({
  open,
  onOpenChange,
  organizationId,
  organization,
  sharedMembers,
  sharedInvitations,
  sharedTeams,
  sharedRoles,
  onSuccess,
}: InviteMemberDialogProps) {
  const { toast } = useToast();
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [roles, setRoles] = useState<OrganizationRole[]>([]);
  const [loading, setLoading] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [inviteForms, setInviteForms] = useState<InviteForm[]>([{ email: '', role: 'member', team_ids: [] }]);
  const [shareLinkCopied, setShareLinkCopied] = useState(false);

  const useShared = sharedMembers !== undefined && sharedRoles !== undefined;

  useEffect(() => {
    if (!open || !organizationId) return;
    if (useShared && sharedMembers && sharedRoles) {
      setMembers(sharedMembers);
      setInvitations(sharedInvitations ?? []);
      setTeams(sharedTeams ?? []);
      setRoles(sharedRoles);
      return;
    }
    let cancelled = false;
    setLoading(true);
    Promise.all([
      api.getOrganizationMembers(organizationId),
      api.getOrganizationInvitations(organizationId),
      api.getTeams(organizationId).catch(() => []),
      api.getOrganizationRoles(organizationId).catch(() => []),
    ])
      .then(([membersData, invitationsData, teamsData, rolesData]) => {
        if (!cancelled) {
          setMembers(membersData);
          setInvitations(invitationsData);
          setTeams(teamsData);
          setRoles(rolesData);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [open, organizationId, useShared, sharedMembers, sharedInvitations, sharedTeams, sharedRoles]);

  const userRank = organization?.user_rank ?? 0;
  const isOrgOwner = organization?.role === 'owner';
  const currentPermissions: RolePermissions | null = organization?.permissions ?? null;

  const getAssignableRoles = (): OrganizationRole[] => {
    return roles
      .filter((role) => {
        if (role.display_order < userRank || role.name === 'owner') return false;
        if (isOrgOwner) return true;
        if (!currentPermissions) return false;
        if (role.permissions) {
          for (const [key, value] of Object.entries(role.permissions)) {
            if (value === true && !(currentPermissions as Record<string, boolean>)[key]) return false;
          }
        }
        return true;
      })
      .sort((a, b) => a.display_order - b.display_order);
  };

  const getRoleDisplayName = (roleName: string): string => {
    const r = roles.find((x) => x.name === roleName);
    if (r?.display_name) return r.display_name;
    if (roleName === 'owner') return 'Owner';
    if (roleName === 'member') return 'Member';
    return roleName.charAt(0).toUpperCase() + roleName.slice(1);
  };

  const getRoleColor = (roleName: string): string | undefined => {
    return roles.find((r) => r.name === roleName)?.color ?? undefined;
  };

  const handleInviteChange = (index: number, field: keyof InviteForm, value: string | string[]) => {
    const updated = [...inviteForms];
    updated[index] = { ...updated[index], [field]: value };
    setInviteForms(updated);
  };

  const handleSendInvites = async () => {
    if (!organizationId) return;
    const form = inviteForms[0];
    if (!form?.email.trim()) {
      toast({ title: 'Error', description: 'Please enter an email address', variant: 'destructive' });
      return;
    }
    const emailLower = form.email.trim().toLowerCase();
    if (members.some((m) => m.email.toLowerCase() === emailLower)) {
      toast({ title: 'Already a Member', description: 'This person is already a member of the organization', variant: 'destructive' });
      return;
    }
    if (invitations.some((inv) => inv.email.toLowerCase() === emailLower)) {
      toast({ title: 'Already Invited', description: 'This person has already been invited', variant: 'destructive' });
      return;
    }
    setInviting(true);
    try {
      await api.createInvitation(
        organizationId,
        form.email.trim(),
        form.role,
        form.team_ids && form.team_ids.length > 0 ? form.team_ids : undefined
      );
      setInviteForms([{ email: '', role: 'member', team_ids: [] }]);
      onOpenChange(false);
      onSuccess?.();
      toast({ title: 'Success', description: 'Invitation sent successfully' });
    } catch (error: any) {
      if (error.message?.includes('Already invited')) {
        toast({ title: 'Already Invited', description: 'This person has already been invited', variant: 'destructive' });
      } else {
        toast({ title: 'Error', description: error.message || 'Failed to send invitation', variant: 'destructive' });
      }
    } finally {
      setInviting(false);
    }
  };

  const handleCopyShareLink = () => {
    if (!organizationId) return;
    const selectedTeamIds = inviteForms[0]?.team_ids || [];
    let shareLink = `${window.location.origin}/join/${organizationId}`;
    if (selectedTeamIds.length > 0) shareLink += `?teams=${selectedTeamIds.join(',')}`;
    navigator.clipboard.writeText(shareLink);
    setShareLinkCopied(true);
    toast({ title: 'Copied!', description: 'Share link copied to clipboard' });
    setTimeout(() => setShareLinkCopied(false), 2000);
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) setInviteForms([{ email: '', role: 'member', team_ids: [] }]);
    onOpenChange(next);
  };

  const assignableRoles = getAssignableRoles();
  const memberCounts: Record<string, number> = {};
  assignableRoles.forEach((role) => {
    memberCounts[role.name] = members.filter((m) => m.role === role.name).length;
  });

  // Show form immediately; role/teams load in background (no blocking spinner)

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
        <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
          <DialogTitle>Invite new member</DialogTitle>
          <DialogDescription className="mt-1">
            Invite new members to your organization by email. You can assign them a role and optionally add them to a team.
          </DialogDescription>
        </div>

        <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
          <div className="grid gap-2">
            <label htmlFor="invite-email" className="text-sm font-medium text-foreground">
              Email Address
            </label>
            <input
              id="invite-email"
              type="email"
              placeholder=""
              value={inviteForms[0]?.email || ''}
              onChange={(e) => handleInviteChange(0, 'email', e.target.value)}
              className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && inviteForms[0]?.email) handleSendInvites();
              }}
            />
          </div>

          <div className="grid gap-2">
            <label className="text-sm font-medium text-foreground">Role</label>
            {assignableRoles.length > 0 ? (
              <RoleDropdown
                value={inviteForms[0]?.role || 'member'}
                onChange={(value) => handleInviteChange(0, 'role', value)}
                roles={assignableRoles}
                getRoleDisplayName={getRoleDisplayName}
                getRoleColor={getRoleColor}
                memberCounts={memberCounts}
                showBadges={true}
                variant="modal"
              />
            ) : (
              <div className="flex items-center gap-2 h-9 px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground-secondary">
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin shrink-0" />
                    <span>Loading roles…</span>
                  </>
                ) : (
                  <span>Member</span>
                )}
              </div>
            )}
          </div>

          <div className="grid gap-2">
            <label className="text-sm font-medium text-foreground">Teams</label>
            {teams.length > 0 ? (
              <ProjectTeamMultiSelect
                value={inviteForms[0]?.team_ids || []}
                onChange={(value) => handleInviteChange(0, 'team_ids', value)}
                teams={teams}
                variant="modal"
              />
            ) : (
              <div className="flex items-center gap-2 min-h-9 px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground-secondary">
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin shrink-0" />
                    <span>Loading teams…</span>
                  </>
                ) : (
                  <span>No teams</span>
                )}
              </div>
            )}
          </div>

          <div className="pt-2">
            <Button variant="outline" size="sm" onClick={handleCopyShareLink} className="text-xs">
              {shareLinkCopied ? (
                <>
                  <Check className="h-3 w-3 mr-1" />
                  Copied!
                </>
              ) : (
                <>
                  <LinkIcon className="h-3 w-3 mr-1" />
                  Copy Invite Link
                </>
              )}
            </Button>
          </div>
        </div>

        <DialogFooter className="px-6 py-4 bg-background">
          <Button
            variant="outline"
            onClick={() => handleOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSendInvites}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            disabled={inviting}
          >
            {inviting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
            Send Invitation
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
