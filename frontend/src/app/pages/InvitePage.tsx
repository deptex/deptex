import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Loader2, Mail } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { api } from '../../lib/api';
import { Button } from '../../components/ui/button';
import { RoleBadge } from '../../components/RoleBadge';
import { OrgAvatar } from '../../components/Avatar';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';

interface InvitationDetails {
  id: string;
  email: string;
  role: string;
  role_display_name: string | null;
  role_color: string | null;
  organization_id: string;
  organization_name: string;
  organization_avatar_url: string | null;
  expires_at: string;
}

// Mirrors OrganizationSwitcher's DEFAULT_ROLE_COLORS. Member is intentionally
// absent so it falls through to RoleBadge's neutral styling.
const DEFAULT_ROLE_COLORS: Record<string, string> = {
  owner: '#3b82f6',
  admin: '#14b8a6',
};

export default function InvitePage() {
  const { invitationId } = useParams<{ invitationId: string }>();
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [invitation, setInvitation] = useState<InvitationDetails | null>(null);
  const [loadingInvitation, setLoadingInvitation] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);
  const [declining, setDeclining] = useState(false);

  // Logged-out users get bounced to /login with a redirect-back so they can
  // come right back here after auth.
  useEffect(() => {
    if (authLoading) return;
    if (!user && invitationId) {
      navigate(`/login?redirect=/invite/${invitationId}`, { replace: true });
    }
  }, [user, authLoading, navigate, invitationId]);

  useEffect(() => {
    if (!user || !invitationId) return;
    let cancelled = false;
    setLoadingInvitation(true);
    setLoadError(null);
    api.getInvitation(invitationId)
      .then((data) => {
        if (!cancelled) setInvitation(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setLoadError(err?.message || 'Failed to load invitation');
      })
      .finally(() => {
        if (!cancelled) setLoadingInvitation(false);
      });
    return () => { cancelled = true; };
  }, [user, invitationId]);

  const handleAccept = async () => {
    if (!invitation || accepting || declining) return;
    setAccepting(true);
    try {
      await api.acceptInvitation(invitation.organization_id, invitation.id);
      toast({
        title: 'Joined',
        description: `You're now a member of ${invitation.organization_name}.`,
      });
      navigate(`/organizations/${invitation.organization_id}`, { replace: true });
    } catch (err: any) {
      toast({
        title: 'Failed to accept invitation',
        description: err?.message || 'Please try again.',
        variant: 'destructive',
      });
      setAccepting(false);
    }
  };

  const handleDecline = async () => {
    if (!invitation || declining || accepting) return;
    setDeclining(true);
    try {
      await api.declineInvitation(invitation.organization_id, invitation.id);
      toast({ title: 'Invitation declined' });
      navigate('/organizations', { replace: true });
    } catch (err: any) {
      toast({
        title: 'Failed to decline invitation',
        description: err?.message || 'Please try again.',
        variant: 'destructive',
      });
      setDeclining(false);
    }
  };

  // Waiting on auth or being bounced to /login.
  if (authLoading || !user) {
    return (
      <div className="min-h-screen bg-background">
        <Toaster position="bottom-right" />
      </div>
    );
  }

  if (loadingInvitation) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-foreground-secondary" />
        <Toaster position="bottom-right" />
      </div>
    );
  }

  if (loadError || !invitation) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center px-4">
        <div className="w-full max-w-md rounded-xl border border-border bg-background-card-header p-6 text-center">
          <div className="inline-flex items-center justify-center w-10 h-10 rounded-lg border border-foreground/15 bg-background-subtle/50 text-foreground-secondary mb-3">
            <Mail className="h-5 w-5" />
          </div>
          <h1 className="text-base font-semibold text-foreground mb-1">
            {loadError === 'Invitation has expired' ? 'Invitation expired' : 'Invitation unavailable'}
          </h1>
          <p className="text-sm text-foreground-secondary mb-4">
            {loadError || 'This invitation may have already been used or is no longer valid.'}
          </p>
          <Button variant="white" onClick={() => navigate('/organizations', { replace: true })}>
            Go to organizations
          </Button>
        </div>
        <Toaster position="bottom-right" />
      </div>
    );
  }

  const isWrongEmail = !!user.email && invitation.email.toLowerCase() !== user.email.toLowerCase();
  const badgeColor =
    invitation.role_color
    || DEFAULT_ROLE_COLORS[invitation.role.toLowerCase()]
    || null;

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      <div className="w-full max-w-md rounded-xl border border-border bg-background-card-header overflow-hidden">
        <div className="p-6 flex flex-col items-center text-center">
          <OrgAvatar
            src={invitation.organization_avatar_url}
            className="h-12 w-12 rounded-full object-cover bg-transparent border border-border mb-3 flex-shrink-0"
          />
          <h1 className="text-base font-semibold text-foreground mb-1">
            You&apos;ve been invited to join
          </h1>
          <p className="text-sm text-foreground mb-3">
            <span className="font-medium">{invitation.organization_name}</span>
          </p>
          <RoleBadge
            role={invitation.role}
            roleDisplayName={invitation.role_display_name}
            roleColor={badgeColor}
          />
          {isWrongEmail && (
            <p className="text-xs text-error mt-4">
              This invitation is for <span className="font-medium">{invitation.email}</span>. You&apos;re signed in as <span className="font-medium">{user.email}</span>.
            </p>
          )}
        </div>
        <div className="px-6 py-4 bg-background border-t border-border flex items-center justify-between">
          <Button
            variant="outline"
            className="!h-8 !px-3 !rounded-lg relative"
            onClick={handleDecline}
            disabled={declining || accepting || isWrongEmail}
          >
            {declining ? (
              <>
                <span className="invisible">Decline</span>
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-4 w-4 animate-spin" />
                </span>
              </>
            ) : (
              'Decline'
            )}
          </Button>
          <Button
            variant="green"
            onClick={handleAccept}
            disabled={accepting || declining || isWrongEmail}
          >
            {accepting ? (
              <>
                <span className="invisible">Accept</span>
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-4 w-4 animate-spin" />
                </span>
              </>
            ) : (
              'Accept'
            )}
          </Button>
        </div>
      </div>
      <Toaster position="bottom-right" />
    </div>
  );
}
