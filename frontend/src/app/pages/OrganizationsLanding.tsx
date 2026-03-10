import { useState, useEffect } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Avatar, AvatarFallback, AvatarImage } from '../../components/ui/avatar';
import { api, Organization, OrganizationInvitation } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';
import { Loader2 } from 'lucide-react';

/**
 * Landing at /organizations: redirects to default org or shows empty state.
 * Replaces the former organizations list page.
 */
export default function OrganizationsLanding() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [defaultOrgId, setDefaultOrgId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [createName, setCreateName] = useState('');
  const [creating, setCreating] = useState(false);
  const [acceptingId, setAcceptingId] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const { toast } = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [orgsData, profile, invitationsData] = await Promise.all([
          api.getOrganizations(),
          api.getUserProfile().catch(() => ({ default_organization_id: null as string | null })),
          api.getInvitations(),
        ]);

        if (cancelled) return;

        setOrganizations(orgsData);
        setInvitations(invitationsData);

        if (orgsData.length === 0) {
          setLoading(false);
          return;
        }

        const profileDefault = profile?.default_organization_id ?? null;
        const validDefault =
          profileDefault && orgsData.some((o) => o.id === profileDefault)
            ? profileDefault
            : orgsData[0].id;

        setDefaultOrgId(validDefault);

        orgsData.forEach((org) => {
          if (org.id && org.role) {
            localStorage.setItem(`org_role_${org.id}`, org.role);
            if (org.permissions) {
              localStorage.setItem(`org_permissions_${org.id}`, JSON.stringify(org.permissions));
            }
          }
        });
      } catch (error: any) {
        if (!cancelled) {
          toast({
            title: 'Error',
            description: error.message || 'Failed to load',
            variant: 'destructive',
          });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [toast]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createName.trim() || creating) return;
    setCreateError(null);
    setCreating(true);
    try {
      const org = await api.createOrganization(createName.trim());
      try {
        await api.updateUserProfile({ default_organization_id: org.id });
      } catch {
        // Non-blocking
      }
      navigate(`/organizations/${org.id}`, { replace: true });
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create organization');
    } finally {
      setCreating(false);
    }
  };

  const handleAcceptInvitation = async (inv: OrganizationInvitation) => {
    setAcceptingId(inv.id);
    try {
      const result = await api.acceptInvitation(inv.organization_id, inv.id);
      try {
        await api.updateUserProfile({ default_organization_id: result.organization_id });
      } catch {
        // Non-blocking
      }
      navigate(`/organizations/${result.organization_id}`, { replace: true });
    } catch (err: any) {
      toast({
        title: 'Error',
        description: err.message || 'Failed to accept invitation',
        variant: 'destructive',
      });
    } finally {
      setAcceptingId(null);
    }
  };

  // Loading: show nothing (no spinner, no header)
  if (loading) {
    return (
      <div className="min-h-screen bg-background">
        <Toaster position="bottom-right" />
      </div>
    );
  }

  if (organizations.length >= 1 && defaultOrgId) {
    return <Navigate to={`/organizations/${defaultOrgId}`} replace />;
  }

  const pendingInvites = invitations.filter((i) => (i.status || '').toLowerCase() === 'pending');

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        {/* Create organization card — org-settings style */}
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 bg-background-card-header">
            <h1 className="text-base font-semibold text-foreground">
              Create your first organization
            </h1>
            <p className="text-sm text-foreground-secondary mt-0.5">
              Organizations help you manage projects, teams, and security in one place.
            </p>
          </div>
          <form onSubmit={handleCreate}>
            <div className="p-6">
              <div>
                <label htmlFor="org-name" className="block text-sm font-medium text-foreground mb-1.5">
                  Name
                </label>
                <Input
                  id="org-name"
                  type="text"
                  value={createName}
                  onChange={(e) => {
                    setCreateName(e.target.value);
                    setCreateError(null);
                  }}
                  className="bg-background border-border text-foreground placeholder:text-foreground-secondary"
                  autoFocus
                  disabled={creating}
                />
              </div>
              {createError && (
                <p className="text-sm text-error mt-2">{createError}</p>
              )}
            </div>
            <div className="px-4 py-3 border-t border-border bg-black/20 flex justify-end">
              <Button
                type="submit"
                disabled={creating || !createName.trim()}
                size="sm"
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20"
              >
                {creating ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                ) : null}
                Create organization
              </Button>
            </div>
          </form>
        </div>

        {/* Invitations card — separate, with org avatars */}
        {pendingInvites.length > 0 && (
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h2 className="text-base font-semibold text-foreground">
                You&apos;ve also been invited to
              </h2>
              <p className="text-sm text-foreground-secondary mt-0.5">
                Accept to join these organizations
              </p>
            </div>
            <ul className="divide-y divide-border">
              {pendingInvites.map((inv) => (
                <li
                  key={inv.id}
                  className="flex items-center gap-3 px-4 py-3 bg-background-card"
                >
                  <Avatar className="h-9 w-9 shrink-0 overflow-hidden rounded-full border-0 bg-transparent">
                    <AvatarImage src={inv.organization_avatar_url ?? undefined} alt="" />
                    <AvatarFallback className="text-xs text-foreground-secondary bg-background-subtle/20">
                      {(inv.organization_name || 'O').slice(0, 2).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <span className="text-sm text-foreground flex-1 min-w-0 truncate">
                    {inv.organization_name || 'Organization'}
                  </span>
                  <Button
                    size="sm"
                    className="flex-shrink-0 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20"
                    disabled={acceptingId !== null}
                    onClick={() => handleAcceptInvitation(inv)}
                  >
                    {acceptingId === inv.id && (
                      <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                    )}
                    Accept
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <Toaster position="bottom-right" />
    </div>
  );
}
