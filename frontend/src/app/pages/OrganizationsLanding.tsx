import { useState, useEffect } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Button } from '../../components/ui/button';
import { api, Organization, OrganizationInvitation } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';
import { Loader2, X } from 'lucide-react';
import { OrgAvatar } from '../../components/Avatar';

/**
 * Landing at /organizations: redirects to default org or shows empty state.
 * Replaces the former organizations list page.
 */
export default function OrganizationsLanding() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [defaultOrgId, setDefaultOrgId] = useState<string | null>(
    () => localStorage.getItem('deptex_default_org')
  );
  const [loading, setLoading] = useState(
    () => localStorage.getItem('deptex_default_org') === null
  );
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [createName, setCreateName] = useState('');
  const [creating, setCreating] = useState(false);
  const [acceptingId, setAcceptingId] = useState<string | null>(null);
  const [decliningId, setDecliningId] = useState<string | null>(null);
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
        localStorage.setItem('deptex_default_org', validDefault);

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
      navigate(`/organizations/${org.id}`, { replace: true });
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create organization');
    } finally {
      setCreating(false);
    }
  };

  const handleAcceptInvitation = async (inv: OrganizationInvitation) => {
    if (acceptingId || decliningId) return;
    setAcceptingId(inv.id);
    try {
      const result = await api.acceptInvitation(inv.organization_id, inv.id);
      navigate(`/organizations/${result.organization_id}`, { replace: true });
    } catch (err: any) {
      toast({
        title: 'Error',
        description: err.message || 'Failed to accept invitation',
        variant: 'destructive',
      });
      setAcceptingId(null);
    }
  };

  const handleDeclineInvitation = async (inv: OrganizationInvitation) => {
    if (decliningId || acceptingId) return;
    setDecliningId(inv.id);
    try {
      await api.declineInvitation(inv.organization_id, inv.id);
      setInvitations((prev) => prev.filter((i) => i.id !== inv.id));
    } catch (err: any) {
      toast({
        title: 'Failed to decline invitation',
        description: err.message || 'Please try again.',
        variant: 'destructive',
      });
    } finally {
      setDecliningId(null);
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

  // After OAuth provider linking, redirect back to connected-accounts with the
  // toast param. Cleared by AccountSettingsPage when the toast fires (not here,
  // because StrictMode double-renders and would clear before commit).
  const pendingConnect = sessionStorage.getItem('deptex_connect_return');
  if (pendingConnect && defaultOrgId) {
    return (
      <Navigate
        to={`/organizations/${defaultOrgId}/account/connected-accounts?connected=${pendingConnect}`}
        replace
      />
    );
  }

  if (defaultOrgId) {
    return <Navigate to={`/organizations/${defaultOrgId}`} replace />;
  }

  const pendingInvites = invitations.filter((i) => (i.status || '').toLowerCase() === 'pending');

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        {/* Create organization card — matches CreateOrganizationModal two-tone */}
        <div className="rounded-xl border border-border bg-background-card-header overflow-hidden">
          <div className="px-6 pt-6 pb-4">
            <h1 className="text-base font-semibold text-foreground">
              Create your first organization
            </h1>
            <p className="text-sm text-foreground-secondary mt-1">
              Organizations help you manage projects, teams, and security in one place.
            </p>
          </div>
          <form onSubmit={handleCreate}>
            <div className="px-6 py-4">
              <label htmlFor="org-name" className="block text-sm font-medium text-foreground mb-2">
                Organization Name
              </label>
              <input
                id="org-name"
                type="text"
                value={createName}
                onChange={(e) => {
                  setCreateName(e.target.value);
                  setCreateError(null);
                }}
                maxLength={32}
                className="w-full px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
                autoFocus
                disabled={creating}
              />
              {createError && (
                <p className="text-sm text-error mt-2">{createError}</p>
              )}
            </div>
            <div className="px-6 py-4 bg-background border-t border-border flex items-center justify-end">
              <Button
                type="submit"
                variant="green"
                disabled={creating || !createName.trim()}
              >
                {creating ? (
                  <>
                    <span className="invisible">Create organization</span>
                    <span className="absolute inset-0 flex items-center justify-center">
                      <Loader2 className="h-4 w-4 animate-spin" />
                    </span>
                  </>
                ) : (
                  'Create organization'
                )}
              </Button>
            </div>
          </form>
        </div>

        {/* Invitations card */}
        {pendingInvites.length > 0 && (
          <div className="rounded-xl border border-border bg-background-card-header overflow-hidden">
            <div className="px-6 py-4 bg-background border-b border-border">
              <h2 className="text-sm font-semibold text-foreground">
                Pending invitations
              </h2>
            </div>
            <ul className="divide-y divide-border">
              {pendingInvites.map((inv) => (
                <li
                  key={inv.id}
                  className="flex items-center gap-3 px-6 py-3"
                >
                  <OrgAvatar
                    src={inv.organization_avatar_url}
                    className="h-8 w-8 rounded-full object-cover bg-transparent flex-shrink-0"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-foreground truncate">
                      {inv.organization_name || 'Organization'}
                    </div>
                    <div className="text-xs text-foreground-secondary capitalize">
                      Invited as {inv.role}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDeclineInvitation(inv)}
                    disabled={decliningId === inv.id || acceptingId !== null}
                    aria-label="Decline invitation"
                    className="inline-flex items-center justify-center h-7 w-7 rounded-lg border border-foreground/15 text-foreground-secondary hover:text-foreground hover:bg-background-subtle/85 transition-colors disabled:opacity-50 flex-shrink-0"
                  >
                    {decliningId === inv.id ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <X className="h-3.5 w-3.5" />
                    )}
                  </button>
                  <Button
                    variant="green"
                    onClick={() => handleAcceptInvitation(inv)}
                    disabled={acceptingId !== null || decliningId !== null}
                    className="!h-7 !px-2.5 !text-xs flex-shrink-0"
                  >
                    {acceptingId === inv.id ? (
                      <>
                        <span className="invisible">Accept</span>
                        <span className="absolute inset-0 flex items-center justify-center">
                          <Loader2 className="h-3 w-3 animate-spin" />
                        </span>
                      </>
                    ) : (
                      'Accept'
                    )}
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
