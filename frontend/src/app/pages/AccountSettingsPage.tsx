import { useState, useEffect, useMemo } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { supabase } from '../../lib/supabase';
import { api, Organization } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { Edit2, Loader2 } from 'lucide-react';
import { getAvatarUrl, getDisplayNameOrNull } from '../../lib/userIdentity';
import { Skeleton } from '../../components/ui/skeleton';
import { UserAvatar, OrgAvatar } from '../../components/Avatar';

export default function AccountSettingsPage() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const isConnectedAccounts = pathname.endsWith('connected-accounts');
  const { user, signOut } = useAuth();
  const { toast } = useToast();
  const [, setSearchParams] = useSearchParams();
  const avatarUrl = getAvatarUrl(user);
  const fullName = getDisplayNameOrNull(user);

  const [displayName, setDisplayName] = useState(fullName || '');
  const [pendingAvatarFile, setPendingAvatarFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [savingGeneral, setSavingGeneral] = useState(false);
  // Derived from user.identities, with a per-user localStorage cache so revisits
  // don't flash the Connect button while AuthContext refreshes the session.
  const integrations = useMemo<Record<string, boolean>>(() => {
    const map: Record<string, boolean> = { github: false, google: false };
    const fromUser = user?.identities;
    if (fromUser && fromUser.length > 0) {
      fromUser.forEach((identity) => {
        if (identity.provider === 'github') map.github = true;
        else if (identity.provider === 'google') map.google = true;
      });
      if (user?.id) {
        try { localStorage.setItem(`deptex_integrations_${user.id}`, JSON.stringify(map)); } catch {}
      }
      return map;
    }
    if (user?.id) {
      try {
        const cached = localStorage.getItem(`deptex_integrations_${user.id}`);
        if (cached) return JSON.parse(cached);
      } catch {}
    }
    return map;
  }, [user]);

  const [organizations, setOrganizations] = useState<Organization[] | null>(null);
  const [defaultOrgId, setDefaultOrgId] = useState<string | null>(null);
  const [pendingDefaultOrgId, setPendingDefaultOrgId] = useState<string | null>(null);
  const [savingDefaultOrg, setSavingDefaultOrg] = useState(false);

  const isDefaultOrgDirty = pendingDefaultOrgId !== defaultOrgId;
  const canSaveDefaultOrg = !savingDefaultOrg && organizations !== null && isDefaultOrgDirty;

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmInput, setDeleteConfirmInput] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [deleteBlockedOrgs, setDeleteBlockedOrgs] = useState<{ id: string; name: string }[] | null>(null);

  const trimmedName = displayName.trim();
  const currentName = (fullName || '').trim();
  const isNameInvalid = trimmedName.length === 0 || trimmedName.length > 32;
  const isNameUnchanged = trimmedName === currentName;
  const isAvatarPending = pendingAvatarFile !== null;
  const hasPendingChange = !isNameUnchanged || isAvatarPending;
  const canSave = !savingGeneral && !isNameInvalid && hasPendingChange;

  useEffect(() => {
    if (!previewUrl) return;
    return () => URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  useEffect(() => {
    const prev = document.title;
    document.title = 'Account Settings | Deptex';
    return () => {
      document.title = prev;
    };
  }, []);

  // Re-sync the input when the live name changes (e.g., after our own save
  // propagates through onAuthStateChange, or after OAuth re-login).
  useEffect(() => {
    if (fullName) {
      setDisplayName(fullName);
    }
  }, [fullName]);

  // Load the user's orgs + current default for the picker. Failures are
  // non-fatal — the card just won't render until orgs resolve.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [orgs, profile] = await Promise.all([
          api.getOrganizations(),
          api.getUserProfile(),
        ]);
        if (cancelled) return;
        setOrganizations(orgs);
        // If no explicit default is set, treat the first joined org as the
        // effective default so the Save button stays inactive until the user
        // actually picks something different.
        const effectiveDefault = profile.default_organization_id ?? (orgs[0]?.id ?? null);
        setDefaultOrgId(effectiveDefault);
        setPendingDefaultOrgId(effectiveDefault);
      } catch (error) {
        console.error('Failed to load organizations / default org:', error);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const handleSelectDefaultOrg = (value: string) => {
    setPendingDefaultOrgId(value);
  };

  const handleSaveDefaultOrg = async () => {
    if (!canSaveDefaultOrg) return;

    const previous = defaultOrgId;
    setSavingDefaultOrg(true);
    try {
      await api.updateUserProfile({ default_organization_id: pendingDefaultOrgId });
      setDefaultOrgId(pendingDefaultOrgId);
      // Keep the localStorage cache in sync so SettingsRedirect + the
      // OrganizationsLanding fast-path see the new default without a refetch.
      if (pendingDefaultOrgId) {
        localStorage.setItem('deptex_default_org', pendingDefaultOrgId);
      } else {
        localStorage.removeItem('deptex_default_org');
      }
      toast({
        title: 'Default organization updated',
        description: pendingDefaultOrgId
          ? 'You will land here next time you open Deptex.'
          : 'Your default organization has been cleared.',
      });
    } catch (error) {
      console.error('Failed to update default organization:', error);
      setPendingDefaultOrgId(previous);
      toast({
        title: 'Update failed',
        description: 'Could not update your default organization. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setSavingDefaultOrg(false);
    }
  };

  // After linkIdentity OAuth, the cached session still has the old identities
  // until refreshed. Force a refresh so the Connected badge picks up the new
  // provider, and clean up the URL param.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const connected = params.get('connected');
    if (!connected) return;
    sessionStorage.removeItem('deptex_connect_return');
    supabase.auth.refreshSession();
    setSearchParams({}, { replace: true });
  }, [setSearchParams]);

  const handleAvatarSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: 'File too large',
        description: 'Please upload an image smaller than 5MB.',
        variant: 'destructive',
      });
      return;
    }

    if (!file.type.startsWith('image/')) {
      toast({
        title: 'Invalid file type',
        description: 'Please upload an image file.',
        variant: 'destructive',
      });
      return;
    }

    setPendingAvatarFile(file);
    setPreviewUrl(URL.createObjectURL(file));
  };

  const handleSaveGeneral = async () => {
    if (!canSave) return;
    if (!isNameUnchanged && isNameInvalid) {
      toast({
        title: 'Invalid display name',
        description: trimmedName.length === 0
          ? 'Display name cannot be empty.'
          : 'Display name must be 32 characters or fewer.',
        variant: 'destructive',
      });
      return;
    }

    setSavingGeneral(true);
    let uploadedFilePath: string | null = null;
    try {
      const updates: Record<string, string> = {};
      if (!isNameUnchanged) {
        updates.custom_full_name = trimmedName;
      }

      if (pendingAvatarFile && user?.id) {
        const fileExt = pendingAvatarFile.name.split('.').pop();
        const fileName = `${user.id}-${Date.now()}.${fileExt}`;
        const filePath = `${user.id}/${fileName}`;

        const { error: uploadError } = await supabase.storage
          .from('avatars')
          .upload(filePath, pendingAvatarFile, {
            cacheControl: '3600',
            upsert: true,
          });
        if (uploadError) throw uploadError;
        uploadedFilePath = filePath;

        const { data: { publicUrl } } = supabase.storage
          .from('avatars')
          .getPublicUrl(filePath);
        updates.custom_avatar_url = publicUrl;
      }

      const { error: updateError } = await supabase.auth.updateUser({ data: updates });
      if (updateError) throw updateError;

      setPendingAvatarFile(null);
      setPreviewUrl(null);
      toast({
        title: 'Settings saved',
        description: 'Your changes have been applied.',
      });
    } catch (error) {
      console.error('Error saving settings:', error);
      // If we uploaded the avatar but the auth update failed, drop the
      // orphan file so the bucket doesn't accumulate dead uploads.
      if (uploadedFilePath) {
        await supabase.storage
          .from('avatars')
          .remove([uploadedFilePath])
          .catch((cleanupError) => {
            console.error('Failed to clean up orphaned avatar:', cleanupError);
          });
      }
      toast({
        title: 'Save failed',
        description: 'Could not save your changes. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setSavingGeneral(false);
    }
  };

  const handleOpenDeleteConfirm = () => {
    setDeleteConfirmInput('');
    setDeleteBlockedOrgs(null);
    setShowDeleteConfirm(true);
  };

  const handleCancelDelete = () => {
    if (deleting) return;
    setShowDeleteConfirm(false);
    setDeleteConfirmInput('');
    setDeleteBlockedOrgs(null);
  };

  const handleDeleteAccount = async () => {
    if (deleting) return;
    if (!user?.email || deleteConfirmInput.trim().toLowerCase() !== user.email.toLowerCase()) {
      return;
    }

    setDeleting(true);
    try {
      await api.deleteAccount();
      toast({ title: 'Account deleted', description: 'Your account has been permanently removed.' });
      await signOut();
      navigate('/');
    } catch (error: unknown) {
      console.error('Error deleting account:', error);
      const responseBody = (error as { responseBody?: { organizations?: { id: string; name: string }[] } } | null)?.responseBody;
      if (responseBody?.organizations && responseBody.organizations.length > 0) {
        setDeleteBlockedOrgs(responseBody.organizations);
      } else {
        toast({
          title: 'Could not delete account',
          description: 'Please try again or contact support.',
          variant: 'destructive',
        });
      }
    } finally {
      setDeleting(false);
    }
  };

  const handleConnectProvider = async (provider: 'github' | 'google') => {
    try {
      sessionStorage.setItem('deptex_connect_return', provider);
      const { error } = await supabase.auth.linkIdentity({
        provider,
        options: {
          redirectTo: `${window.location.origin}/organizations`,
        },
      });
      if (error) throw error;
    } catch (error) {
      sessionStorage.removeItem('deptex_connect_return');
      console.error(`Error connecting ${provider}:`, error);
      toast({
        title: 'Connection failed',
        description: `Failed to connect ${provider}. Please try again.`,
        variant: 'destructive',
      });
    }
  };

  const integrationList = [
    { id: 'github', name: 'GitHub', image: '/images/integrations/github.png', description: 'Use GitHub to sign in to your account' },
    { id: 'google', name: 'Google', image: '/images/integrations/google.png', description: 'Use Google to sign in to your account' },
  ];

  return (
    <div className="bg-background">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        {!isConnectedAccounts && (
          <div className="space-y-6">
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <div className="p-6">
                <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto] items-start gap-6">
                  <div className="space-y-3 min-w-0">
                    <h3 className="text-base font-semibold text-foreground">Display Name</h3>
                    <p className="text-sm text-foreground-secondary">
                      This is your display name. It will be shown throughout the dashboard.
                    </p>
                    <div className="max-w-md">
                      <input
                        type="text"
                        value={displayName}
                        onChange={(e) => setDisplayName(e.target.value)}
                        placeholder="Enter your display name"
                        maxLength={32}
                        className="w-full px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
                      />
                    </div>
                  </div>
                  <div className="flex-shrink-0 sm:justify-self-end self-end">
                    <input
                      type="file"
                      accept="image/*"
                      className="hidden"
                      id="avatar-upload"
                      onChange={handleAvatarSelect}
                    />
                    <label htmlFor="avatar-upload" className={`cursor-pointer block group ${savingGeneral ? 'pointer-events-none' : ''}`}>
                      <div className="relative">
                        <UserAvatar
                          src={previewUrl || avatarUrl}
                          alt={user?.email || 'User'}
                          className="h-20 w-20 rounded-full object-cover border-2 border-border group-hover:border-primary/50 transition-all shadow-lg"
                        />
                        <div className="absolute inset-0 rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                          <Edit2 className="h-5 w-5 text-white" />
                        </div>
                      </div>
                    </label>
                  </div>
                </div>
              </div>
              <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                <Button
                  onClick={handleSaveGeneral}
                  disabled={!canSave || savingGeneral}
                  variant="green"
                >
                  <span className={savingGeneral ? 'invisible' : ''}>Save</span>
                  {savingGeneral && (
                    <span className="absolute inset-0 flex items-center justify-center">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    </span>
                  )}
                </Button>
              </div>
            </div>


            {/* Default Organization Card */}
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <div className="p-6 space-y-3">
                <h3 className="text-base font-semibold text-foreground">Default Organization</h3>
                <p className="text-sm text-foreground-secondary">
                  When you open Deptex, you'll land in this organization.
                </p>
                <div className="max-w-md">
                  <Select
                    value={pendingDefaultOrgId ?? ''}
                    onValueChange={handleSelectDefaultOrg}
                    disabled={organizations === null}
                  >
                    <SelectTrigger className="w-full h-10 bg-black/20 border-border [&>span]:flex [&>span]:items-center [&>span]:gap-2 [&>span]:min-w-0 [&>span]:flex-1">
                      {organizations === null ? (
                        <div className="flex items-center gap-2.5 flex-1">
                          <Skeleton className="h-6 w-6 rounded-full flex-shrink-0" />
                          <Skeleton className="h-4 w-28" />
                        </div>
                      ) : (
                        <SelectValue placeholder="Select an organization" />
                      )}
                    </SelectTrigger>
                    <SelectContent>
                      {organizations?.map((org) => (
                        <SelectItem key={org.id} value={org.id}>
                          <div className="flex items-center gap-2.5 min-w-0">
                            <OrgAvatar
                              src={org.avatar_url}
                              alt={org.name}
                              className="h-6 w-6 rounded-full object-cover bg-transparent flex-shrink-0"
                            />
                            <span className="truncate">{org.name}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                <Button
                  onClick={handleSaveDefaultOrg}
                  disabled={!canSaveDefaultOrg || savingDefaultOrg}
                  variant="green"
                >
                  <span className={savingDefaultOrg ? 'invisible' : ''}>Save</span>
                  {savingDefaultOrg && (
                    <span className="absolute inset-0 flex items-center justify-center">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    </span>
                  )}
                </Button>
              </div>
            </div>

            {/* Danger Zone */}
            <div className="border border-destructive/30 rounded-lg overflow-hidden bg-destructive/5">
              <div className="px-6 py-3 border-b border-destructive/30 bg-destructive/10">
                <h3 className="text-sm font-semibold text-destructive uppercase tracking-wide">Danger Zone</h3>
              </div>
              <div className="p-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <h4 className="text-base font-semibold text-foreground mb-1">Delete Account</h4>
                    <p className="text-sm text-foreground-secondary">
                      Permanently delete your account and everything tied to it — profile, memberships, and per-user data. This cannot be undone.
                    </p>
                  </div>
                  {!showDeleteConfirm && (
                    <Button
                      onClick={handleOpenDeleteConfirm}
                      variant="destructive"
                      className="flex-shrink-0"
                    >
                      Delete
                    </Button>
                  )}
                </div>

                {showDeleteConfirm && (
                  <div className="mt-4 p-4 bg-background/50 rounded-lg border border-destructive/30 space-y-4">
                    {deleteBlockedOrgs && deleteBlockedOrgs.length > 0 ? (
                      <>
                        <p className="text-sm text-foreground">
                          You're the only owner of {deleteBlockedOrgs.length === 1 ? 'this organization' : 'these organizations'}:
                        </p>
                        <ul className="text-sm text-foreground-secondary list-disc list-inside space-y-1">
                          {deleteBlockedOrgs.map((org) => (
                            <li key={org.id}>{org.name}</li>
                          ))}
                        </ul>
                        <p className="text-sm text-foreground-secondary">
                          Transfer ownership or delete {deleteBlockedOrgs.length === 1 ? 'the organization' : 'them'} first, then come back here.
                        </p>
                        <div>
                          <Button onClick={handleCancelDelete} variant="ghost" size="sm" className="h-8">
                            Close
                          </Button>
                        </div>
                      </>
                    ) : (
                      <>
                        <p className="text-sm text-foreground">
                          To confirm deletion, type <strong className="text-destructive font-mono bg-destructive/10 px-1.5 py-0.5 rounded">{user?.email}</strong> below:
                        </p>
                        <input
                          type="text"
                          value={deleteConfirmInput}
                          onChange={(e) => setDeleteConfirmInput(e.target.value)}
                          placeholder={user?.email ?? ''}
                          autoFocus
                          className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-all"
                        />
                        <div className="flex gap-2">
                          <Button
                            onClick={handleDeleteAccount}
                            variant="destructive"
                            disabled={
                              deleting ||
                              !user?.email ||
                              deleteConfirmInput.trim().toLowerCase() !== user.email.toLowerCase()
                            }
                          >
                            <span className={deleting ? 'invisible' : ''}>Delete Forever</span>
                            {deleting && (
                              <span className="absolute inset-0 flex items-center justify-center">
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              </span>
                            )}
                          </Button>
                          <Button onClick={handleCancelDelete} variant="ghost" size="sm" className="h-8">
                            Cancel
                          </Button>
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {isConnectedAccounts && (
          <div className="space-y-6">
            <div>
              <h2 className="text-2xl font-bold text-foreground">Connected Accounts</h2>
              <p className="text-foreground-secondary mt-1">
                Manage your login providers. These accounts are used for authentication and sign-in only.
              </p>
            </div>

            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-background-card-header border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Provider
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Status
                    </th>
                    <th className="w-24"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {integrationList.map((integration) => {
                    const isConnected = integrations[integration.id];
                    return (
                      <tr key={integration.id} className="hover:bg-table-hover transition-colors">
                        <td className="px-4 py-3 min-w-0">
                          <div className="flex items-center gap-3 min-w-0">
                            <img
                              src={integration.image}
                              alt={integration.name}
                              className={`h-8 w-8 rounded object-contain flex-shrink-0 ${isConnected ? 'opacity-100' : 'opacity-60'}`}
                            />
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-foreground">
                                {integration.name}
                              </div>
                              <div className="text-xs text-foreground-secondary truncate">
                                {isConnected
                                  ? `You can sign in using your ${integration.name} account`
                                  : integration.description
                                }
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {isConnected ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/20">
                              Connected
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-foreground-secondary/10 text-foreground-secondary border border-foreground-secondary/20">
                              Not Connected
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {!isConnected && (
                            <Button
                              variant="white"
                              onClick={() => handleConnectProvider(integration.id as 'github' | 'google')}
                            >
                              Connect
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="p-4 bg-background-subtle/50 border border-border rounded-lg">
              <p className="text-sm text-foreground-secondary">
                <strong className="text-foreground font-medium">Note:</strong> You can add additional login methods by clicking &quot;Connect&quot; above.
                Once connected, login methods cannot be removed from this page to prevent account lockout.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
