import { useState, useEffect } from 'react';
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
import { Edit2, Loader2, Trash2 } from 'lucide-react';
import { getAvatarUrl, getDisplayNameOrNull } from '../../lib/userIdentity';

const NO_DEFAULT_ORG = '__none__';

export default function AccountSettingsPage() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const isConnectedAccounts = pathname.endsWith('connected-accounts');
  const { user, signInWithGitHub, signInWithGoogle, signOut } = useAuth();
  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const avatarUrl = getAvatarUrl(user);
  const fullName = getDisplayNameOrNull(user);

  const [displayName, setDisplayName] = useState(fullName || '');
  const [pendingAvatarFile, setPendingAvatarFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [savingGeneral, setSavingGeneral] = useState(false);
  const [integrations, setIntegrations] = useState<Record<string, boolean>>({
    github: false,
    google: false,
  });

  const [organizations, setOrganizations] = useState<Organization[] | null>(null);
  const [defaultOrgId, setDefaultOrgId] = useState<string | null>(null);
  const [pendingDefaultOrgId, setPendingDefaultOrgId] = useState<string | null>(null);
  const [savingDefaultOrg, setSavingDefaultOrg] = useState(false);

  const isDefaultOrgDirty = pendingDefaultOrgId !== defaultOrgId;
  const canSaveDefaultOrg = !savingDefaultOrg && organizations !== null && isDefaultOrgDirty;

  const [emailEditing, setEmailEditing] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [savingEmail, setSavingEmail] = useState(false);

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmInput, setDeleteConfirmInput] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [deleteBlockedOrgs, setDeleteBlockedOrgs] = useState<{ id: string; name: string }[] | null>(null);

  // Supabase exposes a pending email change as `new_email` on the user object
  // until the new address is confirmed. Treat it as the source of truth for
  // the "verification pending" state.
  const pendingEmail = (user as unknown as { new_email?: string } | null)?.new_email ?? null;
  const emailVerified = !!user?.email_confirmed_at;

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

  useEffect(() => {
    const integrationMap: Record<string, boolean> = { github: false, google: false };
    user?.identities?.forEach((identity) => {
      if (identity.provider === 'github') integrationMap.github = true;
      else if (identity.provider === 'google') integrationMap.google = true;
    });
    setIntegrations(integrationMap);
  }, [user]);

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
        setDefaultOrgId(profile.default_organization_id);
        setPendingDefaultOrgId(profile.default_organization_id);
      } catch (error) {
        console.error('Failed to load organizations / default org:', error);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const handleSelectDefaultOrg = (value: string) => {
    setPendingDefaultOrgId(value === NO_DEFAULT_ORG ? null : value);
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

  useEffect(() => {
    const connected = searchParams.get('connected');
    const error = searchParams.get('error');
    const message = searchParams.get('message');

    if (connected) {
      toast({
        title: 'Connected',
        description: `${connected.charAt(0).toUpperCase() + connected.slice(1)} has been connected successfully.`,
      });
      setSearchParams({});
    } else if (error) {
      toast({
        title: 'Connection failed',
        description: message || `Failed to connect ${error}.`,
        variant: 'destructive',
      });
      setSearchParams({});
    }
  }, [searchParams, toast, setSearchParams]);

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

  const handleStartEmailEdit = () => {
    setNewEmail(user?.email ?? '');
    setEmailEditing(true);
  };

  const handleCancelEmailEdit = () => {
    setEmailEditing(false);
    setNewEmail('');
  };

  const handleSaveEmail = async () => {
    if (savingEmail) return;
    const trimmed = newEmail.trim();
    if (!trimmed || !trimmed.includes('@')) {
      toast({
        title: 'Invalid email',
        description: 'Please enter a valid email address.',
        variant: 'destructive',
      });
      return;
    }
    if (trimmed.toLowerCase() === (user?.email ?? '').toLowerCase()) {
      handleCancelEmailEdit();
      return;
    }

    setSavingEmail(true);
    try {
      const { error } = await supabase.auth.updateUser({ email: trimmed });
      if (error) throw error;
      toast({
        title: 'Verification sent',
        description: `Check ${trimmed} for a confirmation link to complete the change.`,
      });
      handleCancelEmailEdit();
    } catch (error) {
      console.error('Error updating email:', error);
      toast({
        title: 'Could not change email',
        description: 'Please try again or contact support.',
        variant: 'destructive',
      });
    } finally {
      setSavingEmail(false);
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
      if (provider === 'github') {
        await signInWithGitHub();
      } else if (provider === 'google') {
        await signInWithGoogle();
      }
    } catch (error) {
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
                        className="w-full px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
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
                        <img
                          src={previewUrl || avatarUrl}
                          alt={user?.email || 'User'}
                          className="h-20 w-20 rounded-full object-cover border-2 border-border group-hover:border-primary/50 transition-all shadow-lg"
                          onError={(e) => {
                            e.currentTarget.src = '/images/blank_profile_image.png';
                          }}
                        />
                        {savingGeneral && isAvatarPending ? (
                          <div className="absolute inset-0 rounded-full bg-black/60 flex items-center justify-center">
                            <span className="animate-spin h-6 w-6 border-2 border-white border-t-transparent rounded-full" />
                          </div>
                        ) : (
                          <div className="absolute inset-0 rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                            <Edit2 className="h-5 w-5 text-white" />
                          </div>
                        )}
                      </div>
                    </label>
                  </div>
                </div>
              </div>
              <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                <p className="text-xs text-foreground-secondary">
                  Please use 32 characters at maximum.
                </p>
                <Button
                  onClick={handleSaveGeneral}
                  disabled={!canSave}
                  size="sm"
                  className="h-8 min-w-[64px] bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {savingGeneral ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Save'}
                </Button>
              </div>
            </div>

            {/* Email Card */}
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <div className="p-6 space-y-3">
                <h3 className="text-base font-semibold text-foreground">Email</h3>
                <p className="text-sm text-foreground-secondary">
                  Used for sign-in and notifications. Changing it requires confirming the new address.
                </p>

                {!emailEditing ? (
                  <div className="flex items-center gap-3 max-w-md">
                    <div className="flex-1 min-w-0 px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm text-foreground truncate">
                      {user?.email ?? '—'}
                    </div>
                    {emailVerified && (
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/20 flex-shrink-0">
                        Verified
                      </span>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={handleStartEmailEdit}
                      className="h-9 flex-shrink-0"
                    >
                      Change
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 max-w-md">
                    <input
                      type="email"
                      value={newEmail}
                      onChange={(e) => setNewEmail(e.target.value)}
                      placeholder="new@example.com"
                      autoFocus
                      className="flex-1 min-w-0 px-3 py-2 bg-black/20 border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                    />
                    <Button
                      size="sm"
                      onClick={handleSaveEmail}
                      disabled={savingEmail || newEmail.trim().length === 0}
                      className="h-9 bg-primary text-primary-foreground hover:bg-primary/90"
                    >
                      {savingEmail ? 'Sending...' : 'Send link'}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={handleCancelEmailEdit}
                      disabled={savingEmail}
                      className="h-9"
                    >
                      Cancel
                    </Button>
                  </div>
                )}

                {pendingEmail && pendingEmail !== user?.email && (
                  <p className="text-xs text-foreground-secondary">
                    Verification pending for <span className="text-foreground font-medium">{pendingEmail}</span>. Click the link in your inbox to complete the change.
                  </p>
                )}
              </div>
            </div>

            {/* Default Organization Card */}
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <div className="p-6 space-y-3">
                <h3 className="text-base font-semibold text-foreground">Default Organization</h3>
                <p className="text-sm text-foreground-secondary">
                  When you open Deptex, you'll land in this organization. Pick "No default" to land on the org switcher instead.
                </p>
                <div className="max-w-md">
                  <Select
                    value={pendingDefaultOrgId ?? NO_DEFAULT_ORG}
                    onValueChange={handleSelectDefaultOrg}
                    disabled={savingDefaultOrg || organizations === null}
                  >
                    <SelectTrigger className="w-full h-10 bg-black/20 border-border [&>span]:flex [&>span]:items-center [&>span]:gap-2 [&>span]:min-w-0 [&>span]:flex-1">
                      <SelectValue placeholder={organizations === null ? 'Loading...' : 'Select an organization'} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NO_DEFAULT_ORG}>
                        <span className="text-foreground-secondary">No default</span>
                      </SelectItem>
                      {organizations?.map((org) => (
                        <SelectItem key={org.id} value={org.id}>
                          <div className="flex items-center gap-2 min-w-0">
                            <img
                              src={org.avatar_url || '/images/org_profile.png'}
                              alt={org.name}
                              className="h-5 w-5 rounded-full object-cover bg-transparent flex-shrink-0"
                            />
                            <span className="truncate">{org.name}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                <p className="text-xs text-foreground-secondary">
                  Members of an org can be set as default. You can always switch in the sidebar.
                </p>
                <Button
                  onClick={handleSaveDefaultOrg}
                  disabled={!canSaveDefaultOrg}
                  size="sm"
                  className="h-8 min-w-[64px] bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {savingDefaultOrg ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Save'}
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
                      variant="outline"
                      size="sm"
                      className="flex-shrink-0 h-8 border-destructive/50 text-destructive hover:bg-destructive/10 hover:border-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5 mr-2" />
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
                            size="sm"
                            disabled={
                              deleting ||
                              !user?.email ||
                              deleteConfirmInput.trim().toLowerCase() !== user.email.toLowerCase()
                            }
                            className="h-8"
                          >
                            {deleting ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                            ) : (
                              <Trash2 className="h-3.5 w-3.5 mr-2" />
                            )}
                            Delete Forever
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
                              size="sm"
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
