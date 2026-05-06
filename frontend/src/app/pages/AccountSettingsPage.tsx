import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useLocation, useSearchParams } from 'react-router-dom';
import { supabase } from '../../lib/supabase';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { Edit2 } from 'lucide-react';
import { getAvatarUrl, getDisplayNameOrNull } from '../../lib/userIdentity';

export default function AccountSettingsPage() {
  const { pathname } = useLocation();
  const isConnectedAccounts = pathname.endsWith('connected-accounts');
  const { user, signInWithGitHub, signInWithGoogle } = useAuth();
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
                        className="w-full px-3 py-2.5 bg-black/20 border border-border rounded-lg text-sm text-foreground-secondary placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
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
                  className="h-8 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {savingGeneral ? 'Saving...' : 'Save'}
                </Button>
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
