import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import AppHeader from '../../components/AppHeader';
import SettingsSidebar from '../../components/SettingsSidebar';
import { Button } from '../../components/ui/button';
import { Toaster } from '../../components/ui/toaster';
import { useToast } from '../../hooks/use-toast';
import { Save, Edit2 } from 'lucide-react';
import { api } from '../../lib/api';
import { useSearchParams, useLocation } from 'react-router-dom';
import { supabase } from '../../lib/supabase';

export default function SettingsPage() {
  const { pathname } = useLocation();
  const isConnectedAccounts = pathname === '/settings/general/connected-accounts';
  const { user, signInWithGitHub, signInWithGoogle } = useAuth();
  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  // Use the hook to get profile data (with caching - no flash!)
  const { avatarUrl, fullName } = useUserProfile();
  
  const [displayName, setDisplayName] = useState(fullName || user?.user_metadata?.full_name || '');
  const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);
  const [integrations, setIntegrations] = useState<Record<string, boolean>>({
    github: false,
    google: false,
  });

  // Sync display name from hook
  useEffect(() => {
    if (fullName) {
      setDisplayName(fullName);
    }
  }, [fullName]);

  // Load integrations on mount and check GitHub login
  useEffect(() => {
    loadIntegrations();
    // Check if user logged in with GitHub via Supabase
    if (user?.identities?.some((identity: any) => identity.provider === 'github')) {
      setIntegrations(prev => ({ ...prev, github: true }));
    }
    // Check and restore avatar if missing from metadata but exists in storage
    checkAndRestoreAvatar();
  }, [user]);

  // Check if avatar exists in storage but is missing from profile, and restore it
  const checkAndRestoreAvatar = async () => {
    if (!user?.id) return;
    
    try {
      // Check if profile already has avatar_url
      const profile = await api.getUserProfile();
      if (profile.avatar_url) return;
      
      // List files in the user's avatar folder
      const { data: files, error } = await supabase.storage
        .from('avatars')
        .list(user.id, {
          limit: 1,
          sortBy: { column: 'created_at', order: 'desc' }
        });
      
      if (error) {
        console.error('Error checking avatar storage:', error);
        return;
      }
      
      // If we found a file, restore the avatar_url in profile
      if (files && files.length > 0) {
        const filePath = `${user.id}/${files[0].name}`;
        const { data: { publicUrl } } = supabase.storage
          .from('avatars')
          .getPublicUrl(filePath);
        
        // Update user profile with the restored avatar URL
        await api.updateUserProfile({ avatar_url: publicUrl });
        console.log('Avatar restored from storage');
      }
    } catch (error) {
      console.error('Error in checkAndRestoreAvatar:', error);
    }
  };
  
  // Handle OAuth callback
  useEffect(() => {
    const connected = searchParams.get('connected');
    const error = searchParams.get('error');
    const message = searchParams.get('message');

      if (connected) {
        toast({
          title: 'Connected',
          description: `${connected.charAt(0).toUpperCase() + connected.slice(1)} has been connected successfully.`,
        });
        loadIntegrations();
        // Clean up URL
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

  const loadIntegrations = async () => {
    try {
      // For user settings, we only care about login providers (GitHub, Google)
      // Check if user logged in with these providers via Supabase
      const integrationMap: Record<string, boolean> = {
        github: false,
        google: false,
      };
      
      // Check identities from Supabase Auth
      if (user?.identities) {
        user.identities.forEach((identity: any) => {
          if (identity.provider === 'github') {
            integrationMap.github = true;
          } else if (identity.provider === 'google') {
            integrationMap.google = true;
          }
        });
      }
      
      setIntegrations(integrationMap);
    } catch (error: any) {
      console.error('Failed to load integrations:', error);
    }
  };

  const handleSaveGeneral = () => {
    // TODO: Implement API call to save settings
    toast({
      title: 'Settings saved',
      description: 'Your general settings have been updated.',
    });
  };

  const handleConnectProvider = async (provider: 'github' | 'google') => {
    try {
      if (provider === 'github') {
        await signInWithGitHub();
      } else if (provider === 'google') {
        await signInWithGoogle();
      }
      // The OAuth flow will redirect, so we don't need to do anything else here
    } catch (error: any) {
      toast({
        title: 'Connection failed',
        description: error.message || `Failed to connect ${provider}. Please try again.`,
        variant: 'destructive',
      });
    }
  };



  const integrationList = [
    { id: 'github', name: 'GitHub', image: '/images/integrations/github.png', description: 'Use GitHub to sign in to your account' },
    { id: 'google', name: 'Google', image: '/images/integrations/google.png', description: 'Use Google to sign in to your account' },
  ];

  return (
    <>
      <div className="min-h-screen bg-background">
        <AppHeader
          breadcrumb={[{ label: 'Settings' }]}
          showSearch={false}
          showNewOrg={false}
        />

        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex gap-8">
            {/* Sidebar */}
            <SettingsSidebar />

            {/* Content */}
            <div className="flex-1">
              {!isConnectedAccounts && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground">General</h2>
                    <p className="text-foreground-secondary mt-1">
                      Manage your profile and account settings.
                    </p>
                  </div>

                  {/* Profile Card: Display Name + Avatar */}
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
                              className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                            />
                          </div>
                        </div>
                        <div className="flex-shrink-0 sm:justify-self-end self-end">
                          <input
                            type="file"
                            accept="image/*"
                            className="hidden"
                            id="avatar-upload"
                            onChange={async (e) => {
                              const file = e.target.files?.[0];
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
                              
                              try {
                                setIsUploadingAvatar(true);
                                const fileExt = file.name.split('.').pop();
                                const fileName = `${user?.id}-${Date.now()}.${fileExt}`;
                                const filePath = `${user?.id}/${fileName}`;
                                
                                const { error: uploadError } = await supabase.storage
                                  .from('avatars')
                                  .upload(filePath, file, {
                                    cacheControl: '3600',
                                    upsert: true,
                                  });
                                
                                if (uploadError) throw uploadError;
                                
                                const { data: { publicUrl } } = supabase.storage
                                  .from('avatars')
                                  .getPublicUrl(filePath);
                                
                                await api.updateUserProfile({ avatar_url: publicUrl });
                                
                                if (user?.id) {
                                  localStorage.removeItem(`user_profile_${user.id}`);
                                }
                                
                                await new Promise<void>((resolve) => {
                                  const img = new Image();
                                  img.onload = () => resolve();
                                  img.onerror = () => resolve();
                                  img.src = publicUrl;
                                });
                                
                                toast({
                                  title: 'Avatar updated',
                                  description: 'Your avatar has been updated successfully.',
                                });
                                
                                window.location.reload();
                              } catch (error: any) {
                                console.error('Error uploading avatar:', error);
                                setIsUploadingAvatar(false);
                                toast({
                                  title: 'Upload failed',
                                  description: error.message || 'Failed to upload avatar. Please try again.',
                                  variant: 'destructive',
                                });
                              }
                              
                              e.target.value = '';
                            }}
                          />
                          <label htmlFor="avatar-upload" className={`cursor-pointer block group ${isUploadingAvatar ? 'pointer-events-none' : ''}`}>
                            <div className="relative">
                              <img
                                src={avatarUrl}
                                alt={user?.email || 'User'}
                                className="h-20 w-20 rounded-full object-cover border-2 border-border group-hover:border-primary/50 transition-all shadow-lg"
                                onError={(e) => {
                                  e.currentTarget.src = '/images/blank_profile_image.png';
                                }}
                              />
                              {isUploadingAvatar ? (
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
                        size="sm"
                        className="h-8 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                      >
                        Save
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
        </div>
      </div>
      
      <Toaster position="bottom-right" />
    </>
  );
}


