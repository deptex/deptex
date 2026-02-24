import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import AppHeader from '../../components/AppHeader';
import SettingsSidebar from '../../components/SettingsSidebar';
import { Button } from '../../components/ui/button';
import { Toaster } from '../../components/ui/toaster';
import { useToast } from '../../hooks/use-toast';
import { Save, Edit2 } from 'lucide-react';
import { api, Integration } from '../../lib/api';
import { useSearchParams } from 'react-router-dom';
import { supabase } from '../../lib/supabase';

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('general');
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
  const [stripeConnected, setStripeConnected] = useState(false);

  // Sync display name from hook
  useEffect(() => {
    if (fullName) {
      setDisplayName(fullName);
    }
  }, [fullName]);

  // Load integrations on mount and check GitHub login
  useEffect(() => {
    loadIntegrations();
    loadStripeConnection();
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
  
  const loadStripeConnection = async () => {
    try {
      const data = await api.getIntegrations();
      const stripeIntegration = data.find((integration: Integration) => integration.provider === 'stripe');
      setStripeConnected(!!stripeIntegration);
    } catch (error: any) {
      console.error('Failed to load Stripe connection:', error);
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
        if (connected === 'stripe') {
          loadStripeConnection();
        }
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
            <SettingsSidebar
              activeSection={activeSection}
              onSectionChange={setActiveSection}
            />

            {/* Content */}
            <div className="flex-1">
              {activeSection === 'general' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground">General Settings</h2>
                    <p className="text-foreground-secondary mt-1">
                      Manage your profile and account settings.
                    </p>
                  </div>

                  {/* Display Name Card */}
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <div className="p-6">
                      <h3 className="text-base font-semibold text-foreground mb-1">Display Name</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
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
                    <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                      <p className="text-xs text-foreground-secondary">
                        Please use 32 characters at maximum.
                      </p>
                      <Button
                        onClick={handleSaveGeneral}
                        size="sm"
                        className="h-8"
                      >
                        Save
                      </Button>
                    </div>
                  </div>

                  {/* Avatar Card */}
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <div className="p-6">
                      <div className="flex items-start justify-between gap-6">
                        <div className="flex-1">
                          <h3 className="text-base font-semibold text-foreground mb-1">Avatar</h3>
                          <p className="text-sm text-foreground-secondary">
                            This is your avatar. Click on the avatar to upload a custom one from your files.
                          </p>
                        </div>
                        <div className="flex-shrink-0">
                          <input
                            type="file"
                            accept="image/*"
                            className="hidden"
                            id="avatar-upload"
                            onChange={async (e) => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              
                              // Validate file size (max 5MB)
                              if (file.size > 5 * 1024 * 1024) {
                                toast({
                                  title: 'File too large',
                                  description: 'Please upload an image smaller than 5MB.',
                                  variant: 'destructive',
                                });
                                return;
                              }
                              
                              // Validate file type
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
                                
                                // Create a unique filename with user ID
                                const fileExt = file.name.split('.').pop();
                                const fileName = `${user?.id}-${Date.now()}.${fileExt}`;
                                const filePath = `${user?.id}/${fileName}`;
                                
                                // Upload to Supabase Storage
                                const { error: uploadError } = await supabase.storage
                                  .from('avatars')
                                  .upload(filePath, file, {
                                    cacheControl: '3600',
                                    upsert: true,
                                  });
                                
                                if (uploadError) {
                                  throw uploadError;
                                }
                                
                                // Get public URL
                                const { data: { publicUrl } } = supabase.storage
                                  .from('avatars')
                                  .getPublicUrl(filePath);
                                
                                // Update user profile in database (persists across OAuth logins)
                                await api.updateUserProfile({ avatar_url: publicUrl });
                                
                                // Clear cache to force refresh
                                if (user?.id) {
                                  localStorage.removeItem(`user_profile_${user.id}`);
                                }
                                
                                // Preload the new image before reloading (prevents flash of blank image)
                                await new Promise<void>((resolve) => {
                                  const img = new Image();
                                  img.onload = () => resolve();
                                  img.onerror = () => resolve(); // Resolve even on error to not block
                                  img.src = publicUrl;
                                });
                                
                                toast({
                                  title: 'Avatar updated',
                                  description: 'Your avatar has been updated successfully.',
                                });
                                
                                // Reload the page to show updated avatar everywhere
                                // Image is now cached so it won't flash blank
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
                              
                              // Reset input
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
                  </div>

                </div>
              )}

              {activeSection === 'billing' && (
                <div className="space-y-8">
                  <h2 className="text-2xl font-bold text-foreground">Billing Information</h2>

                  {/* Stripe Connection Section */}
                  <div className="bg-background border border-border rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-foreground mb-2">Stripe Account</h3>
                    <p className="text-sm text-foreground-secondary mb-6">
                      {stripeConnected 
                        ? 'Your Stripe account is connected. You can use this account to set up billing for your organizations.'
                        : 'Connect your Stripe account to enable billing for your organizations. This account will be used when you add a plan to an organization.'}
                    </p>
                    {stripeConnected ? (
                      <div className="flex items-center gap-4">
                        <Button
                          variant="outline"
                          onClick={async () => {
                            try {
                              await api.disconnectIntegration('stripe');
                              setStripeConnected(false);
                              toast({
                                title: 'Disconnected',
                                description: 'Stripe account has been disconnected.',
                              });
                            } catch (error: any) {
                              toast({
                                title: 'Error',
                                description: error.message || 'Failed to disconnect Stripe.',
                                variant: 'destructive',
                              });
                            }
                          }}
                        >
                          Disconnect Stripe
                        </Button>
                      </div>
                    ) : (
                      <Button
                        onClick={async () => {
                          try {
                            const { data: { session } } = await supabase.auth.getSession();
                            if (!session?.access_token) {
                              toast({
                                title: 'Error',
                                description: 'Please log in to connect Stripe.',
                                variant: 'destructive',
                              });
                              return;
                            }

                            const data = await api.connectIntegration('stripe');
                            window.location.href = data.redirectUrl;
                          } catch (error: any) {
                            toast({
                              title: 'Error',
                              description: error.message || 'Failed to connect Stripe.',
                              variant: 'destructive',
                            });
                          }
                        }}
                      >
                        Connect Stripe Account
                      </Button>
                    )}
                  </div>
                </div>
              )}

              {activeSection === 'authentication' && (
                <div className="space-y-8">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground mb-2">Connected Accounts</h2>
                    <p className="text-foreground-secondary">
                      Manage your login providers. These accounts are used for authentication and sign-in only.
                    </p>
                  </div>

                  <div className="bg-background border border-border rounded-lg divide-y divide-border">
                    {integrationList.map((integration) => {
                      const isConnected = integrations[integration.id];

                      return (
                        <div
                          key={integration.id}
                          className="flex items-center justify-between p-4"
                        >
                          <div className="flex items-center gap-4 flex-1">
                            <div className="flex-shrink-0">
                              <img
                                src={integration.image}
                                alt={integration.name}
                                className={`h-8 w-8 rounded object-contain ${isConnected ? 'opacity-100' : 'opacity-60'}`}
                              />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-3">
                                <h3 className="text-sm font-semibold text-foreground">
                                  {integration.name}
                                </h3>
                                {isConnected ? (
                                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/20">
                                    Connected
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-foreground-secondary/10 text-foreground-secondary border border-foreground-secondary/20">
                                    Not Connected
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-foreground-secondary mt-1">
                                {isConnected 
                                  ? `You can sign in using your ${integration.name} account`
                                  : integration.description
                                }
                              </p>
                            </div>
                          </div>
                          {!isConnected && (
                            <div className="flex-shrink-0">
                              <Button
                                size="sm"
                                onClick={() => handleConnectProvider(integration.id as 'github' | 'google')}
                              >
                                Connect
                              </Button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  
                  <div className="mt-4 p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                    <p className="text-sm text-foreground">
                      <strong className="text-blue-400">Note:</strong> You can add additional login methods by clicking "Connect" above. 
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


