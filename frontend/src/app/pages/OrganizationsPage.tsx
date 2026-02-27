import { useState, useEffect, useRef } from 'react';
import { Search, Plus, Mail, X, ChevronRight, Check, Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import OrganizationsHeader from '../../components/OrganizationsHeader';
import { Button } from '../../components/ui/button';
import { api, Organization, OrganizationInvitation } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Toaster } from '../../components/ui/toaster';
import CreateOrganizationModal from '../../components/CreateOrganizationModal';
import { RoleBadge } from '../../components/RoleBadge';

export default function OrganizationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [dismissedInvitations, setDismissedInvitations] = useState<Set<string>>(new Set());
  const [acceptingInvitationId, setAcceptingInvitationId] = useState<string | null>(null);
  const { toast } = useToast();
  const navigate = useNavigate();
  const prefetchTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && searchQuery) {
        setSearchQuery('');
        searchInputRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [searchQuery]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [orgsData, invitesData] = await Promise.all([
        api.getOrganizations(),
        api.getInvitations().catch((err) => {
          console.error('Failed to load invitations:', err);
          return [];
        }),
      ]);
      setOrganizations(orgsData);
      setInvitations(invitesData || []);
      // Cache roles AND permissions in localStorage for faster access and instant tab display
      orgsData.forEach(org => {
        if (org.id && org.role) {
          localStorage.setItem(`org_role_${org.id}`, org.role);
          // Also cache permissions if available for instant tab display
          if (org.permissions) {
            localStorage.setItem(`org_permissions_${org.id}`, JSON.stringify(org.permissions));
          }
        }
      });
      console.log('Loaded organizations:', orgsData.length, 'invitations:', (invitesData || []).length);
    } catch (error: any) {
      console.error('Failed to load data:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to load data',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateOrganization = () => {
    setIsCreateModalOpen(true);
  };

  const filteredOrganizations = organizations.filter(org =>
    org.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredInvitations = invitations.filter(inv =>
    (inv.organization_name || 'Organization').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const visibleInvitations = filteredInvitations.filter(inv => !dismissedInvitations.has(inv.id));

  const handleDismissInvitation = (invitationId: string) => {
    setDismissedInvitations(prev => new Set([...prev, invitationId]));
  };

  const handleAcceptInvitation = async (invitation: OrganizationInvitation) => {
    const invitationToAccept = invitation;

    // Set loading state
    setAcceptingInvitationId(invitation.id);

    try {
      // Accept invitation and fetch organization data
      await api.acceptInvitation(invitation.organization_id, invitation.id);

      // Immediately fetch the organization to get correct data (avatar, etc.)
      const newOrg = await api.getOrganization(invitation.organization_id);

      // Fetch member count separately since getOrganization doesn't include it
      try {
        const members = await api.getOrganizationMembers(invitation.organization_id);
        newOrg.member_count = members.length;
      } catch (err) {
        // If member count fetch fails, set to 1 (at least the user)
        newOrg.member_count = 1;
      }

      // Remove invitation and add organization with correct data
      setInvitations(prev => prev.filter(inv => inv.id !== invitation.id));
      setOrganizations(prev => {
        // Check if org already exists (shouldn't, but be safe)
        if (!prev.find(org => org.id === newOrg.id)) {
          return [...prev, newOrg];
        }
        // If it exists, update it
        return prev.map(org => org.id === newOrg.id ? newOrg : org);
      });

      // Cache role in localStorage
      if (newOrg.role) {
        localStorage.setItem(`org_role_${newOrg.id}`, newOrg.role);
      }

      // Show success
      toast({
        title: 'Success',
        description: `You've joined ${newOrg.name || 'the organization'}!`,
      });
    } catch (error: any) {
      console.error('Failed to accept invitation:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to accept invitation',
        variant: 'destructive',
      });
    } finally {
      setAcceptingInvitationId(null);
    }
  };

  const handleRejectInvitation = (invitationId: string) => {
    handleDismissInvitation(invitationId);
    toast({
      title: 'Invitation Rejected',
      description: 'The invitation has been dismissed.',
    });
  };

  // Prefetch organization data on hover
  const handleOrgHover = (orgId: string) => {
    // Clear any existing timeout for this org
    const existingTimeout = prefetchTimeouts.current.get(orgId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Small delay to avoid prefetching on accidental hovers
    const timeout = setTimeout(() => {
      api.prefetchOrganization(orgId).catch(() => {
        // Silently fail - prefetch errors shouldn't interrupt the user
      });
      prefetchTimeouts.current.delete(orgId);
    }, 100); // 100ms delay before prefetching

    prefetchTimeouts.current.set(orgId, timeout);
  };

  const handleOrgHoverEnd = (orgId: string) => {
    // Clear timeout if user moves mouse away before prefetch starts
    const timeout = prefetchTimeouts.current.get(orgId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchTimeouts.current.delete(orgId);
    }
  };

  return (
    <>
      <div className="min-h-screen bg-background">
        <OrganizationsHeader />

        <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          {/* Invitation Notifications */}
          {visibleInvitations.length > 0 && (
            <div className="mb-6 space-y-3">
              {visibleInvitations.map((invitation) => (
                <div
                  key={invitation.id}
                  className="bg-primary/10 border border-primary/30 rounded-lg p-4 flex items-center justify-between gap-4 animate-in slide-in-from-top-2"
                >
                  <div className="flex items-center gap-4 flex-1 min-w-0">
                    <div className="flex-shrink-0">
                      <div className="h-10 w-10 rounded-full bg-primary/20 border border-primary/40 flex items-center justify-center">
                        <Mail className="h-5 w-5 text-primary" />
                      </div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-base font-semibold text-foreground mb-1 truncate">
                        You've been invited to join {invitation.organization_name || 'an organization'}
                      </h3>
                      <p className="text-sm text-foreground-secondary">
                        Invited as <span className="capitalize font-medium">{invitation.role}</span>
                        {invitation.team_name && ` for ${invitation.team_name} team`}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Button
                      onClick={() => handleAcceptInvitation(invitation)}
                      disabled={acceptingInvitationId === invitation.id}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-9"
                    >
                      {acceptingInvitationId === invitation.id ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Check className="h-4 w-4 mr-2" />
                      )}
                      Accept
                    </Button>
                    <button
                      onClick={() => handleRejectInvitation(invitation.id)}
                      className="p-2 text-foreground-secondary hover:text-foreground hover:bg-background-subtle rounded-md transition-colors"
                      aria-label="Reject"
                      title="Reject"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="mb-8">
            <h1 className="text-3xl font-bold text-foreground mb-6">
              Your Organizations
            </h1>

            {/* Search and Create */}
            <div className="flex items-center justify-between gap-4">
              <div className="relative max-w-sm w-80">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
                <input
                  ref={searchInputRef}
                  type="text"
                  placeholder="Search organizations"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={`w-full pl-9 py-2 bg-background-card border border-border rounded-md text-foreground placeholder:text-foreground-secondary text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent ${searchQuery ? 'pr-14' : 'pr-3'}`}
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                    aria-label="Clear search (Esc)"
                  >
                    Esc
                  </button>
                )}
              </div>
              <Button
                onClick={handleCreateOrganization}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-9"
              >
                <Plus className="h-5 w-5 mr-2" />
                New organization
              </Button>
            </div>
          </div>

          {/* Organizations List */}
          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="bg-background-card border border-border rounded-lg p-5 animate-pulse"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <div className="h-10 w-10 rounded-full bg-muted flex-shrink-0" />
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <div className="h-5 bg-muted rounded w-32" />
                          <div className="h-5 bg-muted rounded w-16" />
                        </div>
                        <div className="h-4 bg-muted rounded w-12" />
                      </div>
                    </div>
                    <div className="h-5 w-5 bg-muted rounded flex-shrink-0" />
                  </div>
                </div>
              ))}
            </div>
          ) : filteredOrganizations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <h3 className="text-base font-medium text-foreground mb-1.5">
                {searchQuery ? 'No organizations found' : 'No organizations yet'}
              </h3>
              <p className="text-sm text-foreground-secondary mb-6 max-w-sm">
                {searchQuery
                  ? 'Try adjusting your search query.'
                  : 'Get started by creating your first organization.'}
              </p>
              {!searchQuery && (
                <Button
                  onClick={handleCreateOrganization}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  <Plus className="h-5 w-5 mr-2" />
                  Create organization
                </Button>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {/* Organizations */}
              {filteredOrganizations.map((org) => (
                <div
                  key={org.id}
                  onClick={() => navigate(`/organizations/${org.id}`)}
                  onMouseEnter={() => handleOrgHover(org.id)}
                  onMouseLeave={() => handleOrgHoverEnd(org.id)}
                  className="bg-background-card border border-border rounded-lg p-5 hover:bg-background-card/80 transition-all cursor-pointer group relative"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <img
                        src={org.avatar_url || '/images/org_profile.png'}
                        alt={org.name}
                        className="h-10 w-10 rounded-full object-cover border border-border flex-shrink-0"
                      />
                      <div className="flex flex-col min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="text-base font-semibold text-foreground truncate">
                            {org.name}
                          </h3>
                          <RoleBadge
                            role={org.role || 'member'}
                            roleDisplayName={org.role_display_name || (org.role === 'owner' ? 'CEO' : (org.role ? org.role.charAt(0).toUpperCase() + org.role.slice(1) : 'Member'))}
                            roleColor={org.role_color}
                          />
                        </div>
                        <div className="text-sm text-foreground-secondary">
                          Free
                        </div>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-foreground-secondary group-hover:text-foreground transition-colors flex-shrink-0 ml-2" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </main>
      </div>
      <CreateOrganizationModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={loadData}
      />
      <Toaster position="bottom-right" />
    </>
  );
}

