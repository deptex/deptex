import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Plus, Loader2, X } from 'lucide-react';
import { api, Organization, OrganizationInvitation } from '../lib/api';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { Button } from './ui/button';
import { useToast } from '../hooks/use-toast';
import CreateOrganizationModal from './CreateOrganizationModal';
import { RoleBadge } from './RoleBadge';
import { OrgAvatar } from './Avatar';

/** Tiny in-memory cache so rapid open → close → open doesn't re-fetch.
 * The real "feels instant" mechanism is prefetch-on-hover; this just covers
 * the rapid-toggle case. Keep short so role/name changes from elsewhere
 * (org settings, role admin) clear within seconds. */
const ORG_SWITCHER_CACHE_TTL_MS = 30 * 1000; // 30 seconds
let orgSwitcherCache: {
  organizations: Organization[];
  invitations: OrganizationInvitation[];
  fetchedAt: number;
} | null = null;

function getCachedOrgList(): { organizations: Organization[]; invitations: OrganizationInvitation[] } | null {
  if (!orgSwitcherCache) return null;
  if (Date.now() - orgSwitcherCache.fetchedAt > ORG_SWITCHER_CACHE_TTL_MS) return null;
  return { organizations: orgSwitcherCache.organizations, invitations: orgSwitcherCache.invitations };
}

function setCachedOrgList(organizations: Organization[], invitations: OrganizationInvitation[]): void {
  orgSwitcherCache = { organizations, invitations, fetchedAt: Date.now() };
}

// AuthContext.signOut dispatches this so the cache doesn't leak to the next
// user that signs in within the same tab session.
if (typeof window !== 'undefined') {
  window.addEventListener('auth:signedOut', () => {
    orgSwitcherCache = null;
  });
}

/** Role label for display; fallback when role_display_name is missing. */
function roleLabel(org: Organization): string {
  if (org.role_display_name) return org.role_display_name;
  if (!org.role) return 'Member';
  return org.role.charAt(0).toUpperCase() + org.role.slice(1);
}

/** Default badge colors for built-in roles. Member is intentionally absent so it
 * falls through to the neutral foreground-tinted styling in RoleBadge. */
const DEFAULT_ROLE_COLORS: Record<string, string> = {
  owner: '#3b82f6',   // Blue
  admin: '#14b8a6',   // Teal
};
function roleBadgeColor(org: Organization): string | null {
  if (org.role_color) return org.role_color;
  if (org.role && DEFAULT_ROLE_COLORS[org.role]) return DEFAULT_ROLE_COLORS[org.role];
  return null;
}

interface OrganizationSwitcherProps {
  currentOrganizationId: string;
  currentOrganizationName: string;
  currentOrganizationAvatarUrl?: string | null;
  currentOrganizationRole?: string | null;
  currentOrganizationRoleDisplayName?: string | null;
  currentOrganizationRoleColor?: string | null;
}

export default function OrganizationSwitcher({
  currentOrganizationId,
  currentOrganizationName,
  currentOrganizationAvatarUrl,
  currentOrganizationRole,
  currentOrganizationRoleDisplayName,
  currentOrganizationRoleColor,
}: OrganizationSwitcherProps) {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [acceptingId, setAcceptingId] = useState<string | null>(null);
  const [decliningId, setDecliningId] = useState<string | null>(null);
  const navigate = useNavigate();
  const { toast } = useToast();
  const inflightRef = useRef<Promise<void> | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    void loadData();
  }, [isOpen]);

  const loadData = async (force = false): Promise<void> => {
    if (!force) {
      const cached = getCachedOrgList();
      if (cached) {
        setOrganizations(cached.organizations);
        setInvitations(cached.invitations);
        return;
      }
    }

    if (inflightRef.current) return inflightRef.current;

    const promise = (async () => {
      try {
        setIsLoading(true);
        const [orgsData, invitesData] = await Promise.all([
          api.getOrganizations(),
          api.getInvitations().catch(() => []),
        ]);
        setOrganizations(orgsData);
        setInvitations(invitesData || []);
        setCachedOrgList(orgsData, invitesData || []);
      } catch (error) {
        console.error('Failed to load organizations:', error);
      } finally {
        setIsLoading(false);
        inflightRef.current = null;
      }
    })();

    inflightRef.current = promise;
    return promise;
  };

  const filteredOrganizations = organizations.filter(org =>
    org.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleEscape = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      setSearchQuery('');
      setIsOpen(false);
    }
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [isOpen, handleEscape]);

  const handleSelectOrganization = (orgId: string) => {
    navigate(`/organizations/${orgId}`);
    setIsOpen(false);
  };

  const handleCreateOrganization = () => {
    setIsCreateModalOpen(true);
    setIsOpen(false);
  };

  const handleCreateSuccess = (org?: Organization) => {
    void loadData(true);
    if (org?.id) {
      setIsOpen(false);
      navigate(`/organizations/${org.id}`);
    }
  };

  const handleAcceptInvitation = async (invitation: OrganizationInvitation) => {
    if (acceptingId) return;
    setAcceptingId(invitation.id);
    try {
      await api.acceptInvitation(invitation.organization_id, invitation.id);
      setInvitations((prev) => prev.filter((i) => i.id !== invitation.id));
      await loadData(true);
      setIsOpen(false);
      navigate(`/organizations/${invitation.organization_id}`);
      toast({
        title: 'Joined',
        description: `You're now a member of ${invitation.organization_name || 'the organization'}.`,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to accept invitation',
        description: error?.message || 'Please try again.',
        variant: 'destructive',
      });
    } finally {
      setAcceptingId(null);
    }
  };

  const handleDeclineInvitation = async (invitation: OrganizationInvitation) => {
    if (decliningId) return;
    setDecliningId(invitation.id);
    try {
      await api.declineInvitation(invitation.organization_id, invitation.id);
      setInvitations((prev) => prev.filter((i) => i.id !== invitation.id));
      // Cache had stale invitations; rewrite without bumping the orgs list.
      setCachedOrgList(organizations, invitations.filter((i) => i.id !== invitation.id));
    } catch (error: any) {
      toast({
        title: 'Failed to decline invitation',
        description: error?.message || 'Please try again.',
        variant: 'destructive',
      });
    } finally {
      setDecliningId(null);
    }
  };

  const dropdownContent = (
    <DropdownMenuContent align="start" className="w-[420px] min-h-[380px] max-h-[min(80vh,640px)] p-0 flex flex-col rounded-xl">
            {/* Search bar ingrained at top — no card, just bar + Esc */}
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-transparent">
              <Search className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
              <input
                type="text"
                placeholder="Find organization..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="org-switcher-search flex-1 min-w-0 py-1.5 bg-transparent text-sm text-foreground placeholder:text-foreground-secondary outline-none border-0 border-transparent focus:outline-none focus:ring-0 focus:ring-offset-0 focus:border-transparent focus:shadow-none focus-visible:outline-none focus-visible:ring-0 focus-visible:ring-offset-0"
                autoFocus
              />
              <button
                type="button"
                onClick={() => { setSearchQuery(''); setIsOpen(false); }}
                className="flex-shrink-0 px-2 py-1 text-xs border border-foreground/15 rounded-lg text-foreground-secondary hover:text-foreground hover:bg-background-subtle/85 transition-colors"
              >
                Esc
              </button>
            </div>

            <div className="flex-1 overflow-y-scroll min-h-0 p-2">
                {isLoading ? (
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 px-3 py-2">
                      <div className="h-7 w-7 rounded-full bg-border animate-pulse" />
                      <div className="h-4 w-32 bg-border rounded animate-pulse" />
                    </div>
                  </div>
                ) : (
                  <>
                    {/* Current organization */}
                    {(() => {
                      const currentOrg = filteredOrganizations.find(org => org.id === currentOrganizationId);
                      const badgeColor = currentOrg ? roleBadgeColor(currentOrg) : undefined;
                      return currentOrg && (
                        <button
                          onClick={() => handleSelectOrganization(currentOrganizationId)}
                          className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-left bg-background-subtle/85"
                        >
                          <OrgAvatar
                            src={currentOrg.avatar_url}
                            alt={currentOrganizationName}
                            className="h-7 w-7 rounded-full object-cover bg-transparent flex-shrink-0"
                          />
                          <span className="text-sm font-medium text-foreground truncate flex-1 min-w-0">
                            {currentOrganizationName}
                          </span>
                          <RoleBadge
                            role={currentOrg.role || 'member'}
                            roleDisplayName={roleLabel(currentOrg)}
                            roleColor={badgeColor ?? null}
                            className="flex-shrink-0"
                          />
                        </button>
                      );
                    })()}

                    {/* Other organizations */}
                    {filteredOrganizations
                      .filter(org => org.id !== currentOrganizationId)
                      .map((org) => {
                        const badgeColor = roleBadgeColor(org);
                        return (
                          <button
                            key={org.id}
                            onClick={() => handleSelectOrganization(org.id)}
                            className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-left hover:bg-background-subtle/85"
                          >
                            <OrgAvatar
                              src={org.avatar_url}
                              alt={org.name}
                              className="h-7 w-7 rounded-full object-cover bg-transparent flex-shrink-0"
                            />
                            <span className="text-sm text-foreground truncate flex-1 min-w-0">{org.name}</span>
                            <RoleBadge
                              role={org.role || 'member'}
                              roleDisplayName={roleLabel(org)}
                              roleColor={badgeColor}
                              className="flex-shrink-0"
                            />
                          </button>
                        );
                      })}

                    {/* Empty state when no other orgs, or no search results */}
                    {!isLoading && filteredOrganizations.filter(org => org.id !== currentOrganizationId).length === 0 && (
                      <div className="flex flex-col items-center justify-center py-8 px-4 text-center">
                        <div className="flex items-center justify-center w-10 h-10 rounded-lg border border-foreground/15 bg-background-subtle/50 text-foreground-secondary mb-3" aria-hidden>
                          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                            <circle cx="9" cy="7" r="4" />
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                          </svg>
                        </div>
                        <p className="text-sm text-foreground-secondary">
                          {searchQuery
                            ? 'No organizations match your search.'
                            : 'Organizations you create and join appear here for quick context switching.'}
                        </p>
                      </div>
                    )}
                  </>
                )}
              </div>

              {/* Invitations */}
              {invitations.length > 0 && (
                <>
                  <div className="border-t border-border my-2 mx-2" />
                  <div className="px-2 pt-2 pb-2">
                    <div className="text-xs font-medium text-foreground-secondary mb-2">
                      Invitations
                    </div>
                    {invitations.map((invitation) => (
                      <div
                        key={invitation.id}
                        className="w-full flex items-center gap-2 px-3 py-2 rounded-md hover:bg-background-subtle/85 transition-colors"
                      >
                        <OrgAvatar
                          src={invitation.organization_avatar_url}
                          className="h-7 w-7 rounded-full object-cover bg-transparent flex-shrink-0"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-foreground truncate">
                            {invitation.organization_name || 'Organization'}
                          </div>
                          <div className="text-xs text-foreground-secondary">
                            You&apos;ve been invited • {invitation.role}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleDeclineInvitation(invitation)}
                          disabled={decliningId !== null || acceptingId !== null}
                          aria-label="Decline invitation"
                          className="inline-flex items-center justify-center h-7 w-7 rounded-lg border border-foreground/15 text-foreground-secondary hover:text-foreground hover:bg-background-subtle/85 transition-colors disabled:opacity-50 flex-shrink-0"
                        >
                          {decliningId === invitation.id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <X className="h-3.5 w-3.5" />
                          )}
                        </button>
                        <Button
                          variant="green"
                          onClick={() => handleAcceptInvitation(invitation)}
                          disabled={acceptingId !== null || decliningId !== null}
                          className="!h-7 !px-2.5 !text-xs flex-shrink-0"
                        >
                          {acceptingId === invitation.id ? (
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
                      </div>
                    ))}
                  </div>
                </>
              )}

              {/* New organization — white text + subtext */}
              <div className="border-t border-border mt-2 pt-2 px-2 pb-2">
                <button
                  onClick={handleCreateOrganization}
                  className="w-full flex items-center justify-start gap-2 px-3 py-2.5 text-foreground hover:bg-background-subtle/85 rounded-md transition-colors group text-left"
                >
                  <Plus className="h-4 w-4 flex-shrink-0 text-foreground" />
                  <div className="flex flex-col items-start min-w-0">
                    <span className="text-sm font-medium text-foreground">New organization</span>
                    <span className="text-xs text-foreground-secondary mt-0.5">
                      Collaborate with others in a shared workspace.
                    </span>
                  </div>
                </button>
              </div>
    </DropdownMenuContent>
  );

  // Apply the same fallback as the dropdown rows. Returns null for member so
  // RoleBadge falls into its neutral-styled branch.
  const triggerBadgeColor =
    currentOrganizationRoleColor
    || (currentOrganizationRole && DEFAULT_ROLE_COLORS[currentOrganizationRole.toLowerCase()])
    || null;

  return (
    <>
      <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            onMouseEnter={() => { void loadData(); }}
            onFocus={() => { void loadData(); }}
            className="flex items-center gap-2 w-full pl-2 pr-0.5 py-1 text-left rounded-md hover:bg-background-subtle/85 transition-colors outline-none border-0 focus-visible:outline-none focus-visible:ring-0"
          >
            <OrgAvatar
              src={currentOrganizationAvatarUrl}
              className="h-7 w-7 rounded-full object-cover flex-shrink-0 bg-transparent"
            />
            <span className="text-sm font-semibold text-foreground truncate flex-1 min-w-0">
              {currentOrganizationName}
            </span>
            <div className="flex items-center gap-0.5 flex-shrink-0">
              {currentOrganizationRole && (
                <RoleBadge
                  role={currentOrganizationRole}
                  roleDisplayName={currentOrganizationRoleDisplayName}
                  roleColor={triggerBadgeColor}
                />
              )}
            </div>
          </button>
        </DropdownMenuTrigger>
        {dropdownContent}
      </DropdownMenu>

      <CreateOrganizationModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={handleCreateSuccess}
      />
    </>
  );
}

