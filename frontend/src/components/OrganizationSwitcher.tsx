import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Plus, Check, ChevronsUpDown, Mail, LogOut } from 'lucide-react';
import { api, Organization, OrganizationInvitation } from '../lib/api';
import { supabase } from '../lib/supabase';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { Button } from './ui/button';
import CreateOrganizationModal from './CreateOrganizationModal';
import { RoleBadge } from './RoleBadge';

/** In-memory cache for org list so we don't refetch every time the dropdown opens (same pattern as settings tabs). */
const ORG_SWITCHER_CACHE_TTL_MS = 2 * 60 * 1000; // 2 minutes
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

/** Role label for display; fallback when role_display_name is missing. */
function roleLabel(org: Organization): string {
  if (org.role_display_name) return org.role_display_name;
  if (!org.role) return 'Member';
  return org.role.charAt(0).toUpperCase() + org.role.slice(1);
}

/** Default badge colors for built-in roles (match Organization Settings > Roles palette). */
const DEFAULT_ROLE_COLORS: Record<string, string> = {
  owner: '#3b82f6',   // Blue
  admin: '#14b8a6',   // Teal
  member: '#71717a',   // Muted (zinc-500)
};
function roleBadgeColor(org: Organization): string {
  if (org.role_color) return org.role_color;
  if (org.role && DEFAULT_ROLE_COLORS[org.role]) return DEFAULT_ROLE_COLORS[org.role];
  return '#71717a'; // fallback muted
}

interface OrganizationSwitcherProps {
  currentOrganizationId: string;
  currentOrganizationName: string;
  currentOrganizationAvatarUrl?: string | null;
  showOrgName?: boolean;
  /** When "full", trigger shows avatar + name + chevron (for header). Default "icon" (chevron only). */
  triggerVariant?: 'full' | 'icon';
}

export default function OrganizationSwitcher({
  currentOrganizationId,
  currentOrganizationName,
  currentOrganizationAvatarUrl,
  showOrgName = false,
  triggerVariant = 'icon',
}: OrganizationSwitcherProps) {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);
  const [leavingOrgId, setLeavingOrgId] = useState<string | null>(null);
  const [showLeaveConfirmModal, setShowLeaveConfirmModal] = useState(false);
  const [orgToLeave, setOrgToLeave] = useState<{ id: string; name: string } | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    loadCurrentUser();
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    const cached = getCachedOrgList();
    if (cached) {
      setOrganizations(cached.organizations);
      setInvitations(cached.invitations);
      return;
    }
    loadData();
  }, [isOpen]);

  const loadCurrentUser = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        setCurrentUserId(user.id);
      }
    } catch (error) {
      console.error('Failed to load current user:', error);
    }
  };

  const loadData = async () => {
    try {
      setIsLoading(true);
      const [orgsData, invitesData] = await Promise.all([
        api.getOrganizations(),
        api.getInvitations().catch(() => []), // Fallback to empty array if endpoint doesn't exist yet
      ]);
      setOrganizations(orgsData);
      setInvitations(invitesData || []);
      setCachedOrgList(orgsData, invitesData || []);
    } catch (error) {
      console.error('Failed to load organizations:', error);
    } finally {
      setIsLoading(false);
    }
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

  const handleSelectOrganization = async (orgId: string) => {
    try {
      await api.updateUserProfile({ default_organization_id: orgId });
    } catch {
      // Non-blocking
    }
    navigate(`/organizations/${orgId}`);
    setIsOpen(false);
  };

  const handleCreateOrganization = () => {
    setIsCreateModalOpen(true);
    setIsOpen(false);
  };

  const handleCreateSuccess = (_org?: Organization) => {
    loadData();
  };

  const handleLeaveOrganization = (orgId: string, orgName: string) => {
    if (!currentUserId) return;
    setOrgToLeave({ id: orgId, name: orgName });
    setShowLeaveConfirmModal(true);
    setIsOpen(false); // Close the dropdown
  };

  const confirmLeaveOrganization = async () => {
    if (!currentUserId || !orgToLeave) return;

    try {
      setLeavingOrgId(orgToLeave.id);
      await api.removeMember(orgToLeave.id, currentUserId);

      // Remove from local state
      setOrganizations(orgs => orgs.filter(org => org.id !== orgToLeave.id));

      // If leaving the current org, navigate to landing (redirects to default or empty state)
      if (orgToLeave.id === currentOrganizationId) {
        try {
          const remaining = organizations.filter((o) => o.id !== orgToLeave.id);
          const newDefaultId = remaining.length > 0 ? remaining[0].id : null;
          await api.updateUserProfile({ default_organization_id: newDefaultId });
        } catch {
          // Non-blocking
        }
        navigate('/organizations');
      }

      setShowLeaveConfirmModal(false);
      setOrgToLeave(null);
    } catch (error: any) {
      console.error('Failed to leave organization:', error);
      alert(error.message || 'Failed to leave organization. Please try again.');
    } finally {
      setLeavingOrgId(null);
    }
  };

  const triggerContent =
    triggerVariant === 'full' ? (
      <button
        type="button"
        className="org-switcher-trigger flex items-center gap-2 min-w-0 rounded-md py-1 pr-1 -ml-1 hover:bg-background-subtle transition-colors text-left outline-none border-0 focus:outline-none focus:ring-0 focus:border-0 focus-visible:outline-none focus-visible:ring-0"
      >
        <img
          src={currentOrganizationAvatarUrl || '/images/org_profile.png'}
          alt=""
          className="h-6 w-6 rounded-full object-cover flex-shrink-0 bg-transparent"
        />
        <span className="text-sm font-medium text-foreground truncate max-w-[140px]">
          {currentOrganizationName}
        </span>
        <ChevronsUpDown className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
      </button>
    ) : (
      <button
        type="button"
        className="org-switcher-trigger flex items-center justify-center p-1 -ml-1.5 rounded hover:bg-background-subtle transition-colors outline-none border-0 focus:outline-none focus:ring-0 focus:border-0 focus-visible:outline-none focus-visible:ring-0"
      >
        <ChevronsUpDown className="h-4 w-4 text-foreground-secondary hover:text-foreground transition-colors" />
      </button>
    );

  return (
    <>
      <div className="flex items-center gap-2">
        {triggerVariant === 'icon' && showOrgName && (
          <span className="text-foreground font-medium">{currentOrganizationName}</span>
        )}
        <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
          <DropdownMenuTrigger asChild>
            {triggerContent}
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-[420px] min-h-[380px] p-0 flex flex-col">
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
                className="flex-shrink-0 px-2 py-1 text-xs border border-border rounded text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50 transition-colors"
              >
                Esc
              </button>
            </div>

            <div className="flex-1 overflow-y-auto min-h-0 p-2">
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
                      const isOwner = currentOrg?.role === 'owner';
                      const badgeColor = currentOrg ? roleBadgeColor(currentOrg) : undefined;
                      return currentOrg && (
                        <div className="group">
                          <button
                            onClick={() => handleSelectOrganization(currentOrganizationId)}
                            className="w-full flex items-center justify-between px-3 py-2 rounded-md text-left hover:bg-background-subtle/50"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <img
                                src={currentOrg.avatar_url || '/images/org_profile.png'}
                                alt={currentOrganizationName}
                                className="h-7 w-7 rounded-full object-cover bg-transparent flex-shrink-0"
                              />
                              <span className="text-sm font-medium text-foreground truncate">
                                {currentOrganizationName}
                              </span>
                              <RoleBadge
                                role={currentOrg.role || 'member'}
                                roleDisplayName={roleLabel(currentOrg)}
                                roleColor={badgeColor ?? null}
                                className="flex-shrink-0"
                              />
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              {!isOwner && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleLeaveOrganization(currentOrg.id, currentOrg.name);
                                      }}
                                      disabled={leavingOrgId === currentOrg.id}
                                      className="p-1 rounded hover:bg-destructive/10 transition-colors opacity-0 group-hover:opacity-100"
                                    >
                                      <LogOut className="h-3.5 w-3.5 text-destructive" />
                                    </button>
                                  </TooltipTrigger>
                                  <TooltipContent side="left" sideOffset={6}>
                                    Leave organization
                                  </TooltipContent>
                                </Tooltip>
                              )}
                              <Check className="h-4 w-4 text-white drop-shadow-md flex-shrink-0" />
                            </div>
                          </button>
                        </div>
                      );
                    })()}

                    {/* Other organizations */}
                    {filteredOrganizations
                      .filter(org => org.id !== currentOrganizationId)
                      .map((org) => {
                        const isOwner = org.role === 'owner';
                        const badgeColor = roleBadgeColor(org);
                        return (
                          <div key={org.id} className="group">
                            <button
                              onClick={() => handleSelectOrganization(org.id)}
                              className="w-full flex items-center justify-between px-3 py-2 rounded-md text-left hover:bg-background-subtle/50"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <img
                                  src={org.avatar_url || '/images/org_profile.png'}
                                  alt={org.name}
                                  className="h-7 w-7 rounded-full object-cover bg-transparent flex-shrink-0"
                                />
                                <span className="text-sm text-foreground-secondary group-hover:text-foreground transition-colors truncate">{org.name}</span>
                                <RoleBadge
                                  role={org.role || 'member'}
                                  roleDisplayName={roleLabel(org)}
                                  roleColor={badgeColor}
                                  className="flex-shrink-0"
                                />
                              </div>
                              {!isOwner && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleLeaveOrganization(org.id, org.name);
                                      }}
                                      disabled={leavingOrgId === org.id}
                                      className="p-1 rounded hover:bg-destructive/10 transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0"
                                    >
                                      <LogOut className="h-3.5 w-3.5 text-destructive" />
                                    </button>
                                  </TooltipTrigger>
                                  <TooltipContent side="left" sideOffset={6}>
                                    Leave organization
                                  </TooltipContent>
                                </Tooltip>
                              )}
                            </button>
                          </div>
                        );
                      })}

                    {/* Empty state when no other orgs, or no search results */}
                    {!isLoading && filteredOrganizations.filter(org => org.id !== currentOrganizationId).length === 0 && (
                      <div className="flex flex-col items-center justify-center py-8 px-4 text-center">
                        <div className="flex items-center justify-center w-10 h-10 rounded-full bg-muted/50 text-foreground-secondary mb-3" aria-hidden>
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
                      <button
                        key={invitation.id}
                        onClick={() => {
                          navigate(`/invite/${invitation.id}`);
                          setIsOpen(false);
                        }}
                        className="w-full flex items-center gap-2 px-3 py-2 rounded-md group text-left hover:bg-background-subtle/50"
                      >
                        <Mail className="h-4 w-4 text-foreground-secondary group-hover:text-foreground transition-colors" />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-foreground-secondary group-hover:text-foreground truncate transition-colors">
                            {invitation.organization_name || 'Organization'}
                          </div>
                          <div className="text-xs text-foreground-secondary">
                            You&apos;ve been invited • {invitation.role}
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                </>
              )}

              {/* New organization — white text + subtext */}
              <div className="border-t border-border mt-2 pt-2 px-2 pb-2">
                <button
                  onClick={handleCreateOrganization}
                  className="w-full flex items-center justify-start gap-2 px-3 py-2.5 text-foreground hover:bg-background-subtle/50 rounded-md transition-colors group text-left"
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
        </DropdownMenu>
      </div>

      <CreateOrganizationModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={handleCreateSuccess}
      />

      {/* Leave Organization Confirmation Modal */}
      {showLeaveConfirmModal && orgToLeave && (
        <div className="fixed inset-0 z-50">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setShowLeaveConfirmModal(false);
              setOrgToLeave(null);
            }}
          />

          {/* Modal - centered */}
          <div className="fixed inset-0 flex items-center justify-center p-4">
            <div
              className="bg-background border border-border rounded-lg shadow-2xl w-full max-w-md"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="px-6 py-5 border-b border-border">
                <h2 className="text-xl font-semibold text-foreground">
                  Leave Organization
                </h2>
              </div>

              {/* Content */}
              <div className="px-6 py-6">
                <p className="text-foreground-secondary">
                  Are you sure you want to leave <strong>"{orgToLeave.name}"</strong>? You will lose access to all teams and projects in this organization.
                </p>
              </div>

              {/* Footer */}
              <div className="px-6 py-5 border-t border-border flex items-center justify-end gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowLeaveConfirmModal(false);
                    setOrgToLeave(null);
                  }}
                  disabled={leavingOrgId === orgToLeave.id}
                >
                  Cancel
                </Button>
                <Button
                  onClick={confirmLeaveOrganization}
                  disabled={leavingOrgId === orgToLeave.id}
                  className="bg-red-600 text-white hover:bg-red-700"
                >
                  {leavingOrgId === orgToLeave.id ? (
                    <>
                      <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                      Leaving
                    </>
                  ) : (
                    'Leave Organization'
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

