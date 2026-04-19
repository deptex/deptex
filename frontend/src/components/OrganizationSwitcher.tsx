import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Plus, Check, ChevronsUpDown, Mail, LogOut } from 'lucide-react';
import { api, Organization, OrganizationInvitation } from '../lib/api';
import { supabase } from '../lib/supabase';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { Button } from './ui/button';
import CreateOrganizationModal from './CreateOrganizationModal';

interface OrganizationSwitcherProps {
  currentOrganizationId: string;
  currentOrganizationName: string;
  showOrgName?: boolean;
}

export default function OrganizationSwitcher({
  currentOrganizationId,
  currentOrganizationName,
  showOrgName = false,
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
    if (isOpen) {
      loadData();
    }
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
    } catch (error) {
      console.error('Failed to load organizations:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const filteredOrganizations = organizations.filter(org =>
    org.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSelectOrganization = (orgId: string) => {
    navigate(`/organizations/${orgId}`);
    setIsOpen(false);
  };

  const handleCreateOrganization = () => {
    setIsCreateModalOpen(true);
    setIsOpen(false);
  };

  const handleCreateSuccess = () => {
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

      // If leaving the current org, navigate to organizations page
      if (orgToLeave.id === currentOrganizationId) {
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

  return (
    <>
      <div className="flex items-center gap-2">
        {showOrgName && (
          <span className="text-foreground font-medium">{currentOrganizationName}</span>
        )}
        <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center justify-center p-1 -ml-1.5 rounded hover:bg-background-subtle transition-colors">
              <ChevronsUpDown className="h-4 w-4 text-foreground-secondary hover:text-foreground transition-colors" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-80 p-0">
            <div className="p-2">
              <div className="relative mb-2">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                <input
                  type="text"
                  placeholder="Find organization..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                  autoFocus
                />
              </div>

              <div className="max-h-64 overflow-y-auto">
                {isLoading ? (
                  // Loading skeleton
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
                      return currentOrg && (
                        <div className="group">
                          <button
                            onClick={() => handleSelectOrganization(currentOrganizationId)}
                            className="w-full flex items-center justify-between px-3 py-2 rounded-md text-left"
                          >
                            <div className="flex items-center gap-2">
                              <img
                                src={currentOrg.avatar_url || '/images/org_profile.png'}
                                alt={currentOrganizationName}
                                className="h-7 w-7 rounded-full object-cover border border-border"
                              />
                              <span className="text-sm font-medium text-foreground group-hover:text-foreground transition-colors">
                                {currentOrganizationName}
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              {!isOwner && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleLeaveOrganization(currentOrg.id, currentOrg.name);
                                  }}
                                  disabled={leavingOrgId === currentOrg.id}
                                  className="p-1 rounded hover:bg-destructive/10 transition-colors opacity-0 group-hover:opacity-100"
                                  title="Leave organization"
                                >
                                  <LogOut className="h-3.5 w-3.5 text-destructive" />
                                </button>
                              )}
                              <Check className="h-4 w-4 text-primary" />
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
                        return (
                          <div key={org.id} className="group">
                            <button
                              onClick={() => handleSelectOrganization(org.id)}
                              className="w-full flex items-center justify-between px-3 py-2 rounded-md text-left"
                            >
                              <div className="flex items-center gap-2">
                                <img
                                  src={org.avatar_url || '/images/org_profile.png'}
                                  alt={org.name}
                                  className="h-7 w-7 rounded-full object-cover border border-border"
                                />
                                <span className="text-sm text-foreground-secondary group-hover:text-foreground transition-colors">{org.name}</span>
                              </div>
                              {!isOwner && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleLeaveOrganization(org.id, org.name);
                                  }}
                                  disabled={leavingOrgId === org.id}
                                  className="p-1 rounded hover:bg-destructive/10 transition-colors opacity-0 group-hover:opacity-100"
                                  title="Leave organization"
                                >
                                  <LogOut className="h-3.5 w-3.5 text-destructive" />
                                </button>
                              )}
                            </button>
                          </div>
                        );
                      })}
                  </>
                )}
              </div>

              {/* Invitations section */}
              {invitations.length > 0 && (
                <>
                  <div className="border-t border-border my-2"></div>
                  <div className="px-3 py-2">
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
                        className="w-full flex items-center gap-2 px-3 py-2 rounded-md group text-left"
                      >
                        <Mail className="h-4 w-4 text-foreground-secondary group-hover:text-foreground transition-colors" />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-foreground-secondary group-hover:text-foreground truncate transition-colors">
                            {invitation.organization_name || 'Organization'}
                          </div>
                          <div className="text-xs text-foreground-secondary">
                            You've been invited • {invitation.role}
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                </>
              )}

              {/* New organization button */}
              <div className="border-t border-border mt-2 pt-2">
                <button
                  onClick={handleCreateOrganization}
                  className="w-full flex items-center justify-start px-3 py-2 text-foreground-secondary hover:text-foreground transition-colors group"
                >
                  <Plus className="h-4 w-4 mr-2 group-hover:text-foreground transition-colors" />
                  New organization
                </button>
              </div>
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

