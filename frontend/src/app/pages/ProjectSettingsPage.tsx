import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useOutletContext, useNavigate, useParams, useLocation } from 'react-router-dom';
import { Settings, Trash2, Shield, Bell, ChevronDown, Users, Plus, X, Search, Crown, UserPlus, AlertTriangle, Package, GitPullRequest, FolderOpen, Folder, Copy, Lock, Check, BookOpen, Undo2 } from 'lucide-react';
import { api, ProjectWithRole, ProjectPermissions, Team, ProjectTeamsResponse, ProjectContributingTeam, ProjectMember, OrganizationMember, ProjectPRGuardrails, ProjectRepository, ProjectImportStatus, type ProjectEffectivePolicies, type AssetTier, type CiCdConnection, type RepoWithProvider } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { PRGuardrailsSidepanel } from '../../components/PRGuardrailsSidepanel';
import { FrameworkIcon } from '../../components/framework-icon';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

/** Display label for package.json path: "Root" or folder name e.g. "Frontend". */
function getWorkspaceDisplayPath(packageJsonPath: string | undefined): string {
  if (!packageJsonPath || packageJsonPath === 'package.json' || packageJsonPath.trim() === '') return 'Root';
  const dir = packageJsonPath.replace(/\/?package\.json$/i, '').trim();
  if (!dir) return 'Root';
  const lastSegment = dir.split('/').filter(Boolean).pop() || dir;
  return lastSegment.charAt(0).toUpperCase() + lastSegment.slice(1).toLowerCase();
}

export default function ProjectSettingsPage() {
  const { project, reloadProject, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId } = useParams<{ projectId: string }>();
  const location = useLocation();
  const [activeSection, setActiveSection] = useState('general');
  const [projectName, setProjectName] = useState(project?.name || '');
  const [assetTier, setAssetTier] = useState<AssetTier>(project?.asset_tier ?? 'EXTERNAL');
  const [isSaving, setIsSaving] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [isDeletingProject, setIsDeletingProject] = useState(false);
  const { toast } = useToast();
  const navigate = useNavigate();

  const canViewSettings = userPermissions?.view_settings === true;
  const canEditSettings = userPermissions?.edit_settings === true;

  // Redirect if user doesn't have permission to view settings
  useEffect(() => {
    // Wait for permissions to be loaded before checking
    if (userPermissions !== null && !canViewSettings) {
      toast({
        title: 'Access Denied',
        description: 'You do not have permission to view project settings',
      });
      navigate(`/organizations/${organizationId}/projects/${projectId}`, { replace: true });
    }
  }, [userPermissions, canViewSettings, organizationId, projectId, navigate, toast]);

  // Repository connection state
  const [repositories, setRepositories] = useState<RepoWithProvider[]>([]);
  const [repoSearchQuery, setRepoSearchQuery] = useState('');
  const [connectedRepository, setConnectedRepository] = useState<ProjectRepository | null>(null);
  const [repositoriesLoading, setRepositoriesLoading] = useState(false);
  const [repositoriesError, setRepositoriesError] = useState<string | null>(null);
  const [cliCopied, setCliCopied] = useState(false);
  const [importStatus, setImportStatus] = useState<ProjectImportStatus | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const [settingsConnections, setSettingsConnections] = useState<CiCdConnection[]>([]);
  const [settingsSelectedIntegration, setSettingsSelectedIntegration] = useState<string | null>(null);
  const [settingsSourceOpen, setSettingsSourceOpen] = useState(false);
  const settingsSourceRef = useRef<HTMLDivElement>(null);

  // Select project (monorepo) flow
  const [repoToConnect, setRepoToConnect] = useState<RepoWithProvider | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<{
    isMonorepo: boolean;
    confidence?: 'high' | 'medium';
    potentialProjects: Array<{ name: string; path: string; isLinked: boolean; linkedByProjectId?: string; linkedByProjectName?: string; ecosystem?: string }>;
  } | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedPackagePath, setSelectedPackagePath] = useState<string>('');

  // Framework detection state (for connected repository)
  const [detectedFramework, setDetectedFramework] = useState<string>('unknown');
  const [frameworkLoading, setFrameworkLoading] = useState(false);
  const [prGuardrails, setPRGuardrails] = useState<ProjectPRGuardrails | null>(null);
  const [guardrailsLoading, setGuardrailsLoading] = useState(false);
  const [showGuardrailsSidepanel, setShowGuardrailsSidepanel] = useState(false);
  const [savingGuardrails, setSavingGuardrails] = useState(false);

  // Transfer project state
  const [teams, setTeams] = useState<Team[]>([]);
  const [loadingTeams, setLoadingTeams] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState<string>('');
  const [showTeamDropdown, setShowTeamDropdown] = useState(false);
  const [isTransferring, setIsTransferring] = useState(false);
  const teamDropdownRef = useRef<HTMLDivElement>(null);

  // Access section state
  const [projectTeams, setProjectTeams] = useState<ProjectTeamsResponse | null>(null);
  const [loadingProjectTeams, setLoadingProjectTeams] = useState(false);
  const [directMembers, setDirectMembers] = useState<ProjectMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [orgMembers, setOrgMembers] = useState<OrganizationMember[]>([]);

  // Sidepanel states
  const [showAddTeamSidepanel, setShowAddTeamSidepanel] = useState(false);
  const [showAddMemberSidepanel, setShowAddMemberSidepanel] = useState(false);
  const [teamSearchQuery, setTeamSearchQuery] = useState('');
  const [memberSearchQuery, setMemberSearchQuery] = useState('');
  const [addingTeam, setAddingTeam] = useState(false);
  const [addingMember, setAddingMember] = useState(false);
  const [removingTeamId, setRemovingTeamId] = useState<string | null>(null);
  const [removingMemberId, setRemovingMemberId] = useState<string | null>(null);
  const [selectedTeamsToAdd, setSelectedTeamsToAdd] = useState<string[]>([]);
  const [selectedMembersToAdd, setSelectedMembersToAdd] = useState<string[]>([]);
  const [teamMemberIds, setTeamMemberIds] = useState<Set<string>>(new Set());

  // Policies section state
  const [orgPoliciesCode, setOrgPoliciesCode] = useState<string>('');
  const [projectPolicies, setProjectPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [policyView, setPolicyView] = useState<'org' | 'project'>('project');
  const [policyEditorCode, setPolicyEditorCode] = useState('');
  const [policyExceptionReason, setPolicyExceptionReason] = useState('');
  const [policySubmitting, setPolicySubmitting] = useState(false);
  const [policyCancelling, setPolicyCancelling] = useState(false);

  // Open Policies section when navigated from "Request Exception" (e.g. compliance table)
  useEffect(() => {
    const state = location.state as { section?: string } | null;
    if (state?.section === 'policies') {
      setActiveSection('policies');
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, location.pathname, navigate]);

  // Sync projectName and assetTier state when project changes
  useEffect(() => {
    if (project?.name) {
      setProjectName(project.name);
    }
    if (project?.asset_tier) {
      setAssetTier(project.asset_tier);
    }
  }, [project?.name, project?.asset_tier]);

  // Load PR guardrails
  const loadPRGuardrails = async () => {
    if (!organizationId || !projectId) return;
    try {
      setGuardrailsLoading(true);
      const guardrails = await api.getProjectPRGuardrails(organizationId, projectId);
      setPRGuardrails(guardrails);
    } catch (error: any) {
      console.error('Failed to load PR guardrails:', error);
    } finally {
      setGuardrailsLoading(false);
    }
  };

  const loadSettingsConnections = async () => {
    if (!organizationId) return;
    try {
      const conns = await api.getOrganizationConnections(organizationId);
      setSettingsConnections(conns);
    } catch { /* ignore */ }
  };

  const loadProjectRepositories = async (integrationId?: string) => {
    if (!organizationId || !projectId) return;
    const cached = !integrationId ? api.getCachedProjectRepositories(organizationId, projectId) : null;
    try {
      if (!cached) setRepositoriesLoading(true);
      const targetIntegration = integrationId || settingsSelectedIntegration || undefined;
      const data = await api.getProjectRepositories(organizationId, projectId, targetIntegration);
      setConnectedRepository(data.connectedRepository);
      setRepositories(data.repositories);
      setRepositoriesError(null);
    } catch (error: any) {
      setRepositoriesError(error.message || 'Failed to load repositories');
    } finally {
      setRepositoriesLoading(false);
    }
  };

  useEffect(() => {
    if (activeSection === 'cicd') {
      loadPRGuardrails();
      loadSettingsConnections();
    }
  }, [activeSection, organizationId, projectId]);

  const loadPoliciesSection = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setPoliciesLoading(true);
    try {
      const [orgPol, projPol] = await Promise.all([
        api.getOrganizationPolicies(organizationId),
        api.getProjectPolicies(organizationId, projectId),
      ]);
      const inherited = (orgPol.policy_code ?? '').trim() || '';
      setOrgPoliciesCode(inherited);
      setProjectPolicies(projPol);
    } catch (e) {
      console.error('Failed to load policies:', e);
    } finally {
      setPoliciesLoading(false);
    }
  }, [organizationId, projectId]);

  useEffect(() => {
    if (activeSection === 'policies') {
      loadPoliciesSection();
    }
  }, [activeSection, loadPoliciesSection]);

  useEffect(() => {
    if (!projectPolicies || policiesLoading) return;
    const effective = projectPolicies.effective_policy_code ?? projectPolicies.inherited_policy_code ?? orgPoliciesCode;
    const displayCode = policyView === 'org' ? orgPoliciesCode : effective;
    setPolicyEditorCode(displayCode);
  }, [policyView, orgPoliciesCode, projectPolicies?.effective_policy_code, projectPolicies?.inherited_policy_code, policiesLoading]);

  useEffect(() => {
    if (activeSection === 'general' && organizationId && projectId) {
      const cached = api.getCachedProjectRepositories(organizationId, projectId);
      if (cached) {
        setConnectedRepository(cached.connectedRepository);
        setRepositories(cached.repositories);
      }
      loadProjectRepositories();
    }
  }, [activeSection, organizationId, projectId]);

  // Get connected repository's framework from the repositories list
  useEffect(() => {
    if (!connectedRepository || repositories.length === 0) return;
    
    const matchingRepo = repositories.find(
      repo => repo.full_name === connectedRepository.repo_full_name
    );
    
    if (matchingRepo) {
      setDetectedFramework(matchingRepo.framework);
    } else {
      setDetectedFramework('unknown');
    }
  }, [connectedRepository, repositories]);

  const checkImportStatus = useCallback(async () => {
    if (!organizationId || !projectId) return false;
    try {
      const status = await api.getProjectImportStatus(organizationId, projectId);
      setImportStatus(status);
      if (status.status === 'ready' && (connectedRepository?.status === 'analyzing' || connectedRepository?.status === 'finalizing')) {
        setConnectedRepository(prev => prev ? { ...prev, status: 'ready' } : null);
        await loadProjectRepositories();
        await reloadProject();
        toast({ title: 'Analysis complete', description: `All ${status.total} dependencies have been analyzed.` });
      }
      return status.status === 'ready';
    } catch {
      return false;
    }
  }, [organizationId, projectId, connectedRepository?.status, reloadProject, toast]);

  useEffect(() => {
    const repoStatus = connectedRepository?.status;
    const importStatusPoll = importStatus?.status;
    const shouldPoll =
      repoStatus === 'extracting' ||
      repoStatus === 'analyzing' ||
      repoStatus === 'finalizing' ||
      importStatusPoll === 'finalizing';
    if (!shouldPoll) return;
    checkImportStatus();
    const id = setInterval(() => {
      checkImportStatus().then(done => { if (done && pollingIntervalRef.current) clearInterval(pollingIntervalRef.current); });
    }, 3000);
    pollingIntervalRef.current = id;
    return () => { if (pollingIntervalRef.current) clearInterval(pollingIntervalRef.current); pollingIntervalRef.current = null; };
  }, [connectedRepository?.status, importStatus?.status, checkImportStatus]);

  const handleSaveGuardrails = async (data: Partial<ProjectPRGuardrails>) => {
    if (!organizationId || !projectId) return;
    try {
      setSavingGuardrails(true);
      await api.updateProjectPRGuardrails(organizationId, projectId, data);
      toast({
        title: 'Guardrails Updated',
        description: 'PR guardrails have been saved successfully.',
      });
      setShowGuardrailsSidepanel(false);
      await loadPRGuardrails();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to save guardrails',
      });
      throw error;
    } finally {
      setSavingGuardrails(false);
    }
  };

  // Load teams for transfer dropdown
  const loadTeams = async () => {
    if (!organizationId) return;
    try {
      setLoadingTeams(true);
      const teamsData = await api.getTeams(organizationId);
      setTeams(teamsData);
    } catch (error: any) {
      console.error('Failed to load teams:', error);
    } finally {
      setLoadingTeams(false);
    }
  };

  // Load teams when component mounts
  useEffect(() => {
    if (organizationId) {
      loadTeams();
    }
  }, [organizationId]);

  // Load project teams on mount for transfer functionality
  useEffect(() => {
    if (organizationId && projectId) {
      loadProjectTeams();
    }
  }, [organizationId, projectId]);

  // Load project teams and members when access section is active
  const loadProjectTeams = async () => {
    if (!organizationId || !projectId) return;
    try {
      setLoadingProjectTeams(true);
      const teamsData = await api.getProjectTeams(organizationId, projectId);
      setProjectTeams(teamsData);

      // Fetch members of all teams with access to build exclusion list
      const teamIds: string[] = [];
      if (teamsData.owner_team) {
        teamIds.push(teamsData.owner_team.id);
      }
      teamsData.contributing_teams.forEach(t => teamIds.push(t.id));

      // Get members for each team
      const memberIds = new Set<string>();
      for (const teamId of teamIds) {
        try {
          const teamMembers = await api.getTeamMembers(organizationId, teamId);
          teamMembers.forEach(m => memberIds.add(m.user_id));
        } catch (error) {
          console.error(`Failed to load members for team ${teamId}:`, error);
        }
      }
      setTeamMemberIds(memberIds);
    } catch (error: any) {
      console.error('Failed to load project teams:', error);
    } finally {
      setLoadingProjectTeams(false);
    }
  };

  const loadProjectMembers = async () => {
    if (!organizationId || !projectId) return;
    try {
      setLoadingMembers(true);
      const membersData = await api.getProjectMembers(organizationId, projectId);
      setDirectMembers(membersData.direct_members);
    } catch (error: any) {
      console.error('Failed to load project members:', error);
    } finally {
      setLoadingMembers(false);
    }
  };

  const loadOrgMembers = async () => {
    if (!organizationId) return;
    try {
      const members = await api.getOrganizationMembers(organizationId);
      setOrgMembers(members);
    } catch (error: any) {
      console.error('Failed to load org members:', error);
    }
  };

  useEffect(() => {
    if (activeSection === 'access' && organizationId && projectId) {
      loadProjectTeams();
      loadProjectMembers();
      loadOrgMembers();
    }
  }, [activeSection, organizationId, projectId]);

  // Available teams for adding (exclude owner and already contributing teams)
  const availableTeamsForAdding = useMemo(() => {
    if (!projectTeams || !teams.length) return [];
    const existingTeamIds = new Set<string>();
    if (projectTeams.owner_team) {
      existingTeamIds.add(projectTeams.owner_team.id);
    }
    projectTeams.contributing_teams.forEach(t => existingTeamIds.add(t.id));
    return teams.filter(t => !existingTeamIds.has(t.id));
  }, [teams, projectTeams]);

  // Filter available teams by search query
  const filteredTeamsForAdding = useMemo(() => {
    if (!teamSearchQuery.trim()) return availableTeamsForAdding;
    const query = teamSearchQuery.toLowerCase();
    return availableTeamsForAdding.filter(t =>
      t.name.toLowerCase().includes(query) ||
      t.description?.toLowerCase().includes(query)
    );
  }, [availableTeamsForAdding, teamSearchQuery]);

  // Available members for adding (exclude already direct members AND team members with access)
  const availableMembersForAdding = useMemo(() => {
    const directMemberIds = new Set(directMembers.map(m => m.user_id));
    return orgMembers.filter(m =>
      !directMemberIds.has(m.user_id) && !teamMemberIds.has(m.user_id)
    );
  }, [orgMembers, directMembers, teamMemberIds]);

  // Filter available members by search query
  const filteredMembersForAdding = useMemo(() => {
    if (!memberSearchQuery.trim()) return availableMembersForAdding;
    const query = memberSearchQuery.toLowerCase();
    return availableMembersForAdding.filter(m =>
      m.email.toLowerCase().includes(query) ||
      m.full_name?.toLowerCase().includes(query)
    );
  }, [availableMembersForAdding, memberSearchQuery]);

  // Handler for adding selected contributing teams
  const handleAddContributingTeams = async () => {
    if (!organizationId || !projectId || addingTeam || selectedTeamsToAdd.length === 0) return;
    try {
      setAddingTeam(true);
      for (const teamId of selectedTeamsToAdd) {
        await api.addProjectContributingTeam(organizationId, projectId, teamId);
      }
      toast({
        title: selectedTeamsToAdd.length === 1 ? 'Team added' : 'Teams added',
        description: `${selectedTeamsToAdd.length} team${selectedTeamsToAdd.length !== 1 ? 's have' : ' has'} been added as contributor${selectedTeamsToAdd.length !== 1 ? 's' : ''} to this project.`,
      });
      await loadProjectTeams();
      setShowAddTeamSidepanel(false);
      setTeamSearchQuery('');
      setSelectedTeamsToAdd([]);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to add teams',
        variant: 'destructive',
      });
    } finally {
      setAddingTeam(false);
    }
  };

  // Toggle team selection
  const toggleTeamSelection = (teamId: string) => {
    setSelectedTeamsToAdd(prev =>
      prev.includes(teamId)
        ? prev.filter(id => id !== teamId)
        : [...prev, teamId]
    );
  };

  // Handler for removing a contributing team
  const handleRemoveContributingTeam = async (teamId: string) => {
    if (!organizationId || !projectId || removingTeamId) return;
    try {
      setRemovingTeamId(teamId);
      await api.removeProjectContributingTeam(organizationId, projectId, teamId);
      toast({
        title: 'Team removed',
        description: 'Team has been removed from this project.',
      });
      await loadProjectTeams();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to remove team',
        variant: 'destructive',
      });
    } finally {
      setRemovingTeamId(null);
    }
  };

  // Handler for adding selected direct members
  const handleAddDirectMembers = async () => {
    if (!organizationId || !projectId || addingMember || selectedMembersToAdd.length === 0) return;
    try {
      setAddingMember(true);
      for (const userId of selectedMembersToAdd) {
        await api.addProjectMember(organizationId, projectId, userId);
      }
      toast({
        title: selectedMembersToAdd.length === 1 ? 'Member added' : 'Members added',
        description: `${selectedMembersToAdd.length} member${selectedMembersToAdd.length !== 1 ? 's have' : ' has'} been added to this project.`,
      });
      await loadProjectMembers();
      setShowAddMemberSidepanel(false);
      setMemberSearchQuery('');
      setSelectedMembersToAdd([]);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to add members',
        variant: 'destructive',
      });
    } finally {
      setAddingMember(false);
    }
  };

  // Toggle member selection
  const toggleMemberSelection = (userId: string) => {
    setSelectedMembersToAdd(prev =>
      prev.includes(userId)
        ? prev.filter(id => id !== userId)
        : [...prev, userId]
    );
  };

  // Handler for removing a direct member
  const handleRemoveDirectMember = async (userId: string) => {
    if (!organizationId || !projectId || removingMemberId) return;
    try {
      setRemovingMemberId(userId);
      await api.removeProjectMember(organizationId, projectId, userId);
      toast({
        title: 'Member removed',
        description: 'Member has been removed from this project.',
      });
      await loadProjectMembers();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to remove member',
        variant: 'destructive',
      });
    } finally {
      setRemovingMemberId(null);
    }
  };

  // Set initial selected team from project teams data (owner team)
  useEffect(() => {
    if (projectTeams?.owner_team) {
      setSelectedTeamId(projectTeams.owner_team.id);
    } else if (project?.team_ids && project.team_ids.length > 0) {
      setSelectedTeamId(project.team_ids[0]);
    }
  }, [projectTeams?.owner_team, project?.team_ids]);

  // Close team dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (teamDropdownRef.current && !teamDropdownRef.current.contains(event.target as Node)) {
        setShowTeamDropdown(false);
      }
    };

    if (showTeamDropdown) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showTeamDropdown]);

  // Handle transfer project to new team
  const handleTransferProject = async () => {
    if (!organizationId || !project?.id || !selectedTeamId || isTransferring) return;

    // Check if selected team is same as current owner
    if (projectTeams?.owner_team?.id === selectedTeamId) {
      toast({
        title: 'No change',
        description: 'This team is already the owner of this project.',
      });
      return;
    }

    try {
      setIsTransferring(true);
      await api.transferProjectOwnership(organizationId, project.id, selectedTeamId);

      const selectedTeam = teams.find(t => t.id === selectedTeamId);
      toast({
        title: 'Ownership transferred',
        description: `Project ownership has been transferred to ${selectedTeam?.name || 'the selected team'}.`,
      });

      await loadProjectTeams();
      await reloadProject();
    } catch (error: any) {
      toast({
        title: 'Transfer failed',
        description: error.message || 'Failed to transfer project ownership. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsTransferring(false);
    }
  };

  // Settings sections configuration
  const projectSettingsSections = [
    {
      id: 'general',
      label: 'General',
      icon: <Settings className="h-4 w-4 tab-icon-shake" />,
    },
    {
      id: 'access',
      label: 'Access',
      icon: <Shield className="h-4 w-4 tab-icon-shake" />,
    },
    {
      id: 'notifications',
      label: 'Notifications',
      icon: <Bell className="h-4 w-4 tab-icon-shake" />,
    },
    {
      id: 'policies',
      label: 'Policies',
      icon: <BookOpen className="h-4 w-4 tab-icon-shake" />,
    },
    {
      id: 'cicd',
      label: 'CI/CD',
      icon: <GitPullRequest className="h-4 w-4 tab-icon-shake" />,
    },
  ];

  // Permission check - redirect if user doesn't have view_settings permission
  useEffect(() => {
    if (!project || !projectId || !userPermissions) return;

    if (!userPermissions.view_settings) {
      // Redirect to first available tab
      if (userPermissions.view_overview) {
        navigate(`/organizations/${organizationId}/projects/${projectId}`, { replace: true });
      } else if (userPermissions.view_dependencies) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies`, { replace: true });
      } else if (userPermissions.view_watchlist) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/watchlist`, { replace: true });
      } else if (userPermissions.view_members) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/members`, { replace: true });
      }
    }
  }, [project, projectId, userPermissions, navigate, organizationId]);

  // Show loading until project is available
  if (!project) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-muted rounded w-48"></div>
          <div className="h-64 bg-muted rounded"></div>
        </div>
      </main>
    );
  }

  const handleSave = async () => {
    if (!organizationId || !project?.id || !projectName.trim()) return;

    try {
      setIsSaving(true);
      await api.updateProject(organizationId, project.id, {
        name: projectName.trim(),
        asset_tier: assetTier,
      });
      toast({
        title: 'Success',
        description: 'Project settings saved',
      });
      await reloadProject();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to save settings',
      });
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!organizationId || !project?.id || deleteConfirmText !== project.name || isDeletingProject) return;

    try {
      setIsDeletingProject(true);
      await api.deleteProject(organizationId, project.id);
      toast({
        title: 'Success',
        description: 'Project deleted',
      });
      navigate(`/organizations/${organizationId}/projects`);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to delete project',
      });
    } finally {
      setIsDeletingProject(false);
    }
  };

  const handleImportRepository = async (repo: RepoWithProvider) => {
    if (!organizationId || !projectId) return;
    setRepoToConnect(repo);
    setScanLoading(true);
    setScanError(null);
    setScanResult(null);
    try {
      const data = await api.getRepositoryScan(organizationId, projectId, repo.full_name, repo.default_branch, repo.integration_id ?? '');
      setScanResult(data);
      if (data.potentialProjects.length === 0) {
        toast({ title: 'No package.json found', description: 'This repository has no detectable package.json (root or workspaces).', variant: 'destructive' });
        setRepoToConnect(null);
      } else {
        const firstUnlinked = data.potentialProjects.find((p) => !p.isLinked);
        setSelectedPackagePath(firstUnlinked ? firstUnlinked.path : data.potentialProjects[0]?.path ?? '');
      }
    } catch (error: any) {
      setScanError(error.message || 'Failed to scan repository');
      toast({ title: 'Scan failed', description: error.message || 'Failed to scan repository', variant: 'destructive' });
      setRepoToConnect(null);
    } finally {
      setScanLoading(false);
    }
  };

  const handleConnectWithPath = async (packagePath: string) => {
    if (!organizationId || !projectId || !repoToConnect) return;
    const repo = repoToConnect;
    setConnectedRepository({
      repo_full_name: repo.full_name,
      default_branch: repo.default_branch,
      status: 'extracting',
      package_json_path: packagePath || undefined,
    });
    if (repo.framework) setDetectedFramework(repo.framework);
    setRepoToConnect(null);
    setScanResult(null);
    try {
      const matchedProject = scanResult?.potentialProjects?.find((p: any) => p.path === packagePath);
      const connected = await api.connectProjectRepository(organizationId, projectId, {
        repo_id: repo.id,
        repo_full_name: repo.full_name,
        default_branch: repo.default_branch,
        framework: repo.framework,
        package_json_path: packagePath || undefined,
        ecosystem: matchedProject?.ecosystem || repo.ecosystem,
        provider: repo.provider,
        integration_id: repo.integration_id,
      });
      setConnectedRepository(connected);
      api.setProjectRepositoriesCache(organizationId, projectId, { connectedRepository: connected, repositories });
      if (connected.status === 'analyzing' || connected.status === 'finalizing') {
        try { const s = await api.getProjectImportStatus(organizationId, projectId); setImportStatus(s); } catch (_) {}
      }
      await reloadProject();
      toast({
        title: 'Repository connected',
        description: connected.status === 'analyzing'
          ? `Extraction complete. Analyzing ${connected.dependencies_count} dependencies...`
          : connected.status === 'finalizing'
            ? `Extraction complete. Finalizing import analysis...`
            : `Successfully extracted dependencies from ${repo.full_name}.`,
      });
    } catch (error: any) {
      setConnectedRepository(null);
      setDetectedFramework('unknown');
      api.invalidateProjectRepositoriesCache(organizationId, projectId);
      toast({
        title: 'Import failed',
        description: error.message || 'Failed to import repository',
        variant: 'destructive',
      });
    }
  };

  const closeSelectProjectDialog = () => {
    setRepoToConnect(null);
    setScanResult(null);
    setScanError(null);
  };

  const handleCopyCli = async () => {
    const repo = connectedRepository?.repo_full_name || 'owner/repo';
    const proj = project?.name || 'my-app';
    const command = `npx deptex init --project "${proj}" --repo "${repo}"`;

    try {
      await navigator.clipboard.writeText(command);
      setCliCopied(true);
      setTimeout(() => setCliCopied(false), 2000);
    } catch {
      setCliCopied(false);
    }
  };

  return (
    <div className="bg-background">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-8 items-start">
          {/* Sidebar */}
          <aside className="w-64 flex-shrink-0">
            <div className="sticky top-24 pt-8 bg-background z-10">
              <nav className="space-y-1">
                {projectSettingsSections.map((section) => (
                  <button
                    key={section.id}
                    onClick={() => setActiveSection(section.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${activeSection === section.id
                      ? 'text-foreground'
                      : 'text-foreground-secondary hover:text-foreground'
                      }`}
                  >
                    {section.icon}
                    {section.label}
                  </button>
                ))}
              </nav>
            </div>
          </aside>

          {/* Content */}
          <div className="flex-1 no-scrollbar">
            {activeSection === 'general' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">General Settings</h2>
                  <p className="text-foreground-secondary mt-1">
                    Manage your project's profile and settings.
                  </p>
                </div>

                {/* Project Name & Asset Tier Card - Anyone with edit can edit */}
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <div className="p-6 space-y-6">
                    <div>
                      <h3 className="text-base font-semibold text-foreground mb-1">Project Name</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
                        This is your project's visible name. It will be displayed throughout the dashboard.
                      </p>
                      <div className="max-w-md">
                        <input
                          type="text"
                          value={projectName}
                          onChange={(e) => setProjectName(e.target.value)}
                          placeholder="Enter project name"
                          className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                        />
                      </div>
                    </div>
                    <div>
                      <h3 className="text-base font-semibold text-foreground mb-1">Asset Tier</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
                        Used by Dexcore to weight vulnerability scores and blast radius (Crown Jewels vs non-production).
                      </p>
                      <div className="max-w-md">
                        <select
                          value={assetTier}
                          onChange={(e) => setAssetTier(e.target.value as AssetTier)}
                          className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                        >
                          <option value="CROWN_JEWELS">Crown Jewels</option>
                          <option value="EXTERNAL">External</option>
                          <option value="INTERNAL">Internal</option>
                          <option value="NON_PRODUCTION">Non-production</option>
                        </select>
                      </div>
                    </div>
                  </div>
                  <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                    <p className="text-xs text-foreground-secondary">
                      Changes will be visible to all project members.
                    </p>
                    <Button
                      onClick={handleSave}
                      disabled={isSaving || (projectName === project?.name && assetTier === (project?.asset_tier ?? 'EXTERNAL'))}
                      size="sm"
                      className="h-8"
                    >
                      {isSaving ? (
                        <>
                          <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                          Saving
                        </>
                      ) : (
                        'Save'
                      )}
                    </Button>
                  </div>
                </div>

                {/* Repository Settings Card */}
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <div className="p-6 space-y-6">
                    {/* Loading State */}
                    {repositoriesLoading ? (
                      <div>
                        <h3 className="text-base font-semibold text-foreground mb-1">Connected Repository</h3>
                        <p className="text-sm text-foreground-secondary mb-4">
                          This repository is linked for automatic dependency updates.
                        </p>
                        <div className="flex items-center gap-3 p-3 rounded-lg border border-border bg-background min-h-[52px]">
                          <div className="h-5 w-5 rounded bg-muted animate-pulse shrink-0" />
                          <div className="flex flex-col gap-2 min-w-0">
                            <div className="h-3.5 w-32 bg-muted rounded animate-pulse" />
                            <div className="h-3 w-20 bg-muted rounded animate-pulse" />
                          </div>
                        </div>
                      </div>
                    ) : repositoriesError && (repositoriesError.includes('integration') || repositoriesError.includes('GitHub App') || repositoriesError.includes('No source')) ? (
                      <div className="text-center py-8">
                        <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-foreground-secondary/10 mb-4">
                          <FolderOpen className="h-6 w-6 text-foreground-secondary" />
                        </div>
                        <h3 className="text-base font-semibold text-foreground mb-2">No Source Code Connections</h3>
                        <p className="text-sm text-foreground-secondary mb-4 max-w-sm mx-auto">
                          Connect a Git provider in Organization Settings to import repositories.
                        </p>
                        <Button
                          variant="outline"
                          onClick={() => navigate(`/organizations/${organizationId}/settings/integrations`)}
                        >
                          Go to Integrations
                        </Button>
                      </div>
                    ) : connectedRepository ? (
                      /* Connected Repository – status + repo, and Project workspace */
                      <div className="space-y-6">
                        <div>
                          <h3 className="text-base font-semibold text-foreground mb-1">Connected Repository</h3>
                          <p className="text-sm text-foreground-secondary mb-4">
                            This repository is linked for automatic dependency updates.
                          </p>
                          <div className="flex items-center justify-between gap-4 p-3 rounded-lg border border-border bg-background min-h-[52px]">
                            <div className="flex items-center gap-3">
                              <FrameworkIcon frameworkId={detectedFramework} />
                              <div>
                                <div className="text-sm font-medium text-foreground">
                                  {connectedRepository.repo_full_name}
                                </div>
                                <div className="text-xs text-foreground-secondary flex items-center gap-1.5">
                                  <Folder className="h-3.5 w-3.5 shrink-0" />
                                  {getWorkspaceDisplayPath(connectedRepository.package_json_path)}
                                </div>
                              </div>
                            </div>
                            <div className="flex flex-col items-end gap-1">
                              <span className={`px-2 py-1 text-xs font-medium rounded border flex items-center gap-2 ${(connectedRepository.status === 'ready' && importStatus?.status !== 'finalizing')
                                ? 'bg-success/20 text-success border-success/40'
                                : connectedRepository.status === 'extracting' || connectedRepository.status === 'analyzing' || connectedRepository.status === 'finalizing' || importStatus?.status === 'finalizing'
                                  ? 'bg-foreground-secondary/10 text-foreground-secondary border-border'
                                  : connectedRepository.status === 'error'
                                    ? 'bg-destructive/20 text-destructive border-destructive/40'
                                    : 'bg-background-subtle text-foreground-secondary border-border'
                                }`}>
                                {(connectedRepository.status === 'extracting' || connectedRepository.status === 'analyzing' || connectedRepository.status === 'finalizing' || importStatus?.status === 'finalizing') && (
                                  <span className="animate-spin h-3 w-3 border-2 border-current border-t-transparent rounded-full" />
                                )}
                                {importStatus?.status === 'finalizing' || connectedRepository.status === 'finalizing'
                                  ? 'Finalizing'
                                  : connectedRepository.status === 'ready'
                                    ? 'Connected'
                                    : connectedRepository.status === 'extracting'
                                      ? 'Extracting'
                                      : connectedRepository.status === 'analyzing'
                                        ? 'Analyzing'
                                        : connectedRepository.status === 'error'
                                          ? 'Error'
                                          : 'Pending'}
                              </span>
                              {importStatus && importStatus.total > 0 && (connectedRepository.status === 'analyzing' || importStatus?.status === 'analyzing') && (
                                <span className="text-xs text-foreground-secondary">{importStatus.ready} / {importStatus.total} analyzed</span>
                              )}
                            </div>
                          </div>
                          {importStatus && importStatus.total > 0 && (connectedRepository.status === 'analyzing' || importStatus?.status === 'analyzing') && (
                            <div className="mt-4 pt-4 border-t border-border">
                              <div className="flex justify-between text-xs text-foreground-secondary mb-2">
                                <span>Analyzing dependencies...</span>
                                <span>{importStatus.ready} / {importStatus.total}</span>
                              </div>
                              <div className="h-1 bg-border rounded-full overflow-hidden">
                                <div className="h-full bg-primary transition-all duration-500" style={{ width: `${Math.round((importStatus.ready / importStatus.total) * 100)}%` }} />
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      /* No Connected Repository – status only */
                      <div>
                        <h3 className="text-base font-semibold text-foreground mb-1">Connected Repository</h3>
                        <p className="text-sm text-foreground-secondary mb-4">
                          This repository is linked for automatic dependency updates.
                        </p>
                        <div className="flex items-center gap-3 p-3 rounded-lg border border-border bg-background min-h-[52px]">
                          <span className="text-sm text-foreground-secondary">Not connected</span>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="px-6 py-3 bg-black/20 border-t border-border">
                    <p className="text-xs text-foreground-secondary">
                      Connected repositories will automatically resync on new commits.
                    </p>
                  </div>
                </div>

                {/* Select project (monorepo) dialog */}
                {repoToConnect && scanResult && scanResult.potentialProjects.length > 0 && !scanLoading && (
                  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={closeSelectProjectDialog}>
                    <div
                      className="bg-background-card border border-border rounded-lg shadow-lg max-w-md w-full p-6 space-y-4"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <h3 className="text-base font-semibold text-foreground">Select project to track</h3>
                      <p className="text-sm text-foreground-secondary">
                        {repoToConnect.full_name} — choose which package to connect to this project.
                      </p>
                      {scanError && (
                        <div className="text-sm text-destructive bg-destructive/10 border border-destructive/30 rounded-lg p-3">
                          {scanError}
                        </div>
                      )}
                      <div className="divide-y divide-border rounded-lg border border-border overflow-hidden max-h-64 overflow-y-auto">
                        {scanResult.potentialProjects.map((p) => {
                          const isSelected = selectedPackagePath === p.path;
                          const isDisabled = p.isLinked;
                          return (
                            <button
                              key={p.path || '(root)'}
                              type="button"
                              disabled={isDisabled}
                              onClick={() => !isDisabled && setSelectedPackagePath(p.path)}
                              className={`w-full px-4 py-3 flex items-center justify-between gap-3 text-left transition-colors ${
                                isDisabled ? 'opacity-60 cursor-not-allowed bg-background-subtle/50' : 'hover:bg-background-subtle/50'
                              } ${isSelected ? 'ring-inset ring-2 ring-primary/50 bg-primary/5' : ''}`}
                            >
                              <div className="min-w-0">
                                <div className="text-sm font-medium text-foreground truncate">{p.name}</div>
                                <div className="text-xs text-foreground-secondary">{p.path === '' ? 'Root' : p.path}</div>
                              </div>
                              {p.isLinked && (
                                <span className="flex items-center gap-1 text-xs text-foreground-secondary shrink-0" title={p.linkedByProjectName ? `Linked to ${p.linkedByProjectName}` : 'Already linked'}>
                                  <Lock className="h-4 w-4" />
                                  {p.linkedByProjectName ? `Linked to ${p.linkedByProjectName}` : 'Linked'}
                                </span>
                              )}
                            </button>
                          );
                        })}
                      </div>
                      <div className="flex justify-end gap-2 pt-2">
                        <Button variant="outline" onClick={closeSelectProjectDialog}>
                          Cancel
                        </Button>
                        <Button
                          disabled={scanResult.potentialProjects.find((p) => p.path === selectedPackagePath)?.isLinked}
                          onClick={() => handleConnectWithPath(selectedPackagePath)}
                        >
                          Connect
                        </Button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Transfer Project Card */}
                <div className="bg-background-card border border-border rounded-lg overflow-visible">
                  <div className="p-6">
                    <h3 className="text-base font-semibold text-foreground mb-1">Transfer Project</h3>
                    <p className="text-sm text-foreground-secondary mb-4">
                      Transfer this project to another team within your organization.
                    </p>
                    {teams.length > 0 || loadingTeams ? (
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <label className="text-sm font-medium text-foreground">Owner Team</label>
                          <div className="relative" ref={teamDropdownRef}>
                            <button
                              type="button"
                              onClick={() => setShowTeamDropdown(!showTeamDropdown)}
                              className="max-w-md w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between hover:border-foreground-secondary/50 transition-all"
                            >
                              <div className="flex items-center gap-2 flex-1 min-w-0 text-left">
                                {loadingTeams ? (
                                  <>
                                    <div className="h-5 w-5 rounded-full bg-muted animate-pulse flex-shrink-0" />
                                    <div className="h-4 w-36 bg-muted rounded animate-pulse" />
                                  </>
                                ) : selectedTeamId ? (
                                  (() => {
                                    const selectedTeam = teams.find(t => t.id === selectedTeamId);
                                    if (!selectedTeam) return <span className="text-foreground-secondary">Select a team...</span>;
                                    return (
                                      <>
                                        {selectedTeam.avatar_url ? (
                                          <img
                                            src={selectedTeam.avatar_url}
                                            alt={selectedTeam.name}
                                            className="h-5 w-5 rounded-full object-cover border border-border flex-shrink-0"
                                          />
                                        ) : (
                                          <img
                                            src="/images/team_profile.png"
                                            alt={selectedTeam.name}
                                            className="h-5 w-5 rounded-full object-cover border border-border flex-shrink-0"
                                          />
                                        )}
                                        <span className="truncate">{selectedTeam.name}</span>
                                      </>
                                    );
                                  })()
                                ) : (
                                  <span className="text-foreground-secondary">Select a team...</span>
                                )}
                              </div>
                              <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform ${showTeamDropdown ? 'rotate-180' : ''}`} />
                            </button>

                            {showTeamDropdown && !loadingTeams && (
                              <div className="absolute z-50 w-full max-w-md mt-2 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden">
                                <div className="max-h-60 overflow-auto">
                                  <div className="py-1">
                                    {teams.map((team) => {
                                      const isSelected = team.id === selectedTeamId;
                                      const isCurrentTeam = project?.team_ids?.includes(team.id);

                                      return (
                                        <button
                                          key={team.id}
                                          type="button"
                                          onClick={() => {
                                            setSelectedTeamId(team.id);
                                            setShowTeamDropdown(false);
                                          }}
                                          className="w-full px-3 py-2.5 flex items-center gap-3 hover:bg-table-hover transition-colors text-left"
                                        >
                                          {team.avatar_url ? (
                                            <img
                                              src={team.avatar_url}
                                              alt={team.name}
                                              className="h-8 w-8 rounded-full object-cover border border-border flex-shrink-0"
                                            />
                                          ) : (
                                            <img
                                              src="/images/team_profile.png"
                                              alt={team.name}
                                              className="h-8 w-8 rounded-full object-cover border border-border flex-shrink-0"
                                            />
                                          )}
                                          <div className="flex-1 min-w-0">
                                            <div className="text-sm font-medium text-foreground truncate">
                                              {team.name}
                                            </div>
                                            {team.description && (
                                              <div className="text-xs text-foreground-secondary truncate">
                                                {team.description}
                                              </div>
                                            )}
                                          </div>
                                          {isSelected && (
                                            <Check className="h-4 w-4 text-primary flex-shrink-0" />
                                          )}
                                        </button>
                                      );
                                    })}
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-foreground-secondary bg-black/20 rounded-lg p-3 border border-border">
                        <Users className="h-4 w-4 flex-shrink-0" />
                        <span>No teams available. Create a team first to transfer this project.</span>
                      </div>
                    )}
                  </div>
                  {teams.length > 0 && (
                    <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                      <p className="text-xs text-foreground-secondary">
                        This will change which team owns this project.
                      </p>
                      <Button
                        onClick={handleTransferProject}
                        variant="outline"
                        size="sm"
                        className="h-8"
                        disabled={!selectedTeamId || isTransferring || projectTeams?.owner_team?.id === selectedTeamId}
                      >
                        {isTransferring ? (
                          <>
                            <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                            Transferring
                          </>
                        ) : (
                          'Transfer'
                        )}
                      </Button>
                    </div>
                  )}
                </div>

                {/* Danger Zone */}
                <div className="border border-destructive/30 rounded-lg overflow-hidden bg-destructive/5">
                  <div className="px-6 py-3 border-b border-destructive/30 bg-destructive/10">
                    <h3 className="text-sm font-semibold text-destructive uppercase tracking-wide">Danger Zone</h3>
                  </div>
                  <div className="p-6">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <h4 className="text-base font-semibold text-foreground mb-1">Delete Project</h4>
                        <p className="text-sm text-foreground-secondary">
                          Permanently delete this project and all of its data. This action cannot be undone.
                        </p>
                      </div>
                      {!showDeleteConfirm && project && (
                        <Button
                          onClick={() => setShowDeleteConfirm(true)}
                          variant="outline"
                          size="sm"
                          className="flex-shrink-0 h-8 border-destructive/50 text-destructive hover:bg-destructive/10 hover:border-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5 mr-2" />
                          Delete
                        </Button>
                      )}
                    </div>

                    {showDeleteConfirm && project && (
                      <div className="mt-4 p-4 bg-background/50 rounded-lg border border-destructive/30 space-y-4">
                        <p className="text-sm text-foreground">
                          To confirm deletion, type <strong className="text-destructive font-mono bg-destructive/10 px-1.5 py-0.5 rounded">{project.name}</strong> below:
                        </p>
                        <input
                          type="text"
                          value={deleteConfirmText}
                          onChange={(e) => setDeleteConfirmText(e.target.value)}
                          placeholder={project.name}
                          className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-all"
                        />
                        <div className="flex gap-2">
                          <Button
                            onClick={handleDelete}
                            variant="destructive"
                            size="sm"
                            disabled={deleteConfirmText !== project.name || isDeletingProject}
                            className="h-8"
                          >
                            {isDeletingProject ? (
                              <>
                                <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                                Deleting
                              </>
                            ) : (
                              <>
                                <Trash2 className="h-3.5 w-3.5 mr-2" />
                                Delete Forever
                              </>
                            )}
                          </Button>
                          <Button
                            onClick={() => {
                              setShowDeleteConfirm(false);
                              setDeleteConfirmText('');
                            }}
                            variant="ghost"
                            size="sm"
                            className="h-8"
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeSection === 'access' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">Access Settings</h2>
                  <p className="text-foreground-secondary mt-1">
                    Manage who can access this project and their permissions.
                  </p>
                </div>

                {loadingProjectTeams ? (
                  <>
                    {/* Owner Team Loading Skeleton */}
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="p-6">
                        <div className="flex items-center gap-2 mb-4">
                          <Crown className="h-5 w-5 text-amber-500" />
                          <h3 className="text-base font-semibold text-foreground">Owner Team</h3>
                          <span className="ml-2 px-2 py-0.5 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs rounded-full">
                            Full Control
                          </span>
                        </div>
                        <p className="text-sm text-foreground-secondary mb-4">
                          The owner team has full control over this project including settings and member management.
                        </p>
                        <div className="flex items-center gap-3 p-3 bg-background rounded-lg border border-border animate-pulse">
                          <div className="h-10 w-10 bg-muted rounded-full"></div>
                          <div className="flex-1 min-w-0">
                            <div className="h-4 bg-muted rounded w-32 mb-1"></div>
                            <div className="h-3 bg-muted rounded w-48"></div>
                          </div>
                        </div>
                      </div>
                      <div className="px-6 py-3 bg-black/20 border-t border-border">
                        <p className="text-xs text-foreground-secondary">
                          Transfer ownership in the General settings tab.
                        </p>
                      </div>
                    </div>

                    {/* Contributing Teams Loading Skeleton */}
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-border bg-black/20 flex items-center justify-between">
                        <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                          Contributing Teams
                        </span>
                        <div className="h-7 w-24 bg-muted rounded animate-pulse"></div>
                      </div>
                      <div className="divide-y divide-border">
                        {[1, 2].map((i) => (
                          <div key={i} className="px-4 py-3 flex items-center justify-between animate-pulse">
                            <div className="flex items-center gap-3 flex-1">
                              <div className="h-10 w-10 bg-muted rounded-full"></div>
                              <div className="flex-1 min-w-0">
                                <div className="h-4 bg-muted rounded w-28 mb-1"></div>
                                <div className="h-3 bg-muted rounded w-40"></div>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Additional Members Loading Skeleton */}
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-border bg-black/20 flex items-center justify-between">
                        <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                          Additional Members
                        </span>
                        <div className="h-7 w-28 bg-muted rounded animate-pulse"></div>
                      </div>
                      <div className="divide-y divide-border">
                        {[1, 2, 3].map((i) => (
                          <div key={i} className="px-4 py-3 flex items-center justify-between animate-pulse">
                            <div className="flex items-center gap-3 flex-1">
                              <div className="h-10 w-10 bg-muted rounded-full"></div>
                              <div className="flex-1 min-w-0">
                                <div className="h-4 bg-muted rounded w-32 mb-1"></div>
                                <div className="h-3 bg-muted rounded w-44"></div>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    {/* Owner Team Card */}
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="p-6">
                        <div className="flex items-center gap-2 mb-4">
                          <Crown className="h-5 w-5 text-amber-500" />
                          <h3 className="text-base font-semibold text-foreground">Owner Team</h3>
                          <span className="ml-2 px-2 py-0.5 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-xs rounded-full">
                            Full Control
                          </span>
                        </div>
                        <p className="text-sm text-foreground-secondary mb-4">
                          The owner team has full control over this project including settings and member management.
                        </p>
                        {projectTeams?.owner_team ? (
                          <div className="flex items-center gap-3 p-3 bg-background rounded-lg border border-border">
                            {projectTeams.owner_team.avatar_url ? (
                              <img
                                src={projectTeams.owner_team.avatar_url}
                                alt={projectTeams.owner_team.name}
                                className="h-10 w-10 rounded-full object-cover border border-border"
                              />
                            ) : (
                              <img
                                src="/images/team_profile.png"
                                alt={projectTeams.owner_team.name}
                                className="h-10 w-10 rounded-full object-cover border border-border"
                              />
                            )}
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-foreground truncate">
                                {projectTeams.owner_team.name}
                              </div>
                              {projectTeams.owner_team.description && (
                                <div className="text-xs text-foreground-secondary truncate">
                                  {projectTeams.owner_team.description}
                                </div>
                              )}
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-sm text-foreground-secondary bg-black/20 rounded-lg p-3 border border-border">
                            <Users className="h-4 w-4 flex-shrink-0" />
                            <span>No owner team assigned.</span>
                          </div>
                        )}
                      </div>
                      <div className="px-6 py-3 bg-black/20 border-t border-border">
                        <p className="text-xs text-foreground-secondary">
                          Transfer ownership in the General settings tab.
                        </p>
                      </div>
                    </div>

                    {/* Contributing Teams Card */}
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-border bg-black/20 flex items-center justify-between">
                        <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                          Contributing Teams
                        </span>
                        <Button
                          onClick={() => setShowAddTeamSidepanel(true)}
                          size="sm"
                          className="h-7 text-xs"
                        >
                          <Plus className="h-3 w-3 mr-1.5" />
                          Add Team
                        </Button>
                      </div>
                      {projectTeams && projectTeams.contributing_teams.length > 0 ? (
                        <div className="divide-y divide-border">
                          {projectTeams.contributing_teams.map((team) => (
                            <div key={team.id} className="px-4 py-3 flex items-center justify-between hover:bg-table-hover transition-colors">
                              <div className="flex items-center gap-3 flex-1">
                                <img
                                  src={team.avatar_url || '/images/team_profile.png'}
                                  alt={team.name}
                                  className="h-10 w-10 rounded-full object-cover border border-border"
                                  onError={(e) => {
                                    e.currentTarget.src = '/images/team_profile.png';
                                  }}
                                />
                                <div className="flex-1 min-w-0">
                                  <div className="text-sm font-medium text-foreground truncate">
                                    {team.name}
                                  </div>
                                  {team.description && (
                                    <div className="text-xs text-foreground-secondary truncate">
                                      {team.description}
                                    </div>
                                  )}
                                </div>
                              </div>
                              <Button
                                onClick={() => handleRemoveContributingTeam(team.id)}
                                variant="ghost"
                                size="sm"
                                className="h-8 text-foreground-secondary hover:text-destructive hover:bg-destructive/10"
                                disabled={removingTeamId === team.id}
                              >
                                {removingTeamId === team.id ? (
                                  <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
                                ) : (
                                  <X className="h-4 w-4" />
                                )}
                              </Button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="px-6 py-8 text-center">
                          <Users className="h-10 w-10 text-foreground-secondary/50 mx-auto mb-3" />
                          <p className="text-sm text-foreground-secondary">
                            No contributing teams yet. Add teams to give them access to this project.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* Direct Members Card */}
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-border bg-black/20 flex items-center justify-between">
                        <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                          Additional Members
                        </span>
                        <Button
                          onClick={() => setShowAddMemberSidepanel(true)}
                          size="sm"
                          className="h-7 text-xs"
                        >
                          <Plus className="h-3 w-3 mr-1.5" />
                          Add Member
                        </Button>
                      </div>
                      {loadingMembers ? (
                        <div className="divide-y divide-border">
                          {[1, 2].map((i) => (
                            <div key={i} className="px-4 py-3 flex items-center justify-between animate-pulse">
                              <div className="flex items-center gap-3 flex-1">
                                <div className="h-10 w-10 bg-muted rounded-full"></div>
                                <div className="flex-1 min-w-0">
                                  <div className="h-4 bg-muted rounded w-24 mb-1"></div>
                                  <div className="h-3 bg-muted rounded w-32"></div>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : directMembers.length > 0 ? (
                        <div className="divide-y divide-border">
                          {directMembers.map((member) => (
                            <div key={member.user_id} className="px-4 py-3 flex items-center justify-between hover:bg-table-hover transition-colors">
                              <div className="flex items-center gap-3 flex-1">
                                <img
                                  src={member.avatar_url || '/images/blank_profile_image.png'}
                                  alt={member.full_name || member.email || ''}
                                  className="h-10 w-10 rounded-full object-cover border border-border"
                                  referrerPolicy="no-referrer"
                                  onError={(e) => {
                                    e.currentTarget.src = '/images/blank_profile_image.png';
                                  }}
                                />
                                <div className="flex-1 min-w-0">
                                  <div className="text-sm font-medium text-foreground truncate">
                                    {member.full_name || member.email}
                                  </div>
                                  {member.full_name && (
                                    <div className="text-xs text-foreground-secondary truncate">
                                      {member.email}
                                    </div>
                                  )}
                                </div>
                              </div>
                              <Button
                                onClick={() => handleRemoveDirectMember(member.user_id)}
                                variant="ghost"
                                size="sm"
                                className="h-8 text-foreground-secondary hover:text-destructive hover:bg-destructive/10"
                                disabled={removingMemberId === member.user_id}
                              >
                                {removingMemberId === member.user_id ? (
                                  <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
                                ) : (
                                  <X className="h-4 w-4" />
                                )}
                              </Button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="px-6 py-8 text-center">
                          <UserPlus className="h-10 w-10 text-foreground-secondary/50 mx-auto mb-3" />
                          <p className="text-sm text-foreground-secondary">
                            No direct members yet. Add members who need individual access.
                          </p>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {activeSection === 'notifications' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">Notification Settings</h2>
                  <p className="text-foreground-secondary mt-1">
                    Configure how you receive notifications for this project.
                  </p>
                </div>

                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <div className="p-6">
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <Bell className="h-12 w-12 text-foreground-secondary/50 mb-4" />
                      <h3 className="text-lg font-semibold text-foreground mb-2">Notification Preferences</h3>
                      <p className="text-sm text-foreground-secondary max-w-md">
                        Project-level notification settings are coming soon. You'll be able to customize alerts for vulnerabilities, dependency updates, and compliance changes here.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeSection === 'policies' && (
              <div className="space-y-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground">Policies</h2>
                    <p className="text-foreground-secondary mt-1">
                      View organization policy as code. Request an exception to use different policy for this project.
                    </p>
                  </div>
                  {!policiesLoading && projectPolicies && (
                    <div className="flex items-center gap-2 shrink-0">
                      {projectPolicies.pending_exception ? (
                        <Badge variant="warning">Policy exception under review</Badge>
                      ) : (projectPolicies.effective_policy_code !== projectPolicies.inherited_policy_code && projectPolicies.inherited_policy_code !== undefined) ? (
                        <Badge variant="outline">Project policy</Badge>
                      ) : (
                        <Badge variant="outline">Inherited from org</Badge>
                      )}
                    </div>
                  )}
                </div>
                {policiesLoading ? (
                  <div className="rounded-lg border border-border bg-[#1d1f21] overflow-hidden p-4 min-h-[320px] animate-pulse" />
                ) : projectPolicies ? (
                  <div className="space-y-4">
                    {!projectPolicies.pending_exception && (
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setPolicyView('org')}
                          className={`px-3 py-1.5 text-sm font-medium rounded-md ${policyView === 'org' ? 'bg-background-card text-foreground' : 'text-foreground-secondary hover:text-foreground'}`}
                        >
                          Org policy
                        </button>
                        <button
                          type="button"
                          onClick={() => setPolicyView('project')}
                          className={`px-3 py-1.5 text-sm font-medium rounded-md ${policyView === 'project' ? 'bg-background-card text-foreground' : 'text-foreground-secondary hover:text-foreground'}`}
                        >
                          Project policy
                        </button>
                      </div>
                    )}
                    {projectPolicies.pending_exception ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <p className="text-sm text-foreground-secondary">Requested policy (pending review)</p>
                          {canViewSettings && (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={policyCancelling}
                              onClick={async () => {
                                if (!organizationId || !projectPolicies.pending_exception?.id) return;
                                setPolicyCancelling(true);
                                try {
                                  await api.deletePolicyException(organizationId, projectPolicies.pending_exception.id);
                                  toast({ title: 'Request withdrawn', description: 'Exception request has been cancelled.' });
                                  await loadPoliciesSection();
                                } catch (e: any) {
                                  toast({ title: 'Error', description: e.message || 'Failed to cancel request', variant: 'destructive' });
                                } finally {
                                  setPolicyCancelling(false);
                                }
                              }}
                            >
                              {policyCancelling ? 'Cancelling…' : 'Cancel request'}
                            </Button>
                          )}
                        </div>
                        <PolicyCodeEditor
                          value={projectPolicies.pending_exception.requested_policy_code}
                          onChange={() => {}}
                          readOnly
                          minHeight="360px"
                        />
                      </div>
                    ) : (() => {
                      const effectiveCode = projectPolicies.effective_policy_code ?? projectPolicies.inherited_policy_code ?? orgPoliciesCode;
                      const isDirty = policyEditorCode !== effectiveCode;
                      return (
                      <div className="relative">
                        <PolicyCodeEditor
                          value={policyEditorCode}
                          onChange={(code) => {
                            setPolicyEditorCode(code);
                          }}
                          readOnly={!canViewSettings}
                          minHeight="360px"
                        />
                        {canViewSettings && isDirty && (
                          <div className="absolute top-3 right-3 flex flex-wrap items-center gap-2 z-10">
                            <input
                              type="text"
                              placeholder="Reason for exception (optional)"
                              value={policyExceptionReason}
                              onChange={(e) => setPolicyExceptionReason(e.target.value)}
                              className="px-3 py-1.5 text-sm border border-border rounded-md bg-background-card text-foreground placeholder:text-foreground-secondary max-w-[220px]"
                            />
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => {
                                setPolicyEditorCode(projectPolicies.effective_policy_code ?? projectPolicies.inherited_policy_code ?? orgPoliciesCode);
                                setPolicyExceptionReason('');
                              }}
                              disabled={policySubmitting}
                            >
                              <Undo2 className="h-4 w-4 mr-1.5" />
                              Discard
                            </Button>
                            <Button
                              size="sm"
                              disabled={policySubmitting || !policyExceptionReason.trim()}
                              onClick={async () => {
                                if (!organizationId || !projectId || !policyExceptionReason.trim()) return;
                                setPolicySubmitting(true);
                                try {
                                  await api.createPolicyException(organizationId, projectId, {
                                    reason: policyExceptionReason.trim(),
                                    requested_policy_code: policyEditorCode,
                                  });
                                  toast({ title: 'Exception requested', description: 'Your request has been sent for review.' });
                                  setPolicyExceptionReason('');
                                  await loadPoliciesSection();
                                } catch (e: any) {
                                  toast({ title: 'Error', description: e.message || 'Failed to submit exception request', variant: 'destructive' });
                                } finally {
                                  setPolicySubmitting(false);
                                }
                              }}
                            >
                              {policySubmitting ? 'Submitting…' : 'Apply for exception'}
                            </Button>
                          </div>
                        )}
                      </div>
                    ); })()}
                  </div>
                ) : (
                  <div className="rounded-lg border border-border p-8 text-center text-foreground-secondary text-sm">
                    Failed to load policies.
                  </div>
                )}
              </div>
            )}

            {activeSection === 'cicd' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">CI/CD</h2>
                  <p className="text-foreground-secondary mt-1">
                    Manage PR blockers that prevent merging when dependency security or policy checks fail.
                  </p>
                </div>

                <Card>
                  <CardHeader className="pb-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <GitPullRequest className="h-5 w-5 text-foreground-secondary" />
                        <CardTitle>PR Blockers</CardTitle>
                      </div>
                      <Button
                        onClick={() => setShowGuardrailsSidepanel(true)}
                        variant="outline"
                        size="sm"
                        disabled={guardrailsLoading}
                      >
                        Configure
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-foreground-secondary mb-4">
                      Configure rules that block PR merges based on dependency security and health.
                    </p>

                    {guardrailsLoading ? (
                      <div className="animate-pulse space-y-3">
                        <div className="h-4 bg-muted rounded w-3/4"></div>
                        <div className="h-4 bg-muted rounded w-1/2"></div>
                      </div>
                    ) : prGuardrails ? (
                      (() => {
                        const hasVulnBlocking = prGuardrails.block_critical_vulns || prGuardrails.block_high_vulns || prGuardrails.block_medium_vulns || prGuardrails.block_low_vulns;
                        const hasAnyGuardrails = hasVulnBlocking || prGuardrails.block_policy_violations || prGuardrails.block_transitive_vulns;

                        if (!hasAnyGuardrails) {
                          return <p className="text-sm text-foreground-secondary">No PR blockers configured</p>;
                        }

                        return (
                          <div className="space-y-4">
                            {hasVulnBlocking && (
                              <div className="flex items-start gap-3">
                                <AlertTriangle className="h-4 w-4 text-foreground-secondary mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <h4 className="text-sm font-medium text-foreground mb-2">Vulnerability blocking</h4>
                                  <div className="flex flex-wrap gap-2">
                                    {prGuardrails.block_critical_vulns && (
                                      <Badge variant="destructive">Critical</Badge>
                                    )}
                                    {prGuardrails.block_high_vulns && (
                                      <Badge variant="warning">High</Badge>
                                    )}
                                    {prGuardrails.block_medium_vulns && (
                                      <Badge variant="default">Medium</Badge>
                                    )}
                                    {prGuardrails.block_low_vulns && (
                                      <Badge variant="outline">Low</Badge>
                                    )}
                                  </div>
                                </div>
                              </div>
                            )}
                            {prGuardrails.block_policy_violations && (
                              <Badge variant="outline">Block policy violations (license)</Badge>
                            )}
                            {prGuardrails.block_transitive_vulns && (
                              <Badge variant="outline">Block transitive vulnerabilities</Badge>
                            )}
                          </div>
                        );
                      })()
                    ) : (
                      <p className="text-sm text-foreground-secondary">Unable to load PR blockers</p>
                    )}
                  </CardContent>
                </Card>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* PR Guardrails Sidepanel */}
      {showGuardrailsSidepanel && prGuardrails && (
        <PRGuardrailsSidepanel
          guardrails={prGuardrails}
          onSave={handleSaveGuardrails}
          onCancel={() => setShowGuardrailsSidepanel(false)}
          isLoading={savingGuardrails}
          projectName={project?.name || 'Project'}
        />
      )}

      {/* Add Team Sidepanel */}
      {showAddTeamSidepanel && (
        <div className="fixed inset-0 z-50">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setShowAddTeamSidepanel(false);
              setTeamSearchQuery('');
              setSelectedTeamsToAdd([]);
            }}
          />

          {/* Side Panel */}
          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-6 py-5 border-b border-border flex items-center justify-between flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Add Contributing Teams</h2>
              <button
                onClick={() => {
                  setShowAddTeamSidepanel(false);
                  setTeamSearchQuery('');
                  setSelectedTeamsToAdd([]);
                }}
                className="text-foreground-secondary hover:text-foreground transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
              <p className="text-sm text-foreground-secondary mb-4">
                Select teams to give them access to this project. Contributing teams can view the project but cannot manage settings.
              </p>

              {/* Search */}
              <div className="relative mb-4">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                <input
                  type="text"
                  placeholder="Search teams..."
                  value={teamSearchQuery}
                  onChange={(e) => setTeamSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                />
              </div>

              {/* Teams List */}
              {filteredTeamsForAdding.length > 0 ? (
                <div className="space-y-2">
                  {filteredTeamsForAdding.map((team) => {
                    const isSelected = selectedTeamsToAdd.includes(team.id);
                    return (
                      <button
                        key={team.id}
                        onClick={() => toggleTeamSelection(team.id)}
                        className={`w-full flex items-center gap-3 p-3 rounded-lg border transition-all text-left ${isSelected
                          ? 'bg-primary/10 border-primary'
                          : 'bg-background-card border-border hover:border-primary/50'
                          }`}
                      >
                        <img
                          src={team.avatar_url || '/images/team_profile.png'}
                          alt={team.name}
                          className="h-10 w-10 rounded-full object-cover border border-border"
                          onError={(e) => {
                            e.currentTarget.src = '/images/team_profile.png';
                          }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-foreground truncate">
                            {team.name}
                          </div>
                          {team.description && (
                            <div className="text-xs text-foreground-secondary truncate">
                              {team.description}
                            </div>
                          )}
                        </div>
                        <div className={`h-5 w-5 rounded border flex items-center justify-center transition-colors ${isSelected
                          ? 'bg-primary border-primary text-primary-foreground'
                          : 'border-border'
                          }`}>
                          {isSelected && <Check className="h-3 w-3" />}
                        </div>
                      </button>
                    );
                  })}
                </div>
              ) : availableTeamsForAdding.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Users className="h-12 w-12 text-foreground-secondary/50 mb-4" />
                  <h3 className="text-base font-medium text-foreground mb-2">No Teams Available</h3>
                  <p className="text-sm text-foreground-secondary">
                    All teams in your organization are already associated with this project.
                  </p>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Search className="h-12 w-12 text-foreground-secondary/50 mb-4" />
                  <h3 className="text-base font-medium text-foreground mb-2">No Results</h3>
                  <p className="text-sm text-foreground-secondary">
                    No teams match your search query.
                  </p>
                </div>
              )}
            </div>

            {/* Footer with Add Button */}
            {filteredTeamsForAdding.length > 0 && (
              <div className="px-6 py-4 border-t border-border flex items-center justify-between flex-shrink-0">
                <p className="text-sm text-foreground-secondary">
                  {selectedTeamsToAdd.length} team{selectedTeamsToAdd.length !== 1 ? 's' : ''} selected
                </p>
                <Button
                  onClick={handleAddContributingTeams}
                  disabled={selectedTeamsToAdd.length === 0 || addingTeam}
                >
                  {addingTeam ? (
                    <>
                      <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                      Adding
                    </>
                  ) : (
                    <>
                      <Plus className="h-4 w-4 mr-2" />
                      Add {selectedTeamsToAdd.length > 0 ? `(${selectedTeamsToAdd.length})` : ''}
                    </>
                  )}
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Add Member Sidepanel */}
      {showAddMemberSidepanel && (
        <div className="fixed inset-0 z-50">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setShowAddMemberSidepanel(false);
              setMemberSearchQuery('');
              setSelectedMembersToAdd([]);
            }}
          />

          {/* Side Panel */}
          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-6 py-5 border-b border-border flex items-center justify-between flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Add Project Members</h2>
              <button
                onClick={() => {
                  setShowAddMemberSidepanel(false);
                  setMemberSearchQuery('');
                  setSelectedMembersToAdd([]);
                }}
                className="text-foreground-secondary hover:text-foreground transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
              <p className="text-sm text-foreground-secondary mb-4">
                Select members to give them direct access to this project. Members already on teams with access are not shown.
              </p>

              {/* Search */}
              <div className="relative mb-4">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                <input
                  type="text"
                  placeholder="Search members..."
                  value={memberSearchQuery}
                  onChange={(e) => setMemberSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                />
              </div>

              {/* Members List */}
              {filteredMembersForAdding.length > 0 ? (
                <div className="space-y-2">
                  {filteredMembersForAdding.map((member) => {
                    const isSelected = selectedMembersToAdd.includes(member.user_id);
                    return (
                      <button
                        key={member.user_id}
                        onClick={() => toggleMemberSelection(member.user_id)}
                        className={`w-full flex items-center gap-3 p-3 rounded-lg border transition-all text-left ${isSelected
                          ? 'bg-primary/10 border-primary'
                          : 'bg-background-card border-border hover:border-primary/50'
                          }`}
                      >
                        <img
                          src={member.avatar_url || '/images/blank_profile_image.png'}
                          alt={member.full_name || member.email}
                          className="h-10 w-10 rounded-full object-cover border border-border"
                          referrerPolicy="no-referrer"
                          onError={(e) => {
                            e.currentTarget.src = '/images/blank_profile_image.png';
                          }}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-foreground truncate">
                            {member.full_name || member.email}
                          </div>
                          {member.full_name && (
                            <div className="text-xs text-foreground-secondary truncate">
                              {member.email}
                            </div>
                          )}
                        </div>
                        <div className={`h-5 w-5 rounded border flex items-center justify-center transition-colors ${isSelected
                          ? 'bg-primary border-primary text-primary-foreground'
                          : 'border-border'
                          }`}>
                          {isSelected && <Check className="h-3 w-3" />}
                        </div>
                      </button>
                    );
                  })}
                </div>
              ) : availableMembersForAdding.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <UserPlus className="h-12 w-12 text-foreground-secondary/50 mb-4" />
                  <h3 className="text-base font-medium text-foreground mb-2">No Members Available</h3>
                  <p className="text-sm text-foreground-secondary">
                    All organization members already have access through teams or direct membership.
                  </p>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <Search className="h-12 w-12 text-foreground-secondary/50 mb-4" />
                  <h3 className="text-base font-medium text-foreground mb-2">No Results</h3>
                  <p className="text-sm text-foreground-secondary">
                    No members match your search query.
                  </p>
                </div>
              )}
            </div>

            {/* Footer with Add Button */}
            {filteredMembersForAdding.length > 0 && (
              <div className="px-6 py-4 border-t border-border flex items-center justify-between flex-shrink-0">
                <p className="text-sm text-foreground-secondary">
                  {selectedMembersToAdd.length} member{selectedMembersToAdd.length !== 1 ? 's' : ''} selected
                </p>
                <Button
                  onClick={handleAddDirectMembers}
                  disabled={selectedMembersToAdd.length === 0 || addingMember}
                >
                  {addingMember ? (
                    <>
                      <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                      Adding
                    </>
                  ) : (
                    <>
                      <Plus className="h-4 w-4 mr-2" />
                      Add {selectedMembersToAdd.length > 0 ? `(${selectedMembersToAdd.length})` : ''}
                    </>
                  )}
                </Button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
