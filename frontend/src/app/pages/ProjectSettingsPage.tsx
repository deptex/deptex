import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { useOutletContext, useNavigate, useParams, useLocation, Link, useSearchParams } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { Settings, Trash2, Shield, Bell, ChevronDown, Users, Plus, X, Search, Crown, UserPlus, FolderOpen, Folder, Copy, Lock, Check, BookOpen, Sparkles, Clock, Loader2, Eye, Ban, Mail, Webhook, GitBranch, Info, RefreshCw, GitCommit } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../../components/ui/dialog';
import { Label } from '../../components/ui/label';
import { Input } from '../../components/ui/input';
import { api, ProjectWithRole, ProjectPermissions, Team, ProjectTeamsResponse, ProjectContributingTeam, ProjectMember, OrganizationMember, ProjectRepository, ProjectImportStatus, type ProjectEffectivePolicies, type ProjectPolicyException, type AssetTier, type RepoWithProvider, type CiCdConnection } from '../../lib/api';
import NotificationRulesSection from './NotificationRulesSection';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { FrameworkIcon } from '../../components/framework-icon';
import { PolicyCodeEditor } from '../../components/PolicyCodeEditor';
import { PolicyAIAssistant } from '../../components/PolicyAIAssistant';
import { PolicyExceptionSidebar } from '../../components/PolicyExceptionSidebar';
import { SyncDetailSidebar, type SyncLogEntry } from '../../components/SyncDetailSidebar';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { ProjectTeamSelect } from '../../components/ProjectTeamSelect';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select';
import { Switch } from '../../components/ui/switch';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

/** Repo name without account prefix: "owner/repo" -> "repo" */
function repoNameOnly(fullName: string): string {
  const parts = fullName.split('/');
  return parts.length > 1 ? parts[parts.length - 1] : fullName;
}

/** Display label for package.json path: "Root" or folder name e.g. "Frontend". */
function getWorkspaceDisplayPath(packageJsonPath: string | undefined): string {
  if (!packageJsonPath || packageJsonPath === 'package.json' || packageJsonPath.trim() === '') return 'Root';
  const dir = packageJsonPath.replace(/\/?package\.json$/i, '').trim();
  if (!dir) return 'Root';
  const lastSegment = dir.split('/').filter(Boolean).pop() || dir;
  return lastSegment.charAt(0).toUpperCase() + lastSegment.slice(1).toLowerCase();
}

function formatConnectedAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return '';
  const diff = (Date.now() - new Date(dateStr).getTime()) / 1000;
  const mins = Math.floor(diff / 60);
  const hours = Math.floor(diff / 3600);
  const days = Math.floor(diff / 86400);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

const VALID_PROJECT_SETTINGS_SECTIONS = new Set(['general', 'repository', 'access', 'notifications', 'policies']);

/** Renders a tab-specific content skeleton for the project settings loading state. */
function ProjectSettingsTabSkeleton({ section }: { section: string }) {
  const pulse = 'bg-muted animate-pulse rounded';
  switch (section) {
    case 'general':
      return (
        <div className="space-y-6">
          <div>
            <div className={`h-8 w-48 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-6">
              <div className={`h-4 w-40 ${pulse} mb-2`} />
              <div className={`h-3 w-full max-w-md ${pulse} mb-4`} />
              <div className={`h-10 w-full max-w-md ${pulse}`} />
            </div>
            <div className="p-6 pt-0">
              <div className={`h-4 w-36 ${pulse} mb-2`} />
              <div className={`h-3 w-full max-w-sm ${pulse} mb-4`} />
              <div className={`h-10 w-full max-w-md ${pulse}`} />
            </div>
            <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
              <div className={`h-3 w-48 ${pulse}`} />
              <div className={`h-8 w-16 ${pulse}`} />
            </div>
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-6">
              <div className={`h-4 w-36 ${pulse} mb-2`} />
              <div className={`h-3 w-full max-w-sm ${pulse} mb-4`} />
              <div className={`h-10 w-full max-w-md ${pulse}`} />
            </div>
          </div>
          <div className="border border-destructive/30 rounded-lg overflow-hidden bg-destructive/5">
            <div className="px-6 py-3 border-b border-destructive/30 bg-destructive/10">
              <div className={`h-4 w-24 ${pulse}`} />
            </div>
            <div className="p-6 flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className={`h-4 w-32 ${pulse} mb-2`} />
                <div className={`h-3 w-72 ${pulse}`} />
              </div>
              <div className={`h-8 w-20 ${pulse}`} />
            </div>
          </div>
        </div>
      );
    case 'repository':
      return (
        <div className="space-y-8">
          <div>
            <div className={`h-8 w-40 ${pulse}`} />
          </div>
          <div className="space-y-4">
            <div>
              <div className={`h-5 w-48 ${pulse} mb-2`} />
              <div className={`h-3 w-72 ${pulse}`} />
            </div>
            <div className="flex items-center gap-4 py-5 px-4 rounded-lg border border-border/60 bg-background-content/50 min-h-[80px]">
              <div className="h-12 w-12 rounded-lg bg-muted animate-pulse shrink-0" />
              <div className="flex flex-col gap-2 min-w-0 flex-1">
                <div className={`h-4 w-48 ${pulse}`} />
                <div className={`h-3 w-28 ${pulse}`} />
              </div>
            </div>
          </div>
        </div>
      );
    case 'access':
      return (
        <div className="space-y-6">
          <div>
            <div className={`h-8 w-32 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-5 w-5 rounded bg-muted animate-pulse" />
                <div className={`h-5 w-28 ${pulse}`} />
              </div>
              <div className={`h-3 w-72 ${pulse} mb-4`} />
              <div className="flex items-center gap-3 p-3 bg-background rounded-lg border border-border">
                <div className="h-10 w-10 bg-muted rounded-full animate-pulse" />
                <div className="flex-1 min-w-0">
                  <div className={`h-4 w-32 ${pulse} mb-1`} />
                  <div className={`h-3 w-48 ${pulse}`} />
                </div>
              </div>
            </div>
            <div className="px-6 py-3 bg-black/20 border-t border-border">
              <div className={`h-3 w-56 ${pulse}`} />
            </div>
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 border-b border-border bg-black/20 flex items-center justify-between">
              <div className={`h-4 w-32 ${pulse}`} />
              <div className={`h-7 w-24 ${pulse}`} />
            </div>
            <div className="divide-y divide-border">
              {[1, 2].map((i) => (
                <div key={i} className="px-4 py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    <div className="h-10 w-10 bg-muted rounded-full animate-pulse" />
                    <div className="flex-1 min-w-0">
                      <div className={`h-4 w-28 ${pulse} mb-1`} />
                      <div className={`h-3 w-40 ${pulse}`} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 border-b border-border bg-black/20 flex items-center justify-between">
              <div className={`h-4 w-36 ${pulse}`} />
              <div className={`h-7 w-28 ${pulse}`} />
            </div>
            <div className="divide-y divide-border">
              {[1, 2, 3].map((i) => (
                <div key={i} className="px-4 py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    <div className="h-10 w-10 bg-muted rounded-full animate-pulse" />
                    <div className="flex-1 min-w-0">
                      <div className={`h-4 w-32 ${pulse} mb-1`} />
                      <div className={`h-3 w-44 ${pulse}`} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    case 'notifications':
      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className={`h-8 w-36 ${pulse}`} />
            <div className={`h-9 w-24 ${pulse}`} />
          </div>
          <div className="flex items-center border-b border-border pb-px">
            <div className="flex items-center gap-6">
              <div className={`h-4 w-24 ${pulse} pb-3`} />
              <div className={`h-4 w-20 ${pulse} pb-3`} />
            </div>
          </div>
          <div className="pt-6 space-y-8">
            <div>
              <div className={`h-5 w-48 ${pulse} mb-3`} />
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="px-4 py-2.5 bg-background-card-header border-b border-border">
                  <div className={`h-4 w-16 ${pulse}`} />
                </div>
                <table className="w-full">
                  <thead className="bg-background-subtle/30 border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-2.5"><div className={`h-3 w-16 ${pulse}`} /></th>
                      <th className="text-left px-4 py-2.5"><div className={`h-3 w-20 ${pulse}`} /></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {[1, 2, 3].map((i) => (
                      <tr key={i}>
                        <td className="px-4 py-3"><div className={`h-4 w-20 ${pulse}`} /></td>
                        <td className="px-4 py-3"><div className={`h-4 w-28 ${pulse}`} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div>
              <div className={`h-5 w-40 ${pulse} mb-3`} />
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full">
                  <thead className="bg-background-subtle/30 border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-2.5"><div className={`h-3 w-16 ${pulse}`} /></th>
                      <th className="text-left px-4 py-2.5"><div className={`h-3 w-20 ${pulse}`} /></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {[1, 2].map((i) => (
                      <tr key={i}>
                        <td className="px-4 py-3"><div className={`h-4 w-20 ${pulse}`} /></td>
                        <td className="px-4 py-3"><div className={`h-4 w-28 ${pulse}`} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      );
    case 'policies':
      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className={`h-8 w-24 ${pulse}`} />
            </div>
            <div className="flex items-center gap-2">
              <div className={`h-8 w-24 ${pulse}`} />
              <div className={`h-8 w-16 ${pulse}`} />
            </div>
          </div>
          <div className="flex items-center border-b border-border pb-px">
            <div className="flex items-center gap-6">
              <div className={`h-4 w-20 ${pulse} pb-3`} />
              <div className={`h-4 w-24 ${pulse} pb-3`} />
            </div>
          </div>
          <div className="pt-6 space-y-6">
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-border bg-background-subtle/30">
                <div className={`h-4 w-20 ${pulse}`} />
              </div>
              <div className="p-6">
                <div className={`h-4 w-full max-w-lg ${pulse} mb-3`} />
                <div className={`h-3 w-full max-w-md ${pulse} mb-4`} />
                <div className={`h-24 w-full ${pulse}`} />
              </div>
            </div>
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-border bg-background-subtle/30">
                <div className={`h-4 w-24 ${pulse}`} />
              </div>
              <div className="divide-y divide-border">
                {[1, 2].map((i) => (
                  <div key={i} className="px-4 py-3 flex items-center justify-between">
                    <div className={`h-4 w-32 ${pulse}`} />
                    <div className={`h-5 w-16 ${pulse}`} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    default:
      return (
        <div className="space-y-6">
          <div className={`h-8 w-48 ${pulse}`} />
          <div className={`h-64 w-full ${pulse}`} />
        </div>
      );
  }
}

export default function ProjectSettingsPage() {
  const { project, reloadProject, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId, section: sectionParam } = useParams<{ projectId: string; section?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const activeSection = (sectionParam && VALID_PROJECT_SETTINGS_SECTIONS.has(sectionParam) ? sectionParam : 'general');
  const { toast } = useToast();
  const [projectName, setProjectName] = useState(project?.name || '');
  const [assetTier, setAssetTier] = useState<AssetTier>(project?.asset_tier ?? 'EXTERNAL');
  const [isSaving, setIsSaving] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [isDeletingProject, setIsDeletingProject] = useState(false);

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
  // Pull request comments toggle (repository settings)
  const [pullRequestCommentsEnabled, setPullRequestCommentsEnabled] = useState(true);
  const [autoFixVulnerabilitiesEnabled, setAutoFixVulnerabilitiesEnabled] = useState(false);
  const [selectedSyncLog, setSelectedSyncLog] = useState<SyncLogEntry | null>(null);
  // Transfer project state
  const [teams, setTeams] = useState<Team[]>([]);
  const [loadingTeams, setLoadingTeams] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [isTransferring, setIsTransferring] = useState(false);

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
  const [projectPolicies, setProjectPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [policyCancellingId, setPolicyCancellingId] = useState<string | null>(null);
  const [policyActiveTab, setPolicyActiveTab] = useState<'policies' | 'exceptions'>('policies');
  const [notificationActiveTab, setNotificationActiveTab] = useState<'notifications' | 'destinations'>('notifications');
  const [hasVisitedNotifications, setHasVisitedNotifications] = useState(false);
  const [hasVisitedPolicies, setHasVisitedPolicies] = useState(false);
  const [projectConnections, setProjectConnections] = useState<{ inherited: CiCdConnection[]; team: CiCdConnection[]; project: CiCdConnection[] }>({ inherited: [], team: [], project: [] });
  const [projectConnectionsLoading, setProjectConnectionsLoading] = useState(false);
  const [showJiraPatDialog, setShowJiraPatDialog] = useState(false);
  const [jiraPatBaseUrl, setJiraPatBaseUrl] = useState('');
  const [jiraPatToken, setJiraPatToken] = useState('');
  const [jiraPatSaving, setJiraPatSaving] = useState(false);
  const [showProjectEmailDialog, setShowProjectEmailDialog] = useState(false);
  const [projectEmailToAdd, setProjectEmailToAdd] = useState('');
  const [projectEmailSaving, setProjectEmailSaving] = useState(false);
  const [showProjectCustomDialog, setShowProjectCustomDialog] = useState(false);
  const [projectCustomType, setProjectCustomType] = useState<'notification' | 'ticketing'>('notification');
  const [projectCustomName, setProjectCustomName] = useState('');
  const [projectCustomWebhookUrl, setProjectCustomWebhookUrl] = useState('');
  const [projectCustomSaving, setProjectCustomSaving] = useState(false);

  const [inheritedComplianceBody, setInheritedComplianceBody] = useState('');
  const [inheritedPullRequestBody, setInheritedPullRequestBody] = useState('');
  const [effectiveComplianceBody, setEffectiveComplianceBody] = useState('');
  const [effectivePullRequestBody, setEffectivePullRequestBody] = useState('');
  const [complianceBody, setComplianceBody] = useState('');
  const [pullRequestBody, setPullRequestBody] = useState('');
  const [hasSyncedPolicies, setHasSyncedPolicies] = useState(false);

  const [showExceptionSidebar, setShowExceptionSidebar] = useState<'compliance' | 'pullRequest' | null>(null);
  const [viewingExceptionId, setViewingExceptionId] = useState<string | null>(null);
  const [showAI, setShowAI] = useState(false);
  const [aiPanelVisible, setAiPanelVisible] = useState(false);
  const aiCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const notificationCreateRef = useRef<(() => void) | null>(null);

  // Open Policies section when navigated from "Request Exception" (e.g. compliance table)
  useEffect(() => {
    const state = location.state as { section?: string } | null;
    if (state?.section === 'policies' && organizationId && projectId) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/settings/policies`, { replace: true, state: {} });
    }
  }, [location.state, organizationId, projectId, navigate]);

  // Normalize legacy ?section=... query to path so refresh and back/forward work
  useEffect(() => {
    const qSection = searchParams.get('section');
    if (!organizationId || !projectId || !qSection) return;
    if (VALID_PROJECT_SETTINGS_SECTIONS.has(qSection)) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/settings/${qSection}`, { replace: true });
    }
  }, [organizationId, projectId, searchParams, navigate]);

  // Redirect to settings/general when section param is invalid
  useEffect(() => {
    if (organizationId && projectId && sectionParam && !VALID_PROJECT_SETTINGS_SECTIONS.has(sectionParam)) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/settings/general`, { replace: true });
    }
  }, [organizationId, projectId, sectionParam, navigate]);

  // Sync projectName and assetTier state when project changes
  useEffect(() => {
    if (project?.name) {
      setProjectName(project.name);
    }
    if (project?.asset_tier) {
      setAssetTier(project.asset_tier);
    }
  }, [project?.name, project?.asset_tier]);

  const loadProjectRepositories = async (integrationId?: string) => {
    if (!organizationId || !projectId) return;
    const cached = !integrationId ? api.getCachedProjectRepositories(organizationId, projectId) : null;
    try {
      if (!cached) setRepositoriesLoading(true);
      const targetIntegration = integrationId || undefined;
      const data = await api.getProjectRepositories(organizationId, projectId, targetIntegration);
      setConnectedRepository(data.connectedRepository);
      setRepositories(data.repositories);
      setRepositoriesError(null);
      if (data.connectedRepository?.pull_request_comments_enabled !== undefined) {
        setPullRequestCommentsEnabled(data.connectedRepository.pull_request_comments_enabled !== false);
      }
      if (data.connectedRepository?.auto_fix_vulnerabilities_enabled !== undefined) {
        setAutoFixVulnerabilitiesEnabled(data.connectedRepository.auto_fix_vulnerabilities_enabled === true);
      }
    } catch (error: any) {
      setRepositoriesError(error.message || 'Failed to load repositories');
    } finally {
      setRepositoriesLoading(false);
    }
  };

  const DEFAULT_PULL_REQUEST_BODY = 'return { passed: true };';
  const DEFAULT_COMPLIANCE_BODY = 'return { compliant: true };';

  function extractFunctionBody(code: string, fnName: string): string | null {
    const regex = new RegExp(`function\\s+${fnName}\\s*\\([^)]*\\)\\s*\\{`, 'g');
    const match = regex.exec(code);
    if (!match) return null;
    const startIdx = match.index + match[0].length;
    let depth = 1;
    let i = startIdx;
    while (i < code.length && depth > 0) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') depth--;
      i++;
    }
    return code.slice(startIdx, i - 1).trim();
  }

  function parsePolicyCode(code: string): { pullRequestBody: string; complianceBody: string } {
    const prBody = extractFunctionBody(code, 'pullRequestCheck');
    const compBody = extractFunctionBody(code, 'projectCompliance');
    return {
      pullRequestBody: prBody ?? DEFAULT_PULL_REQUEST_BODY,
      complianceBody: compBody ?? DEFAULT_COMPLIANCE_BODY,
    };
  }

  function assemblePolicyCode(prBody: string, compBody: string): string {
    const prLines = prBody.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
    const compLines = compBody.trim().split('\n').map((l) => (l ? `  ${l}` : ''));
    return `function pullRequestCheck(context) {\n${prLines.join('\n')}\n}\n\nfunction projectCompliance(context) {\n${compLines.join('\n')}\n}`;
  }

  const loadPoliciesSection = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setPoliciesLoading(true);
    try {
      const [orgPol, projPol] = await Promise.all([
        api.getOrganizationPolicies(organizationId),
        api.getProjectPolicies(organizationId, projectId),
      ]);
      const inheritedCode = (orgPol.policy_code ?? '').trim();
      const { pullRequestBody: iPR, complianceBody: iComp } = inheritedCode
        ? parsePolicyCode(inheritedCode)
        : { pullRequestBody: DEFAULT_PULL_REQUEST_BODY, complianceBody: DEFAULT_COMPLIANCE_BODY };
      setInheritedComplianceBody(iComp);
      setInheritedPullRequestBody(iPR);
      setProjectPolicies(projPol);

      const effectiveCode = (projPol.effective_policy_code ?? inheritedCode).trim();
      const { pullRequestBody: ePR, complianceBody: eComp } = effectiveCode
        ? parsePolicyCode(effectiveCode)
        : { pullRequestBody: DEFAULT_PULL_REQUEST_BODY, complianceBody: DEFAULT_COMPLIANCE_BODY };
      setEffectiveComplianceBody(eComp);
      setEffectivePullRequestBody(ePR);
      setComplianceBody(eComp);
      setPullRequestBody(ePR);
      setHasSyncedPolicies(true);
      policiesDataLoadedForRef.current = `${organizationId}:${projectId}`;
    } catch (e) {
      console.error('Failed to load policies:', e);
    } finally {
      setPoliciesLoading(false);
    }
  }, [organizationId, projectId]);

  // Load policies when policies section is active; skip if already loaded for this project (cache)
  useEffect(() => {
    if (activeSection !== 'policies' || !organizationId || !projectId) return;
    const key = `${organizationId}:${projectId}`;
    if (policiesDataLoadedForRef.current === key) return;
    loadPoliciesSection();
  }, [activeSection, organizationId, projectId, loadPoliciesSection]);

  const complianceDirty = hasSyncedPolicies && complianceBody !== effectiveComplianceBody;
  const pullRequestDirty = hasSyncedPolicies && pullRequestBody !== effectivePullRequestBody;

  // AI sidebar animation
  useEffect(() => {
    if (showAI) {
      setAiPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setAiPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setAiPanelVisible(false);
    }
  }, [showAI]);

  useEffect(() => () => {
    if (aiCloseTimeoutRef.current) clearTimeout(aiCloseTimeoutRef.current);
  }, []);

  const closeAIPanel = useCallback(() => {
    setAiPanelVisible(false);
    if (aiCloseTimeoutRef.current) clearTimeout(aiCloseTimeoutRef.current);
    aiCloseTimeoutRef.current = setTimeout(() => {
      aiCloseTimeoutRef.current = null;
      setShowAI(false);
    }, 150);
  }, []);

  useEffect(() => {
    if (activeSection === 'repository' && organizationId && projectId) {
      const cached = api.getCachedProjectRepositories(organizationId, projectId);
      if (cached) {
        setConnectedRepository(cached.connectedRepository);
        setRepositories(cached.repositories);
        if (cached.connectedRepository?.pull_request_comments_enabled !== undefined) {
          setPullRequestCommentsEnabled(cached.connectedRepository.pull_request_comments_enabled !== false);
        }
        if (cached.connectedRepository?.auto_fix_vulnerabilities_enabled !== undefined) {
          setAutoFixVulnerabilitiesEnabled(cached.connectedRepository.auto_fix_vulnerabilities_enabled === true);
        }
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

  // Track which project we've loaded access data for (skip refetch when returning to tab)
  const accessDataLoadedForRef = useRef<string | null>(null);
  const notificationsDataLoadedForRef = useRef<string | null>(null);
  const policiesDataLoadedForRef = useRef<string | null>(null);
  const integrationCallbackHandledRef = useRef<string | null>(null);

  // Clear access state when project or org changes
  useEffect(() => {
    if (!organizationId || !projectId) return;
    const key = `${organizationId}:${projectId}`;
    if (accessDataLoadedForRef.current && accessDataLoadedForRef.current !== key) {
      setProjectTeams(null);
      setDirectMembers([]);
      setOrgMembers([]);
      setTeamMemberIds(new Set());
      accessDataLoadedForRef.current = null;
    }
  }, [organizationId, projectId]);

  // Load project teams on mount for transfer functionality
  useEffect(() => {
    if (organizationId && projectId) {
      loadProjectTeams();
    }
  }, [organizationId, projectId]);

  // Load project teams and members when access section is active
  const loadProjectTeams = async (opts?: { skipLoadingState?: boolean }) => {
    if (!organizationId || !projectId) return;
    try {
      if (!opts?.skipLoadingState) setLoadingProjectTeams(true);
      const teamsData = await api.getProjectTeams(organizationId, projectId);
      setProjectTeams(teamsData);

      // Fetch members of all teams with access to build exclusion list (parallelized)
      const teamIds: string[] = [];
      if (teamsData.owner_team) {
        teamIds.push(teamsData.owner_team.id);
      }
      teamsData.contributing_teams.forEach(t => teamIds.push(t.id));

      const memberIds = new Set<string>();
      if (teamIds.length > 0) {
        const results = await Promise.allSettled(
          teamIds.map((teamId) => api.getTeamMembers(organizationId, teamId))
        );
        results.forEach((result, i) => {
          if (result.status === 'fulfilled') {
            result.value.forEach((m) => memberIds.add(m.user_id));
          } else {
            console.error(`Failed to load members for team ${teamIds[i]}:`, result.reason);
          }
        });
      }
      setTeamMemberIds(memberIds);
    } catch (error: any) {
      console.error('Failed to load project teams:', error);
    } finally {
      if (!opts?.skipLoadingState) setLoadingProjectTeams(false);
    }
  };

  const loadProjectMembers = async (opts?: { skipLoadingState?: boolean }) => {
    if (!organizationId || !projectId) return;
    try {
      if (!opts?.skipLoadingState) setLoadingMembers(true);
      const membersData = await api.getProjectMembers(organizationId, projectId);
      setDirectMembers(membersData.direct_members);
    } catch (error: any) {
      console.error('Failed to load project members:', error);
    } finally {
      if (!opts?.skipLoadingState) setLoadingMembers(false);
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

  // Load access data when access section is active; skip if already loaded for this project (cache)
  useEffect(() => {
    if (activeSection !== 'access' || !organizationId || !projectId) return;
    const key = `${organizationId}:${projectId}`;
    if (accessDataLoadedForRef.current === key) {
      return; // Already have cached data for this project
    }
    const loadAccessData = async () => {
      setLoadingProjectTeams(true);
      setLoadingMembers(true);
      try {
        await Promise.all([
          loadProjectTeams({ skipLoadingState: true }),
          loadProjectMembers({ skipLoadingState: true }),
          loadOrgMembers(),
        ]);
        accessDataLoadedForRef.current = key;
      } finally {
        setLoadingProjectTeams(false);
        setLoadingMembers(false);
      }
    };
    loadAccessData();
  }, [activeSection, organizationId, projectId]);

  const loadProjectConnections = useCallback(async () => {
    if (!organizationId || !projectId) return;
    setProjectConnectionsLoading(true);
    try {
      const data = await api.getProjectConnections(organizationId, projectId);
      setProjectConnections(data);
      notificationsDataLoadedForRef.current = `${organizationId}:${projectId}`;
    } catch (err: any) {
      toast({ title: 'Failed to load connections', description: err.message, variant: 'destructive' });
    } finally {
      setProjectConnectionsLoading(false);
    }
  }, [organizationId, projectId, toast]);

  // Clear notifications cache and visit flag when project or org changes
  useEffect(() => {
    if (!organizationId || !projectId) return;
    const key = `${organizationId}:${projectId}`;
    if (notificationsDataLoadedForRef.current && notificationsDataLoadedForRef.current !== key) {
      setProjectConnections({ inherited: [], team: [], project: [] });
      setHasVisitedNotifications(false);
      notificationsDataLoadedForRef.current = null;
    }
  }, [organizationId, projectId]);

  // Clear policies cache and visit flag when project or org changes
  useEffect(() => {
    if (!organizationId || !projectId) return;
    const key = `${organizationId}:${projectId}`;
    if (policiesDataLoadedForRef.current && policiesDataLoadedForRef.current !== key) {
      setProjectPolicies(null);
      setHasSyncedPolicies(false);
      setHasVisitedPolicies(false);
      policiesDataLoadedForRef.current = null;
    }
  }, [organizationId, projectId]);

  // Track when user visits Notifications/Policies tabs so we can keep them mounted when switching away (like Access)
  useEffect(() => {
    if (activeSection === 'notifications') setHasVisitedNotifications(true);
    if (activeSection === 'policies') setHasVisitedPolicies(true);
  }, [activeSection]);

  // Load project connections when notifications section is active; skip if already loaded (cache)
  useEffect(() => {
    if (activeSection !== 'notifications' || !organizationId || !projectId) return;
    const key = `${organizationId}:${projectId}`;
    if (notificationsDataLoadedForRef.current === key) return;
    loadProjectConnections();
  }, [activeSection, organizationId, projectId, loadProjectConnections]);

  // Handle integration OAuth callbacks (Slack, Discord, Jira, Linear, Asana) - toast + switch to destinations + refetch + clear URL
  useEffect(() => {
    const connected = searchParams.get('connected');
    const error = searchParams.get('error');
    const message = searchParams.get('message');
    const callbackKey = connected || error ? `${connected || error}-${organizationId}-${projectId}` : null;

    if (!callbackKey || integrationCallbackHandledRef.current === callbackKey) return;
    if (!organizationId || !projectId) return;

    // If we landed on General (e.g. old redirect URL), navigate to notifications first so we handle in context
    if (activeSection !== 'notifications') {
      navigate(`/organizations/${organizationId}/projects/${projectId}/settings/notifications?${searchParams.toString()}`, { replace: true });
      return;
    }

    const providerLabels: Record<string, string> = {
      slack: 'Slack', discord: 'Discord', jira: 'Jira', linear: 'Linear', asana: 'Asana',
    };
    const providerLabel = (connected || error) ? (providerLabels[connected || error || ''] || (connected || error)) : '';

    if (connected) {
      integrationCallbackHandledRef.current = callbackKey;
      setNotificationActiveTab('destinations');
      loadProjectConnections();
      toast({
        title: `${providerLabel} Connected`,
        description: `${providerLabel} has been successfully connected to this project.`,
      });
      // Defer clearing URL so the toast has time to render before the re-render from setSearchParams
      setTimeout(() => setSearchParams({}), 100);
    } else if (error && message) {
      integrationCallbackHandledRef.current = callbackKey;
      toast({
        title: `${providerLabel} Connection Failed`,
        description: decodeURIComponent(message),
        variant: 'destructive',
      });
      setTimeout(() => setSearchParams({}), 100);
    }
  }, [searchParams, activeSection, organizationId, projectId, navigate, toast, setSearchParams, loadProjectConnections, location.search]);

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
      setSelectedTeamId(project.team_ids[0] ?? null);
    }
  }, [projectTeams?.owner_team, project?.team_ids]);

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
      id: 'repository',
      label: 'Repository',
      icon: <GitBranch className="h-4 w-4 tab-icon-shake" />,
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

  // Don't render if project not loaded yet — show full-page settings skeleton with tab-specific content
  if (!project) {
    const loadingSection = sectionParam && VALID_PROJECT_SETTINGS_SECTIONS.has(sectionParam) ? sectionParam : 'general';
    return (
      <div className="bg-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex gap-8 items-start">
            {/* Sidebar skeleton */}
            <aside className="w-64 flex-shrink-0">
              <div className="sticky top-24 pt-8 bg-background z-10">
                <nav className="space-y-1">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="flex items-center gap-3 px-3 py-2">
                      <div className="h-4 w-4 bg-muted animate-pulse rounded" />
                      <div className="h-4 bg-muted animate-pulse rounded flex-1" style={{ maxWidth: i === 2 ? 90 : i === 4 ? 100 : 70 }} />
                    </div>
                  ))}
                </nav>
              </div>
            </aside>
            {/* Tab-specific content skeleton */}
            <div className="flex-1 no-scrollbar">
              <ProjectSettingsTabSkeleton section={loadingSection} />
            </div>
          </div>
        </div>
      </div>
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

  const handlePullRequestCommentsToggle = async (enabled: boolean) => {
    if (!organizationId || !projectId) return;
    setPullRequestCommentsEnabled(enabled);
    try {
      await api.updateProjectRepositorySettings(organizationId, projectId, {
        pull_request_comments_enabled: enabled,
      });
      setConnectedRepository((prev) =>
        prev ? { ...prev, pull_request_comments_enabled: enabled } : null
      );
      toast({
        title: enabled ? 'Pull request comments enabled' : 'Pull request comments disabled',
      });
    } catch (err: any) {
      setPullRequestCommentsEnabled(!enabled);
      toast({
        title: 'Failed to update setting',
        description: (err as Error).message,
        variant: 'destructive',
      });
    }
  };

  const handleAutoFixVulnerabilitiesToggle = async (enabled: boolean) => {
    if (!organizationId || !projectId) return;
    setAutoFixVulnerabilitiesEnabled(enabled);
    try {
      await api.updateProjectRepositorySettings(organizationId, projectId, {
        auto_fix_vulnerabilities_enabled: enabled,
      });
      setConnectedRepository((prev) =>
        prev ? { ...prev, auto_fix_vulnerabilities_enabled: enabled } : null
      );
      toast({
        title: enabled ? 'Auto-fix vulnerabilities enabled' : 'Auto-fix vulnerabilities disabled',
      });
    } catch (err: any) {
      setAutoFixVulnerabilitiesEnabled(!enabled);
      toast({
        title: 'Failed to update setting',
        description: (err as Error).message,
        variant: 'destructive',
      });
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
                    onClick={() => organizationId && projectId && navigate(`/organizations/${organizationId}/projects/${projectId}/settings/${section.id}`)}
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
                  <h2 className="text-2xl font-bold text-foreground">General</h2>
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
                          className="w-full px-3 py-2.5 bg-background-content border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                        />
                      </div>
                    </div>
                    <div>
                      <h3 className="text-base font-semibold text-foreground mb-1">Asset Tier</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
                        Used by Depscore to weight vulnerability scores and blast radius (Crown Jewels vs non-production).
                      </p>
                      <div className="max-w-md">
                        <Select value={assetTier} onValueChange={(v) => setAssetTier(v as AssetTier)}>
                          <SelectTrigger className="w-full px-3 py-2.5 h-auto bg-background-content">
                            <SelectValue placeholder="Select asset tier" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="CROWN_JEWELS">Crown Jewels</SelectItem>
                            <SelectItem value="EXTERNAL">External</SelectItem>
                            <SelectItem value="INTERNAL">Internal</SelectItem>
                            <SelectItem value="NON_PRODUCTION">Non-production</SelectItem>
                          </SelectContent>
                        </Select>
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
                      className="h-8 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                    >
                      {isSaving && <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />}
                      Save
                    </Button>
                  </div>
                </div>

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
                          {loadingTeams ? (
                            <div className="max-w-md w-full px-3 py-2.5 bg-background-content border border-border rounded-lg flex items-center gap-2">
                              <div className="h-5 w-5 rounded bg-muted animate-pulse flex-shrink-0" />
                              <div className="h-4 w-36 bg-muted rounded animate-pulse" />
                            </div>
                          ) : (
                            <div className="max-w-md">
                              <ProjectTeamSelect
                                value={selectedTeamId}
                                onChange={setSelectedTeamId}
                                teams={teams}
                                placeholder="Select a team"
                                showNoTeamOption={false}
                                className="bg-background-content"
                              />
                            </div>
                          )}
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
                          <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                        ) : (
                          <UserPlus className="h-3.5 w-3.5 mr-2" />
                        )}
                        Transfer
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
                              <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                            ) : (
                              <Trash2 className="h-3.5 w-3.5 mr-2" />
                            )}
                            Delete Forever
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

            {activeSection === 'repository' && (
              <div className="space-y-8">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">Repository</h2>
                </div>

                {/* Connected Git Repository card */}
                <section className="space-y-4">
                  {repositoriesLoading ? (
                    <div className="flex items-center gap-4 py-5 px-4 rounded-lg border border-border/60 bg-background-content/50 min-h-[80px]">
                      <div className="h-12 w-12 rounded-lg bg-muted/60 animate-pulse shrink-0" />
                      <div className="flex flex-col gap-2 min-w-0 flex-1">
                        <div className="h-4 w-48 bg-muted/60 rounded animate-pulse" />
                        <div className="h-3 w-28 bg-muted/60 rounded animate-pulse" />
                      </div>
                    </div>
                  ) : repositoriesError && (repositoriesError.includes('integration') || repositoriesError.includes('GitHub App') || repositoriesError.includes('No source')) ? (
                    <div className="text-center py-12 px-6 rounded-lg border border-border/60 bg-background-content/30">
                      <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-primary/10 mb-4">
                        <FolderOpen className="h-7 w-7 text-primary" />
                      </div>
                      <h4 className="text-base font-semibold text-foreground mb-2">No Source Code Connections</h4>
                      <p className="text-sm text-foreground-secondary mb-5 max-w-sm mx-auto">
                        Connect a Git provider in Organization Settings to import repositories.
                      </p>
                      <Button
                        variant="outline"
                        onClick={() => navigate(`/organizations/${organizationId}/settings/integrations`)}
                        className="border-border hover:bg-background-subtle"
                      >
                        Go to Integrations
                      </Button>
                    </div>
                  ) : connectedRepository ? (
                    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                      <div className="flex items-center justify-between gap-4 p-5">
                        <div className="flex items-center gap-3 min-w-0 flex-1">
                          <img
                            src={(connectedRepository as { provider?: string }).provider === 'gitlab'
                              ? '/images/integrations/gitlab.png'
                              : (connectedRepository as { provider?: string }).provider === 'bitbucket'
                                ? '/images/integrations/bitbucket.png'
                                : '/images/integrations/github.png'}
                            alt=""
                            className="h-5 w-5 rounded-sm flex-shrink-0 object-contain"
                          />
                          <div className="min-w-0 flex-1">
                            <div className="text-base font-semibold text-foreground truncate font-mono">
                              {connectedRepository.repo_full_name}
                            </div>
                            <div className="text-xs text-foreground-secondary flex items-center gap-2 mt-0.5 flex-wrap">
                              <span className="flex items-center gap-1">
                                <GitBranch className="h-3.5 w-3.5" />
                                {connectedRepository.default_branch || 'main'}
                              </span>
                              <span>·</span>
                              <span>Last synced {formatConnectedAgo(connectedRepository.connected_at) || '—'}</span>
                              {getWorkspaceDisplayPath(connectedRepository.package_json_path) !== 'Root' && (
                                <>
                                  <span>·</span>
                                  <span>{getWorkspaceDisplayPath(connectedRepository.package_json_path)}</span>
                                </>
                              )}
                              {(importStatus?.status === 'finalizing' || connectedRepository.status === 'extracting' || connectedRepository.status === 'analyzing' || connectedRepository.status === 'finalizing') && (
                                <>
                                  <span>·</span>
                                  {importStatus?.status === 'finalizing' || connectedRepository.status === 'finalizing'
                                    ? 'Finalizing'
                                    : connectedRepository.status === 'extracting'
                                      ? 'Extracting'
                                      : 'Analyzing'}
                                  {importStatus && importStatus.total > 0 && ` ${importStatus.ready}/${importStatus.total}`}
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                        {(connectedRepository.status === 'ready' && importStatus?.status !== 'finalizing') ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <button
                                type="button"
                                className="h-9 w-9 rounded-md flex items-center justify-center text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors shrink-0"
                                aria-label="Sync repository"
                              >
                                <RefreshCw className="h-4 w-4" />
                              </button>
                            </TooltipTrigger>
                            <TooltipContent>Sync</TooltipContent>
                          </Tooltip>
                        ) : (
                          <div className="h-9 w-9 rounded-md flex items-center justify-center shrink-0">
                            <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" />
                          </div>
                        )}
                      </div>
                      {importStatus && importStatus.total > 0 && (connectedRepository?.status === 'analyzing' || importStatus?.status === 'analyzing') && (
                        <div className="px-5 pb-5 pt-0">
                          <div className="flex justify-between text-xs text-foreground-secondary mb-2">
                            <span>Analyzing dependencies...</span>
                            <span>{importStatus.ready} / {importStatus.total}</span>
                          </div>
                          <div className="h-1.5 bg-border/60 rounded-full overflow-hidden">
                            <div className="h-full bg-primary transition-all duration-500 rounded-full" style={{ width: `${Math.round((importStatus.ready / importStatus.total) * 100)}%` }} />
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center gap-4 py-5 px-5 rounded-lg border border-dashed border-border/60 bg-background-content/30">
                      <div className="h-12 w-12 rounded-lg bg-foreground/5 flex items-center justify-center shrink-0">
                        <GitBranch className="h-6 w-6 text-foreground-secondary" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">Not connected</p>
                        <p className="text-xs text-foreground-secondary mt-0.5">
                          Connect a repository from the Dependencies tab to sync package data.
                        </p>
                      </div>
                    </div>
                  )}
                </section>

                {/* Automation section */}
                {connectedRepository && (
                  <section>
                    <h3 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider pb-3 border-b border-border/60">Automation</h3>
                    <div className="mt-4 rounded-lg border border-border bg-background-card overflow-hidden">
                      <div className="flex items-center gap-4 px-4 py-3">
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-foreground">Pull Request Comments</div>
                          <p className="text-xs text-foreground-secondary mt-0.5">
                            Post dependency summaries on new PRs automatically.
                          </p>
                        </div>
                        <Switch
                          checked={pullRequestCommentsEnabled}
                          onCheckedChange={handlePullRequestCommentsToggle}
                          className="shrink-0 self-center"
                        />
                      </div>
                      <div className="border-t border-border/60" />
                      <button
                        type="button"
                        onClick={() => handleAutoFixVulnerabilitiesToggle(!autoFixVulnerabilitiesEnabled)}
                        className="w-full flex items-center gap-4 px-4 py-3 text-left hover:bg-background-subtle/50 transition-colors"
                      >
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-foreground">Auto-Fix Vulnerabilities</div>
                          <p className="text-xs text-foreground-secondary mt-0.5">
                            Create fix PRs for critical security issues.
                          </p>
                        </div>
                        <Switch
                          checked={autoFixVulnerabilitiesEnabled}
                          onCheckedChange={handleAutoFixVulnerabilitiesToggle}
                          className="shrink-0 self-center pointer-events-none"
                        />
                      </button>
                    </div>
                  </section>
                )}

                {/* Recent Activity */}
                {connectedRepository && (
                  <div>
                    <h3 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider pb-3 border-b border-border/60">Recent Activity</h3>
                    <div className="mt-4 rounded-lg border border-border bg-background-card overflow-hidden">
                      <table className="w-full">
                        <thead className="bg-background-card-header border-b border-border">
                          <tr>
                            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Commit</th>
                            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                            <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Time</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {([
                            { id: 8291, shortId: '8sGTNkrBp', commit: '8a2b9f', time: '2 mins ago', duration: '1.2s', status: 'success' as const, trigger: 'Webhook' },
                            { id: 8290, shortId: '4JuN99N55', commit: '4d1c2a', time: '4 hours ago', duration: '0.4s', status: 'error' as const, trigger: 'Push to main' },
                            { id: 8289, shortId: 'B55SoE5rj', commit: 'b19c21', time: '1 day ago', duration: '1.8s', status: 'success' as const, trigger: 'Scheduled' },
                          ] as SyncLogEntry[]).map((log) => (
                            <tr
                              key={log.id}
                              onClick={() => setSelectedSyncLog(log)}
                              className="group hover:bg-table-hover transition-colors cursor-pointer"
                            >
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <GitCommit className="h-4 w-4 text-foreground-secondary shrink-0" />
                                  <span className="text-sm font-mono text-foreground">{log.commit}</span>
                                </div>
                              </td>
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <span className={cn(
                                    'h-2 w-2 rounded-full shrink-0',
                                    log.status === 'success' ? 'bg-success' : 'bg-destructive'
                                  )} />
                                  <span className="text-sm text-foreground-secondary">
                                    {log.status === 'success' ? 'Complete' : 'Failed'}
                                  </span>
                                </div>
                              </td>
                              <td className="px-4 py-3 text-right text-sm text-foreground-secondary">
                                {log.time} by henryru
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Note: Cannot disconnect */}
                {connectedRepository && (
                  <div className="rounded-lg border border-border/60 bg-background-content/30 px-4 py-4">
                    <p className="text-sm text-foreground-secondary">
                      Projects cannot be disconnected from a repository. To use a different repository, create a new project or remove this project.
                    </p>
                  </div>
                )}

                {/* Sync detail sidebar */}
                {selectedSyncLog && (
                  <SyncDetailSidebar
                    entry={selectedSyncLog}
                    onClose={() => setSelectedSyncLog(null)}
                  />
                )}
              </div>
            )}

            {/* Select project (monorepo) dialog – shown regardless of active section */}
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
                            <div className="text-sm font-medium text-foreground truncate">{p.path === '' ? (repoToConnect ? repoNameOnly(repoToConnect.full_name) : 'Root') : p.name}</div>
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

            {activeSection === 'access' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">Access</h2>
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
                          className="h-7 text-xs bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
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
                                aria-label={`Remove team ${team.name}`}
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
                          className="h-7 text-xs bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
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
                                aria-label={`Remove member ${member.full_name || member.email}`}
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

            {/* Keep Notifications mounted after first visit so it doesn't reload when switching tabs (like Access) */}
            {(activeSection === 'notifications' || hasVisitedNotifications) && organizationId && projectId && (
              <div style={{ display: activeSection === 'notifications' ? undefined : 'none' }}>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-2xl font-bold text-foreground">Notifications</h2>
                  {notificationActiveTab === 'notifications' && organizationId && projectId && (
                    <Button
                      onClick={() => notificationCreateRef.current?.()}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Create Rule
                    </Button>
                  )}
                </div>

                <div className="flex items-center justify-between border-b border-border pb-px">
                  <div className="flex items-center gap-6">
                    <button
                      type="button"
                      onClick={() => setNotificationActiveTab('notifications')}
                      className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                        notificationActiveTab === 'notifications' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                      }`}
                    >
                      Notifications
                    </button>
                    <button
                      type="button"
                      onClick={() => setNotificationActiveTab('destinations')}
                      className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                        notificationActiveTab === 'destinations' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                      }`}
                    >
                      Destinations
                    </button>
                  </div>
                </div>

                {notificationActiveTab === 'notifications' && organizationId && projectId && (
                  <div className="pt-6">
                    <NotificationRulesSection
                      organizationId={organizationId}
                      projectId={projectId}
                      hideTitle
                      createHandlerRef={notificationCreateRef}
                      connections={[...(projectConnections.inherited || []), ...(projectConnections.team || []), ...(projectConnections.project || [])]}
                    />
                  </div>
                )}

                {notificationActiveTab === 'destinations' && (
                  <div className="pt-6 space-y-8">
                    <div>
                      <h3 className="text-lg font-semibold text-foreground mb-3">Inherited from organization</h3>
                      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                        <table className="w-full table-fixed">
                          <colgroup>
                            <col className="w-[200px]" />
                            <col />
                            <col className="w-[120px]" />
                          </colgroup>
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                              <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {projectConnectionsLoading ? (
                              [1, 2, 3].map((i) => (
                                <tr key={i}>
                                  <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3" />
                                </tr>
                              ))
                            ) : projectConnections.inherited.length === 0 ? (
                              <tr>
                                <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                  No inherited integrations. Connect integrations in Organization Settings.
                                </td>
                              </tr>
                            ) : (
                              projectConnections.inherited.map((conn: CiCdConnection) => (
                                <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-3">
                                    <div className="flex items-center gap-2.5">
                                      {(conn.provider === 'slack' || conn.provider === 'discord') && (
                                        <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />
                                      )}
                                      {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                      {(conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing') && (
                                        conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                        conn.provider === 'jira' ? <img src="/images/integrations/jira.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        conn.provider === 'linear' ? <img src="/images/integrations/linear.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      <span className="text-sm font-medium text-foreground">
                                        {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' :
                                          conn.provider === 'email' ? 'Email' :
                                          conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') :
                                          conn.provider === 'slack' ? 'Slack' : conn.provider === 'discord' ? 'Discord' : conn.provider === 'linear' ? 'Linear' : conn.provider}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className="text-sm text-foreground truncate block">{conn.display_name || '-'}</span>
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    <span className="text-xs text-foreground-secondary px-2 py-1 rounded border border-border bg-transparent">Inherited</span>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Inherited from team */}
                    <div>
                      <h3 className="text-lg font-semibold text-foreground mb-3">Inherited from team</h3>
                      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                        <table className="w-full table-fixed">
                          <colgroup>
                            <col className="w-[200px]" />
                            <col />
                            <col className="w-[120px]" />
                          </colgroup>
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                              <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {projectConnectionsLoading ? (
                              [1, 2].map((i) => (
                                <tr key={i}>
                                  <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3" />
                                </tr>
                              ))
                            ) : (projectConnections.team || []).length === 0 ? (
                              <tr>
                                <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                  No team integrations. Connect integrations in Team Settings.
                                </td>
                              </tr>
                            ) : (
                              (projectConnections.team || []).map((conn: CiCdConnection) => (
                                <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-3">
                                    <div className="flex items-center gap-2.5">
                                      {(conn.provider === 'slack' || conn.provider === 'discord') && (
                                        <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />
                                      )}
                                      {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                      {(conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing') && (
                                        conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                        conn.provider === 'jira' ? <img src="/images/integrations/jira.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        conn.provider === 'linear' ? <img src="/images/integrations/linear.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      <span className="text-sm font-medium text-foreground">
                                        {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' :
                                          conn.provider === 'email' ? 'Email' :
                                          conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') :
                                          conn.provider === 'slack' ? 'Slack' : conn.provider === 'discord' ? 'Discord' : conn.provider === 'linear' ? 'Linear' : conn.provider}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className="text-sm text-foreground truncate block">{conn.display_name || '-'}</span>
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    <span className="text-xs text-foreground-secondary px-2 py-1 rounded border border-border bg-transparent">Inherited</span>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold text-foreground mb-3">Project-specific</h3>
                      {canEditSettings && (
                        <div className="flex items-center gap-2 mb-4 flex-wrap">
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={() => { setProjectEmailToAdd(''); setShowProjectEmailDialog(true); }}
                          >
                            <Mail className="h-3.5 w-3.5 mr-1.5" />
                            Add Email
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={async () => {
                              try {
                                const { redirectUrl } = await api.connectSlackOrg(organizationId!, projectId!);
                                window.location.href = redirectUrl;
                              } catch (err: any) {
                                toast({ title: 'Error', description: err.message || 'Failed to connect Slack', variant: 'destructive' });
                              }
                            }}
                          >
                            <img src="/images/integrations/slack.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />
                            Add Slack
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={async () => {
                              try {
                                const { redirectUrl } = await api.connectDiscordOrg(organizationId!, projectId!);
                                window.location.href = redirectUrl;
                              } catch (err: any) {
                                toast({ title: 'Error', description: err.message || 'Failed to connect Discord', variant: 'destructive' });
                              }
                            }}
                          >
                            <img src="/images/integrations/discord.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />
                            Add Discord
                          </Button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="outline" size="sm" className="text-xs">
                                <img src="/images/integrations/jira.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />
                                Add Jira
                                <ChevronDown className="h-3 w-3 ml-1" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={async () => {
                                try {
                                  const { redirectUrl } = await api.connectJiraOrg(organizationId!, projectId!);
                                  window.location.href = redirectUrl;
                                } catch (err: any) {
                                  toast({ title: 'Error', description: err.message || 'Failed to connect Jira', variant: 'destructive' });
                                }
                              }}>
                                Jira Cloud (OAuth)
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => {
                                setJiraPatBaseUrl('');
                                setJiraPatToken('');
                                setShowJiraPatDialog(true);
                              }}>
                                Jira Data Center (PAT)
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={async () => {
                              try {
                                const { redirectUrl } = await api.connectLinearOrg(organizationId!, projectId!);
                                window.location.href = redirectUrl;
                              } catch (err: any) {
                                toast({ title: 'Error', description: err.message || 'Failed to connect Linear', variant: 'destructive' });
                              }
                            }}
                          >
                            <img src="/images/integrations/linear.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />
                            Add Linear
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={() => { setProjectCustomType('notification'); setProjectCustomName(''); setProjectCustomWebhookUrl(''); setShowProjectCustomDialog(true); }}
                          >
                            <Webhook className="h-3.5 w-3.5 mr-1.5" />
                            Add Custom Notifications
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={() => { setProjectCustomType('ticketing'); setProjectCustomName(''); setProjectCustomWebhookUrl(''); setShowProjectCustomDialog(true); }}
                          >
                            <Webhook className="h-3.5 w-3.5 mr-1.5" />
                            Add Custom Ticketing
                          </Button>
                        </div>
                      )}
                      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                        <table className="w-full table-fixed">
                          <colgroup>
                            <col className="w-[200px]" />
                            <col />
                            <col className="w-[140px]" />
                          </colgroup>
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                              <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {projectConnectionsLoading ? (
                              [1, 2].map((i) => (
                                <tr key={i}>
                                  <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3" />
                                </tr>
                              ))
                            ) : projectConnections.project.length === 0 ? (
                              <tr>
                                <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                  No project-specific integrations. Add one above.
                                </td>
                              </tr>
                            ) : (
                              projectConnections.project.map((conn: CiCdConnection) => (
                                <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-3">
                                    <div className="flex items-center gap-2.5">
                                      {(conn.provider === 'slack' || conn.provider === 'discord') && (
                                        <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />
                                      )}
                                      {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                      {(conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing') && (
                                        conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                        conn.provider === 'jira' ? <img src="/images/integrations/jira.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        conn.provider === 'linear' ? <img src="/images/integrations/linear.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      <span className="text-sm font-medium text-foreground">
                                        {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' :
                                          conn.provider === 'email' ? 'Email' :
                                          conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') :
                                          conn.provider === 'slack' ? 'Slack' : conn.provider === 'discord' ? 'Discord' : conn.provider === 'linear' ? 'Linear' : conn.provider}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className="text-sm text-foreground truncate block">
                                      {conn.provider === 'email' ? conn.metadata?.email || conn.display_name : conn.display_name || '-'}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    {canEditSettings && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        className="text-xs hover:bg-destructive/10 hover:border-destructive/30 opacity-0 group-hover:opacity-100 transition-opacity"
                                        onClick={async () => {
                                          if (!confirm('Remove this integration?')) return;
                                          try {
                                            await api.deleteProjectConnection(organizationId!, projectId!, conn.id);
                                            toast({ title: 'Removed', description: 'Integration removed.' });
                                            loadProjectConnections();
                                          } catch (err: any) {
                                            toast({ title: 'Failed to remove', description: err.message, variant: 'destructive' });
                                          }
                                        }}
                                      >
                                        Remove
                                      </Button>
                                    )}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Keep Policies mounted after first visit so it doesn't reload when switching tabs (like Notifications) */}
            {(activeSection === 'policies' || hasVisitedPolicies) && (
              <div style={{ display: activeSection === 'policies' ? undefined : 'none' }}>
                <div className="sticky top-0 z-10 bg-background pb-2">
                  <div className="mb-6 flex items-start justify-between">
                    <h2 className="text-2xl font-bold text-foreground">Policies</h2>
                    <div className="flex items-center gap-2">
                      {canViewSettings && (
                        <Button variant="outline" size="sm" className="text-xs" onClick={() => setShowAI(true)}>
                          <Sparkles className="h-3.5 w-3.5 mr-1.5" />
                          AI Assistant
                        </Button>
                      )}
                      <Link to="/docs/policies" target="_blank">
                        <Button variant="outline" size="sm" className="text-xs">
                          <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                          Docs
                        </Button>
                      </Link>
                    </div>
                  </div>

                  <div className="flex items-center justify-between border-b border-border pb-px">
                    <div className="flex items-center gap-6">
                      <button
                        type="button"
                        onClick={() => setPolicyActiveTab('policies')}
                        className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                          policyActiveTab === 'policies' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                        }`}
                      >
                        Policy
                      </button>
                      <button
                        type="button"
                        onClick={() => setPolicyActiveTab('exceptions')}
                        className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                          policyActiveTab === 'exceptions' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                        }`}
                      >
                        Exception applications
                      </button>
                    </div>
                  </div>
                </div>

                {policyActiveTab === 'policies' && (
                  <>
                    {policiesLoading ? (
                      <div className="space-y-6 pt-2 pb-8">
                        {[0, 1].map((i) => (
                          <div key={i} className="rounded-lg border border-border bg-background-card overflow-hidden">
                            <div className="px-4 py-2.5 bg-background-card-header border-b border-border">
                              <div className="h-3.5 bg-muted rounded w-32 animate-pulse" />
                            </div>
                            <div className="bg-[#1d1f21] px-4 py-3 font-mono text-[13px] leading-6" style={{ minHeight: '180px' }}>
                              <div className="space-y-1.5 animate-pulse">
                                <div className="h-3 bg-white/[0.06] rounded w-[70%]" />
                                <div className="h-3 bg-white/[0.06] rounded w-[55%] ml-4" />
                                <div className="h-3 bg-white/[0.06] rounded w-[80%] ml-4" />
                                <div className="h-3 bg-white/[0.06] rounded w-[40%] ml-8" />
                                <div className="h-3 bg-white/[0.06] rounded w-[60%] ml-4" />
                                <div className="h-3 bg-white/[0.06] rounded w-[30%]" />
                                <div className="h-3" />
                                <div className="h-3 bg-white/[0.06] rounded w-[50%] ml-4" />
                                <div className="h-3 bg-white/[0.06] rounded w-[45%] ml-4" />
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : projectPolicies ? (
                      <div className="space-y-6 pt-2 pb-8">
                        {(projectPolicies.pending_exceptions ?? [])
                          .filter((p) => p.status === 'pending')
                          .map((pending) => (
                            <div key={pending.id} className="rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Clock className="h-4 w-4 text-warning" />
                                <span className="text-sm text-foreground">
                                  {pending.policy_type === 'pull_request'
                                    ? 'Pull request exception under review'
                                    : pending.policy_type === 'compliance'
                                      ? 'Compliance exception under review'
                                      : 'Policy exception under review'}
                                </span>
                              </div>
                              {canViewSettings && (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  disabled={!!policyCancellingId}
                                  className="h-7 text-xs"
                                  onClick={async () => {
                                    if (!organizationId || !pending.id) return;
                                    setPolicyCancellingId(pending.id);
                                    try {
                                      await api.deletePolicyException(organizationId, pending.id);
                                      toast({ title: 'Request withdrawn', description: 'Exception request has been cancelled.' });
                                      await loadPoliciesSection();
                                    } catch (e: any) {
                                      toast({ title: 'Error', description: e.message || 'Failed to cancel request', variant: 'destructive' });
                                    } finally {
                                      setPolicyCancellingId(null);
                                    }
                                  }}
                                >
                                  {policyCancellingId === pending.id ? (
                                    <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                                  ) : (
                                    <X className="h-3.5 w-3.5 mr-1.5" />
                                  )}
                                  Cancel request
                                </Button>
                              )}
                            </div>
                          ))}

                        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                          <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project Compliance</span>
                              {!complianceDirty && !(projectPolicies.pending_exceptions ?? []).some((p) => ['compliance', 'full'].includes(p.policy_type ?? 'full')) && (
                                (projectPolicies.accepted_exceptions ?? []).some((e) => ['compliance', 'full'].includes(e.policy_type ?? 'full'))
                                  ? <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-emerald-500/40 text-emerald-500">Exception active</Badge>
                                  : <Badge variant="outline" className="text-[10px] px-1.5 py-0">Inherited from org</Badge>
                              )}
                            </div>
                            {canViewSettings && complianceDirty && !(projectPolicies.pending_exceptions ?? []).some((p) => ['compliance', 'full'].includes(p.policy_type ?? 'full')) && (
                              <div className="flex items-center gap-1.5">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => setComplianceBody(effectiveComplianceBody)}
                                  className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none"
                                >
                                  Cancel
                                </Button>
                                <Button
                                  size="sm"
                                  onClick={() => setShowExceptionSidebar('compliance')}
                                  className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none shadow-sm gap-1 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20"
                                >
                                  Apply for Exception
                                </Button>
                              </div>
                            )}
                          </div>
                          <div className="bg-background-card">
                            <PolicyCodeEditor
                              value={complianceBody}
                              onChange={setComplianceBody}
                              readOnly={!canViewSettings || (projectPolicies.pending_exceptions ?? []).some((p) => ['compliance', 'full'].includes(p.policy_type ?? 'full'))}
                              fitContent
                            />
                          </div>
                        </div>

                        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                          <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Pull Request Check</span>
                              {!pullRequestDirty && !(projectPolicies.pending_exceptions ?? []).some((p) => ['pull_request', 'full'].includes(p.policy_type ?? 'full')) && (
                                (projectPolicies.accepted_exceptions ?? []).some((e) => ['pull_request', 'full'].includes(e.policy_type ?? 'full'))
                                  ? <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-emerald-500/40 text-emerald-500">Exception active</Badge>
                                  : <Badge variant="outline" className="text-[10px] px-1.5 py-0">Inherited from org</Badge>
                              )}
                            </div>
                            {canViewSettings && pullRequestDirty && !(projectPolicies.pending_exceptions ?? []).some((p) => ['pull_request', 'full'].includes(p.policy_type ?? 'full')) && (
                              <div className="flex items-center gap-1.5">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => setPullRequestBody(effectivePullRequestBody)}
                                  className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none"
                                >
                                  Cancel
                                </Button>
                                <Button
                                  size="sm"
                                  onClick={() => setShowExceptionSidebar('pullRequest')}
                                  className="h-5 min-h-5 px-1.5 py-0 text-[11px] leading-none shadow-sm gap-1 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20"
                                >
                                  Apply for Exception
                                </Button>
                              </div>
                            )}
                          </div>
                          <div className="bg-background-card">
                            <PolicyCodeEditor
                              value={pullRequestBody}
                              onChange={setPullRequestBody}
                              readOnly={!canViewSettings || (projectPolicies.pending_exceptions ?? []).some((p) => ['pull_request', 'full'].includes(p.policy_type ?? 'full'))}
                              fitContent
                            />
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="rounded-lg border border-border p-8 text-center text-foreground-secondary text-sm">
                        Failed to load policies.
                      </div>
                    )}
                  </>
                )}

                {policyActiveTab === 'exceptions' && (
                  <div className="space-y-6 pt-2 pb-8 min-w-0">
                    <div className="rounded-lg border border-border bg-background-card overflow-x-auto">
                      <table className="w-full table-auto min-w-[640px]">
                        <colgroup>
                          <col className="w-[130px]" />
                          <col className="w-[110px]" />
                          <col className="min-w-[120px]" />
                          <col className="w-[95px]" />
                          <col className="w-[90px]" />
                        </colgroup>
                        <thead className="bg-background-card-header border-b border-border">
                          <tr>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Type</th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Reason</th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Date</th>
                            <th className="text-right px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {policiesLoading ? (
                            [0, 1, 2].map((i) => (
                              <tr key={i} className="animate-pulse">
                                <td className="px-4 py-3"><div className="h-5 bg-muted rounded w-16" /></td>
                                <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-20" /></td>
                                <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-3/4" /></td>
                                <td className="px-4 py-3"><div className="h-4 bg-muted rounded w-16" /></td>
                                <td className="px-4 py-3 text-right"><div className="h-7 bg-muted rounded w-12 ml-auto" /></td>
                              </tr>
                            ))
                          ) : (() => {
                            const allExceptions: ProjectPolicyException[] = [
                              ...(projectPolicies?.pending_exceptions ?? []),
                              ...(projectPolicies?.accepted_exceptions ?? []),
                              ...(projectPolicies?.revoked_exceptions ?? []),
                            ];
                            if (allExceptions.length === 0) {
                              return (
                                <tr>
                                  <td colSpan={5} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                    No exception applications
                                  </td>
                                </tr>
                              );
                            }
                            return allExceptions.map((ex) => (
                              <tr key={ex.id} className="group hover:bg-table-hover transition-colors">
                                <td className="px-4 py-3">
                                  {ex.status === 'pending' && (
                                    <Badge variant="warning" className="gap-1"><Clock className="h-3 w-3" /> Pending</Badge>
                                  )}
                                  {ex.status === 'accepted' && (
                                    <Badge variant="success" className="gap-1"><Check className="h-3 w-3" /> Accepted</Badge>
                                  )}
                                  {ex.status === 'rejected' && (
                                    <Badge variant="destructive" className="gap-1"><X className="h-3 w-3" /> Rejected</Badge>
                                  )}
                                  {ex.status === 'revoked' && (
                                    <Badge variant="destructive" className="gap-1"><Ban className="h-3 w-3" /> Revoked</Badge>
                                  )}
                                </td>
                                <td className="px-4 py-3 text-sm text-foreground-secondary">
                                  {ex.policy_type === 'pull_request' ? 'Pull Request' : ex.policy_type === 'compliance' ? 'Compliance' : 'Full'}
                                </td>
                                <td className="px-4 py-3 text-sm text-foreground-secondary min-w-0 max-w-[200px]">
                                  <span className="block truncate" title={ex.reason || undefined}>{ex.reason || '\u2014'}</span>
                                </td>
                                <td className="px-4 py-3 text-sm text-foreground-secondary whitespace-nowrap">{new Date(ex.created_at).toLocaleDateString()}</td>
                                <td className="px-4 py-3 text-right whitespace-nowrap">
                                  {ex.base_policy_code && ex.requested_policy_code && (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      className="h-7 text-xs"
                                      onClick={() => setViewingExceptionId(ex.id)}
                                    >
                                      <Eye className="h-3.5 w-3.5 mr-1" />
                                      View
                                    </Button>
                                  )}
                                </td>
                              </tr>
                            ));
                          })()}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Policy Exception View Sidebar */}
      {viewingExceptionId && projectPolicies && project && (() => {
        const allEx = [...(projectPolicies.pending_exceptions ?? []), ...(projectPolicies.accepted_exceptions ?? []), ...(projectPolicies.revoked_exceptions ?? [])];
        const ex = allEx.find((e) => e.id === viewingExceptionId);
        if (!ex?.base_policy_code || !ex?.requested_policy_code) return null;
        return (
          <PolicyExceptionSidebar
            key={viewingExceptionId}
            mode="view"
            baseCode={ex.base_policy_code}
            requestedCode={ex.requested_policy_code}
            projectName={project.name}
            reason={ex.reason}
            status={ex.status}
            onClose={() => setViewingExceptionId(null)}
          />
        );
      })()}

      {/* Policy Exception Sidebar */}
      {showExceptionSidebar && organizationId && projectId && (
        <PolicyExceptionSidebar
          mode="apply"
          baseCode={assemblePolicyCode(effectivePullRequestBody, effectiveComplianceBody)}
          requestedCode={assemblePolicyCode(
            showExceptionSidebar === 'pullRequest' ? pullRequestBody : effectivePullRequestBody,
            showExceptionSidebar === 'compliance' ? complianceBody : effectiveComplianceBody
          )}
          onApply={async (reason) => {
            const code = assemblePolicyCode(pullRequestBody, complianceBody);
            await api.createPolicyException(organizationId, projectId, {
              reason,
              requested_policy_code: code,
              policy_type: showExceptionSidebar === 'compliance' ? 'compliance' : 'pull_request',
            });
            toast({ title: 'Exception requested', description: 'Your request has been sent for review.' });
            setShowExceptionSidebar(null);
            await loadPoliciesSection();
          }}
          onClose={() => setShowExceptionSidebar(null)}
        />
      )}

      {/* AI Assistant */}
      {showAI && organizationId && createPortal(
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              aiPanelVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeAIPanel}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[40rem] bg-background-card-header border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              aiPanelVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <PolicyAIAssistant
              organizationId={organizationId}
              complianceBody={complianceBody}
              pullRequestBody={pullRequestBody}
              onUpdateCompliance={setComplianceBody}
              onUpdatePullRequest={setPullRequestBody}
              onClose={closeAIPanel}
              variant="edge"
            />
          </div>
        </div>,
        document.body
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

      {/* Project Email Notification Dialog */}
      <Dialog open={showProjectEmailDialog} onOpenChange={setShowProjectEmailDialog}>
        <DialogContent hideClose className="sm:max-w-[440px] bg-background p-0 gap-0">
          <div className="px-6 pt-6 pb-4 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="h-7 w-7 rounded flex items-center justify-center text-foreground-secondary">
                <Mail className="h-7 w-7" />
              </div>
              <div>
                <DialogTitle>Add Email</DialogTitle>
                <DialogDescription>Add an email address to receive notification alerts.</DialogDescription>
              </div>
            </div>
          </div>
          <div className="px-6 py-6 grid gap-4 bg-background">
            <div className="grid gap-2">
              <Label htmlFor="project-email-to-add">Email address</Label>
              <Input
                id="project-email-to-add"
                type="email"
                value={projectEmailToAdd}
                onChange={(e) => setProjectEmailToAdd(e.target.value)}
                placeholder=""
              />
            </div>
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setShowProjectEmailDialog(false)}>Cancel</Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={!projectEmailToAdd.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(projectEmailToAdd.trim()) || projectEmailSaving}
              onClick={async () => {
                if (!organizationId || !projectId) return;
                setProjectEmailSaving(true);
                try {
                  await api.createProjectEmailNotification(organizationId, projectId, projectEmailToAdd.trim());
                  toast({ title: 'Added', description: 'Email notification added successfully.' });
                  setShowProjectEmailDialog(false);
                  setProjectEmailToAdd('');
                  loadProjectConnections();
                } catch (err: any) {
                  toast({ title: 'Error', description: err.message || 'Failed to add email.', variant: 'destructive' });
                } finally {
                  setProjectEmailSaving(false);
                }
              }}
            >
              {projectEmailSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Project Custom Integration Dialog */}
      <Dialog open={showProjectCustomDialog} onOpenChange={setShowProjectCustomDialog}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden">
          <div className="px-6 pt-6 pb-4 border-b border-border">
            <div className="flex items-start justify-between gap-4">
              <div>
                <DialogTitle>Add custom {projectCustomType === 'notification' ? 'notifications' : 'ticketing'}</DialogTitle>
                <DialogDescription className="mt-1">
                  {projectCustomType === 'notification'
                    ? 'Set up a custom webhook endpoint for notifications.'
                    : 'Set up a custom webhook endpoint for ticketing (e.g. create issues).'}
                </DialogDescription>
              </div>
              <Link to="/docs/integrations" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" size="sm" className="text-xs shrink-0">
                  <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                  Docs
                </Button>
              </Link>
            </div>
          </div>
          <div className="px-6 py-4 grid gap-4 bg-background">
            <div className="grid gap-2">
              <Label htmlFor="project-custom-name">Name</Label>
              <Input
                id="project-custom-name"
                value={projectCustomName}
                onChange={(e) => setProjectCustomName(e.target.value)}
                placeholder=""
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="project-custom-webhook">Webhook URL</Label>
              <Input
                id="project-custom-webhook"
                type="url"
                value={projectCustomWebhookUrl}
                onChange={(e) => setProjectCustomWebhookUrl(e.target.value)}
                placeholder=""
                className={projectCustomWebhookUrl.trim() && !projectCustomWebhookUrl.trim().toLowerCase().startsWith('https://') ? 'border-destructive focus-visible:ring-destructive/50' : undefined}
              />
            </div>
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setShowProjectCustomDialog(false)}>Cancel</Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={!projectCustomName.trim() || !projectCustomWebhookUrl.trim() || projectCustomSaving || !/^https:\/\/[^\s]+$/i.test(projectCustomWebhookUrl.trim())}
              onClick={async () => {
                if (!organizationId || !projectId) return;
                setProjectCustomSaving(true);
                try {
                  await api.createProjectCustomIntegration(organizationId, projectId, {
                    name: projectCustomName.trim(),
                    type: projectCustomType,
                    webhook_url: projectCustomWebhookUrl.trim(),
                  });
                  toast({ title: 'Created', description: 'Custom integration created.' });
                  setShowProjectCustomDialog(false);
                  setProjectCustomName('');
                  setProjectCustomWebhookUrl('');
                  loadProjectConnections();
                } catch (err: any) {
                  toast({ title: 'Error', description: err.message || 'Failed to save.', variant: 'destructive' });
                } finally {
                  setProjectCustomSaving(false);
                }
              }}
            >
              {projectCustomSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Create connection
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Jira Data Center PAT Dialog (for project Destinations) */}
      <Dialog open={showJiraPatDialog} onOpenChange={setShowJiraPatDialog}>
        <DialogContent hideClose className="sm:max-w-[440px] bg-background p-0 gap-0">
          <div className="px-6 pt-6 pb-4 border-b border-border">
            <div className="flex items-center gap-3">
              <img src="/images/integrations/jira.png" alt="Jira" className="h-7 w-7 rounded object-contain" />
              <div>
                <DialogTitle>Jira Data Center</DialogTitle>
                <DialogDescription>Connect via Personal Access Token</DialogDescription>
              </div>
            </div>
          </div>

          <div className="px-6 py-6 grid gap-4 bg-background">
            <div className="grid gap-2">
              <Label htmlFor="jira-url">Server URL</Label>
              <Input
                id="jira-url"
                type="url"
                value={jiraPatBaseUrl}
                onChange={(e) => setJiraPatBaseUrl(e.target.value)}
                placeholder="https://jira.example.com"
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="jira-pat">Personal Access Token</Label>
              <Input
                id="jira-pat"
                type="password"
                value={jiraPatToken}
                onChange={(e) => setJiraPatToken(e.target.value)}
                placeholder=""
              />
            </div>
          </div>

          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setShowJiraPatDialog(false)}>Cancel</Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={!jiraPatBaseUrl.trim() || !jiraPatToken.trim() || jiraPatSaving}
              onClick={async () => {
                if (!organizationId || !projectId) return;
                setJiraPatSaving(true);
                try {
                  await api.connectJiraPatOrg(organizationId, jiraPatBaseUrl.trim(), jiraPatToken.trim(), projectId);
                  toast({ title: 'Connected', description: 'Jira Data Center connected successfully.' });
                  setShowJiraPatDialog(false);
                  setJiraPatBaseUrl('');
                  setJiraPatToken('');
                  loadProjectConnections();
                } catch (err: any) {
                  toast({ title: 'Error', description: err.message || 'Failed to connect.', variant: 'destructive' });
                } finally {
                  setJiraPatSaving(false);
                }
              }}
            >
              {jiraPatSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Create connection
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
