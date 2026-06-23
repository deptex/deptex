import { useState, useEffect, useRef, useMemo, useCallback, Fragment } from 'react';
import { useOutletContext, useNavigate, useParams, useLocation, useSearchParams } from 'react-router-dom';
import { cn } from '../../lib/utils';
import { Settings, Shield, Users, X, Search, Crown, UserPlus, FolderOpen, Folder, Copy, Lock, Check, Loader2, GitBranch, RefreshCw, GitCommit, AlertTriangle, Globe } from 'lucide-react';
import { DastScanningTab } from '../../components/dast/DastScanningTab';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../../components/ui/dialog';
import { api, ProjectWithRole, ProjectPermissions, Team, ProjectTeamsResponse, ProjectContributingTeam, ProjectMember, OrganizationMember, ProjectRepository, ProjectImportStatus, type RepoWithProvider, type ExtractionRun, type Organization } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { FrameworkIcon } from '../../components/framework-icon';
import { InlineExtractionLogs } from '../../components/InlineExtractionLogs';
import { isExtractionOngoing } from '../../lib/extractionStatus';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { ProjectTeamSelect } from '../../components/ProjectTeamSelect';
import { RoleBadge } from '../../components/RoleBadge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select';
import { Switch } from '../../components/ui/switch';
import { Avatar, AvatarFallback, AvatarImage } from '../../components/ui/avatar';

/** Single table row that expands in-place to show extraction logs. */
function RunRow({
  run,
  organizationId,
  projectId,
  onCancelled,
}: {
  run: import('../../lib/api').ExtractionRun;
  organizationId: string;
  projectId: string;
  onCancelled: () => void;
}) {
  const isActive = run.status === 'queued' || run.status === 'processing';
  const duration = formatRunDuration(run.created_at, run.completed_at ?? null, run.status);
  const [expanded, setExpanded] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [animateOpen, setAnimateOpen] = useState(false);

  useEffect(() => {
    if (expanded) {
      setMounted(true);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => setAnimateOpen(true));
      });
    } else {
      setAnimateOpen(false);
    }
  }, [expanded]);

  return (
    <tr
      onClick={() => setExpanded((v) => !v)}
      className="hover:bg-table-hover transition-colors cursor-pointer align-top"
    >
      <td colSpan={3} className="p-0">
        {/* Row content — flex mimics the 3 columns */}
        <div className="flex items-center px-4 py-3 gap-4">
          {/* Source */}
          <div className="flex-[4] flex flex-col gap-1 min-w-0">
            <div className="flex items-center gap-1.5 min-w-0">
              <GitBranch className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />
              <span className="text-sm text-foreground truncate">{run.branch || 'main'}</span>
            </div>
            <div className="flex items-center gap-1.5 min-w-0">
              <GitCommit className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />
              {run.commit_sha ? (
                <span className="text-sm text-foreground truncate">
                  {(run.commit_sha as string).slice(0, 7)}
                  {run.commit_message ? ` ${(run.commit_message as string).split('\n')[0]}` : ''}
                </span>
              ) : (
                <span className="text-sm text-foreground truncate">
                  {run.trigger_type === 'initial' ? 'Initial extraction' : 'Manual sync'}
                </span>
              )}
            </div>
          </div>

          {/* Status */}
          <div className="flex-[1] flex flex-col gap-0.5 pt-0.5">
            <div className="flex items-center gap-2">
              {isActive ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-foreground-secondary" aria-hidden />
                  <span className="text-sm font-medium text-foreground">Extracting</span>
                </>
              ) : run.status === 'completed' ? (
                <>
                  <span className="h-2 w-2 rounded-full shrink-0 bg-emerald-500" />
                  <span className="text-sm font-medium text-foreground">Ready</span>
                </>
              ) : run.status === 'cancelled' ? (
                <>
                  <span className="h-2 w-2 rounded-full shrink-0 bg-amber-500" />
                  <span className="text-sm font-medium text-foreground">Cancelled</span>
                </>
              ) : (
                <>
                  <span className="h-2 w-2 rounded-full shrink-0 bg-destructive" />
                  <span className="text-sm font-medium text-foreground">Error</span>
                </>
              )}
            </div>
            <span className="text-sm text-foreground-secondary tabular-nums">{duration}</span>
          </div>

          {/* Time + trigger source */}
          <div className="flex-[1] flex items-center justify-end gap-1.5">
            <span className="text-sm text-foreground-secondary tabular-nums">
              {formatConnectedAgo(run.created_at)}
            </span>
            {(() => {
              const tt = run.trigger_type;
              if (tt === 'manual' || tt === 'initial') {
                if (run.started_by?.avatar_url) {
                  return (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <img src={run.started_by.avatar_url} alt="" className="h-6 w-6 rounded-full flex-shrink-0" />
                      </TooltipTrigger>
                      <TooltipContent>{run.started_by.full_name || (tt === 'initial' ? 'Initial connect' : 'Manual sync')}</TooltipContent>
                    </Tooltip>
                  );
                }
                return (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="h-6 w-6 rounded-full bg-foreground-secondary/20 flex items-center justify-center flex-shrink-0">
                        <Users className="h-3.5 w-3.5 text-foreground-secondary" />
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>{tt === 'initial' ? 'Initial connect' : 'Manual sync'}</TooltipContent>
                  </Tooltip>
                );
              }
              if (tt === 'scheduled') {
                return (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <img src="/images/logo.png" alt="" className="h-6 w-6 rounded-full flex-shrink-0" />
                    </TooltipTrigger>
                    <TooltipContent>Scheduled sync</TooltipContent>
                  </Tooltip>
                );
              }
              if (tt === 'webhook') {
                if (run.commit_author?.avatar_url) {
                  return (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <img src={run.commit_author.avatar_url} alt="" className="h-6 w-6 rounded-full flex-shrink-0" />
                      </TooltipTrigger>
                      <TooltipContent>{run.commit_author.username ? `Push by ${run.commit_author.username}` : 'Commit push'}</TooltipContent>
                    </Tooltip>
                  );
                }
                return (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="h-6 w-6 rounded-full bg-foreground-secondary/20 flex items-center justify-center flex-shrink-0">
                        <GitCommit className="h-3.5 w-3.5 text-foreground-secondary" />
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>Commit push</TooltipContent>
                  </Tooltip>
                );
              }
              return null;
            })()}
          </div>
        </div>

        {/* Animated in-place expansion */}
        {mounted && (
          <div
            className="grid transition-[grid-template-rows] duration-300 ease-out"
            style={{ gridTemplateRows: animateOpen ? '1fr' : '0fr' }}
            onTransitionEnd={() => { if (!expanded) setMounted(false); }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="overflow-hidden">
              <div className="px-4 pb-4">
                <InlineExtractionLogs
                  organizationId={organizationId}
                  projectId={projectId}
                  runId={run.run_id}
                  maxHeightClass="max-h-72"
                  showCancelButton={isActive}
                  onCancelled={onCancelled}
                />
              </div>
            </div>
          </div>
        )}
      </td>
    </tr>
  );
}

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  organization: Organization | null;
  userPermissions: ProjectPermissions | null;
}

/** Props for standalone use (e.g. org overview project sidebar). */
export interface ProjectSettingsContentProps {
  project: ProjectWithRole | null;
  organizationId: string;
  organization: Organization | null;
  userPermissions: ProjectPermissions | null;
  reloadProject: () => Promise<void>;
  embedInSidebar?: boolean;
  /** When embedded in a sidebar, the section to show on mount (e.g. 'general', 'repository'). */
  initialSection?: string;
  /** Called when the active section changes while embedded in a sidebar. */
  onSectionChange?: (section: string) => void;
  /** Optimistic rename: patch the new name into the graph/sidebar stores in place
   *  (no refetch) so the node label + header update instantly. */
  onProjectRenamed?: (newName: string) => void;
  /** Optimistic transfer: move the project node to its new owner team in the graph
   *  store in place (no refetch) so it relocates instantly. */
  onProjectTransferred?: (newOwnerTeamId: string) => void;
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

function formatWebhookTimeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return 'never';
  const diff = (Date.now() - new Date(dateStr).getTime()) / 1000;
  const mins = Math.floor(diff / 60);
  const hours = Math.floor(diff / 3600);
  const days = Math.floor(diff / 86400);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function formatRunDuration(createdAt: string, completedAt: string | null, status: string): string {
  const start = new Date(createdAt).getTime();
  const end = (completedAt ? new Date(completedAt).getTime() : Date.now());
  const sec = Math.max(0, Math.floor((end - start) / 1000));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h`;
}

const VALID_PROJECT_SETTINGS_SECTIONS = new Set(['general', 'repository', 'access', 'scanning']);


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
    case 'scanning':
      return (
        <div className="space-y-6">
          <div className={`h-8 w-32 ${pulse}`} />
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <div className={`h-4 w-20 ${pulse}`} />
            </div>
            <div className="p-4 space-y-4">
              <div className={`h-10 w-full max-w-xl ${pulse}`} />
              <div className={`h-10 w-full max-w-xl ${pulse}`} />
            </div>
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <div className={`h-4 w-24 ${pulse}`} />
              <div className={`h-8 w-24 ${pulse}`} />
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

export function ProjectSettingsContent(props: ProjectSettingsContentProps) {
  const { project, reloadProject, organizationId, organization, userPermissions, embedInSidebar, initialSection, onSectionChange, onProjectRenamed, onProjectTransferred } = props;
  const params = useParams<{ projectId: string; section?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const projectId = project?.id ?? params.projectId ?? '';
  const sectionParam = params.section;
  const [sidebarSection, setSidebarSection] = useState<string>(initialSection ?? 'general');
  const activeSection = embedInSidebar ? sidebarSection : (sectionParam && VALID_PROJECT_SETTINGS_SECTIONS.has(sectionParam) ? sectionParam : 'general');
  /** Match Dependencies / Compliance embed: bleed past org project drawer px-5; same shell as drawer (not lighter bg-background-content). */
  const mainEmbedClass = embedInSidebar
    ? '-mx-5 min-h-[28rem] h-full w-[calc(100%+2.5rem)] max-w-none'
    : undefined;
  const embedShellBg = 'bg-background-card-header';
  const settingsInnerShellClass = cn(
    embedInSidebar ? 'max-w-none w-full' : 'mx-auto max-w-7xl',
    embedInSidebar ? 'px-3 py-4' : 'px-4 sm:px-6 lg:px-8 py-8'
  );
  const { toast } = useToast();
  const [projectName, setProjectName] = useState(project?.name || '');
  const [isSavingName, setIsSavingName] = useState(false);
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
    framework?: string;
    ecosystem?: string;
  } | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedPackagePath, setSelectedPackagePath] = useState<string>('');

  // Framework detection state (for connected repository)
  const [detectedFramework, setDetectedFramework] = useState<string>('unknown');
  const [frameworkLoading, setFrameworkLoading] = useState(false);
  // Pull request comments toggle (repository settings)
  const [pullRequestCommentsEnabled, setPullRequestCommentsEnabled] = useState(true);
  const [autoFixVulnerabilitiesEnabled, setAutoFixVulnerabilitiesEnabled] = useState(false);
  const [scanOnCommit, setScanOnCommit] = useState<boolean>(false);
  const [syncFrequency, setSyncFrequency] = useState<string>('daily');
  const [syncFrequencySaving, setSyncFrequencySaving] = useState(false);
  const [extractionRuns, setExtractionRuns] = useState<ExtractionRun[]>([]);
  const [extractionRunsLoading, setExtractionRunsLoading] = useState(true);
  const [rescanning, setRescanning] = useState(false);
  // Which project's runs we've already loaded — gates the skeleton to the first load only.
  const loadedRunsForProjectRef = useRef<string | null>(null);
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

  // Normalize legacy ?section=... query to path so refresh and back/forward work
  useEffect(() => {
    if (embedInSidebar) return;
    const qSection = searchParams.get('section');
    if (!organizationId || !projectId || !qSection) return;
    if (VALID_PROJECT_SETTINGS_SECTIONS.has(qSection)) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/settings/${qSection}`, { replace: true });
    }
  }, [organizationId, projectId, searchParams, navigate, embedInSidebar]);

  // Redirect to settings/general when section param is invalid
  useEffect(() => {
    if (embedInSidebar) return;
    if (organizationId && projectId && sectionParam && !VALID_PROJECT_SETTINGS_SECTIONS.has(sectionParam)) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/settings/general`, { replace: true });
    }
  }, [organizationId, projectId, sectionParam, navigate, embedInSidebar]);

  // Sync projectName when project changes
  useEffect(() => {
    if (project?.name) {
      setProjectName(project.name);
    }
  }, [project?.name]);

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
      setSyncFrequency((data.connectedRepository as any)?.sync_frequency === 'weekly' ? 'weekly' : 'daily');
      setScanOnCommit((data.connectedRepository as any)?.scan_on_commit === true);
    } catch (error: any) {
      setRepositoriesError(error.message || 'Failed to load repositories');
    } finally {
      setRepositoriesLoading(false);
    }
  };

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
        setSyncFrequency((cached.connectedRepository as any)?.sync_frequency === 'weekly' ? 'weekly' : 'daily');
        setScanOnCommit((cached.connectedRepository as any)?.scan_on_commit === true);
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

  // Fetch extraction runs when Repository tab is active.
  // Only show the skeleton on the first load for a given project; on tab revisits
  // (component stays mounted) keep the existing rows and refetch silently — no flash.
  useEffect(() => {
    if (activeSection !== 'repository' || !organizationId || !projectId) return;
    const isFirstLoadForProject = loadedRunsForProjectRef.current !== projectId;
    if (isFirstLoadForProject) setExtractionRunsLoading(true);
    api.getExtractionRuns(organizationId, projectId).then((runs) => {
      setExtractionRuns(runs);
      loadedRunsForProjectRef.current = projectId;
    }).catch(() => {
      if (isFirstLoadForProject) setExtractionRuns([]);
    }).finally(() => {
      setExtractionRunsLoading(false);
    });

  }, [activeSection, organizationId, projectId]);

  // Poll extraction runs when on Repository tab so status and "X ago" stay live
  useEffect(() => {
    if (activeSection !== 'repository' || !organizationId || !projectId) return;
    const interval = setInterval(() => {
      api.getExtractionRuns(organizationId, projectId).then(setExtractionRuns).catch(() => {});
    }, 6000);
    return () => clearInterval(interval);
   
  }, [activeSection, organizationId, projectId]);

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

  // Teams this project can be transferred TO — every team except the one that already
  // owns it (transferring to the current owner is a no-op). A contributing team is a
  // valid target, so this only excludes the owner.
  const transferableTeams = useMemo(
    () => teams.filter(t => t.id !== projectTeams?.owner_team?.id),
    [teams, projectTeams?.owner_team?.id],
  );

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

  // Reset the transfer picker to no selection when the project (owner) changes. The
  // current owner isn't a transfer target, so there's no sensible default — the user
  // picks the destination team explicitly.
  useEffect(() => {
    setSelectedTeamId(null);
  }, [projectTeams?.owner_team?.id, project?.id]);

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

      // Move the project node to its new owner team on the graph in place — instant,
      // no refetch (mirrors the name-save pattern).
      onProjectTransferred?.(selectedTeamId);

      const selectedTeam = teams.find(t => t.id === selectedTeamId);
      toast({
        title: 'Ownership transferred',
        description: `Project ownership has been transferred to ${selectedTeam?.name || 'the selected team'}.`,
      });

      // Reconcile the sidebar's owner/contributing details in the background — don't
      // block the spinner on these two full GETs (the slow part).
      void loadProjectTeams();
      void reloadProject();
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
      id: 'scanning',
      label: 'DAST',
      icon: <Globe className="h-4 w-4 tab-icon-shake" />,
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
      <div
        className={cn(
          embedInSidebar ? embedShellBg : 'bg-background-content',
          embedInSidebar && 'min-h-0 h-full',
          mainEmbedClass
        )}
      >
        <div className={settingsInnerShellClass}>
          <div
            className={cn(
              'flex items-start',
              embedInSidebar ? 'gap-6 pr-12' : 'gap-8'
            )}
          >
            {/* Sidebar skeleton */}
            <aside className={cn('flex-shrink-0', embedInSidebar ? 'w-48 pt-6' : 'w-64')}>
              <div className={cn(!embedInSidebar && 'sticky top-24 pt-8 bg-background-content z-10')}>
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

  const handleSaveName = async () => {
    if (!organizationId || !project?.id || !projectName.trim()) return;
    const trimmed = projectName.trim();
    try {
      setIsSavingName(true);
      await api.updateProject(organizationId, project.id, { name: trimmed } as any);
      // Patch the name into the graph/sidebar stores in place — no refetch. The PUT
      // already returned the updated project, so a second GET only adds latency and
      // wouldn't touch the graph stores anyway (which is why the node didn't update).
      onProjectRenamed?.(trimmed);
      toast({ title: 'Success', description: 'Project name saved' });
    } catch (error: any) {
      toast({ title: 'Error', description: error.message || 'Failed to save project name' });
    } finally {
      setIsSavingName(false);
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
      if (data.framework && data.framework !== 'unknown') {
        setDetectedFramework(data.framework);
      }
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
    const resolvedFramework = scanResult?.framework || repo.framework || 'unknown';
    const matchedProject = scanResult?.potentialProjects?.find((p: any) => p.path === packagePath);
    const resolvedEcosystem = matchedProject?.ecosystem || scanResult?.ecosystem || repo.ecosystem;
    if (resolvedFramework !== 'unknown') setDetectedFramework(resolvedFramework);
    setRepoToConnect(null);
    setScanResult(null);
    try {
      const connected = await api.connectProjectRepository(organizationId, projectId, {
        repo_id: repo.id,
        repo_full_name: repo.full_name,
        default_branch: repo.default_branch,
        framework: resolvedFramework,
        package_json_path: packagePath || undefined,
        ecosystem: resolvedEcosystem,
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

  const handleSyncFrequencySelect = (value: string) => {
    setSyncFrequency(value);
  };

  const handleSaveSyncFrequency = async () => {
    if (!organizationId || !projectId) return;
    const savedFreq = (connectedRepository as any)?.sync_frequency ?? 'daily';
    const savedScan = (connectedRepository as any)?.scan_on_commit === true;
    if (syncFrequency === savedFreq && scanOnCommit === savedScan) return;
    setSyncFrequencySaving(true);
    try {
      await api.updateProjectRepositorySettings(organizationId, projectId, {
        scan_on_commit: scanOnCommit,
        sync_frequency: syncFrequency,
      });
      setConnectedRepository((r) =>
        r ? { ...r, scan_on_commit: scanOnCommit, sync_frequency: syncFrequency } as any : null
      );
      toast({ title: 'Sync settings saved' });
    } catch (err: any) {
      toast({
        title: 'Failed to update sync settings',
        description: (err as Error).message,
        variant: 'destructive',
      });
    } finally {
      setSyncFrequencySaving(false);
    }
  };

  // Manual "Rescan now" — re-queues an extraction for the connected repo on
  // demand (same path as the periodic sync). The backend rejects a concurrent
  // run (409) and enforces a short cooldown (429); we surface either as a toast.
  const handleTriggerRescan = async () => {
    if (!organizationId || !projectId || rescanning) return;
    setRescanning(true);
    try {
      await api.triggerProjectSync(organizationId, projectId);
      toast({ title: 'Rescan queued', description: 'A fresh scan is starting — new results will appear shortly.' });
      // Reflect the just-queued run in the activity table + project state.
      await reloadProject?.();
      api.getExtractionRuns(organizationId, projectId).then(setExtractionRuns).catch(() => {});
    } catch (err: any) {
      toast({
        title: 'Could not start rescan',
        description: (err as Error).message,
        variant: 'destructive',
      });
    } finally {
      setRescanning(false);
    }
  };

  const isRepoDisconnected = connectedRepository?.status === 'repo_deleted'
    || connectedRepository?.status === 'access_revoked'
    || connectedRepository?.status === 'installation_removed';

  const disconnectedBannerMessage = (() => {
    const provider = (connectedRepository as any)?.provider || 'GitHub';
    const providerLabel = provider === 'gitlab' ? 'GitLab' : provider === 'bitbucket' ? 'Bitbucket' : 'GitHub';
    switch (connectedRepository?.status) {
      case 'repo_deleted':
        return `This repository has been deleted on ${providerLabel}. Please connect a different repository.`;
      case 'access_revoked':
        return `The Deptex ${providerLabel} App no longer has access to this repository. Please re-install the App or connect a different repository.`;
      case 'installation_removed':
        return `The Deptex ${providerLabel} App has been uninstalled from this organization. Please re-install to continue syncing.`;
      default:
        return '';
    }
  })();

  return (
    <div
      className={cn(
        embedInSidebar ? embedShellBg : 'bg-background-content',
        embedInSidebar && 'min-h-0 h-full',
        mainEmbedClass
      )}
    >
      <div className={settingsInnerShellClass}>
        <div
          className={cn(
            'flex items-start',
            embedInSidebar ? 'gap-6 pr-12' : 'gap-8'
          )}
        >
          {/* Sidebar — embed: match team settings drawer (w-48, pt-6); full page: sticky + w-64 */}
          <aside className={cn('flex-shrink-0', embedInSidebar ? 'w-48 pt-6' : 'w-64')}>
            <div className={cn(!embedInSidebar && 'sticky top-24 pt-8 bg-background-content z-10')}>
              <nav className="space-y-1">
                {projectSettingsSections.map((section) => (
                  <button
                    key={section.id}
                    type="button"
                    onClick={() => {
                      if (embedInSidebar) { setSidebarSection(section.id); onSectionChange?.(section.id); }
                      else if (organizationId && projectId) navigate(`/organizations/${organizationId}/projects/${projectId}/settings/${section.id}`);
                    }}
                    className={cn(
                      'group w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors',
                      activeSection === section.id
                        ? 'text-foreground'
                        : 'text-foreground-secondary hover:text-foreground'
                    )}
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
                {/* Project Name Card */}
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <div className="p-6">
                    <h3 className="text-base font-semibold text-foreground mb-1">Project Name</h3>
                    <p className="text-sm text-foreground-secondary mb-4">
                      This is your project's visible name. It will be displayed throughout the dashboard.
                    </p>
                    <div className="max-w-md">
                      <input
                        type="text"
                        value={projectName}
                        onChange={(e) => canEditSettings && setProjectName(e.target.value)}
                        readOnly={!canEditSettings}
                        placeholder="Enter project name"
                        className={cn("w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors", !canEditSettings && "opacity-60 cursor-not-allowed")}
                      />
                    </div>
                  </div>
                  <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                    <Button
                      variant="green"
                      onClick={handleSaveName}
                      disabled={isSavingName || !canEditSettings || projectName === project?.name || !projectName.trim()}
                      className="relative"
                    >
                      <span className={isSavingName ? 'invisible' : undefined}>Save</span>
                      {isSavingName && (
                        <span className="absolute inset-0 flex items-center justify-center">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        </span>
                      )}
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
                    {transferableTeams.length > 0 || loadingTeams ? (
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <label className="text-sm font-medium text-foreground">New owner team</label>
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
                                teams={transferableTeams}
                                placeholder="Select a team"
                                className="bg-background-card border border-border rounded-lg text-sm text-foreground transition-colors"
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-foreground-secondary bg-black/20 rounded-lg p-3 border border-border">
                        <Users className="h-4 w-4 flex-shrink-0" />
                        <span>No other teams to transfer to. Create another team first.</span>
                      </div>
                    )}
                  </div>
                  {transferableTeams.length > 0 && (
                    <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                      <Button
                        onClick={handleTransferProject}
                        variant="green"
                        className="relative"
                        disabled={!selectedTeamId || isTransferring}
                      >
                        <span className={isTransferring ? 'invisible' : undefined}>Transfer</span>
                        {isTransferring && (
                          <span className="absolute inset-0 flex items-center justify-center">
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          </span>
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
                          variant="destructive"
                          className="flex-shrink-0"
                        >
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
                          autoFocus
                          className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-colors"
                        />
                        <div className="flex gap-2">
                          <Button
                            onClick={handleDelete}
                            variant="destructive"
                            disabled={deleteConfirmText !== project.name || isDeletingProject}
                          >
                            <span className={isDeletingProject ? 'invisible' : undefined}>Delete Forever</span>
                            {isDeletingProject && (
                              <span className="absolute inset-0 flex items-center justify-center">
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              </span>
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

            {activeSection === 'repository' && (
              <div className="space-y-8">
                {/* Disconnected repository banner */}
                {isRepoDisconnected && disconnectedBannerMessage && (
                  <div className="flex items-start gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-4 py-3">
                    <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0 mt-0.5" />
                    <p className="text-sm text-foreground">{disconnectedBannerMessage}</p>
                  </div>
                )}

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
                    <div className="flex flex-wrap gap-2 justify-center">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => navigate(`/organizations/${organizationId}/settings/integrations`)}
                        className="gap-2 border-border hover:bg-background-subtle"
                      >
                        <img src="/images/integrations/github.png" alt="" className="h-3.5 w-3.5 rounded-sm" />
                        Add GitHub
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => navigate(`/organizations/${organizationId}/settings/integrations`)}
                        className="gap-2 border-border hover:bg-background-subtle"
                      >
                        <img src="/images/integrations/gitlab.png" alt="" className="h-3.5 w-3.5 rounded-sm" />
                        Add GitLab
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => navigate(`/organizations/${organizationId}/settings/integrations`)}
                        className="gap-2 border-border hover:bg-background-subtle"
                      >
                        <img src="/images/integrations/bitbucket.png" alt="" className="h-3.5 w-3.5 rounded-sm" />
                        Add Bitbucket
                      </Button>
                    </div>
                  ) : connectedRepository ? (
                    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                      <div className="flex items-center gap-4 p-5">
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
                          <div className="text-xs text-foreground-secondary flex items-center gap-1 mt-0.5 font-mono">
                            <Folder className="h-3.5 w-3.5 shrink-0" />
                            {connectedRepository.package_json_path
                              ? `/${connectedRepository.package_json_path.replace(/^\/+/, '')}`
                              : 'Repository root'}
                          </div>
                        </div>
                        <Button
                          variant="green"
                          onClick={handleTriggerRescan}
                          disabled={rescanning || !canEditSettings || isRepoDisconnected || isExtractionOngoing(connectedRepository?.status ?? '')}
                          className="relative shrink-0"
                        >
                          <span className={rescanning ? 'invisible' : undefined}>Rescan</span>
                          {rescanning && (
                            <span className="absolute inset-0 flex items-center justify-center">
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            </span>
                          )}
                        </Button>
                      </div>
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

                {/* Sync Frequency */}
                {connectedRepository && (
                  <section>
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <div className="p-6">
                        <h3 className="text-base font-semibold text-foreground mb-1">Sync Frequency</h3>
                        <p className="text-sm text-foreground-secondary mb-4">
                          When Deptex re-extracts dependencies from this repository.
                        </p>
                        {/* Part 1 — scan on every commit (event-driven, real-time); a single toggleable card styled like the floor options */}
                        <button
                          type="button"
                          role="checkbox"
                          aria-checked={scanOnCommit}
                          aria-label="Scan on every commit"
                          onClick={() => setScanOnCommit((v) => !v)}
                          className={cn(
                            'w-full rounded-lg border px-4 py-3 flex items-center gap-3 text-left transition-all',
                            scanOnCommit
                              ? 'bg-background-card border-foreground/50 ring-1 ring-foreground/20'
                              : 'bg-black/20 border-border text-foreground hover:border-foreground-secondary/30 hover:bg-black/30'
                          )}
                        >
                          <div className={cn('h-4 w-4 rounded-full border-2 flex-shrink-0 transition-colors', scanOnCommit ? 'border-foreground bg-foreground' : 'border-foreground-secondary/50 bg-transparent')} aria-hidden />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-foreground">Scan on every commit</div>
                            <p className="text-xs text-muted-foreground mt-0.5">Re-extract on each push to the default branch — catches a newly-added vulnerable dependency immediately.</p>
                          </div>
                        </button>

                        {/* Part 2 — periodic floor (always runs, independent of the commit toggle) */}
                        <div className="mt-6">
                          <div className="text-sm font-medium text-foreground mb-1">Re-check for new vulnerabilities</div>
                          <p className="text-xs text-muted-foreground mb-3">Even without new commits, re-scan dependencies against newly-published advisories at least this often.</p>
                          <div className="w-full space-y-2" role="radiogroup" aria-label="Re-check frequency">
                            {[
                              { value: 'daily', label: 'Daily', description: 'Re-check once per day.' },
                              { value: 'weekly', label: 'Weekly', description: 'Re-check once per week.' },
                            ].map((opt) => {
                              const isSelected = syncFrequency === opt.value;
                              return (
                                <button
                                  key={opt.value}
                                  type="button"
                                  role="radio"
                                  aria-checked={isSelected}
                                  onClick={() => handleSyncFrequencySelect(opt.value)}
                                  className={cn(
                                    'w-full rounded-lg border px-4 py-3 flex items-center gap-3 text-left transition-all',
                                    isSelected
                                      ? 'bg-background-card border-foreground/50 ring-1 ring-foreground/20'
                                      : 'bg-black/20 border-border text-foreground hover:border-foreground-secondary/30 hover:bg-black/30'
                                  )}
                                >
                                  <div className={cn('h-4 w-4 rounded-full border-2 flex-shrink-0 transition-colors', isSelected ? 'border-foreground bg-foreground' : 'border-foreground-secondary/50 bg-transparent')} aria-hidden />
                                  <div className="flex-1 min-w-0">
                                    <div className="text-sm font-medium text-foreground">{opt.label}</div>
                                    <p className="text-xs text-muted-foreground mt-0.5">{opt.description}</p>
                                  </div>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                      <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                        {(() => {
                          const savedSync = (connectedRepository as any)?.sync_frequency ?? 'daily';
                          const savedScan = (connectedRepository as any)?.scan_on_commit === true;
                          const hasChange = syncFrequency !== savedSync || scanOnCommit !== savedScan;
                          return (
                            <Button
                              variant="green"
                              onClick={handleSaveSyncFrequency}
                              disabled={syncFrequencySaving || !canEditSettings || !hasChange}
                              className="relative"
                            >
                              <span className={syncFrequencySaving ? 'invisible' : undefined}>Save</span>
                              {syncFrequencySaving && (
                                <span className="absolute inset-0 flex items-center justify-center">
                                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                </span>
                              )}
                            </Button>
                          );
                        })()}
                      </div>
                    </div>
                  </section>
                )}

                {/* Recent Activity — Vercel-style deployments table */}
                {connectedRepository && (
                  <div>
                    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                      <table className="w-full">
                        <thead className="bg-background-card-header border-b border-border">
                          <tr>
                            <th colSpan={3} className="p-0">
                              <div className="flex items-center px-4 py-2.5 gap-4">
                                <span className="flex-[4] text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Source</span>
                                <span className="flex-[1] text-left text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</span>
                                <span className="flex-[1] text-right text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Time</span>
                              </div>
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {extractionRunsLoading ? (
                            [1, 2, 3, 4, 5].map((i) => (
                              <tr key={i} className="animate-pulse">
                                <td className="px-4 py-3">
                                  <div className="flex items-center gap-2">
                                    <div className="h-4 w-4 bg-muted rounded shrink-0" />
                                    <div className="h-4 bg-muted rounded w-24" />
                                    <div className="h-4 bg-muted rounded w-32 hidden sm:block" />
                                  </div>
                                </td>
                                <td className="px-4 py-3">
                                  <div className="flex flex-col gap-1">
                                    <div className="flex items-center gap-2">
                                      <div className="h-2 w-2 rounded-full bg-muted" />
                                      <div className="h-4 bg-muted rounded w-16" />
                                    </div>
                                    <div className="h-3 bg-muted rounded w-8" />
                                  </div>
                                </td>
                                <td className="px-4 py-3 text-right">
                                  <div className="flex flex-col items-end gap-1">
                                    <div className="h-4 bg-muted rounded w-14 ml-auto" />
                                    <div className="flex items-center gap-1.5">
                                      <div className="h-5 w-5 rounded-full bg-muted" />
                                      <div className="h-3 bg-muted rounded w-16" />
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            ))
                          ) : extractionRuns.length === 0 ? (
                            <tr>
                              <td colSpan={3} className="px-4 py-8 text-center text-sm text-foreground-secondary">
                                No extraction runs yet. Sync the repository to see activity.
                              </td>
                            </tr>
                          ) : (
                            extractionRuns.map((run) => (
                              <RunRow
                                key={run.run_id}
                                run={run}
                                organizationId={organizationId}
                                projectId={projectId!}
                                onCancelled={() => {
                                  reloadProject?.();
                                  api.getExtractionRuns(organizationId, projectId!).then(setExtractionRuns).catch(() => {});
                                }}
                              />
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
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
                        <div className="h-8 w-28 bg-muted rounded-lg animate-pulse"></div>
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
                        <div className="h-8 w-28 bg-muted rounded-lg animate-pulse"></div>
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
                          <div className="flex items-center gap-3 p-3 bg-black/20 rounded-lg border border-border">
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
                          variant="green"
                        >
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
                          variant="green"
                        >
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

            {activeSection === 'scanning' && projectId && (
              <DastScanningTab
                projectId={projectId}
                canManage={!!userPermissions?.edit_settings}
              />
            )}

          </div>
        </div>
      </div>

      {/* Add Team Modal */}
      <Dialog open={showAddTeamSidepanel} onOpenChange={(open) => {
        if (!open) {
          setShowAddTeamSidepanel(false);
          setTeamSearchQuery('');
          setSelectedTeamsToAdd([]);
        }
      }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden flex flex-col min-h-[480px] max-h-[85vh]">
          {/* Header */}
          <div className="px-6 pt-6 pb-4 flex-shrink-0">
            <DialogTitle>Add Contributing Teams</DialogTitle>
            <DialogDescription className="mt-1">
              Select teams to give them access to this project. Contributing teams can view the project but cannot manage settings.
            </DialogDescription>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">

            {/* Search */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
              <input
                type="text"
                placeholder="Search teams..."
                value={teamSearchQuery}
                onChange={(e) => setTeamSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors"
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
                        ? 'bg-background-subtle border-foreground/40'
                        : 'bg-background-card border-border hover:border-foreground-secondary/40'
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
                        ? 'bg-foreground border-foreground text-background'
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

          {/* Footer */}
          <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
            <Button
              variant="outline"
              className="h-8 rounded-lg px-3"
              disabled={addingTeam}
              onClick={() => {
                setShowAddTeamSidepanel(false);
                setTeamSearchQuery('');
                setSelectedTeamsToAdd([]);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddContributingTeams}
              variant="green"
              disabled={selectedTeamsToAdd.length === 0 || addingTeam}
              className="relative"
            >
              <span className={addingTeam ? 'invisible' : undefined}>
                Add{selectedTeamsToAdd.length > 0 ? ` (${selectedTeamsToAdd.length})` : ''}
              </span>
              {addingTeam && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                </span>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Member Modal */}
      <Dialog open={showAddMemberSidepanel} onOpenChange={(open) => {
        if (!open) {
          setShowAddMemberSidepanel(false);
          setMemberSearchQuery('');
          setSelectedMembersToAdd([]);
        }
      }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden flex flex-col min-h-[480px] max-h-[85vh]">
          {/* Header */}
          <div className="px-6 pt-6 pb-4 flex-shrink-0">
            <DialogTitle>Add Project Members</DialogTitle>
            <DialogDescription className="mt-1">
              Select members to give them direct access to this project. Members already on teams with access are not shown.
            </DialogDescription>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">

            {/* Search */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
              <input
                type="text"
                placeholder="Search members..."
                value={memberSearchQuery}
                onChange={(e) => setMemberSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors"
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
                        ? 'bg-background-subtle border-foreground/40'
                        : 'bg-background-card border-border hover:border-foreground-secondary/40'
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
                        ? 'bg-foreground border-foreground text-background'
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

          {/* Footer */}
          <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
            <Button
              variant="outline"
              className="h-8 rounded-lg px-3"
              disabled={addingMember}
              onClick={() => {
                setShowAddMemberSidepanel(false);
                setMemberSearchQuery('');
                setSelectedMembersToAdd([]);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddDirectMembers}
              variant="green"
              disabled={selectedMembersToAdd.length === 0 || addingMember}
              className="relative"
            >
              <span className={addingMember ? 'invisible' : undefined}>
                Add{selectedMembersToAdd.length > 0 ? ` (${selectedMembersToAdd.length})` : ''}
              </span>
              {addingMember && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                </span>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function ProjectSettingsPage() {
  const { project, reloadProject, organizationId, organization, userPermissions } = useOutletContext<ProjectContextType>();
  return (
    <ProjectSettingsContent
      project={project}
      organizationId={organizationId}
      organization={organization}
      userPermissions={userPermissions}
      reloadProject={reloadProject}
    />
  );
}
