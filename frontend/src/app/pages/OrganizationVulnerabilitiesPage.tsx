import { Fragment, useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useOutletContext, useParams, useNavigate, Link, useSearchParams } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Filter, Plus, Search, ShieldCheck, X, LayoutDashboard, FolderKanban, Shield, FileCode, Settings, Activity, UserPlus, Users, FolderPlus, Loader2, Package, HeartPulse, ChevronRight, Check, AlertTriangle, CircleCheck, Bell, Grid3x3, List, MoreVertical, Trash2, Save, Mail, Webhook, ChevronDown, BookOpen, PauseCircle, Tag, Palette, GripVertical, Edit2, FileCheck, CircleHelp } from 'lucide-react';
import { Button } from '../../components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { Checkbox } from '../../components/ui/checkbox';
import { Badge } from '../../components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '../../components/ui/tooltip';
import { api, Organization, Team, Project, TeamWithRole, type ProjectStats, type ProjectVulnerability, type OrganizationStatus, type TeamStats, type TeamMember, type ProjectDependency, type OrganizationMember, type TeamRole, type TeamPermissions, type CiCdConnection, type ProjectSecuritySummary, type ProjectWithRole, type VulnerabilityDetail } from '../../lib/api';
import { cn } from '../../lib/utils';
import { computeOverviewStatusRollup, type OverviewStatusRollup } from '../../lib/overviewStatusRollup';
import { isExtractionOngoing } from '../../lib/extractionStatus';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../hooks/use-toast';
import {
  useOrganizationOverviewGraphLayout,
  ORG_CENTER_ID,
  type OverviewTeamWithProjects,
  type OverviewProjectItem,
} from '../../components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout';
import {
  ORG_OVERVIEW_EDGE_STROKE,
  ORG_OVERVIEW_CENTER_WIDTH,
  ORG_OVERVIEW_CENTER_HEIGHT,
} from '../../components/vulnerabilities-graph/overviewOrgLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { SkeletonGroupCenterNode } from '../../components/vulnerabilities-graph/SkeletonGroupCenterNode';
import { VulnProjectNode, OVERVIEW_PROJECT_NODE_WIDTH, OVERVIEW_PROJECT_NODE_HEIGHT } from '../../components/vulnerabilities-graph/VulnProjectNode';
import { ProjectCenterNode } from '../../components/vulnerabilities-graph/ProjectCenterNode';
import { TeamGroupNode } from '../../components/vulnerabilities-graph/TeamGroupNode';
import { SyncDetailSidebar } from '../../components/SyncDetailSidebar';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { FrameworkIcon } from '../../components/framework-icon';
import { TeamIcon } from '../../components/TeamIcon';
import { RoleBadge } from '../../components/RoleBadge';
import { RoleDropdown } from '../../components/RoleDropdown';
import NotificationRulesSection from './NotificationRulesSection';
import { TeamPermissionEditor } from '../../components/TeamPermissionEditor';
import type { NodeTypes } from '@xyflow/react';
import { ProjectDependenciesContent } from './ProjectDependenciesPage';
import { ProjectComplianceContent } from './ProjectCompliancePage';
import { ProjectSettingsContent } from './ProjectSettingsPage';
import {
  VulnOrgSidebarExpandedSkeleton,
  VulnerabilityOrgSidebarExpandedContent,
} from '../../components/security/VulnerabilityOrgSidebarExpandedContent';
import VulnerabilityExpandableTable from '../../components/security/VulnerabilityExpandableTable';
import OrganizationVulnerabilitiesTableSkeleton from '../../components/security/OrganizationVulnerabilitiesTableSkeleton';

interface OrganizationContextType {
  organization: Organization | null;
}

const nodeTypes: NodeTypes = {
  groupCenterNode: GroupCenterNode,
  vulnProjectNode: VulnProjectNode,
  projectCenterNode: ProjectCenterNode,
  dependencyNode: DependencyNode,
  teamGroupNode: TeamGroupNode,
};

const skeletonNodeTypes: NodeTypes = {
  skeletonGroupCenterNode: SkeletonGroupCenterNode,
};

const ORG_SKELETON_CENTER_POS = {
  x: -ORG_OVERVIEW_CENTER_WIDTH / 2,
  y: -ORG_OVERVIEW_CENTER_HEIGHT / 2,
};

const orgSkeletonNodes = [
  {
    id: 'skeleton-org-center',
    type: 'skeletonGroupCenterNode',
    position: ORG_SKELETON_CENTER_POS,
    data: {},
    style: { width: ORG_OVERVIEW_CENTER_WIDTH, height: ORG_OVERVIEW_CENTER_HEIGHT },
  },
];

const UNGROUPED_TEAM_ID = 'org-ungrouped';
const UNGROUPED_TEAM_NAME = 'No team';


/** Top-left of a node in flow coordinates, including parent group offset (nested project nodes). */
function getNodeFlowTopLeft(getNode: (id: string) => Node | undefined, nodeId: string): { x: number; y: number } | null {
  const node = getNode(nodeId);
  if (!node) return null;
  let x = node.position.x;
  let y = node.position.y;
  let pid = node.parentId;
  while (pid) {
    const p = getNode(pid);
    if (!p) break;
    x += p.position.x;
    y += p.position.y;
    pid = p.parentId;
  }
  return { x, y };
}

/** Match org Security graph overlay panels: `max-w-[1000px] sm:max-w-[1200px]`. */
function graphSidePanelWidthPx(paneWidth: number): number {
  if (typeof window === 'undefined') return Math.min(1000, paneWidth);
  const cap = window.innerWidth >= 640 ? 1200 : 1000;
  return Math.min(cap, paneWidth);
}

function getReactFlowPaneSize(paneEl: HTMLElement | null): { width: number; height: number } {
  const r = paneEl?.getBoundingClientRect();
  if (r && r.width > 0) return { width: r.width, height: r.height };
  if (typeof window === 'undefined') return { width: 1200, height: 800 };
  return { width: window.innerWidth, height: window.innerHeight - 48 };
}

export type ExpandFilter = 'all' | 'vulnerable' | 'not_allowed' | 'outdated';

function projectStatusLabel(project: Project): { label: string; inProgress: boolean; isError: boolean } {
  const status = project.repo_status;
  if (isExtractionOngoing(status || '', project.extraction_step ?? null)) {
    const step = project.extraction_step;
    const labels: Record<string, string> = {
      queued: 'Creating', cloning: 'Creating', sbom: 'Creating', deps_synced: 'Creating',
      ast_parsing: 'Creating', scanning: 'Creating', uploading: 'Creating', completed: 'Creating',
    };
    const label = step ? (labels[step] ?? 'Creating') : (status === 'analyzing' || status === 'finalizing' ? 'Analyzing' : 'Creating');
    return { label, inProgress: true, isError: false };
  }
  if (status === 'error') return { label: 'Failed', inProgress: false, isError: true };
  return {
    label: project.is_compliant !== false ? 'COMPLIANT' : 'NOT COMPLIANT',
    inProgress: false,
    isError: false,
  };
}

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  const day = date.getDate().toString().padStart(2, '0');
  const month = date.toLocaleDateString('en-US', { month: 'short' });
  const year = date.getFullYear().toString().slice(-2);
  return `${day} ${month} ${year}`;
};

/** Fixed column widths for project sidebar vuln table — keep skeleton + data table aligned (no layout shift). */
function OrgProjectVulnerabilitiesTableColgroup() {
  return (
    <colgroup>
      <col className="w-[6.75rem]" />
      <col />
      <col className="w-[7.5rem]" />
    </colgroup>
  );
}

const ORG_PROJECT_VULN_TABLE_CLASS = 'w-full text-sm table-fixed';

/** Skeleton for the project sidebar vulnerabilities table (matches loaded table chrome + columns). */
function OrgProjectVulnerabilitiesTableSkeleton({ rowCount = 6 }: { rowCount?: number }) {
  return (
    <div
      className="border border-border rounded-lg overflow-hidden"
      aria-busy="true"
      aria-label="Loading vulnerabilities"
    >
      <table className={ORG_PROJECT_VULN_TABLE_CLASS}>
        <OrgProjectVulnerabilitiesTableColgroup />
        <thead className="bg-background-card-header border-b border-border">
          <tr>
            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">
              Depscore
            </th>
            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase min-w-0">
              Dependency
            </th>
            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">
              Advisory
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {Array.from({ length: rowCount }, (_, i) => (
            <tr key={i}>
              <td className="px-4 py-2.5 align-middle">
                <div
                  className="h-4 rounded-md bg-muted/55 animate-pulse w-14"
                />
              </td>
              <td className="px-4 py-2.5 align-middle min-w-0">
                <div className="space-y-1.5 min-w-0 max-w-full">
                  <div
                    className={cn(
                      'h-3.5 rounded-md bg-muted/50 animate-pulse max-w-full',
                      i % 3 === 0 && 'w-[72%]',
                      i % 3 === 1 && 'w-[88%]',
                      i % 3 === 2 && 'w-[64%]',
                    )}
                  />
                  <div className="h-3 max-w-[6rem] rounded-md bg-muted/40 animate-pulse" />
                </div>
              </td>
              <td className="px-4 py-2.5 align-middle">
                <div className="h-5 w-[4.75rem] rounded-md bg-muted/50 animate-pulse" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function OrganizationVulnerabilitiesPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { toast } = useToast();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [teamsById, setTeamsById] = useState<Record<string, Team>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [orgSidebarOpen, setOrgSidebarOpen] = useState(false);
  const [orgSidebarVisible, setOrgSidebarVisible] = useState(false);
  const [teamSidebarOpen, setTeamSidebarOpen] = useState(false);
  const [teamSidebarVisible, setTeamSidebarVisible] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [selectedTeamName, setSelectedTeamName] = useState<string | null>(null);
  const [projectSidebarOpen, setProjectSidebarOpen] = useState(false);
  const [projectSidebarVisible, setProjectSidebarVisible] = useState(false);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [selectedProjectName, setSelectedProjectName] = useState<string | null>(null);
  const [selectedProjectFramework, setSelectedProjectFramework] = useState<string | null>(null);
  const [selectedProjectIsExtracting, setSelectedProjectIsExtracting] = useState(false);
  const [projectStats, setProjectStats] = useState<ProjectStats | null>(null);
  const [projectStatsLoading, setProjectStatsLoading] = useState(false);
  const [projectVulnerabilities, setProjectVulnerabilities] = useState<ProjectVulnerability[] | null>(null);
  const [expandedProjectVulnRowId, setExpandedProjectVulnRowId] = useState<string | null>(null);
  const [projectVulnDetailByRowId, setProjectVulnDetailByRowId] = useState<Record<string, { loading: boolean; error: string | null; data: VulnerabilityDetail | null }>>({});
  const [projectSidebarTab, setProjectSidebarTab] = useState<'vulnerabilities' | 'dependencies' | 'compliance' | 'settings'>('vulnerabilities');
  const [projectSidebarProject, setProjectSidebarProject] = useState<ProjectWithRole | null>(null);
  const [projectSidebarOrganization, setProjectSidebarOrganization] = useState<Organization | null>(null);
  const [projectSidebarProjectLoading, setProjectSidebarProjectLoading] = useState(false);
  const [statuses, setStatuses] = useState<OrganizationStatus[]>([]);
  const [selectedStatusIds, setSelectedStatusIds] = useState<Set<string>>(new Set());
  const [rawTeamsWithProjects, setRawTeamsWithProjects] = useState<OverviewTeamWithProjects[]>([]);
  const [graphRefreshTrigger, setGraphRefreshTrigger] = useState(0);
  const [silentRefreshTrigger, setSilentRefreshTrigger] = useState(0);
  const [expandingProjectId, setExpandingProjectId] = useState<string | null>(null);
  const [expandedProjectId, setExpandedProjectId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Node[]>([]);
  const [expandedEdges, setExpandedEdges] = useState<Edge[]>([]);
  const graphNodesRef = useRef<Node[]>([]);
  const [teamSidebarStats, setTeamSidebarStats] = useState<TeamStats | null>(null);
  const [teamSidebarMembers, setTeamSidebarMembers] = useState<TeamMember[]>([]);
  const [teamSidebarProjects, setTeamSidebarProjects] = useState<Project[]>([]);
  const [teamSidebarSecuritySummary, setTeamSidebarSecuritySummary] = useState<ProjectSecuritySummary[]>([]);
  const [teamSidebarVulns, setTeamSidebarVulns] = useState<ProjectVulnerability[]>([]);
  const [teamSidebarVulnsLoading, setTeamSidebarVulnsLoading] = useState(false);
  const [teamSidebarVulnsTotal, setTeamSidebarVulnsTotal] = useState(0);
  const [teamSidebarVulnsPage, setTeamSidebarVulnsPage] = useState(1);
  const [teamSidebarOrgMembers, setTeamSidebarOrgMembers] = useState<OrganizationMember[]>([]);
  const [teamSidebarRoles, setTeamSidebarRoles] = useState<TeamRole[]>([]);
  const [teamSidebarDataLoading, setTeamSidebarDataLoading] = useState(false);
  const [teamSidebarAddingMember, setTeamSidebarAddingMember] = useState(false);
  const [teamSidebarAddMemberOpen, setTeamSidebarAddMemberOpen] = useState(false);
  const [teamSidebarAddMemberVisible, setTeamSidebarAddMemberVisible] = useState(false);
  const [addMemberSearchQuery, setAddMemberSearchQuery] = useState('');
  const [addMemberSelectedUserIds, setAddMemberSelectedUserIds] = useState<string[]>([]);
  const [addMemberSelectedRoleId, setAddMemberSelectedRoleId] = useState<string>('member');
  const [addMemberAdding, setAddMemberAdding] = useState(false);
  const [syncDetailProjectId, setSyncDetailProjectId] = useState<string | null>(null);
  const [teamSidebarTab, setTeamSidebarTab] = useState<'projects' | 'security' | 'members' | 'settings'>('security');
  const [teamSidebarProjectsSearch, setTeamSidebarProjectsSearch] = useState('');
  const [teamSidebarProjectsViewMode, setTeamSidebarProjectsViewMode] = useState<'grid' | 'list'>('grid');
  const [teamSidebarMembersSearch, setTeamSidebarMembersSearch] = useState('');
  const [teamSidebarPermissions, setTeamSidebarPermissions] = useState<TeamPermissions | null>(null);
  const [teamSidebarTeamData, setTeamSidebarTeamData] = useState<TeamWithRole | null>(null);
  const [teamSidebarRoleChangeOpen, setTeamSidebarRoleChangeOpen] = useState(false);
  const [teamSidebarMemberToChangeRole, setTeamSidebarMemberToChangeRole] = useState<TeamMember | null>(null);
  const [teamSidebarNewRole, setTeamSidebarNewRole] = useState<string>('member');
  const [teamSidebarUpdatingRole, setTeamSidebarUpdatingRole] = useState(false);
  const [teamSidebarRemoveConfirmOpen, setTeamSidebarRemoveConfirmOpen] = useState(false);
  const [teamSidebarMemberToRemove, setTeamSidebarMemberToRemove] = useState<string | null>(null);
  const [teamSidebarRemovingMember, setTeamSidebarRemovingMember] = useState(false);
  // Project settings subtab state (persisted to URL when embedded in sidebar)
  const [projectSettingsSubTab, setProjectSettingsSubTab] = useState<string>('general');
  // Ref to ensure URL→state restoration only happens once per mount
  const restoredRef = useRef(false);
  // Team sidebar settings state
  const [teamSettingsSubTab, setTeamSettingsSubTab] = useState<'general' | 'notifications' | 'roles'>('general');
  const [teamSettingsName, setTeamSettingsName] = useState('');
  const [teamSettingsDescription, setTeamSettingsDescription] = useState('');
  const [teamSettingsSaving, setTeamSettingsSaving] = useState(false);
  const [teamSettingsShowDeleteConfirm, setTeamSettingsShowDeleteConfirm] = useState(false);
  const [teamSettingsDeleteConfirmText, setTeamSettingsDeleteConfirmText] = useState('');
  const [teamSettingsDeleting, setTeamSettingsDeleting] = useState(false);
  // Team sidebar notifications settings state
  const [teamSettingsConnections, setTeamSettingsConnections] = useState<{ inherited: CiCdConnection[]; team: CiCdConnection[] }>({ inherited: [], team: [] });
  const [teamSettingsConnectionsLoading, setTeamSettingsConnectionsLoading] = useState(false);
  const [teamSettingsNotifActiveTab, setTeamSettingsNotifActiveTab] = useState<'notifications' | 'destinations'>('notifications');
  const [teamSettingsNotifPausedUntil, setTeamSettingsNotifPausedUntil] = useState<string | null>(null);
  const [teamSettingsNotifPauseLoading, setTeamSettingsNotifPauseLoading] = useState(false);
  const teamSettingsNotificationCreateRef = useRef<(() => void) | null>(null);
  // Team sidebar roles settings state
  const [teamSettingsLoadingRoles, setTeamSettingsLoadingRoles] = useState(false);
  const [teamSettingsShowAddRoleSidepanel, setTeamSettingsShowAddRoleSidepanel] = useState(false);
  const [teamSettingsAddRolePanelVisible, setTeamSettingsAddRolePanelVisible] = useState(false);
  const [teamSettingsNewRoleNameInput, setTeamSettingsNewRoleNameInput] = useState('');
  const [teamSettingsNewRoleColor, setTeamSettingsNewRoleColor] = useState('');
  const [teamSettingsNewRolePermissions, setTeamSettingsNewRolePermissions] = useState<TeamPermissions>({
    view_overview: true, manage_projects: false, manage_members: false, view_settings: false,
    view_roles: false, edit_roles: false, manage_notification_settings: false, add_members: false, kick_members: false,
  });
  const [teamSettingsIsCreatingRole, setTeamSettingsIsCreatingRole] = useState(false);
  const [teamSettingsShowRoleSettingsModal, setTeamSettingsShowRoleSettingsModal] = useState(false);
  const [teamSettingsRoleSettingsPanelVisible, setTeamSettingsRoleSettingsPanelVisible] = useState(false);
  const [teamSettingsSelectedRoleForSettings, setTeamSettingsSelectedRoleForSettings] = useState<TeamRole | null>(null);
  const [teamSettingsEditingRolePermissions, setTeamSettingsEditingRolePermissions] = useState<TeamPermissions | null>(null);
  const [teamSettingsEditingRoleName, setTeamSettingsEditingRoleName] = useState('');
  const [teamSettingsEditingRoleColor, setTeamSettingsEditingRoleColor] = useState('');
  const [teamSettingsIsSavingRole, setTeamSettingsIsSavingRole] = useState(false);
  const [teamSettingsDeletingRoleId, setTeamSettingsDeletingRoleId] = useState<string | null>(null);
  const [teamSettingsCanEditSelectedRole, setTeamSettingsCanEditSelectedRole] = useState(false);
  const reactFlowInstanceRef = useRef<{
    fitView: (opts?: { nodes?: { id: string }[]; duration?: number }) => void;
    getViewport: () => { x: number; y: number; zoom: number };
    setViewport: (viewport: { x: number; y: number; zoom: number }, options?: { duration?: number }) => void;
    getNode: (id: string) => Node | undefined;
  } | null>(null);
  const reactFlowPaneRef = useRef<HTMLDivElement | null>(null);
  const focusedNodeIdRef = useRef<string | null>(null);

  /** Update URL search params in-place (replace, no new history entry). Pass null to delete a key. */
  const setSidebarParams = useCallback((updates: Record<string, string | null>) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(updates)) {
        if (v === null) next.delete(k);
        else next.set(k, v);
      }
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  /** Restore sidebar state from URL params after initial data load (runs once per mount). */
  useEffect(() => {
    if (loading || restoredRef.current) return;
    restoredRef.current = true;
    const sidebarParam = searchParams.get('sidebar');
    if (!sidebarParam) return;
    if (sidebarParam === 'org') {
      setOrgSidebarOpen(true);
      requestAnimationFrame(() => setOrgSidebarVisible(true));
    } else if (sidebarParam === 'team') {
      const tid = searchParams.get('teamId');
      const tabRaw = searchParams.get('tab');
      const validTeamTabs = new Set(['projects', 'security', 'members', 'settings']);
      const tab = (tabRaw && validTeamTabs.has(tabRaw) ? tabRaw : 'security') as 'projects' | 'security' | 'members' | 'settings';
      const subtabRaw = searchParams.get('subtab');
      const validTeamSubtabs = new Set(['general', 'notifications', 'roles']);
      const subtab = (subtabRaw && validTeamSubtabs.has(subtabRaw) ? subtabRaw : 'general') as 'general' | 'notifications' | 'roles';
      if (tid) {
        setSelectedTeamId(tid);
        setSelectedTeamName(teamsById[tid]?.name ?? null);
        setTeamSidebarTab(tab);
        setTeamSettingsSubTab(subtab);
        setTeamSidebarOpen(true);
        requestAnimationFrame(() => setTeamSidebarVisible(true));
      }
    } else if (sidebarParam === 'project') {
      const pid = searchParams.get('projectId');
      const tabRaw = searchParams.get('tab');
      const validProjectTabs = new Set(['vulnerabilities', 'dependencies', 'compliance', 'settings']);
      const tab = (tabRaw && validProjectTabs.has(tabRaw) ? tabRaw : 'vulnerabilities') as 'vulnerabilities' | 'dependencies' | 'compliance' | 'settings';
      const subtab = searchParams.get('subtab') ?? 'general';
      if (pid) {
        const projectInfo = rawTeamsWithProjects.flatMap(t => t.projects).find(p => p.projectId === pid);
        setSelectedProjectId(pid);
        setSelectedProjectName(projectInfo?.projectName ?? null);
        setSelectedProjectFramework(projectInfo?.framework ?? null);
        setProjectSidebarTab(tab);
        setProjectSettingsSubTab(subtab);
        setProjectSidebarOpen(true);
        requestAnimationFrame(() => setProjectSidebarVisible(true));
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, teamsById, rawTeamsWithProjects]);

  // Animate graph viewport when org sidebar opens/closes - center the clicked node
  useEffect(() => {
    const instance = reactFlowInstanceRef.current;
    if (!instance) return;

    const nodeId = focusedNodeIdRef.current;
    if (!nodeId) return;

    const node = instance.getNode(nodeId);
    if (!node) return;

    // Get the node's center position in flow coordinates (org hub uses overview center slot size)
    const nodeWidth =
      nodeId === ORG_CENTER_ID ? ORG_OVERVIEW_CENTER_WIDTH : 400;
    const nodeHeight = nodeId === ORG_CENTER_ID ? ORG_OVERVIEW_CENTER_HEIGHT : 300;
    const nodeCenterX = node.position.x + nodeWidth / 2;
    const nodeCenterY = node.position.y + nodeHeight / 2;

    const currentViewport = instance.getViewport();
    const zoom = currentViewport.zoom;
    const { width: screenWidth, height: screenHeight } = getReactFlowPaneSize(reactFlowPaneRef.current);
    const actualSidebarWidth = graphSidePanelWidthPx(screenWidth);

    if (orgSidebarVisible) {
      // Sidebar opening: center node in the LEFT portion of the screen
      const visibleWidth = screenWidth - actualSidebarWidth;
      const targetScreenX = visibleWidth / 2;
      const targetScreenY = screenHeight / 2;

      // Calculate viewport.x so that nodeCenterX appears at targetScreenX
      // screenX = nodeCenterX * zoom + viewport.x => viewport.x = targetScreenX - nodeCenterX * zoom
      const newViewportX = targetScreenX - nodeCenterX * zoom;
      const newViewportY = targetScreenY - nodeCenterY * zoom;

      const timer = setTimeout(() => {
        instance.setViewport(
          { x: newViewportX, y: newViewportY, zoom },
          { duration: 300 }
        );
      }, 50);
      return () => clearTimeout(timer);
    } else {
      // Sidebar closing: center node in the FULL screen
      const targetScreenX = screenWidth / 2;
      const targetScreenY = screenHeight / 2;

      const newViewportX = targetScreenX - nodeCenterX * zoom;
      const newViewportY = targetScreenY - nodeCenterY * zoom;

      instance.setViewport(
        { x: newViewportX, y: newViewportY, zoom },
        { duration: 300 }
      );
    }
  }, [orgSidebarVisible]);

  // Animate graph viewport when team sidebar opens/closes - center the clicked team node
  useEffect(() => {
    const instance = reactFlowInstanceRef.current;
    if (!instance) return;

    const nodeId = focusedNodeIdRef.current;
    if (!nodeId || !nodeId.startsWith('team-')) return;

    const node = instance.getNode(nodeId);
    if (!node) return;

    // Get the node's center position in flow coordinates
    // Team container size varies, use data.width/height if available
    const nodeData = node.data as { width?: number; height?: number };
    const nodeWidth = nodeData.width ?? 400;
    const nodeHeight = nodeData.height ?? 300;
    const nodeCenterX = node.position.x + nodeWidth / 2;
    const nodeCenterY = node.position.y + nodeHeight / 2;

    const currentViewport = instance.getViewport();
    const zoom = currentViewport.zoom;
    const { width: screenWidth, height: screenHeight } = getReactFlowPaneSize(reactFlowPaneRef.current);
    const actualSidebarWidth = graphSidePanelWidthPx(screenWidth);

    if (teamSidebarVisible) {
      const visibleWidth = screenWidth - actualSidebarWidth;
      const targetScreenX = visibleWidth / 2;
      const targetScreenY = screenHeight / 2;

      const newViewportX = targetScreenX - nodeCenterX * zoom;
      const newViewportY = targetScreenY - nodeCenterY * zoom;

      const timer = setTimeout(() => {
        instance.setViewport(
          { x: newViewportX, y: newViewportY, zoom },
          { duration: 300 }
        );
      }, 50);
      return () => clearTimeout(timer);
    } else {
      const targetScreenX = screenWidth / 2;
      const targetScreenY = screenHeight / 2;

      const newViewportX = targetScreenX - nodeCenterX * zoom;
      const newViewportY = targetScreenY - nodeCenterY * zoom;

      instance.setViewport(
        { x: newViewportX, y: newViewportY, zoom },
        { duration: 300 }
      );
    }
  }, [teamSidebarVisible]);

  // Animate graph viewport when project sidebar opens/closes — center the clicked project node
  useEffect(() => {
    const instance = reactFlowInstanceRef.current;
    if (!instance) return;

    const nodeId = focusedNodeIdRef.current;
    if (!nodeId || !nodeId.startsWith('project-')) return;

    const topLeft = getNodeFlowTopLeft((id) => instance.getNode(id), nodeId);
    if (!topLeft) return;

    const nodeWidth = OVERVIEW_PROJECT_NODE_WIDTH;
    const nodeHeight = OVERVIEW_PROJECT_NODE_HEIGHT;
    const nodeCenterX = topLeft.x + nodeWidth / 2;
    const nodeCenterY = topLeft.y + nodeHeight / 2;

    const currentViewport = instance.getViewport();
    const zoom = currentViewport.zoom;
    const { width: screenWidth, height: screenHeight } = getReactFlowPaneSize(reactFlowPaneRef.current);
    const actualSidebarWidth = graphSidePanelWidthPx(screenWidth);

    if (projectSidebarVisible) {
      const visibleWidth = screenWidth - actualSidebarWidth;
      const targetScreenX = visibleWidth / 2;
      const targetScreenY = screenHeight / 2;

      const newViewportX = targetScreenX - nodeCenterX * zoom;
      const newViewportY = targetScreenY - nodeCenterY * zoom;

      const timer = setTimeout(() => {
        instance.setViewport(
          { x: newViewportX, y: newViewportY, zoom },
          { duration: 300 }
        );
      }, 50);
      return () => clearTimeout(timer);
    }

    const targetScreenX = screenWidth / 2;
    const targetScreenY = screenHeight / 2;
    const newViewportX = targetScreenX - nodeCenterX * zoom;
    const newViewportY = targetScreenY - nodeCenterY * zoom;

    instance.setViewport(
      { x: newViewportX, y: newViewportY, zoom },
      { duration: 300 }
    );
  }, [projectSidebarVisible]);

  useEffect(() => {
    // Silent background refresh (no loading flash) triggered after sidebar data updates
    const onTeamsUpdated = () => setSilentRefreshTrigger((t) => t + 1);
    const onProjectsUpdated = () => setSilentRefreshTrigger((t) => t + 1);

    // Optimistic additions — immediately add new entities to graph without any fetch
    const onTeamCreated = (e: Event) => {
      const { id, name, role_display_name, role_color } = (e as CustomEvent).detail as { id: string; name: string; role_display_name: string | null; role_color: string | null };
      setRawTeamsWithProjects((prev) => [
        ...prev,
        { teamId: id, teamName: name, userRoleLabel: role_display_name ?? undefined, userRoleColor: role_color ?? undefined, projects: [], projectCount: 0, memberCount: 1 },
      ]);
    };
    const onProjectCreated = (e: Event) => {
      const { id, name, owner_team_id, team_ids } = (e as CustomEvent).detail as { id: string; name: string; owner_team_id: string | null; team_ids: string[] };
      const targetTeamId = owner_team_id ?? (team_ids?.[0] ?? null) ?? UNGROUPED_TEAM_ID;
      const newProj: OverviewTeamWithProjects['projects'][number] = {
        projectId: id,
        projectName: name,
        framework: null,
        statusName: null,
        statusColor: null,
        statusId: null,
        assetTierName: null,
        assetTierColor: null,
        isExtracting: false,
        healthScore: null,
      };
      setRawTeamsWithProjects((prev) => {
        const targetExists = prev.some((t) => t.teamId === targetTeamId);
        if (targetExists) {
          return prev.map((t) =>
            t.teamId === targetTeamId
              ? { ...t, projects: [...t.projects, newProj], projectCount: t.projectCount + 1 }
              : t
          );
        }
        // If team not yet in graph, add to ungrouped
        return prev.map((t) =>
          t.teamId === UNGROUPED_TEAM_ID
            ? { ...t, projects: [...t.projects, newProj], projectCount: t.projectCount + 1 }
            : t
        );
      });
    };

    window.addEventListener('organization:teamsUpdated', onTeamsUpdated);
    window.addEventListener('organization:projectsUpdated', onProjectsUpdated);
    window.addEventListener('organization:teamCreated', onTeamCreated);
    window.addEventListener('organization:projectCreated', onProjectCreated);
    return () => {
      window.removeEventListener('organization:teamsUpdated', onTeamsUpdated);
      window.removeEventListener('organization:projectsUpdated', onProjectsUpdated);
      window.removeEventListener('organization:teamCreated', onTeamCreated);
      window.removeEventListener('organization:projectCreated', onProjectCreated);
    };
  }, []);

  useEffect(() => {
    if (!organization?.id) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.getTeams(organization.id),
      api.getProjects(organization.id),
      api.getOrganizationStatuses(organization.id).catch(() => []),
    ])
      .then(([teams, allProjects, statusesData]) => {
        if (cancelled) return;
        setStatuses((statusesData as OrganizationStatus[]) ?? []);
        const byId: Record<string, Team> = {};
        (teams as Team[]).forEach((t) => { byId[t.id] = t; });
        setTeamsById(byId);

        const teamIds = new Set(teams.map((t: Team) => t.id));
        const projectsByTeam = new Map<string, Project[]>();
        teamIds.forEach((tid) => projectsByTeam.set(tid, []));
        projectsByTeam.set(UNGROUPED_TEAM_ID, []);

        allProjects.forEach((p: Project) => {
          const displayTeamId: string | null =
            p.owner_team_id ?? (p.team_ids && p.team_ids.length > 0 ? p.team_ids[0] : null);
          const bucket = displayTeamId && teamIds.has(displayTeamId)
            ? displayTeamId
            : UNGROUPED_TEAM_ID;
          projectsByTeam.get(bucket)!.push(p);
        });

        const ungroupedProjects = projectsByTeam.get(UNGROUPED_TEAM_ID) ?? [];
        // Include all teams in the graph (not only teams with projects) so new/empty teams show up
        const teamList: Array<{ id: string; name: string }> = [
          ...teams.map((t: Team) => ({ id: t.id, name: t.name })),
          ...(ungroupedProjects.length > 0 ? [{ id: UNGROUPED_TEAM_ID, name: UNGROUPED_TEAM_NAME }] : []),
        ];

        const byTeam = new Map<string, OverviewTeamWithProjects['projects']>();
        teamList.forEach((t) => byTeam.set(t.id, []));
        allProjects.forEach((p: Project) => {
          const displayTeamId =
            p.owner_team_id ?? (p.team_ids && p.team_ids.length > 0 ? p.team_ids[0] : null);
          const bucket =
            displayTeamId && teamIds.has(displayTeamId) ? displayTeamId : UNGROUPED_TEAM_ID;
          if (byTeam.has(bucket)) {
            const repoStatus = (p as Project).repo_status ?? null;
            const isExtracting = isExtractionOngoing(repoStatus || '', (p as Project).extraction_step ?? null);
            byTeam.get(bucket)!.push({
              projectId: p.id,
              projectName: p.name,
              framework: p.framework ?? null,
              statusName: p.status_name ?? null,
              statusColor: p.status_color ?? null,
              statusId: p.status_id ?? null,
              assetTierName: p.asset_tier_name ?? null,
              assetTierColor: p.asset_tier_color ?? null,
              isExtracting,
              healthScore: typeof (p as Project).health_score === 'number' ? (p as Project).health_score : null,
            });
          }
        });

        const realTeamIds = teamList.filter((t) => t.id !== UNGROUPED_TEAM_ID).map((t) => t.id);

        function applyResult(roleByTeamId: Map<string, { label: string | null; color: string | null }>) {
          const result: OverviewTeamWithProjects[] = teamList.map((t) => {
            const roleInfo = t.id === UNGROUPED_TEAM_ID ? null : roleByTeamId.get(t.id);
            const teamProjects = byTeam.get(t.id) ?? [];
            const teamMeta = t.id !== UNGROUPED_TEAM_ID ? (teams as Team[]).find((te) => te.id === t.id) : null;
            return {
              teamId: t.id,
              teamName: t.name,
              userRoleLabel: roleInfo?.label ?? undefined,
              userRoleColor: roleInfo?.color ?? undefined,
              projects: teamProjects,
              projectCount: teamProjects.length,
              memberCount: teamMeta?.member_count ?? undefined,
            };
          });
          setRawTeamsWithProjects(result);
        }

        const roleByTeamId = new Map<string, { label: string | null; color: string | null }>();
        (teams as TeamWithRole[]).forEach((t) => {
          roleByTeamId.set(t.id, {
            label: t.role_display_name ?? t.role ?? null,
            color: t.role_color ?? null,
          });
        });
        applyResult(roleByTeamId);
      })
      .catch((err) => {
        if (!cancelled) setError(err?.message ?? 'Failed to load data');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [organization?.id, graphRefreshTrigger]);

  // Silent background refresh — syncs graph data after sidebar operations without showing a loading state
  useEffect(() => {
    if (!organization?.id || silentRefreshTrigger === 0) return;
    let cancelled = false;
    const orgId = organization.id;
    Promise.all([
      api.getTeams(orgId),
      api.getProjects(orgId),
      api.getOrganizationStatuses(orgId).catch(() => []),
    ])
      .then(([teams, allProjects, statusesData]) => {
        if (cancelled) return;
        setStatuses((statusesData as OrganizationStatus[]) ?? []);
        const byId: Record<string, Team> = {};
        (teams as Team[]).forEach((t) => { byId[t.id] = t; });
        setTeamsById(byId);
        const teamIds = new Set(teams.map((t: Team) => t.id));
        const ungroupedProjects = (allProjects as Project[]).filter((p) => {
          const tid = p.owner_team_id ?? (p.team_ids && p.team_ids.length > 0 ? p.team_ids[0] : null);
          return !tid || !teamIds.has(tid);
        });
        const teamList: Array<{ id: string; name: string }> = [
          ...teams.map((t: Team) => ({ id: t.id, name: t.name })),
          ...(ungroupedProjects.length > 0 ? [{ id: UNGROUPED_TEAM_ID, name: UNGROUPED_TEAM_NAME }] : []),
        ];
        const byTeam = new Map<string, OverviewTeamWithProjects['projects']>();
        teamList.forEach((t) => byTeam.set(t.id, []));
        (allProjects as Project[]).forEach((p) => {
          const displayTeamId = p.owner_team_id ?? (p.team_ids && p.team_ids.length > 0 ? p.team_ids[0] : null);
          const bucket = displayTeamId && teamIds.has(displayTeamId) ? displayTeamId : UNGROUPED_TEAM_ID;
          if (byTeam.has(bucket)) {
            const repoStatus = p.repo_status ?? null;
            const isExtracting = isExtractionOngoing(repoStatus || '', p.extraction_step ?? null);
            byTeam.get(bucket)!.push({
              projectId: p.id, projectName: p.name, framework: p.framework ?? null,
              statusName: p.status_name ?? null, statusColor: p.status_color ?? null, statusId: p.status_id ?? null,
              assetTierName: p.asset_tier_name ?? null, assetTierColor: p.asset_tier_color ?? null,
              isExtracting, healthScore: typeof p.health_score === 'number' ? p.health_score : null,
            });
          }
        });
        const roleByTeamId = new Map<string, { label: string | null; color: string | null }>();
        (teams as TeamWithRole[]).forEach((t) => {
          roleByTeamId.set(t.id, { label: t.role_display_name ?? t.role ?? null, color: t.role_color ?? null });
        });
        const result: OverviewTeamWithProjects[] = teamList.map((t) => {
          const roleInfo = t.id === UNGROUPED_TEAM_ID ? null : roleByTeamId.get(t.id);
          const teamProjects = byTeam.get(t.id) ?? [];
          const teamMeta = t.id !== UNGROUPED_TEAM_ID ? (teams as Team[]).find((te) => te.id === t.id) : null;
          return {
            teamId: t.id, teamName: t.name,
            userRoleLabel: roleInfo?.label ?? undefined, userRoleColor: roleInfo?.color ?? undefined,
            projects: teamProjects, projectCount: teamProjects.length, memberCount: teamMeta?.member_count ?? undefined,
          };
        });
        setRawTeamsWithProjects(result);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [organization?.id, silentRefreshTrigger]);

  const teamsWithProjects = useMemo(() => {
    if (selectedStatusIds.size === 0) return rawTeamsWithProjects;
    return rawTeamsWithProjects.map((t) => ({
      ...t,
      projects: t.projects.filter(
        (proj) => proj.statusId != null && selectedStatusIds.has(proj.statusId)
      ),
    }));
  }, [rawTeamsWithProjects, selectedStatusIds]);

  const teamsWithProjectsForGraph = teamsWithProjects;

  const orgStatusRollup = useMemo(
    () => computeOverviewStatusRollup(teamsWithProjectsForGraph.flatMap((t) => t.projects), statuses),
    [teamsWithProjectsForGraph, statuses]
  );

  const teamStatusRollups = useMemo(() => {
    const m: Record<string, OverviewStatusRollup> = {};
    for (const t of teamsWithProjectsForGraph) {
      if (t.teamId === UNGROUPED_TEAM_ID) continue;
      m[t.teamId] = computeOverviewStatusRollup(t.projects, statuses);
    }
    return m;
  }, [teamsWithProjectsForGraph, statuses]);

  const orgRoleLabel = organization?.role_display_name ?? organization?.role ?? null;
  const orgRoleColor = organization?.role_color ?? null;

  // Placeholder: wire real data (e.g. active violations, policy failures) per org/team
  const orgItemsToAddress: string[] = [];
  const teamItemsToAddress: string[] = [];

  const scanCategories = [
    { label: 'Vulnerabilities', pct: 100 },
    { label: 'Secrets', pct: 100 },
    { label: 'License', pct: 100 },
    { label: 'Code', pct: 100 },
  ];

  const { nodes: layoutNodes, edges: layoutEdges } = useOrganizationOverviewGraphLayout(
    organization?.name ?? 'Organization',
    teamsWithProjectsForGraph,
    organization?.avatar_url || '/images/org_profile.png',
    orgRoleLabel,
    orgRoleColor,
    organization?.id ?? null,
    organization?.role ?? null,
    orgStatusRollup,
    teamStatusRollups
  );

  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>([]);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const stillShowingSkeleton = (!organization || loading) && teamsWithProjects.length === 0;

  const closeOrgSidebar = useCallback(() => {
    setOrgSidebarVisible(false);
    setSidebarParams({ sidebar: null, teamId: null, tab: null, subtab: null, projectId: null });
    setTimeout(() => setOrgSidebarOpen(false), 150);
  }, [setSidebarParams]);

  const closeTeamSidebar = useCallback(() => {
    setTeamSidebarVisible(false);
    setSidebarParams({ sidebar: null, teamId: null, tab: null, subtab: null, projectId: null });
    setTimeout(() => {
      setTeamSidebarOpen(false);
      setSelectedTeamId(null);
      setSelectedTeamName(null);
      setTeamSidebarAddMemberOpen(false);
      setTeamSidebarAddMemberVisible(false);
      setTeamSidebarTab('security');
      setTeamSidebarProjectsSearch('');
      setTeamSidebarProjectsViewMode('grid');
      setTeamSidebarMembersSearch('');
      setTeamSidebarPermissions(null);
      setTeamSidebarTeamData(null);
      setTeamSidebarRoleChangeOpen(false);
      setTeamSidebarMemberToChangeRole(null);
      setTeamSidebarRemoveConfirmOpen(false);
      setTeamSidebarMemberToRemove(null);
      // Reset settings state
      setTeamSettingsSubTab('general');
      setTeamSettingsName('');
      setTeamSettingsDescription('');
      setTeamSettingsShowDeleteConfirm(false);
      setTeamSettingsDeleteConfirmText('');
      setTeamSettingsConnections({ inherited: [], team: [] });
      setTeamSettingsNotifActiveTab('notifications');
      setTeamSettingsShowAddRoleSidepanel(false);
      setTeamSettingsAddRolePanelVisible(false);
      setTeamSettingsShowRoleSettingsModal(false);
      setTeamSettingsRoleSettingsPanelVisible(false);
    }, 150);
  }, [setSidebarParams]);

  const closeTeamSidebarAddMember = useCallback(() => {
    setTeamSidebarAddMemberVisible(false);
    setTimeout(() => {
      setTeamSidebarAddMemberOpen(false);
      setAddMemberSearchQuery('');
      setAddMemberSelectedUserIds([]);
      setAddMemberSelectedRoleId('member');
    }, 150);
  }, []);

  const teamSidebarAvailableOrgMembers = useMemo(() => {
    const teamMemberIds = new Set(teamSidebarMembers.map((m) => m.user_id));
    return teamSidebarOrgMembers.filter((m) => !teamMemberIds.has(m.user_id));
  }, [teamSidebarOrgMembers, teamSidebarMembers]);

  const teamSidebarFilteredAvailableMembers = useMemo(() => {
    if (!addMemberSearchQuery.trim()) return teamSidebarAvailableOrgMembers;
    const q = addMemberSearchQuery.toLowerCase();
    return teamSidebarAvailableOrgMembers.filter(
      (m) => m.email?.toLowerCase().includes(q) || m.full_name?.toLowerCase().includes(q)
    );
  }, [teamSidebarAvailableOrgMembers, addMemberSearchQuery]);

  const teamSidebarMemberCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    teamSidebarMembers.forEach((m) => {
      const name = m.role || 'member';
      counts[name] = (counts[name] || 0) + 1;
    });
    return counts;
  }, [teamSidebarMembers]);

  const teamSidebarFilteredProjects = useMemo(() => {
    if (!teamSidebarProjectsSearch.trim()) return teamSidebarProjects;
    const q = teamSidebarProjectsSearch.toLowerCase();
    return teamSidebarProjects.filter((p) => p.name.toLowerCase().includes(q));
  }, [teamSidebarProjects, teamSidebarProjectsSearch]);

  const teamSidebarFilteredMembers = useMemo(() => {
    let result = teamSidebarMembers;
    if (teamSidebarMembersSearch.trim()) {
      const q = teamSidebarMembersSearch.toLowerCase();
      result = result.filter((m) =>
        m.email?.toLowerCase().includes(q) || m.full_name?.toLowerCase().includes(q)
      );
    }
    // Sort by rank (lower rank = higher priority)
    return [...result].sort((a, b) => (a.rank ?? 999) - (b.rank ?? 999));
  }, [teamSidebarMembers, teamSidebarMembersSearch]);

  // Team sidebar member permission helpers
  const teamSidebarCanManageMembers = teamSidebarPermissions?.manage_members || teamSidebarPermissions?.kick_members || false;
  const teamSidebarCanAddMembers = teamSidebarPermissions?.manage_members || teamSidebarPermissions?.add_members || false;
  const teamSidebarCanEditRoles = teamSidebarPermissions?.edit_roles || false;
  const teamSidebarHasOrgManagePermission = organization?.permissions?.manage_teams_and_projects || false;

  // Get current user's membership in this team
  const teamSidebarUserMembership = teamSidebarMembers.find((m) => m.user_id === user?.id);
  const teamSidebarMaxValidRank = useMemo(() => {
    if (teamSidebarRoles.length === 0) return 1;
    return Math.max(...teamSidebarRoles.map((r) => r.display_order));
  }, [teamSidebarRoles]);
  const teamSidebarIsOrgLevelAccess = !teamSidebarUserMembership && teamSidebarCanEditRoles;
  const teamSidebarMemberRank = teamSidebarUserMembership?.rank;
  const teamSidebarIsValidRank = teamSidebarMemberRank !== null && teamSidebarMemberRank !== undefined && teamSidebarMemberRank <= teamSidebarMaxValidRank;
  const teamSidebarUserRank = teamSidebarIsOrgLevelAccess ? 0 : (teamSidebarIsValidRank ? teamSidebarMemberRank : teamSidebarMaxValidRank);

  // Handle role change
  const handleTeamSidebarChangeRole = useCallback((member: TeamMember) => {
    setTeamSidebarMemberToChangeRole(member);
    setTeamSidebarNewRole(member.role);
    setTeamSidebarRoleChangeOpen(true);
  }, []);

  const handleTeamSidebarUpdateRole = useCallback(async () => {
    if (!orgId || !selectedTeamId || !teamSidebarMemberToChangeRole) return;
    const roleToUse = teamSidebarRoles.find((r) => r.name === teamSidebarNewRole);
    if (!roleToUse?.id) return;
    try {
      setTeamSidebarUpdatingRole(true);
      await api.updateTeamMemberRole(orgId, selectedTeamId, teamSidebarMemberToChangeRole.user_id, roleToUse.id);
      setTeamSidebarMembers((prev) =>
        prev.map((m) =>
          m.user_id === teamSidebarMemberToChangeRole.user_id
            ? { ...m, role: teamSidebarNewRole, role_display_name: roleToUse.display_name || teamSidebarNewRole, role_color: roleToUse.color || null }
            : m
        )
      );
      toast({ title: 'Success', description: 'Member role updated' });
      setTeamSidebarRoleChangeOpen(false);
      setTeamSidebarMemberToChangeRole(null);
    } catch (err: any) {
      toast({ title: 'Error', description: err?.message || 'Failed to update role', variant: 'destructive' });
    } finally {
      setTeamSidebarUpdatingRole(false);
    }
  }, [orgId, selectedTeamId, teamSidebarMemberToChangeRole, teamSidebarNewRole, teamSidebarRoles, toast]);

  // Handle member removal
  const handleTeamSidebarRemoveMember = useCallback((userId: string) => {
    setTeamSidebarMemberToRemove(userId);
    setTeamSidebarRemoveConfirmOpen(true);
  }, []);

  const confirmTeamSidebarRemoveMember = useCallback(async () => {
    if (!orgId || !selectedTeamId || !teamSidebarMemberToRemove) return;
    const isSelf = user?.id === teamSidebarMemberToRemove;
    try {
      setTeamSidebarRemovingMember(true);
      await api.removeTeamMember(orgId, selectedTeamId, teamSidebarMemberToRemove);
      if (isSelf) {
        toast({ title: 'Left Team', description: 'You have left the team.' });
        closeTeamSidebar();
      } else {
        setTeamSidebarMembers((prev) => prev.filter((m) => m.user_id !== teamSidebarMemberToRemove));
        toast({ title: 'Success', description: 'Member removed from team' });
      }
      setTeamSidebarRemoveConfirmOpen(false);
      setTeamSidebarMemberToRemove(null);
    } catch (err: any) {
      toast({ title: 'Error', description: err?.message || 'Failed to remove member', variant: 'destructive' });
    } finally {
      setTeamSidebarRemovingMember(false);
    }
  }, [orgId, selectedTeamId, teamSidebarMemberToRemove, user?.id, toast, closeTeamSidebar]);

  useEffect(() => {
    if (teamSidebarAddMemberOpen) {
      setTeamSidebarAddMemberVisible(false);
      requestAnimationFrame(() => requestAnimationFrame(() => setTeamSidebarAddMemberVisible(true)));
    } else {
      setTeamSidebarAddMemberVisible(false);
    }
  }, [teamSidebarAddMemberOpen]);

  const closeProjectSidebar = useCallback(() => {
    setProjectSidebarVisible(false);
    setSidebarParams({ sidebar: null, teamId: null, tab: null, subtab: null, projectId: null });
    setTimeout(() => {
      setProjectSidebarOpen(false);
      setSelectedProjectId(null);
      setSelectedProjectName(null);
      setSelectedProjectFramework(null);
      setProjectStats(null);
      setProjectVulnerabilities(null);
      setExpandedProjectVulnRowId(null);
      setProjectVulnDetailByRowId({});
      setProjectSidebarProject(null);
      setProjectSidebarOrganization(null);
      setProjectSettingsSubTab('general');
    }, 150);
  }, [setSidebarParams]);

  const closeOrgSidebarImmediate = useCallback(() => {
    setOrgSidebarVisible(false);
    setOrgSidebarOpen(false);
  }, []);

  const closeTeamSidebarImmediate = useCallback(() => {
    setTeamSidebarVisible(false);
    setTeamSidebarOpen(false);
    setSelectedTeamId(null);
    setSelectedTeamName(null);
    setTeamSidebarAddMemberOpen(false);
    setTeamSidebarAddMemberVisible(false);
    setTeamSidebarTab('security');
    setTeamSidebarProjectsSearch('');
    setTeamSidebarProjectsViewMode('grid');
    setTeamSidebarMembersSearch('');
    setTeamSidebarPermissions(null);
    setTeamSidebarTeamData(null);
    setTeamSidebarRoleChangeOpen(false);
    setTeamSidebarMemberToChangeRole(null);
    setTeamSidebarRemoveConfirmOpen(false);
    setTeamSidebarMemberToRemove(null);
    setTeamSettingsSubTab('general');
    setTeamSettingsName('');
    setTeamSettingsDescription('');
    setTeamSettingsShowDeleteConfirm(false);
    setTeamSettingsDeleteConfirmText('');
    setTeamSettingsConnections({ inherited: [], team: [] });
    setTeamSettingsNotifActiveTab('notifications');
    setTeamSettingsShowAddRoleSidepanel(false);
    setTeamSettingsAddRolePanelVisible(false);
    setTeamSettingsShowRoleSettingsModal(false);
    setTeamSettingsRoleSettingsPanelVisible(false);
  }, []);

  const closeProjectSidebarImmediate = useCallback(() => {
    setProjectSidebarVisible(false);
    setProjectSidebarOpen(false);
    setSelectedProjectId(null);
    setSelectedProjectName(null);
    setSelectedProjectFramework(null);
    setSelectedProjectIsExtracting(false);
    setProjectStats(null);
    setProjectVulnerabilities(null);
    setExpandedProjectVulnRowId(null);
    setProjectVulnDetailByRowId({});
    setProjectSidebarProject(null);
    setProjectSidebarOrganization(null);
    setProjectSettingsSubTab('general');
  }, []);

  /** Open the project sidebar for a project (e.g. clicked from team projects list). Closes all other sidebars. */
  const openProjectInSidebar = useCallback((project: Project) => {
    focusedNodeIdRef.current = null; // prevent viewport re-center when team sidebar closes
    closeOrgSidebarImmediate();
    closeTeamSidebarImmediate();
    setSelectedProjectId(project.id);
    setSelectedProjectName(project.name);
    setSelectedProjectFramework(project.framework ?? null);
    setProjectStats(null);
    setProjectSidebarTab('vulnerabilities');
    setProjectSettingsSubTab('general');
    setSidebarParams({ sidebar: 'project', projectId: project.id, tab: 'vulnerabilities', subtab: null, teamId: null });
    setProjectSidebarOpen(true);
    requestAnimationFrame(() => setProjectSidebarVisible(true));
  }, [closeOrgSidebarImmediate, closeTeamSidebarImmediate, setSidebarParams]);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (!orgId) return;
      if (node.id === ORG_CENTER_ID) {
        closeTeamSidebarImmediate();
        closeProjectSidebarImmediate();
        focusedNodeIdRef.current = node.id;
        setSidebarParams({ sidebar: 'org', teamId: null, tab: null, subtab: null, projectId: null });
        setOrgSidebarOpen(true);
        requestAnimationFrame(() => setOrgSidebarVisible(true));
        return;
      }

      if (node.type === 'teamGroupNode') {
        const teamData = node.data as { teamId?: string; teamName?: string };
        if (teamData.teamId) {
          closeOrgSidebarImmediate();
          closeProjectSidebarImmediate();
          focusedNodeIdRef.current = node.id;
          setSelectedTeamId(teamData.teamId);
          setSelectedTeamName(teamData.teamName ?? null);
          setSidebarParams({ sidebar: 'team', teamId: teamData.teamId, tab: 'security', subtab: null, projectId: null });
          setTeamSidebarOpen(true);
          requestAnimationFrame(() => setTeamSidebarVisible(true));
        }
        return;
      }

      const d = node.data as {
        projectId?: string;
        projectName?: string;
        isTeamNode?: boolean;
        framework?: string | null;
        organizationId?: string;
        isExtracting?: boolean;
      };
      if (d.projectId && d.isTeamNode) {
        closeOrgSidebarImmediate();
        closeProjectSidebarImmediate();
        focusedNodeIdRef.current = node.id;
        setSelectedTeamId(d.projectId);
        setSelectedTeamName((d.projectName as string) ?? null);
        setSidebarParams({ sidebar: 'team', teamId: d.projectId, tab: 'security', subtab: null, projectId: null });
        setTeamSidebarOpen(true);
        requestAnimationFrame(() => setTeamSidebarVisible(true));
        return;
      }
      if (d.projectId) {
        closeOrgSidebarImmediate();
        closeTeamSidebarImmediate();
        focusedNodeIdRef.current = node.id;
        setSelectedProjectId(d.projectId);
        setSelectedProjectName((d.projectName as string) ?? null);
        setSelectedProjectFramework(d.framework ?? null);
        setSelectedProjectIsExtracting(d.isExtracting ?? false);
        setProjectStats(null);
        setProjectSidebarTab('vulnerabilities');
        setProjectSettingsSubTab('general');
        setSidebarParams({ sidebar: 'project', projectId: d.projectId, tab: 'vulnerabilities', subtab: null, teamId: null });
        setProjectSidebarOpen(true);
        requestAnimationFrame(() => setProjectSidebarVisible(true));
      }
    },
    [
      orgId,
      closeOrgSidebarImmediate,
      closeTeamSidebarImmediate,
      closeProjectSidebarImmediate,
      setSidebarParams,
      toast,
    ]
  );

  const onExpandProject = useCallback(
    async (projectId: string, filter: ExpandFilter = 'all') => {
      if (!orgId) return;
      if (expandedProjectId === projectId) {
        setExpandedProjectId(null);
        setExpandedNodes([]);
        setExpandedEdges([]);
        return;
      }
      setExpandingProjectId(projectId);
      setExpandedProjectId(null);
      setExpandedNodes([]);
      setExpandedEdges([]);
      try {
        const deps = await api.getProjectDependencies(orgId, projectId);
        // Only show direct deps (is_direct from project_dependencies); API returns all deps.
        let directDeps = deps.filter((d: ProjectDependency) => d.is_direct === true);
        const hasVulns = (d: ProjectDependency) => {
          const vulns = (d as ProjectDependency & { vulnerabilities?: unknown[] }).vulnerabilities;
          if (Array.isArray(vulns) && vulns.length > 0) return true;
          const a = d.analysis as { critical_vulns?: number; high_vulns?: number; medium_vulns?: number; low_vulns?: number } | undefined;
          if (a)
            return (a.critical_vulns ?? 0) + (a.high_vulns ?? 0) + (a.medium_vulns ?? 0) + (a.low_vulns ?? 0) > 0;
          return false;
        };
        if (filter === 'vulnerable') {
          directDeps = directDeps.filter(hasVulns);
        } else if (filter === 'not_allowed') {
          directDeps = directDeps.filter((d) => d.policy_result != null && d.policy_result.allowed === false);
        } else if (filter === 'outdated') {
          directDeps = directDeps.filter((d) => d.is_outdated === true || (d.versions_behind != null && d.versions_behind > 0));
        }
        const currentNodes = graphNodesRef.current;
        const projectNode = currentNodes.find((n) => n.id === `project-${projectId}`);
        const pos = projectNode?.position ?? { x: 0, y: 0 };
        const centerX = pos.x + OVERVIEW_PROJECT_NODE_WIDTH / 2;
        const centerY = pos.y + OVERVIEW_PROJECT_NODE_HEIGHT / 2;
        const depNodeWidth = 220;
        const depNodeHeight = 72;
        const n = directDeps.length;
        const minRadius = 140 + n * 6;
        const radiusSpread = 120 + n * 10;
        const grayStroke = 'rgba(100, 116, 139, 0.4)';
        const hash = (s: string) => {
          let h = 0;
          for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
          return Math.abs(h);
        };
        const newNodes: Node[] = directDeps.map((dep: ProjectDependency) => {
          const angle = (hash(dep.id) % 1000) / 1000 * 2 * Math.PI;
          const radius = minRadius + (hash(dep.id + 'r') % 1000) / 1000 * radiusSpread;
          const nx = centerX + Math.cos(angle) * radius - depNodeWidth / 2;
          const ny = centerY + Math.sin(angle) * radius - depNodeHeight / 2;
          return {
            id: `expand-dep-${projectId}-${dep.id}`,
            type: 'dependencyNode',
            position: { x: nx, y: ny },
            data: {
              name: dep.name,
              version: dep.version,
              score: dep.analysis?.score ?? null,
              license: dep.license ?? null,
              policies: null,
              criticalVulns: 0,
              highVulns: 0,
              mediumVulns: 0,
              lowVulns: 0,
              vulnerabilities: [],
              showLicense: false,
              ecosystem: dep.ecosystem ?? null,
              policyAllowed: dep.policy_result != null ? dep.policy_result.allowed : undefined,
            },
            draggable: true,
            selectable: false,
          };
        });
        const newEdges: Edge[] = directDeps.map((dep: ProjectDependency) => ({
          id: `edge-expand-${projectId}-${dep.id}`,
          source: `project-${projectId}`,
          target: `expand-dep-${projectId}-${dep.id}`,
          type: 'default',
          style: { stroke: grayStroke, strokeWidth: 1.2 },
        }));
        setExpandedProjectId(projectId);
        setExpandedNodes(newNodes);
        setExpandedEdges(newEdges);
      } catch {
        setExpandedProjectId(null);
        setExpandedNodes([]);
        setExpandedEdges([]);
      } finally {
        setExpandingProjectId(null);
      }
    },
    [orgId, expandedProjectId, toast]
  );

  useEffect(() => {
    graphNodesRef.current = graphNodes;
  }, [graphNodes]);

  // Fetch team stats, members, projects, org members, roles, and team data when team sidebar opens
  useEffect(() => {
    if (!orgId || !selectedTeamId || !teamSidebarOpen || selectedTeamId === UNGROUPED_TEAM_ID) {
      setTeamSidebarStats(null);
      setTeamSidebarMembers([]);
      setTeamSidebarProjects([]);
      setTeamSidebarOrgMembers([]);
      setTeamSidebarRoles([]);
      setTeamSidebarPermissions(null);
      setTeamSidebarTeamData(null);
      return;
    }
    let cancelled = false;
    setTeamSidebarDataLoading(true);
    Promise.all([
      api.getTeamStats(orgId, selectedTeamId),
      api.getTeamMembers(orgId, selectedTeamId),
      api.getProjects(orgId),
      api.getOrganizationMembers(orgId),
      api.getTeamRoles(orgId, selectedTeamId),
      api.getTeam(orgId, selectedTeamId),
      api.getTeamSecuritySummary(orgId, selectedTeamId).catch(() => ({ projects: [] })),
    ])
      .then(([stats, members, allProjects, orgMembers, roles, teamData, securitySummary]) => {
        if (cancelled) return;
        setTeamSidebarStats(stats);
        setTeamSidebarMembers(members);
        setTeamSidebarOrgMembers(orgMembers);
        setTeamSidebarRoles(roles);
        setTeamSidebarTeamData(teamData);
        setTeamSidebarPermissions(teamData.permissions || null);
        const forTeam = allProjects.filter(
          (p: Project) => p.team_ids?.includes(selectedTeamId) || p.owner_team_id === selectedTeamId
        );
        setTeamSidebarProjects(forTeam);
        setTeamSidebarSecuritySummary(securitySummary.projects || []);
      })
      .catch(() => {
        if (!cancelled) {
          setTeamSidebarStats(null);
          setTeamSidebarMembers([]);
          setTeamSidebarProjects([]);
          setTeamSidebarSecuritySummary([]);
          setTeamSidebarOrgMembers([]);
          setTeamSidebarRoles([]);
          setTeamSidebarPermissions(null);
          setTeamSidebarTeamData(null);
        }
      })
      .finally(() => {
        if (!cancelled) setTeamSidebarDataLoading(false);
      });
    return () => { cancelled = true; };
  }, [orgId, selectedTeamId, teamSidebarOpen]);

  // Load team vulnerabilities for the security tab
  const loadTeamVulns = useCallback(async (p: number) => {
    if (!orgId || !selectedTeamId || selectedTeamId === UNGROUPED_TEAM_ID) return;
    setTeamSidebarVulnsLoading(true);
    try {
      const res = await api.getTeamVulnerabilities(orgId, selectedTeamId, { page: p, per_page: 50 });
      setTeamSidebarVulns(res.data);
      setTeamSidebarVulnsTotal(res.total);
      setTeamSidebarVulnsPage(res.page);
    } catch {
      setTeamSidebarVulns([]);
      setTeamSidebarVulnsTotal(0);
    } finally {
      setTeamSidebarVulnsLoading(false);
    }
  }, [orgId, selectedTeamId]);

  useEffect(() => {
    if (teamSidebarTab === 'security' && teamSidebarOpen && selectedTeamId && selectedTeamId !== UNGROUPED_TEAM_ID) {
      void loadTeamVulns(1);
    }
  }, [teamSidebarTab, teamSidebarOpen, selectedTeamId, loadTeamVulns]);

  // Initialize team settings form data when team data loads
  useEffect(() => {
    if (teamSidebarTeamData) {
      setTeamSettingsName(teamSidebarTeamData.name || '');
      setTeamSettingsDescription(teamSidebarTeamData.description || '');
      setTeamSettingsNotifPausedUntil((teamSidebarTeamData as { notifications_paused_until?: string | null }).notifications_paused_until ?? null);
    }
  }, [teamSidebarTeamData]);

  // Load team connections when settings/notifications tab is selected
  const loadTeamConnections = useCallback(async () => {
    if (!orgId || !selectedTeamId) return;
    setTeamSettingsConnectionsLoading(true);
    try {
      const [orgConns, teamConns] = await Promise.all([
        api.getOrganizationConnections(orgId) as Promise<CiCdConnection[]>,
        api.getTeamConnections(orgId, selectedTeamId).catch(() => []) as Promise<CiCdConnection[]>,
      ]);
      const notifProviders = ['slack', 'discord', 'email', 'jira', 'linear', 'pagerduty', 'custom_notification', 'custom_ticketing', 'asana'];
      setTeamSettingsConnections({
        inherited: (orgConns || []).filter((c) => notifProviders.includes(c.provider)),
        team: (teamConns || []).filter((c) => notifProviders.includes(c.provider)),
      });
    } catch {
      setTeamSettingsConnections({ inherited: [], team: [] });
    } finally {
      setTeamSettingsConnectionsLoading(false);
    }
  }, [orgId, selectedTeamId]);

  useEffect(() => {
    if (teamSidebarTab === 'settings' && teamSettingsSubTab === 'notifications' && selectedTeamId) {
      loadTeamConnections();
    }
  }, [teamSidebarTab, teamSettingsSubTab, selectedTeamId, loadTeamConnections]);

  // Team settings handlers
  const handleTeamSettingsSave = async () => {
    if (!orgId || !selectedTeamId || !teamSidebarTeamData) return;
    setTeamSettingsSaving(true);
    try {
      await api.updateTeam(orgId, selectedTeamId, { name: teamSettingsName, description: teamSettingsDescription });
      toast({ title: 'Saved', description: 'Team settings saved.' });
      setSelectedTeamName(teamSettingsName);
      setGraphRefreshTrigger((t) => t + 1);
    } catch (err: unknown) {
      toast({ title: 'Error', description: (err as Error).message || 'Failed to save settings.', variant: 'destructive' });
    } finally {
      setTeamSettingsSaving(false);
    }
  };

  const handleTeamSettingsDelete = async () => {
    if (!orgId || !selectedTeamId || !teamSidebarTeamData) return;
    setTeamSettingsDeleting(true);
    try {
      await api.deleteTeam(orgId, selectedTeamId);
      toast({ title: 'Deleted', description: 'Team has been deleted.' });
      closeTeamSidebar();
      setGraphRefreshTrigger((t) => t + 1);
    } catch (err: unknown) {
      toast({ title: 'Error', description: (err as Error).message || 'Failed to delete team.', variant: 'destructive' });
    } finally {
      setTeamSettingsDeleting(false);
    }
  };

  const handleTeamSettingsCreateRole = async (permissions: TeamPermissions) => {
    if (!orgId || !selectedTeamId || !teamSettingsNewRoleNameInput.trim()) return;
    setTeamSettingsIsCreatingRole(true);
    try {
      await api.createTeamRole(orgId, selectedTeamId, {
        name: teamSettingsNewRoleNameInput.trim().toLowerCase().replace(/\s+/g, '_'),
        display_name: teamSettingsNewRoleNameInput.trim(),
        color: teamSettingsNewRoleColor || null,
        permissions,
      });
      toast({ title: 'Role Created', description: `Role "${teamSettingsNewRoleNameInput}" has been created.` });
      const roles = await api.getTeamRoles(orgId, selectedTeamId);
      setTeamSidebarRoles(roles);
      setTeamSettingsShowAddRoleSidepanel(false);
      setTeamSettingsNewRoleNameInput('');
      setTeamSettingsNewRoleColor('');
      setTeamSettingsNewRolePermissions({
        view_overview: true, manage_projects: false, manage_members: false, view_settings: false,
        view_roles: false, edit_roles: false, manage_notification_settings: false, add_members: false, kick_members: false,
      });
    } catch (err: unknown) {
      toast({ title: 'Error', description: (err as Error).message || 'Failed to create role.', variant: 'destructive' });
    } finally {
      setTeamSettingsIsCreatingRole(false);
    }
  };

  const handleTeamSettingsEditRolePermissions = (role: TeamRole, canEdit: boolean) => {
    setTeamSettingsSelectedRoleForSettings(role);
    setTeamSettingsEditingRolePermissions(role.permissions as TeamPermissions);
    setTeamSettingsEditingRoleName(role.display_name || role.name);
    setTeamSettingsEditingRoleColor(role.color || '');
    setTeamSettingsCanEditSelectedRole(canEdit);
    setTeamSettingsShowRoleSettingsModal(true);
    requestAnimationFrame(() => setTeamSettingsRoleSettingsPanelVisible(true));
  };

  const handleTeamSettingsSaveRolePermissions = async () => {
    if (!orgId || !selectedTeamId || !teamSettingsSelectedRoleForSettings || !teamSettingsEditingRolePermissions) return;
    setTeamSettingsIsSavingRole(true);
    try {
      await api.updateTeamRole(orgId, selectedTeamId, teamSettingsSelectedRoleForSettings.id, {
        display_name: teamSettingsEditingRoleName,
        color: teamSettingsEditingRoleColor || null,
        permissions: teamSettingsEditingRolePermissions,
      });
      toast({ title: 'Saved', description: 'Role permissions saved.' });
      const roles = await api.getTeamRoles(orgId, selectedTeamId);
      setTeamSidebarRoles(roles);
      setTeamSettingsRoleSettingsPanelVisible(false);
      setTimeout(() => setTeamSettingsShowRoleSettingsModal(false), 150);
    } catch (err: unknown) {
      toast({ title: 'Error', description: (err as Error).message || 'Failed to save role.', variant: 'destructive' });
    } finally {
      setTeamSettingsIsSavingRole(false);
    }
  };

  const handleTeamSettingsDeleteRole = async (role: TeamRole) => {
    if (!orgId || !selectedTeamId) return;
    if (!confirm(`Delete role "${role.display_name || role.name}"? Members with this role will be assigned to "member".`)) return;
    setTeamSettingsDeletingRoleId(role.id);
    try {
      await api.deleteTeamRole(orgId, selectedTeamId, role.id);
      toast({ title: 'Deleted', description: `Role "${role.display_name || role.name}" deleted.` });
      const roles = await api.getTeamRoles(orgId, selectedTeamId);
      setTeamSidebarRoles(roles);
    } catch (err: unknown) {
      toast({ title: 'Error', description: (err as Error).message || 'Failed to delete role.', variant: 'destructive' });
    } finally {
      setTeamSettingsDeletingRoleId(null);
    }
  };

  // Team settings computed values
  const teamSettingsCanManageSettings = teamSidebarPermissions?.view_settings || teamSidebarHasOrgManagePermission || false;
  const teamSettingsCanDeleteTeam = (teamSidebarPermissions?.manage_members && teamSidebarTeamData?.role === 'owner') || teamSidebarHasOrgManagePermission;
  const teamSettingsMemberCountByRole = useMemo(() => {
    const counts = new Map<string, number>();
    teamSidebarMembers.forEach((m) => {
      const name = m.role || 'member';
      counts.set(name, (counts.get(name) || 0) + 1);
    });
    return counts;
  }, [teamSidebarMembers]);

  // Fetch project stats, vulnerabilities, full project and org when project sidebar opens
  useEffect(() => {
    if (!orgId || !selectedProjectId || !projectSidebarOpen) return;
    let cancelled = false;
    setProjectStatsLoading(true);
    setProjectStats(null);
    setProjectVulnerabilities(null);
    setExpandedProjectVulnRowId(null);
    setProjectVulnDetailByRowId({});
    setProjectSidebarProjectLoading(true);
    setProjectSidebarProject(null);
    setProjectSidebarOrganization(null);
    Promise.all([
      api.getProjectStats(orgId, selectedProjectId),
      api.getProjectVulnerabilities(orgId, selectedProjectId),
      api.getProject(orgId, selectedProjectId),
      api.getOrganization(orgId),
    ])
      .then(([stats, vulns, project, org]) => {
        if (!cancelled) {
          setProjectStats(stats);
          setProjectVulnerabilities(vulns ?? []);
          setProjectSidebarProject(project);
          setProjectSidebarOrganization(org);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setProjectStats(null);
          setProjectVulnerabilities(null);
          setProjectSidebarProject(null);
          setProjectSidebarOrganization(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setProjectStatsLoading(false);
          setProjectSidebarProjectLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, [orgId, selectedProjectId, projectSidebarOpen]);

  /** One row per (dependency, CVE); keeps highest depscore. Fixes duplicate rows / shared osv_id expansion. */
  const dedupedProjectVulnerabilities = useMemo(() => {
    if (!projectVulnerabilities?.length) return [];
    const rowScore = (v: ProjectVulnerability) => {
      const c = v.contextual_depscore;
      if (c != null && Number.isFinite(Number(c))) return Number(c);
      const d = v.depscore;
      if (d != null && Number.isFinite(Number(d))) return Number(d);
      return -1;
    };
    const byKey = new Map<string, ProjectVulnerability>();
    for (const v of projectVulnerabilities) {
      const key = `${v.dependency_id}:${v.osv_id}`;
      const prev = byKey.get(key);
      if (!prev || rowScore(v) > rowScore(prev)) byKey.set(key, v);
    }
    return Array.from(byKey.values()).sort((a, b) => {
      const diff = rowScore(b) - rowScore(a);
      if (diff !== 0) return diff;
      return a.osv_id.localeCompare(b.osv_id);
    });
  }, [projectVulnerabilities]);

  const toggleProjectVulnerabilityRow = useCallback(async (rowId: string, osvId: string) => {
    setExpandedProjectVulnRowId((prev) => (prev === rowId ? null : rowId));
    if (!orgId || !selectedProjectId) return;
    if (projectVulnDetailByRowId[rowId]?.loading || projectVulnDetailByRowId[rowId]?.data) return;
    setProjectVulnDetailByRowId((prev) => ({ ...prev, [rowId]: { loading: true, error: null, data: null } }));
    try {
      const detail = await api.getVulnerabilityDetail(orgId, selectedProjectId, osvId);
      setProjectVulnDetailByRowId((prev) => ({ ...prev, [rowId]: { loading: false, error: null, data: detail } }));
    } catch (e: any) {
      setProjectVulnDetailByRowId((prev) => ({
        ...prev,
        [rowId]: { loading: false, error: e?.message || 'Failed to load vulnerability details', data: null },
      }));
    }
  }, [orgId, selectedProjectId, projectVulnDetailByRowId]);

  useEffect(() => {
    if (loading) return;
    const injectedLayoutNodes = layoutNodes.map((n) => {
      if (n.type === 'vulnProjectNode' && n.data && typeof n.data === 'object') {
        const data = n.data as Record<string, unknown>;
        return {
          ...n,
          data: {
            ...data,
            onExpandProject,
            isExpanding: data.projectId === expandingProjectId,
            expandedProjectId,
          },
        };
      }
      return n;
    });
    setGraphNodes([...injectedLayoutNodes, ...expandedNodes]);
    setGraphEdges([...layoutEdges, ...expandedEdges]);
  }, [
    loading,
    layoutNodes,
    layoutEdges,
    expandingProjectId,
    expandedProjectId,
    expandedNodes,
    expandedEdges,
    onExpandProject,
    setGraphNodes,
    setGraphEdges,
  ]);

  return (
    <main className="relative flex flex-col min-h-[calc(100vh-3rem)] w-full bg-background">
      {error && (
        <div className="flex-shrink-0 px-4 pt-3">
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive">
            {error}
          </div>
        </div>
      )}
      <div className="flex-1 min-h-0 relative">
        <div className="absolute top-3 right-3 z-10 flex flex-col items-end gap-2">
          <div className="flex items-center gap-2 rounded-lg border border-border bg-background-card-header p-1 shadow-sm">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
                aria-label="Add"
              >
                <Plus className="h-3.5 w-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-52 rounded-lg border-border bg-background-card shadow-lg">
              <DropdownMenuLabel className="text-foreground font-semibold px-2 pt-2 pb-1">
                Create
              </DropdownMenuLabel>
              <DropdownMenuItem
                className="cursor-pointer gap-2"
                onClick={() => window.dispatchEvent(new CustomEvent('organization:openInvite'))}
              >
                <UserPlus className="h-4 w-4" />
                Invite member
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer gap-2"
                onClick={() => window.dispatchEvent(new CustomEvent('organization:openCreateTeam'))}
              >
                <Users className="h-4 w-4" />
                Create team
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer gap-2"
                onClick={() => window.dispatchEvent(new CustomEvent('organization:openCreateProject'))}
              >
                <FolderPlus className="h-4 w-4" />
                Create project
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
                aria-label="Filter graph"
              >
                <Filter className="h-3.5 w-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56 rounded-lg border-border bg-background-card shadow-lg">
              <DropdownMenuLabel className="text-foreground font-semibold px-2 pt-2 pb-1">
                Filter by
              </DropdownMenuLabel>
              <div className="px-2 space-y-0 max-h-[280px] overflow-y-auto">
                {statuses.length === 0 ? (
                  <p className="text-sm text-foreground-secondary py-2 px-0">No custom statuses</p>
                ) : (
                  [...statuses]
                    .sort((a, b) => a.rank - b.rank)
                    .map((status) => {
                      const checked = selectedStatusIds.has(status.id);
                      return (
                        <div
                          key={status.id}
                          className="group flex items-center gap-2 py-1 px-0 rounded-md cursor-pointer"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setSelectedStatusIds((prev) => {
                              const next = new Set(prev);
                              if (next.has(status.id)) next.delete(status.id);
                              else next.add(status.id);
                              return next;
                            });
                          }}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              setSelectedStatusIds((prev) => {
                                const next = new Set(prev);
                                if (next.has(status.id)) next.delete(status.id);
                                else next.add(status.id);
                                return next;
                              });
                            }
                          }}
                          role="option"
                          aria-selected={checked}
                          tabIndex={0}
                        >
                          <Checkbox
                            id={`filter-status-${status.id}`}
                            checked={checked}
                            onCheckedChange={(c) => {
                              setSelectedStatusIds((prev) => {
                                const next = new Set(prev);
                                if (c === true) next.add(status.id);
                                else next.delete(status.id);
                                return next;
                              });
                            }}
                            className="data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
                          />
                          <label
                            htmlFor={`filter-status-${status.id}`}
                            className="text-sm font-normal cursor-pointer flex-1 text-foreground"
                          >
                            {status.name}
                          </label>
                          <button
                            type="button"
                            className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-xs font-medium px-2 py-1 rounded-md border border-foreground/40 bg-transparent text-foreground hover:bg-foreground/10 focus:opacity-100 focus:outline-none"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedStatusIds(new Set([status.id]));
                            }}
                          >
                            Select only
                          </button>
                        </div>
                      );
                    })
                )}
              </div>
            </DropdownMenuContent>
          </DropdownMenu>
          </div>
        </div>
        <div className="absolute inset-0 flex min-h-0">
          {/* Graph */}
          <div className="flex-1 min-w-0 min-h-0 overflow-hidden bg-background relative">
            <div ref={reactFlowPaneRef} className="absolute inset-0 overflow-hidden">
              <ReactFlow
                className="org-overview-hub-flow"
                nodes={stillShowingSkeleton ? orgSkeletonNodes : graphNodes}
                edges={stillShowingSkeleton ? [] : graphEdges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={onNodeClick}
                onInit={(instance) => { reactFlowInstanceRef.current = instance as any; }}
                nodeTypes={stillShowingSkeleton ? skeletonNodeTypes : nodeTypes}
                fitView
                fitViewOptions={{
                  padding: 0.38,
                  maxZoom: stillShowingSkeleton ? 1.2 : 1.15,
                }}
                minZoom={0.12}
                maxZoom={2}
                proOptions={{ hideAttribution: true }}
                nodesDraggable={false}
                nodesConnectable={false}
                defaultEdgeOptions={{
                  type: 'default',
                  style: { stroke: ORG_OVERVIEW_EDGE_STROKE, strokeWidth: 1 },
                }}
              >
                <Background
                  variant={BackgroundVariant.Dots}
                  gap={16}
                  size={1.2}
                  color="rgba(148, 163, 184, 0.3)"
                />
              </ReactFlow>
            </div>
          </div>

          {/* Org sidebar: slides in from right, inside the graph area */}
          {orgSidebarOpen && organization && (
            <div
              className={cn(
                'absolute top-6 bottom-0 right-0 w-full max-w-[1000px] sm:max-w-[1200px] bg-background-card-header border-l border-t border-border rounded-tl-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-300 ease-out z-20',
                orgSidebarVisible ? 'translate-x-0' : 'translate-x-full'
              )}
            >
            {/* Header - Org avatar and name */}
            <div className="flex-shrink-0 flex items-center justify-between gap-4 border-b border-border px-5 pt-5 pb-4">
              <div className="flex items-center gap-3 min-w-0">
                <img
                  src={organization.avatar_url || '/images/org_profile.png'}
                  alt={organization.name}
                  className="h-9 w-9 rounded-lg object-contain flex-shrink-0"
                />
                <h2 className="text-lg font-semibold text-foreground truncate">{organization.name}</h2>
              </div>
              <button
                type="button"
                onClick={closeOrgSidebar}
                className="shrink-0 p-1 text-foreground-secondary hover:text-foreground transition-colors"
                aria-label="Close"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto">
              {/* Section Title */}
              <div className="px-5 pt-5 pb-4">
                <h3 className="text-base font-semibold text-foreground">Organization Security</h3>
                <p className="text-sm text-foreground-secondary mt-1">Security status overview for your organization</p>
              </div>

              {/* Status Items */}
              <div className="px-5 pt-6 pb-8">
                <div className="flex flex-col items-center justify-center text-center">
                  <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
                    <ShieldCheck className="h-6 w-6 text-foreground-secondary" />
                  </div>
                  <h3 className="text-base font-medium text-foreground mb-1">All Projects Safe</h3>
                  <p className="text-sm text-foreground-secondary max-w-[240px]">
                    No major security threats found across your projects.
                  </p>
                </div>
              </div>
            </div>
            </div>
          )}

          {/* Team sidebar: slides in from right, inside the graph area */}
          {teamSidebarOpen && selectedTeamId && (
            <div
              className={cn(
                'absolute top-6 bottom-0 right-0 w-full max-w-[1000px] sm:max-w-[1200px] bg-background-card-header border-l border-t border-border rounded-tl-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-300 ease-out z-20',
                teamSidebarVisible ? 'translate-x-0' : 'translate-x-full'
              )}
            >
            {/* Header */}
            <div className="flex-shrink-0 flex items-center justify-between gap-4 px-5 pt-5 pb-5">
              <div className="flex items-center gap-3 min-w-0">
                <Users className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                <h2 className="text-lg font-semibold text-foreground truncate">{selectedTeamName ?? 'Team'}</h2>
              </div>
              <button
                type="button"
                onClick={closeTeamSidebar}
                className="shrink-0 p-1 text-foreground-secondary hover:text-foreground transition-colors"
                aria-label="Close"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            {/* Tabs */}
            <div className="flex-shrink-0 px-5 border-b border-border">
              <div className="flex items-center gap-6">
                {(['security', 'projects', 'members', 'settings'] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => { setTeamSidebarTab(tab); setSidebarParams({ tab, subtab: null }); }}
                    className={cn(
                      'relative pb-3 text-sm font-medium transition-colors',
                      teamSidebarTab === tab
                        ? 'text-foreground'
                        : 'text-foreground-secondary hover:text-foreground'
                    )}
                  >
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
                    {teamSidebarTab === tab && (
                      <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-foreground rounded-full" />
                    )}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-5">
              {/* Projects Tab */}
              {teamSidebarTab === 'projects' && (
                <div className="space-y-4">
                  {/* Search, View Toggle, and Create Button */}
                  <div className="flex items-center justify-between gap-3">
                    <div className="relative w-64">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
                      <input
                        type="text"
                        placeholder="Filter projects..."
                        value={teamSidebarProjectsSearch}
                        onChange={(e) => setTeamSidebarProjectsSearch(e.target.value)}
                        className={`w-full pl-9 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent ${teamSidebarProjectsSearch ? 'pr-14' : 'pr-4'}`}
                      />
                      {teamSidebarProjectsSearch && (
                        <button
                          type="button"
                          onClick={() => setTeamSidebarProjectsSearch('')}
                          className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                          aria-label="Clear search (Esc)"
                        >
                          Esc
                        </button>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {/* View Toggle */}
                      <div className="flex items-center border border-border rounded-md overflow-hidden">
                        <button
                          onClick={() => setTeamSidebarProjectsViewMode('grid')}
                          className={`px-3 py-1.5 text-sm transition-colors ${teamSidebarProjectsViewMode === 'grid'
                            ? 'bg-background-card text-foreground'
                            : 'text-foreground-secondary hover:text-foreground hover:bg-background-card/50'
                          }`}
                          aria-label="Grid view"
                        >
                          <Grid3x3 className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => setTeamSidebarProjectsViewMode('list')}
                          className={`px-3 py-1.5 text-sm transition-colors border-l border-border ${teamSidebarProjectsViewMode === 'list'
                            ? 'bg-background-card text-foreground'
                            : 'text-foreground-secondary hover:text-foreground hover:bg-background-card/50'
                          }`}
                          aria-label="List view"
                        >
                          <List className="h-4 w-4" />
                        </button>
                      </div>
                      <Button
                        onClick={() => {
                          window.dispatchEvent(new CustomEvent('organization:openCreateProject'));
                        }}
                        className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Create Project
                      </Button>
                    </div>
                  </div>

                  {/* Projects Grid/List */}
                  {teamSidebarDataLoading ? (
                    teamSidebarProjectsViewMode === 'grid' ? (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {[1, 2, 3].map((i) => (
                          <div key={i} className="bg-background-card border border-border rounded-lg p-5 animate-pulse">
                            <div className="flex items-start justify-between mb-3">
                              <div className="flex items-center gap-3">
                                <div className="h-6 w-6 rounded bg-muted" />
                                <div className="h-4 w-24 rounded bg-muted" />
                                <div className="h-4 w-20 rounded bg-muted" />
                              </div>
                              <div className="h-5 w-5 rounded-full bg-muted" />
                            </div>
                            <div className="flex items-center gap-1.5">
                              <div className="h-4 w-4 rounded-full bg-muted" />
                              <div className="h-4 w-20 rounded bg-muted" />
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                        <table className="w-full">
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Health</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {[1, 2, 3].map((i) => (
                              <tr key={i} className="animate-pulse">
                                <td className="px-4 py-3"><div className="flex items-center gap-2"><div className="h-5 w-5 rounded bg-muted" /><div className="h-4 w-32 rounded bg-muted" /></div></td>
                                <td className="px-4 py-3"><div className="h-5 w-20 rounded bg-muted" /></td>
                                <td className="px-4 py-3"><div className="h-4 w-12 rounded bg-muted" /></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )
                  ) : teamSidebarFilteredProjects.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
                        <FolderKanban className="h-6 w-6 text-foreground-secondary" />
                      </div>
                      <h3 className="text-base font-medium text-foreground mb-1">No projects found</h3>
                      <p className="text-sm text-foreground-secondary max-w-[240px]">
                        {teamSidebarProjects.length === 0
                          ? "This team doesn't have any projects yet."
                          : "No projects match your search criteria."}
                      </p>
                    </div>
                  ) : teamSidebarProjectsViewMode === 'grid' ? (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {teamSidebarFilteredProjects.map((project) => {
                        const { label, inProgress, isError } = projectStatusLabel(project);
                        return (
                          <div
                            key={project.id}
                            onClick={() => openProjectInSidebar(project)}
                            className="bg-background-card border border-border rounded-lg p-5 hover:bg-background-card/80 transition-all cursor-pointer group"
                          >
                            <div className="flex items-center justify-between mb-3">
                              <div className="flex items-center gap-3 flex-1 min-w-0">
                                <FrameworkIcon frameworkId={project.framework ?? undefined} size={24} />
                                <h3 className="text-base font-semibold text-foreground truncate">{project.name}</h3>
                                {inProgress ? (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 flex-shrink-0 flex items-center gap-1">
                                    <Loader2 className="h-3 w-3 animate-spin" />
                                    {label}
                                  </span>
                                ) : isError ? (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 flex-shrink-0">
                                    Failed
                                  </span>
                                ) : label === 'COMPLIANT' ? (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40 flex-shrink-0">
                                    COMPLIANT
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 flex-shrink-0">
                                    NOT COMPLIANT
                                  </span>
                                )}
                              </div>
                              <ChevronRight className="h-5 w-5 text-foreground-secondary group-hover:text-foreground transition-colors flex-shrink-0 ml-2" />
                            </div>
                            <div className="flex items-center gap-1.5 text-sm text-foreground-secondary">
                              <Bell className="h-4 w-4" />
                              <span>{project.alerts_count || 0} {project.alerts_count === 1 ? 'alert' : 'alerts'}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      <table className="w-full">
                        <thead className="bg-background-card-header border-b border-border">
                          <tr>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Health</th>
                            <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Created</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {teamSidebarFilteredProjects.map((project) => {
                            const { label, inProgress, isError } = projectStatusLabel(project);
                            return (
                              <tr
                                key={project.id}
                                onClick={() => openProjectInSidebar(project)}
                                className="hover:bg-table-hover transition-colors cursor-pointer group"
                              >
                                <td className="px-4 py-3">
                                  <div className="flex items-center gap-2">
                                    <FrameworkIcon frameworkId={project.framework ?? undefined} size={20} />
                                    <span className="text-sm font-semibold text-foreground">{project.name}</span>
                                  </div>
                                </td>
                                <td className="px-4 py-3">
                                  {inProgress ? (
                                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 flex items-center gap-1 w-fit">
                                      <Loader2 className="h-3 w-3 animate-spin" />
                                      {label}
                                    </span>
                                  ) : isError ? (
                                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40">Failed</span>
                                  ) : label === 'COMPLIANT' ? (
                                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40">COMPLIANT</span>
                                  ) : (
                                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40">NOT COMPLIANT</span>
                                  )}
                                </td>
                                <td className="px-4 py-3">
                                  <span className="text-sm text-foreground-secondary">{project.health_score != null ? `${Math.round(project.health_score)}%` : '—'}</span>
                                </td>
                                <td className="px-4 py-3">
                                  <span className="text-sm text-foreground-secondary">{formatDate(project.created_at)}</span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Security Tab */}
              {teamSidebarTab === 'security' && (
                <div className="space-y-4">
                  {teamSidebarVulnsLoading && teamSidebarVulns.length === 0 ? (
                    <OrganizationVulnerabilitiesTableSkeleton />
                  ) : teamSidebarVulns.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
                        <Shield className="h-6 w-6 text-foreground-secondary" />
                      </div>
                      <h3 className="text-base font-medium text-foreground mb-1">No security issues</h3>
                      <p className="text-sm text-foreground-secondary max-w-[240px]">
                        {teamSidebarProjects.length === 0
                          ? "This team doesn't have any projects yet."
                          : "All projects in this team are secure with no open vulnerabilities."}
                      </p>
                    </div>
                  ) : (
                    <>
                      <VulnerabilityExpandableTable organizationId={orgId!} vulnerabilities={teamSidebarVulns} />
                      {Math.ceil(teamSidebarVulnsTotal / 50) > 1 && (
                        <div className="flex items-center justify-between gap-3 pt-2">
                          <span className="text-xs text-foreground-secondary">
                            Page {teamSidebarVulnsPage} of {Math.ceil(teamSidebarVulnsTotal / 50)}
                          </span>
                          <div className="flex gap-2">
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              className="h-8"
                              disabled={teamSidebarVulnsLoading || teamSidebarVulnsPage <= 1}
                              onClick={() => void loadTeamVulns(teamSidebarVulnsPage - 1)}
                            >
                              Previous
                            </Button>
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              className="h-8"
                              disabled={teamSidebarVulnsLoading || teamSidebarVulnsPage >= Math.ceil(teamSidebarVulnsTotal / 50)}
                              onClick={() => void loadTeamVulns(teamSidebarVulnsPage + 1)}
                            >
                              Next
                            </Button>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
              {/* Members Tab */}
              {teamSidebarTab === 'members' && (
                <div className="space-y-4">
                  {/* Search and Add Member Button */}
                  <div className="flex items-center justify-between gap-3">
                    <div className="relative w-64">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
                      <input
                        type="text"
                        placeholder="Filter members..."
                        value={teamSidebarMembersSearch}
                        onChange={(e) => setTeamSidebarMembersSearch(e.target.value)}
                        className={`w-full pl-9 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent ${teamSidebarMembersSearch ? 'pr-14' : 'pr-4'}`}
                      />
                      {teamSidebarMembersSearch && (
                        <button
                          type="button"
                          onClick={() => setTeamSidebarMembersSearch('')}
                          className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
                          aria-label="Clear search (Esc)"
                        >
                          Esc
                        </button>
                      )}
                    </div>
                    <Button
                      onClick={() => {
                        setTeamSidebarAddMemberOpen(true);
                        requestAnimationFrame(() => setTeamSidebarAddMemberVisible(true));
                      }}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                    >
                      Add Member
                    </Button>
                  </div>

                  {/* Members List */}
                  {teamSidebarDataLoading ? (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden divide-y divide-border">
                      {[1, 2, 3].map((i) => (
                        <div key={i} className="px-4 py-3 grid grid-cols-[1fr_auto] gap-4 items-center animate-pulse">
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="h-10 w-10 bg-muted rounded-full" />
                            <div className="min-w-0">
                              <div className="h-4 bg-muted rounded w-24 mb-1" />
                              <div className="h-3 bg-muted rounded w-32" />
                            </div>
                          </div>
                          <div className="h-6 bg-muted rounded w-20" />
                        </div>
                      ))}
                    </div>
                  ) : teamSidebarFilteredMembers.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
                        <Users className="h-6 w-6 text-foreground-secondary" />
                      </div>
                      <h3 className="text-base font-medium text-foreground mb-1">
                        {teamSidebarMembers.length === 0 ? 'This team is empty' : 'No members found'}
                      </h3>
                      <p className="text-sm text-foreground-secondary max-w-[240px]">
                        {teamSidebarMembers.length === 0
                          ? "You don't have any members in this team yet."
                          : 'No members match your search criteria.'}
                      </p>
                    </div>
                  ) : (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden divide-y divide-border">
                      {teamSidebarFilteredMembers.map((member) => {
                          const isCurrentUser = user && member.user_id === user.id;
                          const isOwner = member.role === 'owner';
                          const memberTeamRank = member.rank ?? 999;
                          const memberOrgRank = member.org_rank ?? 999;
                          const currentUserOrgRank = (teamSidebarTeamData as any)?.user_org_rank ?? 999;
                          const isUserOrgRankLoaded = (teamSidebarTeamData as any)?.user_org_rank !== undefined;
                          const canManageByHierarchy =
                            (!isUserOrgRankLoaded && teamSidebarHasOrgManagePermission) ||
                            memberOrgRank > currentUserOrgRank ||
                            (memberOrgRank === currentUserOrgRank && memberTeamRank > (teamSidebarUserRank ?? 999));
                          const canKickThisMember = (teamSidebarCanManageMembers || teamSidebarHasOrgManagePermission) && !isOwner && canManageByHierarchy;
                          const canChangeThisMemberRole = (teamSidebarCanEditRoles || teamSidebarHasOrgManagePermission) && !isOwner && canManageByHierarchy;
                          const canChangeOwnRole = isCurrentUser && teamSidebarHasOrgManagePermission;
                          const hasAnyAction = isCurrentUser || canChangeThisMemberRole || canKickThisMember;

                          return (
                            <div
                              key={member.user_id}
                              className="px-4 py-3 grid grid-cols-[1fr_auto_32px] gap-4 items-center hover:bg-table-hover transition-colors"
                            >
                              <div className="flex items-center gap-3 min-w-0">
                                <img
                                  src={member.avatar_url || '/images/blank_profile_image.png'}
                                  alt={member.full_name || member.email}
                                  className="h-10 w-10 rounded-full object-cover border border-border"
                                  referrerPolicy="no-referrer"
                                  onError={(e) => { e.currentTarget.src = '/images/blank_profile_image.png'; }}
                                />
                                <div className="min-w-0">
                                  <div className="text-sm font-medium text-foreground truncate flex items-center gap-2">
                                    {member.full_name || 'Unknown'}
                                    {isCurrentUser && (
                                      <span className="px-1.5 py-px rounded-full text-[10px] font-medium border flex-shrink-0" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', color: '#22c55e', borderColor: 'rgba(34, 197, 94, 0.25)' }}>You</span>
                                    )}
                                  </div>
                                  <div className="text-xs text-foreground-secondary truncate">{member.email}</div>
                                </div>
                              </div>
                              <div className="justify-self-end">
                                <RoleBadge
                                  role={member.role}
                                  roleDisplayName={member.role_display_name}
                                  roleColor={member.role_color}
                                />
                              </div>
                              <div className="justify-self-end">
                                {hasAnyAction ? (
                                  <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                      <button className="p-1 text-foreground-secondary hover:text-foreground transition-colors">
                                        <MoreVertical className="h-4 w-4" />
                                      </button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                      {isCurrentUser ? (
                                        <>
                                          {canChangeOwnRole && (
                                            <DropdownMenuItem onClick={() => handleTeamSidebarChangeRole(member)}>
                                              Change Role
                                            </DropdownMenuItem>
                                          )}
                                          <DropdownMenuItem
                                            onClick={() => {
                                              if (isOwner) {
                                                toast({
                                                  title: 'Cannot Leave',
                                                  description: 'Must transfer team ownership in the settings first.',
                                                  variant: 'destructive',
                                                });
                                                return;
                                              }
                                              handleTeamSidebarRemoveMember(member.user_id);
                                            }}
                                          >
                                            Leave Team
                                          </DropdownMenuItem>
                                        </>
                                      ) : (
                                        <>
                                          {canChangeThisMemberRole && (
                                            <DropdownMenuItem onClick={() => handleTeamSidebarChangeRole(member)}>
                                              Change Role
                                            </DropdownMenuItem>
                                          )}
                                          {canKickThisMember && (
                                            <DropdownMenuItem onClick={() => handleTeamSidebarRemoveMember(member.user_id)}>
                                              Remove from Team
                                            </DropdownMenuItem>
                                          )}
                                        </>
                                      )}
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                ) : (
                                  <div className="w-6" />
                                )}
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  )}
                </div>
              )}
              {teamSidebarTab === 'settings' && teamSidebarTeamData && (
                <div className="flex gap pr-12">
                  {/* Settings Sidebar */}
                  <aside className="w-48 flex-shrink-0 pt-6">
                    <nav className="space-y-1">
                      <button
                        type="button"
                        onClick={() => { setTeamSettingsSubTab('general'); setSidebarParams({ subtab: 'general' }); }}
                        className={cn(
                          'w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors',
                          teamSettingsSubTab === 'general' ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
                        )}
                      >
                        <Settings className="h-4 w-4" />
                        General
                      </button>
                      {(teamSidebarPermissions?.manage_notification_settings || teamSidebarHasOrgManagePermission) && (
                        <button
                          type="button"
                          onClick={() => { setTeamSettingsSubTab('notifications'); setSidebarParams({ subtab: 'notifications' }); }}
                          className={cn(
                            'w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors',
                            teamSettingsSubTab === 'notifications' ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
                          )}
                        >
                          <Bell className="h-4 w-4" />
                          Notifications
                        </button>
                      )}
                      {((teamSidebarPermissions?.view_roles || teamSidebarPermissions?.edit_roles) || teamSidebarHasOrgManagePermission) && (
                        <button
                          type="button"
                          onClick={() => { setTeamSettingsSubTab('roles'); setSidebarParams({ subtab: 'roles' }); }}
                          className={cn(
                            'w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors',
                            teamSettingsSubTab === 'roles' ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
                          )}
                        >
                          <Users className="h-4 w-4" />
                          Roles
                        </button>
                      )}
                    </nav>
                  </aside>

                  {/* Settings Content */}
                  <div className="flex-1 min-w-0">
                    {/* General Settings */}
                    {teamSettingsSubTab === 'general' && (
                      <div className="space-y-6">
                        <h2 className="text-2xl font-bold text-foreground">General</h2>
                        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                          <div className="p-6">
                            <h3 className="text-base font-semibold text-foreground mb-1">Team Name</h3>
                            <p className="text-sm text-foreground-secondary mb-4">
                              This is your team's visible name.
                            </p>
                            <div className="max-w-md mb-6">
                              <input
                                type="text"
                                value={teamSettingsName}
                                onChange={(e) => setTeamSettingsName(e.target.value)}
                                placeholder="Enter team name"
                                className="w-full px-3 py-2.5 bg-background-content border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                              />
                            </div>

                            <h3 className="text-base font-semibold text-foreground mb-1">Team Description</h3>
                            <p className="text-sm text-foreground-secondary mb-4">
                              Describe your team's purpose and responsibilities.
                            </p>
                            <textarea
                              value={teamSettingsDescription}
                              onChange={(e) => setTeamSettingsDescription(e.target.value)}
                              placeholder="Describe the team's purpose..."
                              rows={3}
                              className="w-full px-3 py-2.5 bg-background-content border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all resize-none"
                            />
                          </div>
                          <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                            <p className="text-xs text-foreground-secondary">Changes will be visible to all team members.</p>
                            <Button
                              onClick={handleTeamSettingsSave}
                              disabled={teamSettingsSaving || (teamSettingsName === teamSidebarTeamData.name && teamSettingsDescription === (teamSidebarTeamData.description || ''))}
                              size="sm"
                              className="h-8 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                            >
                              {teamSettingsSaving && <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />}
                              Save
                            </Button>
                          </div>
                        </div>

                      {/* Danger Zone */}
                      {teamSettingsCanDeleteTeam && (
                        <div className="border border-destructive/30 rounded-lg overflow-hidden bg-destructive/5">
                          <div className="px-6 py-3 border-b border-destructive/30 bg-destructive/10">
                            <h3 className="text-sm font-semibold text-destructive uppercase tracking-wide">Danger Zone</h3>
                          </div>
                          <div className="p-6">
                            <div className="flex items-start justify-between gap-4">
                              <div className="flex-1">
                                <h4 className="text-base font-semibold text-foreground mb-1">Delete Team</h4>
                                <p className="text-sm text-foreground-secondary">
                                  Permanently delete this team and all of its data. This action cannot be undone.
                                </p>
                              </div>
                              {!teamSettingsShowDeleteConfirm && (
                                <Button
                                  onClick={() => setTeamSettingsShowDeleteConfirm(true)}
                                  variant="outline"
                                  size="sm"
                                  className="flex-shrink-0 h-8 border-destructive/50 text-destructive hover:bg-destructive/10 hover:border-destructive"
                                >
                                  <Trash2 className="h-3.5 w-3.5 mr-2" />
                                  Delete
                                </Button>
                              )}
                            </div>
                            {teamSettingsShowDeleteConfirm && (
                              <div className="mt-4 p-4 bg-background/50 rounded-lg border border-destructive/30 space-y-4">
                                <p className="text-sm text-foreground">
                                  To confirm deletion, type <strong className="text-destructive font-mono bg-destructive/10 px-1.5 py-0.5 rounded">{teamSidebarTeamData.name}</strong> below:
                                </p>
                                <input
                                  type="text"
                                  value={teamSettingsDeleteConfirmText}
                                  onChange={(e) => setTeamSettingsDeleteConfirmText(e.target.value)}
                                  placeholder={teamSidebarTeamData.name}
                                  className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-all"
                                />
                                <div className="flex gap-2">
                                  <Button
                                    onClick={handleTeamSettingsDelete}
                                    variant="destructive"
                                    size="sm"
                                    disabled={teamSettingsDeleteConfirmText !== teamSidebarTeamData.name || teamSettingsDeleting}
                                    className="h-8"
                                  >
                                    {teamSettingsDeleting ? (
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
                                    onClick={() => { setTeamSettingsShowDeleteConfirm(false); setTeamSettingsDeleteConfirmText(''); }}
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
                      )}
                    </div>
                  )}

                    {/* Notifications Settings */}
                    {teamSettingsSubTab === 'notifications' && orgId && selectedTeamId && (
                      <div className="space-y-6">
                        <div className="flex items-center justify-between gap-4 flex-wrap pb-2">
                          <div>
                            <div className="flex items-center gap-2">
                              <h2 className="text-2xl font-bold text-foreground">Notifications</h2>
                              <Link to="/docs/notification-rules" target="_blank" rel="noopener noreferrer" className="shrink-0 text-foreground-secondary hover:text-foreground">
                                <BookOpen className="h-4 w-4" />
                              </Link>
                            </div>
                            <p className="mt-1.5 text-sm text-foreground-secondary">
                              Create custom rules to decide when to notify. Send alerts to Slack, email, Jira, and more.
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="outline" size="sm" className="text-xs gap-1.5" disabled={teamSettingsNotifPauseLoading}>
                                  {teamSettingsNotifPauseLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PauseCircle className="h-3.5 w-3.5" />}
                                  {teamSettingsNotifPausedUntil && new Date(teamSettingsNotifPausedUntil) > new Date() ? 'Paused' : 'Pause All'}
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                {teamSettingsNotifPausedUntil && new Date(teamSettingsNotifPausedUntil) > new Date() ? (
                                  <DropdownMenuItem onClick={async () => {
                                    setTeamSettingsNotifPauseLoading(true);
                                    try {
                                      await api.updateTeam(orgId, selectedTeamId, { notifications_paused_until: null });
                                      setTeamSettingsNotifPausedUntil(null);
                                      toast({ title: 'Resumed', description: 'Notifications have been resumed.' });
                                    } catch { toast({ title: 'Error', description: 'Failed to resume notifications.', variant: 'destructive' }); }
                                    finally { setTeamSettingsNotifPauseLoading(false); }
                                  }}>
                                    Resume notifications
                                  </DropdownMenuItem>
                                ) : (
                                  <>
                                    {[{ label: 'Pause for 1 hour', hours: 1 }, { label: 'Pause for 4 hours', hours: 4 }, { label: 'Pause for 24 hours', hours: 24 }].map(({ label, hours }) => (
                                      <DropdownMenuItem key={hours} onClick={async () => {
                                        setTeamSettingsNotifPauseLoading(true);
                                        try {
                                          const until = new Date(Date.now() + hours * 3600000).toISOString();
                                          await api.updateTeam(orgId, selectedTeamId, { notifications_paused_until: until });
                                          setTeamSettingsNotifPausedUntil(until);
                                          toast({ title: 'Paused', description: `Notifications paused for ${hours} hour${hours > 1 ? 's' : ''}.` });
                                        } catch { toast({ title: 'Error', description: 'Failed to pause notifications.', variant: 'destructive' }); }
                                        finally { setTeamSettingsNotifPauseLoading(false); }
                                      }}>
                                        {label}
                                      </DropdownMenuItem>
                                    ))}
                                  </>
                                )}
                              </DropdownMenuContent>
                            </DropdownMenu>
                            {teamSettingsNotifActiveTab === 'notifications' && (
                              <Button
                                onClick={() => teamSettingsNotificationCreateRef.current?.()}
                                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                              >
                                Create Rule
                              </Button>
                            )}
                          </div>
                        </div>

                        {teamSettingsNotifPausedUntil && new Date(teamSettingsNotifPausedUntil) > new Date() && (
                          <div className="flex items-center gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-3">
                            <PauseCircle className="h-4 w-4 text-amber-400 flex-shrink-0" />
                            <span className="text-sm text-amber-400">
                              Notifications paused until {new Date(teamSettingsNotifPausedUntil).toLocaleString()}
                            </span>
                          </div>
                        )}

                        <div className="flex items-center gap-6 border-b border-border pb-px">
                          <button
                            type="button"
                            onClick={() => setTeamSettingsNotifActiveTab('notifications')}
                            className={cn(
                              'pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                              teamSettingsNotifActiveTab === 'notifications' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                            )}
                          >
                            Notifications
                          </button>
                          <button
                            type="button"
                            onClick={() => setTeamSettingsNotifActiveTab('destinations')}
                            className={cn(
                              'pb-3 text-sm font-medium transition-colors border-b-2 -mb-px',
                              teamSettingsNotifActiveTab === 'destinations' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                            )}
                          >
                            Destinations
                          </button>
                        </div>

                        {teamSettingsNotifActiveTab === 'notifications' && (
                          <div className="pt-2">
                          <NotificationRulesSection
                            organizationId={orgId}
                            teamId={selectedTeamId}
                            hideTitle
                            createHandlerRef={teamSettingsNotificationCreateRef}
                            connections={[...teamSettingsConnections.inherited, ...teamSettingsConnections.team]}
                          />
                        </div>
                      )}

                      {teamSettingsNotifActiveTab === 'destinations' && (
                        <div className="pt-2 space-y-8">
                          {/* Inherited from organization */}
                          <div>
                            <h4 className="text-base font-semibold text-foreground mb-3">Inherited from organization</h4>
                            <p className="text-sm text-foreground-secondary mb-4">
                              Integrations connected at the organization level are available for this team.
                            </p>
                            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                              <table className="w-full table-fixed">
                                <colgroup><col className="w-[200px]" /><col /><col className="w-[120px]" /></colgroup>
                                <thead className="bg-background-card-header border-b border-border">
                                  <tr>
                                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                                    <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                  {teamSettingsConnectionsLoading ? (
                                    [1, 2, 3].map((i) => (
                                      <tr key={i}>
                                        <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                        <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                        <td className="px-4 py-3" />
                                      </tr>
                                    ))
                                  ) : teamSettingsConnections.inherited.length === 0 ? (
                                    <tr>
                                      <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                        No inherited integrations. Connect integrations in Organization Settings.
                                      </td>
                                    </tr>
                                  ) : (
                                    teamSettingsConnections.inherited.map((conn) => (
                                      <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                        <td className="px-4 py-3">
                                          <div className="flex items-center gap-2.5">
                                            {['slack', 'discord'].includes(conn.provider) && <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />}
                                            {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                            {['custom_notification', 'custom_ticketing'].includes(conn.provider) && (conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />)}
                                            {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                              ['jira', 'linear', 'pagerduty'].includes(conn.provider) ? <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                            )}
                                            <span className="text-sm font-medium text-foreground">
                                              {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' : conn.provider === 'email' ? 'Email' : conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') : conn.provider.charAt(0).toUpperCase() + conn.provider.slice(1)}
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

                          {/* Team-specific */}
                          <div>
                            <h4 className="text-base font-semibold text-foreground mb-3">Team-specific</h4>
                            <p className="text-sm text-foreground-secondary mb-4">
                              Add integrations that are specific to this team.
                            </p>
                            {teamSettingsCanManageSettings && (
                              <div className="flex items-center gap-2 mb-4 flex-wrap">
                                <Button variant="outline" size="sm" className="text-xs" onClick={async () => {
                                  try { const { redirectUrl } = await api.connectSlackOrg(orgId, undefined, selectedTeamId); window.location.href = redirectUrl; }
                                  catch (err: unknown) { toast({ title: 'Error', description: (err as Error).message || 'Failed to connect Slack', variant: 'destructive' }); }
                                }}>
                                  <img src="/images/integrations/slack.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />Add Slack
                                </Button>
                                <Button variant="outline" size="sm" className="text-xs" onClick={async () => {
                                  try { const { redirectUrl } = await api.connectDiscordOrg(orgId, undefined, selectedTeamId); window.location.href = redirectUrl; }
                                  catch (err: unknown) { toast({ title: 'Error', description: (err as Error).message || 'Failed to connect Discord', variant: 'destructive' }); }
                                }}>
                                  <img src="/images/integrations/discord.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />Add Discord
                                </Button>
                                <Button variant="outline" size="sm" className="text-xs" onClick={async () => {
                                  try { const { redirectUrl } = await api.connectLinearOrg(orgId, undefined, selectedTeamId); window.location.href = redirectUrl; }
                                  catch (err: unknown) { toast({ title: 'Error', description: (err as Error).message || 'Failed to connect Linear', variant: 'destructive' }); }
                                }}>
                                  <img src="/images/integrations/linear.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />Add Linear
                                </Button>
                              </div>
                            )}
                            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                              <table className="w-full table-fixed">
                                <colgroup><col className="w-[200px]" /><col /><col className="w-[140px]" /></colgroup>
                                <thead className="bg-background-card-header border-b border-border">
                                  <tr>
                                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                                    <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                  {teamSettingsConnectionsLoading ? (
                                    [1, 2].map((i) => (
                                      <tr key={i}>
                                        <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                        <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                        <td className="px-4 py-3" />
                                      </tr>
                                    ))
                                  ) : teamSettingsConnections.team.length === 0 ? (
                                    <tr>
                                      <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                        No team-specific integrations. Add one above.
                                      </td>
                                    </tr>
                                  ) : (
                                    teamSettingsConnections.team.map((conn) => (
                                      <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                        <td className="px-4 py-3">
                                          <div className="flex items-center gap-2.5">
                                            {['slack', 'discord'].includes(conn.provider) && <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />}
                                            {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                            {['custom_notification', 'custom_ticketing'].includes(conn.provider) && (conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />)}
                                            {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                              ['jira', 'linear', 'pagerduty'].includes(conn.provider) ? <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                            )}
                                            <span className="text-sm font-medium text-foreground">
                                              {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' : conn.provider === 'email' ? 'Email' : conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') : conn.provider.charAt(0).toUpperCase() + conn.provider.slice(1)}
                                            </span>
                                          </div>
                                        </td>
                                        <td className="px-4 py-3">
                                          <span className="text-sm text-foreground truncate block">
                                            {conn.provider === 'email' ? conn.metadata?.email || conn.display_name : conn.display_name || '-'}
                                          </span>
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                          {teamSettingsCanManageSettings && (
                                            <Button
                                              variant="outline"
                                              size="sm"
                                              className="text-xs hover:bg-destructive/10 hover:border-destructive/30 opacity-0 group-hover:opacity-100 transition-opacity"
                                              onClick={async () => {
                                                if (!confirm('Remove this integration?')) return;
                                                try {
                                                  await api.deleteTeamConnection(orgId, selectedTeamId, conn.id);
                                                  toast({ title: 'Removed', description: 'Integration removed.' });
                                                  loadTeamConnections();
                                                } catch (err: unknown) {
                                                  toast({ title: 'Failed to remove', description: (err as Error).message, variant: 'destructive' });
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

                    {/* Roles Settings */}
                    {teamSettingsSubTab === 'roles' && orgId && selectedTeamId && (
                      <div className="space-y-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <h2 className="text-2xl font-bold text-foreground">Roles</h2>
                            <p className="text-foreground-secondary mt-2 text-sm">Manage roles and permissions for your team.</p>
                          </div>
                          {teamSettingsCanManageSettings && (teamSidebarPermissions?.edit_roles || teamSidebarHasOrgManagePermission) && (
                            <Button
                              onClick={() => {
                              setTeamSettingsShowAddRoleSidepanel(true);
                              requestAnimationFrame(() => setTeamSettingsAddRolePanelVisible(true));
                            }}
                            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                          >
                            <Plus className="h-4 w-4 mr-2" />
                            Add Role
                          </Button>
                        )}
                      </div>

                      {/* Roles List */}
                      {teamSidebarRoles.length > 0 ? (
                        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                          <div className="px-4 py-2 border-b border-border bg-background-card-header text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                            Roles
                          </div>
                          <div className="divide-y divide-border">
                            {teamSidebarRoles.map((role) => {
                              const isUserRole = teamSidebarTeamData?.role === role.name;
                              const userRoleIndex = teamSidebarRoles.findIndex((r) => r.name === teamSidebarTeamData?.role);
                              const roleIndex = teamSidebarRoles.findIndex((r) => r.id === role.id);
                              const isRoleBelowUserRank = userRoleIndex !== -1 && roleIndex !== -1 && roleIndex > userRoleIndex;
                              const isTopRankedRole = role.display_order === 0;
                              const isUserTopRanked = userRoleIndex === 0;
                              const canEditRole = teamSettingsCanManageSettings && (teamSidebarHasOrgManagePermission || isRoleBelowUserRank || (isUserRole && isUserTopRanked));
                              const canDeleteRole = teamSettingsCanManageSettings && (teamSidebarHasOrgManagePermission || isRoleBelowUserRank) && !isTopRankedRole;
                              const memberCount = teamSettingsMemberCountByRole.get(role.name) ?? 0;

                              return (
                                <div key={role.id || role.name} className="px-4 py-3 flex items-center justify-between group hover:bg-table-hover transition-all">
                                  <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <div className="flex flex-col min-w-0">
                                      <div className="flex items-center gap-2">
                                        <span className="text-sm font-medium text-foreground truncate cursor-default">
                                          {role.display_name || role.name}
                                        </span>
                                        {isUserRole && (
                                          <span className="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide bg-green-600/15 text-green-500 rounded-full whitespace-nowrap">
                                            Your Role
                                          </span>
                                        )}
                                      </div>
                                      <div className="flex items-center gap-1 text-foreground-secondary">
                                        <Users className="h-3 w-3" />
                                        <span className="text-xs">{memberCount} {memberCount === 1 ? 'member' : 'members'}</span>
                                      </div>
                                    </div>
                                  </div>
                                  <div className="flex items-center justify-end flex-shrink-0 w-36 relative">
                                    <div className={cn('flex justify-end transition-opacity', teamSettingsCanManageSettings ? 'group-hover:opacity-0' : '')}>
                                      <RoleBadge role={role.name} roleDisplayName={role.display_name} roleColor={role.color} />
                                    </div>
                                    {teamSettingsCanManageSettings && (
                                      <div className="absolute inset-0 flex items-center justify-end gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <Button
                                          variant="ghost"
                                          size="icon"
                                          onClick={() => handleTeamSettingsEditRolePermissions(role, canEditRole)}
                                          className="h-7 w-7 text-foreground-secondary hover:text-foreground"
                                          title={canEditRole ? 'Settings' : 'View Settings (read-only)'}
                                        >
                                          <Settings className="h-4 w-4" />
                                        </Button>
                                        {canDeleteRole && (
                                          <Button
                                            variant="ghost"
                                            size="icon"
                                            onClick={() => handleTeamSettingsDeleteRole(role)}
                                            disabled={teamSettingsDeletingRoleId === role.id}
                                            className="h-7 w-7 text-foreground-secondary hover:text-destructive disabled:opacity-100"
                                            title="Delete"
                                          >
                                            {teamSettingsDeletingRoleId === role.id ? (
                                              <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full" />
                                            ) : (
                                              <Trash2 className="h-4 w-4" />
                                            )}
                                          </Button>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ) : (
                        <div className="bg-background-card border border-border rounded-lg p-12 flex flex-col items-center justify-center text-center">
                          <div className="h-12 w-12 rounded-full bg-background-subtle flex items-center justify-center mb-4">
                            <Users className="h-6 w-6 text-foreground-secondary" />
                          </div>
                          <h3 className="text-lg font-semibold text-foreground mb-1">No roles found</h3>
                          <p className="text-sm text-foreground-secondary max-w-sm">
                            Create roles to define permissions and access levels for your team members.
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                  </div>
                </div>
              )}
            </div>
          </div>
          )}
        </div>
      </div>

          {/* Project sidebar: same layout as team sidebar, with tabs */}
          {projectSidebarOpen && selectedProjectId && orgId && (
            <div
              className={cn(
                'absolute top-6 bottom-0 right-0 w-full max-w-[1000px] sm:max-w-[1200px] bg-background-card-header border-l border-t border-border rounded-tl-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-300 ease-out z-20',
                projectSidebarVisible ? 'translate-x-0' : 'translate-x-full'
              )}
            >
              <div className="flex-shrink-0 flex items-center justify-between gap-4 px-5 pt-5 pb-5">
                <div className="flex items-center gap-3 min-w-0">
                  <FrameworkIcon frameworkId={selectedProjectFramework ?? undefined} size={20} className="flex-shrink-0 text-muted-foreground" />
                  <h2 className="text-lg font-semibold text-foreground truncate">{selectedProjectName ?? 'Project'}</h2>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={closeProjectSidebar}
                    className="p-1 text-foreground-secondary hover:text-foreground transition-colors"
                    aria-label="Close"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>
              </div>
              <div className="flex-shrink-0 px-5 border-b border-border">
                <div className="flex items-center gap-6">
                  {(['vulnerabilities', 'dependencies', 'compliance', 'settings'] as const).map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      onClick={() => { setProjectSidebarTab(tab); setSidebarParams({ tab, subtab: null }); }}
                      className={cn(
                        'relative pb-3 text-sm font-medium transition-colors',
                        projectSidebarTab === tab ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
                      )}
                    >
                      {tab.charAt(0).toUpperCase() + tab.slice(1)}
                      {projectSidebarTab === tab && (
                        <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-foreground rounded-full" />
                      )}
                    </button>
                  ))}
                </div>
              </div>
              <div
                className={cn(
                  'flex-1 min-h-0 flex flex-col overflow-y-auto px-5',
                  projectSidebarTab === 'vulnerabilities' ? 'py-5' : 'pb-5 pt-0'
                )}
              >
                {projectSidebarTab === 'vulnerabilities' && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-medium text-foreground">Vulnerabilities</h3>
                    {selectedProjectIsExtracting ? (
                      <div className="py-10 flex flex-col items-center gap-3 text-center border border-border rounded-lg bg-background-subtle/50">
                        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" aria-hidden />
                        <p className="text-sm text-muted-foreground">Project is still extracting — check back soon.</p>
                      </div>
                    ) : projectStatsLoading && !projectVulnerabilities ? (
                      <OrgProjectVulnerabilitiesTableSkeleton rowCount={8} />
                    ) : !dedupedProjectVulnerabilities.length ? (
                      <div className="py-8 text-center text-sm text-muted-foreground border border-border rounded-lg bg-background-subtle/50">
                        No vulnerabilities found
                      </div>
                    ) : (
                      <div className="border border-border rounded-lg overflow-hidden">
                        <table className={ORG_PROJECT_VULN_TABLE_CLASS}>
                          <OrgProjectVulnerabilitiesTableColgroup />
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <span
                                      className="inline-flex items-center gap-1 cursor-help outline-none rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                                      tabIndex={0}
                                      aria-label="What is Depscore?"
                                    >
                                      Depscore
                                      <CircleHelp className="h-3.5 w-3.5 shrink-0 text-muted-foreground opacity-90" aria-hidden />
                                    </span>
                                  </TooltipTrigger>
                                  <TooltipContent side="top" className="max-w-sm text-left text-xs font-normal normal-case">
                                    <p className="font-medium text-foreground mb-1.5">Deptex Depscore (0–100)</p>
                                    <p className="text-muted-foreground mb-2">
                                      A project-aware priority score—not raw severity alone. It combines CVSS, EPSS,
                                      CISA KEV, this project&apos;s asset tier, how reachable the issue is from your
                                      code, direct vs transitive use, environment (e.g. dev), and package reputation.
                                    </p>
                                    <p className="text-muted-foreground">
                                      When EPD has run, the value is <span className="text-foreground">contextual</span>:
                                      a base score (signals above, without double-counting reachability the same way)
                                      multiplied by an execution-path factor from entry-point exposure and path depth.
                                      Strong sanitization on the path can reduce that factor toward zero.
                                    </p>
                                  </TooltipContent>
                                </Tooltip>
                              </th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase min-w-0">
                                Dependency
                              </th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase">
                                Advisory
                              </th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {dedupedProjectVulnerabilities.map((v) => {
                              const rawScore =
                                v.contextual_depscore != null && Number.isFinite(Number(v.contextual_depscore))
                                  ? Number(v.contextual_depscore)
                                  : v.depscore != null && Number.isFinite(Number(v.depscore))
                                    ? Number(v.depscore)
                                    : null;
                              const isExpanded = expandedProjectVulnRowId === v.id;
                              const detail = projectVulnDetailByRowId[v.id];
                              return (
                                <Fragment key={v.id}>
                                  <tr
                                    className="hover:bg-background-subtle/50 cursor-pointer"
                                    onClick={() => void toggleProjectVulnerabilityRow(v.id, v.osv_id)}
                                    aria-expanded={isExpanded}
                                  >
                                    <td className="px-4 py-2.5 align-middle">
                                      <Tooltip>
                                        <TooltipTrigger asChild>
                                          <span
                                            className={cn(
                                              'inline-flex w-14 min-w-[3.25rem] justify-start text-xs font-semibold tabular-nums cursor-default',
                                              rawScore == null ? 'text-muted-foreground' : (
                                                rawScore >= 75
                                                  ? 'text-destructive'
                                                  : rawScore >= 40
                                                    ? 'text-amber-600 dark:text-amber-400'
                                                    : 'text-muted-foreground'
                                              )
                                            )}
                                          >
                                            {rawScore != null ? rawScore.toFixed(1) : '—'}
                                          </span>
                                        </TooltipTrigger>
                                        <TooltipContent side="right" className="max-w-xs text-xs space-y-1">
                                          <p className="font-medium capitalize">Severity: {v.severity}</p>
                                          {v.contextual_depscore != null && (
                                            <p>
                                              Contextual (EPD): {Number(v.contextual_depscore).toFixed(1)}
                                              {v.depscore != null && (
                                                <span className="text-muted-foreground"> · Base: {Number(v.depscore).toFixed(1)}</span>
                                              )}
                                            </p>
                                          )}
                                          {v.contextual_depscore == null && v.depscore != null && (
                                            <p>Depscore: {Number(v.depscore).toFixed(1)}</p>
                                          )}
                                          {rawScore == null && <p className="text-muted-foreground">Score not computed yet (re-run extraction after vuln sync).</p>}
                                          {v.is_reachable === false && <p className="text-muted-foreground">Not flagged as reachable in this project.</p>}
                                        </TooltipContent>
                                      </Tooltip>
                                    </td>
                                    <td className="px-4 py-2.5 text-foreground min-w-0 align-middle">
                                      <div
                                        className="truncate min-w-0"
                                        title={`${v.dependency_name}@${v.dependency_version}`}
                                      >
                                        {v.dependency_name}
                                        <span className="text-muted-foreground font-normal">
                                          @{v.dependency_version}
                                        </span>
                                      </div>
                                    </td>
                                    <td className="px-4 py-2.5 align-middle">
                                      <div className="flex items-center gap-2 min-w-0">
                                        {v.cvss_score != null ? (
                                          <span
                                            className={cn(
                                              'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border tabular-nums',
                                              Number(v.cvss_score) >= 9
                                                ? 'bg-destructive/12 text-destructive border-destructive/30'
                                                : Number(v.cvss_score) >= 7
                                                  ? 'bg-amber-500/12 text-amber-600 dark:text-amber-400 border-amber-500/30'
                                                  : Number(v.cvss_score) >= 4
                                                    ? 'bg-yellow-500/12 text-yellow-600 dark:text-yellow-400 border-yellow-500/30'
                                                    : 'bg-muted/80 text-muted-foreground border-border'
                                            )}
                                          >
                                            CVSS {Number(v.cvss_score).toFixed(1)}
                                          </span>
                                        ) : (
                                          <span
                                            className={cn(
                                              'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border',
                                              v.severity === 'critical'
                                                ? 'bg-destructive/12 text-destructive border-destructive/30'
                                                : v.severity === 'high'
                                                  ? 'bg-amber-500/12 text-amber-600 dark:text-amber-400 border-amber-500/30'
                                                  : v.severity === 'medium'
                                                    ? 'bg-yellow-500/12 text-yellow-600 dark:text-yellow-400 border-yellow-500/30'
                                                    : 'bg-muted/80 text-muted-foreground border-border'
                                            )}
                                          >
                                            {String(v.severity || 'unknown').toUpperCase()}
                                          </span>
                                        )}
                                      </div>
                                    </td>
                                  </tr>
                                  <tr>
                                    <td colSpan={3} className="px-0 py-0">
                                      <div
                                        className="overflow-hidden transition-[max-height,opacity] duration-300 ease-in-out"
                                        style={{ maxHeight: isExpanded ? 1800 : 0, opacity: isExpanded ? 1 : 0 }}
                                      >
                                        <div className="px-4 py-4 bg-background-subtle/30 border-t border-border">
                                          {detail?.loading ? (
                                            <VulnOrgSidebarExpandedSkeleton />
                                          ) : detail?.error ? (
                                            <div className="text-sm text-destructive">{detail.error}</div>
                                          ) : detail?.data ? (
                                            <VulnerabilityOrgSidebarExpandedContent
                                              detail={detail.data}
                                              rowSummary={v.summary ?? null}
                                            />
                                          ) : (
                                            <div className="text-sm text-muted-foreground">No details available.</div>
                                          )}
                                        </div>
                                      </div>
                                    </td>
                                  </tr>
                                </Fragment>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
                {projectSidebarTab === 'dependencies' && projectSidebarProject && orgId && (
                  <ProjectDependenciesContent
                    project={projectSidebarProject}
                    organizationId={orgId}
                    userPermissions={projectSidebarProject.permissions ?? null}
                    reloadProject={async () => {
                      if (!orgId || !selectedProjectId) return;
                      const p = await api.getProject(orgId, selectedProjectId);
                      setProjectSidebarProject(p);
                    }}
                    embedInSidebar
                  />
                )}
                {projectSidebarTab === 'compliance' && projectSidebarProject && orgId && (
                  <ProjectComplianceContent
                    project={projectSidebarProject}
                    organizationId={orgId}
                    userPermissions={projectSidebarProject.permissions ?? null}
                    reloadProject={async () => {
                      if (!orgId || !selectedProjectId) return;
                      const p = await api.getProject(orgId, selectedProjectId);
                      setProjectSidebarProject(p);
                    }}
                    embedInSidebar
                  />
                )}
                {projectSidebarTab === 'settings' && projectSidebarProject && projectSidebarOrganization && orgId && (
                  <ProjectSettingsContent
                    project={projectSidebarProject}
                    organizationId={orgId}
                    organization={projectSidebarOrganization}
                    userPermissions={projectSidebarProject.permissions ?? null}
                    reloadProject={async () => {
                      if (!orgId || !selectedProjectId) return;
                      const [p, o] = await Promise.all([api.getProject(orgId, selectedProjectId), api.getOrganization(orgId)]);
                      setProjectSidebarProject(p);
                      setProjectSidebarOrganization(o);
                    }}
                    embedInSidebar
                    initialSection={projectSettingsSubTab}
                    onSectionChange={(s) => { setProjectSettingsSubTab(s); setSidebarParams({ subtab: s }); }}
                  />
                )}
                {projectSidebarTab !== 'vulnerabilities' && projectSidebarProjectLoading && (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                  </div>
                )}
                {projectSidebarTab !== 'vulnerabilities' && !projectSidebarProjectLoading && !projectSidebarProject && (
                  <div className="py-8 text-center text-sm text-muted-foreground">Could not load project.</div>
                )}
              </div>
            </div>
          )}

      {/* Add Team Member sidebar (from team sidebar) */}
      {teamSidebarAddMemberOpen && selectedTeamId && orgId && selectedTeamId !== UNGROUPED_TEAM_ID && (
        <div className="fixed inset-0 z-[60]">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              teamSidebarAddMemberVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeTeamSidebarAddMember}
            aria-hidden
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[520px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              teamSidebarAddMemberVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
              <h2 className="text-xl font-semibold text-foreground">Add Team Member</h2>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-4">
              <div className="space-y-6">
                <div className="space-y-3">
                  <label className="text-base font-semibold text-foreground">
                    Select Member
                  </label>
                  <div className="relative mb-2">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                    <input
                      type="text"
                      placeholder="Search organization members..."
                      value={addMemberSearchQuery}
                      onChange={(e) => setAddMemberSearchQuery(e.target.value)}
                      className="w-full pl-9 pr-4 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>
                  <div className="max-h-48 overflow-y-auto border border-border rounded-md">
                    {teamSidebarFilteredAvailableMembers.length === 0 ? (
                      <div className="p-4 text-sm text-foreground-secondary text-center">
                        No members available to add
                      </div>
                    ) : (
                      teamSidebarFilteredAvailableMembers.map((member) => (
                        <button
                          key={member.user_id}
                          type="button"
                          onClick={() => {
                            setAddMemberSelectedUserIds((prev) =>
                              prev.includes(member.user_id)
                                ? prev.filter((id) => id !== member.user_id)
                                : [...prev, member.user_id]
                            );
                          }}
                          className={cn(
                            'w-full flex items-center gap-3 px-3 py-2 text-left transition-colors',
                            addMemberSelectedUserIds.includes(member.user_id) ? 'bg-background-card/80' : 'hover:bg-background-card/60'
                          )}
                        >
                          <img
                            src={member.avatar_url || '/images/blank_profile_image.png'}
                            alt={member.full_name || member.email}
                            className="h-8 w-8 rounded-full object-cover border border-border"
                            referrerPolicy="no-referrer"
                            onError={(e) => { e.currentTarget.src = '/images/blank_profile_image.png'; }}
                          />
                          <div className="flex-1 min-w-0 text-left">
                            <div className="text-sm font-medium text-foreground">{member.full_name || 'Unknown'}</div>
                            <div className="text-xs text-foreground-secondary">{member.email}</div>
                          </div>
                          {addMemberSelectedUserIds.includes(member.user_id) && (
                            <Check className="h-4 w-4 text-white flex-shrink-0" />
                          )}
                        </button>
                      ))
                    )}
                  </div>
                </div>
                <div className="border-t border-border" />
                <div className="space-y-3">
                  <label className="text-base font-semibold text-foreground">
                    Role
                  </label>
                  <RoleDropdown
                    value={addMemberSelectedRoleId}
                    onChange={(value) => setAddMemberSelectedRoleId(value)}
                    roles={teamSidebarRoles.filter((r) => r.name !== 'owner')}
                    variant="modal"
                    className="w-full"
                    showBadges={true}
                    memberCounts={teamSidebarMemberCounts}
                  />
                </div>
              </div>
            </div>
            <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
              <Button variant="outline" onClick={closeTeamSidebarAddMember} disabled={addMemberAdding}>
                Cancel
              </Button>
              <Button
                onClick={async () => {
                  if (!orgId || !selectedTeamId || addMemberSelectedUserIds.length === 0) return;
                  const role = teamSidebarRoles.find((r) => r.name === addMemberSelectedRoleId);
                  const roleId = role?.id;
                  setAddMemberAdding(true);
                  try {
                    await Promise.all(
                      addMemberSelectedUserIds.map((userId) =>
                        api.addTeamMember(orgId, selectedTeamId, userId, roleId)
                      )
                    );
                    toast({
                      title: 'Success',
                      description: addMemberSelectedUserIds.length === 1 ? 'Member added to team' : 'Members added to team',
                    });
                    const [members, orgMembers] = await Promise.all([
                      api.getTeamMembers(orgId, selectedTeamId),
                      api.getOrganizationMembers(orgId),
                    ]);
                    setTeamSidebarMembers(members);
                    setTeamSidebarOrgMembers(orgMembers);
                    closeTeamSidebarAddMember();
                  } catch (err: any) {
                    toast({
                      title: 'Error',
                      description: err?.message || 'Failed to add member',
                      variant: 'destructive',
                    });
                  } finally {
                    setAddMemberAdding(false);
                  }
                }}
                disabled={addMemberSelectedUserIds.length === 0 || addMemberAdding}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                {addMemberAdding && (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                )}
                {addMemberSelectedUserIds.length <= 1 ? 'Add Member' : `Add ${addMemberSelectedUserIds.length} Members`}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Team Sidebar: Change Role Dialog */}
      {teamSidebarRoleChangeOpen && teamSidebarMemberToChangeRole && (
        <div className="fixed inset-0 z-[70]">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setTeamSidebarRoleChangeOpen(false);
              setTeamSidebarMemberToChangeRole(null);
            }}
          />
          <div className="fixed inset-0 flex items-center justify-center p-4">
            <div
              className="bg-background border border-border rounded-lg shadow-2xl w-full max-w-md"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-5 border-b border-border">
                <h2 className="text-xl font-semibold text-foreground">Change Role</h2>
                <p className="text-sm text-foreground-secondary mt-1">
                  Select a new role for {teamSidebarMemberToChangeRole.full_name || teamSidebarMemberToChangeRole.email?.split('@')[0] || 'this member'}.
                </p>
              </div>
              <div className="px-6 py-6 space-y-4">
                <div className="flex items-center gap-3 p-3 bg-background-card border border-border rounded-md">
                  <img
                    src={teamSidebarMemberToChangeRole.avatar_url || '/images/blank_profile_image.png'}
                    alt={teamSidebarMemberToChangeRole.full_name || teamSidebarMemberToChangeRole.email}
                    className="h-10 w-10 rounded-full object-cover border border-border"
                    referrerPolicy="no-referrer"
                    onError={(e) => { e.currentTarget.src = '/images/blank_profile_image.png'; }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-foreground truncate">
                      {teamSidebarMemberToChangeRole.full_name || teamSidebarMemberToChangeRole.email?.split('@')[0]}
                    </div>
                    <div className="text-xs text-foreground-secondary truncate">
                      {teamSidebarMemberToChangeRole.email}
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground">Role</label>
                  <RoleDropdown
                    value={teamSidebarNewRole}
                    onChange={(value) => setTeamSidebarNewRole(value)}
                    roles={teamSidebarHasOrgManagePermission
                      ? teamSidebarRoles.filter((r) => r.name !== 'owner')
                      : teamSidebarRoles.filter((r) => r.name !== 'owner' && r.display_order >= (teamSidebarUserRank ?? 999))
                    }
                    variant="modal"
                    className="w-full"
                    showBadges={true}
                    memberCounts={teamSidebarMemberCounts}
                  />
                </div>
              </div>
              <div className="px-6 py-5 border-t border-border flex items-center justify-end gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setTeamSidebarRoleChangeOpen(false);
                    setTeamSidebarMemberToChangeRole(null);
                  }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleTeamSidebarUpdateRole}
                  disabled={teamSidebarUpdatingRole}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {teamSidebarUpdatingRole && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                  Update Role
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Team Sidebar: Leave/Remove Confirmation Modal */}
      {teamSidebarRemoveConfirmOpen && teamSidebarMemberToRemove && (
        <div className="fixed inset-0 z-[70]">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setTeamSidebarRemoveConfirmOpen(false);
              setTeamSidebarMemberToRemove(null);
            }}
          />
          <div className="fixed inset-0 flex items-center justify-center p-4">
            <div
              className="bg-background border border-border rounded-lg shadow-2xl w-full max-w-md"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-5 border-b border-border">
                <h2 className="text-xl font-semibold text-foreground">
                  {user?.id === teamSidebarMemberToRemove ? 'Leave Team' : 'Remove Member'}
                </h2>
              </div>
              <div className="px-6 py-6">
                <p className="text-foreground-secondary">
                  {user?.id === teamSidebarMemberToRemove
                    ? 'Are you sure you want to leave this team? You will need to be re-added by a team admin to rejoin.'
                    : 'Are you sure you want to remove this member from the team?'}
                </p>
              </div>
              <div className="px-6 py-5 border-t border-border flex items-center justify-end gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setTeamSidebarRemoveConfirmOpen(false);
                    setTeamSidebarMemberToRemove(null);
                  }}
                  disabled={teamSidebarRemovingMember}
                >
                  Cancel
                </Button>
                <Button
                  onClick={confirmTeamSidebarRemoveMember}
                  disabled={teamSidebarRemovingMember}
                  className="bg-red-600 text-white hover:bg-red-700"
                >
                  {teamSidebarRemovingMember && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                    {user?.id === teamSidebarMemberToRemove ? 'Leave Team' : 'Remove Member'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Team Settings: Create New Role Sidepanel */}
      {teamSettingsShowAddRoleSidepanel && selectedTeamId && orgId && (
        <div className="fixed inset-0 z-[60]">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              teamSettingsAddRolePanelVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={() => { setTeamSettingsAddRolePanelVisible(false); setTimeout(() => setTeamSettingsShowAddRoleSidepanel(false), 150); }}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              teamSettingsAddRolePanelVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0 bg-background-card">
              <h2 className="text-xl font-semibold text-foreground">Create New Role</h2>
              <p className="text-sm text-foreground-secondary mt-0.5">Define a custom role with specific permissions for your team.</p>
            </div>
            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
              <div className="space-y-6">
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <Tag className="h-5 w-5 text-foreground-secondary" />
                    Role Name
                  </label>
                  <input
                    type="text"
                    placeholder=""
                    value={teamSettingsNewRoleNameInput}
                    onChange={(e) => setTeamSettingsNewRoleNameInput(e.target.value)}
                    maxLength={24}
                    className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    autoFocus
                    disabled={teamSettingsIsCreatingRole}
                  />
                </div>
                <div className="border-t border-border" />
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <Palette className="h-5 w-5 text-foreground-secondary" />
                    Role Color
                  </label>
                  <div className="flex flex-wrap items-center gap-2">
                    {[
                      { color: '#ef4444', name: 'Red' }, { color: '#f97316', name: 'Orange' }, { color: '#eab308', name: 'Yellow' },
                      { color: '#22c55e', name: 'Green' }, { color: '#14b8a6', name: 'Teal' }, { color: '#3b82f6', name: 'Blue' },
                      { color: '#8b5cf6', name: 'Purple' }, { color: '#ec4899', name: 'Pink' },
                    ].map(({ color, name }) => (
                      <button
                        key={color}
                        type="button"
                        onClick={() => setTeamSettingsNewRoleColor(color)}
                        disabled={teamSettingsIsCreatingRole}
                        title={name}
                        className={cn(
                          'h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center',
                          teamSettingsNewRoleColor === color ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'
                        )}
                        style={{ backgroundColor: color }}
                      >
                        {teamSettingsNewRoleColor === color && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                      </button>
                    ))}
                    {teamSettingsNewRoleColor && (
                      <button
                        type="button"
                        onClick={() => setTeamSettingsNewRoleColor('')}
                        disabled={teamSettingsIsCreatingRole}
                        className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                        title="Clear color"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                  {teamSettingsNewRoleNameInput && (
                    <div className="pt-3 border-t border-border/50">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-foreground-secondary">Preview:</span>
                        <RoleBadge role={teamSettingsNewRoleNameInput.toLowerCase()} roleDisplayName={teamSettingsNewRoleNameInput} roleColor={teamSettingsNewRoleColor || null} />
                      </div>
                    </div>
                  )}
                </div>
                <div className="pt-4 border-t border-border">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold text-foreground mb-1">Permissions</h3>
                    <p className="text-sm text-foreground-secondary">Configure what this role can do in your team.</p>
                  </div>
                  <TeamPermissionEditor
                    permissions={teamSettingsNewRolePermissions}
                    onSave={async () => {}}
                    onChange={setTeamSettingsNewRolePermissions}
                    hideActions={true}
                    currentUserPermissions={teamSidebarPermissions}
                    isOwner={teamSidebarHasOrgManagePermission}
                  />
                </div>
              </div>
            </div>
            <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
              <Button variant="outline" onClick={() => { setTeamSettingsAddRolePanelVisible(false); setTimeout(() => setTeamSettingsShowAddRoleSidepanel(false), 150); }} disabled={teamSettingsIsCreatingRole}>
                Cancel
              </Button>
              <Button
                onClick={() => handleTeamSettingsCreateRole(teamSettingsNewRolePermissions)}
                disabled={teamSettingsIsCreatingRole || !teamSettingsNewRoleNameInput.trim()}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                {teamSettingsIsCreatingRole ? (
                  <><span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />Create Role</>
                ) : (
                  <><FileCheck className="h-4 w-4 mr-2" />Create Role</>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Team Settings: Edit Role Sidepanel */}
      {teamSettingsShowRoleSettingsModal && teamSettingsSelectedRoleForSettings && teamSettingsEditingRolePermissions && selectedTeamId && orgId && (
        <div className="fixed inset-0 z-[60]">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              teamSettingsRoleSettingsPanelVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={() => { setTeamSettingsRoleSettingsPanelVisible(false); setTimeout(() => setTeamSettingsShowRoleSettingsModal(false), 150); }}
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              teamSettingsRoleSettingsPanelVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0 bg-background-card">
              <h2 className="text-xl font-semibold text-foreground">Role Settings</h2>
              <p className="text-sm text-foreground-secondary mt-0.5">
                {teamSettingsCanEditSelectedRole ? 'Edit role settings and permissions.' : 'View role settings (read-only).'}
              </p>
            </div>
            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
              <div className="space-y-6">
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <Tag className="h-5 w-5 text-foreground-secondary" />
                    Role Name
                  </label>
                  <input
                    type="text"
                    value={teamSettingsEditingRoleName}
                    onChange={(e) => setTeamSettingsEditingRoleName(e.target.value)}
                    maxLength={24}
                    className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent disabled:opacity-60"
                    disabled={!teamSettingsCanEditSelectedRole || teamSettingsIsSavingRole}
                  />
                </div>
                <div className="border-t border-border" />
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <Palette className="h-5 w-5 text-foreground-secondary" />
                    Role Color
                  </label>
                  <div className="flex flex-wrap items-center gap-2">
                    {[
                      { color: '#ef4444', name: 'Red' }, { color: '#f97316', name: 'Orange' }, { color: '#eab308', name: 'Yellow' },
                      { color: '#22c55e', name: 'Green' }, { color: '#14b8a6', name: 'Teal' }, { color: '#3b82f6', name: 'Blue' },
                      { color: '#8b5cf6', name: 'Purple' }, { color: '#ec4899', name: 'Pink' },
                    ].map(({ color, name }) => (
                      <button
                        key={color}
                        type="button"
                        onClick={() => setTeamSettingsEditingRoleColor(color)}
                        disabled={!teamSettingsCanEditSelectedRole || teamSettingsIsSavingRole}
                        title={name}
                        className={cn(
                          'h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center disabled:opacity-60',
                          teamSettingsEditingRoleColor === color ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'
                        )}
                        style={{ backgroundColor: color }}
                      >
                        {teamSettingsEditingRoleColor === color && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                      </button>
                    ))}
                    {teamSettingsEditingRoleColor && teamSettingsCanEditSelectedRole && (
                      <button
                        type="button"
                        onClick={() => setTeamSettingsEditingRoleColor('')}
                        disabled={teamSettingsIsSavingRole}
                        className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                        title="Clear color"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                  {teamSettingsEditingRoleName && (
                    <div className="pt-3 border-t border-border/50">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-foreground-secondary">Preview:</span>
                        <RoleBadge role={teamSettingsEditingRoleName.toLowerCase()} roleDisplayName={teamSettingsEditingRoleName} roleColor={teamSettingsEditingRoleColor || null} />
                      </div>
                    </div>
                  )}
                </div>
                <div className="pt-4 border-t border-border">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold text-foreground mb-1">Permissions</h3>
                    <p className="text-sm text-foreground-secondary">
                      {teamSettingsCanEditSelectedRole ? 'Configure what this role can do.' : 'View permissions for this role.'}
                    </p>
                  </div>
                  <TeamPermissionEditor
                    permissions={teamSettingsEditingRolePermissions}
                    onSave={async () => {}}
                    onChange={teamSettingsCanEditSelectedRole ? setTeamSettingsEditingRolePermissions : undefined}
                    hideActions={true}
                    currentUserPermissions={teamSidebarPermissions}
                    isOwner={teamSidebarHasOrgManagePermission}
                  />
                </div>
              </div>
            </div>
            <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
              <Button variant="outline" onClick={() => { setTeamSettingsRoleSettingsPanelVisible(false); setTimeout(() => setTeamSettingsShowRoleSettingsModal(false), 150); }} disabled={teamSettingsIsSavingRole}>
                {teamSettingsCanEditSelectedRole ? 'Cancel' : 'Close'}
              </Button>
              {teamSettingsCanEditSelectedRole && (
                <Button
                  onClick={handleTeamSettingsSaveRolePermissions}
                  disabled={teamSettingsIsSavingRole}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {teamSettingsIsSavingRole ? (
                    <><span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />Save</>
                  ) : (
                    'Save'
                  )}
                </Button>
              )}
            </div>
          </div>
        </div>
      )}

      {syncDetailProjectId && orgId && (
        <SyncDetailSidebar
          projectId={syncDetailProjectId}
          organizationId={orgId}
          onClose={() => setSyncDetailProjectId(null)}
          onCancelled={() => setSyncDetailProjectId(null)}
        />
      )}
    </main>
  );
}
