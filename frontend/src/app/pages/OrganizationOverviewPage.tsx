import { Fragment, useState, useEffect, useRef, useCallback, useMemo, type ReactNode } from 'react';
import { useOutletContext, useParams, useNavigate, Link, useSearchParams } from 'react-router-dom';
import {
  ReactFlow,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Plus, Minus, Search, ShieldCheck, X, LayoutDashboard, FolderKanban, Shield, FileCode, Settings, Activity, UserPlus, Users, FolderPlus, Loader2, Package, HeartPulse, ChevronRight, Check, CircleCheck, MoreVertical, Trash2, Save, Mail, Webhook, BookOpen, PauseCircle, Tag, Palette, GripVertical, Edit2, FileCheck, CircleHelp, Maximize2, GitFork, MousePointer2, MousePointerClick, PanelRight, Lock } from 'lucide-react';
import { Button } from '../../components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { Badge } from '../../components/ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from '../../components/ui/tooltip';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../../components/ui/dialog';
import { api, Organization, Team, Project, TeamWithRole, type ProjectStats, type ProjectVulnerability, type OrganizationStatus, type TeamStats, type TeamMember, type ProjectDependency, type OrganizationMember, type TeamRole, type TeamPermissions, type CiCdConnection, type ProjectSecuritySummary, type ProjectWithRole, type VulnerabilityDetail, type SecretFinding, type SemgrepFinding, type IaCFinding, type ContainerFinding, type MaliciousFinding, type DastFindingDTO, type BaseImageRecommendation, type DataFlowFinding, type FindingTrackerLink, type FindingGroupSuppression, type FindingAcknowledgement, type OverviewBundle } from '../../lib/api';
import { readOverviewCache, writeOverviewCache } from '../../lib/overview-cache';
import { cn } from '../../lib/utils';
import { computeOverviewStatusRollup, type OverviewStatusRollup } from '../../lib/overviewStatusRollup';
import { isExtractionOngoing, isInitialExtraction } from '../../lib/extractionStatus';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { ExtractionProgressCard } from '../../components/ExtractionProgressCard';
import { useAuth } from '../../contexts/AuthContext';
import { getAvatarUrl, getDisplayNameOrNull } from '../../lib/userIdentity';
import { useToast } from '../../hooks/use-toast';
import {
  useOrganizationOverviewGraphLayout,
  ORG_CENTER_ID,
  getTeamProjectHandles,
  type OverviewTeamWithProjects,
  type OverviewProjectItem,
} from '../../components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout';
import {
  ORG_OVERVIEW_EDGE_STROKE,
  ORG_OVERVIEW_ORG_WIDTH,
  ORG_OVERVIEW_ORG_HEIGHT,
  ORG_OVERVIEW_TEAM_WIDTH,
  ORG_OVERVIEW_TEAM_HEIGHT,
  getOrgToSatelliteHandles,
} from '../../components/vulnerabilities-graph/overviewOrgLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { SkeletonGroupCenterNode } from '../../components/vulnerabilities-graph/SkeletonGroupCenterNode';
import { ReactiveDotGrid } from '../../components/vulnerabilities-graph/ReactiveDotGrid';
import { OrgCanvasCursors } from '../../components/vulnerabilities-graph/OrgCanvasCursors';
import { setCanvasDragging } from '../../components/vulnerabilities-graph/canvasDragSignal';
import {
  useOrgCanvasCursors,
  type LocalIdentity,
  type NodePositionUpdate,
  type RemoteDragMoveMessage,
  type RemoteDragStartMessage,
  type RemoteDragStopMessage,
} from '../../components/vulnerabilities-graph/useOrgCanvasCursors';
import { VulnProjectNode, OVERVIEW_PROJECT_NODE_WIDTH, OVERVIEW_PROJECT_NODE_HEIGHT } from '../../components/vulnerabilities-graph/VulnProjectNode';
import { ProjectCenterNode } from '../../components/vulnerabilities-graph/ProjectCenterNode';
import { TeamGroupNode } from '../../components/vulnerabilities-graph/TeamGroupNode';
import { SyncDetailSidebar } from '../../components/SyncDetailSidebar';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { FrameworkIcon } from '../../components/framework-icon';
import { FindingTypeIcon } from '../../components/security/FindingTypeIcon';
import { SeverityPills } from '../../components/SeverityPills';
import { ProjectsAssetTable } from '../../components/ProjectsAssetTable';
import { formatDate, formatRelativeTime, prettyFramework, PROVIDER_LOGOS } from '../../lib/projectDisplay';
import { TeamIcon } from '../../components/TeamIcon';
import { RoleBadge } from '../../components/RoleBadge';
import { RoleDropdown } from '../../components/RoleDropdown';
import { TeamPermissionEditor } from '../../components/TeamPermissionEditor';
import type { NodeTypes } from '@xyflow/react';
import { ProjectDependenciesContent } from './ProjectDependenciesContent';
import { ProjectComplianceContent } from './ProjectComplianceContent';
import { ProjectSettingsContent } from './ProjectSettingsContent';
import {
  VulnOrgSidebarExpandedSkeleton,
  VulnerabilityOrgSidebarExpandedContent,
} from '../../components/security/VulnerabilityOrgSidebarExpandedContent';
import VulnerabilityExpandableTable, { type SecurityTableRow } from '../../components/security/VulnerabilityExpandableTable';
import OrganizationVulnerabilitiesTableSkeleton from '../../components/security/OrganizationVulnerabilitiesTableSkeleton';
import { supabase } from '../../lib/supabase';

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
  x: -ORG_OVERVIEW_ORG_WIDTH / 2,
  y: -ORG_OVERVIEW_ORG_HEIGHT / 2,
};

const orgSkeletonNodes = [
  {
    id: 'skeleton-org-center',
    type: 'skeletonGroupCenterNode',
    position: ORG_SKELETON_CENTER_POS,
    data: {},
    style: { width: ORG_OVERVIEW_ORG_WIDTH, height: ORG_OVERVIEW_ORG_HEIGHT },
  },
];

const UNGROUPED_TEAM_ID = 'org-ungrouped';
const UNGROUPED_TEAM_NAME = 'No team';
// Stable empty-state references so the OrgCanvasCursors memo/deps don't
// churn every render when the cursor toggles are off.
const EMPTY_CURSORS: [] = [];
const EMPTY_DRAGGERS: Record<string, string> = {};
const noopCursorMove = (_x: number, _y: number) => {};


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

/** Loading skeleton for the team Settings tab — mirrors the loaded layout (w-32 subnav with two
 *  items, General heading, Team details card with name field + save footer, Danger Zone card) and
 *  fades downward. animate-pulse lives on the placeholder blocks only, never on bordered elements. */
function TeamSettingsSkeleton() {
  return (
    <div className="flex gap-6 pointer-events-none select-none" aria-busy="true" aria-label="Loading team settings">
      <aside className="w-32 flex-shrink-0">
        <div className="space-y-1">
          {['w-16', 'w-12'].map((w, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-2">
              <div className="h-4 w-4 rounded bg-muted animate-pulse" />
              <div className={`h-4 ${w} rounded bg-muted animate-pulse`} />
            </div>
          ))}
        </div>
      </aside>
      <div
        className="flex-1 min-w-0 space-y-6"
        style={{
          maskImage: 'linear-gradient(to bottom, #000 0%, #000 45%, transparent 100%)',
          WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 45%, transparent 100%)',
        }}
      >
        <div className="h-8 w-32 rounded-md bg-muted animate-pulse" />
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <div className="p-6 space-y-4">
            <div className="h-5 w-28 rounded bg-muted animate-pulse" />
            <div className="space-y-2 max-w-md">
              <div className="h-4 w-12 rounded bg-muted/70 animate-pulse" />
              <div className="h-10 w-full rounded-lg bg-muted/40 animate-pulse" />
            </div>
          </div>
          <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
            <div className="h-8 w-16 rounded-lg bg-muted animate-pulse" />
          </div>
        </div>
        <div className="bg-background-card border border-border rounded-lg p-6 space-y-3">
          <div className="h-4 w-28 rounded bg-muted animate-pulse" />
          <div className="h-4 w-2/3 rounded bg-muted/60 animate-pulse" />
          <div className="h-8 w-28 rounded-lg bg-muted/70 animate-pulse" />
        </div>
      </div>
    </div>
  );
}

/** House error state for sidebar tab bodies — same shape as ProjectsAssetTable's error card
 *  (title, context line, plain outline Try again — deliberately no icon). */
function SidebarErrorState({ title, context, onRetry }: { title: string; context: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <h3 className="text-base font-medium text-foreground mb-1">{title}</h3>
      <p className="text-sm text-foreground-secondary max-w-[260px] mb-4">Something went wrong fetching {context}.</p>
      <Button variant="outline" onClick={onRetry} className="h-8 rounded-lg px-3">
        Try again
      </Button>
    </div>
  );
}

/** Skeleton for the project Findings tab — the unified findings table without a
 *  Project column (single project). Delegates to the shared skeleton so it always
 *  mirrors the real columns + downward fade. */
function OrgProjectVulnerabilitiesTableSkeleton() {
  return <OrganizationVulnerabilitiesTableSkeleton showProjectCol={false} />;
}

/**
 * Recomputes org→satellite and team→project edge handles for the observer's canvas
 * during remote drag. Uses simple face handles (top/right/bottom/left) which are
 * always rendered unconditionally on every node — no slot-fan synchronisation needed.
 */
function recomputeOrgCanvasLayout(edges: Edge[], nodes: Node[]): Edge[] {
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const orgNode = nodeById.get(ORG_CENTER_ID);
  if (!orgNode) return edges;

  const orgCX = orgNode.position.x + (orgNode.width ?? ORG_OVERVIEW_ORG_WIDTH) / 2;
  const orgCY = orgNode.position.y + (orgNode.height ?? ORG_OVERVIEW_ORG_HEIGHT) / 2;

  return edges.map((edge) => {
    if (edge.source === ORG_CENTER_ID) {
      const tgt = nodeById.get(edge.target);
      if (!tgt) return edge;
      const dx = tgt.position.x + (tgt.width ?? ORG_OVERVIEW_TEAM_WIDTH) / 2 - orgCX;
      const dy = tgt.position.y + (tgt.height ?? ORG_OVERVIEW_TEAM_HEIGHT) / 2 - orgCY;
      const { sourceHandle, targetHandle } = getOrgToSatelliteHandles(dx, dy);
      return { ...edge, sourceHandle, targetHandle };
    }
    if (edge.source.startsWith('team-') && edge.target.startsWith('project-')) {
      const src = nodeById.get(edge.source);
      const tgt = nodeById.get(edge.target);
      if (!src || !tgt) return edge;
      const dx = (tgt.position.x + (tgt.width ?? OVERVIEW_PROJECT_NODE_WIDTH) / 2) - (src.position.x + (src.width ?? ORG_OVERVIEW_TEAM_WIDTH) / 2);
      const dy = (tgt.position.y + (tgt.height ?? OVERVIEW_PROJECT_NODE_HEIGHT) / 2) - (src.position.y + (src.height ?? ORG_OVERVIEW_TEAM_HEIGHT) / 2);
      const { sourceHandle, targetHandle } = getTeamProjectHandles(Math.atan2(dy, dx));
      return { ...edge, sourceHandle, targetHandle };
    }
    return edge;
  });
}

export default function OrganizationOverviewPage() {
  const { id: orgId } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const myAvatarUrl = getAvatarUrl(user);
  const myFullName = getDisplayNameOrNull(user);
  const { toast } = useToast();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [teamsById, setTeamsById] = useState<Record<string, Team>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [orgSidebarOpen, setOrgSidebarOpen] = useState(false);
  const [orgSidebarVisible, setOrgSidebarVisible] = useState(false);
  const [orgSidebarSecuritySummary, setOrgSidebarSecuritySummary] = useState<ProjectSecuritySummary[]>([]);
  const [orgSidebarProjects, setOrgSidebarProjects] = useState<Project[]>([]);
  // Flat copy of the org's projects from the graph load — lets the org sidebar seed
  // instantly from memory instead of waiting on a fresh getProjects round-trip.
  const [allProjectsFlat, setAllProjectsFlat] = useState<Project[]>([]);
  const [orgSidebarLoading, setOrgSidebarLoading] = useState(false);
  const [orgSidebarError, setOrgSidebarError] = useState(false);
  const [orgSidebarRefetch, setOrgSidebarRefetch] = useState(0);
  const [teamSidebarOpen, setTeamSidebarOpen] = useState(false);
  const [teamSidebarVisible, setTeamSidebarVisible] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [selectedTeamName, setSelectedTeamName] = useState<string | null>(null);
  const [projectSidebarOpen, setProjectSidebarOpen] = useState(false);
  const [projectSidebarVisible, setProjectSidebarVisible] = useState(false);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [trackerLinks, setTrackerLinks] = useState<FindingTrackerLink[]>([]);
  const [groupSuppressions, setGroupSuppressions] = useState<FindingGroupSuppression[]>([]);
  const [acknowledgements, setAcknowledgements] = useState<FindingAcknowledgement[]>([]);
  const [selectedProjectName, setSelectedProjectName] = useState<string | null>(null);
  const [selectedProjectFramework, setSelectedProjectFramework] = useState<string | null>(null);
  const [selectedProjectIsExtracting, setSelectedProjectIsExtracting] = useState(false);
  const [selectedProjectIsInitialExtracting, setSelectedProjectIsInitialExtracting] = useState(false);
  const [projectStats, setProjectStats] = useState<ProjectStats | null>(null);
  const [projectStatsLoading, setProjectStatsLoading] = useState(false);
  const [projectVulnerabilities, setProjectVulnerabilities] = useState<ProjectVulnerability[] | null>(null);
  const [projectSecrets, setProjectSecrets] = useState<SecretFinding[]>([]);
  const [projectSemgrep, setProjectSemgrep] = useState<SemgrepFinding[]>([]);
  // The rest of the unified findings table: IaC misconfigs, container CVEs,
  // malicious packages, and DAST runtime findings — fetched resiliently so one
  // failing scanner endpoint never blanks the others (same pattern as the full
  // org findings page).
  const [projectIacFindings, setProjectIacFindings] = useState<IaCFinding[]>([]);
  const [projectContainerFindings, setProjectContainerFindings] = useState<ContainerFinding[]>([]);
  const [projectBaseImageRecs, setProjectBaseImageRecs] = useState<BaseImageRecommendation[]>([]);
  const [projectMaliciousFindings, setProjectMaliciousFindings] = useState<MaliciousFinding[]>([]);
  const [projectDastFindings, setProjectDastFindings] = useState<DastFindingDTO[]>([]);
  const [projectCodeFlows, setProjectCodeFlows] = useState<DataFlowFinding[]>([]);
  const [expandedProjectVulnRowId, setExpandedProjectVulnRowId] = useState<string | null>(null);
  const [projectVulnDetailByRowId, setProjectVulnDetailByRowId] = useState<Record<string, { loading: boolean; error: string | null; data: VulnerabilityDetail | null }>>({});
  const [projectSidebarTab, setProjectSidebarTab] = useState<'findings' | 'dependencies' | 'compliance' | 'settings'>('findings');
  // osv_id to deep-open in the Findings tab — set when a finding is clicked from
  // the dependencies supply-chain table; consumed by VulnerabilityExpandableTable.
  const [projectFindingToOpen, setProjectFindingToOpen] = useState<string | null>(null);
  const [projectSidebarProject, setProjectSidebarProject] = useState<ProjectWithRole | null>(null);
  const [projectSidebarOrganization, setProjectSidebarOrganization] = useState<Organization | null>(null);
  const [projectSidebarProjectLoading, setProjectSidebarProjectLoading] = useState(false);
  const [statuses, setStatuses] = useState<OrganizationStatus[]>([]);
  const [rawTeamsWithProjects, setRawTeamsWithProjects] = useState<OverviewTeamWithProjects[]>([]);
  // Per-project depscore-band counts (phase48 security-summary RPC) — drives the mini
  // SeverityPills under each project tile. Keyed by project id.
  const [securitySummaryByProject, setSecuritySummaryByProject] = useState<Map<string, ProjectSecuritySummary>>(new Map());
  const [graphRefreshTrigger, setGraphRefreshTrigger] = useState(0);
  const [silentRefreshTrigger, setSilentRefreshTrigger] = useState(0);
  const [expandingProjectId, setExpandingProjectId] = useState<string | null>(null);
  const [expandedProjectId, setExpandedProjectId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Node[]>([]);
  const [expandedEdges, setExpandedEdges] = useState<Edge[]>([]);
  const graphNodesRef = useRef<Node[]>([]);
  const rawTeamsWithProjectsRef = useRef<OverviewTeamWithProjects[]>([]);
  const [teamSidebarStats, setTeamSidebarStats] = useState<TeamStats | null>(null);
  const [teamSidebarMembers, setTeamSidebarMembers] = useState<TeamMember[]>([]);
  const [teamSidebarProjects, setTeamSidebarProjects] = useState<Project[]>([]);
  const [teamSidebarSecuritySummary, setTeamSidebarSecuritySummary] = useState<ProjectSecuritySummary[]>([]);
  // The team Findings tab loads ALL finding types across every project in the team
  // (fanned out per-project, identical to the project Findings tab) so the team view
  // is exactly the union of its projects' findings — same collapses, same triage.
  const [teamSidebarFindingRows, setTeamSidebarFindingRows] = useState<SecurityTableRow[]>([]);
  const [teamSidebarBaseImageRecs, setTeamSidebarBaseImageRecs] = useState<BaseImageRecommendation[]>([]);
  const [teamSidebarFindingsLoading, setTeamSidebarFindingsLoading] = useState(false);
  // Surface load failures — a blank list with no error reads as "no findings", which is a lie.
  const [teamSidebarFindingsError, setTeamSidebarFindingsError] = useState(false);
  const [teamSidebarOrgMembers, setTeamSidebarOrgMembers] = useState<OrganizationMember[]>([]);
  const [teamSidebarRoles, setTeamSidebarRoles] = useState<TeamRole[]>([]);
  const [teamSidebarDataLoading, setTeamSidebarDataLoading] = useState(false);
  // Error triple mirroring the org sidebar (orgSidebarError/Msg/Refetch) — the eager team load
  // previously swallowed failures into empty state, which reads as "team has no data".
  const [teamSidebarError, setTeamSidebarError] = useState(false);
  const [teamSidebarRefetch, setTeamSidebarRefetch] = useState(0);
  const [teamSidebarAddingMember, setTeamSidebarAddingMember] = useState(false);
  const [teamSidebarAddMemberOpen, setTeamSidebarAddMemberOpen] = useState(false);
  const [addMemberSearchQuery, setAddMemberSearchQuery] = useState('');
  const [addMemberSelectedUserIds, setAddMemberSelectedUserIds] = useState<string[]>([]);
  const [addMemberSelectedRoleId, setAddMemberSelectedRoleId] = useState<string>('member');
  const [addMemberAdding, setAddMemberAdding] = useState(false);
  const [syncDetailProjectId, setSyncDetailProjectId] = useState<string | null>(null);
  const [teamSidebarTab, setTeamSidebarTab] = useState<'projects' | 'findings' | 'members' | 'settings'>('findings');
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
  const [teamSettingsSubTab, setTeamSettingsSubTab] = useState<'general' | 'roles'>('general');
  const [teamSettingsName, setTeamSettingsName] = useState('');
  const [teamSettingsSaving, setTeamSettingsSaving] = useState(false);
  const [teamSettingsShowDeleteConfirm, setTeamSettingsShowDeleteConfirm] = useState(false);
  const [teamSettingsDeleteConfirmText, setTeamSettingsDeleteConfirmText] = useState('');
  const [teamSettingsDeleting, setTeamSettingsDeleting] = useState(false);
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
  const [teamSettingsDraggedRoleId, setTeamSettingsDraggedRoleId] = useState<string | null>(null);
  const [teamSettingsDragPreviewRoles, setTeamSettingsDragPreviewRoles] = useState<TeamRole[] | null>(null);
  const reactFlowInstanceRef = useRef<{
    fitView: (opts?: { nodes?: { id: string }[]; duration?: number; padding?: number; maxZoom?: number }) => void;
    zoomIn: (opts?: { duration?: number }) => void;
    zoomOut: (opts?: { duration?: number }) => void;
    getViewport: () => { x: number; y: number; zoom: number };
    setViewport: (viewport: { x: number; y: number; zoom: number }, options?: { duration?: number }) => void;
    getNode: (id: string) => Node | undefined;
  } | null>(null);
  const reactFlowPaneRef = useRef<HTMLDivElement | null>(null);
  const focusedNodeIdRef = useRef<string | null>(null);
  const sidebarSwitchingRef = useRef(false);

  // Real-time extraction status for the currently selected project (more accurate than graph node snapshot)
  const selectedProjectRealtime = useRealtimeStatus(orgId, selectedProjectId ?? undefined);
  const selectedProjectEffectiveIsExtracting =
    isExtractionOngoing(selectedProjectRealtime.status, selectedProjectRealtime.extractionStep)
    || (selectedProjectRealtime.isLoading && selectedProjectIsExtracting);
  // Only block sidebar UI (show ExtractionProgressCard) for first-ever extraction
  const selectedProjectEffectiveIsInitialExtracting =
    isInitialExtraction(selectedProjectRealtime.status, selectedProjectRealtime.extractionStep, selectedProjectRealtime.lastExtractedAt)
    || (selectedProjectRealtime.isLoading && selectedProjectIsInitialExtracting);
  // Show error card when extraction failed and there's no prior successful extraction to fall back on
  const selectedProjectExtractionFailed =
    selectedProjectRealtime.status === 'error' &&
    !selectedProjectRealtime.isLoading &&
    !selectedProjectRealtime.lastExtractedAt;

  // Sync the graph node for the selected project directly from selectedProjectRealtime.
  // This guarantees the node updates in lockstep with the sidebar without relying on a
  // separate Realtime subscription (which has timing/setup race conditions).
  useEffect(() => {
    if (!selectedProjectId || selectedProjectRealtime.isLoading) return;
    const pid = selectedProjectId;
    const repoStatus = selectedProjectRealtime.status;
    const extractionStep = selectedProjectRealtime.extractionStep;
    const lastExtractedAt = selectedProjectRealtime.lastExtractedAt;
    const isExtract = isExtractionOngoing(repoStatus || '', extractionStep);
    const isInitialExtract = isInitialExtraction(repoStatus || '', extractionStep, lastExtractedAt);
    const isFailed = repoStatus === 'error' && !lastExtractedAt;
    setRawTeamsWithProjects((prev) =>
      prev.map((t) => ({
        ...t,
        projects: t.projects.map((p) =>
          p.projectId === pid
            ? { ...p, isExtracting: isExtract, isInitialExtracting: isInitialExtract, isInitialExtractionFailed: isFailed }
            : p,
        ),
      })),
    );
  }, [selectedProjectId, selectedProjectRealtime.status, selectedProjectRealtime.extractionStep, selectedProjectRealtime.lastExtractedAt, selectedProjectRealtime.isLoading]);

  // Reset the "syncing" spinner flags once Realtime confirms extraction is no longer in progress.
  // This handles both: (a) initial node click sets isExtracting=true from stale node data,
  // and (b) manual sync button click that was never cleared.
  useEffect(() => {
    if (selectedProjectRealtime.isLoading) return;
    if (!isExtractionOngoing(selectedProjectRealtime.status, selectedProjectRealtime.extractionStep)) {
      setSelectedProjectIsExtracting(false);
      setSelectedProjectIsInitialExtracting(false);
    }
  }, [selectedProjectRealtime.status, selectedProjectRealtime.extractionStep, selectedProjectRealtime.isLoading]);

  // Reload project (status badge etc.) when extraction finishes
  const prevExtractingRef = useRef(false);
  useEffect(() => {
    const nowExtracting = selectedProjectEffectiveIsExtracting;
    if (prevExtractingRef.current && !nowExtracting && orgId && selectedProjectId) {
      api.getProject(orgId, selectedProjectId).then(setProjectSidebarProject).catch(() => {});
    }
    prevExtractingRef.current = nowExtracting;
  }, [selectedProjectEffectiveIsExtracting, orgId, selectedProjectId]);

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
      // Legacy `tab=issues` URLs fail validation and fall back to 'findings' — its successor.
      const validTeamTabs = new Set(['projects', 'findings', 'members', 'settings']);
      const tab = (tabRaw && validTeamTabs.has(tabRaw) ? tabRaw : 'findings') as 'projects' | 'findings' | 'members' | 'settings';
      const subtabRaw = searchParams.get('subtab');
      const validTeamSubtabs = new Set(['general', 'roles']);
      const subtab = (subtabRaw && validTeamSubtabs.has(subtabRaw) ? subtabRaw : 'general') as 'general' | 'roles';
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
      // Accept the legacy 'vulnerabilities' tab key as an alias for 'findings' so
      // old bookmarked URLs still resolve to the right tab.
      const validProjectTabs = new Set(['findings', 'dependencies', 'settings']); // 'compliance' parked for MVP
      const tabResolved = tabRaw === 'vulnerabilities' ? 'findings' : tabRaw;
      const tab = (tabResolved && validProjectTabs.has(tabResolved) ? tabResolved : 'findings') as 'findings' | 'dependencies' | 'compliance' | 'settings';
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

    // When switching to another sidebar, skip the close→full-screen recenter (the incoming
    // sidebar's own effect recenters). Lets the org sidebar animate out without a viewport fight.
    if (!orgSidebarVisible && sidebarSwitchingRef.current) return;

    const nodeId = focusedNodeIdRef.current;
    if (!nodeId) return;

    const node = instance.getNode(nodeId);
    if (!node) return;

    // Get the node's center position in flow coordinates (org hub uses compact org slot size)
    const nodeWidth =
      nodeId === ORG_CENTER_ID ? ORG_OVERVIEW_ORG_WIDTH : 400;
    const nodeHeight = nodeId === ORG_CENTER_ID ? ORG_OVERVIEW_ORG_HEIGHT : 300;
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

    // Skip the close animation when we're switching to a different team/sidebar
    if (!teamSidebarVisible && sidebarSwitchingRef.current) return;

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

    // Skip the close animation when switching to a different sidebar
    if (!projectSidebarVisible && sidebarSwitchingRef.current) return;

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
      const { id, name, owner_team_id, team_ids, framework } = (e as CustomEvent).detail as { id: string; name: string; owner_team_id: string | null; team_ids: string[]; framework: string | null };
      const targetTeamId = owner_team_id ?? (team_ids?.[0] ?? null) ?? UNGROUPED_TEAM_ID;
      const newProj: OverviewTeamWithProjects['projects'][number] = {
        projectId: id,
        projectName: name,
        framework: framework ?? null,
        statusName: null,
        statusColor: null,
        statusId: null,
        importance: null,
        isExtracting: true,
        isInitialExtracting: true,
        healthScore: null,
      };
      setRawTeamsWithProjects((prev) => {
        const targetExists = prev.some((t) => t.teamId === targetTeamId);
        if (targetExists) {
          return prev.map((t) =>
            t.teamId === targetTeamId
              ? { ...t, projects: [...t.projects, newProj], projectCount: (t.projectCount ?? 0) + 1 }
              : t
          );
        }
        // If team not yet in graph, add to ungrouped
        return prev.map((t) =>
          t.teamId === UNGROUPED_TEAM_ID
            ? { ...t, projects: [...t.projects, newProj], projectCount: (t.projectCount ?? 0) + 1 }
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

  // Subscribe to project_repositories changes via Supabase Realtime for each extracting project.
  // Triggers a silent graph refresh when any extraction finishes — picks up framework icons and status.
  const hasExtractingProjects = useMemo(
    () => rawTeamsWithProjects.some((t) => t.projects.some((p) => p.isExtracting || p.isInitialExtracting)),
    [rawTeamsWithProjects],
  );
  useEffect(() => {
    if (!hasExtractingProjects || !organization?.id) return;
    const extractingIds = rawTeamsWithProjects
      .flatMap((t) => t.projects)
      .filter((p) => p.isExtracting || p.isInitialExtracting)
      .map((p) => p.projectId);
    if (extractingIds.length === 0) return;
    const channels = extractingIds.map((pid) =>
      supabase
        .channel(`graph-extract-${pid}`)
        .on(
          'postgres_changes',
          { event: 'UPDATE', schema: 'public', table: 'project_repositories', filter: `project_id=eq.${pid}` },
          (payload) => {
            const row = payload.new as any;
            const repoStatus = row.status ?? null;
            const extractionStep = row.extraction_step ?? null;
            const lastExtractedAt = row.last_extracted_at ?? null;
            const isExtract = isExtractionOngoing(repoStatus || '', extractionStep);
            const isInitialExtract = isInitialExtraction(repoStatus || '', extractionStep, lastExtractedAt);
            const isFailed = repoStatus === 'error' && !lastExtractedAt;
            // Directly patch the project state — no API call, instant like useRealtimeStatus
            setRawTeamsWithProjects((prev) =>
              prev.map((t) => ({
                ...t,
                projects: t.projects.map((p) =>
                  p.projectId === pid
                    ? { ...p, isExtracting: isExtract, isInitialExtracting: isInitialExtract, isInitialExtractionFailed: isFailed }
                    : p,
                ),
              })),
            );
            // For terminal states, also do a full refresh to pick up health score, status badge, etc.
            if (repoStatus === 'ready' || repoStatus === 'error') {
              setSilentRefreshTrigger((t) => t + 1);
            }
          },
        )
        .subscribe(),
    );
    return () => { channels.forEach((c) => supabase.removeChannel(c)); };
    // rawTeamsWithProjects intentionally excluded — subscribe once when extraction starts, clean up when done
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasExtractingProjects, organization?.id]);

  useEffect(() => {
    if (!organization?.id) return;

    const orgId = organization.id;
    let cancelled = false;

    // Process a bundle (cached or fresh) into all the overview state. Same logic the
    // four separate mount fetches used to drive, fed from one payload so it can also
    // run synchronously on the cached bundle for an instant repeat-visit paint.
    const processBundle = (bundle: OverviewBundle) => {
        if (cancelled) return;
        const teams = (bundle.teams ?? []) as TeamWithRole[];
        const allProjects = (bundle.projects ?? []) as Project[];
        setAllProjectsFlat(allProjects as Project[]);
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
            const extractionStep = (p as Project).extraction_step ?? null;
            const lastExtractedAt = (p as Project).last_extracted_at ?? null;
            const isExtracting = isExtractionOngoing(repoStatus || '', extractionStep);
            byTeam.get(bucket)!.push({
              projectId: p.id,
              projectName: p.name,
              framework: p.framework ?? null,
              statusName: p.status_name ?? null,
              statusColor: p.status_color ?? null,
              statusId: p.status_id ?? null,
              importance: typeof p.importance === 'number' ? p.importance : null,
              isExtracting,
              isInitialExtracting: isInitialExtraction(repoStatus || '', extractionStep, lastExtractedAt),
              isInitialExtractionFailed: repoStatus === 'error' && !lastExtractedAt,
              healthScore: typeof (p as Project).health_score === 'number' ? (p as Project).health_score : null,
              dependenciesCount: (p as Project).direct_dependencies_count ?? null,
              canvasPositionX: p.canvas_position_x ?? null,
              canvasPositionY: p.canvas_position_y ?? null,
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
              canvasPositionX: teamMeta?.canvas_position_x ?? null,
              canvasPositionY: teamMeta?.canvas_position_y ?? null,
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

        // Decoration: org statuses + per-project security summary (band pills).
        setStatuses((bundle.statuses ?? []) as OrganizationStatus[]);
        const summaryProjects = bundle.securitySummary?.projects;
        if (summaryProjects) {
          setSecuritySummaryByProject(new Map(summaryProjects.map((x) => [x.project_id, x])));
        }
    };

    // Stale-while-revalidate: paint the last-known bundle instantly (zero network),
    // then refresh in the background and reconcile. The overview is the app's front
    // door, so a repeat visit should never sit behind a spinner.
    const cached = readOverviewCache(orgId);
    if (cached) {
      processBundle(cached.data);
      setError(null);
      setLoading(false);
    } else {
      setLoading(true);
      setError(null);
      // No cache → wipe any previous org's nodes so the skeleton shows instead of
      // briefly rendering another org's stale graph.
      setRawTeamsWithProjects([]);
      setTeamsById({});
      setSecuritySummaryByProject(new Map());
    }

    api.getOrgOverview(orgId)
      .then((bundle) => {
        if (cancelled) return;
        processBundle(bundle);
        writeOverviewCache(orgId, bundle);
      })
      .catch((err) => {
        // A failed revalidate behind a good cached paint is silent; only surface an
        // error when there was nothing to show.
        if (!cancelled && !cached) setError(err?.message ?? 'Failed to load data');
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
    api.getOrgOverview(orgId)
      .then((bundle) => {
        if (cancelled) return;
        // Keep the SWR cache warm so the next mount paints this fresh state instantly.
        writeOverviewCache(orgId, bundle);
        const teams = bundle.teams ?? [];
        const allProjects = bundle.projects ?? [];
        const statusesData = bundle.statuses ?? [];
        const securitySummary = bundle.securitySummary;
        setStatuses((statusesData as OrganizationStatus[]) ?? []);
        setAllProjectsFlat(allProjects as Project[]);
        if (securitySummary?.projects) {
          setSecuritySummaryByProject(new Map(securitySummary.projects.map((s) => [s.project_id, s])));
        }
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
            const extractionStep = p.extraction_step ?? null;
            const lastExtractedAt = p.last_extracted_at ?? null;
            const isExtracting = isExtractionOngoing(repoStatus || '', extractionStep);
            byTeam.get(bucket)!.push({
              projectId: p.id, projectName: p.name, framework: p.framework ?? null,
              statusName: p.status_name ?? null, statusColor: p.status_color ?? null, statusId: p.status_id ?? null,
              importance: typeof p.importance === 'number' ? p.importance : null,
              isExtracting, isInitialExtracting: isInitialExtraction(repoStatus || '', extractionStep, lastExtractedAt),
              isInitialExtractionFailed: repoStatus === 'error' && !lastExtractedAt,
              healthScore: typeof p.health_score === 'number' ? p.health_score : null,
              dependenciesCount: p.direct_dependencies_count ?? null,
              canvasPositionX: p.canvas_position_x ?? null,
              canvasPositionY: p.canvas_position_y ?? null,
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
            canvasPositionX: teamMeta?.canvas_position_x ?? null,
            canvasPositionY: teamMeta?.canvas_position_y ?? null,
          };
        });
        // Preserve the existing project order within each team to avoid nodes jumping around.
        // Updated data is applied in-place; new projects (from API but not in graph yet) are appended.
        setRawTeamsWithProjects((prev) => {
          const prevTeamMap = new Map(prev.map((t) => [t.teamId, t]));
          return result.map((newTeam) => {
            const prevTeam = prevTeamMap.get(newTeam.teamId);
            if (!prevTeam) return newTeam;
            const newProjectMap = new Map(newTeam.projects.map((p) => [p.projectId, p]));
            const prevIds = new Set(prevTeam.projects.map((p) => p.projectId));
            const ordered = [
              // Existing projects in their original order, with fresh data applied —
              // but keep the locally-known canvas position when the fresh fetch has
              // none yet: a drag-save still in flight returns NULL until it commits,
              // and we mustn't let that NULL snap the node back to the spawn point.
              ...prevTeam.projects.filter((p) => newProjectMap.has(p.projectId)).map((p) => {
                const fresh = newProjectMap.get(p.projectId)!;
                return {
                  ...fresh,
                  canvasPositionX: fresh.canvasPositionX ?? p.canvasPositionX ?? null,
                  canvasPositionY: fresh.canvasPositionY ?? p.canvasPositionY ?? null,
                };
              }),
              // New projects from API not yet in the graph
              ...newTeam.projects.filter((p) => !prevIds.has(p.projectId)),
            ];
            // Same coalesce for the team's own node position — a NULL from a racing
            // refresh must not clobber a just-dragged (in-flight) position.
            return {
              ...newTeam,
              canvasPositionX: newTeam.canvasPositionX ?? prevTeam.canvasPositionX ?? null,
              canvasPositionY: newTeam.canvasPositionY ?? prevTeam.canvasPositionY ?? null,
              projects: ordered,
            };
          });
        });
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [organization?.id, silentRefreshTrigger]);

  // The status-filter dropdown was removed (no compliant/non-compliant statuses yet) — the graph
  // renders the unfiltered team/project list directly.
  const teamsWithProjects = rawTeamsWithProjects;
  // Graph copy with depscore-band counts merged in — project tiles render mini SeverityPills
  // once the security summary lands (undefined bandCounts = no pills, not fake zeros).
  const teamsWithProjectsForGraph = useMemo(() => {
    if (securitySummaryByProject.size === 0) return teamsWithProjects;
    return teamsWithProjects.map((t) => ({
      ...t,
      projects: t.projects.map((p) => {
        const s = securitySummaryByProject.get(p.projectId);
        if (!s) return p;
        return {
          ...p,
          bandCounts: {
            critical: s.band_critical ?? 0,
            high: s.band_high ?? 0,
            medium: s.band_medium ?? 0,
            low: s.band_low ?? 0,
          },
        };
      }),
    }));
  }, [teamsWithProjects, securitySummaryByProject]);

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

  const canvasIdentity = useMemo<LocalIdentity | null>(() => {
    if (!user) return null;
    const stockAvatar = myAvatarUrl && !myAvatarUrl.endsWith('/images/blank_profile_image.png')
      ? myAvatarUrl
      : null;
    return {
      userId: user.id,
      name: myFullName ?? user.email?.split('@')[0] ?? 'You',
      avatarUrl: stockAvatar,
      role: organization?.role ?? null,
      roleLabel: orgRoleLabel,
      roleColor: orgRoleColor,
    };
  }, [user, myAvatarUrl, myFullName, organization?.role, orgRoleLabel, orgRoleColor]);

  // userId -> the id of the node that user is currently dragging.
  // Populated on drag-start, cleared on drag-stop. Used to hide their cursor
  // floating and anchor it to the dragged node instead.
  const [remoteDraggers, setRemoteDraggers] = useState<Record<string, string>>({});
  // Mirror of remoteDraggers as a ref so drag-stop can verify the claimed
  // nodeId without depending on remoteDraggers in its callback deps.
  const remoteDraggersRef = useRef<Record<string, string>>({});
  remoteDraggersRef.current = remoteDraggers;

  const tagNodeClass = useCallback(
    (nodeIds: Set<string>, cls: string, add: boolean) => {
      setGraphNodes((nodes) =>
        nodes.map((n) => {
          if (!nodeIds.has(n.id)) return n;
          const existing = (n.className ?? '').split(' ').filter(Boolean);
          const has = existing.includes(cls);
          if (add && !has) return { ...n, className: [...existing, cls].join(' ') };
          if (!add && has) {
            const stripped = existing.filter((c) => c !== cls).join(' ');
            return { ...n, className: stripped || undefined };
          }
          return n;
        }),
      );
    },
    [setGraphNodes],
  );

  // Track last-seen timestamp per remote dragger so we can auto-clear
  // stale entries if drag-stop never arrives (e.g. sender crashed).
  const dragHeartbeatRef = useRef<Record<string, number>>({});
  // Always-current snapshot of cursor-visibility prefs; read inside drag callbacks
  // without needing them in the deps arrays (avoids re-registering the channel hook).
  const cursorVisibleRef = useRef({ showOthers: true, orgEnabled: false });

  const handleRemoteDragStart = useCallback((msg: RemoteDragStartMessage) => {
    const draggerId = msg.sessionId || msg.userId;
    dragHeartbeatRef.current[draggerId] = Date.now();
    setRemoteDraggers((prev) => ({ ...prev, [draggerId]: msg.nodeId }));
    const { showOthers, orgEnabled } = cursorVisibleRef.current;
    if (showOthers && orgEnabled) {
      // canDrag: false means sender lacks manage_teams_and_projects — drag won't persist.
      // Show a faint amber ghost ring instead of the full white "claimed" ring.
      const cls = msg.canDrag === false ? 'remote-ghost-drag' : 'remote-dragging';
      tagNodeClass(new Set([msg.nodeId]), cls, true);
      if (msg.nodeId.startsWith('team-')) {
        const teamId = msg.nodeId.slice('team-'.length);
        const team = rawTeamsWithProjectsRef.current.find((t) => t.teamId === teamId);
        const childIds = (team?.projects ?? []).map((p) => `project-${p.projectId}`);
        if (childIds.length > 0) tagNodeClass(new Set(childIds), 'remote-drag-child', true);
      }
    }
  }, [tagNodeClass]);

  const handleRemoteDragMove = useCallback((msg: RemoteDragMoveMessage) => {
    dragHeartbeatRef.current[msg.sessionId || msg.userId] = Date.now();
    if (!Array.isArray(msg.moves) || msg.moves.length === 0) return;
    // Drop malformed entries (missing/empty nodeId, non-finite coords) so a
    // broken or hostile sender can't flick nodes off-screen or into NaN-land.
    const validMoves = msg.moves.filter(
      (m) =>
        typeof m?.nodeId === 'string' &&
        m.nodeId.length > 0 &&
        typeof m.x === 'number' &&
        Number.isFinite(m.x) &&
        typeof m.y === 'number' &&
        Number.isFinite(m.y),
    );
    if (validMoves.length === 0) return;
    const byId = new Map(validMoves.map((m) => [m.nodeId, m]));
    // Apply position updates and recompute edge face routing.
    // Uses simple face handles (top/right/bottom/left) which always exist — no slot-fan sync needed.
    const updatedNodes = graphNodesRef.current.map((n) => {
      const m = byId.get(n.id);
      return m ? { ...n, position: { x: m.x, y: m.y } } : n;
    });
    setGraphNodes(updatedNodes);
    setGraphEdges(recomputeOrgCanvasLayout(graphEdgesRef.current, updatedNodes));
  }, [setGraphNodes, setGraphEdges]);

  const handleRemoteDragStop = useCallback((msg: RemoteDragStopMessage) => {
    // Recompute edge routing unconditionally — covers the case where drag-start was
    // missed (channel gap) but drag-move messages already updated node positions.
    setGraphEdges(recomputeOrgCanvasLayout(graphEdgesRef.current, graphNodesRef.current));

    const draggerId = msg.sessionId || msg.userId;
    // Guard: verify the stop is for the node this dragger claimed. Out-of-order or
    // hostile messages must not clear an unrelated drag ring.
    const claimed = remoteDraggersRef.current[draggerId];
    if (!claimed || claimed !== msg.nodeId) return;
    delete dragHeartbeatRef.current[draggerId];
    setRemoteDraggers((prev) => {
      if (!(draggerId in prev)) return prev;
      const next = { ...prev };
      delete next[draggerId];
      return next;
    });
    // Remove both possible drag classes — whichever was applied on start.
    tagNodeClass(new Set([msg.nodeId]), 'remote-dragging', false);
    tagNodeClass(new Set([msg.nodeId]), 'remote-ghost-drag', false);
    if (msg.nodeId.startsWith('team-')) {
      const teamId = msg.nodeId.slice('team-'.length);
      const team = rawTeamsWithProjectsRef.current.find((t) => t.teamId === teamId);
      const childIds = (team?.projects ?? []).map((p) => `project-${p.projectId}`);
      if (childIds.length > 0) tagNodeClass(new Set(childIds), 'remote-drag-child', false);
    }
  }, [tagNodeClass, setGraphEdges]);

  // Sweep: if a remote drag hasn't heartbeated in 5s, synthesize a stop.
  // Covers the sender crashing / tab closing mid-drag so nodes don't get
  // stuck visually "picked up".
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      const stale: Array<{ draggerId: string; nodeId: string }> = [];
      for (const [draggerId, nodeId] of Object.entries(remoteDraggers)) {
        const ts = dragHeartbeatRef.current[draggerId];
        if (!ts || now - ts > 5000) stale.push({ draggerId, nodeId });
      }
      for (const s of stale) {
        // Pass draggerId as both sessionId and userId so handleRemoteDragStop
        // resolves the same key regardless of whether it's a sessionId or userId.
        handleRemoteDragStop({ userId: s.draggerId, sessionId: s.draggerId, nodeId: s.nodeId, seq: 0 });
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [remoteDraggers, handleRemoteDragStop]);

  const readBoolPref = (key: string, fallback: boolean) => {
    try {
      const raw = localStorage.getItem(key);
      return raw === null ? fallback : raw === '1';
    } catch { return fallback; }
  };
  const [showOthersCursors, setShowOthersCursors] = useState<boolean>(
    () => readBoolPref('org-canvas:cursors-show-others', true),
  );
  const [broadcastOwnCursor, setBroadcastOwnCursor] = useState<boolean>(
    () => readBoolPref('org-canvas:cursors-broadcast-own', true),
  );
  const persistShowOthers = useCallback((next: boolean) => {
    setShowOthersCursors(next);
    try { localStorage.setItem('org-canvas:cursors-show-others', next ? '1' : '0'); } catch { /* ignore */ }
  }, []);
  const persistBroadcastOwn = useCallback((next: boolean) => {
    setBroadcastOwnCursor(next);
    try { localStorage.setItem('org-canvas:cursors-broadcast-own', next ? '1' : '0'); } catch { /* ignore */ }
  }, []);

  // Org-level cursor enable flag (owner-controlled).
  // Default false until org loads so we never broadcast before knowing the org's setting.
  const [canvasCursorsOrgEnabled, setCanvasCursorsOrgEnabled] = useState(false);
  useEffect(() => {
    if (organization) setCanvasCursorsOrgEnabled(organization.canvas_cursors_enabled ?? true);
  }, [organization?.canvas_cursors_enabled, organization]);

  // Keep cursor-visibility ref current every render so drag-start callbacks read fresh values.
  cursorVisibleRef.current = { showOthers: showOthersCursors, orgEnabled: canvasCursorsOrgEnabled };

  // Re-sync when the tab regains focus — covers the case where the owner toggled while we were offline/backgrounded
  // and we missed the realtime broadcast.
  useEffect(() => {
    if (!organization?.id) return;
    const handleVisible = () => {
      if (document.visibilityState !== 'visible') return;
      api.getOrganization(organization.id, false)
        .then((org) => setCanvasCursorsOrgEnabled(org.canvas_cursors_enabled ?? true))
        .catch(() => {});
    };
    document.addEventListener('visibilitychange', handleVisible);
    return () => document.removeEventListener('visibilitychange', handleVisible);
  }, [organization?.id]);

  const toggleOrgCursorsEnabled = useCallback(async (next: boolean) => {
    if (!organization?.id) return;
    setCanvasCursorsOrgEnabled(next);
    canvasChannelRef.current.sendOrgSettings(next);
    try {
      await api.updateCanvasSettings(organization.id, { canvas_cursors_enabled: next });
    } catch { setCanvasCursorsOrgEnabled(!next); }
  }, [organization?.id]);

  // Actual team memberships for the current user in this org. For non-admins
  // this equals visibleTeamIds (the API only returns their teams), but for
  // admins we need the real subset so their cursor only broadcasts to
  // teams they're actually in (strict rule).
  const [myActualTeamIds, setMyActualTeamIds] = useState<string[]>([]);
  useEffect(() => {
    if (!organization?.id || !user?.id) return;
    let cancelled = false;
    supabase
      .from('team_members')
      .select('team_id, teams!inner(organization_id)')
      .eq('user_id', user.id)
      .eq('teams.organization_id', organization.id)
      .then(({ data }) => {
        if (cancelled) return;
        setMyActualTeamIds((data ?? []).map((r: any) => r.team_id));
      });
    return () => { cancelled = true; };
  }, [organization?.id, user?.id]);

  const canvasAccess = useMemo(() => {
    const isOrgAdmin = organization?.permissions?.manage_teams_and_projects === true
      || organization?.role === 'owner';
    const visibleTeamIds = rawTeamsWithProjects
      .map((t) => t.teamId)
      .filter((id) => id !== UNGROUPED_TEAM_ID);
    const projectTeamMap: Record<string, string> = {};
    for (const t of rawTeamsWithProjects) {
      if (t.teamId === UNGROUPED_TEAM_ID) continue;
      for (const p of t.projects) projectTeamMap[p.projectId] = t.teamId;
    }
    return { visibleTeamIds, myActualTeamIds, isOrgAdmin, projectTeamMap };
  }, [
    organization?.permissions?.manage_teams_and_projects,
    organization?.role,
    rawTeamsWithProjects,
    myActualTeamIds,
  ]);

  // Hook is always on so drag sync works regardless of cursor visibility.
  // The toggle only controls whether the OrgCanvasCursors layer renders —
  // which in turn is what tracks local pointer + paints remote cursors.
  const canvasChannel = useOrgCanvasCursors(organization?.id, canvasIdentity, canvasAccess, {
    onRemoteDragStart: handleRemoteDragStart,
    onRemoteDragMove: handleRemoteDragMove,
    onRemoteDragStop: handleRemoteDragStop,
    onOrgSettingsChange: setCanvasCursorsOrgEnabled,
  });
  const canvasChannelRef = useRef(canvasChannel);
  canvasChannelRef.current = canvasChannel;

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
      setTeamSidebarTab('findings');
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
      setTeamSettingsShowDeleteConfirm(false);
      setTeamSettingsDeleteConfirmText('');
      setTeamSettingsShowAddRoleSidepanel(false);
      setTeamSettingsAddRolePanelVisible(false);
      setTeamSettingsShowRoleSettingsModal(false);
      setTeamSettingsRoleSettingsPanelVisible(false);
    }, 150);
  }, [setSidebarParams]);

  const closeTeamSidebarAddMember = useCallback(() => {
    setTeamSidebarAddMemberOpen(false);
    setAddMemberSearchQuery('');
    setAddMemberSelectedUserIds([]);
    setAddMemberSelectedRoleId('member');
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
    } catch (err: any) {
      toast({ title: 'Error', description: err?.message || 'Failed to remove member', variant: 'destructive' });
    } finally {
      setTeamSidebarRemovingMember(false);
    }
  }, [orgId, selectedTeamId, teamSidebarMemberToRemove, user?.id, toast, closeTeamSidebar]);

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
      setProjectFindingToOpen(null);
    }, 150);
  }, [setSidebarParams]);

  /** From the dependencies supply-chain table: switch to the Findings tab and
   *  deep-open the clicked finding's card (one home for finding detail). */
  const handleOpenProjectFinding = useCallback((osvId: string) => {
    setProjectSidebarTab('findings');
    setSidebarParams({ tab: 'findings', subtab: null });
    setProjectFindingToOpen(osvId);
  }, [setSidebarParams]);

  /** Optimistic project rename: patch the new name into every store the graph + sidebar
   *  derive from (no refetch), so the node label and header update instantly — mirrors the
   *  team-rename in handleTeamSettingsSave. */
  const handleProjectRenamed = useCallback((newName: string) => {
    if (!selectedProjectId) return;
    setSelectedProjectName(newName);
    setProjectSidebarProject((prev) => (prev ? { ...prev, name: newName } : prev));
    setRawTeamsWithProjects((prev) =>
      prev.map((t) => ({
        ...t,
        projects: t.projects.map((p) =>
          p.projectId === selectedProjectId ? { ...p, projectName: newName } : p
        ),
      }))
    );
  }, [selectedProjectId]);

  /** Optimistic transfer — move the project node out of its current owner team and into
   *  the new one in the graph store (no refetch), so it relocates instantly. The sidebar's
   *  owner/contributing details reconcile via the background refetch in handleTransferProject. */
  const handleProjectTransferred = useCallback((newOwnerTeamId: string) => {
    if (!selectedProjectId) return;
    setRawTeamsWithProjects((prev) => {
      // Bail if the destination team isn't on the graph — a refresh will reconcile.
      if (!prev.some((t) => t.teamId === newOwnerTeamId)) return prev;
      const moved = prev.flatMap((t) => t.projects).find((p) => p.projectId === selectedProjectId);
      if (!moved) return prev;
      // Clear the stale canvas position so it re-spawns cleanly under the new team
      // rather than rendering at its old team's coordinates.
      const movedProject = { ...moved, canvasPositionX: null, canvasPositionY: null };
      return prev.map((t) => {
        if (t.teamId === newOwnerTeamId) {
          const projects = [...t.projects.filter((p) => p.projectId !== selectedProjectId), movedProject];
          return { ...t, projects, projectCount: projects.length };
        }
        if (t.projects.some((p) => p.projectId === selectedProjectId)) {
          const projects = t.projects.filter((p) => p.projectId !== selectedProjectId);
          return { ...t, projects, projectCount: projects.length };
        }
        return t;
      });
    });
  }, [selectedProjectId]);

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
    setTeamSidebarTab('findings');
    setTeamSidebarMembersSearch('');
    setTeamSidebarPermissions(null);
    setTeamSidebarTeamData(null);
    setTeamSidebarRoleChangeOpen(false);
    setTeamSidebarMemberToChangeRole(null);
    setTeamSidebarRemoveConfirmOpen(false);
    setTeamSidebarMemberToRemove(null);
    setTeamSettingsSubTab('general');
    setTeamSettingsName('');
    setTeamSettingsShowDeleteConfirm(false);
    setTeamSettingsDeleteConfirmText('');
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
    setSelectedProjectIsInitialExtracting(false);
    setProjectStats(null);
    setProjectVulnerabilities(null);
    setExpandedProjectVulnRowId(null);
    setProjectVulnDetailByRowId({});
    setProjectSidebarProject(null);
    setProjectSidebarOrganization(null);
    setProjectSettingsSubTab('general');
    setProjectFindingToOpen(null);
  }, []);

  /** Open the project sidebar for a project (e.g. clicked from team projects list). Closes all other sidebars. */
  const openProjectInSidebar = useCallback((project: Project) => {
    focusedNodeIdRef.current = `project-${project.id}`;
    const openProject = () => {
      setSelectedProjectId(project.id);
      setSelectedProjectName(project.name);
      setSelectedProjectFramework(project.framework ?? null);
      setSelectedProjectIsExtracting(false);
      setProjectStats(null);
      setProjectVulnerabilities(null);
      setProjectSidebarProject(null);
      setExpandedProjectVulnRowId(null);
      setProjectVulnDetailByRowId({});
      setProjectSidebarTab('findings');
      setProjectSettingsSubTab('general');
      setProjectFindingToOpen(null);
      setSidebarParams({ sidebar: 'project', projectId: project.id, tab: 'findings', subtab: null, teamId: null });
      setProjectSidebarOpen(true);
      requestAnimationFrame(() => setProjectSidebarVisible(true));
    };
    if (orgSidebarVisible) {
      sidebarSwitchingRef.current = true;
      setOrgSidebarVisible(false);
      setTimeout(() => {
        sidebarSwitchingRef.current = false;
        setOrgSidebarOpen(false);
        openProject();
      }, 150);
    } else if (teamSidebarVisible) {
      sidebarSwitchingRef.current = true;
      setTeamSidebarVisible(false);
      setTimeout(() => {
        sidebarSwitchingRef.current = false;
        setTeamSidebarOpen(false);
        setSelectedTeamId(null);
        setSelectedTeamName(null);
        openProject();
      }, 150);
    } else {
      closeOrgSidebarImmediate();
      closeTeamSidebarImmediate();
      openProject();
    }
  }, [closeOrgSidebarImmediate, closeTeamSidebarImmediate, orgSidebarVisible, teamSidebarVisible, setSidebarParams]);

  // Open a team/project panel in response to the sidebar search palette. The
  // palette also navigates with ?sidebar= params so a cross-page jump restores
  // on mount; this handles the case where the overview is already mounted (the
  // once-per-mount restore effect won't re-run on a same-page param change).
  useEffect(() => {
    const onOpenProject = (e: Event) => {
      const project = (e as CustomEvent).detail?.project as Project | undefined;
      if (project?.id) openProjectInSidebar(project);
    };
    const onOpenTeam = (e: Event) => {
      const detail = (e as CustomEvent).detail as { teamId?: string; teamName?: string } | undefined;
      const teamId = detail?.teamId;
      if (!teamId) return;
      closeOrgSidebarImmediate();
      closeProjectSidebarImmediate();
      setSelectedTeamId(teamId);
      setSelectedTeamName(detail?.teamName ?? teamsById[teamId]?.name ?? null);
      setTeamSidebarTab('findings');
      setTeamSettingsSubTab('general');
      setSidebarParams({ sidebar: 'team', teamId, tab: 'findings', subtab: null, projectId: null });
      setTeamSidebarOpen(true);
      requestAnimationFrame(() => setTeamSidebarVisible(true));
    };
    window.addEventListener('organization:openProject', onOpenProject as EventListener);
    window.addEventListener('organization:openTeam', onOpenTeam as EventListener);
    return () => {
      window.removeEventListener('organization:openProject', onOpenProject as EventListener);
      window.removeEventListener('organization:openTeam', onOpenTeam as EventListener);
    };
  }, [openProjectInSidebar, closeOrgSidebarImmediate, closeProjectSidebarImmediate, setSidebarParams, teamsById]);

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
          focusedNodeIdRef.current = node.id;
          const openNewTeam = () => {
            setSelectedTeamId(teamData.teamId!);
            setSelectedTeamName(teamData.teamName ?? null);
            setSidebarParams({ sidebar: 'team', teamId: teamData.teamId!, tab: 'findings', subtab: null, projectId: null });
            setTeamSidebarOpen(true);
            requestAnimationFrame(() => setTeamSidebarVisible(true));
          };
          // Animate close whichever sidebar is open, then open the team sidebar
          if (orgSidebarVisible) {
            sidebarSwitchingRef.current = true;
            setOrgSidebarVisible(false);
            setTimeout(() => {
              sidebarSwitchingRef.current = false;
              setOrgSidebarOpen(false);
              openNewTeam();
            }, 150);
          } else if (projectSidebarVisible) {
            sidebarSwitchingRef.current = true;
            setProjectSidebarVisible(false);
            setTimeout(() => {
              sidebarSwitchingRef.current = false;
              setProjectSidebarOpen(false);
              setSelectedProjectId(null);
              setSelectedProjectName(null);
              openNewTeam();
            }, 150);
          } else if (teamSidebarVisible && selectedTeamId && selectedTeamId !== teamData.teamId) {
            sidebarSwitchingRef.current = true;
            setTeamSidebarVisible(false);
            setTimeout(() => {
              sidebarSwitchingRef.current = false;
              setTeamSidebarOpen(false);
              openNewTeam();
            }, 150);
          } else {
            closeOrgSidebarImmediate();
            closeProjectSidebarImmediate();
            openNewTeam();
          }
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
        isInitialExtracting?: boolean;
      };
      if (d.projectId && d.isTeamNode) {
        focusedNodeIdRef.current = node.id;
        const openNewTeam = () => {
          setSelectedTeamId(d.projectId!);
          setSelectedTeamName((d.projectName as string) ?? null);
          setSidebarParams({ sidebar: 'team', teamId: d.projectId!, tab: 'findings', subtab: null, projectId: null });
          setTeamSidebarOpen(true);
          requestAnimationFrame(() => setTeamSidebarVisible(true));
        };
        if (orgSidebarVisible) {
          sidebarSwitchingRef.current = true;
          setOrgSidebarVisible(false);
          setTimeout(() => {
            sidebarSwitchingRef.current = false;
            setOrgSidebarOpen(false);
            openNewTeam();
          }, 150);
        } else if (projectSidebarVisible) {
          sidebarSwitchingRef.current = true;
          setProjectSidebarVisible(false);
          setTimeout(() => {
            sidebarSwitchingRef.current = false;
            setProjectSidebarOpen(false);
            setSelectedProjectId(null);
            setSelectedProjectName(null);
            openNewTeam();
          }, 150);
        } else if (teamSidebarVisible && selectedTeamId && selectedTeamId !== d.projectId) {
          sidebarSwitchingRef.current = true;
          setTeamSidebarVisible(false);
          setTimeout(() => {
            sidebarSwitchingRef.current = false;
            setTeamSidebarOpen(false);
            openNewTeam();
          }, 150);
        } else {
          closeOrgSidebarImmediate();
          openNewTeam();
        }
        return;
      }
      if (d.projectId) {
        focusedNodeIdRef.current = node.id;
        const openNewProject = () => {
          setSelectedProjectId(d.projectId!);
          setSelectedProjectName((d.projectName as string) ?? null);
          setSelectedProjectFramework(d.framework ?? null);
          setSelectedProjectIsExtracting(d.isExtracting ?? false);
          setSelectedProjectIsInitialExtracting(d.isInitialExtracting ?? false);
          setProjectStats(null);
          setProjectVulnerabilities(null);
          setProjectSidebarProject(null);
          setExpandedProjectVulnRowId(null);
          setProjectVulnDetailByRowId({});
          setProjectSidebarTab('findings');
          setProjectSettingsSubTab('general');
          setProjectFindingToOpen(null);
          setSidebarParams({ sidebar: 'project', projectId: d.projectId!, tab: 'findings', subtab: null, teamId: null });
          setProjectSidebarOpen(true);
          requestAnimationFrame(() => setProjectSidebarVisible(true));
        };
        // Animate close whichever sidebar is open, then open the project sidebar
        if (orgSidebarVisible) {
          sidebarSwitchingRef.current = true;
          setOrgSidebarVisible(false);
          setTimeout(() => {
            sidebarSwitchingRef.current = false;
            setOrgSidebarOpen(false);
            openNewProject();
          }, 150);
        } else if (teamSidebarVisible) {
          sidebarSwitchingRef.current = true;
          setTeamSidebarVisible(false);
          setTimeout(() => {
            sidebarSwitchingRef.current = false;
            setTeamSidebarOpen(false);
            setSelectedTeamId(null);
            setSelectedTeamName(null);
            openNewProject();
          }, 150);
        } else if (projectSidebarVisible && selectedProjectId === d.projectId) {
          // Already showing this project — do nothing
          return;
        } else if (projectSidebarVisible && selectedProjectId !== d.projectId) {
          sidebarSwitchingRef.current = true;
          setProjectSidebarVisible(false);
          setTimeout(() => {
            sidebarSwitchingRef.current = false;
            setProjectSidebarOpen(false);
            openNewProject();
          }, 150);
        } else {
          closeOrgSidebarImmediate();
          closeTeamSidebarImmediate();
          openNewProject();
        }
      }
    },
    [
      orgId,
      orgSidebarVisible,
      closeOrgSidebarImmediate,
      closeTeamSidebarImmediate,
      closeProjectSidebarImmediate,
      setSidebarParams,
      teamSidebarVisible,
      selectedTeamId,
      projectSidebarVisible,
      selectedProjectId,
      toast,
    ]
  );

  const canManageCanvas = organization?.permissions?.manage_teams_and_projects === true;

  // Pre-drag positions keyed by node id. Used to detect actual movement and to
  // revert the visual position if the server rejects the write.
  const dragStartPositionsRef = useRef<Map<string, { x: number; y: number }>>(new Map());

  // Child project ids of the currently-dragged team (null when a team isn't
  // being dragged). Captured at drag start so the drag-move handler can
  // translate the same set of children even if rawTeamsWithProjects changes.
  const draggingTeamChildrenRef = useRef<string[] | null>(null);

  const handleNodeDragStart = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setCanvasDragging(true);
      canvasChannelRef.current.sendDragStart(node.id);
      // Always remember the dragged node's start position.
      dragStartPositionsRef.current.set(node.id, { x: node.position.x, y: node.position.y });

      // If this is a team, snapshot every child project's start position too,
      // so we can translate them rigidly with the team on each drag frame.
      if (node.id.startsWith('team-')) {
        const teamId = node.id.slice('team-'.length);
        if (teamId === UNGROUPED_TEAM_ID) {
          draggingTeamChildrenRef.current = null;
          return;
        }
        const team = rawTeamsWithProjectsRef.current.find((t) => t.teamId === teamId);
        const childIds = team?.projects.map((p) => p.projectId) ?? [];
        draggingTeamChildrenRef.current = childIds;

        const currentNodes = graphNodesRef.current;
        for (const projectId of childIds) {
          const childNode = currentNodes.find((n) => n.id === `project-${projectId}`);
          if (childNode) {
            dragStartPositionsRef.current.set(childNode.id, {
              x: childNode.position.x,
              y: childNode.position.y,
            });
          }
        }

        // Tag child project nodes so CSS can mirror the "held" affordance
        // (scale + ring) on them while the parent team is being dragged.
        if (childIds.length > 0) {
          const childNodeIds = new Set(childIds.map((pid) => `project-${pid}`));
          setGraphNodes((nodes) =>
            nodes.map((n) => {
              if (!childNodeIds.has(n.id)) return n;
              const existing = n.className ?? '';
              if (existing.split(' ').includes('team-drag-child')) return n;
              return { ...n, className: existing ? `${existing} team-drag-child` : 'team-drag-child' };
            }),
          );
        }
      } else {
        draggingTeamChildrenRef.current = null;
      }
    },
    [setGraphNodes],
  );

  // While a team is being dragged, translate its children by the same delta.
  // React Flow handles the dragged team node itself — we only touch children.
  const handleNodeDrag = useCallback(
    (_: React.MouseEvent, node: Node) => {
      // Broadcast this frame's positions to other clients (throttled inside the hook).
      const moves: NodePositionUpdate[] = [{
        nodeId: node.id,
        x: node.position.x,
        y: node.position.y,
      }];

      const childIds = draggingTeamChildrenRef.current;
      const isTeamDrag = !!childIds && childIds.length > 0 && node.id.startsWith('team-');
      if (isTeamDrag) {
        const teamStart = dragStartPositionsRef.current.get(node.id);
        if (teamStart) {
          const dx = node.position.x - teamStart.x;
          const dy = node.position.y - teamStart.y;
          for (const pid of childIds!) {
            const start = dragStartPositionsRef.current.get(`project-${pid}`);
            if (!start) continue;
            moves.push({ nodeId: `project-${pid}`, x: start.x + dx, y: start.y + dy });
          }
        }
      }
      canvasChannelRef.current.sendDragMove(moves);

      if (!childIds || childIds.length === 0) return;
      if (!node.id.startsWith('team-')) return;

      const teamStart = dragStartPositionsRef.current.get(node.id);
      if (!teamStart) return;

      const dx = node.position.x - teamStart.x;
      const dy = node.position.y - teamStart.y;
      if (dx === 0 && dy === 0) return;

      const childNodeIds = new Set(childIds.map((pid) => `project-${pid}`));
      setGraphNodes((nodes) =>
        nodes.map((n) => {
          if (!childNodeIds.has(n.id)) return n;
          const start = dragStartPositionsRef.current.get(n.id);
          if (!start) return n;
          return { ...n, position: { x: start.x + dx, y: start.y + dy } };
        }),
      );
    },
    [setGraphNodes],
  );

  const handleNodeDragStop = useCallback(
    async (_: React.MouseEvent, node: Node) => {
      setCanvasDragging(false);
      canvasChannelRef.current.sendDragStop(node.id);
      const orgIdNow = organization?.id;
      const draggedChildIds = draggingTeamChildrenRef.current ?? [];
      draggingTeamChildrenRef.current = null;

      // Remove the team-drag-child CSS tag from any carried children. The
      // layout recompute after an optimistic rawTeamsWithProjects update will
      // also produce fresh nodes without the className, but we strip it here
      // to cover the no-movement early-return paths.
      if (draggedChildIds.length > 0) {
        const childNodeIds = new Set(draggedChildIds.map((pid) => `project-${pid}`));
        setGraphNodes((nodes) =>
          nodes.map((n) => {
            if (!childNodeIds.has(n.id) || !n.className) return n;
            const stripped = n.className
              .split(' ')
              .filter((c) => c !== 'team-drag-child')
              .join(' ');
            return { ...n, className: stripped || undefined };
          }),
        );
      }

      const cleanupStartPositions = () => {
        dragStartPositionsRef.current.delete(node.id);
        for (const pid of draggedChildIds) {
          dragStartPositionsRef.current.delete(`project-${pid}`);
        }
      };

      if (!orgIdNow || node.id === ORG_CENTER_ID) {
        cleanupStartPositions();
        return;
      }

      const startPos = dragStartPositionsRef.current.get(node.id);
      const { x, y } = node.position;
      if (startPos && startPos.x === x && startPos.y === y) {
        cleanupStartPositions();
        return; // no actual movement
      }

      const isTeam = node.id.startsWith('team-');
      const isProject = node.id.startsWith('project-');
      const teamId = isTeam ? node.id.slice('team-'.length) : null;
      const projectId = isProject ? node.id.slice('project-'.length) : null;
      if (isTeam && teamId === UNGROUPED_TEAM_ID) {
        cleanupStartPositions();
        return;
      }
      if (!isTeam && !isProject) {
        cleanupStartPositions();
        return;
      }

      // Compute final positions for carried children (team-drag case).
      const childUpdates: Array<{ id: string; x: number; y: number }> = [];
      if (isTeam && startPos) {
        const dx = x - startPos.x;
        const dy = y - startPos.y;
        for (const pid of draggedChildIds) {
          const childStart = dragStartPositionsRef.current.get(`project-${pid}`);
          if (!childStart) continue;
          childUpdates.push({ id: pid, x: childStart.x + dx, y: childStart.y + dy });
        }
      }

      cleanupStartPositions();

      // Snapshot current child canvas positions so we can revert them if the
      // server rejects the write. Read from rawTeamsWithProjectsRef to avoid a
      // stale closure.
      const childRevertMap = new Map<string, { x: number | null; y: number | null }>();
      if (isTeam && childUpdates.length > 0) {
        const teamData = rawTeamsWithProjectsRef.current.find((t) => t.teamId === teamId);
        if (teamData) {
          for (const p of teamData.projects) {
            childRevertMap.set(p.projectId, {
              x: p.canvasPositionX ?? null,
              y: p.canvasPositionY ?? null,
            });
          }
        }
      }

      // Optimistically update rawTeamsWithProjects BEFORE firing the PATCH.
      // This prevents a concurrent PATCH resolution from triggering a layout
      // recompute that emits this node at its stale saved position while our
      // own PATCH is still in flight.
      setRawTeamsWithProjects((prev) => {
        if (isTeam) {
          const childPosById = new Map(childUpdates.map((u) => [u.id, { x: u.x, y: u.y }]));
          return prev.map((t) => {
            if (t.teamId !== teamId) return t;
            return {
              ...t,
              canvasPositionX: x,
              canvasPositionY: y,
              projects: t.projects.map((p) => {
                const newPos = childPosById.get(p.projectId);
                return newPos
                  ? { ...p, canvasPositionX: newPos.x, canvasPositionY: newPos.y }
                  : p;
              }),
            };
          });
        }
        return prev.map((t) => ({
          ...t,
          projects: t.projects.map((p) =>
            p.projectId === projectId
              ? { ...p, canvasPositionX: x, canvasPositionY: y }
              : p,
          ),
        }));
      });

      try {
        if (isTeam) {
          if (childUpdates.length > 0) {
            await api.updateCanvasPositionsBatch(orgIdNow, {
              teams: [{ id: teamId!, x, y }],
              projects: childUpdates,
            });
          } else {
            await api.updateTeamCanvasPosition(orgIdNow, teamId!, { x, y });
          }
        } else {
          await api.updateProjectCanvasPosition(orgIdNow, projectId!, { x, y });
        }
      } catch (err: any) {
        toast({
          title: 'Failed to save position',
          description: err?.message || 'Please try again.',
          variant: 'destructive',
        });
        // Revert the optimistic rawTeamsWithProjects update. This cascades
        // through the layout hook → sync effect → graphNodes automatically,
        // so we don't need to touch graphNodes directly.
        const revertX = startPos?.x ?? null;
        const revertY = startPos?.y ?? null;
        setRawTeamsWithProjects((prev) => {
          if (isTeam) {
            return prev.map((t) => {
              if (t.teamId !== teamId) return t;
              return {
                ...t,
                canvasPositionX: revertX,
                canvasPositionY: revertY,
                projects: t.projects.map((p) => {
                  const revertPos = childRevertMap.get(p.projectId);
                  return revertPos
                    ? { ...p, canvasPositionX: revertPos.x, canvasPositionY: revertPos.y }
                    : p;
                }),
              };
            });
          }
          return prev.map((t) => ({
            ...t,
            projects: t.projects.map((p) =>
              p.projectId === projectId
                ? { ...p, canvasPositionX: revertX, canvasPositionY: revertY }
                : p,
            ),
          }));
        });
      }
    },
    [organization?.id, toast],
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
        // Without this the expand just silently collapses — say why, and that clicking retries.
        toast({ title: 'Failed to load dependencies', description: 'Click the project again to retry.', variant: 'destructive' });
      } finally {
        setExpandingProjectId(null);
      }
    },
    [orgId, expandedProjectId, toast]
  );

  useEffect(() => {
    graphNodesRef.current = graphNodes;
  }, [graphNodes]);

  const graphEdgesRef = useRef<Edge[]>([]);
  useEffect(() => {
    graphEdgesRef.current = graphEdges;
  }, [graphEdges]);

  useEffect(() => {
    rawTeamsWithProjectsRef.current = rawTeamsWithProjects;
  }, [rawTeamsWithProjects]);

  // Fetch the org-wide projects + security summary when the org sidebar opens.
  // The graph load already fetched both, so seed the table from that in-memory data
  // for an instant open (no skeleton), then revalidate in the background. The sidebar
  // is the same data the tiles already show, so a stale-while-revalidate render is safe.
  useEffect(() => {
    if (!orgId || !orgSidebarOpen) return;
    let cancelled = false;
    const seededSummaries = Array.from(securitySummaryByProject.values());
    const haveSeed = seededSummaries.length > 0 && allProjectsFlat.length > 0;
    if (haveSeed) {
      setOrgSidebarSecuritySummary(seededSummaries);
      setOrgSidebarProjects(allProjectsFlat);
      setOrgSidebarLoading(false); // we have data — skip the skeleton
    } else {
      setOrgSidebarLoading(true);
    }
    setOrgSidebarError(false);
    Promise.all([api.getOrgSecuritySummary(orgId), api.getProjects(orgId)])
      .then(([summary, projects]) => {
        if (cancelled) return;
        setOrgSidebarSecuritySummary(summary.projects || []);
        setOrgSidebarProjects(projects);
        // Keep the graph tiles' band pills in sync with the fresher sidebar fetch.
        if (summary.projects?.length) {
          setSecuritySummaryByProject(new Map(summary.projects.map((s) => [s.project_id, s])));
        }
      })
      .catch(() => {
        // Only surface an error if we had nothing to show; a failed refresh over a
        // good seed should leave the seeded rows in place, not blank them.
        if (!cancelled && !haveSeed) setOrgSidebarError(true);
      })
      .finally(() => {
        if (!cancelled) setOrgSidebarLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // securitySummaryByProject / allProjectsFlat are read once for the seed; excluding
    // them keeps the effect from re-firing (and re-fetching) on every background graph
    // refresh while the sidebar is open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, orgSidebarOpen, orgSidebarRefetch]);

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
      setTeamSidebarFindingRows([]);
      setTeamSidebarBaseImageRecs([]);
      return;
    }
    let cancelled = false;
    // Clear stale data from previous team immediately
    setTeamSidebarFindingRows([]);
    setTeamSidebarBaseImageRecs([]);
    setTeamSidebarDataLoading(true);
    setTeamSidebarError(false);
    // Note: getOrganizationMembers is NOT loaded here — it only feeds the Add-Member dialog, so it's
    // deferred to when the Members tab opens (see the effect below). Most sidebar opens land on the
    // Findings tab and never need it, and it's the heaviest call (per-user auth lookups).
    Promise.all([
      api.getTeamStats(orgId, selectedTeamId),
      api.getTeamMembers(orgId, selectedTeamId),
      api.getProjects(orgId),
      api.getTeamRoles(orgId, selectedTeamId),
      api.getTeam(orgId, selectedTeamId),
      api.getTeamSecuritySummary(orgId, selectedTeamId),
    ])
      .then(([stats, members, allProjects, roles, teamData, securitySummary]) => {
        if (cancelled) return;
        setTeamSidebarStats(stats);
        setTeamSidebarMembers(members);
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
          // Surface the failure — empty state with no error reads as "this team has no data".
          setTeamSidebarError(true);
        }
      })
      .finally(() => {
        if (!cancelled) setTeamSidebarDataLoading(false);
      });
    return () => { cancelled = true; };
  }, [orgId, selectedTeamId, teamSidebarOpen, teamSidebarRefetch]);

  // Org members feed only the Add-Member dialog's "available people" list — load them lazily when
  // the Members tab is opened (the default Findings tab never needs them). By the time the user
  // clicks Add Member they're ready, and the heaviest call is off the common-case critical path.
  // The ref makes the load once-per-team-per-open: swapping tabs away and back must not refetch.
  const teamOrgMembersLoadedForRef = useRef<string | null>(null);
  useEffect(() => {
    if (!teamSidebarOpen) { teamOrgMembersLoadedForRef.current = null; return; }
    if (teamSidebarTab !== 'members' || !orgId || !selectedTeamId || selectedTeamId === UNGROUPED_TEAM_ID) return;
    if (teamOrgMembersLoadedForRef.current === selectedTeamId) return;
    teamOrgMembersLoadedForRef.current = selectedTeamId;
    let cancelled = false;
    api.getOrganizationMembers(orgId)
      .then((m) => { if (!cancelled) setTeamSidebarOrgMembers(m); })
      .catch(() => {
        if (cancelled) return;
        // Explain the otherwise-mysterious empty "available people" list in the Add Member
        // dialog, and let the next Members-tab visit retry instead of being blocked by the ref.
        teamOrgMembersLoadedForRef.current = null;
        toast({ title: 'Could not load organization members', description: 'The Add Member list may be empty — reopen the tab to retry.', variant: 'destructive' });
      });
    return () => { cancelled = true; };
  }, [teamSidebarOpen, teamSidebarTab, orgId, selectedTeamId, toast]);

  // Load every finding type for ONE project into unified table rows — the exact
  // same set the project Findings tab assembles (SCA + secrets + semgrep + IaC +
  // container + DAST + malicious), so a team is just the union of its projects.
  // Each row is stamped with project_id/project_name so the collapses (container,
  // IaC hardening) group per-project and the table can attribute each finding.
  const loadProjectFindingRows = useCallback(async (
    oid: string,
    project: { id: string; name?: string | null },
  ): Promise<{ rows: SecurityTableRow[]; baseImageRecs: BaseImageRecommendation[] }> => {
    const pid = project.id;
    const projectName = project.name ?? undefined;
    const [vulnsR, secretsR, semgrepR, iacR, containerR, maliciousR, recsR] = await Promise.allSettled([
      api.getProjectVulnerabilities(oid, pid),
      api.getProjectSecretFindings(oid, pid, 1, 100),
      api.getProjectSemgrepFindings(oid, pid, 1, 100),
      api.getProjectIaCFindings(oid, pid, { perPage: 100, status: 'open' }),
      api.getProjectContainerFindings(oid, pid, { perPage: 100, status: 'open' }),
      api.maliciousFindings.list(oid, pid, 1, 100),
      api.getBaseImageRecommendations(oid, pid),
    ]);

    const rows: SecurityTableRow[] = [];

    // SCA: one row per (dependency, CVE), keeping the highest depscore — mirrors
    // the project tab's dedupedProjectVulnerabilities.
    if (vulnsR.status === 'fulfilled') {
      const vulns = (vulnsR.value ?? []) as ProjectVulnerability[];
      const rowScore = (v: ProjectVulnerability) => {
        const c = v.contextual_depscore;
        if (c != null && Number.isFinite(Number(c))) return Number(c);
        const d = v.depscore;
        if (d != null && Number.isFinite(Number(d))) return Number(d);
        return -1;
      };
      const byKey = new Map<string, ProjectVulnerability>();
      for (const v of vulns) {
        const key = `${v.dependency_id}:${v.osv_id}`;
        const prev = byKey.get(key);
        if (!prev || rowScore(v) > rowScore(prev)) byKey.set(key, { ...v, project_name: projectName ?? v.project_name });
      }
      for (const v of byKey.values()) rows.push({ type: 'vulnerability', data: v });
    }
    if (secretsR.status === 'fulfilled') {
      for (const s of secretsR.value?.data ?? []) rows.push({ type: 'secret', data: { ...s, project_id: pid, project_name: projectName } });
    }
    if (semgrepR.status === 'fulfilled') {
      for (const s of semgrepR.value?.data ?? []) rows.push({ type: 'semgrep', data: { ...s, project_id: pid, project_name: projectName } });
    }
    if (iacR.status === 'fulfilled') {
      for (const f of iacR.value?.data ?? []) rows.push({ type: 'iac', data: { ...f, project_id: pid, project_name: projectName } });
    }
    if (containerR.status === 'fulfilled') {
      for (const f of containerR.value?.data ?? []) rows.push({ type: 'container', data: { ...f, project_id: pid, project_name: projectName } });
    }
    if (maliciousR.status === 'fulfilled') {
      for (const f of maliciousR.value?.data ?? []) rows.push({ type: 'malicious', data: { ...f, project_id: pid, project_name: projectName } });
    }
    // DAST is per-target: resolve the latest scan's target, then load its findings.
    try {
      const jobs = await api.getDastJobs(pid, { limit: 5 });
      const targetId = jobs.find((j) => j.target_id)?.target_id ?? undefined;
      const dast = targetId ? await api.getDastFindings(pid, { limit: 200, targetId }) : [];
      for (const f of dast) rows.push({ type: 'dast', data: { ...f, project_name: projectName } });
    } catch { /* no DAST target for this project */ }

    // First-party data-flow findings — the taint engine's source→sink paths in
    // the project's own code. One cheap request; empty for most projects.
    try {
      const cf = await api.getCodeFlowFindings(oid, pid);
      for (const f of cf.data ?? []) rows.push({ type: 'taint_flow', data: { ...f, project_name: projectName } });
    } catch { /* no code-flow findings for this project */ }

    const baseImageRecs = recsR.status === 'fulfilled' ? (recsR.value.recommendations ?? []) : [];
    return { rows, baseImageRecs };
  }, []);

  // Load the team Findings tab: fan out loadProjectFindingRows across every project
  // in the team and concat. The team project list comes from the security-summary
  // RPC (authoritative + race-free), so it covers projects whose only findings are
  // Tracker links across the org — drives the linked-ticket chips on findings.
  // One org-wide fetch covers both the project panel and the team sidebar (each
  // row matches by its own project_id). Tracker links + group-level Ignore for
  // the collapsed rows ride together so the status cell has both in one pass.
  const loadTrackerLinks = useCallback(async () => {
    if (!orgId) return;
    // Two INDEPENDENT fetches — a failure in one (e.g. a route the running
    // backend doesn't have yet) must not block the other, or the links (and the
    // resolved-✓ external_state they carry) silently freeze at a stale snapshot.
    api.getOrgTrackerLinks(orgId).then(({ links }) => setTrackerLinks(links)).catch(() => {});
    api.getOrgGroupSuppressions(orgId).then(({ suppressions }) => setGroupSuppressions(suppressions)).catch(() => {});
    api.getOrgAcknowledgements(orgId).then(({ acknowledgements }) => setAcknowledgements(acknowledgements)).catch(() => {});
  }, [orgId]);

  // Tracker links / group-suppressions / acknowledgements feed ONLY the sidebar findings tables
  // (project + team). Loading them on the bare overview is premature — defer until a findings
  // surface actually opens, so the overview's first paint isn't competing for the (locally
  // 6-per-host) connection pool with three calls it never renders.
  useEffect(() => {
    if (!projectSidebarOpen && !teamSidebarOpen) return;
    void loadTrackerLinks();
  }, [projectSidebarOpen, teamSidebarOpen, loadTrackerLinks]);

  // IaC/container/DAST — not just ones with SCA rows.
  const loadTeamFindings = useCallback(async () => {
    if (!orgId || !selectedTeamId || selectedTeamId === UNGROUPED_TEAM_ID) return;
    setTeamSidebarFindingsLoading(true);
    setTeamSidebarFindingsError(false);
    setTeamSidebarFindingRows([]);
    setTeamSidebarBaseImageRecs([]);
    try {
      const summary = await api
        .getTeamSecuritySummary(orgId, selectedTeamId)
        .catch(() => ({ projects: [] as ProjectSecuritySummary[] }));
      const teamProjects = (summary.projects ?? []).map((p) => ({ id: p.project_id, name: p.project_name }));
      if (teamProjects.length === 0) {
        setTeamSidebarFindingRows([]);
        setTeamSidebarBaseImageRecs([]);
        return;
      }
      // Fan out across the team's projects, then swap the whole set in once. Appending
      // each project's rows as it landed made the list visibly grow and grow ("it keeps
      // loading more and more"); with the table paginated, settling first and rendering a
      // stable, complete list reads better — the animated skeleton covers the wait. A
      // single project failing is swallowed so it can't blank the team.
      const collectedRows: SecurityTableRow[] = [];
      const collectedRecs: BaseImageRecommendation[] = [];
      await Promise.all(teamProjects.map(async (p) => {
        try {
          const { rows, baseImageRecs } = await loadProjectFindingRows(orgId, p);
          if (rows.length) collectedRows.push(...rows);
          if (baseImageRecs.length) collectedRecs.push(...baseImageRecs);
        } catch { /* one project's findings failing shouldn't blank the rest of the team */ }
      }));
      setTeamSidebarFindingRows(collectedRows);
      setTeamSidebarBaseImageRecs(collectedRecs);
    } catch {
      setTeamSidebarFindingsError(true);
      setTeamSidebarFindingRows([]);
      setTeamSidebarBaseImageRecs([]);
    } finally {
      setTeamSidebarFindingsLoading(false);
    }
  }, [orgId, selectedTeamId, loadProjectFindingRows]);

  // Findings load once per team per sidebar-open. Without the ref, swapping to another tab and
  // back re-fires the effect (teamSidebarTab is a dep) and loadTeamFindings blanks the list before
  // refetching — the tab visibly "reloads". A status change refreshes via loadTeamFindings directly.
  const teamFindingsLoadedForRef = useRef<string | null>(null);
  useEffect(() => {
    if (!teamSidebarOpen) { teamFindingsLoadedForRef.current = null; return; }
    if (teamSidebarTab !== 'findings' || !selectedTeamId || selectedTeamId === UNGROUPED_TEAM_ID) return;
    if (teamFindingsLoadedForRef.current === selectedTeamId) return;
    teamFindingsLoadedForRef.current = selectedTeamId;
    void loadTeamFindings();
  }, [teamSidebarTab, teamSidebarOpen, selectedTeamId, loadTeamFindings]);

  // When a project is created that belongs to the currently open team sidebar, add it to the sidebar's project list
  useEffect(() => {
    if (!teamSidebarOpen || !selectedTeamId) return;
    const handler = (e: Event) => {
      const { id, name, owner_team_id, team_ids, framework } = (e as CustomEvent).detail as { id: string; name: string; owner_team_id: string | null; team_ids: string[]; framework: string | null };
      const belongsToTeam = owner_team_id === selectedTeamId || (team_ids ?? []).includes(selectedTeamId);
      if (belongsToTeam) {
        setTeamSidebarProjects(prev => {
          if (prev.some(p => p.id === id)) return prev;
          return [...prev, { id, name, owner_team_id, team_ids: team_ids ?? [], framework, repo_status: 'queued', extraction_step: 'queued', created_at: new Date().toISOString(), updated_at: new Date().toISOString(), organization_id: '', health_score: 0 } as Project];
        });
      }
    };
    window.addEventListener('organization:projectCreated', handler);
    return () => window.removeEventListener('organization:projectCreated', handler);
  }, [teamSidebarOpen, selectedTeamId]);

  // Initialize team settings form data when team data loads
  useEffect(() => {
    if (teamSidebarTeamData) {
      setTeamSettingsName(teamSidebarTeamData.name || '');
    }
  }, [teamSidebarTeamData]);

  // Team settings handlers
  const handleTeamSettingsSave = async () => {
    if (!orgId || !selectedTeamId || !teamSidebarTeamData) return;
    setTeamSettingsSaving(true);
    try {
      await api.updateTeam(orgId, selectedTeamId, { name: teamSettingsName });
      toast({ title: 'Saved', description: 'Team settings saved.' });
      setSelectedTeamName(teamSettingsName);
      setTeamSidebarTeamData(prev => prev ? { ...prev, name: teamSettingsName } : prev);
      // Rename the team node in place — the graph derives from these stores, so patching them
      // updates the label without the wipe-and-refetch a graphRefreshTrigger bump causes.
      setTeamsById(prev => prev[selectedTeamId] ? { ...prev, [selectedTeamId]: { ...prev[selectedTeamId], name: teamSettingsName } } : prev);
      setRawTeamsWithProjects(prev => prev.map(t => t.teamId === selectedTeamId ? { ...t, teamName: teamSettingsName } : t));
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
    const membersWithRole = teamSidebarMembers.filter((m) => m.role === role.name).length;
    if (membersWithRole > 0) {
      toast({ title: 'Cannot delete role', description: `${membersWithRole} ${membersWithRole === 1 ? 'member has' : 'members have'} this role. Update their roles first.`, variant: 'destructive' });
      return;
    }
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

  // Team role drag-to-reorder
  const handleTeamSettingsDragPreview = (draggedId: string, targetId: string) => {
    const sourceRoles = teamSettingsDragPreviewRoles || teamSidebarRoles;
    const draggedIndex = sourceRoles.findIndex(r => r.id === draggedId);
    const targetIndex = sourceRoles.findIndex(r => r.id === targetId);
    if (draggedIndex === -1 || targetIndex === -1 || draggedIndex === targetIndex) return;
    const newRoles = [...sourceRoles];
    const [draggedRole] = newRoles.splice(draggedIndex, 1);
    newRoles.splice(targetIndex, 0, draggedRole);
    setTeamSettingsDragPreviewRoles(newRoles);
  };

  const handleTeamSettingsDragReorder = async () => {
    if (!orgId || !selectedTeamId || !teamSettingsDragPreviewRoles) return;

    // Calculate which roles changed position (compare original array index to new index)
    const updates: Array<{ id: string; newOrder: number; originalIndex: number }> = [];
    teamSettingsDragPreviewRoles.forEach((role, newIndex) => {
      const originalIndex = teamSidebarRoles.findIndex(r => r.id === role.id);
      if (originalIndex !== -1 && originalIndex !== newIndex) {
        updates.push({ id: role.id, newOrder: newIndex, originalIndex });
      }
    });
    if (updates.length === 0) { setTeamSettingsDragPreviewRoles(null); return; }

    // Rank validation: prevent moving a role above the user's rank (unless org-level admin)
    if (!teamSidebarHasOrgManagePermission) {
      const originalUserIndex = teamSidebarRoles.findIndex(r => r.name === teamSidebarTeamData?.role);
      const userNewPosition = teamSettingsDragPreviewRoles.findIndex(r => r.name === teamSidebarTeamData?.role);
      if (originalUserIndex !== -1 && userNewPosition !== -1) {
        const invalidUpdate = updates.find(update => {
          const wasBelow = update.originalIndex > originalUserIndex;
          const isNowAbove = update.newOrder < userNewPosition;
          return wasBelow && isNowAbove;
        });
        if (invalidUpdate) {
          toast({ title: 'Cannot reorder role', description: 'You cannot reorder a role to be above your rank.', variant: 'destructive' });
          setTeamSettingsDragPreviewRoles(null);
          return;
        }
      }
    }

    // Commit the preview to actual state
    const finalRoles = teamSettingsDragPreviewRoles.map((role, index) => ({ ...role, display_order: index }));
    setTeamSidebarRoles(finalRoles);
    setTeamSettingsDragPreviewRoles(null);
    Promise.all(updates.map(({ id: roleId, newOrder }) => api.updateTeamRole(orgId, selectedTeamId, roleId, { display_order: newOrder })))
      .catch(async () => {
        // The optimistic order is already on screen and the writes may have PARTIALLY landed —
        // refetch server truth instead of leaving the UI lying about the saved order.
        toast({ title: 'Failed to reorder roles', description: 'Restoring the saved order.', variant: 'destructive' });
        try {
          const roles = await api.getTeamRoles(orgId, selectedTeamId);
          setTeamSidebarRoles(roles);
        } catch { /* next sidebar open refetches */ }
      });
  };

  // Team settings computed values
  const teamSettingsCanManageSettings = teamSidebarPermissions?.view_settings || teamSidebarHasOrgManagePermission || false;

  // Guard: redirect unauthorized settings tab/subtabs (e.g. from URL params) once permissions are known
  useEffect(() => {
    if (!teamSidebarOpen || !teamSidebarTeamData || teamSidebarDataLoading) return;
    if (teamSidebarTab === 'settings') {
      const canRoles = teamSidebarPermissions?.view_roles || teamSidebarPermissions?.edit_roles || teamSidebarHasOrgManagePermission;
      if (teamSettingsSubTab === 'roles' && !canRoles) {
        setTeamSettingsSubTab('general');
        setSidebarParams({ subtab: 'general' });
      }
    }
  }, [teamSidebarOpen, teamSidebarTeamData, teamSidebarDataLoading, teamSidebarTab, teamSettingsSubTab, teamSettingsCanManageSettings, teamSidebarPermissions, teamSidebarHasOrgManagePermission, setSidebarParams]);
  const teamSettingsCanDeleteTeam = (teamSidebarPermissions?.manage_members && teamSidebarTeamData?.role === 'owner') || teamSidebarHasOrgManagePermission;
  const teamSettingsMemberCountByRole = useMemo(() => {
    const counts = new Map<string, number>();
    teamSidebarMembers.forEach((m) => {
      const name = m.role || 'member';
      counts.set(name, (counts.get(name) || 0) + 1);
    });
    return counts;
  }, [teamSidebarMembers]);

  /**
   * Load the non-SCA finding types for the project sidebar's unified findings
   * table — IaC, container, malicious, and DAST. Resilient (allSettled) so a
   * single failing scanner endpoint never blanks the others; DAST is per-target
   * so we learn the latest scan's target before loading its findings. Shared by
   * the open effect and the post-mutation refresh.
   */
  const loadProjectExtraFindings = useCallback(async (
    oid: string,
    pid: string,
    isCancelled?: () => boolean,
  ) => {
    const [iac, container, malicious, baseImageRecs, codeFlows] = await Promise.allSettled([
      api.getProjectIaCFindings(oid, pid, { perPage: 100, status: 'open' }),
      api.getProjectContainerFindings(oid, pid, { perPage: 100, status: 'open' }),
      api.maliciousFindings.list(oid, pid, 1, 100),
      api.getBaseImageRecommendations(oid, pid),
      api.getCodeFlowFindings(oid, pid),
    ]);
    if (isCancelled?.()) return;
    setProjectIacFindings(iac.status === 'fulfilled' ? iac.value.data ?? [] : []);
    setProjectContainerFindings(container.status === 'fulfilled' ? container.value.data ?? [] : []);
    setProjectMaliciousFindings(malicious.status === 'fulfilled' ? malicious.value.data ?? [] : []);
    setProjectBaseImageRecs(baseImageRecs.status === 'fulfilled' ? baseImageRecs.value.recommendations ?? [] : []);
    setProjectCodeFlows(codeFlows.status === 'fulfilled' ? codeFlows.value.data ?? [] : []);
    try {
      const jobs = await api.getDastJobs(pid, { limit: 5 });
      if (isCancelled?.()) return;
      const targetId = jobs.find((j) => j.target_id)?.target_id ?? undefined;
      const dast = targetId ? await api.getDastFindings(pid, { limit: 200, targetId }) : [];
      if (isCancelled?.()) return;
      setProjectDastFindings(dast);
    } catch {
      if (!isCancelled?.()) setProjectDastFindings([]);
    }
  }, []);

  // Fetch project findings, stats, full project and org when the project sidebar opens.
  // The Findings tab is the default landing tab, so its time-to-render is what "opening
  // the project" feels like. We gate the table on ONLY the finding data it draws
  // (SCA vulns + secrets + semgrep) and load everything else — stats, the full project,
  // the org — on independent tracks so they can't hold the table behind them. Previously
  // all six were one Promise.all, so the table waited on the slowest call (often the
  // 10-query stats aggregate) even though it renders none of that data.
  useEffect(() => {
    if (!orgId || !selectedProjectId || !projectSidebarOpen) return;
    const pid = selectedProjectId;
    let cancelled = false;
    // projectStatsLoading is (despite the name) the findings-table skeleton gate — it
    // stays true until the finding data below settles.
    setProjectStatsLoading(true);
    setProjectStats(null);
    setProjectVulnerabilities(null);
    setProjectSecrets([]);
    setProjectSemgrep([]);
    setProjectIacFindings([]);
    setProjectContainerFindings([]);
    setProjectBaseImageRecs([]);
    setProjectMaliciousFindings([]);
    setProjectDastFindings([]);
    setProjectCodeFlows([]);
    setExpandedProjectVulnRowId(null);
    setProjectVulnDetailByRowId({});
    // Clear stale project/org; the full project + org are loaded lazily by the
    // effect below, only when a tab that needs them (Dependencies / Settings) is
    // opened. The default Findings tab never touches them, so keeping them off the
    // open burst frees two of the browser's ~6 concurrent connections for the
    // finding requests that actually gate the table.
    setProjectSidebarProjectLoading(false);
    setProjectSidebarProject(null);
    setProjectSidebarOrganization(null);

    // Non-SCA finding types (IaC / container / malicious / DAST / code-flow) load on
    // their own track and pop into the table as they arrive.
    void loadProjectExtraFindings(orgId, pid, () => cancelled);

    // CRITICAL PATH — the findings table appears as soon as these three settle.
    // allSettled so one failing scanner endpoint never blanks the others.
    void (async () => {
      const [vulnsR, secretsR, semgrepR] = await Promise.allSettled([
        api.getProjectVulnerabilities(orgId, pid),
        api.getProjectSecretFindings(orgId, pid, 1, 50),
        api.getProjectSemgrepFindings(orgId, pid, 1, 50),
      ]);
      if (cancelled) return;
      setProjectVulnerabilities(vulnsR.status === 'fulfilled' ? (vulnsR.value ?? []) : []);
      setProjectSecrets(secretsR.status === 'fulfilled' ? (secretsR.value?.data ?? []) : []);
      setProjectSemgrep(semgrepR.status === 'fulfilled' ? (semgrepR.value?.data ?? []) : []);
      setProjectStatsLoading(false);
    })();

    // Stats feed only the partial-coverage banner + header chips — never the table rows.
    api.getProjectStats(orgId, pid)
      .then((stats) => { if (!cancelled) setProjectStats(stats); })
      .catch(() => { if (!cancelled) setProjectStats(null); });

    return () => { cancelled = true; };
  }, [orgId, selectedProjectId, projectSidebarOpen]);

  // Lazily load the full project + org — they back only the Dependencies / Settings
  // tabs, so we fetch them the first time one of those tabs is opened rather than on
  // every project open. The ref keys on project id so swapping tabs back and forth
  // doesn't refetch, but switching to a different project does.
  const projectMetaLoadedForRef = useRef<string | null>(null);
  useEffect(() => {
    if (!projectSidebarOpen) { projectMetaLoadedForRef.current = null; return; }
    if (!orgId || !selectedProjectId || projectSidebarTab === 'findings') return;
    if (projectMetaLoadedForRef.current === selectedProjectId) return;
    projectMetaLoadedForRef.current = selectedProjectId;
    const pid = selectedProjectId;
    let cancelled = false;
    setProjectSidebarProjectLoading(true);
    void (async () => {
      const [projectR, orgR] = await Promise.allSettled([
        api.getProject(orgId, pid),
        api.getOrganization(orgId),
      ]);
      if (cancelled) return;
      setProjectSidebarProject(projectR.status === 'fulfilled' ? projectR.value : null);
      setProjectSidebarOrganization(orgR.status === 'fulfilled' ? orgR.value : null);
      setProjectSidebarProjectLoading(false);
    })();
    return () => { cancelled = true; };
  }, [projectSidebarOpen, orgId, selectedProjectId, projectSidebarTab]);

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

  const projectSecurityRows = useMemo<SecurityTableRow[]>(() => [
    ...dedupedProjectVulnerabilities.map((v) => ({ type: 'vulnerability' as const, data: v })),
    ...projectSecrets.map((s) => ({ type: 'secret' as const, data: s })),
    ...projectSemgrep.map((s) => ({ type: 'semgrep' as const, data: s })),
    ...projectIacFindings.map((f) => ({ type: 'iac' as const, data: f })),
    ...projectContainerFindings.map((f) => ({ type: 'container' as const, data: f })),
    ...projectDastFindings.map((f) => ({ type: 'dast' as const, data: f })),
    ...projectMaliciousFindings.map((f) => ({ type: 'malicious' as const, data: f })),
    ...projectCodeFlows.map((f) => ({ type: 'taint_flow' as const, data: f })),
  ], [dedupedProjectVulnerabilities, projectSecrets, projectSemgrep, projectIacFindings, projectContainerFindings, projectDastFindings, projectMaliciousFindings, projectCodeFlows]);

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
    <main className="relative flex flex-col min-h-[100vh] w-full bg-background">
      {error && (
        <div className="flex-shrink-0 px-4 pt-3">
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive flex items-center justify-between gap-3">
            <span className="min-w-0 break-words">{error}</span>
            <Button
              variant="outline"
              className="h-8 rounded-lg px-3 flex-shrink-0"
              onClick={() => { setError(null); setGraphRefreshTrigger((t) => t + 1); }}
            >
              Try again
            </Button>
          </div>
        </div>
      )}
      <div className="flex-1 min-h-0 relative">
{!stillShowingSkeleton && (
<div className="absolute top-3 right-3 z-10 flex flex-col items-end gap-2">
          <div className="flex items-center gap-2 rounded-lg border border-border bg-background-card-header p-1 shadow-sm">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2 gap-1 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
                aria-label="Add"
              >
                <Plus className="h-3.5 w-3.5" />
                <span className="text-xs font-medium">Add</span>
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
                onClick={() => navigate(`/organizations/${orgId}/new-project`, { state: { teams: Object.values(teamsById) } })}
              >
                <FolderPlus className="h-4 w-4" />
                Create project
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          </div>
        </div>
)}
        {/* Bottom-left canvas controls — Railway-style vertical rail: zoom/fit group + live cursors */}
        {!stillShowingSkeleton && (
          <div className="absolute bottom-3 left-3 z-10 flex flex-col gap-2">
            <div className="flex flex-col items-center gap-0.5 rounded-lg border border-border bg-background-card-header p-1 shadow-sm">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
                    onClick={() => reactFlowInstanceRef.current?.zoomIn({ duration: 150 })}
                    aria-label="Zoom in"
                  >
                    <Plus className="h-3.5 w-3.5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Zoom in</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
                    onClick={() => reactFlowInstanceRef.current?.zoomOut({ duration: 150 })}
                    aria-label="Zoom out"
                  >
                    <Minus className="h-3.5 w-3.5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Zoom out</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
                    onClick={() => reactFlowInstanceRef.current?.fitView({ padding: 0.38, maxZoom: 1.15, duration: 300 })}
                    aria-label="Fit view"
                  >
                    <Maximize2 className="h-3.5 w-3.5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right">Fit view</TooltipContent>
              </Tooltip>
            </div>
            <div className="flex flex-col items-center rounded-lg border border-border bg-background-card-header p-1 shadow-sm">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className={cn(
                      'h-8 w-8 p-0 hover:bg-white/5',
                      canvasCursorsOrgEnabled && (showOthersCursors || broadcastOwnCursor)
                        ? 'text-foreground-secondary hover:text-foreground'
                        : 'text-foreground-secondary/40 hover:text-foreground/60'
                    )}
                    aria-label="Live cursor settings"
                  >
                    {canvasCursorsOrgEnabled && (showOthersCursors || broadcastOwnCursor) ? (
                      <MousePointerClick className="h-3.5 w-3.5" strokeWidth={1.8} />
                    ) : (
                      <MousePointer2 className="h-3.5 w-3.5" strokeWidth={1.8} />
                    )}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="top" align="start" className="w-60 rounded-lg border-border bg-background-card shadow-lg">
                  <DropdownMenuLabel className="text-foreground font-semibold px-2 pt-2 pb-1">Live cursors</DropdownMenuLabel>
                  {!canvasCursorsOrgEnabled && organization?.role !== 'owner' && (
                    <p className="px-3 pb-1 text-xs text-muted-foreground">Disabled by org owner</p>
                  )}
                  <div className="pb-1">
                    {([
                      { label: 'Show others\' cursors', value: showOthersCursors && canvasCursorsOrgEnabled, toggle: persistShowOthers, disabled: !canvasCursorsOrgEnabled },
                      { label: 'Broadcast my cursor', value: broadcastOwnCursor && canvasCursorsOrgEnabled, toggle: persistBroadcastOwn, disabled: !canvasCursorsOrgEnabled },
                    ] as { label: string; value: boolean; toggle: (v: boolean) => void; disabled: boolean }[]).map(({ label, value, toggle, disabled }) => (
                      // Plain item, not CheckboxItem — the ON/OFF pill is the single state indicator
                      // (no redundant checkmark), and preventDefault keeps the menu open while toggling.
                      <DropdownMenuItem
                        key={label}
                        disabled={disabled}
                        onSelect={(e) => { e.preventDefault(); toggle(!value); }}
                        className={cn('gap-2 cursor-pointer', disabled && 'opacity-40 cursor-not-allowed')}
                      >
                        <span className="text-sm flex-1 text-foreground">{label}</span>
                        <span
                          className={cn(
                            'ml-auto text-xs font-medium px-2 py-0.5 rounded-md border transition-colors min-w-[28px] text-center',
                            value
                              ? 'border-foreground/60 bg-foreground/10 text-foreground'
                              : 'border-border bg-transparent text-muted-foreground',
                          )}
                        >
                          {value ? 'ON' : 'OFF'}
                        </span>
                      </DropdownMenuItem>
                    ))}
                  </div>
                  {organization?.role === 'owner' && (
                    <>
                      <DropdownMenuSeparator />
                      <div className="pt-1 pb-1.5">
                        <p className="text-[11px] text-muted-foreground mb-1 font-medium uppercase tracking-wide px-2">Org settings</p>
                        <DropdownMenuItem
                          onSelect={(e) => { e.preventDefault(); toggleOrgCursorsEnabled(!canvasCursorsOrgEnabled); }}
                          className="gap-2 cursor-pointer"
                        >
                          <span className="text-sm flex-1 text-foreground">Enable for org</span>
                          <span
                            className={cn(
                              'ml-auto text-xs font-medium px-2 py-0.5 rounded-md border transition-colors min-w-[28px] text-center',
                              canvasCursorsOrgEnabled
                                ? 'border-foreground/60 bg-foreground/10 text-foreground'
                                : 'border-border bg-transparent text-muted-foreground',
                            )}
                          >
                            {canvasCursorsOrgEnabled ? 'ON' : 'OFF'}
                          </span>
                        </DropdownMenuItem>
                      </div>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        )}
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
                onNodeDragStart={handleNodeDragStart}
                onNodeDrag={handleNodeDrag}
                onNodeDragStop={handleNodeDragStop}
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
                nodesDraggable={canManageCanvas && !stillShowingSkeleton}
                nodesConnectable={false}
                panOnDrag={true}
                zoomOnScroll={true}
                zoomOnPinch={true}
                defaultEdgeOptions={
                  {
                    type: 'smoothstep',
                    style: { stroke: ORG_OVERVIEW_EDGE_STROKE, strokeWidth: 1 },
                    pathOptions: { borderRadius: 20 },
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  } as any
                }
              >
                <ReactiveDotGrid />
                <OrgCanvasCursors
                  remoteCursors={organization && canvasCursorsOrgEnabled && showOthersCursors ? canvasChannel.remoteCursors : EMPTY_CURSORS}
                  onLocalCursorMove={organization && canvasCursorsOrgEnabled && broadcastOwnCursor ? canvasChannel.sendLocal : noopCursorMove}
                  onLocalCursorLeave={organization && canvasCursorsOrgEnabled && broadcastOwnCursor ? canvasChannel.sendLeave : undefined}
                  remoteDraggers={organization && canvasCursorsOrgEnabled && showOthersCursors ? remoteDraggers : EMPTY_DRAGGERS}
                  graphNodes={graphNodes}
                />
              </ReactFlow>
            </div>
          </div>

          {/* Org sidebar: slides in from right, inside the graph area */}
          {orgSidebarOpen && organization && (
            <div
              className={cn(
                'absolute top-6 bottom-0 right-0 w-[calc(100%_-_3rem)] max-w-[1000px] sm:max-w-[1200px] bg-background-card-header border-l border-t border-border rounded-tl-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-300 ease-out z-20',
                orgSidebarVisible ? 'translate-x-0' : 'translate-x-full'
              )}
            >
            {/* Header - Org avatar and name */}
            <div className="flex-shrink-0 flex items-center justify-between gap-4 px-5 pt-5 pb-3">
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
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
                aria-label="Close"
              >
                <PanelRight className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 pt-3 pb-5">
              <ProjectsAssetTable
                summaries={orgSidebarSecuritySummary}
                projects={orgSidebarProjects}
                loading={orgSidebarLoading}
                error={orgSidebarError}
                onRetry={() => setOrgSidebarRefetch((n) => n + 1)}
                onProjectClick={openProjectInSidebar}
                showTeamColumn
                errorContext="this organization's projects"
                emptyHint="Connect a repository to start seeing findings across your organization."
              />
            </div>
            </div>
          )}

          {/* Team sidebar: slides in from right, inside the graph area */}
          {teamSidebarOpen && selectedTeamId && (
            <div
              className={cn(
                'absolute top-6 bottom-0 right-0 w-[calc(100%_-_3rem)] max-w-[1000px] sm:max-w-[1200px] bg-background-card-header border-l border-t border-border rounded-tl-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-300 ease-out z-20',
                teamSidebarVisible ? 'translate-x-0' : 'translate-x-full'
              )}
            >
            {/* Header */}
            <div className="flex-shrink-0 flex items-center justify-between gap-4 px-5 pt-5 pb-5">
              <div className="flex items-center gap-3 min-w-0">
                <h2 className="text-lg font-semibold text-foreground truncate">{selectedTeamName ?? 'Team'}</h2>
              </div>
              <button
                type="button"
                onClick={closeTeamSidebar}
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
                aria-label="Close"
              >
                <PanelRight className="h-4 w-4" />
              </button>
            </div>
            {/* Tabs */}
            <div className="flex-shrink-0 px-5 border-b border-border">
              <div className="flex items-center gap-6">
                {(['findings', 'projects', 'members', 'settings'] as const).map((tab) => (
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
                <ProjectsAssetTable
                  summaries={teamSidebarSecuritySummary}
                  projects={teamSidebarProjects}
                  loading={teamSidebarDataLoading}
                  error={teamSidebarError}
                  onRetry={() => setTeamSidebarRefetch((n) => n + 1)}
                  onProjectClick={openProjectInSidebar}
                  showTeamColumn={false}
                  searchPlaceholder="Search projects, repos…"
                  emptyHint="This team doesn't have any projects yet."
                  errorContext="this team's projects"
                  action={(teamSidebarPermissions?.manage_projects || teamSidebarHasOrgManagePermission) ? (
                    <Button
                      variant="green"
                      onClick={() => navigate(`/organizations/${orgId}/new-project`, {
                        state: {
                          lockedTeam: teamSidebarTeamData ?? null,
                          teams: Object.values(teamsById),
                        },
                      })}
                      className="shrink-0"
                    >
                      Create Project
                    </Button>
                  ) : undefined}
                />
              )}

              {/* Findings Tab */}
              {teamSidebarTab === 'findings' && (() => {
                const securityRows = teamSidebarFindingRows;
                return (
                  <div className="space-y-4">
                    {teamSidebarFindingsError ? (
                      <SidebarErrorState
                        title="Couldn't load findings"
                        context="this team's findings"
                        onRetry={() => void loadTeamFindings()}
                      />
                    ) : teamSidebarFindingsLoading && securityRows.length === 0 ? (
                      <OrganizationVulnerabilitiesTableSkeleton />
                    ) : securityRows.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-12 text-center">
                        <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
                          <Shield className="h-6 w-6 text-foreground-secondary" />
                        </div>
                        <h3 className="text-base font-medium text-foreground mb-1">No findings</h3>
                        <p className="text-sm text-foreground-secondary max-w-[240px]">
                          {teamSidebarProjects.length === 0
                            ? "This team doesn't have any projects yet."
                            : "All projects in this team are clean — no open findings across any scanner."}
                        </p>
                      </div>
                    ) : (
                      <VulnerabilityExpandableTable
                        organizationId={orgId!}
                        rows={securityRows}
                        baseImageRecommendations={teamSidebarBaseImageRecs}
                        onStatusChange={() => { void loadTeamFindings(); void loadTrackerLinks(); }}
                        canManageFindings={!!organization?.permissions?.manage_teams_and_projects}
                        canTriggerFix={!!organization?.permissions?.trigger_fix}
                        trackerLinks={trackerLinks}
                        groupSuppressions={groupSuppressions}
                        acknowledgements={acknowledgements}
                        onTrackerChange={() => void loadTrackerLinks()}
                        onAckChange={() => void loadTrackerLinks()}
                      />
                    )}
                  </div>
                );
              })()}
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
                        onKeyDown={(e) => { if (e.key === 'Escape' && teamSidebarMembersSearch) { e.preventDefault(); setTeamSidebarMembersSearch(''); } }}
                        className={`w-full pl-9 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:border-foreground-secondary/50 focus:ring-1 focus:ring-foreground-secondary/20 ${teamSidebarMembersSearch ? 'pr-14' : 'pr-4'}`}
                      />
                      {teamSidebarMembersSearch && (
                        <button
                          type="button"
                          onClick={() => setTeamSidebarMembersSearch('')}
                          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg border border-foreground/15 px-2 py-1 text-xs text-foreground-secondary transition-colors hover:bg-background-subtle/85 hover:text-foreground"
                          aria-label="Clear search (Esc)"
                        >
                          Esc
                        </button>
                      )}
                    </div>
                    {(teamSidebarCanAddMembers || teamSidebarHasOrgManagePermission) && (
                    <Button
                      variant="green"
                      onClick={() => setTeamSidebarAddMemberOpen(true)}
                      className="shrink-0"
                    >
                      Add Member
                    </Button>
                    )}
                  </div>

                  {/* Members List */}
                  {teamSidebarError ? (
                    <SidebarErrorState
                      title="Couldn't load members"
                      context="this team's members"
                          onRetry={() => setTeamSidebarRefetch((n) => n + 1)}
                    />
                  ) : teamSidebarDataLoading ? (
                    <div
                      className="bg-background-card border border-border rounded-lg overflow-hidden divide-y divide-border pointer-events-none select-none"
                      style={{
                        maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
                        WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
                      }}
                    >
                      {/* animate-pulse on the placeholder blocks, NOT the row — the divide-y borders
                          belong to the rows, so pulsing the row makes the borders flash in and out. */}
                      {[1, 2, 3, 4, 5, 6].map((i) => (
                        <div key={i} className="px-4 py-3 grid grid-cols-[1fr_auto_32px] gap-4 items-center">
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="h-10 w-10 bg-muted rounded-full flex-shrink-0 animate-pulse" />
                            <div className="min-w-0">
                              <div className="h-4 bg-muted rounded w-24 mb-1 animate-pulse" />
                              <div className="h-3 bg-muted rounded w-32 animate-pulse" />
                            </div>
                          </div>
                          <div className="h-6 bg-muted rounded w-20 animate-pulse" />
                          <div className="h-4 w-4 bg-muted rounded justify-self-end animate-pulse" />
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
              {/* Settings needs teamSidebarTeamData — skeleton while it loads, error card when the
                  eager load failed; never a silent blank tab. */}
              {teamSidebarTab === 'settings' && !teamSidebarTeamData && teamSidebarDataLoading && (
                <TeamSettingsSkeleton />
              )}
              {teamSidebarTab === 'settings' && !teamSidebarTeamData && !teamSidebarDataLoading && teamSidebarError && (
                <SidebarErrorState
                  title="Couldn't load team settings"
                  context="this team's settings"
                  onRetry={() => setTeamSidebarRefetch((n) => n + 1)}
                />
              )}
              {teamSidebarTab === 'settings' && teamSidebarTeamData && (
                <div className="flex gap-6">
                  {/* Settings Sidebar — two short items; keep the column tight so content gets the width */}
                  <aside className="w-32 flex-shrink-0">
                    <nav className="space-y-1">
                      <button
                        type="button"
                        onClick={() => { setTeamSettingsSubTab('general'); setSidebarParams({ subtab: 'general' }); }}
                        className={cn(
                          'group w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors',
                          teamSettingsSubTab === 'general' ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
                        )}
                      >
                        <Settings className="h-4 w-4 tab-icon-shake" />
                        General
                      </button>
                      {((teamSidebarPermissions?.view_roles || teamSidebarPermissions?.edit_roles) || teamSidebarHasOrgManagePermission) && (
                        <button
                          type="button"
                          onClick={() => { setTeamSettingsSubTab('roles'); setSidebarParams({ subtab: 'roles' }); }}
                          className={cn(
                            'group w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors',
                            teamSettingsSubTab === 'roles' ? 'text-foreground' : 'text-foreground-secondary hover:text-foreground'
                          )}
                        >
                          <Users className="h-4 w-4 tab-icon-shake" />
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

                        {/* Team details */}
                        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                          <div className="p-6">
                            <h3 className="text-base font-semibold text-foreground mb-4">Team details</h3>
                            <div className="space-y-4">
                              <div className="max-w-md">
                                <label className="block text-sm font-medium text-foreground mb-1.5">Name</label>
                                <input
                                  type="text"
                                  value={teamSettingsName}
                                  onChange={(e) => teamSettingsCanManageSettings && setTeamSettingsName(e.target.value)}
                                  readOnly={!teamSettingsCanManageSettings}
                                  placeholder="Enter team name"
                                  className={cn("w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors", !teamSettingsCanManageSettings && "opacity-60 cursor-not-allowed")}
                                />
                              </div>
                            </div>
                          </div>
                          {teamSettingsCanManageSettings ? (
                            <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-end">
                              <Button
                                variant="green"
                                onClick={handleTeamSettingsSave}
                                disabled={teamSettingsSaving || teamSettingsName === teamSidebarTeamData.name}
                                className="relative"
                              >
                                <span className={teamSettingsSaving ? 'invisible' : undefined}>Save</span>
                                {teamSettingsSaving && (
                                  <span className="absolute inset-0 flex items-center justify-center">
                                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  </span>
                                )}
                              </Button>
                            </div>
                          ) : (
                            <div className="px-6 py-3 bg-black/20 border-t border-border">
                              <p className="text-xs text-foreground-secondary flex items-center gap-1.5">
                                <Lock className="h-3 w-3" />
                                You don't have permission to edit these settings.
                              </p>
                            </div>
                          )}
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
                                    variant="destructive"
                                    className="flex-shrink-0"
                                  >
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
                                    autoFocus
                                    className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-colors"
                                  />
                                  <div className="flex gap-2">
                                    <Button
                                      onClick={handleTeamSettingsDelete}
                                      variant="destructive"
                                      disabled={teamSettingsDeleteConfirmText !== teamSidebarTeamData.name || teamSettingsDeleting}
                                    >
                                      <span className={teamSettingsDeleting ? 'invisible' : undefined}>Delete Forever</span>
                                      {teamSettingsDeleting && (
                                        <span className="absolute inset-0 flex items-center justify-center">
                                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                        </span>
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

                    {/* Roles Settings */}
                    {teamSettingsSubTab === 'roles' && orgId && selectedTeamId && (teamSidebarPermissions?.view_roles || teamSidebarPermissions?.edit_roles || teamSidebarHasOrgManagePermission) && (
                      <div className="space-y-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <h2 className="text-2xl font-bold text-foreground">Roles</h2>
                            <p className="text-foreground-secondary mt-2 text-sm">Manage roles and permissions for your team.</p>
                          </div>
                          {teamSettingsCanManageSettings && (teamSidebarPermissions?.edit_roles || teamSidebarHasOrgManagePermission) && (
                            <Button
                              variant="green"
                              onClick={() => {
                                setTeamSettingsShowAddRoleSidepanel(true);
                                requestAnimationFrame(() => setTeamSettingsAddRolePanelVisible(true));
                              }}
                            >
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
                            {(teamSettingsDragPreviewRoles || teamSidebarRoles).map((role) => {
                              const isUserRole = teamSidebarTeamData?.role === role.name;
                              const displayRoles = teamSettingsDragPreviewRoles || teamSidebarRoles;
                              const userRoleIndex = displayRoles.findIndex((r) => r.name === teamSidebarTeamData?.role);
                              const roleIndex = displayRoles.findIndex((r) => r.id === role.id);
                              const isRoleBelowUserRank = userRoleIndex !== -1 && roleIndex !== -1 && roleIndex > userRoleIndex;
                              const isTopRankedRole = role.display_order === 0;
                              const isUserTopRanked = userRoleIndex === 0;
                              const canEditRole = teamSettingsCanManageSettings && (teamSidebarHasOrgManagePermission || isRoleBelowUserRank || (isUserRole && isUserTopRanked));
                              const canDeleteRole = teamSettingsCanManageSettings && (teamSidebarHasOrgManagePermission || isRoleBelowUserRank) && !isTopRankedRole;
                              const canDrag = teamSettingsCanManageSettings && displayRoles.length > 1 &&
                                (teamSidebarHasOrgManagePermission || (!isTopRankedRole && isRoleBelowUserRank && !isUserRole));
                              const isDragging = teamSettingsDraggedRoleId === role.id;
                              const memberCount = teamSettingsMemberCountByRole.get(role.name) ?? 0;

                              return (
                                <div
                                  key={role.id || role.name}
                                  className={cn('px-4 py-3 flex items-center justify-between group transition-all', isDragging ? 'opacity-50 bg-foreground/10 scale-[0.98]' : 'hover:bg-table-hover')}
                                  draggable={canDrag}
                                  onDragStart={(e) => { if (!canDrag) return; setTeamSettingsDraggedRoleId(role.id); setTeamSettingsDragPreviewRoles([...teamSidebarRoles]); e.dataTransfer.effectAllowed = 'move'; }}
                                  onDragEnd={() => { if (teamSettingsDragPreviewRoles) setTeamSettingsDragPreviewRoles(null); setTeamSettingsDraggedRoleId(null); }}
                                  onDragOver={(e) => { e.preventDefault(); if (teamSettingsDraggedRoleId && teamSettingsDraggedRoleId !== role.id) handleTeamSettingsDragPreview(teamSettingsDraggedRoleId, role.id); }}
                                  onDrop={(e) => { e.preventDefault(); handleTeamSettingsDragReorder(); setTeamSettingsDraggedRoleId(null); }}
                                >
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
                                        <Tooltip>
                                          <TooltipTrigger asChild>
                                            <Button
                                              variant="ghost"
                                              size="icon"
                                              onClick={() => handleTeamSettingsEditRolePermissions(role, canEditRole)}
                                              className="h-7 w-7 text-foreground-secondary hover:text-foreground"
                                            >
                                              <Settings className="h-4 w-4" />
                                            </Button>
                                          </TooltipTrigger>
                                          <TooltipContent>{canEditRole ? 'Settings' : 'View settings (read-only)'}</TooltipContent>
                                        </Tooltip>
                                        {canDeleteRole && (
                                          <Tooltip>
                                            <TooltipTrigger asChild>
                                              <Button
                                                variant="ghost"
                                                size="icon"
                                                onClick={() => handleTeamSettingsDeleteRole(role)}
                                                disabled={teamSettingsDeletingRoleId === role.id}
                                                className="h-7 w-7 text-foreground-secondary hover:text-destructive disabled:opacity-100"
                                              >
                                                {teamSettingsDeletingRoleId === role.id ? (
                                                  <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full" />
                                                ) : (
                                                  <Trash2 className="h-4 w-4" />
                                                )}
                                              </Button>
                                            </TooltipTrigger>
                                            <TooltipContent>Delete</TooltipContent>
                                          </Tooltip>
                                        )}
                                        {canDrag && (
                                          <div className="cursor-grab active:cursor-grabbing text-foreground-secondary hover:text-foreground transition-colors">
                                            <GripVertical className="h-4 w-4" />
                                          </div>
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
                'absolute top-6 bottom-0 right-0 w-[calc(100%_-_3rem)] max-w-[1000px] sm:max-w-[1200px] bg-background-card-header border-l border-t border-border rounded-tl-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-300 ease-out z-20',
                projectSidebarVisible ? 'translate-x-0' : 'translate-x-full'
              )}
            >
              <div className="flex-shrink-0 flex items-center justify-between gap-4 px-5 pt-5 pb-5">
                <div className="flex items-center gap-3 min-w-0">
                  <FrameworkIcon frameworkId={selectedProjectFramework ?? undefined} size={20} className="flex-shrink-0 text-muted-foreground" />
                  <h2 className="text-lg font-semibold text-foreground truncate">{selectedProjectName ?? 'Project'}</h2>
                  {selectedProjectEffectiveIsExtracting && !selectedProjectEffectiveIsInitialExtracting ? (
                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 flex-shrink-0 flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      Syncing
                    </span>
                  ) : null}
                </div>
                <button
                  type="button"
                  onClick={closeProjectSidebar}
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
                  aria-label="Close"
                >
                  <PanelRight className="h-4 w-4" />
                </button>
              </div>
              <div className="flex-shrink-0 px-5 border-b border-border">
                <div className="flex items-center gap-6">
                  {/* MVP scope cut: 'compliance' tab parked (compliance feature shelved). */}
                  {(['findings', 'dependencies', 'settings'] as const).map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      onClick={() => { setProjectSidebarTab(tab); setSidebarParams({ tab, subtab: null }); setProjectFindingToOpen(null); }}
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
                  projectSidebarTab === 'findings' ? 'py-5' : 'pb-5 pt-0'
                )}
              >
{projectSidebarTab === 'findings' && (
                  <div className="space-y-4">
                    {projectStats?.malicious_packages?.scan_status === 'partial' && (
                      <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                        <span className="font-semibold">Partial coverage:</span> the malicious-package scan
                        completed with gaps — some packages could not be scanned this run. Findings shown below
                        are still accurate; investigate <span className="font-mono">extraction_step_errors</span> for
                        the affected packages.
                      </div>
                    )}
                    {selectedProjectEffectiveIsInitialExtracting ? (
                      <ExtractionProgressCard
                        title="Project extraction still in progress"
                        description="Vulnerabilities will appear here once extraction completes."
                        showLogsToggle
                        organizationId={orgId}
                        projectId={selectedProjectId ?? ''}
                      />
                    ) : selectedProjectExtractionFailed ? (
                      <ExtractionProgressCard
                        isError
                        description="Check the logs for details on what went wrong."
                        showLogsToggle
                        organizationId={orgId}
                        projectId={selectedProjectId ?? ''}
                        onRetry={async () => {
                          if (!orgId || !selectedProjectId) return;
                          try {
                            await api.triggerProjectSync(orgId, selectedProjectId);
                          } catch (err: any) {
                            toast({ title: 'Retry failed', description: err?.message || 'Could not retry extraction', variant: 'destructive' });
                          }
                        }}
                      />
                    ) : (projectStatsLoading && !projectVulnerabilities) || selectedProjectRealtime.isLoading ? (
                      <OrgProjectVulnerabilitiesTableSkeleton />
                    ) : !projectSecurityRows.length ? (
                      // No findings for the active run. Distinguish a genuinely
                      // clean finalized scan from one that never finished: a
                      // crashed/incomplete run has status 'error' and no active
                      // run, so showing "No findings" would be misleading.
                      selectedProjectRealtime.status === 'error' ? (
                        <ExtractionProgressCard
                          isError
                          title="Scan didn't finish"
                          description="The last scan stopped before it completed, so there are no results to show yet. Re-run the scan to try again."
                          showLogsToggle
                          organizationId={orgId}
                          projectId={selectedProjectId ?? ''}
                          onRetry={async () => {
                            if (!orgId || !selectedProjectId) return;
                            try {
                              await api.triggerProjectSync(orgId, selectedProjectId);
                            } catch (err: any) {
                              toast({ title: 'Retry failed', description: err?.message || 'Could not retry the scan', variant: 'destructive' });
                            }
                          }}
                        />
                      ) : (
                        <div className="py-8 text-center text-sm text-muted-foreground border border-border rounded-lg bg-background-subtle/50">
                          No findings
                        </div>
                      )
                    ) : (
                      <VulnerabilityExpandableTable
                        organizationId={orgId!}
                        projectId={selectedProjectId ?? undefined}
                        rows={projectSecurityRows}
                        canTriggerFix={!!organization?.permissions?.trigger_fix}
                        trackerLinks={trackerLinks}
                        groupSuppressions={groupSuppressions}
                        acknowledgements={acknowledgements}
                        onTrackerChange={() => void loadTrackerLinks()}
                        onAckChange={() => void loadTrackerLinks()}
                        baseImageRecommendations={projectBaseImageRecs}
                        openFindingId={projectFindingToOpen}
                        onStatusChange={() => {
                          if (orgId && selectedProjectId) {
                            void Promise.all([
                              api.getProjectVulnerabilities(orgId, selectedProjectId),
                              api.getProjectSecretFindings(orgId, selectedProjectId, 1, 50),
                              api.getProjectSemgrepFindings(orgId, selectedProjectId, 1, 50),
                            ])
                              .then(([v, s, g]) => {
                                setProjectVulnerabilities(v ?? []);
                                setProjectSecrets(s?.data ?? []);
                                setProjectSemgrep(g?.data ?? []);
                              })
                              .catch(() => {});
                            // Refresh IaC / container / malicious / DAST too so a
                            // suppress / risk-accept on any of them reflects.
                            void loadProjectExtraFindings(orgId, selectedProjectId);
                            // Group-row Ignore lives in the suppression table, not
                            // a finding store — reload it so the row updates too.
                            void loadTrackerLinks();
                          }
                        }}
                        canManageFindings={Boolean(organization?.permissions?.manage_teams_and_projects)}
                      />
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
                    onOpenFinding={handleOpenProjectFinding}
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
                    onProjectRenamed={handleProjectRenamed}
                    onProjectTransferred={handleProjectTransferred}
                  />
                )}
                {projectSidebarTab !== 'findings' && projectSidebarProjectLoading && (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                  </div>
                )}
                {projectSidebarTab !== 'findings' && !projectSidebarProjectLoading && !projectSidebarProject && (
                  <div className="py-8 text-center text-sm text-muted-foreground">Could not load project.</div>
                )}
              </div>
            </div>
          )}

      {/* Add Team Member dialog — mirrors the org Invite-member dialog chrome (InviteMemberDialog.tsx) */}
      {selectedTeamId && orgId && selectedTeamId !== UNGROUPED_TEAM_ID && (
        <Dialog open={teamSidebarAddMemberOpen} onOpenChange={(next) => { if (!next) closeTeamSidebarAddMember(); }}>
          <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
            <div className="px-6 pt-6 pb-4 flex-shrink-0">
              <DialogTitle>Add team member</DialogTitle>
              <DialogDescription className="mt-1">
                Add existing members of your organization to this team and assign them a role.
              </DialogDescription>
            </div>

            <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto flex-1 min-h-0">
              <div className="grid gap-2">
                <label className="text-sm font-medium text-foreground">Members</label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
                  <input
                    type="text"
                    placeholder="Search organization members…"
                    value={addMemberSearchQuery}
                    onChange={(e) => setAddMemberSearchQuery(e.target.value)}
                    className="w-full pl-9 pr-4 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:border-foreground-secondary/50 focus:ring-1 focus:ring-foreground-secondary/20"
                  />
                </div>
                <div className="h-56 overflow-y-auto border border-border rounded-md">
                  {teamSidebarFilteredAvailableMembers.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-center px-4">
                      <Users className="h-8 w-8 text-muted-foreground/50 mb-2" />
                      <p className="text-sm font-medium text-foreground-secondary">
                        {addMemberSearchQuery.trim() ? 'No members match your search' : 'All organization members are already in this team'}
                      </p>
                    </div>
                  ) : (
                    teamSidebarFilteredAvailableMembers.map((member) => {
                      const selected = addMemberSelectedUserIds.includes(member.user_id);
                      return (
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
                            selected ? 'bg-background-card/80' : 'hover:bg-background-card/60'
                          )}
                        >
                          <img
                            src={member.avatar_url || '/images/blank_profile_image.png'}
                            alt={member.full_name || member.email}
                            className="h-8 w-8 rounded-full object-cover border border-border flex-shrink-0"
                            referrerPolicy="no-referrer"
                            onError={(e) => { e.currentTarget.src = '/images/blank_profile_image.png'; }}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-foreground truncate">{member.full_name || 'Unknown'}</div>
                            <div className="text-xs text-foreground-secondary truncate">{member.email}</div>
                          </div>
                          <span
                            className={cn(
                              'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-colors',
                              selected ? 'bg-foreground border-foreground text-background' : 'border-border'
                            )}
                          >
                            {selected && <Check className="h-3 w-3" />}
                          </span>
                        </button>
                      );
                    })
                  )}
                </div>
              </div>

              <div className="grid gap-2">
                <label className="text-sm font-medium text-foreground">Role</label>
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

            <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
              <Button variant="outline" onClick={closeTeamSidebarAddMember} disabled={addMemberAdding} className="h-8 rounded-lg px-3">
                Cancel
              </Button>
              <Button
                variant="green"
                onClick={async () => {
                  if (!orgId || !selectedTeamId || addMemberSelectedUserIds.length === 0) return;
                  const role = teamSidebarRoles.find((r) => r.name === addMemberSelectedRoleId);
                  const roleId = role?.id;
                  const userIds = addMemberSelectedUserIds;
                  // Build optimistic rows from the org-member data we already hold, so the
                  // members appear instantly instead of waiting on the slow post-add refetch
                  // (getTeamMembers + getOrganizationMembers each fan out a per-user
                  // auth.admin.getUserById call — multiple seconds for a large org).
                  const optimistic: TeamMember[] = userIds
                    .map((uid) => teamSidebarOrgMembers.find((m) => m.user_id === uid))
                    .filter((m): m is OrganizationMember => !!m)
                    .map((m) => ({
                      user_id: m.user_id,
                      email: m.email,
                      full_name: m.full_name ?? null,
                      avatar_url: m.avatar_url ?? null,
                      role: role?.name ?? 'member',
                      role_display_name: role?.display_name ?? null,
                      role_color: role?.color ?? null,
                      rank: role?.display_order ?? 999,
                      org_rank: m.rank ?? 999,
                      permissions: role?.permissions,
                      created_at: new Date().toISOString(),
                    }));
                  setAddMemberAdding(true);
                  try {
                    await Promise.all(
                      userIds.map((uid) => api.addTeamMember(orgId, selectedTeamId, uid, roleId))
                    );
                    // Show them immediately + close; don't block the UI on the refetch.
                    setTeamSidebarMembers((prev) => [
                      ...prev,
                      ...optimistic.filter((nm) => !prev.some((p) => p.user_id === nm.user_id)),
                    ]);
                    toast({
                      title: 'Success',
                      description: userIds.length === 1 ? 'Member added to team' : 'Members added to team',
                    });
                    closeTeamSidebarAddMember();
                    // Reconcile against server truth in the background (exact ranks, etc.)
                    // and refresh the available-members list.
                    Promise.all([
                      api.getTeamMembers(orgId, selectedTeamId),
                      api.getOrganizationMembers(orgId),
                    ])
                      .then(([members, orgMembers]) => {
                        setTeamSidebarMembers(members);
                        setTeamSidebarOrgMembers(orgMembers);
                      })
                      .catch(() => { /* optimistic state stands; next open refetches */ });
                  } catch (err: any) {
                    toast({
                      title: 'Error',
                      description: err?.message || 'Failed to add member',
                      variant: 'destructive',
                    });
                    // A multi-add Promise.all can partially succeed server-side — reconcile the
                    // list against server truth so successfully-added members still show up.
                    api.getTeamMembers(orgId, selectedTeamId)
                      .then((members) => setTeamSidebarMembers(members))
                      .catch(() => { /* next sidebar open refetches */ });
                  } finally {
                    setAddMemberAdding(false);
                  }
                }}
                disabled={addMemberSelectedUserIds.length === 0 || addMemberAdding}
                className="relative"
              >
                <span className={addMemberAdding ? 'invisible' : undefined}>
                  {addMemberSelectedUserIds.length <= 1 ? 'Add member' : `Add ${addMemberSelectedUserIds.length} members`}
                </span>
                {addMemberAdding && (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <Loader2 className="h-4 w-4 animate-spin" />
                  </span>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}

      {/* Team Sidebar: Change Role dialog — same chrome as the Add-team-member dialog */}
      {selectedTeamId && (
        <Dialog open={teamSidebarRoleChangeOpen} onOpenChange={(next) => { if (!next) setTeamSidebarRoleChangeOpen(false); }}>
          <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
            <div className="px-6 pt-6 pb-4 flex-shrink-0">
              <DialogTitle>Change role</DialogTitle>
              <DialogDescription className="mt-1">
                Select a new role for {teamSidebarMemberToChangeRole?.full_name || teamSidebarMemberToChangeRole?.email?.split('@')[0] || 'this member'}.
              </DialogDescription>
            </div>

            <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto flex-1 min-h-0">
              <div className="flex items-center gap-3 p-3 bg-background-card border border-border rounded-md">
                <img
                  src={teamSidebarMemberToChangeRole?.avatar_url || '/images/blank_profile_image.png'}
                  alt={teamSidebarMemberToChangeRole?.full_name || teamSidebarMemberToChangeRole?.email || ''}
                  className="h-10 w-10 rounded-full object-cover border border-border flex-shrink-0"
                  referrerPolicy="no-referrer"
                  onError={(e) => { e.currentTarget.src = '/images/blank_profile_image.png'; }}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-foreground truncate">
                    {teamSidebarMemberToChangeRole?.full_name || teamSidebarMemberToChangeRole?.email?.split('@')[0]}
                  </div>
                  <div className="text-xs text-foreground-secondary truncate">
                    {teamSidebarMemberToChangeRole?.email}
                  </div>
                </div>
              </div>
              <div className="grid gap-2">
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

            <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
              <Button
                variant="outline"
                onClick={() => setTeamSidebarRoleChangeOpen(false)}
                disabled={teamSidebarUpdatingRole}
                className="h-8 rounded-lg px-3"
              >
                Cancel
              </Button>
              <Button
                variant="green"
                onClick={handleTeamSidebarUpdateRole}
                disabled={teamSidebarUpdatingRole}
                className="relative"
              >
                <span className={teamSidebarUpdatingRole ? 'invisible' : undefined}>Update role</span>
                {teamSidebarUpdatingRole && (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <Loader2 className="h-4 w-4 animate-spin" />
                  </span>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}

      {/* Team Sidebar: Leave/Remove confirmation dialog — same chrome as the other team dialogs */}
      {selectedTeamId && (
        <Dialog open={teamSidebarRemoveConfirmOpen} onOpenChange={(next) => { if (!next) setTeamSidebarRemoveConfirmOpen(false); }}>
          <DialogContent hideClose className="sm:max-w-md bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
            <div className="px-6 pt-6 pb-4 flex-shrink-0">
              <DialogTitle>{user?.id === teamSidebarMemberToRemove ? 'Leave team' : 'Remove member'}</DialogTitle>
              <DialogDescription className="mt-1">
                {user?.id === teamSidebarMemberToRemove
                  ? 'Are you sure you want to leave this team? You will need to be re-added by a team admin to rejoin.'
                  : 'Are you sure you want to remove this member from the team?'}
              </DialogDescription>
            </div>

            <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
              <Button
                variant="outline"
                onClick={() => setTeamSidebarRemoveConfirmOpen(false)}
                disabled={teamSidebarRemovingMember}
                className="h-8 rounded-lg px-3"
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={confirmTeamSidebarRemoveMember}
                disabled={teamSidebarRemovingMember}
                className="relative"
              >
                <span className={teamSidebarRemovingMember ? 'invisible' : undefined}>
                  {user?.id === teamSidebarMemberToRemove ? 'Leave team' : 'Remove member'}
                </span>
                {teamSidebarRemovingMember && (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <Loader2 className="h-4 w-4 animate-spin" />
                  </span>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}

      {/* Team Settings: Create New Role Sidepanel */}
      {teamSettingsShowAddRoleSidepanel && selectedTeamId && orgId && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm animate-in fade-in duration-150"
            onClick={() => setTeamSettingsShowAddRoleSidepanel(false)}
          />
          <div
            className="relative w-full max-w-[680px] max-h-[85vh] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
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
                    className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors"
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
                      <Tooltip key={color}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setTeamSettingsNewRoleColor(color)}
                            disabled={teamSettingsIsCreatingRole}
                            className={cn(
                              'h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center',
                              teamSettingsNewRoleColor === color ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'
                            )}
                            style={{ backgroundColor: color }}
                          >
                            {teamSettingsNewRoleColor === color && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>{name}</TooltipContent>
                      </Tooltip>
                    ))}
                    {teamSettingsNewRoleColor && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setTeamSettingsNewRoleColor('')}
                            disabled={teamSettingsIsCreatingRole}
                            className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>Clear color</TooltipContent>
                      </Tooltip>
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
            <div className="px-6 py-4 flex items-center justify-between gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
              <Button variant="outline" onClick={() => setTeamSettingsShowAddRoleSidepanel(false)} disabled={teamSettingsIsCreatingRole} className="!h-8 !px-3 !rounded-lg">
                Cancel
              </Button>
              <Button
                variant="green"
                onClick={() => handleTeamSettingsCreateRole(teamSettingsNewRolePermissions)}
                disabled={teamSettingsIsCreatingRole || !teamSettingsNewRoleNameInput.trim()}
              >
                <span className={teamSettingsIsCreatingRole ? 'invisible' : undefined}>Create Role</span>
                {teamSettingsIsCreatingRole && (
                  <span className="absolute inset-0 flex items-center justify-center">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  </span>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Team Settings: Edit Role Modal */}
      {teamSettingsShowRoleSettingsModal && teamSettingsSelectedRoleForSettings && teamSettingsEditingRolePermissions && selectedTeamId && orgId && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm animate-in fade-in duration-150"
            onClick={() => setTeamSettingsShowRoleSettingsModal(false)}
          />
          <div
            className="relative w-full max-w-[680px] max-h-[85vh] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-3 flex-shrink-0">
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
                    className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors disabled:opacity-60"
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
                      <Tooltip key={color}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setTeamSettingsEditingRoleColor(color)}
                            disabled={!teamSettingsCanEditSelectedRole || teamSettingsIsSavingRole}
                            className={cn(
                              'h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center disabled:opacity-60',
                              teamSettingsEditingRoleColor === color ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'
                            )}
                            style={{ backgroundColor: color }}
                          >
                            {teamSettingsEditingRoleColor === color && <Check className="h-4 w-4 text-white drop-shadow-md" />}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>{name}</TooltipContent>
                      </Tooltip>
                    ))}
                    {teamSettingsEditingRoleColor && teamSettingsCanEditSelectedRole && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setTeamSettingsEditingRoleColor('')}
                            disabled={teamSettingsIsSavingRole}
                            className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>Clear color</TooltipContent>
                      </Tooltip>
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
            <div className="px-6 py-4 flex items-center justify-between gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
              <Button variant="outline" onClick={() => setTeamSettingsShowRoleSettingsModal(false)} disabled={teamSettingsIsSavingRole} className="!h-8 !px-3 !rounded-lg">
                {teamSettingsCanEditSelectedRole ? 'Cancel' : 'Close'}
              </Button>
              {teamSettingsCanEditSelectedRole && (
                <Button
                  variant="green"
                  onClick={handleTeamSettingsSaveRolePermissions}
                  disabled={teamSettingsIsSavingRole}
                >
                  <span className={teamSettingsIsSavingRole ? 'invisible' : undefined}>Save</span>
                  {teamSettingsIsSavingRole && (
                    <span className="absolute inset-0 flex items-center justify-center">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    </span>
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
