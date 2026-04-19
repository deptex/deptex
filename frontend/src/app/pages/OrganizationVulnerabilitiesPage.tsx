import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
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
import { Filter, Plus, Search, ShieldCheck, X, LayoutDashboard, FolderKanban, Shield, FileCode, Settings, Activity, UserPlus, Users, FolderPlus, ExternalLink, Loader2, Package, HeartPulse, ChevronRight, Check } from 'lucide-react';
import { Button } from '../../components/ui/button';
import {
  Dialog,
  DialogContent,
} from '../../components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { Checkbox } from '../../components/ui/checkbox';
import { api, Organization, Team, Project, TeamWithRole, type ProjectStats, type ProjectVulnerability, type OrganizationStatus, type TeamStats, type TeamMember, type ProjectDependency, type OrganizationMember, type TeamRole } from '../../lib/api';
import { cn } from '../../lib/utils';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../hooks/use-toast';
import {
  useOrganizationOverviewGraphLayout,
  ORG_CENTER_ID,
  type OverviewTeamWithProjects,
} from '../../components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout';
import { VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT } from '../../components/vulnerabilities-graph/useVulnerabilitiesGraphLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { SkeletonGroupCenterNode } from '../../components/vulnerabilities-graph/SkeletonGroupCenterNode';
import { VulnProjectNode } from '../../components/vulnerabilities-graph/VulnProjectNode';
import { ProjectCenterNode } from '../../components/vulnerabilities-graph/ProjectCenterNode';
import { SyncDetailSidebar } from '../../components/SyncDetailSidebar';
import { OrgMemberNode, MEMBER_NODE_WIDTH, MEMBER_NODE_HEIGHT } from '../../components/vulnerabilities-graph/OrgMemberNode';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { FrameworkIcon } from '../../components/framework-icon';
import { TeamIcon } from '../../components/TeamIcon';
import { RoleBadge } from '../../components/RoleBadge';
import { RoleDropdown } from '../../components/RoleDropdown';
import type { NodeTypes } from '@xyflow/react';

interface OrganizationContextType {
  organization: Organization | null;
}

const nodeTypes: NodeTypes = {
  groupCenterNode: GroupCenterNode,
  vulnProjectNode: VulnProjectNode,
  projectCenterNode: ProjectCenterNode,
  dependencyNode: DependencyNode,
  orgMemberNode: OrgMemberNode,
};

const skeletonNodeTypes: NodeTypes = {
  skeletonGroupCenterNode: SkeletonGroupCenterNode,
};

const ORG_SKELETON_CENTER_POS = {
  x: -VULN_CENTER_NODE_WIDTH / 2,
  y: -VULN_CENTER_NODE_HEIGHT / 2,
};

const orgSkeletonNodes = [
  {
    id: 'skeleton-org-center',
    type: 'skeletonGroupCenterNode',
    position: ORG_SKELETON_CENTER_POS,
    data: {},
  },
];

const UNGROUPED_TEAM_ID = 'org-ungrouped';
const UNGROUPED_TEAM_NAME = 'No team';

export type ExpandFilter = 'all' | 'vulnerable' | 'not_allowed' | 'outdated';

function projectStatusLabel(project: Project): { label: string; inProgress: boolean; isError: boolean } {
  const status = project.repo_status;
  if (status === 'initializing' || status === 'extracting' || status === 'analyzing' || status === 'finalizing') {
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

export default function OrganizationVulnerabilitiesPage() {
  const { id: orgId } = useParams<{ id: string }>();
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
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [selectedTeamName, setSelectedTeamName] = useState<string | null>(null);
  const [projectSidebarOpen, setProjectSidebarOpen] = useState(false);
  const [projectSidebarVisible, setProjectSidebarVisible] = useState(false);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [selectedProjectName, setSelectedProjectName] = useState<string | null>(null);
  const [selectedProjectFramework, setSelectedProjectFramework] = useState<string | null>(null);
  const [projectStats, setProjectStats] = useState<ProjectStats | null>(null);
  const [projectStatsLoading, setProjectStatsLoading] = useState(false);
  const [projectVulnerabilities, setProjectVulnerabilities] = useState<ProjectVulnerability[] | null>(null);
  const [statuses, setStatuses] = useState<OrganizationStatus[]>([]);
  const [selectedStatusIds, setSelectedStatusIds] = useState<Set<string>>(new Set());
  const [rawTeamsWithProjects, setRawTeamsWithProjects] = useState<OverviewTeamWithProjects[]>([]);
  const [graphRefreshTrigger, setGraphRefreshTrigger] = useState(0);
  const [expandingProjectId, setExpandingProjectId] = useState<string | null>(null);
  const [expandedProjectId, setExpandedProjectId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Node[]>([]);
  const [expandedEdges, setExpandedEdges] = useState<Edge[]>([]);
  const graphNodesRef = useRef<Node[]>([]);
  const [teamSidebarStats, setTeamSidebarStats] = useState<TeamStats | null>(null);
  const [teamSidebarMembers, setTeamSidebarMembers] = useState<TeamMember[]>([]);
  const [teamSidebarProjects, setTeamSidebarProjects] = useState<Project[]>([]);
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
  const [membersExpanded, setMembersExpanded] = useState(false);
  const [membersExpanding, setMembersExpanding] = useState(false);
  const [orgMembersList, setOrgMembersList] = useState<OrganizationMember[]>([]);
  const [syncDetailProjectId, setSyncDetailProjectId] = useState<string | null>(null);

  useEffect(() => {
    if (searchOpen) setTimeout(() => searchInputRef.current?.focus(), 0);
  }, [searchOpen]);

  useEffect(() => {
    const onTeamsUpdated = () => setGraphRefreshTrigger((t) => t + 1);
    const onProjectsUpdated = () => setGraphRefreshTrigger((t) => t + 1);
    window.addEventListener('organization:teamsUpdated', onTeamsUpdated);
    window.addEventListener('organization:projectsUpdated', onProjectsUpdated);
    return () => {
      window.removeEventListener('organization:teamsUpdated', onTeamsUpdated);
      window.removeEventListener('organization:projectsUpdated', onProjectsUpdated);
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
            const isExtracting = ['initializing', 'extracting', 'analyzing', 'finalizing'].includes(repoStatus || '');
            byTeam.get(bucket)!.push({
              projectId: p.id,
              projectName: p.name,
              framework: p.framework ?? null,
              statusName: p.status_name ?? p.status ?? null,
              statusColor: p.status_color ?? null,
              statusId: p.status_id ?? null,
              assetTierName: p.asset_tier_name ?? null,
              dependenciesCount: (p as Project).direct_dependencies_count ?? (p as Project).dependencies_count ?? null,
              isExtracting,
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

        if (realTeamIds.length === 0) {
          applyResult(new Map());
        } else {
          const teamRolePromises = realTeamIds.map((tid) =>
            api.getTeam(organization.id, tid).then((team: TeamWithRole) => ({
              teamId: tid,
              roleLabel: team.role_display_name ?? team.role ?? null,
              roleColor: team.role_color ?? null,
            }))
          );
          Promise.all(teamRolePromises).then((roleList) => {
            if (cancelled) return;
            const roleByTeamId = new Map<string, { label: string | null; color: string | null }>();
            roleList.forEach(({ teamId, roleLabel, roleColor }) =>
              roleByTeamId.set(teamId, { label: roleLabel, color: roleColor })
            );
            applyResult(roleByTeamId);
          }).catch(() => {
            if (!cancelled) applyResult(new Map());
          });
        }
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

  const teamsWithProjects = useMemo(() => {
    if (selectedStatusIds.size === 0) return rawTeamsWithProjects;
    return rawTeamsWithProjects.map((t) => ({
      ...t,
      projects: t.projects.filter(
        (proj) => proj.statusId != null && selectedStatusIds.has(proj.statusId)
      ),
    }));
  }, [rawTeamsWithProjects, selectedStatusIds]);

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
    teamsWithProjects,
    organization?.avatar_url || '/images/org_profile.png',
    orgRoleLabel,
    orgRoleColor,
    organization?.id ?? null
  );

  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>([]);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const stillShowingSkeleton = loading && teamsWithProjects.length === 0;

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (!orgId) return;
      if (node.id === ORG_CENTER_ID) {
        setOrgSidebarOpen(true);
        requestAnimationFrame(() => setOrgSidebarVisible(true));
        return;
      }
      const d = node.data as { projectId?: string; projectName?: string; isTeamNode?: boolean; framework?: string | null; organizationId?: string };
      if (node.type === 'projectCenterNode' && d.projectId && d.organizationId) {
        setSyncDetailProjectId(d.projectId);
        return;
      }
      if (d.projectId && d.isTeamNode) {
        setSelectedTeamId(d.projectId);
        setSelectedTeamName((d.projectName as string) ?? null);
        setTeamSidebarOpen(true);
        requestAnimationFrame(() => setTeamSidebarVisible(true));
        return;
      }
      if (d.projectId) {
        setSelectedProjectId(d.projectId);
        setSelectedProjectName((d.projectName as string) ?? null);
        setSelectedProjectFramework(d.framework ?? null);
        setProjectStats(null);
        setProjectSidebarOpen(true);
        requestAnimationFrame(() => setProjectSidebarVisible(true));
      }
    },
    [orgId]
  );

  const closeOrgSidebar = useCallback(() => {
    setOrgSidebarVisible(false);
    setTimeout(() => setOrgSidebarOpen(false), 150);
  }, []);

  const closeTeamSidebar = useCallback(() => {
    setTeamSidebarVisible(false);
    setTimeout(() => {
      setTeamSidebarOpen(false);
      setSelectedTeamId(null);
      setSelectedTeamName(null);
      setTeamSidebarAddMemberOpen(false);
      setTeamSidebarAddMemberVisible(false);
    }, 150);
  }, []);

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
    setTimeout(() => {
      setProjectSidebarOpen(false);
      setSelectedProjectId(null);
      setSelectedProjectName(null);
      setSelectedProjectFramework(null);
      setProjectStats(null);
      setProjectVulnerabilities(null);
    }, 150);
  }, []);

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
        const centerX = pos.x + 268 / 2;
        const centerY = pos.y + 100 / 2;
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
    [orgId, expandedProjectId]
  );

  const onExpandMembers = useCallback(() => {
    if (!orgId) return;
    if (membersExpanded) {
      setMembersExpanded(false);
      setOrgMembersList([]);
      return;
    }
    setMembersExpanding(true);
    api
      .getOrganizationMembers(orgId)
      .then((members) => {
        setOrgMembersList(members);
        setMembersExpanded(true);
      })
      .catch(() => {
        setMembersExpanded(false);
        setOrgMembersList([]);
      })
      .finally(() => setMembersExpanding(false));
  }, [orgId, membersExpanded]);

  useEffect(() => {
    graphNodesRef.current = graphNodes;
  }, [graphNodes]);

  // Fetch team stats, members, projects, org members, and roles when team sidebar opens
  useEffect(() => {
    if (!orgId || !selectedTeamId || !teamSidebarOpen || selectedTeamId === UNGROUPED_TEAM_ID) {
      setTeamSidebarStats(null);
      setTeamSidebarMembers([]);
      setTeamSidebarProjects([]);
      setTeamSidebarOrgMembers([]);
      setTeamSidebarRoles([]);
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
    ])
      .then(([stats, members, allProjects, orgMembers, roles]) => {
        if (cancelled) return;
        setTeamSidebarStats(stats);
        setTeamSidebarMembers(members);
        setTeamSidebarOrgMembers(orgMembers);
        setTeamSidebarRoles(roles);
        const forTeam = allProjects.filter(
          (p: Project) => p.team_ids?.includes(selectedTeamId) || p.owner_team_id === selectedTeamId
        );
        setTeamSidebarProjects(forTeam);
      })
      .catch(() => {
        if (!cancelled) {
          setTeamSidebarStats(null);
          setTeamSidebarMembers([]);
          setTeamSidebarProjects([]);
          setTeamSidebarOrgMembers([]);
          setTeamSidebarRoles([]);
        }
      })
      .finally(() => {
        if (!cancelled) setTeamSidebarDataLoading(false);
      });
    return () => { cancelled = true; };
  }, [orgId, selectedTeamId, teamSidebarOpen]);

  // Fetch project stats and vulnerabilities when project sidebar opens
  useEffect(() => {
    if (!orgId || !selectedProjectId || !projectSidebarOpen) return;
    let cancelled = false;
    setProjectStatsLoading(true);
    setProjectStats(null);
    setProjectVulnerabilities(null);
    Promise.all([
      api.getProjectStats(orgId, selectedProjectId),
      api.getProjectVulnerabilities(orgId, selectedProjectId),
    ])
      .then(([stats, vulns]) => {
        if (!cancelled) {
          setProjectStats(stats);
          setProjectVulnerabilities(vulns ?? []);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setProjectStats(null);
          setProjectVulnerabilities(null);
        }
      })
      .finally(() => {
        if (!cancelled) setProjectStatsLoading(false);
      });
    return () => { cancelled = true; };
  }, [orgId, selectedProjectId, projectSidebarOpen]);

  const memberNodesAndEdges = useMemo(() => {
    if (!membersExpanded || orgMembersList.length === 0) return { nodes: [] as Node[], edges: [] as Edge[] };
    const centerX = 0;
    const centerY = 0;
    const ringRadius = 320;
    const goldenAngle = Math.PI * (3 - Math.sqrt(5));
    const grayStroke = 'rgba(100, 116, 139, 0.4)';
    const nodes: Node[] = orgMembersList.map((m, i) => {
      const angle = i * goldenAngle;
      const x = centerX + Math.cos(angle) * ringRadius - MEMBER_NODE_WIDTH / 2;
      const y = centerY + Math.sin(angle) * ringRadius - MEMBER_NODE_HEIGHT / 2;
      return {
        id: `member-${m.user_id}`,
        type: 'orgMemberNode',
        position: { x, y },
        data: {
          memberId: m.user_id,
          fullName: m.full_name,
          email: m.email,
          avatarUrl: m.avatar_url,
          role: m.role,
          roleDisplayName: m.role_display_name,
          roleColor: m.role_color,
        },
        draggable: true,
        selectable: false,
      };
    });
    const edges: Edge[] = orgMembersList.map((m) => ({
      id: `edge-org-member-${m.user_id}`,
      source: ORG_CENTER_ID,
      target: `member-${m.user_id}`,
      type: 'default',
      style: { stroke: grayStroke, strokeWidth: 1.2 },
    }));
    return { nodes, edges };
  }, [membersExpanded, orgMembersList]);

  useEffect(() => {
    if (loading) return;
    const injectedLayoutNodes = layoutNodes.map((n) => {
      if (n.id === ORG_CENTER_ID && n.data && typeof n.data === 'object') {
        const data = n.data as Record<string, unknown>;
        return {
          ...n,
          data: {
            ...data,
            onExpandMembers,
            membersExpanded,
            isExpandingMembers: membersExpanding,
          },
        };
      }
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
    setGraphNodes([
      ...injectedLayoutNodes,
      ...expandedNodes,
      ...memberNodesAndEdges.nodes,
    ]);
    setGraphEdges([
      ...layoutEdges,
      ...expandedEdges,
      ...memberNodesAndEdges.edges,
    ]);
  }, [
    loading,
    layoutNodes,
    layoutEdges,
    expandingProjectId,
    expandedNodes,
    expandedEdges,
    onExpandProject,
    setGraphNodes,
    setGraphEdges,
    onExpandMembers,
    membersExpanded,
    membersExpanding,
    memberNodesAndEdges,
  ]);

  if (!organization) {
    return (
      <main className="flex flex-col min-h-[calc(100vh-3rem)] w-full">
        <div className="animate-pulse space-y-6 p-4">
          <div className="h-8 bg-muted rounded w-48" />
          <div className="flex-1 min-h-[400px] bg-muted rounded" />
        </div>
      </main>
    );
  }

  return (
    <main className="relative flex flex-col min-h-[calc(100vh-3rem)] w-full bg-background-content">
      {error && (
        <div className="flex-shrink-0 px-4 pt-3">
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive">
            {error}
          </div>
        </div>
      )}
      <div className="flex-1 min-h-0 relative">
        <div className="absolute top-3 right-3 z-10 flex items-center gap-2 rounded-lg border border-border bg-background-card-header p-1 shadow-sm">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
            aria-label="Search"
            onClick={() => setSearchOpen(true)}
          >
            <Search className="h-3.5 w-3.5" />
          </Button>
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
        <Dialog
          open={searchOpen}
          onOpenChange={(open) => {
            setSearchOpen(open);
            if (!open) setSearchQuery('');
          }}
        >
          <DialogContent
            hideClose
            className="max-w-xl w-[90vw] p-0 gap-0 bg-background-card border-border overflow-hidden"
          >
            <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
              <Search className="h-4 w-4 text-foreground-secondary shrink-0" />
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search or run a command..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="flex-1 bg-transparent text-sm text-foreground placeholder:text-foreground-secondary border-0 min-h-8 outline-none focus:outline-none focus:ring-0"
                autoFocus
              />
              <kbd className="hidden sm:inline-flex items-center justify-center h-6 min-w-[1.75rem] px-1.5 rounded bg-background border border-border font-mono text-xs text-foreground-secondary">
                ESC
              </kbd>
              <button
                type="button"
                onClick={() => setSearchOpen(false)}
                className="flex items-center justify-center w-8 h-8 rounded-md text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors shrink-0"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="max-h-[60vh] overflow-y-auto py-2">
              {(() => {
                const options = [
                  { id: '1', label: 'Go to Projects', description: 'List organization projects', icon: FolderKanban },
                  { id: '2', label: 'Go to Teams', description: 'View teams', icon: LayoutDashboard },
                  { id: '3', label: 'Security findings', description: 'Vulnerabilities and code findings', icon: Shield },
                  { id: '4', label: 'Policies', description: 'Policy-as-code and PR checks', icon: FileCode },
                  { id: '5', label: 'Organization settings', description: 'Settings and integrations', icon: Settings },
                  { id: '6', label: 'Recent activity', description: 'Latest syncs and events', icon: Activity },
                ];
                const q = searchQuery.trim().toLowerCase();
                const filtered = q
                  ? options.filter(
                      (o) =>
                        o.label.toLowerCase().includes(q) || o.description.toLowerCase().includes(q)
                    )
                  : options;
                if (filtered.length === 0) {
                  return (
                    <p className="px-4 py-4 text-sm text-foreground-secondary">No results match.</p>
                  );
                }
                return filtered.map((o) => {
                  const Icon = o.icon;
                  return (
                    <button
                      key={o.id}
                      type="button"
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-left rounded-none hover:bg-background-subtle transition-colors text-foreground"
                    >
                      <span className="text-foreground-secondary">
                        <Icon className="h-4 w-4" />
                      </span>
                      <div className="flex flex-col gap-0.5 min-w-0">
                        <span className="text-sm font-medium">{o.label}</span>
                        <span className="text-xs text-foreground-secondary">{o.description}</span>
                      </div>
                    </button>
                  );
                });
              })()}
            </div>
          </DialogContent>
        </Dialog>
        <div className="absolute inset-0 overflow-hidden">
          <ReactFlow
            nodes={stillShowingSkeleton ? orgSkeletonNodes : graphNodes}
            edges={stillShowingSkeleton ? [] : graphEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={stillShowingSkeleton ? skeletonNodeTypes : nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.3, maxZoom: stillShowingSkeleton ? 1.2 : 1 }}
            minZoom={0.2}
            maxZoom={2}
            proOptions={{ hideAttribution: true }}
            defaultEdgeOptions={{ type: 'smoothstep' }}
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

      {orgSidebarOpen && organization && (
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              orgSidebarVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeOrgSidebar}
            aria-hidden
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[640px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              orgSidebarVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-4 flex-shrink-0 flex items-center justify-between gap-4 border-b border-border">
              <div className="flex flex-col gap-0.5 min-w-0">
                <div className="flex items-center gap-2.5 min-w-0">
                  <img
                    src={organization.avatar_url || '/images/org_profile.png'}
                    alt={organization.name}
                    className="h-8 w-8 rounded-lg object-contain border border-border flex-shrink-0"
                  />
                  <h2 className="text-base font-semibold text-foreground truncate">{organization.name}</h2>
                </div>
                {(organization.role || organization.role_display_name) && (
                  <p className="text-xs text-muted-foreground pl-10 truncate">
                    {organization.role_display_name ?? (organization.role ? organization.role.charAt(0).toUpperCase() + organization.role.slice(1) : 'Member')}
                  </p>
                )}
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-5">
              {/* Action Items */}
              <section>
                <h3 className="text-sm font-medium text-foreground mb-3">Action Items</h3>
                {orgItemsToAddress.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                      <ShieldCheck className="h-10 w-10 text-muted-foreground mb-3" aria-hidden />
                      <p className="text-sm text-muted-foreground">Nothing to worry about here</p>
                    </div>
                  ) : (
                    <ul className="space-y-2">
                      {orgItemsToAddress.map((label) => (
                        <li key={label} className="text-sm text-foreground">• {label}</li>
                      ))}
                    </ul>
                  )}
              </section>
            </div>
          </div>
        </div>
      )}

      {teamSidebarOpen && selectedTeamId && (
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              teamSidebarVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeTeamSidebar}
            aria-hidden
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[640px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              teamSidebarVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-4 flex-shrink-0 flex items-center justify-between gap-4 border-b border-border">
              <div className="flex items-center gap-2.5 min-w-0 flex-1">
                <TeamIcon />
                <div className="min-w-0 flex-1">
                  <h2 className="text-base font-semibold text-foreground truncate">
                    {selectedTeamName ?? 'Team'}
                  </h2>
                  {selectedTeamId && teamsById[selectedTeamId] && (
                    <p className="text-sm text-muted-foreground mt-0.5">
                      {(teamsById[selectedTeamId].member_count ?? 0)} member{(teamsById[selectedTeamId].member_count ?? 0) !== 1 ? 's' : ''} · {(teamsById[selectedTeamId].project_count ?? 0)} project{(teamsById[selectedTeamId].project_count ?? 0) !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
              </div>
              {orgId && selectedTeamId && (
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-shrink-0 gap-1.5"
                  onClick={() => navigate(`/organizations/${orgId}/teams/${selectedTeamId}`)}
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  View team
                </Button>
              )}
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
              {/* Action Items */}
              <section>
                <h3 className="text-sm font-medium text-foreground mb-3">Action Items</h3>
                {teamItemsToAddress.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-6 text-center">
                    <ShieldCheck className="h-10 w-10 text-muted-foreground mb-3" aria-hidden />
                    <p className="text-sm text-muted-foreground">Nothing to worry about here</p>
                  </div>
                ) : (
                  <ul className="space-y-2">
                    {teamItemsToAddress.map((label) => (
                      <li key={label} className="text-sm text-foreground">• {label}</li>
                    ))}
                  </ul>
                )}
              </section>

              {/* Projects table — same as Team Projects tab */}
              <section>
                <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
                  <FolderKanban className="h-4 w-4 text-muted-foreground" />
                  Projects
                </h3>
                {selectedTeamId === UNGROUPED_TEAM_ID ? (
                  <p className="text-sm text-muted-foreground">Ungrouped projects only; open team to see list.</p>
                ) : teamSidebarDataLoading ? (
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead className="bg-background-card-header border-b border-border">
                        <tr>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Health Score</th>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Created</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {[1, 2, 3].map((i) => (
                          <tr key={i} className="animate-pulse">
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <div className="h-5 w-5 rounded bg-muted" />
                                <div className="h-4 w-24 rounded bg-muted" />
                              </div>
                            </td>
                            <td className="px-4 py-3"><div className="h-5 w-20 rounded bg-muted" /></td>
                            <td className="px-4 py-3"><div className="h-4 w-12 rounded bg-muted" /></td>
                            <td className="px-4 py-3"><div className="h-4 w-20 rounded bg-muted" /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : teamSidebarProjects.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-2">No projects in this team.</p>
                ) : (
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead className="bg-background-card-header border-b border-border">
                        <tr>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project</th>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Status</th>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Health Score</th>
                          <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Created</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {teamSidebarProjects.slice(0, 5).map((project) => {
                          const { label, inProgress, isError } = projectStatusLabel(project);
                          return (
                            <tr
                              key={project.id}
                              onClick={() => navigate(`/organizations/${orgId}/projects/${project.id}/overview`)}
                              className="hover:bg-table-hover transition-colors cursor-pointer group"
                            >
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <FrameworkIcon frameworkId={project.framework} size={20} />
                                  <div className="text-sm font-semibold text-foreground">{project.name}</div>
                                </div>
                              </td>
                              <td className="px-4 py-3">
                                {inProgress ? (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-foreground-secondary/20 text-foreground-secondary border-foreground-secondary/40 flex items-center gap-1 w-fit">
                                    <Loader2 className="h-3 w-3 animate-spin" />
                                    {label}
                                  </span>
                                ) : isError ? (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40 w-fit">Failed</span>
                                ) : label === 'COMPLIANT' ? (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40">COMPLIANT</span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-xs font-medium border bg-destructive/20 text-destructive border-destructive/40">NOT COMPLIANT</span>
                                )}
                              </td>
                              <td className="px-4 py-3">
                                <div className="text-sm text-foreground-secondary">{project.health_score}</div>
                              </td>
                              <td className="px-4 py-3">
                                <div className="text-sm text-foreground-secondary">{formatDate(project.created_at)}</div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {/* Members — same structure as Team Members tab (card + grid rows, empty state no card) */}
              <section>
                <h3 className="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
                  <Users className="h-4 w-4 text-muted-foreground" />
                  Members
                </h3>
                {selectedTeamId === UNGROUPED_TEAM_ID ? (
                  <p className="text-sm text-muted-foreground">No members for ungrouped.</p>
                ) : teamSidebarDataLoading ? (
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <div className="px-4 py-3 bg-background-card-header border-b border-border grid grid-cols-[1fr_auto_32px] gap-4 items-center">
                      <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Member</div>
                      <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider justify-self-end">Role</div>
                      <div className="sr-only">Actions</div>
                    </div>
                    <div className="divide-y divide-border">
                      {[1, 2, 3].map((i) => (
                        <div
                          key={i}
                          className="px-4 py-3 grid grid-cols-[1fr_auto_32px] gap-4 items-center animate-pulse"
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="h-10 w-10 bg-muted rounded-full border border-border" />
                            <div className="min-w-0">
                              <div className="h-4 bg-muted rounded w-24 mb-1" />
                              <div className="h-3 bg-muted rounded w-32" />
                            </div>
                          </div>
                          <div className="justify-self-end">
                            <div className="h-6 bg-muted rounded w-20 border border-border" />
                          </div>
                          <div className="justify-self-end">
                            <div className="h-4 w-4 bg-muted rounded-full" />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : teamSidebarMembers.length === 0 ? (
                  <div className="py-8 text-center">
                    <h3 className="text-lg font-semibold text-foreground mb-2">This team is empty</h3>
                    <p className="text-foreground-secondary mb-6 max-w-sm mx-auto">
                      Get started by adding members to collaborate on projects together.
                    </p>
                    <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                      {user && teamSidebarOrgMembers.some((m) => m.user_id === user.id) && (
                        <Button
                          onClick={async () => {
                            if (!orgId || !selectedTeamId || !user?.id) return;
                            try {
                              setTeamSidebarAddingMember(true);
                              const topRole = teamSidebarRoles.find((r) => r.display_order === 0);
                              await api.addTeamMember(orgId, selectedTeamId, user.id, topRole?.id);
                              toast({
                                title: 'Welcome!',
                                description: `You have joined the team as ${topRole?.display_name || topRole?.name || 'admin'}.`,
                              });
                              const [members] = await Promise.all([api.getTeamMembers(orgId, selectedTeamId)]);
                              setTeamSidebarMembers(members);
                              const orgMembers = await api.getOrganizationMembers(orgId);
                              setTeamSidebarOrgMembers(orgMembers);
                            } catch (err: any) {
                              toast({
                                title: 'Error',
                                description: err.message || 'Failed to join team',
                                variant: 'destructive',
                              });
                            } finally {
                              setTeamSidebarAddingMember(false);
                            }
                          }}
                          disabled={teamSidebarAddingMember}
                          className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                        >
                          {teamSidebarAddingMember ? (
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          ) : (
                            <Users className="h-4 w-4 mr-2" />
                          )}
                          Join this team
                        </Button>
                      )}
                      <Button
                        onClick={() => setTeamSidebarAddMemberOpen(true)}
                        variant={user && teamSidebarOrgMembers.some((m) => m.user_id === user.id) ? 'outline' : 'default'}
                        className={user && teamSidebarOrgMembers.some((m) => m.user_id === user.id) ? '' : 'bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm'}
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Add members
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <div className="px-4 py-3 bg-background-card-header border-b border-border grid grid-cols-[1fr_auto_32px] gap-4 items-center">
                      <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Member</div>
                      <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider justify-self-end">Role</div>
                      <div className="sr-only">Actions</div>
                    </div>
                    <div className="divide-y divide-border">
                      {teamSidebarMembers.slice(0, 5).map((member) => {
                        const isCurrentUser = user && member.user_id === user.id;
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
                                    <span className="text-xs text-foreground-secondary font-normal">(You)</span>
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
                              <div className="w-6" />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </section>
            </div>
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
              'fixed right-4 top-4 bottom-4 w-full max-w-[420px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
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
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <Users className="h-5 w-5 text-foreground-secondary" />
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
                  <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                    <Shield className="h-5 w-5 text-foreground-secondary" />
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
                {addMemberAdding ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4 mr-2" />
                )}
                {addMemberSelectedUserIds.length <= 1 ? 'Add Member' : `Add ${addMemberSelectedUserIds.length} Members`}
              </Button>
            </div>
          </div>
        </div>
      )}

      {projectSidebarOpen && selectedProjectId && orgId && (
        <div className="fixed inset-0 z-50">
          <div
            className={cn(
              'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
              projectSidebarVisible ? 'opacity-100' : 'opacity-0'
            )}
            onClick={closeProjectSidebar}
            aria-hidden
          />
          <div
            className={cn(
              'fixed right-4 top-4 bottom-4 w-full max-w-[640px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
              projectSidebarVisible ? 'translate-x-0' : 'translate-x-full'
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 pt-5 pb-4 flex-shrink-0 flex items-center justify-between gap-4 border-b border-border">
              <div className="flex items-center gap-2 min-w-0">
                <FrameworkIcon frameworkId={selectedProjectFramework ?? undefined} size={20} className="flex-shrink-0 text-muted-foreground" />
                <h2 className="text-base font-semibold text-foreground truncate">
                  {selectedProjectName ?? 'Project'}
                </h2>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="flex-shrink-0 gap-1.5"
                onClick={() => navigate(`/organizations/${orgId}/projects/${selectedProjectId}/overview`)}
              >
                <ExternalLink className="h-3.5 w-3.5" />
                View project
              </Button>
            </div>
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
              {projectStatsLoading ? (
                <div className="flex items-center justify-center py-12 text-muted-foreground">
                  <Loader2 className="h-8 w-8 animate-spin" />
                </div>
              ) : projectStats ? (
                <>
                  {/* Stats row */}
                  <section>
                    <h3 className="text-sm font-medium text-foreground mb-3">Overview</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="rounded-lg border border-border bg-background-subtle/50 p-3">
                        <div className="flex items-center gap-2 text-muted-foreground mb-0.5">
                          <Package className="h-4 w-4" />
                          <span className="text-xs font-medium">Dependencies</span>
                        </div>
                        <p className="text-lg font-semibold text-foreground">
                          {projectStats.dependencies?.total ?? 0}
                        </p>
                        {projectStats.dependencies && (
                          <p className="text-xs text-muted-foreground">
                            {projectStats.dependencies.direct} direct · {projectStats.dependencies.transitive} transitive
                          </p>
                        )}
                      </div>
                      <div className="rounded-lg border border-border bg-background-subtle/50 p-3">
                        <div className="flex items-center gap-2 text-muted-foreground mb-0.5">
                          <HeartPulse className="h-4 w-4" />
                          <span className="text-xs font-medium">Health</span>
                        </div>
                        <p className="text-lg font-semibold text-foreground">
                          {projectStats.health_score != null ? `${Math.round(projectStats.health_score)}%` : '—'}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Compliance, vulns & freshness
                        </p>
                      </div>
                    </div>
                  </section>
                  {/* Status & Asset tier */}
                  <section>
                    <h3 className="text-sm font-medium text-foreground mb-3">Status & tier</h3>
                    <div className="flex flex-col gap-1">
                      {projectStats.status ? (
                        <span
                          className="inline-flex items-center w-fit px-2.5 py-1 rounded-md text-xs font-medium border"
                          style={{
                            color: projectStats.status.color || 'inherit',
                            borderColor: projectStats.status.color ? `${projectStats.status.color}40` : 'var(--border)',
                            backgroundColor: projectStats.status.color ? `${projectStats.status.color}12` : 'var(--background-subtle)',
                          }}
                        >
                          {projectStats.status.name}
                        </span>
                      ) : (
                        <span className="text-sm text-muted-foreground">No status</span>
                      )}
                      <p className="text-sm text-muted-foreground">
                        {projectStats.asset_tier ? projectStats.asset_tier.name : 'No asset tier'}
                      </p>
                    </div>
                  </section>
                  {/* Action items: individual vulnerabilities first, then other items */}
                  <section>
                    <h3 className="text-sm font-medium text-foreground mb-3">Action Items</h3>
                    {(() => {
                      const vulnSeverityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                      const sortedVulns = [...(projectVulnerabilities ?? [])].sort(
                        (a, b) => (vulnSeverityOrder[a.severity] ?? 4) - (vulnSeverityOrder[b.severity] ?? 4)
                      );
                      const otherActionItems = (projectStats.action_items ?? []).filter(
                        (item) => item.type !== 'critical_vuln' && item.type !== 'high_vuln'
                      );
                      const hasVulns = sortedVulns.length > 0;
                      const hasOther = otherActionItems.length > 0;
                      if (!hasVulns && !hasOther) {
                        return (
                          <div className="flex flex-col items-center justify-center py-6 text-center">
                            <ShieldCheck className="h-8 w-8 text-muted-foreground mb-2" aria-hidden />
                            <p className="text-sm text-muted-foreground">Nothing to worry about here</p>
                          </div>
                        );
                      }
                      return (
                        <ul className="space-y-2">
                          {sortedVulns.map((v) => {
                            const severityClass =
                              v.severity === 'critical'
                                ? 'bg-destructive/12 text-destructive border-destructive/30'
                                : v.severity === 'high'
                                  ? 'bg-amber-500/12 text-amber-600 dark:text-amber-400 border-amber-500/30'
                                  : v.severity === 'medium'
                                    ? 'bg-yellow-500/12 text-yellow-600 dark:text-yellow-400 border-yellow-500/30'
                                    : 'bg-muted/80 text-muted-foreground border-border';
                            const securityUrl = `/organizations/${orgId}/projects/${selectedProjectId}/security`;
                            return (
                              <li key={v.id} className="text-sm">
                                <a
                                  href={securityUrl}
                                  onClick={(e) => {
                                    e.preventDefault();
                                    navigate(securityUrl);
                                  }}
                                  className="block rounded-lg border border-border bg-background-subtle/50 p-2.5 hover:bg-background-subtle transition-colors"
                                >
                                  <div className="flex items-start justify-between gap-2">
                                    <span
                                      className={cn(
                                        'inline-flex shrink-0 px-1.5 py-0.5 rounded text-xs font-medium border capitalize',
                                        severityClass
                                      )}
                                    >
                                      {v.severity}
                                    </span>
                                    <ExternalLink className="h-3.5 w-3.5 shrink-0 text-muted-foreground mt-0.5" />
                                  </div>
                                  <p className="font-medium text-foreground mt-1 truncate" title={v.dependency_name}>
                                    {v.dependency_name}
                                    <span className="text-muted-foreground font-normal">@{v.dependency_version}</span>
                                  </p>
                                  <p className="text-muted-foreground text-xs mt-0.5 line-clamp-2">
                                    {v.summary || v.osv_id}
                                  </p>
                                </a>
                              </li>
                            );
                          })}
                          {otherActionItems.map((item, i) => (
                            <li key={`other-${i}`} className="text-sm">
                              <a
                                href={item.link}
                                onClick={(e) => {
                                  e.preventDefault();
                                  navigate(item.link);
                                }}
                                className="block rounded-lg border border-border bg-background-subtle/50 p-2.5 hover:bg-background-subtle transition-colors"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-medium text-foreground">{item.title}</span>
                                  <ExternalLink className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                                </div>
                                {item.description && (
                                  <p className="text-muted-foreground text-xs mt-0.5">{item.description}</p>
                                )}
                              </a>
                            </li>
                          ))}
                        </ul>
                      );
                    })()}
                  </section>
                </>
              ) : (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  Could not load project stats.
                </div>
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
