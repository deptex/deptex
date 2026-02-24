import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useOutletContext, useNavigate, useParams } from 'react-router-dom';
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
import { Loader2 } from 'lucide-react';
import { useToast } from '../../hooks/use-toast';
import { api, ProjectWithRole, ProjectPermissions } from '../../lib/api';
import { loadProjectVulnerabilityGraphData } from '../../lib/vulnerability-graph-data';
import { ProjectCenterNode } from '../../components/vulnerabilities-graph/ProjectCenterNode';
import { SkeletonProjectCenterNode } from '../../components/vulnerabilities-graph/SkeletonProjectCenterNode';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { VulnerabilityNode } from '../../components/supply-chain/VulnerabilityNode';
import { useVulnerabilitiesGraphLayout, createVulnerabilitiesCenterNode, type VulnGraphDepNode, type VulnGraphCenterExtras, VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT, VULN_CENTER_ID } from '../../components/vulnerabilities-graph/useVulnerabilitiesGraphLayout';
import { VulnerabilitiesSimulationCard } from '../../components/vulnerabilities-graph/VulnerabilitiesSimulationCard';
import { ShowOnlyReachableCard } from '../../components/vulnerabilities-graph/ShowOnlyReachableCard';
import type { NodeTypes } from '@xyflow/react';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

const vulnerabilityGraphNodeTypes: NodeTypes = {
  projectCenterNode: ProjectCenterNode,
  dependencyNode: DependencyNode,
  vulnerabilityNode: VulnerabilityNode,
};

const skeletonCenterNodeTypes: NodeTypes = {
  skeletonProjectCenterNode: SkeletonProjectCenterNode,
};

const SKELETON_CENTER_POS = {
  x: -VULN_CENTER_NODE_WIDTH / 2,
  y: -VULN_CENTER_NODE_HEIGHT / 2,
};

const skeletonNodes = [
  {
    id: 'skeleton-center',
    type: 'skeletonProjectCenterNode',
    position: SKELETON_CENTER_POS,
    data: {},
  },
];

function VulnerabilitiesGraph({
  projectName,
  vulnerableDependenciesLabel,
  framework,
  graphDepNodes,
  graphLoading,
  vulnerabilitiesLoading,
  centerExtras,
  showOnlyReachable = false,
}: {
  projectName: string;
  vulnerableDependenciesLabel: string;
  framework?: string | null;
  graphDepNodes: VulnGraphDepNode[];
  graphLoading: boolean;
  vulnerabilitiesLoading?: boolean;
  centerExtras?: VulnGraphCenterExtras | null;
  showOnlyReachable?: boolean;
}) {
  const loading = graphLoading || vulnerabilitiesLoading;
  const { nodes: layoutNodes, edges: layoutEdges } = useVulnerabilitiesGraphLayout(
    projectName,
    graphDepNodes,
    framework,
    vulnerableDependenciesLabel,
    centerExtras,
    showOnlyReachable
  );
  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>(skeletonNodes);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const layoutSignature =
    layoutNodes.length + '-' + layoutNodes.map((n) => n.id).join(',');
  const lastAppliedLayoutRef = useRef<string | null>(null);
  if (loading) lastAppliedLayoutRef.current = null;

  useEffect(() => {
    if (
      !loading &&
      layoutNodes.length > 0 &&
      lastAppliedLayoutRef.current !== layoutSignature
    ) {
      lastAppliedLayoutRef.current = layoutSignature;
      // Ensure center node is always present (can disappear when switching to simulated graph)
      const hasCenter = layoutNodes.some((n) => n.id === VULN_CENTER_ID);
      const nodesToSet = hasCenter
        ? layoutNodes
        : [
            createVulnerabilitiesCenterNode(projectName, graphDepNodes, framework),
            ...layoutNodes.filter((n) => n.id !== VULN_CENTER_ID),
          ];
      setGraphNodes(nodesToSet);
      setGraphEdges(layoutEdges);
    }
  }, [
    loading,
    layoutSignature,
    layoutNodes,
    layoutEdges,
    setGraphNodes,
    setGraphEdges,
    projectName,
    graphDepNodes,
    framework,
  ]);

  const stillShowingSkeleton =
    loading ||
    (layoutNodes.length > 0 &&
      graphNodes.length === 1 &&
      graphNodes[0]?.id === 'skeleton-center');

  return (
    <ReactFlow
      nodes={stillShowingSkeleton ? skeletonNodes : graphNodes}
      edges={stillShowingSkeleton ? [] : graphEdges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={stillShowingSkeleton ? skeletonCenterNodeTypes : vulnerabilityGraphNodeTypes}
      fitView={stillShowingSkeleton}
      fitViewOptions={{ padding: 0.3, maxZoom: 1.2 }}
      minZoom={0.3}
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
  );
}

export default function ProjectVulnerabilitiesPage() {
  const { project, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [permissionsChecked, setPermissionsChecked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [, setError] = useState<string | null>(null);
  const [graphDepNodes, setGraphDepNodes] = useState<VulnGraphDepNode[]>([]);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [safeVersionByProjectDepId, setSafeVersionByProjectDepId] = useState<Record<string, { safeVersion: string | null; safeVersionId: string | null; isCurrent: boolean }>>({});
  const [simulatedGraphDepNodes, setSimulatedGraphDepNodes] = useState<VulnGraphDepNode[] | null>(null);
  const [revertedInSimulation, setRevertedInSimulation] = useState<Set<string>>(new Set());
  const [simulateLoading, setSimulateLoading] = useState(false);
  const [createPrLoading, setCreatePrLoading] = useState(false);
  const [showOnlyReachable, setShowOnlyReachable] = useState(false);

  // Permission check
  useEffect(() => {
    if (!project || !projectId || !userPermissions) return;
    
    if (!userPermissions.view_dependencies) {
      // Redirect to first available tab
      if (userPermissions.view_overview) {
        navigate(`/organizations/${organizationId}/projects/${projectId}`, { replace: true });
      } else if (userPermissions.view_settings) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/settings`, { replace: true });
      }
      return;
    }
    
    setPermissionsChecked(true);
  }, [project, projectId, userPermissions, navigate, organizationId]);

  // Load vulnerability graph data via shared loader (single source of truth for vuln + deps + supply chains)
  useEffect(() => {
    if (!organizationId || !projectId || !permissionsChecked) return;

    let cancelled = false;
    setLoading(true);
    setGraphLoading(true);
    setError(null);
    setGraphError(null);

    loadProjectVulnerabilityGraphData(organizationId, projectId)
      .then((result) => {
        if (cancelled) return;
        setGraphDepNodes(result.graphDepNodes);
        setSimulatedGraphDepNodes(null);
        setError(null);
        setGraphError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        const message = err?.message || 'Failed to load vulnerabilities';
        setError(message);
        setGraphError(message);
        setGraphDepNodes([]);
        setSimulatedGraphDepNodes(null);
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
          setGraphLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [organizationId, projectId, permissionsChecked]);

  // Background: fetch latest safe version for each direct vulnerable dependency (single batch request)
  useEffect(() => {
    if (!organizationId || !projectId || graphDepNodes.length === 0) return;
    const directDeps = graphDepNodes.filter((n) => n.parentId === 'project' && n.vulnerabilities.length > 0);
    if (directDeps.length === 0) return;
    let cancelled = false;
    api
      .getBatchLatestSafeVersions(organizationId, projectId, directDeps.map((n) => n.id), { severity: 'high', excludeBanned: true })
      .then((batchResult) => {
        if (cancelled) return;
        setSafeVersionByProjectDepId((prev) => {
          const next = { ...prev };
          directDeps.forEach((node) => {
            const res = batchResult[node.id];
            next[node.id] = res
              ? { safeVersion: res.safeVersion, safeVersionId: res.safeVersionId, isCurrent: res.isCurrent }
              : { safeVersion: null, safeVersionId: null, isCurrent: true };
          });
          return next;
        });
      })
      .catch(() => {
        if (!cancelled) {
          setSafeVersionByProjectDepId((prev) => {
            const next = { ...prev };
            directDeps.forEach((node) => {
              next[node.id] = { safeVersion: null, safeVersionId: null, isCurrent: true };
            });
            return next;
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, projectId, graphDepNodes]);

  const SIMULATE_MIN_LOADING_MS = 1000;

  // Simulate latest safe: show loading first, then apply. Use min delay only when entering simulation from scratch; when re-applying (already simulated) update as soon as ready.
  const handleSimulateLatestSafe = useCallback(() => {
    if (!organizationId || !projectId) return;
    const directDeps = graphDepNodes.filter((n) => n.parentId === 'project');
    const zombieDirects = directDeps.filter((n) => n.isZombie);
    const toSimulate = directDeps.filter((n) => {
      if (n.isZombie) return false;
      const safe = safeVersionByProjectDepId[n.id];
      return safe?.safeVersion != null && safe?.safeVersionId != null && !safe.isCurrent;
    });
    if (toSimulate.length === 0 && zombieDirects.length === 0) return;
    const start = Date.now();
    setSimulateLoading(true);
    setRevertedInSimulation(new Set());

    const isReApplying = simulatedGraphDepNodes != null;
    const applyResult = (merged: VulnGraphDepNode[] | null) => {
      const elapsed = Date.now() - start;
      const remaining = isReApplying ? 0 : Math.max(0, SIMULATE_MIN_LOADING_MS - elapsed);
      setTimeout(() => {
        if (merged !== null) setSimulatedGraphDepNodes(merged);
        setSimulateLoading(false);
      }, remaining);
    };

    if (toSimulate.length === 0) {
      applyResult([]);
      return;
    }

    Promise.all(
      toSimulate.map((node) =>
        api.getSupplyChainForVersion(organizationId, projectId, node.id, safeVersionByProjectDepId[node.id]!.safeVersionId!)
      )
    )
      .then((responses) => {
        const merged: VulnGraphDepNode[] = [];
        const seenTransitive = new Set<string>();
        toSimulate.forEach((directNode, idx) => {
          const res = responses[idx];
          if (!res) return;
          merged.push({
            id: directNode.id,
            name: directNode.name,
            version: res.version,
            is_direct: true,
            parentId: 'project',
            license: directNode.license ?? null,
            vulnerabilities: res.vulnerabilities ?? [],
            isZombie: false,
          });
          (res.children ?? []).forEach((child) => {
            if (seenTransitive.has(child.dependency_version_id)) return;
            seenTransitive.add(child.dependency_version_id);
            merged.push({
              id: child.dependency_version_id,
              name: child.name,
              version: child.version,
              is_direct: false,
              parentId: directNode.id,
              license: child.license ?? null,
              vulnerabilities: child.vulnerabilities,
              isZombie: false,
            });
          });
        });
        applyResult(merged);
      })
      .catch((err) => {
        console.error('Failed to simulate latest safe versions:', err);
        applyResult(null);
      });
  }, [organizationId, projectId, graphDepNodes, safeVersionByProjectDepId, simulatedGraphDepNodes]);

  const handleResetItem = useCallback((projectDependencyId: string) => {
    setRevertedInSimulation((prev) => new Set(prev).add(projectDependencyId));
  }, []);

  /** Collect rootId and all descendant node ids in the graph. */
  const getSubtreeIds = useCallback((nodes: VulnGraphDepNode[], rootId: string): Set<string> => {
    const ids = new Set<string>([rootId]);
    let added = true;
    while (added) {
      added = false;
      for (const n of nodes) {
        if (n.parentId && ids.has(n.parentId) && !ids.has(n.id)) {
          ids.add(n.id);
          added = true;
        }
      }
    }
    return ids;
  }, []);

  const effectiveGraphDepNodes = useMemo(() => {
    if (simulatedGraphDepNodes == null) return graphDepNodes;
    if (revertedInSimulation.size === 0) return simulatedGraphDepNodes;
    const simulatedDirectIds = new Set(simulatedGraphDepNodes.filter((n) => n.parentId === 'project').map((n) => n.id));
    const revertedBumpIds = [...revertedInSimulation].filter((id) => simulatedDirectIds.has(id));
    const nodesToRemove = new Set<string>();
    for (const id of revertedBumpIds) {
      getSubtreeIds(simulatedGraphDepNodes, id).forEach((x) => nodesToRemove.add(x));
    }
    const simulatedMinus = simulatedGraphDepNodes.filter((n) => !nodesToRemove.has(n.id));
    const nodesToAddIds = new Set<string>();
    for (const id of revertedInSimulation) {
      getSubtreeIds(graphDepNodes, id).forEach((x) => nodesToAddIds.add(x));
    }
    const originalNodesToAdd = graphDepNodes.filter((n) => nodesToAddIds.has(n.id));
    return [...simulatedMinus, ...originalNodesToAdd];
  }, [simulatedGraphDepNodes, graphDepNodes, revertedInSimulation, getSubtreeIds]);
  const directNodesForBump = graphDepNodes.filter((n) => n.parentId === 'project');
  const hasDirectVulnDeps = directNodesForBump.some((n) => n.vulnerabilities.length > 0);
  const hasZombieDirects = directNodesForBump.some((n) => n.isZombie);
  const hasPackagesToBump = useMemo(
    () =>
      directNodesForBump.some((n) => {
        const safe = safeVersionByProjectDepId[n.id];
        return safe?.safeVersion != null && !safe.isCurrent;
      }) || hasZombieDirects,
    [directNodesForBump, safeVersionByProjectDepId, hasZombieDirects]
  );
  const simulationChangeList = useMemo(() => {
    if (!simulatedGraphDepNodes) return [];
    const direct = simulatedGraphDepNodes.filter((n) => n.parentId === 'project');
    const bumps: Array<{ type: 'bump'; name: string; fromVersion: string; toVersion: string; projectDependencyId: string }> = direct.map((node) => {
      const original = graphDepNodes.find((o) => o.id === node.id);
      const safe = safeVersionByProjectDepId[node.id];
      return {
        type: 'bump' as const,
        name: node.name,
        fromVersion: original?.version ?? node.version,
        toVersion: safe?.safeVersion ?? node.version,
        projectDependencyId: node.id,
      };
    }).filter((b) => b.fromVersion !== b.toVersion);
    const removed: Array<{ type: 'removed'; name: string; projectDependencyId: string }> = graphDepNodes
      .filter((n) => n.parentId === 'project' && n.isZombie)
      .map((n) => ({ type: 'removed' as const, name: n.name, projectDependencyId: n.id }));
    const list = [...bumps, ...removed];
    return list.filter((item) => !revertedInSimulation.has(item.projectDependencyId));
  }, [simulatedGraphDepNodes, graphDepNodes, safeVersionByProjectDepId, revertedInSimulation]);

  // When every item has been reset, exit simulation and hide the card
  useEffect(() => {
    if (simulatedGraphDepNodes != null && simulationChangeList.length === 0) {
      setSimulatedGraphDepNodes(null);
      setRevertedInSimulation(new Set());
    }
  }, [simulatedGraphDepNodes, simulationChangeList.length]);

  // Always show simulate button when there are any direct deps with vulns (regardless of simulated state or empty graph)
  const centerExtras: VulnGraphCenterExtras | null = hasDirectVulnDeps
    ? {
        onSimulateLatestSafe: handleSimulateLatestSafe,
        simulateLoading,
        hasDirectVulnDeps,
        hasPackagesToBump,
      }
    : null;

  const vulnerableCount = effectiveGraphDepNodes.length;
  const vulnerableDependenciesLabel =
    vulnerableCount === 0
      ? 'No vulnerable dependencies'
      : `${vulnerableCount} vulnerable dependency${vulnerableCount === 1 ? '' : 's'}`;

  // Show loading until project and permissions are verified
  if (!project || !permissionsChecked) {
    return (
      <main className="relative flex flex-col min-h-[calc(100vh-3rem)] w-full">
        <div className="animate-pulse space-y-6 p-4">
          <div className="h-8 bg-muted rounded w-48" />
          <div className="flex-1 min-h-[400px] bg-muted rounded" />
        </div>
      </main>
    );
  }

  // Double-check permission before rendering
  if (!userPermissions?.view_dependencies) {
    return null;
  }

  return (
    <main className="relative flex flex-col min-h-[calc(100vh-3rem)] w-full bg-background-content">
      {graphError && (
        <div className="flex-shrink-0 px-4 pt-3">
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive">
            {graphError}
          </div>
        </div>
      )}
      <div className="flex-1 min-h-0 relative">
        <div className="absolute inset-0 overflow-hidden">
          <VulnerabilitiesGraph
            projectName={project?.name ?? 'Project'}
            vulnerableDependenciesLabel={vulnerableDependenciesLabel}
            framework={project?.framework}
            graphDepNodes={effectiveGraphDepNodes}
            graphLoading={graphLoading}
            vulnerabilitiesLoading={loading}
            centerExtras={centerExtras}
            showOnlyReachable={showOnlyReachable}
          />
        </div>
        {/* Left card: Simulating (always visible); under sidebar (z-30). Empty = Preview fix, with items = Create PRs (transparent style). */}
        <VulnerabilitiesSimulationCard
          changeList={simulationChangeList}
          onResetItem={handleResetItem}
          onPreviewFix={centerExtras?.onSimulateLatestSafe}
          canPreviewFix={centerExtras?.hasPackagesToBump ?? false}
          previewFixLoading={centerExtras?.simulateLoading ?? false}
          onCreatePr={async () => {
              const bumps = simulationChangeList.filter((c): c is typeof c & { type: 'bump'; toVersion: string } => c.type === 'bump');
              const removed = simulationChangeList.filter((c): c is typeof c & { type: 'removed' } => c.type === 'removed');
              if (!organizationId || !projectId || (bumps.length === 0 && removed.length === 0)) return;
              setCreatePrLoading(true);
              let createdCount = 0;
              let alreadyExistedCount = 0;
              try {
                for (const b of bumps) {
                  const result = await api.createWatchtowerBumpPR(organizationId, projectId, b.projectDependencyId, b.toVersion);
                  if (result.already_exists) alreadyExistedCount += 1;
                  else createdCount += 1;
                }
                for (const r of removed) {
                  const removeResult = await api.createRemoveDependencyPR(organizationId, projectId, r.projectDependencyId);
                  if (removeResult.already_exists) alreadyExistedCount += 1;
                  else createdCount += 1;
                }
                if (createdCount > 0 || alreadyExistedCount > 0) {
                  const parts: string[] = [];
                  if (createdCount > 0) parts.push(`${createdCount} new PR${createdCount !== 1 ? 's' : ''} created`);
                  if (alreadyExistedCount > 0) parts.push(`${alreadyExistedCount} already existed`);
                  toast({
                    title: createdCount > 0 ? 'PRs created' : 'PRs already exist',
                    description: parts.join(', '),
                  });
                }
              } catch (err: unknown) {
                toast({
                  title: 'Failed to create PRs',
                  description: err instanceof Error ? err.message : 'An unexpected error occurred',
                  variant: 'destructive',
                });
              } finally {
                setCreatePrLoading(false);
              }
            }}
            createPrLoading={createPrLoading}
            organizationId={organizationId ?? ''}
            projectId={projectId ?? ''}
          />
        <ShowOnlyReachableCard
          showOnlyReachable={showOnlyReachable}
          onToggle={setShowOnlyReachable}
        />
      </div>
    </main>
  );
}
