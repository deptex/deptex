import { useEffect, useState, useCallback, useMemo } from 'react';
import { useOutletContext, useParams, useNavigate } from 'react-router-dom';
import { api, ProjectWithRole, ProjectPermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { loadProjectVulnerabilityGraphData } from '../../lib/vulnerability-graph-data';
import { ProjectVulnerabilitiesGraph } from '../../components/vulnerabilities-graph/ProjectVulnerabilitiesGraph';
import SecuritySidebar, { type ActiveSidebar } from '../../components/security/SecuritySidebar';
import VulnerabilityDetailContent from '../../components/security/VulnerabilityDetailContent';
import DependencySecurityContent from '../../components/security/DependencySecurityContent';
import ProjectSecurityContent from '../../components/security/ProjectSecurityContent';
import SecurityFilterBar, { type SecurityFilters, DEFAULT_FILTERS } from '../../components/security/SecurityFilterBar';
import type { VulnGraphDepNode, VulnGraphCenterExtras } from '../../components/vulnerabilities-graph/useVulnerabilitiesGraphLayout';
import type { Node } from '@xyflow/react';
import { VULN_CENTER_ID } from '../../components/vulnerabilities-graph/useVulnerabilitiesGraphLayout';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

export default function ProjectOverviewPage() {
  const { project, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [permissionsChecked, setPermissionsChecked] = useState(false);
  const [graphDepNodes, setGraphDepNodes] = useState<VulnGraphDepNode[]>([]);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [graphDataLoading, setGraphDataLoading] = useState(false);
  const [safeVersionByProjectDepId, setSafeVersionByProjectDepId] = useState<Record<string, { safeVersion: string | null; safeVersionId: string | null; isCurrent: boolean }>>({});
  const [simulatedGraphDepNodes, setSimulatedGraphDepNodes] = useState<VulnGraphDepNode[] | null>(null);
  const [revertedInSimulation, setRevertedInSimulation] = useState<Set<string>>(new Set());
  const [simulateLoading, setSimulateLoading] = useState(false);
  const [activeSidebar, setActiveSidebar] = useState<ActiveSidebar>(null);
  const [securityFilters, setSecurityFilters] = useState<SecurityFilters>(DEFAULT_FILTERS);

  const realtime = useRealtimeStatus(organizationId, projectId);
  const isExtractionOngoing = realtime.status !== 'ready';

  const canManageSidebars = useMemo(() => {
    if (!userPermissions) return false;
    return (userPermissions as { can_manage_watchtower?: boolean }).can_manage_watchtower === true || userPermissions.edit_settings === true;
  }, [userPermissions]);

  // Permission: need view_dependencies to see the graph (Overview is the graph)
  useEffect(() => {
    if (!project || !projectId || !userPermissions) return;
    if (!userPermissions.view_dependencies) {
      if (userPermissions.view_overview) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies`, { replace: true });
      } else if (userPermissions.view_settings) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/settings`, { replace: true });
      }
      return;
    }
    setPermissionsChecked(true);
  }, [project, projectId, userPermissions, navigate, organizationId]);

  // Load vulnerability graph data
  useEffect(() => {
    if (!organizationId || !projectId || !permissionsChecked) return;
    let cancelled = false;
    setGraphDataLoading(true);
    setGraphLoading(true);
    setGraphError(null);
    loadProjectVulnerabilityGraphData(organizationId, projectId)
      .then((result) => {
        if (cancelled) return;
        setGraphDepNodes(result.graphDepNodes);
        setSimulatedGraphDepNodes(null);
        setGraphError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        const message = err?.message || 'Failed to load vulnerabilities';
        setGraphError(message);
        setGraphDepNodes([]);
        setSimulatedGraphDepNodes(null);
      })
      .finally(() => {
        if (!cancelled) {
          setGraphDataLoading(false);
          setGraphLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, [organizationId, projectId, permissionsChecked]);

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
    return () => { cancelled = true; };
  }, [organizationId, projectId, graphDepNodes]);

  const SIMULATE_MIN_LOADING_MS = 1000;
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

  useEffect(() => {
    if (simulatedGraphDepNodes == null) return;
    const direct = simulatedGraphDepNodes.filter((n) => n.parentId === 'project');
    const bumps = direct.filter((node) => {
      if (revertedInSimulation.has(node.id)) return false;
      const original = graphDepNodes.find((o) => o.id === node.id);
      const safe = safeVersionByProjectDepId[node.id];
      const toVersion = safe?.safeVersion ?? node.version;
      return original && original.version !== toVersion;
    });
    const removed = graphDepNodes
      .filter((n) => n.parentId === 'project' && n.isZombie && !revertedInSimulation.has(n.id));
    if (bumps.length === 0 && removed.length === 0) {
      setSimulatedGraphDepNodes(null);
      setRevertedInSimulation(new Set());
    }
  }, [simulatedGraphDepNodes, graphDepNodes, safeVersionByProjectDepId, revertedInSimulation]);

  const centerExtras: VulnGraphCenterExtras | null = hasDirectVulnDeps
    ? {
        onSimulateLatestSafe: handleSimulateLatestSafe,
        simulateLoading,
        hasDirectVulnDeps,
        hasPackagesToBump,
      }
    : null;

  const graphDepNodesForLayout = useMemo(() => {
    const sla = securityFilters.slaStatus;
    if (sla === 'all') return effectiveGraphDepNodes;
    return effectiveGraphDepNodes
      .map((node) => ({
        ...node,
        vulnerabilities: node.vulnerabilities.filter((v) => (v.sla_status ?? null) === sla),
      }))
      .filter((node) => node.vulnerabilities.length > 0);
  }, [effectiveGraphDepNodes, securityFilters.slaStatus]);

  const vulnerableCount = graphDepNodesForLayout.length;
  const vulnerableDependenciesLabel =
    vulnerableCount === 0
      ? 'No vulnerable dependencies'
      : `${vulnerableCount} vulnerable dependency${vulnerableCount === 1 ? '' : 's'}`;

  const handleGraphNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (!projectId) return;
      if (node.id === VULN_CENTER_ID) {
        setActiveSidebar({ type: 'project', id: projectId });
        return;
      }
      if (node.type === 'vulnerabilityNode' && node.data && typeof (node.data as { osvId?: string }).osvId === 'string') {
        setActiveSidebar({ type: 'vulnerability', id: (node.data as { osvId: string }).osvId });
        return;
      }
      setActiveSidebar({ type: 'dependency', id: node.id });
    },
    [projectId]
  );

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

  if (!userPermissions?.view_dependencies) {
    return null;
  }

  return (
    <main className="relative flex flex-col min-h-[calc(100vh-3rem)] w-full bg-background-content">
      <div className="flex-1 min-h-0 relative">
        <div className="absolute inset-0 overflow-hidden">
          <ProjectVulnerabilitiesGraph
            projectName={project?.name ?? 'Project'}
            vulnerableDependenciesLabel={vulnerableDependenciesLabel}
            framework={project?.framework}
            graphDepNodes={graphDepNodesForLayout}
            graphLoading={graphLoading}
            vulnerabilitiesLoading={graphDataLoading}
            centerExtras={centerExtras}
            showOnlyReachable={securityFilters.reachableOnly}
            extractionOngoing={isExtractionOngoing}
            onNodeClick={handleGraphNodeClick}
            statusName={project?.status_name}
            statusColor={project?.status_color}
          />
        </div>
        <div className="absolute top-3 right-3 z-30 rounded-lg border border-border bg-background-card/95 backdrop-blur-sm shadow-md pointer-events-auto min-w-0">
          <div className="px-3 py-2">
            <SecurityFilterBar filters={securityFilters} onFiltersChange={setSecurityFilters} />
          </div>
          {graphError && (
            <div className="mx-3 mb-2 bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive">
              {graphError}
            </div>
          )}
        </div>
      </div>

      {activeSidebar?.type === 'vulnerability' && (
        <SecuritySidebar
          isOpen
          onClose={() => setActiveSidebar(null)}
          title={activeSidebar.id}
          subtitle="Vulnerability Detail"
        >
          <VulnerabilityDetailContent
            organizationId={organizationId ?? ''}
            projectId={projectId ?? ''}
            osvId={activeSidebar.id}
            canManage={canManageSidebars}
            onNavigateToDep={(depId) => setActiveSidebar({ type: 'dependency', id: depId })}
          />
        </SecuritySidebar>
      )}
      {activeSidebar?.type === 'dependency' && (
        <SecuritySidebar
          isOpen
          onClose={() => setActiveSidebar(null)}
          title="Dependency Security"
          subtitle="Security summary for this dependency"
        >
          <DependencySecurityContent
            organizationId={organizationId ?? ''}
            projectId={projectId ?? ''}
            depId={activeSidebar.id}
            onNavigateToVuln={(osvId) => setActiveSidebar({ type: 'vulnerability', id: osvId })}
            onNavigateToFullDetail={() => {
              navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies/${activeSidebar.id}/overview`);
            }}
          />
        </SecuritySidebar>
      )}
      {activeSidebar?.type === 'project' && (
        <SecuritySidebar
          isOpen
          onClose={() => setActiveSidebar(null)}
          title="Project Security Overview"
          subtitle={project?.name}
        >
          <ProjectSecurityContent
            organizationId={organizationId ?? ''}
            projectId={projectId ?? ''}
            canManage={canManageSidebars}
            onNavigateToVuln={(osvId) => setActiveSidebar({ type: 'vulnerability', id: osvId })}
          />
        </SecuritySidebar>
      )}
    </main>
  );
}
