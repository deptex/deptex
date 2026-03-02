import { useMemo } from 'react';
import { type Node, type Edge, MarkerType } from '@xyflow/react';
import type { DependencyNodeData, VulnerabilityNodeData } from '../supply-chain/useGraphLayout';

// Match supply-chain node dimensions for consistent layout (exported for skeleton position)
export const VULN_CENTER_NODE_WIDTH = 260;
export const VULN_CENTER_NODE_HEIGHT = 80;
const CENTER_NODE_WIDTH = VULN_CENTER_NODE_WIDTH;
const CENTER_NODE_HEIGHT = VULN_CENTER_NODE_HEIGHT;

export const VULN_CENTER_ID = 'project';
const DEP_NODE_WIDTH = 240;
const DEP_NODE_HEIGHT = 72;
const VULN_NODE_WIDTH = 210;
const VULN_NODE_HEIGHT = 70;

export interface VulnGraphDepNode {
  id: string;
  name: string;
  version: string;
  is_direct: boolean;
  parentId: string;
  license?: string | null;
  vulnerabilities: Array<{
    osv_id: string;
    severity: string;
    summary: string | null;
    aliases: string[];
    /** When false, vulnerability is not reachable from app code. Optional; default true. */
    is_reachable?: boolean;
    depscore?: number | null;
    epss_score?: number | null;
    cvss_score?: number | null;
    cisa_kev?: boolean | null;
    fixed_versions?: string[] | null;
  }>;
  /** When true, package is zombie (never imported); show at opacity 0.5. */
  isZombie?: boolean;
}

export interface VulnGraphCenterExtras {
  onSimulateLatestSafe?: () => void;
  simulateLoading?: boolean;
  /** Show button when true (any direct dep with vulns). Button is disabled when !hasPackagesToBump. */
  hasDirectVulnDeps?: boolean;
  hasPackagesToBump?: boolean;
}

function getHandlePair(angle: number): { sourceHandle: string; targetHandle: string } {
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
  if (a < Math.PI / 4 || a >= (7 * Math.PI) / 4) return { sourceHandle: 'right', targetHandle: 'left' };
  if (a < (3 * Math.PI) / 4) return { sourceHandle: 'bottom', targetHandle: 'top' };
  if (a < (5 * Math.PI) / 4) return { sourceHandle: 'left', targetHandle: 'right' };
  return { sourceHandle: 'top', targetHandle: 'bottom' };
}

function getVulnHandlePair(angle: number): { sourceHandle: string; targetHandle: string } {
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
  if (a < Math.PI / 4 || a >= (7 * Math.PI) / 4) return { sourceHandle: 'source-right', targetHandle: 'left' };
  if (a < (3 * Math.PI) / 4) return { sourceHandle: 'source-bottom', targetHandle: 'top' };
  if (a < (5 * Math.PI) / 4) return { sourceHandle: 'source-left', targetHandle: 'right' };
  return { sourceHandle: 'source-top', targetHandle: 'bottom' };
}

function getVulnEdgeColor(severity: string): string {
  const s = (severity || '').toLowerCase();
  switch (s) {
    case 'critical': return 'rgba(239, 68, 68, 0.55)';
    case 'high': return 'rgba(249, 115, 22, 0.50)';
    case 'medium': return 'rgba(234, 179, 8, 0.45)';
    case 'low':
    case 'info':
    case 'informational':
    case 'none':
      return 'rgba(100, 116, 139, 0.30)';
    default: return 'rgba(100, 116, 139, 0.30)';
  }
}

export type DepscoreBracket = 'urgent' | 'moderate' | 'low' | 'healthy';

export function getDepscoreBracket(score: number | null | undefined): DepscoreBracket {
  if (score == null || score <= 0) return 'healthy';
  if (score >= 75) return 'urgent';
  if (score >= 40) return 'moderate';
  return 'low';
}

export function getDepscoreEdgeColor(score: number | null | undefined): string {
  const bracket = getDepscoreBracket(score);
  switch (bracket) {
    case 'urgent': return 'rgba(239, 68, 68, 0.55)';
    case 'moderate': return 'rgba(249, 115, 22, 0.50)';
    case 'low': return 'rgba(100, 116, 139, 0.35)';
    case 'healthy': return 'rgba(34, 197, 94, 0.35)';
  }
}

export function getWorstDepscore(depNodes: VulnGraphDepNode[]): number {
  let worst = 0;
  for (const dep of depNodes) {
    if (dep.isZombie) continue;
    for (const v of reachableVulns(dep.vulnerabilities)) {
      if ((v.depscore ?? 0) > worst) worst = v.depscore ?? 0;
    }
  }
  return worst;
}

export function getDepscoreColorScheme(score: number): {
  border: string;
  shadow: string;
  glow: string;
} {
  const bracket = getDepscoreBracket(score);
  switch (bracket) {
    case 'urgent':
      return { border: 'border-red-500/50', shadow: 'shadow-red-500/20', glow: 'ring-red-500/30' };
    case 'moderate':
      return { border: 'border-orange-500/50', shadow: 'shadow-orange-500/20', glow: 'ring-orange-500/30' };
    case 'low':
      return { border: 'border-zinc-500/30', shadow: '', glow: '' };
    case 'healthy':
      return { border: 'border-green-500/30', shadow: 'shadow-green-500/10', glow: 'ring-green-500/20' };
  }
}

/** Vulnerabilities that are reachable (affect node/edge color). Default true when missing. */
function reachableVulns(vulns: VulnGraphDepNode['vulnerabilities']) {
  return vulns.filter((v) => v.is_reachable !== false);
}

function countVulnsBySeverity(
  vulns: VulnGraphDepNode['vulnerabilities'],
  /** When true, only count reachable vulns (for coloring). Default true. */
  onlyReachable = true
): { critical: number; high: number; medium: number; low: number } {
  const toCount = onlyReachable ? reachableVulns(vulns) : vulns;
  let critical = 0, high = 0, medium = 0, low = 0;
  toCount.forEach((v) => {
    if (v.severity === 'critical') critical++;
    else if (v.severity === 'high') high++;
    else if (v.severity === 'medium') medium++;
    else if (v.severity === 'low') low++;
  });
  return { critical, high, medium, low };
}

const CENTER_ID = VULN_CENTER_ID;

/**
 * Builds only dependency and vulnerability nodes/edges (no center node).
 * Used by project layout (with centerId = VULN_CENTER_ID) and by team/org layouts
 * (with centerId = project-${id}, then positions translated by project node).
 * Node/edge colors only consider reachable vulnerabilities. When showOnlyReachable
 * is true, vulnerability nodes for unreachable vulns are not created.
 */
export function buildDepAndVulnNodesAndEdges(
  centerId: string,
  depNodes: VulnGraphDepNode[],
  /** When true, only show vulnerability nodes for reachable vulns. */
  showOnlyReachable = false
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const centerX = 0;
  const centerY = 0;

  if (depNodes.length === 0) return { nodes, edges };

  const directDeps = depNodes.filter((d) => d.parentId === centerId);
  const transitiveDeps = depNodes.filter((d) => d.parentId !== centerId);

  const worstSeverityByParent = new Map<string, WorstSeverity>();
  transitiveDeps.forEach((d) => {
    if (d.isZombie) return;
    for (const v of reachableVulns(d.vulnerabilities)) {
      const s = v.severity as WorstSeverity;
      if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') {
        const parent = d.parentId;
        const cur = worstSeverityByParent.get(parent!) ?? 'none';
        const order: WorstSeverity[] = ['none', 'low', 'medium', 'high', 'critical'];
        if (order.indexOf(s) > order.indexOf(cur)) worstSeverityByParent.set(parent!, s);
      }
    }
  });

  const getEdgeSeverity = (dep: VulnGraphDepNode): WorstSeverity => {
    if (dep.isZombie) return 'none';
    const counts = countVulnsBySeverity(dep.vulnerabilities, true);
    if (counts.critical > 0) return 'critical';
    if (counts.high > 0) return 'high';
    if (counts.medium > 0) return 'medium';
    if (counts.low > 0) return 'low';
    return worstSeverityByParent.get(dep.id) ?? 'none';
  };

  const directRadius = Math.max(320, 280 + directDeps.length * 28);
  const transitiveRadius = directRadius + 220;
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));

  const depAngles = new Map<string, number>();
  const depPositions = new Map<string, { x: number; y: number; angle: number }>();

  directDeps.forEach((dep, i) => {
    const angle = i * goldenAngle;
    depAngles.set(dep.id, angle);
    const x = centerX + Math.cos(angle) * directRadius - DEP_NODE_WIDTH / 2;
    const y = centerY + Math.sin(angle) * directRadius - DEP_NODE_HEIGHT / 2;
    depPositions.set(dep.id, {
      x: x + DEP_NODE_WIDTH / 2,
      y: y + DEP_NODE_HEIGHT / 2,
      angle,
    });
    const counts = countVulnsBySeverity(dep.vulnerabilities, true);
    const isZombie = dep.isZombie === true;
    const vulnsForDisplay = showOnlyReachable ? reachableVulns(dep.vulnerabilities) : dep.vulnerabilities;
    nodes.push({
      id: dep.id,
      type: 'dependencyNode',
      position: { x, y },
      data: {
        name: dep.name,
        version: dep.version,
        score: null,
        license: dep.license ?? null,
        policies: null,
        criticalVulns: counts.critical,
        highVulns: counts.high,
        mediumVulns: counts.medium,
        lowVulns: counts.low,
        vulnerabilities: vulnsForDisplay,
        showLicense: false,
        notImported: isZombie,
      } satisfies DependencyNodeData,
      draggable: true,
      selectable: false,
      ...(isZombie && { style: { opacity: 0.5 } }),
    });

    const edgeSeverity = getEdgeSeverity(dep);
    const hasVulnsInSubtree = edgeSeverity !== 'none';
    let strokeColor = 'rgba(100, 116, 139, 0.25)';
    if (edgeSeverity === 'critical') strokeColor = 'rgba(239, 68, 68, 0.45)';
    else if (edgeSeverity === 'high') strokeColor = 'rgba(249, 115, 22, 0.45)';
    else if (edgeSeverity === 'medium') strokeColor = 'rgba(234, 179, 8, 0.35)';
    else if (edgeSeverity === 'low') strokeColor = 'rgba(100, 116, 139, 0.35)';
    const { sourceHandle, targetHandle } = getHandlePair(angle);
    edges.push({
      id: `edge-${dep.id}`,
      source: centerId,
      target: dep.id,
      sourceHandle,
      targetHandle,
      type: 'default',
      animated: hasVulnsInSubtree,
      style: { stroke: strokeColor, strokeWidth: hasVulnsInSubtree ? 1.8 : 1.2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor, width: 14, height: 14 },
    });
  });

  const byParent = new Map<string, VulnGraphDepNode[]>();
  transitiveDeps.forEach((d) => {
    const list = byParent.get(d.parentId!) ?? [];
    list.push(d);
    byParent.set(d.parentId!, list);
  });

  let transIdx = 0;
  byParent.forEach((list, parentId) => {
    const parentAngle = depAngles.get(parentId) ?? transIdx * goldenAngle;
    const spread = Math.min(list.length * 0.4, 1.2);
    const startAngle = parentAngle - spread / 2;
    const step = list.length > 1 ? spread / (list.length - 1) : 0;
    list.forEach((dep, i) => {
      const angle = list.length === 1 ? parentAngle : startAngle + i * step;
      transIdx++;
      depAngles.set(dep.id, angle);
      const x = centerX + Math.cos(angle) * transitiveRadius - DEP_NODE_WIDTH / 2;
      const y = centerY + Math.sin(angle) * transitiveRadius - DEP_NODE_HEIGHT / 2;
      depPositions.set(dep.id, {
        x: x + DEP_NODE_WIDTH / 2,
        y: y + DEP_NODE_HEIGHT / 2,
        angle,
      });
      const counts = countVulnsBySeverity(dep.vulnerabilities, true);
      const isZombieTrans = dep.isZombie === true;
      const vulnsForDisplayTrans = showOnlyReachable ? reachableVulns(dep.vulnerabilities) : dep.vulnerabilities;
      nodes.push({
        id: dep.id,
        type: 'dependencyNode',
        position: { x, y },
        data: {
          name: dep.name,
          version: dep.version,
          score: null,
          license: dep.license ?? null,
          policies: null,
          criticalVulns: counts.critical,
          highVulns: counts.high,
          mediumVulns: counts.medium,
          lowVulns: counts.low,
          vulnerabilities: vulnsForDisplayTrans,
          showLicense: false,
        } satisfies DependencyNodeData,
        draggable: true,
        selectable: false,
        ...(isZombieTrans && { style: { opacity: 0.5 } }),
      });

      const hasSignificantVulns = !isZombieTrans && (counts.critical > 0 || counts.high > 0 || counts.medium > 0);
      let strokeColor = 'rgba(100, 116, 139, 0.25)';
      if (!isZombieTrans) {
        if (counts.critical > 0) strokeColor = 'rgba(239, 68, 68, 0.45)';
        else if (counts.high > 0) strokeColor = 'rgba(249, 115, 22, 0.45)';
        else if (counts.medium > 0) strokeColor = 'rgba(234, 179, 8, 0.35)';
      }
      const fromParent = getVulnHandlePair(angle);
      const toChild = getHandlePair(angle);
      edges.push({
        id: `edge-${dep.id}`,
        source: parentId,
        target: dep.id,
        sourceHandle: fromParent.sourceHandle,
        targetHandle: toChild.targetHandle,
        type: 'default',
        animated: hasSignificantVulns,
        style: { stroke: strokeColor, strokeWidth: hasSignificantVulns ? 1.8 : 1.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor, width: 14, height: 14 },
      });
    });
  });

  const VULN_OFFSET_RADIUS = 280;
  depNodes.forEach((dep) => {
    const vulnsToShow = showOnlyReachable ? reachableVulns(dep.vulnerabilities) : dep.vulnerabilities;
    if (vulnsToShow.length === 0) return;
    const pos = depPositions.get(dep.id);
    if (!pos) return;
    const vulnCount = vulnsToShow.length;
    const fanSpread = Math.min(vulnCount - 1, 5) * 0.35;
    const startAngle = pos.angle - fanSpread / 2;
    const angleStep = vulnCount > 1 ? fanSpread / (vulnCount - 1) : 0;
    vulnsToShow.forEach((vuln, vulnIdx) => {
      const vulnNodeId = `vuln-${dep.id}-${vuln.osv_id}`;
      const vulnAngle = vulnCount === 1 ? pos.angle : startAngle + vulnIdx * angleStep;
      const vulnX = pos.x + Math.cos(vulnAngle) * VULN_OFFSET_RADIUS - VULN_NODE_WIDTH / 2;
      const vulnY = pos.y + Math.sin(vulnAngle) * VULN_OFFSET_RADIUS - VULN_NODE_HEIGHT / 2;
      const vulnIsZombie = dep.isZombie === true;
      nodes.push({
        id: vulnNodeId,
        type: 'vulnerabilityNode',
        position: { x: vulnX, y: vulnY },
        data: {
          osvId: vuln.osv_id,
          severity: vuln.severity,
          summary: vuln.summary,
          aliases: vuln.aliases,
          depscore: vuln.depscore ?? undefined,
          epss_score: vuln.epss_score,
          cisa_kev: vuln.cisa_kev,
          is_reachable: vuln.is_reachable,
          fixed_versions: vuln.fixed_versions,
        } satisfies VulnerabilityNodeData,
        draggable: true,
        selectable: false,
        ...(vulnIsZombie && { style: { opacity: 0.5 } }),
      });
      const edgeColor = getVulnEdgeColor(vuln.severity);
      const { sourceHandle, targetHandle } = getVulnHandlePair(vulnAngle);
      edges.push({
        id: `vuln-edge-${dep.id}-${vuln.osv_id}`,
        source: dep.id,
        target: vulnNodeId,
        sourceHandle,
        targetHandle,
        type: 'default',
        animated: true,
        style: { stroke: edgeColor, strokeWidth: 1.4, strokeDasharray: '6 3' },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor, width: 12, height: 12 },
      });
    });
  });

  return { nodes, edges };
}

export type WorstSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none';

/** Worst severity among deps; only considers reachable vulns and non-zombie deps for center/node color. */
export function getWorstSeverity(depNodes: VulnGraphDepNode[]): WorstSeverity {
  let hasLow = false;
  let hasMedium = false;
  let hasHigh = false;
  let hasCritical = false;
  for (const dep of depNodes) {
    if (dep.isZombie) continue;
    for (const v of reachableVulns(dep.vulnerabilities)) {
      if (v.severity === 'critical') hasCritical = true;
      else if (v.severity === 'high') hasHigh = true;
      else if (v.severity === 'medium') hasMedium = true;
      else if (v.severity === 'low') hasLow = true;
    }
  }
  if (hasCritical) return 'critical';
  if (hasHigh) return 'high';
  if (hasMedium) return 'medium';
  if (hasLow) return 'low';
  return 'none';
}

/** Builds the center (project) node for the vulnerabilities graph. Exported so the graph can ensure it is always present when syncing. */
export function createVulnerabilitiesCenterNode(
  projectName: string,
  depNodes: VulnGraphDepNode[],
  framework?: string | null,
  _vulnerableDependenciesLabel?: string
): Node {
  const worstSeverity = getWorstSeverity(depNodes);
  return {
    id: VULN_CENTER_ID,
    type: 'projectCenterNode',
    position: {
      x: -CENTER_NODE_WIDTH / 2,
      y: -CENTER_NODE_HEIGHT / 2,
    },
    data: {
      projectName,
      worstVulnerabilitySeverity: worstSeverity,
      frameworkName: framework ?? undefined,
    },
    draggable: true,
    selectable: false,
  };
}

/**
 * Builds React Flow nodes and edges for the project vulnerabilities graph:
 * center (project) → direct deps with vulns → transitive deps with vulns, plus vuln nodes per dep.
 */
export function useVulnerabilitiesGraphLayout(
  projectName: string,
  depNodes: VulnGraphDepNode[],
  framework?: string | null,
  _vulnerableDependenciesLabel?: string,
  _centerExtras?: VulnGraphCenterExtras | null,
  showOnlyReachable = false
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];

    nodes.push(createVulnerabilitiesCenterNode(projectName, depNodes, framework));

    const sub = buildDepAndVulnNodesAndEdges(CENTER_ID, depNodes, showOnlyReachable);
    nodes.push(...sub.nodes);
    edges.push(...sub.edges);

    return { nodes, edges };
  }, [projectName, depNodes, framework, _vulnerableDependenciesLabel, _centerExtras, showOnlyReachable]);
}
