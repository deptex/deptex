import { useMemo } from 'react';
import { type Node, type Edge, MarkerType, Position } from '@xyflow/react';
import type { SupplyChainResponse, SupplyChainChild, SupplyChainAvailableVersion, SupplyChainBumpPr, ProjectEffectivePolicies, BannedVersion, SupplyChainVersionSecurityData, VersionVulnerabilitySummaryItem } from '../../lib/api';
import type { AssetTier } from '../../lib/api';
import { calculateDepscore, SEVERITY_TO_CVSS } from '../../lib/scoring/depscore';

// Node dimensions for layout calculation
const CENTER_NODE_WIDTH = 260;
const CENTER_NODE_HEIGHT = 80;
const DEP_NODE_WIDTH = 240;
const DEP_NODE_HEIGHT = 72;
const VULN_NODE_WIDTH = 210;
const VULN_NODE_HEIGHT = 70;

export interface CenterNodeData {
  name: string;
  version: string;
  isDirect: boolean;
  childCount: number;
  vulnChildCount: number;
  worstVulnerabilitySeverity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  license: string | null;
  policies: ProjectEffectivePolicies | null;
  availableVersions: SupplyChainAvailableVersion[];
  selectedVersionId: string;
  onVersionChange: (dependencyVersionId: string) => void;
  // PR integration
  isViewingAlternateVersion: boolean;
  originalVersion: string;
  bumpPrs: SupplyChainBumpPr[];
  dependencyId: string;
  orgId: string;
  projectId: string;
  onPrCreated: (pr: SupplyChainBumpPr) => void;
  // Ban integration
  canManage: boolean;
  bannedVersions: BannedVersion[];
  bannedVersionsLoading?: boolean;
  /** When true, we are still loading bump scope (canManage unknown); show loading strip to avoid empty flash. */
  bumpScopeLoading?: boolean;
  onBanClick: (version: string) => void;
  onUnbanClick: (banId: string) => void;
  // Watchtower: current project version + per-version security/quarantine (only when org has package on watchtower)
  currentVersion?: string;
  versionSecurityData?: SupplyChainVersionSecurityData | null;
  /** Safest version (from latest-safe-version) for "Safest version" badge in dropdown */
  safeVersion?: string | null;
  /** Per-version vulnerability flags for dropdown (direct or transitive). */
  versionVulnerabilitySummary?: Record<string, VersionVulnerabilitySummaryItem> | null;
  /** When true, show spinner in version dropdown area (loading version supply chain). */
  versionSwitching?: boolean;
  /** When provided, version area opens this sidebar instead of showing dropdown. */
  onOpenVersionsSidebar?: () => void;
}

export interface DependencyNodeData {
  name: string;
  version: string;
  score: number | null;
  license: string | null;
  policies: ProjectEffectivePolicies | null;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  vulnerabilities: SupplyChainChild['vulnerabilities'];
  /** When false, hide the license badge (e.g. on vulnerabilities graph). Default true. */
  showLicense?: boolean;
  /** When true, show "Not imported" badge (e.g. direct dep that is a zombie on vulnerabilities graph). */
  notImported?: boolean;
}

export interface VulnerabilityNodeData {
  osvId: string;
  severity: string;
  summary: string | null;
  aliases: string[];
  /** Depscore (0-100) when asset tier is available for layout. */
  depscore?: number;
}

/**
 * Simple seeded PRNG (mulberry32) for deterministic "random" layout.
 * Ensures the scatter looks the same on every re-render.
 */
function seededRandom(seed: number) {
  let t = (seed + 0x6d2b79f5) | 0;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}

/**
 * Given an angle in radians, return which handle side (top/right/bottom/left)
 * of the CENTER node the edge should exit from, and which side of the
 * CHILD node the edge should enter.
 */
function getHandlePair(angle: number): { sourceHandle: string; targetHandle: string } {
  // Normalize angle to [0, 2π)
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);

  // Determine which quadrant the child is in relative to center
  if (a < Math.PI / 4 || a >= (7 * Math.PI) / 4) {
    return { sourceHandle: 'right', targetHandle: 'left' };
  } else if (a < (3 * Math.PI) / 4) {
    return { sourceHandle: 'bottom', targetHandle: 'top' };
  } else if (a < (5 * Math.PI) / 4) {
    return { sourceHandle: 'left', targetHandle: 'right' };
  } else {
    return { sourceHandle: 'top', targetHandle: 'bottom' };
  }
}

/**
 * Given an angle (dep→vuln direction), return the source handle on the dep node
 * and the target handle on the vuln node.
 */
function getVulnHandlePair(angle: number): { sourceHandle: string; targetHandle: string } {
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);

  if (a < Math.PI / 4 || a >= (7 * Math.PI) / 4) {
    return { sourceHandle: 'source-right', targetHandle: 'left' };
  } else if (a < (3 * Math.PI) / 4) {
    return { sourceHandle: 'source-bottom', targetHandle: 'top' };
  } else if (a < (5 * Math.PI) / 4) {
    return { sourceHandle: 'source-left', targetHandle: 'right' };
  } else {
    return { sourceHandle: 'source-top', targetHandle: 'bottom' };
  }
}

/** Severity color for vulnerability edges */
function getVulnEdgeColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'rgba(239, 68, 68, 0.55)';
    case 'high':
      return 'rgba(249, 115, 22, 0.50)';
    case 'medium':
      return 'rgba(234, 179, 8, 0.45)';
    case 'low':
      return 'rgba(100, 116, 139, 0.35)';
    default:
      return 'rgba(100, 116, 139, 0.30)';
  }
}

/**
 * Converts SupplyChainResponse data into positioned React Flow nodes and edges
 * using a radial scatter layout — children are distributed organically around
 * the center node instead of in a uniform tree row.
 *
 * Vulnerability nodes are placed as separate cards radiating outward from
 * their parent dependency node.
 */
export function useGraphLayout(
  data: SupplyChainResponse | null,
  versionSwitcher?: {
    availableVersions: SupplyChainAvailableVersion[];
    selectedVersionId: string;
    selectedVersion: string;
    onVersionChange: (dependencyVersionId: string) => void;
  },
  extras?: {
    policies: ProjectEffectivePolicies | null;
    isViewingAlternateVersion: boolean;
    originalVersion: string;
    bumpPrs: SupplyChainBumpPr[];
    dependencyId: string;
    orgId: string;
    projectId: string;
    onPrCreated: (pr: SupplyChainBumpPr) => void;
    canManage: boolean;
    bannedVersions: BannedVersion[];
    bannedVersionsLoading?: boolean;
    bumpScopeLoading?: boolean;
    onBanClick: (version: string) => void;
    onUnbanClick: (banId: string) => void;
    currentVersion?: string;
    versionSecurityData?: SupplyChainVersionSecurityData | null;
    safeVersion?: string | null;
    versionSwitching?: boolean;
    onOpenVersionsSidebar?: () => void;
    assetTier?: AssetTier;
  }
) {
  const tier: AssetTier = extras?.assetTier ?? 'EXTERNAL';

  const vulnToNodeData = (vuln: { osv_id: string; severity: string; summary: string | null; aliases: string[]; depscore?: number | null; cvss_score?: number | null; epss_score?: number | null; cisa_kev?: boolean; is_reachable?: boolean }): VulnerabilityNodeData => {
    const cvss = vuln.cvss_score ?? (vuln.severity ? (SEVERITY_TO_CVSS[vuln.severity] ?? 0) : 0);
    const depscore = vuln.depscore != null && Number.isFinite(vuln.depscore)
      ? vuln.depscore
      : calculateDepscore({
          cvss,
          epss: vuln.epss_score ?? 0,
          cisaKev: vuln.cisa_kev ?? false,
          isReachable: vuln.is_reachable ?? true,
          assetTier: tier,
        });
    return {
      osvId: vuln.osv_id,
      severity: vuln.severity,
      summary: vuln.summary,
      aliases: vuln.aliases ?? [],
      depscore,
    };
  };

  return useMemo(() => {
    if (!data) {
      return { nodes: [], edges: [] };
    }

    const childrenWithVulns = data.children.filter(
      (c) => c.critical_vulns + c.high_vulns + c.medium_vulns + c.low_vulns > 0
    );

    // Parent's own vulnerabilities
    const parentVulns = data.parent.vulnerabilities ?? [];

    // Determine the worst vulnerability severity across all children AND parent
    let worstSeverity: 'critical' | 'high' | 'medium' | 'low' | 'none' = 'none';

    // Check parent's own vulnerabilities
    for (const v of parentVulns) {
      const s = (v as { severity?: string }).severity;
      if (s === 'critical') { worstSeverity = 'critical'; break; }
      if (s === 'high' && (worstSeverity as string) !== 'critical') worstSeverity = 'high';
      if (s === 'medium' && (worstSeverity as string) !== 'critical' && worstSeverity !== 'high') worstSeverity = 'medium';
      if (s === 'low' && worstSeverity === 'none') worstSeverity = 'low';
    }

    // Check children's vulnerabilities (use string cast to avoid TS narrowing on 'critical')
    for (const child of data.children) {
      if ((worstSeverity as string) === 'critical') break;
      if (child.critical_vulns > 0) {
        worstSeverity = 'critical';
        break; // Can't get worse than critical
      } else if (child.high_vulns > 0 && (worstSeverity as string) !== 'critical') {
        worstSeverity = 'high';
      } else if (child.medium_vulns > 0 && (worstSeverity as string) !== 'critical' && worstSeverity !== 'high') {
        worstSeverity = 'medium';
      } else if (child.low_vulns > 0 && worstSeverity === 'none') {
        worstSeverity = 'low';
      }
    }

    const count = data.children.length;

    // --- Radial scatter parameters ---
    const baseRadius = Math.max(360, 300 + count * 32);
    const rings = count <= 8 ? 1 : count <= 20 ? 2 : 3;

    // Place center node at origin
    const centerX = 0;
    const centerY = 0;

    // Build React Flow nodes
    const nodes: Node[] = [];

    // Center/parent node (always shown, even with 0 children, so version dropdown remains accessible)
    nodes.push({
      id: 'parent',
      type: 'centerNode',
      position: {
        x: centerX - CENTER_NODE_WIDTH / 2,
        y: centerY - CENTER_NODE_HEIGHT / 2,
      },
      data: {
        name: data.parent.name,
        version: versionSwitcher?.selectedVersion ?? data.parent.version,
        isDirect: data.parent.is_direct,
        childCount: data.children.length,
        vulnChildCount: childrenWithVulns.length,
        worstVulnerabilitySeverity: worstSeverity,
        license: data.parent.license ?? null,
        policies: extras?.policies ?? null,
        availableVersions: versionSwitcher?.availableVersions ?? data.availableVersions ?? [],
        selectedVersionId: versionSwitcher?.selectedVersionId ?? data.parent.dependency_version_id,
        onVersionChange: versionSwitcher?.onVersionChange ?? (() => { }),
        isViewingAlternateVersion: extras?.isViewingAlternateVersion ?? false,
        originalVersion: extras?.originalVersion ?? data.parent.version,
        bumpPrs: extras?.bumpPrs ?? [],
        dependencyId: extras?.dependencyId ?? '',
        orgId: extras?.orgId ?? '',
        projectId: extras?.projectId ?? '',
        onPrCreated: extras?.onPrCreated ?? (() => { }),
        canManage: extras?.canManage ?? false,
        bannedVersions: extras?.bannedVersions ?? [],
        bannedVersionsLoading: extras?.bannedVersionsLoading ?? false,
        bumpScopeLoading: extras?.bumpScopeLoading ?? false,
        onBanClick: extras?.onBanClick ?? (() => { }),
        onUnbanClick: extras?.onUnbanClick ?? (() => { }),
        currentVersion: extras?.currentVersion ?? data.parent.version,
        versionSecurityData: extras?.versionSecurityData ?? null,
        safeVersion: extras?.safeVersion ?? null,
        versionVulnerabilitySummary: data.versionVulnerabilitySummary ?? null,
        versionSwitching: extras?.versionSwitching ?? false,
        onOpenVersionsSidebar: extras?.onOpenVersionsSidebar,
      } satisfies CenterNodeData,
      draggable: true,
      selectable: false,
    });

    // If no children, show just the center node (+ parent vuln nodes if any)
    if (count === 0) {
      const edges: Edge[] = [];

      if (parentVulns.length > 0) {
        // Place parent vulnerability nodes radiating outward from center
        const PARENT_VULN_RADIUS = 280;
        const fanSpread = Math.min(parentVulns.length - 1, 5) * 0.35;
        const startAngle = -Math.PI / 2 - fanSpread / 2; // Start from top
        const angleStep = parentVulns.length > 1 ? fanSpread / (parentVulns.length - 1) : 0;

        parentVulns.forEach((vuln, idx) => {
          const vulnNodeId = `vuln-parent-${vuln.osv_id}`;
          const vulnAngle = parentVulns.length === 1 ? -Math.PI / 2 : startAngle + idx * angleStep;

          const vulnX = centerX + Math.cos(vulnAngle) * PARENT_VULN_RADIUS - VULN_NODE_WIDTH / 2;
          const vulnY = centerY + Math.sin(vulnAngle) * PARENT_VULN_RADIUS - VULN_NODE_HEIGHT / 2;

          nodes.push({
            id: vulnNodeId,
            type: 'vulnerabilityNode',
            position: { x: vulnX, y: vulnY },
            data: vulnToNodeData(vuln as Parameters<typeof vulnToNodeData>[0]) as unknown as Record<string, unknown>,
            draggable: true,
            selectable: false,
          });

          // Edge from center → vulnerability
          const edgeColor = getVulnEdgeColor(vuln.severity);
          const { sourceHandle, targetHandle } = getHandlePair(vulnAngle);

          edges.push({
            id: `vuln-edge-parent-${vuln.osv_id}`,
            source: 'parent',
            target: vulnNodeId,
            sourceHandle,
            targetHandle,
            type: 'default',
            animated: true,
            style: {
              stroke: edgeColor,
              strokeWidth: 1.4,
              strokeDasharray: '6 3',
            },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: edgeColor,
              width: 12,
              height: 12,
            },
          });
        });
      }

      return { nodes, edges };
    }

    // --- Assign children to rings ---
    const sorted = [...data.children].sort((a, b) => {
      const aVulns = a.critical_vulns + a.high_vulns + a.medium_vulns + a.low_vulns;
      const bVulns = b.critical_vulns + b.high_vulns + b.medium_vulns + b.low_vulns;
      return bVulns - aVulns;
    });

    const perRing: SupplyChainChild[][] = Array.from({ length: rings }, () => []);
    sorted.forEach((child, i) => {
      perRing[i % rings].push(child);
    });

    // Use a seed derived from the parent name for deterministic jitter
    let seedCounter = 0;
    for (let i = 0; i < data.parent.name.length; i++) {
      seedCounter += data.parent.name.charCodeAt(i);
    }

    // Position each child node — store positions for vulnerability node placement
    const childAngles: Map<string, number> = new Map();
    const childPositions: Map<string, { x: number; y: number; angle: number }> = new Map();

    perRing.forEach((ringChildren, ringIndex) => {
      const ringRadius = baseRadius * (0.85 + ringIndex * 0.5);
      const goldenAngle = Math.PI * (3 - Math.sqrt(5));
      const ringOffset = ringIndex * 0.8;

      ringChildren.forEach((child, i) => {
        const baseAngle = ringOffset + i * goldenAngle;
        const angleSeed = seededRandom(seedCounter++);
        const radiusSeed = seededRandom(seedCounter++);
        const angleJitter = (angleSeed - 0.5) * 0.35;
        const radiusJitter = (radiusSeed - 0.5) * 0.25 * ringRadius;

        const finalAngle = baseAngle + angleJitter;
        const finalRadius = ringRadius + radiusJitter;

        const x = centerX + Math.cos(finalAngle) * finalRadius - DEP_NODE_WIDTH / 2;
        const y = centerY + Math.sin(finalAngle) * finalRadius - DEP_NODE_HEIGHT / 2;

        childAngles.set(child.dependency_version_id, finalAngle);
        childPositions.set(child.dependency_version_id, {
          x: x + DEP_NODE_WIDTH / 2,  // store center position
          y: y + DEP_NODE_HEIGHT / 2,
          angle: finalAngle,
        });

        nodes.push({
          id: child.dependency_version_id,
          type: 'dependencyNode',
          position: { x, y },
          data: {
            name: child.name,
            version: child.version,
            score: child.score,
            license: child.license ?? null,
            policies: extras?.policies ?? null,
            criticalVulns: child.critical_vulns,
            highVulns: child.high_vulns,
            mediumVulns: child.medium_vulns,
            lowVulns: child.low_vulns,
            vulnerabilities: child.vulnerabilities,
          } satisfies DependencyNodeData,
          draggable: true,
          selectable: false,
        });
      });
    });

    // --- Build edges from center → dependency nodes ---
    const edges: Edge[] = data.children.map((child) => {
      const totalVulns =
        child.critical_vulns + child.high_vulns + child.medium_vulns + child.low_vulns;
      const hasVulns = totalVulns > 0;
      const hasCritical = child.critical_vulns > 0;
      const hasHigh = child.high_vulns > 0;

      let strokeColor = 'rgba(100, 116, 139, 0.25)';
      if (hasCritical) strokeColor = 'rgba(239, 68, 68, 0.45)';
      else if (hasHigh) strokeColor = 'rgba(249, 115, 22, 0.45)';
      else if (hasVulns) strokeColor = 'rgba(234, 179, 8, 0.35)';

      const angle = childAngles.get(child.dependency_version_id) ?? 0;
      const { sourceHandle, targetHandle } = getHandlePair(angle);

      return {
        id: `edge-${child.dependency_version_id}`,
        source: 'parent',
        target: child.dependency_version_id,
        sourceHandle,
        targetHandle,
        type: 'default',
        animated: hasVulns,
        style: {
          stroke: strokeColor,
          strokeWidth: hasVulns ? 1.8 : 1.2,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 14,
          height: 14,
        },
      };
    });

    // --- Parent vulnerability nodes (when parent has vulns; even when there are children) ---
    if (parentVulns.length > 0) {
      const PARENT_VULN_RADIUS = 280;
      const fanSpread = Math.min(parentVulns.length - 1, 5) * 0.35;
      const startAngle = -Math.PI / 2 - fanSpread / 2;
      const angleStep = parentVulns.length > 1 ? fanSpread / (parentVulns.length - 1) : 0;

      parentVulns.forEach((vuln, idx) => {
        const vulnNodeId = `vuln-parent-${vuln.osv_id}`;
        const vulnAngle = parentVulns.length === 1 ? -Math.PI / 2 : startAngle + idx * angleStep;

        const vulnX = centerX + Math.cos(vulnAngle) * PARENT_VULN_RADIUS - VULN_NODE_WIDTH / 2;
        const vulnY = centerY + Math.sin(vulnAngle) * PARENT_VULN_RADIUS - VULN_NODE_HEIGHT / 2;

        nodes.push({
          id: vulnNodeId,
          type: 'vulnerabilityNode',
          position: { x: vulnX, y: vulnY },
          data: vulnToNodeData(vuln as Parameters<typeof vulnToNodeData>[0]) as unknown as Record<string, unknown>,
          draggable: true,
          selectable: false,
        });

        const edgeColor = getVulnEdgeColor(vuln.severity);
        const { sourceHandle, targetHandle } = getHandlePair(vulnAngle);

        edges.push({
          id: `vuln-edge-parent-${vuln.osv_id}`,
          source: 'parent',
          target: vulnNodeId,
          sourceHandle,
          targetHandle,
          type: 'default',
          animated: true,
          style: {
            stroke: edgeColor,
            strokeWidth: 1.4,
            strokeDasharray: '6 3',
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: edgeColor,
            width: 12,
            height: 12,
          },
        });
      });
    }

    // --- Create vulnerability nodes + edges (dep → vuln) ---
    // Place vulnerability nodes in a fan radiating outward from the dependency node,
    // away from the center.
    const VULN_OFFSET_RADIUS = 280; // distance from dep center to vuln center

    data.children.forEach((child) => {
      if (child.vulnerabilities.length === 0) return;

      const depPos = childPositions.get(child.dependency_version_id);
      if (!depPos) return;

      const vulnCount = child.vulnerabilities.length;
      // Fan spread: wider if more vulns, capped so it doesn't go crazy
      const fanSpread = Math.min(vulnCount - 1, 5) * 0.35; // radians total spread
      const startAngle = depPos.angle - fanSpread / 2;
      const angleStep = vulnCount > 1 ? fanSpread / (vulnCount - 1) : 0;

      child.vulnerabilities.forEach((vuln, vulnIdx) => {
        const vulnNodeId = `vuln-${child.dependency_version_id}-${vuln.osv_id}`;
        const vulnAngle = vulnCount === 1 ? depPos.angle : startAngle + vulnIdx * angleStep;

        const vulnX = depPos.x + Math.cos(vulnAngle) * VULN_OFFSET_RADIUS - VULN_NODE_WIDTH / 2;
        const vulnY = depPos.y + Math.sin(vulnAngle) * VULN_OFFSET_RADIUS - VULN_NODE_HEIGHT / 2;

        nodes.push({
          id: vulnNodeId,
          type: 'vulnerabilityNode',
          position: { x: vulnX, y: vulnY },
          data: vulnToNodeData(vuln as Parameters<typeof vulnToNodeData>[0]) as unknown as Record<string, unknown>,
          draggable: true,
          selectable: false,
        });

        // Edge from dependency → vulnerability
        const edgeColor = getVulnEdgeColor(vuln.severity);
        const { sourceHandle, targetHandle } = getVulnHandlePair(vulnAngle);

        edges.push({
          id: `vuln-edge-${child.dependency_version_id}-${vuln.osv_id}`,
          source: child.dependency_version_id,
          target: vulnNodeId,
          sourceHandle,
          targetHandle,
          type: 'default',
          animated: true,
          style: {
            stroke: edgeColor,
            strokeWidth: 1.4,
            strokeDasharray: '6 3',
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: edgeColor,
            width: 12,
            height: 12,
          },
        });
      });
    });

    return { nodes, edges };
  }, [data, versionSwitcher?.selectedVersionId, versionSwitcher?.availableVersions, versionSwitcher?.selectedVersion, versionSwitcher?.onVersionChange, extras?.policies, extras?.isViewingAlternateVersion, extras?.originalVersion, extras?.bumpPrs, extras?.dependencyId, extras?.orgId, extras?.projectId, extras?.onPrCreated, extras?.canManage, extras?.bannedVersions, extras?.bannedVersionsLoading, extras?.bumpScopeLoading, extras?.onBanClick, extras?.onUnbanClick, extras?.currentVersion, extras?.versionSecurityData, extras?.safeVersion, extras?.versionSwitching, extras?.onOpenVersionsSidebar, extras?.assetTier, data?.versionVulnerabilitySummary]);
}
