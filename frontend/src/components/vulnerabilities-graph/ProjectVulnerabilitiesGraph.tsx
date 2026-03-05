import { useState, useEffect, useRef } from 'react';
import {
  ReactFlow,
  Background,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  type Node,
  type Edge,
  type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ProjectCenterNode } from './ProjectCenterNode';
import { SkeletonProjectCenterNode } from './SkeletonProjectCenterNode';
import { DependencyNode } from '../supply-chain/DependencyNode';
import { VulnerabilityNode } from '../supply-chain/VulnerabilityNode';
import {
  useVulnerabilitiesGraphLayout,
  createVulnerabilitiesCenterNode,
  createExtractingCenterNode,
  type VulnGraphDepNode,
  type VulnGraphCenterExtras,
  VULN_CENTER_NODE_WIDTH,
  VULN_CENTER_NODE_HEIGHT,
  VULN_CENTER_ID,
} from './useVulnerabilitiesGraphLayout';

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

function extractingCenterNodes(projectName: string) {
  return [createExtractingCenterNode(projectName)];
}

export interface ProjectVulnerabilitiesGraphProps {
  projectName: string;
  vulnerableDependenciesLabel: string;
  framework?: string | null;
  graphDepNodes: VulnGraphDepNode[];
  graphLoading: boolean;
  vulnerabilitiesLoading?: boolean;
  centerExtras?: VulnGraphCenterExtras | null;
  showOnlyReachable?: boolean;
  extractionOngoing?: boolean;
  onNodeClick?: (event: React.MouseEvent, node: Node) => void;
  /** Project status from policy (e.g. Compliant, Under Review). Shown as badge on center node. */
  statusName?: string | null;
  statusColor?: string | null;
}

export function ProjectVulnerabilitiesGraph({
  projectName,
  vulnerableDependenciesLabel,
  framework,
  graphDepNodes,
  graphLoading,
  vulnerabilitiesLoading = false,
  centerExtras,
  showOnlyReachable = false,
  extractionOngoing = false,
  onNodeClick,
  statusName,
  statusColor,
}: ProjectVulnerabilitiesGraphProps) {
  const loading = graphLoading || vulnerabilitiesLoading;
  const { nodes: layoutNodes, edges: layoutEdges } = useVulnerabilitiesGraphLayout(
    projectName,
    graphDepNodes,
    framework,
    vulnerableDependenciesLabel,
    centerExtras,
    showOnlyReachable,
    statusName,
    statusColor
  );
  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>(skeletonNodes);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const layoutSignature =
    layoutNodes.length + '-' + layoutNodes.map((n) => n.id).join(',');
  const lastAppliedLayoutRef = useRef<string | null>(null);
  if (loading) lastAppliedLayoutRef.current = null;

  useEffect(() => {
    if (extractionOngoing) {
      setGraphNodes(extractingCenterNodes(projectName));
      setGraphEdges([]);
      return;
    }
    if (
      !loading &&
      layoutNodes.length > 0 &&
      lastAppliedLayoutRef.current !== layoutSignature
    ) {
      lastAppliedLayoutRef.current = layoutSignature;
      const hasCenter = layoutNodes.some((n) => n.id === VULN_CENTER_ID);
      const nodesToSet = hasCenter
        ? layoutNodes
        : [
            createVulnerabilitiesCenterNode(projectName, graphDepNodes, framework, undefined, statusName, statusColor),
            ...layoutNodes.filter((n) => n.id !== VULN_CENTER_ID),
          ];
      setGraphNodes(nodesToSet);
      setGraphEdges(layoutEdges);
    }
  }, [
    extractionOngoing,
    projectName,
    loading,
    layoutSignature,
    layoutNodes,
    layoutEdges,
    setGraphNodes,
    setGraphEdges,
    graphDepNodes,
    framework,
    statusName,
    statusColor,
  ]);

  const stillShowingSkeleton =
    !extractionOngoing &&
    (loading ||
      (layoutNodes.length > 0 &&
        graphNodes.length === 1 &&
        graphNodes[0]?.id === 'skeleton-center'));

  return (
    <ReactFlow
      nodes={
        stillShowingSkeleton
          ? skeletonNodes
          : extractionOngoing
            ? extractingCenterNodes(projectName)
            : graphNodes
      }
      edges={stillShowingSkeleton || extractionOngoing ? [] : graphEdges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      nodeTypes={stillShowingSkeleton ? skeletonCenterNodeTypes : vulnerabilityGraphNodeTypes}
      fitView={stillShowingSkeleton || extractionOngoing}
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
