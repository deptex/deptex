/**
 * HeroOverviewGraph — the REAL org-overview graph, embedded (founder 2026-06-16).
 *
 * Not a facsimile: this mounts the actual ReactFlow graph from
 * OrganizationOverviewPage using the real node components (GroupCenterNode /
 * VulnProjectNode / TeamGroupNode), the real layout engine
 * (useOrganizationOverviewGraphLayout), the real ReactiveDotGrid background, the
 * real OrgCanvasCursors layer, and the real `.org-overview-hub-flow` styling
 * (flowing dashed edges + grab affordance, all in Main.css). The only thing
 * faked is the INPUT — hand-written mock data for one org + 2 teams (3 & 2
 * projects) and two static demo cursors (no auth / supabase / realtime). Pan is
 * on for a little explorability; scroll-zoom is off so the page still scrolls.
 *
 * All these pieces are pure presentational / pure-useMemo — verified zero
 * coupling to router/auth/supabase — so they compose standalone. See
 * [[feedback_landing_use_real_components]].
 */
import {
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { GroupCenterNode } from "../vulnerabilities-graph/GroupCenterNode";
import { VulnProjectNode } from "../vulnerabilities-graph/VulnProjectNode";
import { TeamGroupNode } from "../vulnerabilities-graph/TeamGroupNode";
import { ReactiveDotGrid } from "../vulnerabilities-graph/ReactiveDotGrid";
import { OrgCanvasCursors } from "../vulnerabilities-graph/OrgCanvasCursors";
import { useOrganizationOverviewGraphLayout } from "../vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout";
import type { RemoteCursor } from "../vulnerabilities-graph/useOrgCanvasCursors";
import { HERO_TEAMS, HERO_ORG_NAME, HERO_ORG_AVATAR } from "./heroDemo";

// Per-project severity-count pills render natively inside VulnProjectNode (xs
// SeverityPills) when bandCounts is supplied — fed via heroDemo / the layout.
const nodeTypes = {
  groupCenterNode: GroupCenterNode,
  vulnProjectNode: VulnProjectNode,
  teamGroupNode: TeamGroupNode,
};

// Projects + teams come from the shared heroDemo dataset (the same source the
// Findings table reads) so the two tabs stay consistent. Each carries an
// explicit canvasPositionX/Y — without saved positions the layout stacks them
// all at one spawn point (org center at 0,0; Platform left, Payments right).

// Static "teammates" via the real OrgCanvasCursors layer (realtime not required
// on a public page). Temporarily disabled (founder 2026-06-16) — restore by
// re-adding entries here:
//   { userId: "sarah", sessionId: "s1", name: "Sarah", avatarUrl: null, role: "owner", roleLabel: "Owner", roleColor: "#34d08a", x: 96, y: -52 },
//   { userId: "marcus", sessionId: "s2", name: "Marcus", avatarUrl: null, role: "member", roleLabel: "Member", roleColor: "#60a5fa", x: -156, y: 86 },
const DEMO_CURSORS: RemoteCursor[] = [];

const noop = () => {};

function Graph() {
  const { nodes: layoutNodes, edges: layoutEdges } =
    useOrganizationOverviewGraphLayout(
      HERO_ORG_NAME,
      HERO_TEAMS,
      HERO_ORG_AVATAR,
      "Owner",
      undefined,
      "demo-org",
      "owner",
      null,
      null,
      false,
    );

  const [nodes, , onNodesChange] = useNodesState<Node>(layoutNodes);
  const [edges, , onEdgesChange] = useEdgesState<Edge>(layoutEdges);

  return (
    <ReactFlow
      className="org-overview-hub-flow"
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.1, maxZoom: 1.15 }}
      minZoom={0.12}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      nodesConnectable={false}
      panOnDrag
      zoomOnScroll={false}
      zoomOnPinch
      preventScrolling={false}
    >
      <ReactiveDotGrid />
      <OrgCanvasCursors
        remoteCursors={DEMO_CURSORS}
        onLocalCursorMove={noop}
        onLocalCursorLeave={noop}
        remoteDraggers={{}}
        graphNodes={nodes}
      />
    </ReactFlow>
  );
}

export default function HeroOverviewGraph() {
  return (
    <div className="h-full w-full bg-[#050505]">
      <ReactFlowProvider>
        <Graph />
      </ReactFlowProvider>
    </div>
  );
}
