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
  useReactFlow,
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
import { useHeroCanvasChoreography } from "./useHeroCanvasChoreography";
import { HERO_TEAMS, HERO_ORG_NAME, HERO_ORG_AVATAR } from "./heroDemo";
import { Plus, Minus, Maximize2 } from "lucide-react";
import { Button } from "../ui/button";
import { Tooltip, TooltipTrigger, TooltipContent } from "../ui/tooltip";

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

// Remote "teammates" are scripted by useHeroCanvasChoreography, which feeds the
// real OrgCanvasCursors layer the same RemoteCursor[] / remoteDraggers inputs a
// live multiplayer session would (no realtime/auth on a public page).

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

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>(layoutNodes);
  const [edges, , onEdgesChange] = useEdgesState<Edge>(layoutEdges);
  const rf = useReactFlow();

  // Scripted multiplayer: a teammate cursor picks up a project, moves it, puts
  // it back — driving the real cursor layer + the real `remote-dragging` styling.
  const { cursors, draggers } = useHeroCanvasChoreography(setNodes);

  return (
    <div className="relative h-full w-full">
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
          remoteCursors={cursors}
          onLocalCursorMove={noop}
          onLocalCursorLeave={noop}
          remoteDraggers={draggers}
          graphNodes={nodes}
        />
      </ReactFlow>

      {/* Zoom / recenter rail — bottom-right (the real overview's Railway-style
          rail, mirrored to the right corner). */}
      <div className="absolute bottom-3 right-3 z-10 flex flex-col items-center gap-0.5 rounded-lg border border-border bg-background-card-header p-1 shadow-sm">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
              onClick={() => rf.zoomIn({ duration: 150 })}
              aria-label="Zoom in"
            >
              <Plus className="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="left">Zoom in</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
              onClick={() => rf.zoomOut({ duration: 150 })}
              aria-label="Zoom out"
            >
              <Minus className="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="left">Zoom out</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-foreground-secondary hover:bg-white/5 hover:text-foreground"
              onClick={() => rf.fitView({ padding: 0.1, maxZoom: 1.15, duration: 300 })}
              aria-label="Fit view"
            >
              <Maximize2 className="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="left">Fit view</TooltipContent>
        </Tooltip>
      </div>
    </div>
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
