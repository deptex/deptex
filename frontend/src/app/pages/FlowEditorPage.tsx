import { Fragment, memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ReactFlow,
  ReactFlowProvider,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node as RFNode,
  type Edge as RFEdge,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Zap,
  GitBranch,
  Split,
  Send,
  Filter,
  Clock,
  GitMerge,
  CalendarClock,
  Wand2,
  Workflow,
  Plus,
  X,
  Box,
  Bug,
  Check,
  type LucideIcon,
} from 'lucide-react';
import { api, type Flow, type FlowGraph, type FlowNode } from '../../lib/api';
import { ReactiveDotGrid } from '../../components/vulnerabilities-graph/ReactiveDotGrid';
import { setCanvasDragging } from '../../components/vulnerabilities-graph/canvasDragSignal';
import { useToast } from '../../hooks/use-toast';
import { cn } from '../../lib/utils';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../../components/ui/dialog';
import { Button } from '../../components/ui/button';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '../../components/ui/select';
import { EVENT_SCHEMAS, type EventField, type EventFieldType } from '../../lib/flow-event-schemas';
import { FlowCodeEditor } from '../../components/flow/FlowCodeEditor';
import { toBody, wrapBody } from '../../lib/code-body-helpers';
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs';

const NODE_WIDTH = 60;
const NODE_HEIGHT = 60;
const NODE_HORIZONTAL_GAP = 220;
const NODE_VERTICAL_BRANCH_GAP = 130;
const EDGE_STROKE = '#262626';

const HANDLE_STYLE = {
  opacity: 0,
  background: 'transparent',
  border: 0,
  width: 1,
  height: 1,
  minWidth: 0,
  minHeight: 0,
} as const;

interface NodeTypeMeta {
  label: string;
  icon: LucideIcon;
}

const NODE_TYPE_META: Record<string, NodeTypeMeta> = {
  trigger: { label: 'Trigger', icon: Zap },
  condition: { label: 'Condition', icon: GitBranch },
  switch: { label: 'Switch', icon: Split },
  action: { label: 'Action', icon: Send },
  filter: { label: 'Filter', icon: Filter },
  wait: { label: 'Wait', icon: Clock },
  merge: { label: 'Merge', icon: GitMerge },
  schedule: { label: 'Schedule', icon: CalendarClock },
  transform: { label: 'Transform', icon: Wand2 },
};

// Order shown in the "+" picker. Trigger is excluded — flows have a single trigger.
const ADDABLE_NODE_TYPES: string[] = [
  'condition',
  'switch',
  'action',
  'filter',
  'wait',
  'merge',
  'transform',
];

function metaFor(type: string): NodeTypeMeta {
  return NODE_TYPE_META[type] ?? { label: type, icon: Workflow };
}

interface TriggerEventOption {
  type: string;
  label: string;
  description: string;
  Icon: LucideIcon;
}

const TRIGGER_EVENT_OPTIONS: TriggerEventOption[] = [
  {
    type: 'vulnerability_discovered',
    label: 'Vulnerability discovered',
    description: 'Fires when a new vulnerability is discovered in any project in this organization.',
    Icon: Box,
  },
  {
    type: 'malicious_package_detected',
    label: 'Malicious package detected',
    description: 'Fires when a dependency is flagged as malicious by GuardDog or another scanner.',
    Icon: Bug,
  },
];

/** Trigger nodes mirror the chosen event in their icon + label. Falls back to
 *  the generic Trigger meta when no event is set on the node config. */
function triggerEventOptionFor(eventType: string | undefined | null): TriggerEventOption | null {
  if (!eventType) return null;
  return TRIGGER_EVENT_OPTIONS.find((o) => o.type === eventType) ?? null;
}

function metaForFlowNode(node: FlowNode): NodeTypeMeta {
  if (node.type === 'trigger') {
    const eventType = (node.config as { event_type?: string }).event_type;
    const opt = triggerEventOptionFor(eventType);
    if (opt) return { label: opt.label, icon: opt.Icon };
  }
  return metaFor(node.type);
}

interface FlowCanvasNodeData {
  label: string;
  Icon: LucideIcon;
  isTrigger: boolean;
  onAddNode: (sourceId: string, kind: string) => void;
  nodeId: string;
}

const FlowCanvasNode = memo(({ data }: NodeProps) => {
  const d = data as unknown as FlowCanvasNodeData;
  const Icon = d.Icon;

  return (
    <div className="relative rounded-xl" style={{ width: NODE_WIDTH, height: NODE_HEIGHT }}>
      <Handle id="top" type="target" position={Position.Top} style={HANDLE_STYLE} />
      <Handle
        id="left"
        type="target"
        position={Position.Left}
        style={{ ...HANDLE_STYLE, top: EDGE_HANDLE_Y_FROM_TOP }}
      />
      <Handle id="source-bottom" type="source" position={Position.Bottom} style={HANDLE_STYLE} />
      <Handle
        id="source-right"
        type="source"
        position={Position.Right}
        style={{ ...HANDLE_STYLE, top: EDGE_HANDLE_Y_FROM_TOP }}
      />

      <div className="relative h-full w-full cursor-grab rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5 transition-colors hover:border-border/80 active:cursor-grabbing flex items-center justify-center">
        <Icon className="h-7 w-7 text-white" strokeWidth={1.5} />
      </div>

      <div
        className="pointer-events-none absolute left-1/2 top-full mt-2 -translate-x-1/2 select-none text-center"
        style={{ width: 160 }}
      >
        <p className="truncate text-[12px] font-medium leading-tight text-foreground">{d.label}</p>
      </div>

      <AddNodeAffordance nodeId={d.nodeId} onAddNode={d.onAddNode} />
    </div>
  );
});

const STUB_LENGTH = 15;
const ADD_BUTTON_SIZE = 22;

// Stub for the "+" affordance leaves the right side above center; real outgoing
// edges leave from a handle positioned the same distance below center, so the
// two are symmetric and never overlap.
const HANDLE_OFFSET_FROM_CENTER = 0;
const ADD_STUB_Y_FROM_TOP = NODE_HEIGHT / 2 - HANDLE_OFFSET_FROM_CENTER; // 18
const EDGE_HANDLE_Y_FROM_TOP = NODE_HEIGHT / 2 + HANDLE_OFFSET_FROM_CENTER; // 42

function AddNodeAffordance({
  nodeId,
  onAddNode,
}: {
  nodeId: string;
  onAddNode: (sourceId: string, kind: string) => void;
}) {
  return (
    <div
      className="flow-add-affordance nodrag nopan absolute flex flex-row items-center"
      style={{ left: NODE_WIDTH, top: ADD_STUB_Y_FROM_TOP, transform: 'translateY(-50%)' }}
      onClick={(e) => e.stopPropagation()}
      onMouseDown={(e) => e.stopPropagation()}
    >
      <svg width={STUB_LENGTH} height="2" className="block flow-add-stub" aria-hidden>
        <line
          x1="0"
          y1="1"
          x2={STUB_LENGTH}
          y2="1"
          stroke={EDGE_STROKE}
          strokeWidth="1"
          strokeDasharray="5 5"
        />
      </svg>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            onMouseDown={(e) => e.stopPropagation()}
            onClick={(e) => e.stopPropagation()}
            className="flex items-center justify-center rounded-full border border-border bg-background-card-header text-foreground-secondary shadow-sm transition-colors hover:border-foreground/40 hover:text-foreground data-[state=open]:border-foreground data-[state=open]:bg-background-card data-[state=open]:text-foreground"
            style={{ width: ADD_BUTTON_SIZE, height: ADD_BUTTON_SIZE }}
            aria-label="Add node"
          >
            <Plus className="h-3.5 w-3.5" strokeWidth={2} />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="start"
          side="right"
          sideOffset={6}
          className="min-w-[160px]"
          onCloseAutoFocus={(e) => e.preventDefault()}
        >
          {ADDABLE_NODE_TYPES.map((kind) => {
            const meta = metaFor(kind);
            const Icon = meta.icon;
            return (
              <DropdownMenuItem
                key={kind}
                className="cursor-pointer gap-2"
                onSelect={() => onAddNode(nodeId, kind)}
              >
                <Icon className="h-3.5 w-3.5 text-foreground-secondary" strokeWidth={1.75} />
                <span className="text-sm">{meta.label}</span>
              </DropdownMenuItem>
            );
          })}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

const nodeTypes = { flowNode: FlowCanvasNode };

interface NodeDataDeps {
  onAddNode: (sourceId: string, kind: string) => void;
}

function buildRFNodes(flow: Flow, deps: NodeDataDeps): RFNode[] {
  return flow.graph.nodes.map((n) => {
    const meta = metaForFlowNode(n);
    return {
      id: n.id,
      type: 'flowNode',
      position: n.position,
      data: {
        label: meta.label,
        Icon: meta.icon,
        isTrigger: n.type === 'trigger',
        onAddNode: deps.onAddNode,
        nodeId: n.id,
      } satisfies FlowCanvasNodeData,
    } satisfies RFNode;
  });
}

function buildRFEdges(flow: Flow): RFEdge[] {
  return flow.graph.edges.map((e) => ({
    id: e.id,
    source: e.source,
    sourceHandle: e.sourceHandle,
    target: e.target,
    targetHandle: e.targetHandle,
    type: 'smoothstep',
    style: { stroke: EDGE_STROKE, strokeWidth: 1, strokeDasharray: '5 5' },
    pathOptions: { borderRadius: 20 },
  }));
}

function generateNodeId(kind: string): string {
  const rand =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().slice(0, 8)
      : Math.random().toString(36).slice(2, 10);
  return `${kind}-${rand}`;
}

const SIDEBAR_MAX_WIDTH = 720;

function sidebarWidthPx(paneWidth: number): number {
  return Math.min(SIDEBAR_MAX_WIDTH, paneWidth);
}

export default function FlowEditorPage() {
  const { id: orgId, flowId } = useParams<{ id: string; flowId: string }>();

  const [flow, setFlow] = useState<Flow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const paneRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  // The currently-selected node (drives which sidebar is rendered + viewport
  // centering). Cleared when the node disappears (e.g. flow reset).
  const selectedNode = useMemo<FlowNode | null>(() => {
    if (!flow || !selectedNodeId) return null;
    return flow.graph.nodes.find((n) => n.id === selectedNodeId) ?? null;
  }, [flow, selectedNodeId]);
  useEffect(() => {
    if (selectedNodeId && !selectedNode) setSelectedNodeId(null);
  }, [selectedNodeId, selectedNode]);

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNodeId((prev) => (prev === nodeId ? null : nodeId));
  }, []);
  const closeSidebar = useCallback(() => setSelectedNodeId(null), []);

  // Read the trigger node's currently-saved event type (if any). Driven from
  // `flow` so the sidebar radio mirrors the same source of truth as the node.
  const currentTriggerEventType = useMemo<string | null>(() => {
    const trigger = flow?.graph.nodes.find((n) => n.type === 'trigger');
    return (trigger?.config as { event_type?: string } | undefined)?.event_type ?? null;
  }, [flow]);

  // Pending event-type change awaiting the user's confirmation, when accepting
  // would also wipe downstream nodes/edges.
  const [pendingEventTypeChange, setPendingEventTypeChange] = useState<string | null>(null);

  const applyEventTypeChange = useCallback(
    async (eventType: string, resetDownstream: boolean) => {
      if (!flow) return;
      const trigger = flow.graph.nodes.find((n) => n.type === 'trigger');
      if (!trigger) return;

      const updatedTrigger: FlowNode = {
        ...trigger,
        config: { ...trigger.config, event_type: eventType },
      };
      const nextGraph: FlowGraph = resetDownstream
        ? { ...flow.graph, nodes: [updatedTrigger], edges: [] }
        : {
            ...flow.graph,
            nodes: flow.graph.nodes.map((n) => (n.id === trigger.id ? updatedTrigger : n)),
          };

      // Optimistic — same pattern as drag/add: update local state, then
      // persist. Don't read response back to avoid clobbering newer edits.
      const fallback = flow;
      setFlow({ ...flow, graph: nextGraph });
      try {
        await api.updateFlow(flow.id, { graph: nextGraph });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        toast({ title: 'Failed to save trigger event', description: msg, variant: 'destructive' });
        setFlow(fallback);
      }
    },
    [flow, toast],
  );

  const handleTriggerEventTypeChange = useCallback(
    (eventType: string) => {
      if (!flow) return;
      if (eventType === currentTriggerEventType) return;

      // If anything else exists in the graph, downstream config (filters,
      // conditions, switches) may reference fields from the previous event's
      // schema and become invalid. Confirm + wipe so we never silently leave
      // a broken flow.
      const hasDownstream =
        flow.graph.nodes.some((n) => n.type !== 'trigger') || flow.graph.edges.length > 0;

      if (hasDownstream) {
        setPendingEventTypeChange(eventType);
      } else {
        void applyEventTypeChange(eventType, false);
      }
    },
    [flow, currentTriggerEventType, applyEventTypeChange],
  );

  const confirmEventTypeChange = useCallback(() => {
    if (pendingEventTypeChange === null) return;
    const next = pendingEventTypeChange;
    setPendingEventTypeChange(null);
    void applyEventTypeChange(next, true);
  }, [pendingEventTypeChange, applyEventTypeChange]);

  const handleConditionConfigChange = useCallback(
    async (nodeId: string, config: ConditionConfig) => {
      if (!flow) return;
      const target = flow.graph.nodes.find((n) => n.id === nodeId);
      if (!target) return;

      const nextGraph: FlowGraph = {
        ...flow.graph,
        nodes: flow.graph.nodes.map((n) =>
          n.id === nodeId ? { ...n, config: config as Record<string, unknown> } : n,
        ),
      };

      const fallback = flow;
      setFlow({ ...flow, graph: nextGraph });
      try {
        await api.updateFlow(flow.id, { graph: nextGraph });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        toast({ title: 'Failed to save condition', description: msg, variant: 'destructive' });
        setFlow(fallback);
      }
    },
    [flow, toast],
  );

  useEffect(() => {
    if (!flowId) return;
    let cancelled = false;
    api
      .getFlow(flowId)
      .then((f) => { if (!cancelled) setFlow(f); })
      .catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : String(err);
        const lower = msg.toLowerCase();
        if (lower.includes('404') || lower.includes('not found')) setError('Flow not found.');
        else if (lower.includes('403') || lower.includes('forbidden')) setError("You don't have access to this flow.");
        else setError(msg || 'Failed to load flow.');
      });
    return () => { cancelled = true; };
  }, [flowId]);

  // Esc closes whichever sidebar is open
  useEffect(() => {
    if (!selectedNodeId) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelectedNodeId(null);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [selectedNodeId]);

  const flowsHref = orgId ? `/organizations/${orgId}/flows` : '/organizations';

  return (
    <main
      ref={paneRef}
      className="relative h-[calc(100vh-3rem)] w-full overflow-hidden bg-background text-foreground"
    >
      {error ? (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="flex flex-col items-center gap-2">
            <p className="text-sm font-medium text-foreground">{error}</p>
            <Link to={flowsHref} className="text-xs text-primary hover:underline">
              ← Back to Flows
            </Link>
          </div>
        </div>
      ) : flow ? (
        <ReactFlowProvider>
          <FlowCanvas
            flow={flow}
            onFlowUpdated={setFlow}
            onNodeClick={handleNodeClick}
            selectedNodeId={selectedNodeId}
            paneRef={paneRef}
          />
        </ReactFlowProvider>
      ) : null}

      {flow && (
        <div className="pointer-events-none absolute left-4 top-4 z-20">
          <span className="pointer-events-auto rounded-md border border-border/50 bg-background/80 px-2 py-1 text-sm font-medium text-foreground backdrop-blur-sm">
            {flow.name}
          </span>
        </div>
      )}

      <TriggerSidebar
        open={selectedNode?.type === 'trigger'}
        onClose={closeSidebar}
        currentEventType={currentTriggerEventType}
        onEventTypeChange={handleTriggerEventTypeChange}
      />
      <ConditionSidebar
        open={selectedNode?.type === 'condition'}
        onClose={closeSidebar}
        node={selectedNode?.type === 'condition' ? selectedNode : null}
        flowId={flow?.id ?? ''}
        triggerEventType={currentTriggerEventType}
        onConfigChange={handleConditionConfigChange}
      />

      <Dialog
        open={pendingEventTypeChange !== null}
        onOpenChange={(open) => { if (!open) setPendingEventTypeChange(null); }}
      >
        <DialogContent>
          <DialogTitle>Change trigger event?</DialogTitle>
          <DialogDescription>
            Changing the trigger will reset the rest of this flow. All other nodes and edges will be removed.
          </DialogDescription>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingEventTypeChange(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmEventTypeChange}>
              Reset flow
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}

function TriggerSidebar({
  open,
  onClose,
  currentEventType,
  onEventTypeChange,
}: {
  open: boolean;
  onClose: () => void;
  currentEventType: string | null;
  onEventTypeChange: (eventType: string) => void;
}) {

  return (
    <aside
      className={cn(
        'absolute right-0 top-6 bottom-0 z-30 flex w-full flex-col overflow-hidden rounded-tl-xl border-l border-t border-border bg-background-card-header shadow-2xl transition-transform duration-300 ease-out',
        open ? 'translate-x-0' : 'translate-x-full',
      )}
      style={{ maxWidth: SIDEBAR_MAX_WIDTH }}
      aria-hidden={!open}
    >
      <header className="flex items-center justify-between border-b border-border px-5 py-4">
        <h2 className="text-base font-semibold text-foreground">Configure trigger</h2>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1.5 text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="flex-1 overflow-y-auto">
        <section className="px-5 py-5">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
            Event
          </p>
          <div className="flex flex-col gap-2" role="radiogroup" aria-label="Trigger event">
            {TRIGGER_EVENT_OPTIONS.map((option) => {
              const isSelected = option.type === currentEventType;
              const Icon = option.Icon;
              return (
                <button
                  key={option.type}
                  type="button"
                  role="radio"
                  aria-checked={isSelected}
                  onClick={() => onEventTypeChange(option.type)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg border bg-background-card px-4 py-3 text-left transition-all',
                    isSelected
                      ? 'border-foreground/50 ring-1 ring-foreground/20'
                      : 'border-border hover:border-foreground-secondary/30',
                  )}
                >
                  <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border border-border bg-background-card-header">
                    <Icon className="h-4 w-4 text-foreground" strokeWidth={1.5} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-foreground">{option.label}</p>
                    <p className="mt-1 text-[13px] leading-snug text-foreground-secondary">
                      {option.description}
                    </p>
                  </div>
                  <div
                    className={cn(
                      'flex h-4 w-4 flex-shrink-0 items-center justify-center rounded-full border-2 transition-colors',
                      isSelected
                        ? 'border-foreground bg-foreground text-background'
                        : 'border-foreground-secondary/50 bg-transparent',
                    )}
                    aria-hidden
                  >
                    {isSelected && <Check className="h-2.5 w-2.5" strokeWidth={3} />}
                  </div>
                </button>
              );
            })}
          </div>
        </section>
      </div>
    </aside>
  );
}

// ─── Condition sidebar ──────────────────────────────────────────────────────

interface ConditionRow {
  field?: string;
  operator?: string;
  value?: string | number | boolean | null;
}

/** A condition node's saved configuration. In `visual` mode the runtime
 *  evaluates the rows joined by `combinator` against the trigger event
 *  payload. In `code` mode it runs `code` as a sandboxed function instead. */
interface ConditionConfig {
  mode?: 'visual' | 'code';
  combinator?: 'and' | 'or';
  conditions?: ConditionRow[];
  code?: string;
}

const EMPTY_ROW: ConditionRow = {};

// Body-only default. Old flows that stored the full `function evaluate() {...}`
// form get parse-tolerantly normalized on load via `toBody(...)`.
const DEFAULT_CONDITION_BODY = `  // Return true to continue down this branch, false to stop.
  return true;`;

interface OperatorOption {
  value: string;
  label: string;
  /** When true, this operator doesn't take a comparison value (e.g. `is_true`). */
  noValue?: boolean;
}

const OPERATORS_BY_TYPE: Record<EventFieldType, OperatorOption[]> = {
  string: [
    { value: 'equals', label: 'equals' },
    { value: 'not_equals', label: 'does not equal' },
    { value: 'contains', label: 'contains' },
    { value: 'not_contains', label: 'does not contain' },
  ],
  number: [
    { value: 'equals', label: '=' },
    { value: 'not_equals', label: '!=' },
    { value: 'greater_than', label: '>' },
    { value: 'less_than', label: '<' },
    { value: 'greater_or_equal', label: '>=' },
    { value: 'less_or_equal', label: '<=' },
  ],
  boolean: [
    { value: 'is_true', label: 'is true', noValue: true },
    { value: 'is_false', label: 'is false', noValue: true },
  ],
  enum: [
    { value: 'equals', label: 'is' },
    { value: 'not_equals', label: 'is not' },
  ],
};

function defaultValueForType(type: EventFieldType, field?: EventField): string | number | boolean | null {
  if (type === 'boolean') return null;
  if (type === 'number') return 0;
  if (type === 'enum' && field?.enumValues && field.enumValues.length > 0) return field.enumValues[0];
  return '';
}

function ConditionSidebar({
  open,
  onClose,
  node,
  flowId,
  triggerEventType,
  onConfigChange,
}: {
  open: boolean;
  onClose: () => void;
  node: FlowNode | null;
  flowId: string;
  triggerEventType: string | null;
  onConfigChange: (nodeId: string, config: ConditionConfig) => void;
}) {
  const schema = triggerEventType ? EVENT_SCHEMAS[triggerEventType] : undefined;
  const fields = schema?.fields ?? [];
  const fieldsByGroup = useMemo(() => {
    const order: string[] = [];
    const map = new Map<string, EventField[]>();
    for (const f of fields) {
      if (!map.has(f.group)) {
        map.set(f.group, []);
        order.push(f.group);
      }
      map.get(f.group)!.push(f);
    }
    return order.map((group) => ({ group, fields: map.get(group)! }));
  }, [fields]);

  const config = (node?.config ?? {}) as ConditionConfig;
  const mode: 'visual' | 'code' = config.mode ?? 'visual';
  const conditions: ConditionRow[] =
    config.conditions && config.conditions.length > 0 ? config.conditions : [EMPTY_ROW];
  const combinator: 'and' | 'or' = config.combinator ?? 'and';
  // Stored value can be body-only (new) or a full function declaration (legacy).
  // toBody() returns the body either way; the editor is body-only going forward.
  const codeBody = config.code ? toBody(config.code, 'evaluate') : DEFAULT_CONDITION_BODY;

  const emit = (next: ConditionConfig) => {
    if (!node) return;
    onConfigChange(node.id, { ...config, ...next });
  };

  // Track a pending mode switch waiting on user confirmation.
  // - Code → Visual always confirms (code gets discarded).
  // - Visual → Code with non-empty saved code prompts "Replace?".
  // - Visual → Code with no saved code seeds defaultBody silently.
  const [pendingMode, setPendingMode] = useState<'visual' | 'code' | null>(null);

  const setMode = (next: 'visual' | 'code') => {
    if (next === mode) return;
    if (next === 'visual') {
      // Switching away from code — always confirm before discarding.
      setPendingMode('visual');
      return;
    }
    // next === 'code'
    if (config.code && config.code.trim().length > 0) {
      // User has saved code from a previous session — confirm before overwriting.
      setPendingMode('code');
      return;
    }
    // Fresh visual → code: seed with default body silently.
    emit({ mode: 'code', code: wrapBody(DEFAULT_CONDITION_BODY, 'evaluate', 'context') });
  };

  const confirmModeSwitch = () => {
    if (!pendingMode) return;
    if (pendingMode === 'visual') {
      // Discard code; visual takes over.
      emit({ mode: 'visual', code: undefined });
    } else {
      // Code mode — replace existing body with default seed.
      emit({ mode: 'code', code: wrapBody(DEFAULT_CONDITION_BODY, 'evaluate', 'context') });
    }
    setPendingMode(null);
  };

  const cancelModeSwitch = () => setPendingMode(null);

  const updateRow = (index: number, row: ConditionRow) => {
    const nextConditions = conditions.map((c, i) => (i === index ? row : c));
    emit({ combinator, conditions: nextConditions });
  };

  const addRow = () => {
    emit({ combinator, conditions: [...conditions, { ...EMPTY_ROW }] });
  };

  const removeRow = (index: number) => {
    if (conditions.length <= 1) return;
    emit({ combinator, conditions: conditions.filter((_, i) => i !== index) });
  };

  const setCombinator = (next: 'and' | 'or') => {
    emit({ combinator: next, conditions });
  };

  const setCodeBody = (nextBody: string) => {
    // Persist as a full function declaration so the runtime engine (and any
    // legacy reader) sees the same shape it always has.
    emit({ code: wrapBody(nextBody, 'evaluate', 'context') });
  };

  return (
    <aside
      className={cn(
        'absolute right-0 top-6 bottom-0 z-30 flex w-full flex-col overflow-hidden rounded-tl-xl border-l border-t border-border bg-background-card-header shadow-2xl transition-transform duration-300 ease-out',
        open ? 'translate-x-0' : 'translate-x-full',
      )}
      style={{ maxWidth: SIDEBAR_MAX_WIDTH }}
      aria-hidden={!open}
    >
      <header className="flex items-center justify-between border-b border-border px-5 py-4">
        <h2 className="text-base font-semibold text-foreground">Configure condition</h2>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1.5 text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="flex-1 overflow-y-auto">
        <section className="px-5 py-5">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
              {mode === 'code' ? 'Code' : 'When'}
            </p>
            <Tabs value={mode} onValueChange={(v) => setMode(v as 'visual' | 'code')}>
              <TabsList className="h-auto gap-1 bg-transparent p-0">
                <TabsTrigger
                  value="visual"
                  className="h-7 rounded-md border border-transparent px-2.5 text-xs text-foreground-secondary hover:text-foreground data-[state=active]:border-border data-[state=active]:bg-background-card data-[state=active]:text-foreground data-[state=active]:shadow-none"
                >
                  Visual
                </TabsTrigger>
                <TabsTrigger
                  value="code"
                  className="h-7 rounded-md border border-transparent px-2.5 text-xs text-foreground-secondary hover:text-foreground data-[state=active]:border-border data-[state=active]:bg-background-card data-[state=active]:text-foreground data-[state=active]:shadow-none"
                >
                  Code
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </div>

          {mode === 'code' ? (
            !triggerEventType ? (
              <p className="py-4 text-center text-sm text-foreground-secondary">
                Configure the trigger first — the condition needs to know which event fields are available.
              </p>
            ) : (
              <FlowCodeEditor
                flowId={flowId}
                nodeType="condition"
                eventType={triggerEventType}
                value={codeBody}
                onChange={setCodeBody}
              />
            )
          ) : !triggerEventType ? (
            <p className="py-4 text-center text-sm text-foreground-secondary">
              Configure the trigger first — the condition needs to know which event fields are available.
            </p>
          ) : (
            <div className="rounded-lg border border-border bg-background-card p-3">
              <div className="flex flex-col gap-2">
                {conditions.map((row, idx) => (
                  <Fragment key={idx}>
                    {idx > 0 && (
                      <div className="flex items-center gap-2 px-1 py-1">
                        <div className="h-px flex-1 bg-border" />
                        <Tabs value={combinator} onValueChange={(v) => setCombinator(v as 'and' | 'or')}>
                          <TabsList className="h-auto gap-1 bg-transparent p-0">
                            <TabsTrigger
                              value="and"
                              className="h-7 rounded-md border border-transparent px-2.5 text-[11px] font-semibold uppercase tracking-wider text-foreground-secondary hover:text-foreground data-[state=active]:border-border data-[state=active]:bg-background-card data-[state=active]:text-foreground data-[state=active]:shadow-none"
                            >
                              And
                            </TabsTrigger>
                            <TabsTrigger
                              value="or"
                              className="h-7 rounded-md border border-transparent px-2.5 text-[11px] font-semibold uppercase tracking-wider text-foreground-secondary hover:text-foreground data-[state=active]:border-border data-[state=active]:bg-background-card data-[state=active]:text-foreground data-[state=active]:shadow-none"
                            >
                              Or
                            </TabsTrigger>
                          </TabsList>
                        </Tabs>
                        <div className="h-px flex-1 bg-border" />
                      </div>
                    )}
                    <ConditionRowEditor
                      row={row}
                      fields={fields}
                      fieldsByGroup={fieldsByGroup}
                      removable={conditions.length > 1}
                      onChange={(next) => updateRow(idx, next)}
                      onRemove={() => removeRow(idx)}
                    />
                  </Fragment>
                ))}
              </div>

              <button
                type="button"
                onClick={addRow}
                className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-border bg-background-card px-2.5 py-1.5 text-xs font-medium text-foreground-secondary transition-colors hover:border-foreground-secondary/40 hover:text-foreground"
              >
                <Plus className="h-3.5 w-3.5" strokeWidth={2} />
                Add condition
              </button>
            </div>
          )}
        </section>
      </div>

      <Dialog open={pendingMode !== null} onOpenChange={(open) => { if (!open) cancelModeSwitch(); }}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogTitle>
            {pendingMode === 'visual' ? 'Switch to Visual?' : 'Replace existing code?'}
          </DialogTitle>
          <DialogDescription>
            {pendingMode === 'visual'
              ? 'Switching to Visual will discard the code currently saved on this condition. This cannot be undone.'
              : 'Code is already saved on this condition. Switching to Code mode will replace it with the default template.'}
          </DialogDescription>
          <DialogFooter>
            <Button variant="outline" onClick={cancelModeSwitch}>Cancel</Button>
            <Button onClick={confirmModeSwitch}>
              {pendingMode === 'visual' ? 'Discard code' : 'Replace'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </aside>
  );
}

function ConditionRowEditor({
  row,
  fields,
  fieldsByGroup,
  removable,
  onChange,
  onRemove,
}: {
  row: ConditionRow;
  fields: EventField[];
  fieldsByGroup: { group: string; fields: EventField[] }[];
  removable: boolean;
  onChange: (next: ConditionRow) => void;
  onRemove: () => void;
}) {
  const selectedField = fields.find((f) => f.path === row.field) ?? null;
  const fieldType: EventFieldType | null = selectedField?.type ?? null;
  const operators = fieldType ? OPERATORS_BY_TYPE[fieldType] : [];
  const selectedOperator = operators.find((op) => op.value === row.operator) ?? null;

  const handleFieldChange = (newPath: string) => {
    const newField = fields.find((f) => f.path === newPath);
    if (!newField) return;
    const newOps = OPERATORS_BY_TYPE[newField.type];
    onChange({
      field: newPath,
      operator: newOps[0]?.value,
      value: newOps[0]?.noValue ? null : defaultValueForType(newField.type, newField),
    });
  };

  const handleOperatorChange = (newOp: string) => {
    const op = operators.find((o) => o.value === newOp);
    if (!op) return;
    onChange({
      ...row,
      operator: newOp,
      value: op.noValue
        ? null
        : selectedOperator?.noValue
          ? defaultValueForType(fieldType ?? 'string', selectedField ?? undefined)
          : row.value,
    });
  };

  const handleValueChange = (newValue: string | number | boolean) => {
    onChange({ ...row, value: newValue });
  };

  return (
    <div>
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <Select value={row.field ?? ''} onValueChange={handleFieldChange}>
            <SelectTrigger>
              <SelectValue placeholder="Field…" />
            </SelectTrigger>
            <SelectContent>
              {fieldsByGroup.map(({ group, fields: groupFields }, idx) => (
                <SelectGroup key={group}>
                  <SelectLabel
                    className={cn(
                      'px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-foreground-secondary',
                      idx === 0 ? 'pt-2' : 'pt-3',
                    )}
                  >
                    {group}
                  </SelectLabel>
                  {groupFields.map((f) => (
                    <SelectItem key={f.path} value={f.path}>
                      {f.label}
                    </SelectItem>
                  ))}
                </SelectGroup>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="w-[140px] flex-shrink-0">
          <Select
            value={row.operator ?? ''}
            onValueChange={handleOperatorChange}
            disabled={!selectedField}
          >
            <SelectTrigger>
              <SelectValue placeholder="Operator…" />
            </SelectTrigger>
            <SelectContent>
              {operators.map((op) => (
                <SelectItem key={op.value} value={op.value}>
                  {op.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="min-w-0 flex-1">
          <ConditionValueInput
            field={selectedField}
            value={row.value}
            onChange={handleValueChange}
            disabled={!selectedField || !selectedOperator || !!selectedOperator?.noValue}
          />
        </div>

        <button
          type="button"
          onClick={onRemove}
          disabled={!removable}
          className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-md text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground disabled:cursor-not-allowed disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-foreground-secondary"
          aria-label="Remove condition"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
      {selectedField?.hint && (
        <p className="mt-1.5 text-[12px] text-foreground-secondary">{selectedField.hint}</p>
      )}
    </div>
  );
}

function ConditionValueInput({
  field,
  value,
  onChange,
  disabled,
}: {
  field: EventField | null;
  value: string | number | boolean | null | undefined;
  onChange: (next: string | number | boolean) => void;
  disabled?: boolean;
}) {
  if (!field || field.type === 'boolean') {
    return (
      <input
        type="text"
        value=""
        readOnly
        disabled
        placeholder="Value…"
        className="flex h-9 w-full rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary shadow-sm disabled:cursor-not-allowed disabled:opacity-50"
      />
    );
  }
  if (field.type === 'enum' && field.enumValues) {
    return (
      <Select
        value={(value as string | undefined) ?? ''}
        onValueChange={(v) => onChange(v)}
        disabled={disabled}
      >
        <SelectTrigger>
          <SelectValue placeholder="Value…" />
        </SelectTrigger>
        <SelectContent>
          {field.enumValues.map((v) => (
            <SelectItem key={v} value={v}>
              {v}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  }
  if (field.type === 'number') {
    return (
      <input
        type="number"
        disabled={disabled}
        value={value === '' || value == null ? '' : Number(value)}
        onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))}
        placeholder="Value…"
        className="flex h-9 w-full rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary shadow-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50"
      />
    );
  }
  // string fallback
  return (
    <input
      type="text"
      disabled={disabled}
      value={(value as string | undefined) ?? ''}
      onChange={(e) => onChange(e.target.value)}
      placeholder="Value…"
      className="flex h-9 w-full rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary shadow-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50"
    />
  );
}

/** Node types that have a configuration sidebar. Clicks on others are no-ops. */
const NODE_TYPES_WITH_SIDEBAR = new Set(['trigger', 'condition']);

function FlowCanvas({
  flow,
  onFlowUpdated,
  onNodeClick,
  selectedNodeId,
  paneRef,
}: {
  flow: Flow;
  onFlowUpdated: (f: Flow) => void;
  onNodeClick: (nodeId: string) => void;
  selectedNodeId: string | null;
  paneRef: React.RefObject<HTMLDivElement>;
}) {
  const { toast } = useToast();
  const rfInstance = useReactFlow();

  // Latest flow ref so callbacks always serialize against current state
  const flowRef = useRef(flow);
  flowRef.current = flow;

  // Stable add-node callback (latest impl held in ref so node.data identity stays stable)
  const addNodeImplRef = useRef<(sourceId: string, kind: string) => void>(() => {});
  const handleAddNode = useCallback((sourceId: string, kind: string) => {
    addNodeImplRef.current(sourceId, kind);
  }, []);

  const [nodes, setNodes, onNodesChange] = useNodesState<RFNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<RFEdge>([]);

  // Sync RF state from flow whenever flow changes (initial load, add, drag-stop save).
  // Drag-time position changes still flow through onNodesChange — those don't update
  // `flow` until drag stop, so this effect doesn't fire mid-drag.
  useEffect(() => {
    setNodes(buildRFNodes(flow, { onAddNode: handleAddNode }));
    setEdges(buildRFEdges(flow));
  }, [flow, handleAddNode, setNodes, setEdges]);

  const onMoveStart = useCallback(() => setCanvasDragging(true), []);
  const onMoveEnd = useCallback(() => setCanvasDragging(false), []);

  const handleNodeClick = useCallback(
    (_e: unknown, node: RFNode) => {
      const fnode = flowRef.current.graph.nodes.find((n) => n.id === node.id);
      if (fnode && NODE_TYPES_WITH_SIDEBAR.has(fnode.type)) onNodeClick(node.id);
    },
    [onNodeClick],
  );

  // Pan the selected node into the visible area when a sidebar opens (mirrors
  // the org overview's "click → center node next to sidebar" behavior). On
  // close, recenter to the full pane around the previously-selected node so
  // the user doesn't lose visual context.
  const lastFocusedNodeIdRef = useRef<string | null>(null);
  useEffect(() => {
    const focusId = selectedNodeId ?? lastFocusedNodeIdRef.current;
    if (selectedNodeId) lastFocusedNodeIdRef.current = selectedNodeId;
    const node = focusId ? flowRef.current.graph.nodes.find((n) => n.id === focusId) : null;
    const pane = paneRef.current;
    if (!node || !pane) return;

    const rect = pane.getBoundingClientRect();
    const paneWidth = rect.width;
    const paneHeight = rect.height;
    const sidebarW = selectedNodeId ? sidebarWidthPx(paneWidth) : 0;
    const visibleWidth = paneWidth - sidebarW;

    const nodeCenterX = node.position.x + NODE_WIDTH / 2;
    const nodeCenterY = node.position.y + NODE_HEIGHT / 2;

    const { zoom } = rfInstance.getViewport();
    const targetScreenX = visibleWidth / 2;
    const targetScreenY = paneHeight / 2;
    const x = targetScreenX - nodeCenterX * zoom;
    const y = targetScreenY - nodeCenterY * zoom;

    // Slight delay on open so the sidebar starts sliding before the pan kicks
    // in — they finish together in ~300ms.
    const delay = selectedNodeId ? 50 : 0;
    const timer = setTimeout(() => {
      rfInstance.setViewport({ x, y, zoom }, { duration: 300 });
    }, delay);
    return () => clearTimeout(timer);
  }, [selectedNodeId, rfInstance, paneRef]);

  const persistGraph = useCallback(
    async (nextGraph: FlowGraph, fallback: Flow, errorTitle: string) => {
      onFlowUpdated({ ...fallback, graph: nextGraph });
      try {
        await api.updateFlow(fallback.id, { graph: nextGraph });
        // Intentionally do NOT read the response back into local state. The
        // optimistic update above is already correct (server stores exactly
        // what we sent), and overwriting now would clobber any newer drag
        // that's started since this request was fired — causing the moved
        // node to flash back to its previous position.
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        toast({ title: errorTitle, description: msg, variant: 'destructive' });
        onFlowUpdated(fallback);
      }
    },
    [onFlowUpdated, toast],
  );

  // Pause the ReactiveDotGrid's per-frame work while a node is being dragged
  // (same trick the org overview uses — without it, the dot grid keeps eating
  // frames and the drag goes laggy after a beat).
  const handleNodeDragStart = useCallback(() => {
    setCanvasDragging(true);
  }, []);

  const handleNodeDragStop = useCallback(
    (_e: unknown, node: RFNode) => {
      setCanvasDragging(false);
      const current = flowRef.current;
      const existing = current.graph.nodes.find((n) => n.id === node.id);
      if (!existing) return;
      if (existing.position.x === node.position.x && existing.position.y === node.position.y) return;

      const nextGraph: FlowGraph = {
        ...current.graph,
        nodes: current.graph.nodes.map((n) =>
          n.id === node.id ? { ...n, position: { x: node.position.x, y: node.position.y } } : n,
        ),
      };
      void persistGraph(nextGraph, current, 'Failed to save position');
    },
    [persistGraph],
  );

  // Wired into the AddNodeAffordance via the ref pattern above
  addNodeImplRef.current = (sourceId: string, kind: string) => {
    const current = flowRef.current;
    const sourceNode = current.graph.nodes.find((n) => n.id === sourceId);
    if (!sourceNode) return;

    const newNodeId = generateNodeId(kind);
    const newEdgeId = `e-${sourceId}-${newNodeId}`;

    // If the source already has children, stack the new one below the lowest child
    // so multi-branch fan-outs don't pile on top of each other. Drag to refine.
    const childIds = new Set(
      current.graph.edges.filter((e) => e.source === sourceId).map((e) => e.target),
    );
    const childNodes = current.graph.nodes.filter((n) => childIds.has(n.id));
    const targetX = sourceNode.position.x + NODE_HORIZONTAL_GAP;
    const targetY =
      childNodes.length === 0
        ? sourceNode.position.y
        : Math.max(...childNodes.map((n) => n.position.y)) + NODE_VERTICAL_BRANCH_GAP;

    const newNode: FlowNode = {
      id: newNodeId,
      type: kind,
      position: { x: targetX, y: targetY },
      config: {},
    };

    const nextGraph: FlowGraph = {
      ...current.graph,
      nodes: [...current.graph.nodes, newNode],
      edges: [
        ...current.graph.edges,
        {
          id: newEdgeId,
          source: sourceId,
          sourceHandle: 'source-right',
          target: newNodeId,
          targetHandle: 'left',
        },
      ],
    };

    void persistGraph(nextGraph, current, 'Failed to add node');
  };

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeDragStart={handleNodeDragStart}
      onNodeDragStop={handleNodeDragStop}
      onNodeClick={handleNodeClick}
      onMoveStart={onMoveStart}
      onMoveEnd={onMoveEnd}
      className="flow-builder-canvas"
      fitView
      fitViewOptions={{ padding: 0.5, maxZoom: 1.15 }}
      nodesDraggable
      nodesConnectable={false}
      edgesFocusable={false}
      panOnDrag
      zoomOnScroll
      zoomOnPinch
      proOptions={{ hideAttribution: true }}
      minZoom={0.12}
      maxZoom={2}
    >
      <ReactiveDotGrid />
    </ReactFlow>
  );
}
