// Shared types for the unified flow builder.
// A flow is a graph (nodes + edges). The engine starts at the trigger node and walks
// the graph, executing each node and passing data forward. Same shape for all 4
// flow types — only the trigger and outcome node options differ.

export type FlowType = 'notification' | 'pr_check' | 'policy' | 'status';
export type FlowScope = 'organization' | 'team' | 'project';

// ---------- Graph shape (stored in flows.graph and flow_versions.graph) ----------

export interface FlowGraph {
  version: 1;
  nodes: FlowNode[];
  edges: FlowEdge[];
}

export interface FlowNode {
  id: string;
  type: string; // e.g. "trigger.event", "filter.condition", "destination.slack"
  position: { x: number; y: number };
  config: Record<string, unknown>;
}

export interface FlowEdge {
  id: string;
  source: string;
  sourceHandle: string; // "out" | "true" | "false" | named
  target: string;
  targetHandle: string; // typically "in"
}

// ---------- Persisted flow record ----------

export interface Flow {
  id: string;
  flow_type: FlowType;
  scope: FlowScope;
  scope_id: string;
  organization_id: string;
  name: string;
  description: string | null;
  graph: FlowGraph;
  version: number;
  active: boolean;
  dry_run: boolean;
  snoozed_until: string | null;
  created_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

// ---------- CRUD request shapes ----------

export interface CreateFlowRequest {
  flow_type: FlowType;
  scope: FlowScope;
  scope_id: string;
  name: string;
  description?: string;
  graph?: FlowGraph;
}

export interface UpdateFlowRequest {
  name?: string;
  description?: string;
  graph?: FlowGraph;
  change_summary?: string;
}

// ---------- Test run shapes ----------

export interface TestRunRequest {
  event_id?: string;
  mock_payload?: unknown;
}

export interface TestRunResponse {
  status: 'completed' | 'failed' | 'skipped';
  outcome: unknown;
  node_executions: Array<{
    node_id: string;
    node_type: string;
    status: 'success' | 'failed' | 'skipped';
    input: unknown;
    output: unknown;
    error: string | null;
    duration_ms: number;
  }>;
  total_duration_ms: number;
}

// ---------- Run history shape ----------

export interface FlowRun {
  id: string;
  flow_id: string;
  flow_name: string;
  flow_type: FlowType;
  flow_version: number;
  trigger_event_id: string | null;
  trigger_payload: unknown;
  status: 'running' | 'completed' | 'failed' | 'skipped' | 'dry_run';
  outcome: unknown;
  error: string | null;
  duration_ms: number | null;
  started_at: string;
  completed_at: string | null;
}

// ---------- Engine-internal types (used by node implementations) ----------

export interface NodeContext {
  flowId: string;
  flowRunId: string;
  organizationId: string;
  flowType: FlowType;
  scope: FlowScope;
  scopeId: string;
  // Mutable bag carried between nodes. Each node reads from `data` (the flowing payload)
  // and may write back. Trigger payload is initially placed here.
  data: Record<string, unknown>;
}

export interface NodeExecutionResult {
  output: Record<string, unknown>;
  // Which output handle to follow. Default "out". For branches: "true"/"false" or named.
  next?: string;
  // True = stop walking this path (e.g. filter rejected).
  halt?: boolean;
}

export type NodeCategory =
  | 'trigger'
  | 'filter'
  | 'logic'
  | 'transform'
  | 'destination'
  | 'outcome'
  | 'action'
  | 'code';

export interface ConfigField {
  key: string;
  label: string;
  type:
    | 'string'
    | 'text'
    | 'number'
    | 'boolean'
    | 'select'
    | 'multi-select'
    | 'integration'
    | 'channel'
    | 'event_type_select'
    | 'condition_builder'
    | 'code'
    | 'template'
    | 'json';
  required?: boolean;
  default?: unknown;
  options?: Array<{ value: string; label: string }>;
  // For type='integration': filter by provider (slack, discord, jira, ...)
  providerFilter?: string[];
  // For type='channel': depends on the value of another field (e.g. "integration_id")
  dependsOn?: string;
  description?: string;
  placeholder?: string;
}

export interface NodeDefinition {
  type: string;
  category: NodeCategory;
  label: string;
  validForFlowTypes: FlowType[];
  // Only one trigger node allowed per flow (validated at save time).
  isTrigger?: boolean;
  configSchema: ConfigField[];
  outputHandles: string[]; // ["out"] | ["true","false"] | custom
  // Validate config at save time. Return array of error messages (empty = valid).
  validate?: (config: Record<string, unknown>) => string[];
  execute: (
    config: Record<string, unknown>,
    context: NodeContext,
  ) => Promise<NodeExecutionResult>;
}
