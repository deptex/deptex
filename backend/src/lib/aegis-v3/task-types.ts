// Aegis Task primitive — "a task is a chat with one goal" (Henry's model).
// A task is an aegis_chat_threads row (context_type='task') plus one
// aegis_agent_tasks record; execution reuses the project_security_fixes
// pipeline linked by task_id. v1 goal type = fix findings -> draft PR.

export type AegisTaskStatus =
  | 'proposed'
  | 'working'
  | 'completed'
  | 'completed_with_failures'
  | 'failed'
  | 'declined'
  | 'cancelled'
  | 'needs_input'; // enum kept for Phase-2 forward-compat; nothing sets it in v1

export type AegisTaskSource = 'chat' | 'finding';

// The finding types the fix pipeline can act on (kept in sync with
// plan-types.ts FINDING_TYPES). vulnerability/semgrep/secret + the infra &
// dataflow types added in phase69: iac misconfigs, container OS-CVEs,
// base-image recommendations, reachable taint flows (dataflow), DAST findings.
export type AegisTaskFindingType =
  | 'vulnerability'
  | 'semgrep'
  | 'secret'
  | 'iac'
  | 'container'
  | 'base_image'
  | 'dataflow'
  | 'dast';

// A target stores STABLE identity only — the live PDV/finding row id is
// re-resolved from (project_id, finding_key) at accept time, because those row
// uuids churn on every rescan.
export interface AegisTaskTarget {
  findingType: AegisTaskFindingType;
  findingKey: string;
  osvId?: string;
  // Location handle `file:line` for semgrep / secret. Their finding_key is
  // per-RULE (shared across every occurrence), so the per-finding identity must
  // be the location — otherwise N distinct findings collapse to one fix.
  findingHandle?: string;
  projectId: string;
  label: string;
}

export interface AegisTask {
  id: string;
  organizationId: string;
  projectId: string | null;
  threadId: string | null;
  kind: 'fix';
  title: string;
  description: string | null;
  status: AegisTaskStatus;
  source: AegisTaskSource;
  targets: AegisTaskTarget[];
  totalFixes: number;
  completedFixes: number;
  failedFixes: number;
  summary: string | null;
  createdAt: string;
  updatedAt: string;
  acceptedAt: string | null;
  completedAt: string | null;
}

export const AEGIS_TASK_FINDING_TYPES: readonly AegisTaskFindingType[] = [
  'vulnerability',
  'semgrep',
  'secret',
  'iac',
  'container',
  'base_image',
  'dataflow',
  'dast',
] as const;

// Blast-radius cap: a single task fans out at most this many fixes (each opens
// a draft PR). Overridable via env for power orgs.
export const AEGIS_TASK_MAX_TARGETS = Number(process.env.AEGIS_TASK_MAX_TARGETS) || 10;
