import type { SupabaseClient } from '@supabase/supabase-js';
import type { FixPlan } from './plan-types';

export interface FixJobRow {
  id: string;
  project_id: string;
  organization_id: string;
  payload: Record<string, unknown>;
  plan: FixPlan;
  attempts: number;
}

interface FullFixRow {
  id: string;
  project_id: string;
  organization_id: string;
  fix_type: string;
  strategy: string;
  status: string;
  run_id: string;
  plan: FixPlan | null;
  plan_base_sha: string | null;
  plan_base_branch: string | null;
  payload: Record<string, unknown>;
  attempts: number;
  osv_id: string | null;
  semgrep_finding_id: string | null;
  secret_finding_id: string | null;
  iac_finding_id: string | null;
  container_finding_id: string | null;
  base_image_rec_id: string | null;
  dast_finding_id: string | null;
  reachable_flow_id: string | null;
  // Set when this fix was started by an Aegis task — the worker narrates its
  // real steps into the task's chat thread and carries the terminal status
  // onto the task. Null for a standalone fix.
  thread_id: string | null;
  task_id: string | null;
  // Wake-the-task-agent resume context. run_seq is the billing-meter dedup
  // boundary (0 = first run, +1 per user wake); started_at/approved_at feed the
  // end-of-run drain watermark; the pr_* columns are the prior run's PR so a
  // resume can amend it instead of opening a duplicate.
  run_seq: number;
  started_at: string | null;
  approved_at: string | null;
  pr_url: string | null;
  pr_number: number | null;
  pr_branch: string | null;
  pr_repo_full_name: string | null;
}

export async function claimJob(
  supabase: SupabaseClient,
  machineId: string,
): Promise<FixJobRow | null> {
  const { data, error } = await supabase.rpc('claim_fix_job', {
    p_machine_id: machineId,
  });
  if (error) {
    console.error('[FIX] Failed to claim job:', error.message);
    return null;
  }
  if (!data || (Array.isArray(data) && data.length === 0)) return null;
  const row = Array.isArray(data) ? data[0] : data;
  if (!row?.plan) return null;
  return row as FixJobRow;
}

export async function loadFullRow(
  supabase: SupabaseClient,
  fixId: string,
): Promise<FullFixRow | null> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select(
      'id, project_id, organization_id, fix_type, strategy, status, run_id, plan, plan_base_sha, plan_base_branch, payload, attempts, osv_id, semgrep_finding_id, secret_finding_id, iac_finding_id, container_finding_id, base_image_rec_id, dast_finding_id, reachable_flow_id, thread_id, task_id, run_seq, started_at, approved_at, pr_url, pr_number, pr_branch, pr_repo_full_name',
    )
    .eq('id', fixId)
    .maybeSingle();
  return (data as FullFixRow | null) ?? null;
}

export async function sendHeartbeat(supabase: SupabaseClient, fixId: string) {
  await supabase
    .from('project_security_fixes')
    .update({ heartbeat_at: new Date().toISOString() })
    .eq('id', fixId);
}

export interface AgentRunStats {
  /** Peak input tokens seen this run (= how full the context got). */
  inputTokens: number;
  /** The model's context window, for the meter denominator. */
  window: number;
  /** Steps taken so far. */
  step: number;
}

/**
 * Best-effort per-step telemetry for the task chat's context meter + /status.
 * Machine-fenced so a zombie run can't scribble stats over the live run's row.
 * Never throws — this is a UI nicety, not a correctness path.
 */
export async function updateAgentRunStats(
  supabase: SupabaseClient,
  fixId: string,
  stats: AgentRunStats,
  machineId?: string,
): Promise<void> {
  try {
    let q = supabase
      .from('project_security_fixes')
      .update({ agent_run_stats: { ...stats, updatedAt: new Date().toISOString() } })
      .eq('id', fixId);
    if (machineId) q = q.eq('machine_id', machineId);
    await q;
  } catch {
    /* best-effort */
  }
}

/**
 * Machine-id fence for terminal writes. A Stopped-then-woken row can be
 * reclaimed by a NEW machine while the OLD agent is still running; the old
 * (zombie) run's terminal writes must become no-ops instead of clobbering the
 * new run. Fenced on machine_id ONLY, NOT status — the cancel-restore path
 * legitimately writes while the row is 'rejected'.
 */
function terminalUpdate(
  supabase: SupabaseClient,
  fixId: string,
  patch: Record<string, unknown>,
  machineId?: string,
) {
  let q = supabase.from('project_security_fixes').update(patch).eq('id', fixId);
  if (machineId) q = q.eq('machine_id', machineId);
  return q;
}

export async function markCompleted(
  supabase: SupabaseClient,
  fixId: string,
  result: {
    prUrl: string;
    prNumber: number;
    prBranch: string;
    prRepoFullName: string;
    diffSummary: string;
    tokensUsed?: number;
    estimatedCost?: number;
  },
  machineId?: string,
) {
  await terminalUpdate(
    supabase,
    fixId,
    {
      status: 'completed',
      pr_url: result.prUrl,
      pr_number: result.prNumber,
      pr_branch: result.prBranch,
      pr_provider: 'github',
      pr_repo_full_name: result.prRepoFullName,
      diff_summary: result.diffSummary,
      tokens_used: result.tokensUsed ?? null,
      estimated_cost: result.estimatedCost ?? null,
      completed_at: new Date().toISOString(),
    },
    machineId,
  );
}

export async function markFailed(
  supabase: SupabaseClient,
  fixId: string,
  errorMessage: string,
  errorCategory?: string,
  failureDetails?: Record<string, unknown> | null,
  machineId?: string,
) {
  await terminalUpdate(
    supabase,
    fixId,
    {
      status: 'failed',
      error_message: errorMessage,
      error_category: errorCategory ?? null,
      failure_details: failureDetails ?? null,
      completed_at: new Date().toISOString(),
    },
    machineId,
  );
}

/**
 * Answer-only terminal write: flips the row to completed WITHOUT touching
 * pr_url/pr_number/pr_branch/diff_summary — used for answer-only resumes (the
 * prior PR still stands as-is) and for restoring a Stopped resume of a
 * previously-completed row (the rollup counts failed/rejected rows as failures
 * and would silently downgrade a completed task).
 */
export async function markAnswered(supabase: SupabaseClient, fixId: string, machineId?: string) {
  await terminalUpdate(
    supabase,
    fixId,
    { status: 'completed', completed_at: new Date().toISOString() },
    machineId,
  );
}

/**
 * End-of-run drain: if the user sent a follow-up DURING this run (after the
 * watermark the run actually replayed), re-queue the row via wake_agent_fix so
 * the next run picks the message up. Returns true when it re-queued. Never
 * throws — post-run cleanup must not fail the job.
 */
export async function maybeRequeueFollowup(
  supabase: SupabaseClient,
  fixId: string,
  threadId: string | null,
  taskId: string | null,
  watermarkIso: string | null,
): Promise<boolean> {
  try {
    if (!threadId || !watermarkIso) return false;
    if (taskId) {
      // v1: drain only single-target tasks — a multi-target task's wake fans
      // out through the /message endpoint, not the per-row drain.
      const { data: agentRows } = await supabase
        .from('project_security_fixes')
        .select('id')
        .eq('task_id', taskId)
        .eq('strategy', 'agent')
        .limit(2);
      if ((agentRows?.length ?? 0) > 1) return false;
    }
    const { data: newer } = await supabase
      .from('aegis_chat_messages')
      .select('id')
      .eq('thread_id', threadId)
      .eq('role', 'user')
      .gt('created_at', watermarkIso)
      .limit(1);
    if (!newer || newer.length === 0) return false;
    await supabase.rpc('wake_agent_fix', { p_fix_id: fixId });
    console.log(`[FIX] follow-up arrived during the run — re-queued ${fixId}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Should the running job abort? True on a user Stop (status='rejected') OR —
 * when machineId is provided — on a lease reassignment (a Stopped-then-woken
 * row reset machine_id and may now belong to a NEW machine; the OLD still-
 * running agent must abort at the next step boundary instead of zombie-writing
 * over the new run).
 */
export async function isJobCancelled(
  supabase: SupabaseClient,
  fixId: string,
  machineId?: string,
): Promise<boolean> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select('status, machine_id')
    .eq('id', fixId)
    .maybeSingle();
  if (!data) return false;
  if (data.status === 'rejected') return true;
  return machineId != null && data.machine_id !== machineId;
}

export async function getOrgInstallationId(
  supabase: SupabaseClient,
  organizationId: string,
  projectId: string,
): Promise<{ installationId: string; repoFullName: string; packageJsonPath: string } | null> {
  const { data: repo } = await supabase
    .from('project_repositories')
    .select('repo_full_name, installation_id, package_json_path')
    .eq('project_id', projectId)
    .maybeSingle();
  if (!repo?.repo_full_name) return null;

  // package_json_path is the project's subdirectory within a monorepo
  // (TEXT, '' = repo root, e.g. 'frontend' / 'backend'). Setup + plan-apply +
  // tests run inside this subdir; git ops stay at the clone root.
  const packageJsonPath = (repo.package_json_path as string | null) ?? '';

  if (repo.installation_id) {
    return {
      installationId: repo.installation_id as string,
      repoFullName: repo.repo_full_name,
      packageJsonPath,
    };
  }

  const { data: org } = await supabase
    .from('organizations')
    .select('github_installation_id')
    .eq('id', organizationId)
    .single();
  if (!org?.github_installation_id) return null;
  return {
    installationId: org.github_installation_id as string,
    repoFullName: repo.repo_full_name,
    packageJsonPath,
  };
}
