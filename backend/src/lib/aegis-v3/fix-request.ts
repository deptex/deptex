import { supabase } from '../supabase';
import { generateFixPlan } from './fix-planner';
import { signApprovalToken } from './approval-token';
import { startFixMachine } from '../fly-machines';
import type { FindingType, FixPlan, FixStatus, PlanRefusal } from './plan-types';

// The fix-creation money-path, extracted from the two hand-copies that had
// already drifted (routes/aegis-fix.ts `runPlanForRow` kept the SENTINEL_REASONS
// sanitizer; tools/fix.ts `request_fix` didn't). Both, plus the new task lib,
// now route through here so the sanitizer, the refusal/throw handling, and the
// plan-metadata persistence (plan_base_sha/branch + approval_token) stay in one
// place. The task path additionally auto-approves (Henry: "accept authorizes
// the whole job"; the draft PR is the merge gate).

export function strategyForFindingType(findingType: FindingType): string {
  if (findingType === 'semgrep') return 'fix_semgrep';
  if (findingType === 'secret') return 'remediate_secret';
  return 'code_patch';
}

export function fixTypeColumn(
  findingType: FindingType,
): 'osv_id' | 'semgrep_finding_id' | 'secret_finding_id' {
  if (findingType === 'vulnerability') return 'osv_id';
  if (findingType === 'semgrep') return 'semgrep_finding_id';
  return 'secret_finding_id';
}

// Some models (Qwen3, certain OpenAI configs) always populate optional schema
// fields with placeholders rather than omitting them, so refusal:{reason:"null"}
// shows up on perfectly fine plans. Detect sentinel values and strip the refusal
// before persisting; otherwise the PlanCard renders the refusal layout on what's
// actually an approvable plan.
const SENTINEL_REASONS = new Set(['', 'null', 'none', 'n/a', 'na', 'no', 'false']);

function sanitizeRefusal(plan: FixPlan): { plan: FixPlan; isRealRefusal: boolean } {
  const rawReason = plan.refusal?.reason?.trim().toLowerCase();
  const isRealRefusal = !!plan.refusal && !!rawReason && !SENTINEL_REASONS.has(rawReason);
  return {
    plan: isRealRefusal ? plan : { ...plan, refusal: undefined },
    isRealRefusal,
  };
}

/**
 * Generate, sanitize, and persist a fix plan onto an EXISTING
 * project_security_fixes row. On planner throw, marks the row `failed` and
 * RE-THROWS (the caller decides whether that's a 500 or a best-effort skip).
 * Used by `/regenerate`, the REST `/request` route (via runPlanForRow), and
 * createFixRequest.
 */
export async function persistPlanForFix(args: {
  fixId: string;
  organizationId: string;
  projectId: string;
  findingType: FindingType;
  findingId: string;
  triggeredByUserId: string;
}): Promise<{ status: FixStatus; plan: FixPlan; baseSha: string; baseBranch: string }> {
  const { fixId, organizationId, projectId, findingType, findingId, triggeredByUserId } = args;

  let result;
  try {
    result = await generateFixPlan({
      organizationId,
      projectId,
      findingType,
      findingId,
      triggeredByUserId,
    });
  } catch (err: any) {
    await supabase
      .from('project_security_fixes')
      .update({
        status: 'failed',
        error_message: `Plan generation failed: ${err?.message ?? 'unknown error'}`,
        completed_at: new Date().toISOString(),
      })
      .eq('id', fixId);
    throw err;
  }

  const { plan: finalPlan, isRealRefusal } = sanitizeRefusal(result.plan);
  const generatedAt = new Date().toISOString();
  const status: FixStatus = isRealRefusal ? 'failed' : 'awaiting_approval';
  const approvalToken = isRealRefusal
    ? null
    : signApprovalToken(fixId, organizationId, generatedAt);

  await supabase
    .from('project_security_fixes')
    .update({
      status,
      plan: finalPlan,
      plan_generated_at: generatedAt,
      plan_base_sha: result.baseSha,
      plan_base_branch: result.baseBranch,
      approval_token: approvalToken,
      error_message: isRealRefusal ? `Refusal: ${finalPlan.refusal?.reason}` : null,
      completed_at: isRealRefusal ? generatedAt : null,
    })
    .eq('id', fixId);

  return { status, plan: finalPlan, baseSha: result.baseSha, baseBranch: result.baseBranch };
}

export interface CreateFixRequestResult {
  fixId: string;
  status: FixStatus;
  plan: FixPlan | null;
  refusal?: PlanRefusal;
  error?: string;
}

/**
 * Insert a project_security_fixes row and generate/persist its plan, optionally
 * auto-approving + starting the fix-worker (the task path). Best-effort: a
 * planner crash yields a `failed` result rather than throwing, so a task
 * fan-out can record the failure and continue with the next target.
 *
 * - `threadId` / `taskId` are stamped on the row (BOTH for task fixes, so the
 *   realtime FixPanelHost — keyed by thread_id — shows live progress).
 * - `autoApprove` only takes effect when the plan reaches `awaiting_approval`
 *   (a refusal/crash stays `failed`, never approved). The internal approval
 *   path needs no signed token — there's no verifier on it; we flip to
 *   `approved` directly.
 */
export async function createFixRequest(args: {
  organizationId: string;
  projectId: string;
  findingType: FindingType;
  findingId: string;
  triggeredByUserId: string;
  threadId?: string;
  taskId?: string;
  autoApprove?: boolean;
  payloadSource?: string;
}): Promise<CreateFixRequestResult> {
  const {
    organizationId,
    projectId,
    findingType,
    findingId,
    triggeredByUserId,
    threadId,
    taskId,
    autoApprove,
    payloadSource,
  } = args;

  const insertRow: Record<string, any> = {
    project_id: projectId,
    organization_id: organizationId,
    fix_type: findingType,
    strategy: strategyForFindingType(findingType),
    status: 'planning' as FixStatus,
    triggered_by: triggeredByUserId,
    [fixTypeColumn(findingType)]: findingId,
    payload: { source: payloadSource ?? 'aegis_fix_request' },
  };
  if (threadId) insertRow.thread_id = threadId;
  if (taskId) insertRow.task_id = taskId;

  const { data: created, error: insertError } = await supabase
    .from('project_security_fixes')
    .insert(insertRow)
    .select('id')
    .single();
  if (insertError || !created) {
    return {
      fixId: '',
      status: 'failed',
      plan: null,
      error: insertError?.message ?? 'Failed to create fix request',
    };
  }

  let planResult;
  try {
    planResult = await persistPlanForFix({
      fixId: created.id,
      organizationId,
      projectId,
      findingType,
      findingId,
      triggeredByUserId,
    });
  } catch (err: any) {
    // persistPlanForFix already marked the row failed before rethrowing.
    return {
      fixId: created.id,
      status: 'failed',
      plan: null,
      error: err?.message ?? 'Plan generation failed',
    };
  }

  const { status, plan } = planResult;
  const refusal = status === 'failed' ? plan.refusal : undefined;

  if (autoApprove && status === 'awaiting_approval') {
    await supabase
      .from('project_security_fixes')
      .update({
        status: 'approved',
        approved_at: new Date().toISOString(),
        approved_by_user_id: triggeredByUserId,
      })
      .eq('id', created.id)
      .eq('status', 'awaiting_approval');

    // Best-effort: start a fix-worker machine. If it fails, the fix-recovery
    // cron surfaces orphaned approved jobs and starts machines for them.
    try {
      await startFixMachine();
    } catch (e: any) {
      console.warn(`[aegis-fix-request] Failed to start fix-worker machine: ${e?.message ?? e}`);
    }

    return { fixId: created.id, status: 'approved', plan };
  }

  return { fixId: created.id, status, plan, refusal };
}
