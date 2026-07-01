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
  if (findingType === 'iac') return 'fix_iac';
  // container OS-CVEs are only fixable by moving the base image (you can't patch
  // an OS package baked into an image from app code), so they share the
  // base-image bump path.
  if (findingType === 'base_image' || findingType === 'container') return 'bump_base_image';
  if (findingType === 'dataflow') return 'sanitize_dataflow';
  if (findingType === 'dast') return 'patch_handler';
  return 'code_patch';
}

export type FixFindingIdColumn =
  | 'osv_id'
  | 'semgrep_finding_id'
  | 'secret_finding_id'
  | 'iac_finding_id'
  | 'container_finding_id'
  | 'base_image_rec_id'
  | 'reachable_flow_id'
  | 'dast_finding_id';

export function fixTypeColumn(findingType: FindingType): FixFindingIdColumn {
  if (findingType === 'vulnerability') return 'osv_id';
  if (findingType === 'semgrep') return 'semgrep_finding_id';
  if (findingType === 'secret') return 'secret_finding_id';
  if (findingType === 'iac') return 'iac_finding_id';
  if (findingType === 'container') return 'container_finding_id';
  if (findingType === 'base_image') return 'base_image_rec_id';
  // dataflow keys on the project_reachable_flows row it neutralises.
  if (findingType === 'dataflow') return 'reachable_flow_id';
  return 'dast_finding_id';
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
/**
 * Just the row INSERT (status 'planning', no plan yet). Fast. Split out so the
 * task fan-out can create all its fix rows instantly, return, and generate the
 * (slow, ~60-80s each) plans in the background.
 */
export async function insertFixRow(args: {
  organizationId: string;
  projectId: string;
  findingType: FindingType;
  findingId: string;
  triggeredByUserId: string;
  threadId?: string;
  taskId?: string;
  payloadSource?: string;
}): Promise<{ fixId: string } | { error: string }> {
  const insertRow: Record<string, any> = {
    project_id: args.projectId,
    organization_id: args.organizationId,
    fix_type: args.findingType,
    strategy: strategyForFindingType(args.findingType),
    status: 'planning' as FixStatus,
    triggered_by: args.triggeredByUserId,
    [fixTypeColumn(args.findingType)]: args.findingId,
    payload: { source: args.payloadSource ?? 'aegis_fix_request' },
  };
  if (args.threadId) insertRow.thread_id = args.threadId;
  if (args.taskId) insertRow.task_id = args.taskId;

  const { data: created, error } = await supabase
    .from('project_security_fixes')
    .insert(insertRow)
    .select('id')
    .single();
  if (error || !created) return { error: error?.message ?? 'Failed to create fix request' };
  return { fixId: created.id as string };
}

/**
 * The slow half: generate + persist the plan on an existing fix row, optionally
 * auto-approve + start the worker. Safe to run in the background (a planner
 * crash marks the row failed, never throws out).
 */
export async function planAndApproveFix(args: {
  fixId: string;
  organizationId: string;
  projectId: string;
  findingType: FindingType;
  findingId: string;
  triggeredByUserId: string;
  autoApprove?: boolean;
}): Promise<CreateFixRequestResult> {
  const { fixId, autoApprove, triggeredByUserId } = args;
  let planResult;
  try {
    planResult = await persistPlanForFix({
      fixId,
      organizationId: args.organizationId,
      projectId: args.projectId,
      findingType: args.findingType,
      findingId: args.findingId,
      triggeredByUserId,
    });
  } catch (err: any) {
    // persistPlanForFix already marked the row failed before rethrowing.
    return { fixId, status: 'failed', plan: null, error: err?.message ?? 'Plan generation failed' };
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
      .eq('id', fixId)
      .eq('status', 'awaiting_approval');

    // Best-effort: start a fix-worker machine. If it fails, the fix-recovery
    // cron surfaces orphaned approved jobs and starts machines for them.
    try {
      await startFixMachine();
    } catch (e: any) {
      console.warn(`[aegis-fix-request] Failed to start fix-worker machine: ${e?.message ?? e}`);
    }

    return { fixId, status: 'approved', plan };
  }

  return { fixId, status, plan, refusal };
}

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
  const ins = await insertFixRow(args);
  if ('error' in ins) return { fixId: '', status: 'failed', plan: null, error: ins.error };
  return planAndApproveFix({
    fixId: ins.fixId,
    organizationId: args.organizationId,
    projectId: args.projectId,
    findingType: args.findingType,
    findingId: args.findingId,
    triggeredByUserId: args.triggeredByUserId,
    autoApprove: args.autoApprove,
  });
}
