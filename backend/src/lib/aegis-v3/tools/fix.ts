import { jsonSchema } from 'ai';
import type { AegisToolEntry } from '../tool-types';
import { generateFixPlan } from '../fix-planner';
import { signApprovalToken, verifyApprovalToken } from '../approval-token';
import { resolveProject } from './resolvers';
import {
  FINDING_TYPES,
  type FindingType,
  type FixPlan,
  type FixStatus,
} from '../plan-types';

function strategyForFindingType(findingType: FindingType): string {
  if (findingType === 'semgrep') return 'fix_semgrep';
  if (findingType === 'secret') return 'remediate_secret';
  return 'code_patch';
}

function fixTypeColumn(findingType: FindingType): 'osv_id' | 'semgrep_finding_id' | 'secret_finding_id' {
  if (findingType === 'vulnerability') return 'osv_id';
  if (findingType === 'semgrep') return 'semgrep_finding_id';
  return 'secret_finding_id';
}

// Resolve a non-UUID handle from list_project_issues to the underlying row id
// for semgrep / secret findings. Vulnerability handles are OSV ids and pass
// through unchanged. Returns either `{ rowId }` or `{ error }`.
async function resolveFindingHandle(
  findingType: FindingType,
  handle: string,
  projectId: string,
  supabase: any,
): Promise<{ rowId: string } | { error: string }> {
  if (findingType === 'vulnerability') {
    return { rowId: handle };
  }

  const colon = handle.lastIndexOf(':');
  if (colon < 1) {
    return { error: `Invalid finding handle '${handle}'. Re-run list_project_issues to get a current handle.` };
  }
  const filePath = handle.slice(0, colon);
  const lineRaw = handle.slice(colon + 1);
  const line = parseInt(lineRaw, 10);
  if (!filePath || !Number.isFinite(line)) {
    return { error: `Invalid finding handle '${handle}'. Re-run list_project_issues to get a current handle.` };
  }

  const table = findingType === 'semgrep' ? 'project_semgrep_findings' : 'project_secret_findings';
  let query = supabase
    .from(table)
    .select('id')
    .eq('project_id', projectId)
    .eq('file_path', filePath)
    .eq('start_line', line)
    .eq('status', 'open');
  if (findingType === 'secret') query = query.eq('is_current', true);

  const { data: rows, error } = await query;
  if (error) return { error: `Failed to resolve finding handle: ${error.message}` };
  if (!rows || rows.length === 0) {
    return { error: `No open ${findingType} finding at ${filePath}:${line}. Re-run list_project_issues.` };
  }
  if (rows.length > 1) {
    return {
      error: `Multiple ${findingType} findings at ${filePath}:${line}. Ask the user which one (by rule/detector) before retrying.`,
    };
  }
  return { rowId: (rows[0] as { id: string }).id };
}

const requestFix: AegisToolEntry<{
  findingType: FindingType;
  findingHandle: string;
  projectName: string;
}, {
  fixId?: string;
  status?: FixStatus;
  plan?: FixPlan;
  refusal?: { reason: string; manualSuggestion?: string };
  error?: string;
}> = {
  name: 'request_fix',
  description:
    "Generate a fix plan for a security issue (vulnerability / Semgrep / secret). Pass `projectName` exactly as the user said it (the resolver fuzzy-matches), `findingType` ('vulnerability' | 'semgrep' | 'secret'), and `findingHandle` exactly as returned in the `handle` field by `list_project_issues`. Always call `list_project_issues` first to obtain the right handle; never invent one. The plan must be approved (via `approve_fix`) before execution. Returns the plan, status (awaiting_approval | failed on refusal), and a fix id. Does not open a PR.",
  permission: 'trigger_fix',
  danger: 'medium',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      findingType: { type: 'string', enum: [...FINDING_TYPES] },
      findingHandle: { type: 'string', minLength: 1, description: 'The `handle` from list_project_issues. Opaque — never paraphrase to the user.' },
      projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
    },
    required: ['findingType', 'findingHandle', 'projectName'],
    additionalProperties: false,
  }),
  execute: async ({ findingType, findingHandle, projectName }, ctx) => {
    const resolved = await resolveProject(projectName, ctx.orgId, ctx.supabase);
    if ('error' in resolved) return { error: resolved.error };
    const projectId = resolved.id;

    const handleResolution = await resolveFindingHandle(findingType, findingHandle, projectId, ctx.supabase);
    if ('error' in handleResolution) return { error: handleResolution.error };
    const findingId = handleResolution.rowId;

    const insertRow = {
      project_id: projectId,
      organization_id: ctx.orgId,
      fix_type: findingType,
      strategy: strategyForFindingType(findingType),
      status: 'planning' as FixStatus,
      triggered_by: ctx.userId,
      [fixTypeColumn(findingType)]: findingId,
      payload: { source: 'aegis_tool_request_fix' },
    };

    const { data: created, error: insertError } = await ctx.supabase
      .from('project_security_fixes')
      .insert(insertRow)
      .select('id')
      .single();
    if (insertError || !created) {
      return { error: insertError?.message ?? 'Failed to create fix request' };
    }

    // Link this chat thread to the fix so the sidebar can render a status icon.
    // Best-effort — failure here doesn't break the fix flow.
    if (ctx.threadId) {
      try {
        await ctx.supabase
          .from('aegis_chat_threads')
          .update({ context_type: 'fix', context_id: created.id })
          .eq('id', ctx.threadId)
          .is('context_id', null);
      } catch (err) {
        console.error('[aegis-tool] failed to link thread to fix', ctx.threadId, created.id, err);
      }
    }

    let result;
    try {
      result = await generateFixPlan({
        organizationId: ctx.orgId,
        projectId,
        findingType,
        findingId,
        triggeredByUserId: ctx.userId,
      });
    } catch (err: any) {
      await ctx.supabase
        .from('project_security_fixes')
        .update({
          status: 'failed',
          error_message: `Plan generation failed: ${err?.message ?? 'unknown error'}`,
          completed_at: new Date().toISOString(),
        })
        .eq('id', created.id);
      return { fixId: created.id, status: 'failed', error: err?.message ?? 'Plan generation failed' };
    }

    const generatedAt = new Date().toISOString();
    const isRefusal = !!result.plan.refusal;
    const status: FixStatus = isRefusal ? 'failed' : 'awaiting_approval';
    const approvalToken = isRefusal
      ? null
      : signApprovalToken(created.id, ctx.orgId, generatedAt);

    await ctx.supabase
      .from('project_security_fixes')
      .update({
        status,
        plan: result.plan,
        plan_generated_at: generatedAt,
        plan_base_sha: result.baseSha,
        plan_base_branch: result.baseBranch,
        approval_token: approvalToken,
        error_message: isRefusal ? `Refusal: ${result.plan.refusal?.reason}` : null,
        completed_at: isRefusal ? generatedAt : null,
      })
      .eq('id', created.id);

    return {
      fixId: created.id,
      status,
      plan: result.plan,
      refusal: result.plan.refusal,
    };
  },
};

const approveFix: AegisToolEntry<{ fixId: string; token?: string }, {
  fixId?: string;
  status?: FixStatus;
  message?: string;
  error?: string;
}> = {
  name: 'approve_fix',
  description:
    'Approve a fix plan that is in awaiting_approval status. The fix-worker will then claim and execute it. Requires the user to have already seen the plan; the chat surface signs the approval automatically using the stored token.',
  permission: 'trigger_fix',
  danger: 'high',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      fixId: { type: 'string', format: 'uuid' },
      token: { type: 'string' },
    },
    required: ['fixId'],
    additionalProperties: false,
  }),
  execute: async ({ fixId, token }, ctx) => {
    const { data: row } = await ctx.supabase
      .from('project_security_fixes')
      .select('id, organization_id, status, plan_generated_at, approval_token')
      .eq('id', fixId)
      .maybeSingle();
    if (!row) return { error: 'Fix not found' };
    if (row.organization_id !== ctx.orgId) return { error: 'Fix not in current organization' };
    if (row.status !== 'awaiting_approval') {
      return { error: `Fix is in status '${row.status}' and cannot be approved` };
    }
    if (!row.plan_generated_at || !row.approval_token) {
      return { error: 'Fix has no approval token to validate' };
    }

    const presented = token ?? row.approval_token;
    if (presented !== row.approval_token) return { error: 'Invalid approval token' };
    if (!verifyApprovalToken(presented, row.id, row.organization_id, row.plan_generated_at)) {
      return { error: 'Invalid approval token' };
    }

    const { error: updateError } = await ctx.supabase
      .from('project_security_fixes')
      .update({
        status: 'approved',
        approved_at: new Date().toISOString(),
        approved_by_user_id: ctx.userId,
      })
      .eq('id', fixId)
      .eq('status', 'awaiting_approval');
    if (updateError) return { error: updateError.message };

    return {
      fixId,
      status: 'approved',
      message: 'Fix approved. The fix-worker will pick it up shortly.',
    };
  },
};

const rejectFix: AegisToolEntry<{ fixId: string; reason?: string }, {
  fixId?: string;
  status?: FixStatus;
  message?: string;
  error?: string;
}> = {
  name: 'reject_fix',
  description:
    'Reject a fix plan that is in planning or awaiting_approval status. Optional reason is recorded for the audit trail.',
  permission: 'trigger_fix',
  danger: 'low',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      fixId: { type: 'string', format: 'uuid' },
      reason: { type: 'string', maxLength: 1000 },
    },
    required: ['fixId'],
    additionalProperties: false,
  }),
  execute: async ({ fixId, reason }, ctx) => {
    const { data: row } = await ctx.supabase
      .from('project_security_fixes')
      .select('id, organization_id, status')
      .eq('id', fixId)
      .maybeSingle();
    if (!row) return { error: 'Fix not found' };
    if (row.organization_id !== ctx.orgId) return { error: 'Fix not in current organization' };
    if (!['planning', 'awaiting_approval'].includes(row.status)) {
      return { error: `Fix is in status '${row.status}' and cannot be rejected` };
    }

    const { error: updateError } = await ctx.supabase
      .from('project_security_fixes')
      .update({
        status: 'rejected',
        rejected_at: new Date().toISOString(),
        rejected_by_user_id: ctx.userId,
        rejection_reason: reason ?? null,
      })
      .eq('id', fixId);
    if (updateError) return { error: updateError.message };

    return { fixId, status: 'rejected', message: 'Fix rejected.' };
  },
};

const checkFixStatus: AegisToolEntry<{ fixId: string }, {
  fixId?: string;
  status?: FixStatus;
  prUrl?: string | null;
  prNumber?: number | null;
  errorMessage?: string | null;
  error?: string;
}> = {
  name: 'check_fix_status',
  description: 'Read the current status of a fix job by id. Includes PR url + number when complete.',
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      fixId: { type: 'string', format: 'uuid' },
    },
    required: ['fixId'],
    additionalProperties: false,
  }),
  execute: async ({ fixId }, ctx) => {
    const { data: row } = await ctx.supabase
      .from('project_security_fixes')
      .select('id, organization_id, status, pr_url, pr_number, error_message')
      .eq('id', fixId)
      .maybeSingle();
    if (!row) return { error: 'Fix not found' };
    if (row.organization_id !== ctx.orgId) return { error: 'Fix not in current organization' };
    return {
      fixId: row.id,
      status: row.status,
      prUrl: row.pr_url,
      prNumber: row.pr_number,
      errorMessage: row.error_message,
    };
  },
};

export const fixTools: AegisToolEntry[] = [requestFix, approveFix, rejectFix, checkFixStatus];
