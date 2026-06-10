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
    // Synchronous ordinal — captured BEFORE any await so parallel calls each
    // get a unique number. Used by the fan-out guard below (Set-based dedup
    // updates after async work, which leaks the race).
    const callOrdinal = ++ctx.turnState.requestCallCount;

    const resolved = await resolveProject(projectName, ctx.orgId, ctx.supabase);
    if ('error' in resolved) return { error: resolved.error };
    const projectId = resolved.id;

    const handleResolution = await resolveFindingHandle(findingType, findingHandle, projectId, ctx.supabase);
    if ('error' in handleResolution) return { error: handleResolution.error };
    const findingId = handleResolution.rowId;

    const findingKey = `${findingType}:${projectId}:${findingId}`;

    // Cross-turn dedup. If this thread already has an awaiting_approval plan
    // for the same finding, hand it back instead of creating a duplicate.
    // Without this, a "do it again" prompt in turn N+1 spawns a second row
    // for the same CVE — then revise_fix's planMatch hits both and fails
    // with "matched 2 plans" until the agent gives up. Observed in dogfood
    // 2026-05-07: 8 revise_fix attempts in one turn, 5 of them ambiguity
    // errors, all caused by duplicate (thread, CVE) rows from turn 2.
    if (ctx.threadId) {
      const { data: existing } = await ctx.supabase
        .from('project_security_fixes')
        .select('id, status')
        .eq('thread_id', ctx.threadId)
        .eq(fixTypeColumn(findingType), findingId)
        .eq('status', 'awaiting_approval')
        .limit(1)
        .maybeSingle();
      if (existing) {
        ctx.turnState.requestedFindings.add(findingKey);
        return {
          fixId: existing.id as string,
          status: existing.status as FixStatus,
          error:
            `A plan for ${findingType} ${findingHandle} on '${projectName}' already exists in this thread (awaiting approval). Call revise_fix with planMatch '${findingHandle}' to modify it, or approve_fix to proceed. Don't re-create.`,
        };
      }
    }

    // In-turn dedup. The agent occasionally requests a fix for a finding it
    // already requested earlier in the same turn (after a tool failure or
    // mid-stream confusion). Each plan-generation costs ~45-80s of model
    // time, so refusing is much cheaper than letting the model burn through
    // a duplicate.
    if (ctx.turnState.requestedFindings.has(findingKey)) {
      return {
        error: `A fix for ${findingType} ${findingHandle} on project '${projectName}' was already requested in this turn — the plan is already on screen. (This guard is scoped to the current user message only; it resets on the next one. Never refuse a future request or revision because of it.)`,
      };
    }

    // Fan-out guard: 2nd+ request_fix in the turn AND no set_todos = refuse.
    // Uses the sync ordinal captured at function entry so parallel calls are
    // caught reliably (Set-based size check would race for ~60s while the
    // first planner runs). Rule 10 is exactly for multi-finding fix work.
    if (callOrdinal >= 2 && !ctx.turnState.setTodosCalled) {
      return {
        error:
          "You're requesting fixes for multiple findings in this turn. Call `set_todos` first with one item per finding (rule 10), then resume calling request_fix. The user needs progress UI for fan-out work.",
      };
    }

    const insertRow: Record<string, any> = {
      project_id: projectId,
      organization_id: ctx.orgId,
      fix_type: findingType,
      strategy: strategyForFindingType(findingType),
      status: 'planning' as FixStatus,
      triggered_by: ctx.userId,
      [fixTypeColumn(findingType)]: findingId,
      payload: { source: 'aegis_tool_request_fix' },
    };
    // Phase 28: durable thread <-> fix link so the panel can list every
    // plan generated in this thread without relying on frontend memory.
    if (ctx.threadId) insertRow.thread_id = ctx.threadId;

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

    // Mark BEFORE plan generation so a duplicate request for the same finding
    // mid-generation (the model fan-out racing itself) gets rejected too.
    ctx.turnState.requestedFindings.add(findingKey);

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

const reviseFix: AegisToolEntry<{
  instructions: string;
  planMatch?: string;
}, {
  fixId?: string;
  status?: FixStatus;
  plan?: FixPlan;
  refusal?: { reason: string; manualSuggestion?: string };
  revised?: boolean;
  error?: string;
}> = {
  name: 'revise_fix',
  description:
    "Revise the plan for an EXISTING fix in this chat thread, incorporating user feedback as binding direction. Use this when the user pushes back on a plan you already produced (e.g. 'add more tests', 'use a different library', 'skip the rollback step'). Do NOT use this to start a new fix — call `request_fix` for that. " +
    "Resolves the target fix automatically; if the thread has multiple revisable plans, pass `planMatch` to disambiguate. `planMatch` matches case-insensitively against the plan summary AND against the underlying finding identifier (CVE / OSV id for vulnerabilities, file:line for Semgrep / secrets), so a CVE id like 'CVE-2022-42889' always works even after the plan title is rewritten. " +
    "When the user asks to revise N≥2 plans, call `set_todos` first (rule 10) — `revise_fix` will refuse the 2nd plan in a turn otherwise. Each plan can only be revised once per turn — a duplicate `revise_fix` returns an error. IMPORTANT: that once-per-turn limit resets on every new user message. A plan revised in an earlier turn can ALWAYS be revised again in the current one — never refuse a revision request because the plan was revised before. Replaces the existing plan and re-arms the approval flow.",
  permission: 'trigger_fix',
  danger: 'medium',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      instructions: {
        type: 'string',
        minLength: 4,
        maxLength: 2000,
        description: "Plain-language feedback to apply to the existing plan. Quote or paraphrase the user's own words rather than your interpretation.",
      },
      planMatch: {
        type: 'string',
        minLength: 2,
        maxLength: 200,
        description: "Distinctive substring identifying the target plan. Matches case-insensitively against the plan summary OR the finding id (CVE id like 'CVE-2022-42889', or 'src/file.ts:42' for Semgrep / secrets). Prefer CVE / finding ids when available — they're stable across revisions; plan titles can change. Required when the thread has more than one revisable plan.",
      },
    },
    required: ['instructions'],
    additionalProperties: false,
  }),
  execute: async ({ instructions, planMatch }, ctx) => {
    // Sync ordinal for the fan-out guard (see request_fix for rationale).
    const callOrdinal = ++ctx.turnState.reviseCallCount;

    if (!ctx.threadId) {
      return { error: 'revise_fix can only be used inside a chat thread.' };
    }

    const { data: candidates, error: lookupError } = await ctx.supabase
      .from('project_security_fixes')
      .select('id, project_id, organization_id, fix_type, status, osv_id, semgrep_finding_id, secret_finding_id, plan, created_at')
      .eq('organization_id', ctx.orgId)
      .eq('thread_id', ctx.threadId)
      .in('status', ['awaiting_approval', 'failed'])
      .order('created_at', { ascending: false });
    if (lookupError) {
      return { error: `Failed to look up fixes in this thread: ${lookupError.message}` };
    }
    if (!candidates || candidates.length === 0) {
      return {
        error:
          'No revisable fix in this thread. Plans can only be revised while awaiting approval or after a refusal — once a fix is executing or completed it is final.',
      };
    }

    // Build the haystack for planMatch: combine the plan summary AND the
    // stable finding identifier (osv_id / semgrep_finding_id / secret_finding_id).
    // Without the stable id, a planMatch like "CVE-2022-42889" fails the
    // moment a prior revision rewrites the summary to something generic like
    // "Bump vulnerable dependency" — observed in dogfood, cost ~3min/turn.
    const haystackFor = (c: any): string => {
      const parts: string[] = [];
      if (c.plan?.summary) parts.push(String(c.plan.summary));
      if (c.osv_id) parts.push(String(c.osv_id));
      if (c.semgrep_finding_id) parts.push(String(c.semgrep_finding_id));
      if (c.secret_finding_id) parts.push(String(c.secret_finding_id));
      // Plan-level metadata that often holds the file path (Semgrep / secret
      // findings). Captured generically because plan shape varies.
      if (Array.isArray(c.plan?.fileChanges)) {
        for (const fc of c.plan.fileChanges) if (fc?.path) parts.push(String(fc.path));
      }
      return parts.join(' ').toLowerCase();
    };

    let target = candidates[0];
    if (candidates.length > 1) {
      const trimmed = planMatch?.trim();
      if (!trimmed) {
        const titles = candidates
          .map((c: any) => {
            const summary = c.plan?.summary ?? '(plan still generating)';
            const id = c.osv_id ?? c.semgrep_finding_id ?? c.secret_finding_id ?? '?';
            return `- ${summary}  [id: ${id}]`;
          })
          .join('\n');
        return {
          error:
            `This thread has ${candidates.length} revisable plans:\n${titles}\nCall revise_fix again with planMatch set to a CVE / finding id (preferred — stable across revisions) or a distinctive substring of the target plan's title.`,
        };
      }
      const needle = trimmed.toLowerCase();
      const matches = candidates.filter((c: any) => haystackFor(c).includes(needle));
      if (matches.length === 0) {
        const titles = candidates
          .map((c: any) => {
            const summary = c.plan?.summary ?? '(plan still generating)';
            const id = c.osv_id ?? c.semgrep_finding_id ?? c.secret_finding_id ?? '?';
            return `- ${summary}  [id: ${id}]`;
          })
          .join('\n');
        return {
          error:
            `planMatch '${trimmed}' did not match any plan in this thread. Available plans:\n${titles}\nRetry with a CVE / finding id or a distinctive substring of one of these.`,
        };
      }
      if (matches.length > 1) {
        return {
          error: `planMatch '${trimmed}' matched ${matches.length} plans. Pass a more distinctive substring (e.g. a file name or full CVE id) so it picks exactly one.`,
        };
      }
      target = matches[0];
    }

    // In-turn dedup. revise_fix fired twice on the same plan within one turn
    // means the model lost track — observed in dogfood, agent revised
    // CVE-2021-44228 twice (once via "CVE-..." planMatch, once via
    // "Log4Shell RCE" planMatch). Two ~80s plan-generations for nothing.
    if (ctx.turnState.revisedFixIds.has(target.id)) {
      const summary = target.plan?.summary ?? '(unnamed plan)';
      return {
        error: `Plan '${summary}' was already revised in this turn — the latest revision is already on screen. Move on to the next plan or finalize. (This guard is scoped to the current user message only; it resets on the next one. When the user asks for another revision in a later message, call revise_fix again — never refuse based on this turn's dedup.)`,
      };
    }

    // Fan-out guard via sync ordinal — catches parallel calls that would
    // otherwise both pass a Set.size check before either added to the Set
    // (observed in dogfood: 2 parallel revise_fix sneaking past).
    if (callOrdinal >= 2 && !ctx.turnState.setTodosCalled) {
      return {
        error:
          "You're operating on multiple plans in this turn. Call `set_todos` first with one item per plan you intend to revise (rule 10), then resume revising. The user needs progress UI for fan-out work.",
      };
    }

    const findingId =
      target.fix_type === 'vulnerability'
        ? target.osv_id
        : target.fix_type === 'semgrep'
          ? target.semgrep_finding_id
          : target.secret_finding_id;
    if (!findingId) {
      return { error: 'Existing fix row is missing its finding id and cannot be revised.' };
    }

    // Flip to planning so the panel + chat show the "Revising" pill via
    // realtime, and so the now-stale approval token can't be used. Keep the
    // existing plan/base metadata in place so the card keeps showing the
    // previous title until the new plan overwrites it (and so a failed
    // revise leaves the original plan recoverable).
    await ctx.supabase
      .from('project_security_fixes')
      .update({
        status: 'planning' as FixStatus,
        approval_token: null,
        approved_at: null,
        approved_by_user_id: null,
        rejected_at: null,
        rejected_by_user_id: null,
        rejection_reason: null,
        error_message: null,
        completed_at: null,
      })
      .eq('id', target.id);

    let result;
    try {
      result = await generateFixPlan({
        organizationId: ctx.orgId,
        projectId: target.project_id,
        findingType: target.fix_type,
        findingId,
        triggeredByUserId: ctx.userId,
        userInstructions: instructions,
        // Preserve the plan title across revisions unless the user explicitly
        // asks for a title change. Rewriting the summary on every revise
        // breaks subsequent planMatch lookups (the agent remembers the old
        // title; the new one might drop the CVE id) — observed in dogfood.
        existingSummary: target.plan?.summary,
      });
    } catch (err: any) {
      await ctx.supabase
        .from('project_security_fixes')
        .update({
          status: 'failed',
          error_message: `Plan revision failed: ${err?.message ?? 'unknown error'}`,
          completed_at: new Date().toISOString(),
        })
        .eq('id', target.id);
      // Mark as revised even on failure — a 2nd attempt on the same plan in
      // this turn would just re-run the same broken planner call.
      ctx.turnState.revisedFixIds.add(target.id);
      return { fixId: target.id, status: 'failed', error: err?.message ?? 'Plan revision failed', revised: true };
    }
    ctx.turnState.revisedFixIds.add(target.id);

    const generatedAt = new Date().toISOString();
    const isRefusal = !!result.plan.refusal;
    const status: FixStatus = isRefusal ? 'failed' : 'awaiting_approval';
    const approvalToken = isRefusal
      ? null
      : signApprovalToken(target.id, ctx.orgId, generatedAt);

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
      .eq('id', target.id);

    return {
      fixId: target.id,
      status,
      plan: result.plan,
      refusal: result.plan.refusal,
      revised: true,
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

export const fixTools: AegisToolEntry[] = [requestFix, reviseFix, approveFix, rejectFix, checkFixStatus];
