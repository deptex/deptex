import crypto from 'crypto';
import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { generateFixPlan } from '../lib/aegis-v3/fix-planner';
import { signApprovalToken } from '../lib/aegis-v3/approval-token';
import {
  createInstallationToken,
  getBranchSha,
} from '../lib/github';
import { startFixMachine } from '../lib/fly-machines';
import type {
  FindingType,
  FixPlan,
  FixStatus,
} from '../lib/aegis-v3/plan-types';

const router = express.Router();
router.use(authenticateUser);

const FINDING_TYPES: readonly FindingType[] = ['vulnerability', 'semgrep', 'secret'];

type Permission =
  | 'trigger_fix'
  | 'interact_with_aegis'
  | 'manage_aegis'
  | 'view_ai_spending'
  | 'manage_incidents';

async function hasPermission(
  orgId: string,
  userId: string,
  permission: Permission,
): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.[permission] === true;
}

async function isOrgMember(orgId: string, userId: string): Promise<boolean> {
  const { data } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .maybeSingle();
  return !!data;
}

function strategyForFindingType(findingType: FindingType): string {
  if (findingType === 'semgrep') return 'fix_semgrep';
  if (findingType === 'secret') return 'remediate_secret';
  return 'code_patch';
}

interface FixRow {
  id: string;
  organization_id: string;
  project_id: string;
  fix_type: FindingType;
  status: FixStatus;
  plan: FixPlan | null;
  plan_generated_at: string | null;
  plan_base_sha: string | null;
  plan_base_branch: string | null;
  approval_token: string | null;
  approved_at: string | null;
  rejected_at: string | null;
  pr_url: string | null;
  pr_number: number | null;
  diff_summary: string | null;
  error_message: string | null;
  created_at: string;
  triggered_by: string;
  osv_id: string | null;
  semgrep_finding_id: string | null;
  secret_finding_id: string | null;
  thread_id: string | null;
}

function shapeFixRow(row: FixRow) {
  const findingId =
    row.fix_type === 'vulnerability'
      ? row.osv_id
      : row.fix_type === 'semgrep'
        ? row.semgrep_finding_id
        : row.secret_finding_id;
  return {
    id: row.id,
    organizationId: row.organization_id,
    projectId: row.project_id,
    status: row.status,
    finding: { type: row.fix_type, id: findingId ?? '' },
    plan: row.plan,
    planGeneratedAt: row.plan_generated_at,
    planBaseSha: row.plan_base_sha,
    planBaseBranch: row.plan_base_branch,
    approvalToken: row.approval_token,
    approvedAt: row.approved_at,
    rejectedAt: row.rejected_at,
    prUrl: row.pr_url,
    prNumber: row.pr_number,
    diffSummary: row.diff_summary,
    errorMessage: row.error_message,
    createdAt: row.created_at,
    threadId: row.thread_id,
  };
}

async function loadFixRow(fixId: string): Promise<FixRow | null> {
  const { data } = await supabase
    .from('project_security_fixes')
    .select(
      'id, organization_id, project_id, fix_type, status, plan, plan_generated_at, plan_base_sha, plan_base_branch, approval_token, approved_at, rejected_at, pr_url, pr_number, diff_summary, error_message, created_at, triggered_by, osv_id, semgrep_finding_id, secret_finding_id, thread_id',
    )
    .eq('id', fixId)
    .maybeSingle();
  return (data as FixRow | null) ?? null;
}

async function runPlanForRow(
  fixId: string,
  organizationId: string,
  projectId: string,
  findingType: FindingType,
  findingId: string,
  triggeredByUserId: string,
): Promise<{ status: FixStatus; plan: FixPlan; baseSha: string; baseBranch: string }> {
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

  // Some models (Qwen3, certain OpenAI configs) always populate optional
  // schema fields with placeholders rather than omitting them. So
  // refusal: { reason: "null" } shows up on perfectly fine plans. Detect
  // sentinel values and strip the refusal before persisting; otherwise the
  // PlanCard renders the refusal layout on what's actually an approvable plan.
  const SENTINEL_REASONS = new Set(['', 'null', 'none', 'n/a', 'na', 'no', 'false']);
  const rawReason = result.plan.refusal?.reason?.trim().toLowerCase();
  const isRealRefusal = !!result.plan.refusal && !!rawReason && !SENTINEL_REASONS.has(rawReason);
  const finalPlan: FixPlan = isRealRefusal
    ? result.plan
    : { ...result.plan, refusal: undefined };

  const generatedAt = new Date().toISOString();
  const status: FixStatus = isRealRefusal ? 'failed' : 'awaiting_approval';
  const approvalToken = isRealRefusal ? null : signApprovalToken(fixId, organizationId, generatedAt);

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

router.post('/request', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId, projectId, findingType, findingId } = req.body ?? {};

  if (!organizationId || !projectId || !findingType || !findingId) {
    return res
      .status(400)
      .json({ error: 'organizationId, projectId, findingType, and findingId are required' });
  }
  if (!FINDING_TYPES.includes(findingType)) {
    return res.status(400).json({ error: `findingType must be one of ${FINDING_TYPES.join(', ')}` });
  }

  if (!(await hasPermission(organizationId, userId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }

  const fixTypeColumn =
    findingType === 'vulnerability'
      ? 'osv_id'
      : findingType === 'semgrep'
        ? 'semgrep_finding_id'
        : 'secret_finding_id';

  const insertRow = {
    project_id: projectId,
    organization_id: organizationId,
    fix_type: findingType,
    strategy: strategyForFindingType(findingType),
    status: 'planning' as FixStatus,
    triggered_by: userId,
    [fixTypeColumn]: findingId,
    payload: { source: 'aegis_fix_request' },
  };

  const { data: created, error: insertError } = await supabase
    .from('project_security_fixes')
    .insert(insertRow)
    .select('id')
    .single();

  if (insertError || !created) {
    return res
      .status(500)
      .json({ error: insertError?.message ?? 'Failed to create fix request' });
  }

  try {
    const { status, plan } = await runPlanForRow(
      created.id,
      organizationId,
      projectId,
      findingType,
      findingId,
      userId,
    );
    const row = await loadFixRow(created.id);
    const threadId = await ensureFixThread({
      fixId: created.id,
      organizationId,
      projectId,
      userId,
      planSummary: plan?.summary ?? null,
      findingType,
    });
    return res.status(201).json({
      fixId: created.id,
      threadId,
      status,
      plan,
      fix: row ? shapeFixRow(row) : null,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message ?? 'Plan generation failed', fixId: created.id });
  }
});

/**
 * Pre-create a chat thread tied to a fix (or return the existing one if already linked).
 * Lets the sidebar render a status icon for the fix without the user having
 * sent a message yet, and gives "Fix with Aegis" → chat a 1:1 navigation target.
 */
async function ensureFixThread(args: {
  fixId: string;
  organizationId: string;
  projectId: string;
  userId: string;
  planSummary: string | null;
  findingType: FindingType;
}): Promise<string> {
  const { fixId, organizationId, projectId, userId, planSummary, findingType } = args;

  const { data: existing } = await supabase
    .from('aegis_chat_threads')
    .select('id')
    .eq('organization_id', organizationId)
    .eq('context_type', 'fix')
    .eq('context_id', fixId)
    .maybeSingle();
  if (existing?.id) return existing.id as string;

  const fallbackTitle =
    findingType === 'vulnerability'
      ? 'Fix Vulnerability'
      : findingType === 'semgrep'
        ? 'Fix Semgrep Finding'
        : 'Remediate Secret';
  const title = (planSummary?.trim() || fallbackTitle).slice(0, 120);

  const { data: thread, error } = await supabase
    .from('aegis_chat_threads')
    .insert({
      organization_id: organizationId,
      user_id: userId,
      created_by: userId,
      title,
      project_id: projectId,
      context_type: 'fix',
      context_id: fixId,
    })
    .select('id')
    .single();
  if (error || !thread) {
    // Don't fail the fix request just because we couldn't pre-create a thread —
    // the chat will still work, it just won't show an icon in the sidebar.
    console.error('[aegis-fix] failed to create thread for fix', fixId, error);
    return '';
  }

  await supabase.from('aegis_chat_participants').insert({
    thread_id: thread.id,
    user_id: userId,
  });

  return thread.id as string;
}

router.get('/pending', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const organizationId = (req.query.organizationId as string | undefined) ?? '';
  if (!organizationId) {
    return res.status(400).json({ error: 'organizationId is required' });
  }
  if (!(await isOrgMember(organizationId, userId))) {
    return res.status(403).json({ error: 'Not a member of this organization' });
  }

  const { data, error } = await supabase
    .from('project_security_fixes')
    .select(
      'id, organization_id, project_id, fix_type, status, plan, plan_generated_at, plan_base_sha, plan_base_branch, approval_token, approved_at, rejected_at, pr_url, pr_number, diff_summary, error_message, created_at, triggered_by, osv_id, semgrep_finding_id, secret_finding_id, thread_id',
    )
    .eq('organization_id', organizationId)
    .in('status', ['planning', 'awaiting_approval'])
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) return res.status(500).json({ error: error.message });
  return res.json({ fixes: (data ?? []).map((row: any) => shapeFixRow(row)) });
});

router.get('/by-thread/:threadId', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const threadId = req.params.threadId;
  if (!threadId) return res.status(400).json({ error: 'threadId is required' });

  // Auth: scope to threads visible to this user. Reading from the thread
  // row also tells us the org so we can run the membership check.
  const { data: thread, error: threadError } = await supabase
    .from('aegis_chat_threads')
    .select('id, organization_id')
    .eq('id', threadId)
    .maybeSingle();
  if (threadError) return res.status(500).json({ error: threadError.message });
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await isOrgMember(thread.organization_id, userId))) {
    return res.status(403).json({ error: 'Not a member of this organization' });
  }

  const { data, error } = await supabase
    .from('project_security_fixes')
    .select(
      'id, organization_id, project_id, fix_type, status, plan, plan_generated_at, plan_base_sha, plan_base_branch, approval_token, approved_at, rejected_at, pr_url, pr_number, diff_summary, error_message, created_at, triggered_by, osv_id, semgrep_finding_id, secret_finding_id, thread_id',
    )
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  return res.json({ fixes: (data ?? []).map((row: any) => shapeFixRow(row)) });
});

router.get('/:fixId', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const row = await loadFixRow(req.params.fixId);
  if (!row) return res.status(404).json({ error: 'Fix not found' });
  if (!(await isOrgMember(row.organization_id, userId))) {
    return res.status(403).json({ error: 'Not a member of this organization' });
  }
  return res.json({ fix: shapeFixRow(row) });
});


router.get('/:fixId/staleness', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const row = await loadFixRow(req.params.fixId);
  if (!row) return res.status(404).json({ error: 'Fix not found' });
  if (!(await isOrgMember(row.organization_id, userId))) {
    return res.status(403).json({ error: 'Not a member of this organization' });
  }
  if (!row.plan_base_sha || !row.plan_base_branch) {
    return res.json({ isStale: false, currentHeadSha: null, baseSha: null, baseBranch: null });
  }

  const { data: repo } = await supabase
    .from('project_repositories')
    .select('repo_full_name, installation_id')
    .eq('project_id', row.project_id)
    .maybeSingle();
  if (!repo?.repo_full_name) {
    return res
      .status(409)
      .json({ error: 'Project no longer has a connected repository' });
  }

  const installationId =
    (repo as any).installation_id ??
    (
      await supabase
        .from('organizations')
        .select('github_installation_id')
        .eq('id', row.organization_id)
        .single()
    ).data?.github_installation_id;
  if (!installationId) {
    return res
      .status(409)
      .json({ error: 'Organization has no GitHub App installation' });
  }

  const token = await createInstallationToken(installationId);
  const headSha = await getBranchSha(token, repo.repo_full_name, row.plan_base_branch);

  return res.json({
    isStale: headSha !== row.plan_base_sha,
    currentHeadSha: headSha,
    baseSha: row.plan_base_sha,
    baseBranch: row.plan_base_branch,
  });
});

router.patch('/:fixId/approve', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { token } = req.body ?? {};
  if (!token) return res.status(400).json({ error: 'token is required' });

  const row = await loadFixRow(req.params.fixId);
  if (!row) return res.status(404).json({ error: 'Fix not found' });

  if (!(await hasPermission(row.organization_id, userId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }
  if (row.status !== 'awaiting_approval') {
    return res
      .status(409)
      .json({ error: `Fix is in status '${row.status}' and cannot be approved` });
  }
  if (!row.plan_generated_at || !row.approval_token) {
    return res.status(409).json({ error: 'Fix has no approval token to validate' });
  }
  // The stored approval_token IS the HMAC, signed with INTERNAL_API_KEY at
  // generation time. We compare against the DB column directly — the token
  // is opaque, never leaves the wire/DB roundtrip, and only the legitimate
  // /request response gave it to the client. We previously also re-verified
  // the HMAC against plan_generated_at, but that fails on a real bug:
  // supabase-js returns timestamptz columns as "2026-04-29 00:25:03+00"
  // while sign time used new Date().toISOString() ("2026-04-29T00:25:03.722Z").
  // Format drift made every legit approval 401.
  //
  // Use a timing-safe comparison so an attacker can't byte-walk the HMAC by
  // measuring response latency. Length-mismatch is the only early-exit branch.
  if (typeof token !== 'string' || token.length !== row.approval_token.length) {
    return res.status(401).json({ error: 'Invalid approval token' });
  }
  const tokenBuf = Buffer.from(token);
  const expectedBuf = Buffer.from(row.approval_token);
  if (!crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
    return res.status(401).json({ error: 'Invalid approval token' });
  }

  const { error: updateError } = await supabase
    .from('project_security_fixes')
    .update({
      status: 'approved',
      approved_at: new Date().toISOString(),
      approved_by_user_id: userId,
    })
    .eq('id', req.params.fixId)
    .eq('status', 'awaiting_approval');
  if (updateError) return res.status(500).json({ error: updateError.message });

  // Best-effort: start a fix-worker machine. If it fails, fix-recovery cron
  // will surface orphaned approved jobs and start machines for them.
  try {
    await startFixMachine();
  } catch (e: any) {
    console.warn(`[AEGIS-FIX] Failed to start fix-worker machine: ${e?.message ?? e}`);
  }

  const updated = await loadFixRow(req.params.fixId);
  return res.json({ fix: updated ? shapeFixRow(updated) : null });
});

router.patch('/:fixId/reject', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { reason } = req.body ?? {};
  const row = await loadFixRow(req.params.fixId);
  if (!row) return res.status(404).json({ error: 'Fix not found' });

  if (!(await hasPermission(row.organization_id, userId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }
  if (!['planning', 'awaiting_approval'].includes(row.status)) {
    return res
      .status(409)
      .json({ error: `Fix is in status '${row.status}' and cannot be rejected` });
  }

  const { error: updateError } = await supabase
    .from('project_security_fixes')
    .update({
      status: 'rejected',
      rejected_at: new Date().toISOString(),
      rejected_by_user_id: userId,
      rejection_reason: typeof reason === 'string' ? reason : null,
    })
    .eq('id', req.params.fixId);
  if (updateError) return res.status(500).json({ error: updateError.message });

  const updated = await loadFixRow(req.params.fixId);
  return res.json({ fix: updated ? shapeFixRow(updated) : null });
});

router.post('/:fixId/regenerate', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const row = await loadFixRow(req.params.fixId);
  if (!row) return res.status(404).json({ error: 'Fix not found' });
  if (!(await hasPermission(row.organization_id, userId, 'trigger_fix'))) {
    return res.status(403).json({ error: 'You do not have permission to trigger fixes' });
  }
  if (!['planning', 'awaiting_approval', 'failed'].includes(row.status)) {
    return res
      .status(409)
      .json({ error: `Fix is in status '${row.status}' and cannot be regenerated` });
  }

  const findingId =
    row.fix_type === 'vulnerability'
      ? row.osv_id
      : row.fix_type === 'semgrep'
        ? row.semgrep_finding_id
        : row.secret_finding_id;
  if (!findingId) {
    return res.status(409).json({ error: 'Fix row is missing its finding id' });
  }

  await supabase
    .from('project_security_fixes')
    .update({
      status: 'planning',
      plan: null,
      plan_generated_at: null,
      plan_base_sha: null,
      plan_base_branch: null,
      approval_token: null,
      approved_at: null,
      approved_by_user_id: null,
      rejected_at: null,
      rejected_by_user_id: null,
      rejection_reason: null,
      error_message: null,
      completed_at: null,
    })
    .eq('id', row.id);

  try {
    const { status, plan } = await runPlanForRow(
      row.id,
      row.organization_id,
      row.project_id,
      row.fix_type,
      findingId,
      userId,
    );
    const refreshed = await loadFixRow(row.id);
    return res.json({
      fixId: row.id,
      status,
      plan,
      fix: refreshed ? shapeFixRow(refreshed) : null,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message ?? 'Plan generation failed' });
  }
});

export default router;
