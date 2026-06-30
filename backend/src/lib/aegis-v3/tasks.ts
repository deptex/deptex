import crypto from 'crypto';
import { supabase } from '../supabase';
import { getActiveExtractionId } from '../active-extraction';
import { logSecurityEvent } from '../security-audit';
import { insertFixRow, planAndApproveFix } from './fix-request';
import {
  AEGIS_TASK_MAX_TARGETS,
  type AegisTask,
  type AegisTaskSource,
  type AegisTaskTarget,
} from './task-types';

// ---------------------------------------------------------------------------
// Row shaping
// ---------------------------------------------------------------------------

const TASK_COLUMNS =
  'id, organization_id, project_id, thread_id, kind, title, description, status, source, ' +
  'targets, total_fixes, completed_fixes, failed_fixes, summary, accepted_at, completed_at, ' +
  'created_at, updated_at';

function shapeTask(row: any): AegisTask {
  return {
    id: row.id,
    organizationId: row.organization_id,
    projectId: row.project_id ?? null,
    threadId: row.thread_id ?? null,
    kind: 'fix',
    title: row.title,
    description: row.description ?? null,
    status: row.status,
    source: row.source,
    targets: Array.isArray(row.targets) ? (row.targets as AegisTaskTarget[]) : [],
    totalFixes: row.total_fixes ?? 0,
    completedFixes: row.completed_fixes ?? 0,
    failedFixes: row.failed_fixes ?? 0,
    summary: row.summary ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    acceptedAt: row.accepted_at ?? null,
    completedAt: row.completed_at ?? null,
  };
}

// ---------------------------------------------------------------------------
// Target re-resolution: finding_key (stable) -> the live id the fix pipeline
// targets by (osv_id for vulnerabilities, the row id for semgrep / secret).
// Returns null when the finding is no longer present in the active run.
// ---------------------------------------------------------------------------

async function resolveTargetFindingId(target: AegisTaskTarget): Promise<string | null> {
  const activeRun = await getActiveExtractionId(supabase, target.projectId);
  if (!activeRun) return null;

  if (target.findingType === 'vulnerability') {
    // Vuln finding_key = sha256(package‖osv_id) is location-unique → safe to resolve by.
    const { data } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('osv_id')
      .eq('project_id', target.projectId)
      .eq('finding_key', target.findingKey)
      .eq('extraction_run_id', activeRun)
      .order('depscore', { ascending: false, nullsFirst: false })
      .limit(1)
      .maybeSingle();
    return (data as any)?.osv_id ?? null;
  }

  // semgrep / secret: resolve by LOCATION (findingHandle = `file:line`), because
  // their finding_key is per-rule (shared across all occurrences). Falling back
  // to finding_key would collapse N distinct findings to one row.
  const table =
    target.findingType === 'semgrep' ? 'project_semgrep_findings' : 'project_secret_findings';
  if (target.findingHandle) {
    const colon = target.findingHandle.lastIndexOf(':');
    const filePath = colon > 0 ? target.findingHandle.slice(0, colon) : '';
    const line = colon > 0 ? parseInt(target.findingHandle.slice(colon + 1), 10) : NaN;
    if (filePath && Number.isFinite(line)) {
      let q = supabase
        .from(table)
        .select('id')
        .eq('project_id', target.projectId)
        .eq('file_path', filePath)
        .eq('start_line', line)
        .eq('extraction_run_id', activeRun)
        .eq('status', 'open');
      if (target.findingType === 'secret') q = q.eq('is_current', true);
      const { data } = await q.limit(1).maybeSingle();
      return (data as any)?.id ?? null;
    }
  }
  // Fallback (no location handle): resolve by finding_key (picks one occurrence).
  const { data } = await supabase
    .from(table)
    .select('id')
    .eq('project_id', target.projectId)
    .eq('finding_key', target.findingKey)
    .eq('extraction_run_id', activeRun)
    .limit(1)
    .maybeSingle();
  return (data as any)?.id ?? null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function titleFromDescription(description: string, fallback = 'Aegis task'): string {
  const first = description.trim().split('\n')[0].trim();
  return (first || fallback).slice(0, 120);
}

/**
 * Create the task-chat thread (context_type='task') and bind it 1:1 to the
 * task. The thread IS the task; tearing one down cascades the other. Returns the
 * existing thread id if the task already has one.
 */
async function createTaskThread(args: {
  taskId: string;
  organizationId: string;
  userId: string;
  title: string;
  projectId: string | null;
}): Promise<string> {
  const { taskId, organizationId, userId, title, projectId } = args;
  const { data: thread, error } = await supabase
    .from('aegis_chat_threads')
    .insert({
      organization_id: organizationId,
      user_id: userId,
      created_by: userId,
      title,
      project_id: projectId,
      context_type: 'task',
      context_id: taskId,
    })
    .select('id')
    .single();
  if (error || !thread) {
    throw new Error(error?.message ?? 'Failed to create task chat');
  }
  const threadId = thread.id as string;
  await supabase.from('aegis_chat_participants').insert({ thread_id: threadId, user_id: userId });
  await supabase.from('aegis_agent_tasks').update({ thread_id: threadId }).eq('id', taskId);
  return threadId;
}

/**
 * Idempotent thread-ensure: return the task's existing chat thread, or create
 * one bound 1:1 to the task. Shared by the task runner and the dev `/run`
 * endpoint so both agree on the single thread the task narrates into.
 */
export async function ensureTaskThread(taskId: string): Promise<string> {
  const { data: row } = await supabase
    .from('aegis_agent_tasks')
    .select('id, organization_id, project_id, thread_id, title, created_by')
    .eq('id', taskId)
    .maybeSingle();
  if (!row) throw new Error('Task not found');
  if (row.thread_id) return row.thread_id as string;
  return createTaskThread({
    taskId,
    organizationId: row.organization_id as string,
    userId: row.created_by as string,
    title: (row.title as string) ?? 'Aegis task',
    projectId: (row.project_id as string) ?? null,
  });
}

/**
 * Seed the task-chat with Aegis's opening turn: a short narration plus one
 * inline fix card per fix. The card parts are shaped exactly like a persisted
 * `request_fix` tool result so ChatPane's buildInitialMessages rehydrates them
 * into live-updating PlanCards (each self-subscribes to its fix's realtime
 * status) — that's how "the fixes read as part of the narrative". Best-effort.
 */
async function postTaskOpeningMessage(
  threadId: string,
  text: string,
  fixIds: string[],
): Promise<void> {
  const parts: any[] = [{ type: 'text', text }];
  for (const fixId of fixIds) {
    const toolCallId = crypto.randomUUID();
    parts.push({ type: 'tool-call', toolCallId, toolName: 'request_fix', args: {} });
    parts.push({ type: 'tool-result', toolCallId, toolName: 'request_fix', result: { fixId }, isError: false });
  }
  await supabase
    .from('aegis_chat_messages')
    .insert({ thread_id: threadId, role: 'assistant', content: text, metadata: { parts } })
    .then(undefined, (e: any) => console.error('[aegis-task] opening message insert failed:', e?.message));
}

/**
 * Send-to-Aegis door: create a `proposed` task from a finding AND eagerly spin
 * up its task-chat, so the user lands in a real chat showing the Accept/Decline
 * card (consistent consent with the chat door). No fixes are created until
 * acceptTask. Returns the task + its thread.
 */
export async function proposeTaskFromFinding(args: {
  orgId: string;
  projectId: string;
  createdBy: string;
  description: string;
  target: AegisTaskTarget;
}): Promise<{ taskId: string; threadId: string }> {
  const { orgId, projectId, createdBy, description, target } = args;
  const { taskId } = await createProposedTask({
    orgId,
    projectId,
    createdBy,
    description,
    targets: [target],
    source: 'finding',
    title: target.label,
  });
  const threadId = await createTaskThread({
    taskId,
    organizationId: orgId,
    userId: createdBy,
    title: target.label || titleFromDescription(description),
    projectId,
  });
  return { taskId, threadId };
}

/**
 * Create a `proposed` task (the Create-Task card / Send-to-Aegis confirm state).
 * Stores STABLE target identity only; no thread, no fixes yet.
 */
export async function createProposedTask(args: {
  orgId: string;
  projectId: string | null;
  createdBy: string;
  description: string;
  targets: AegisTaskTarget[];
  source: AegisTaskSource;
  title?: string;
}): Promise<{ taskId: string }> {
  const { orgId, projectId, createdBy, description, targets, source } = args;
  const title = (args.title?.trim() || titleFromDescription(description)).slice(0, 120);

  const { data, error } = await supabase
    .from('aegis_agent_tasks')
    .insert({
      organization_id: orgId,
      project_id: projectId,
      created_by: createdBy,
      kind: 'fix',
      title,
      description,
      status: 'proposed',
      source,
      targets,
    })
    .select('id')
    .single();
  if (error || !data) {
    throw new Error(error?.message ?? 'Failed to create task');
  }
  return { taskId: data.id as string };
}

/**
 * Accept a `proposed` task: spin up its task-chat, re-resolve targets against
 * the latest scan, stamp total_fixes up front, fan out auto-approved fixes, and
 * file an 'aegis' tracker link per target. Idempotent: re-accepting a task
 * that already has a thread returns that thread.
 *
 * Henry's contract: accepting authorizes the WHOLE job — fixes auto-approve and
 * the worker opens draft PRs; the PR merge stays the human gate.
 */
export async function acceptTask(args: {
  taskId: string;
  userId: string;
  organizationId: string;
}): Promise<{ threadId: string }> {
  const { taskId, userId, organizationId } = args;

  const { data: row } = await supabase
    .from('aegis_agent_tasks')
    .select(TASK_COLUMNS)
    .eq('id', taskId)
    .maybeSingle();
  if (!row) throw new Error('Task not found');

  const task = shapeTask(row);
  if (task.organizationId !== organizationId) throw new Error('Task not in current organization');

  // Idempotency keys on STATUS, not thread presence — the finding door
  // pre-creates the thread while the task is still 'proposed'. Only a 'proposed'
  // task fans out; anything else is already accepted/terminal.
  if (task.status !== 'proposed') {
    if (task.threadId) return { threadId: task.threadId };
    throw new Error(`Task is in status '${task.status}' and cannot be accepted`);
  }

  // 1. The task-chat thread (reuse the finding-door's pre-created one, else make it).
  const threadId =
    task.threadId ??
    (await createTaskThread({
      taskId,
      organizationId,
      userId,
      title: task.title,
      projectId: task.projectId,
    }));

  // 2. Re-resolve targets against the latest scan, then cap blast radius.
  const resolved: Array<{ target: AegisTaskTarget; findingId: string }> = [];
  for (const target of task.targets) {
    const findingId = await resolveTargetFindingId(target);
    if (findingId) resolved.push({ target, findingId });
    if (resolved.length >= AEGIS_TASK_MAX_TARGETS) break;
  }

  // 3. Stamp total_fixes UP FRONT (before any fix exists) so the rollup trigger
  //    never sees a momentarily-empty fix set as "completed".
  await supabase
    .from('aegis_agent_tasks')
    .update({
      thread_id: threadId,
      accepted_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      status: 'working',
      total_fixes: resolved.length,
    })
    .eq('id', taskId);

  // 4. Zero-fix terminal: nothing left to fix -> finish here, no chips to flip.
  if (resolved.length === 0) {
    await supabase
      .from('aegis_agent_tasks')
      .update({
        status: 'completed',
        completed_at: new Date().toISOString(),
        summary: 'Nothing to fix — the targeted findings are no longer present in the latest scan.',
      })
      .eq('id', taskId);
    await postTaskOpeningMessage(
      threadId,
      "There's nothing to fix here — the findings I was sent are no longer present in the latest scan. Marking this task complete.",
      [],
    );
    await logSecurityEvent({
      organizationId,
      actorId: userId,
      action: 'aegis_task_accepted',
      targetType: 'aegis_task',
      targetId: taskId,
      metadata: { fixCount: 0, targets: task.targets.length },
    });
    return { threadId };
  }

  // 5. Create all the fix ROWS instantly (status 'planning', no plan yet) and
  //    file the Aegis chip per target. This is FAST — no LLM calls — so the
  //    accept request returns in well under a second.
  const pending: Array<{ fixId: string; target: AegisTaskTarget; findingId: string }> = [];
  for (const { target, findingId } of resolved) {
    const ins = await insertFixRow({
      organizationId,
      projectId: target.projectId,
      findingType: target.findingType,
      findingId,
      triggeredByUserId: userId,
      threadId,
      taskId,
      payloadSource: 'aegis_task',
    });
    if ('fixId' in ins) pending.push({ fixId: ins.fixId, target, findingId });

    // File an 'aegis' tracker link so the finding shows the Aegis chip. The
    // rollup trigger flips it to ✓ when the task resolves cleanly.
    await supabase
      .from('finding_tracker_links')
      .upsert(
        {
          organization_id: organizationId,
          project_id: target.projectId,
          finding_type: target.findingType,
          finding_key: target.findingKey,
          provider: 'aegis',
          external_id: taskId,
          external_url: `/organizations/${organizationId}/aegis/${threadId}`,
          external_state: 'open',
          title: task.title,
          created_by: userId,
        },
        { onConflict: 'project_id,finding_type,finding_key,provider' },
      )
      .then(undefined, (e: any) =>
        console.error('[aegis-task] tracker link upsert failed:', e?.message),
      );
  }

  // Correct total_fixes to the rows actually created (an insert failure would
  // otherwise wedge the task at 'working' forever — v_total < v_planned).
  await supabase.from('aegis_agent_tasks').update({ total_fixes: pending.length }).eq('id', taskId);

  // 6. Seed the task-chat NOW (before any slow plan-gen): Aegis's opening turn +
  //    a live card per fix. The cards render as 'planning' and fill in as plans
  //    generate in the background below.
  const n = pending.length;
  const skipped = resolved.length - n;
  const opening =
    `On it — I'm fixing ${n} ${n === 1 ? 'finding' : 'findings'} and will open ` +
    `${n === 1 ? 'a draft PR' : 'draft PRs'} for ${n === 1 ? 'it' : 'each'}. ` +
    `You can watch each one below; I'll only stop to ask if something blocks me.` +
    (skipped > 0 ? ` (${skipped} target${skipped === 1 ? '' : 's'} were no longer present and were skipped.)` : '');
  await postTaskOpeningMessage(threadId, opening, pending.map((p) => p.fixId));

  await logSecurityEvent({
    organizationId,
    actorId: userId,
    action: 'aegis_task_accepted',
    targetType: 'aegis_task',
    targetId: taskId,
    metadata: { fixCount: n, targets: task.targets.length },
  });

  // 7. Generate plans + auto-approve + start the worker IN THE BACKGROUND so the
  //    accept request returns immediately. Sequential to respect the AI
  //    concurrency limit; each card live-updates as its plan lands. (The backend
  //    is a long-running server — same pattern as the billing setImmediate work.)
  void (async () => {
    for (const p of pending) {
      try {
        await planAndApproveFix({
          fixId: p.fixId,
          organizationId,
          projectId: p.target.projectId,
          findingType: p.target.findingType,
          findingId: p.findingId,
          triggeredByUserId: userId,
          autoApprove: true,
        });
      } catch (e: any) {
        console.error('[aegis-task] background plan/approve failed', p.fixId, e?.message);
      }
    }
  })();

  return { threadId };
}

/** Decline a `proposed` task. */
export async function declineTask(args: {
  taskId: string;
  userId: string;
  organizationId: string;
}): Promise<void> {
  const { taskId, userId, organizationId } = args;
  const { data: row } = await supabase
    .from('aegis_agent_tasks')
    .select('id, organization_id, status')
    .eq('id', taskId)
    .maybeSingle();
  if (!row) throw new Error('Task not found');
  if (row.organization_id !== organizationId) throw new Error('Task not in current organization');
  if (row.status !== 'proposed') {
    throw new Error(`Task is in status '${row.status}' and cannot be declined`);
  }
  await supabase
    .from('aegis_agent_tasks')
    .update({ status: 'declined', updated_at: new Date().toISOString() })
    .eq('id', taskId);
  await logSecurityEvent({
    organizationId,
    actorId: userId,
    action: 'aegis_task_declined',
    targetType: 'aegis_task',
    targetId: taskId,
  });
}

/** The sidebar pile: newest first, tenant-scoped. */
export async function listTasks(
  orgId: string,
  opts: { limit?: number; offset?: number } = {},
): Promise<AegisTask[]> {
  const limit = Math.min(opts.limit ?? 50, 100);
  const offset = opts.offset ?? 0;
  const { data, error } = await supabase
    .from('aegis_agent_tasks')
    .select(TASK_COLUMNS)
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);
  if (error) throw new Error(error.message);
  return (data ?? []).map(shapeTask);
}

/** A single task, asserting it belongs to the caller's org. */
export async function getTask(taskId: string, orgId: string): Promise<AegisTask | null> {
  const { data } = await supabase
    .from('aegis_agent_tasks')
    .select(TASK_COLUMNS)
    .eq('id', taskId)
    .eq('organization_id', orgId)
    .maybeSingle();
  return data ? shapeTask(data) : null;
}

/**
 * Dedup helper for Send-to-Aegis: is there already an open (non-terminal) task
 * or an active 'aegis' tracker link for this finding? Returns the task to
 * attach to, or null.
 */
export async function findOpenTaskForFinding(args: {
  orgId: string;
  projectId: string;
  findingType: string;
  findingKey: string;
  findingHandle?: string;
}): Promise<{ taskId: string; threadId: string | null } | null> {
  const { orgId, projectId, findingType, findingKey, findingHandle } = args;

  // semgrep / secret finding_key is per-RULE (shared across locations), so dedup
  // those on the location handle; vulnerability finding_key is location-unique.
  const locationKeyed = (findingType === 'semgrep' || findingType === 'secret') && !!findingHandle;
  const targetMatch = locationKeyed ? { findingType, findingHandle } : { findingType, findingKey };

  // 1. A non-terminal task already targeting this finding — catches a
  //    finding-door task that's still 'proposed' (no tracker link yet) as well
  //    as a 'working' one. targets is JSONB; @> matches array elements that
  //    contain these keys.
  const { data: openTasks } = await supabase
    .from('aegis_agent_tasks')
    .select('id, thread_id')
    .eq('organization_id', orgId)
    .eq('project_id', projectId)
    .in('status', ['proposed', 'working', 'needs_input'])
    .contains('targets', [targetMatch])
    .order('created_at', { ascending: false })
    .limit(1);
  if (openTasks && openTasks.length > 0) {
    return { taskId: openTasks[0].id as string, threadId: (openTasks[0].thread_id as string) ?? null };
  }

  // 2. The aegis tracker link is keyed by finding_key, which is per-rule for
  //    semgrep/secret — so it would over-match distinct locations. Only trust it
  //    for vulnerabilities (location-unique finding_key).
  if (locationKeyed) return null;
  const { data: link } = await supabase
    .from('finding_tracker_links')
    .select('external_id, external_state')
    .eq('project_id', projectId)
    .eq('finding_type', findingType)
    .eq('finding_key', findingKey)
    .eq('provider', 'aegis')
    .maybeSingle();
  if (link?.external_id) {
    const { data: task } = await supabase
      .from('aegis_agent_tasks')
      .select('id, thread_id, status')
      .eq('id', link.external_id)
      .eq('organization_id', orgId)
      .maybeSingle();
    // Re-delegate only if the prior task is gone or terminal-failed; an active
    // or clean-done task already owns this finding.
    if (
      task &&
      !['declined', 'failed', 'cancelled'].includes(task.status as string)
    ) {
      return { taskId: task.id as string, threadId: (task.thread_id as string) ?? null };
    }
  }
  return null;
}
