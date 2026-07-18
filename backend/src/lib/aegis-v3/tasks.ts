import crypto from 'crypto';
import semver from 'semver';
import { supabase } from '../supabase';
import { getActiveExtractionId } from '../active-extraction';
import { logSecurityEvent } from '../security-audit';
import { captureInfraError } from '../observability/capture';
import { insertAgentFixRow } from './fix-request';
import { saveUserMessage } from './persistence';
import { startFixMachine } from '../fly-machines';
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

export async function resolveTargetFindingId(target: AegisTaskTarget): Promise<string | null> {
  // DAST is endpoint-centric (keyed by dast_run_id, not extraction_run_id), so
  // it resolves independent of the active extraction run. findingHandle/Key
  // carries the dast finding row id.
  if (target.findingType === 'dast') {
    const dastId = target.findingHandle || target.findingKey;
    const { data } = await supabase
      .from('project_dast_findings')
      .select('id')
      .eq('project_id', target.projectId)
      .eq('id', dastId)
      .maybeSingle();
    return (data as any)?.id ?? null;
  }

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

  if (target.findingType === 'container') {
    // Container CVEs aren't location-based; finding_key is per (image,pkg,cve).
    const { data } = await supabase
      .from('project_container_findings')
      .select('id')
      .eq('project_id', target.projectId)
      .eq('finding_key', target.findingKey)
      .eq('extraction_run_id', activeRun)
      .order('depscore', { ascending: false, nullsFirst: false })
      .limit(1)
      .maybeSingle();
    return (data as any)?.id ?? null;
  }

  if (target.findingType === 'base_image') {
    // One recommendation per Dockerfile per run; findingKey = dockerfile_path (stable).
    const { data } = await supabase
      .from('project_base_image_recommendations')
      .select('id')
      .eq('project_id', target.projectId)
      .eq('dockerfile_path', target.findingKey)
      .eq('extraction_run_id', activeRun)
      .limit(1)
      .maybeSingle();
    return (data as any)?.id ?? null;
  }

  if (target.findingType === 'dataflow') {
    // findingKey = flow_signature_hash (stable across rescans, per taint flow).
    const { data } = await supabase
      .from('project_reachable_flows')
      .select('id')
      .eq('project_id', target.projectId)
      .eq('flow_signature_hash', target.findingKey)
      .eq('extraction_run_id', activeRun)
      .limit(1)
      .maybeSingle();
    return (data as any)?.id ?? null;
  }

  // semgrep / secret / iac: resolve by LOCATION (findingHandle = `file:line`),
  // because their finding_key is per-rule (shared across all occurrences).
  // Falling back to finding_key would collapse N distinct findings to one row.
  const table =
    target.findingType === 'semgrep'
      ? 'project_semgrep_findings'
      : target.findingType === 'iac'
        ? 'project_iac_findings'
        : 'project_secret_findings';
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
      if ((data as any)?.id) return (data as any).id;
      // Location miss — DON'T bail to "nothing to fix". Whole-file findings
      // (start_line NULL: Dockerfile-level iac rules) never match a numeric
      // line, and a rescan can drift a line by a few rows. The finding_key
      // fallback below may collapse N occurrences to one, but resolving SOME
      // open occurrence beats falsely completing the task.
    }
  }
  // Fallback (no or unresolvable location handle): resolve by finding_key.
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

// finding_tracker_links.finding_type has a fixed CHECK constraint that predates
// the phase69 fix types. It already lists iac / container / dast / taint_flow /
// malicious, but NOT the two fix-type names we coined — so map those onto the
// closest allowed value at the tracker boundary (write AND read):
// dataflow -> 'taint_flow', base_image -> 'container'.
export function trackerFindingType(findingType: string): string {
  if (findingType === 'dataflow') return 'taint_flow';
  if (findingType === 'base_image') return 'container';
  return findingType;
}

// Pick the single version to cite from a PDV `fixed_versions text[]` (one
// entry per affected range): the semver-max clears every range. Tolerant of
// non-semver strings (falls back to the first entry).
function pickFixedVersion(fixedVersions: unknown): string | null {
  if (!Array.isArray(fixedVersions)) return null;
  const entries = fixedVersions.filter(
    (v): v is string => typeof v === 'string' && v.trim().length > 0,
  );
  if (entries.length === 0) return null;
  let best = entries[0];
  let bestV = semver.coerce(best);
  for (const entry of entries.slice(1)) {
    const v = semver.coerce(entry);
    if (v && (!bestV || semver.gt(v, bestV))) {
      best = entry;
      bestV = v;
    }
  }
  return best;
}

/**
 * Best-effort dependency-context line for a vulnerability target's finding
 * brief. The live e2e showed the agent burning a run discovering that the
 * vulnerable package was TRANSITIVE by spelunking the lockfile — the brief
 * never told it. Tell it up front (direct vs transitive + the recorded fixed
 * version) at accept time. Returns null on any miss or error: enriching the
 * brief must never block an accept. Exported for tests.
 */
export async function vulnDependencyNote(target: AegisTaskTarget): Promise<string | null> {
  try {
    if (target.findingType !== 'vulnerability') return null;

    // Same active-run scoping resolveTargetFindingId uses; fall back to the
    // newest row if the project has no active run recorded.
    const activeRun = await getActiveExtractionId(supabase, target.projectId);
    let query = supabase
      .from('project_dependency_vulnerabilities')
      .select('project_dependency_id, fixed_versions')
      .eq('project_id', target.projectId)
      .eq('finding_key', target.findingKey);
    if (activeRun) query = query.eq('extraction_run_id', activeRun);
    const { data: vuln } = await query
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (!vuln?.project_dependency_id) return null;

    const { data: dep } = await supabase
      .from('project_dependencies')
      .select('name, version, is_direct')
      .eq('id', vuln.project_dependency_id)
      .maybeSingle();
    if (!dep?.name) return null;

    const fixed = pickFixedVersion((vuln as any).fixed_versions);
    const pkg = `${dep.name}@${dep.version}`;
    if (dep.is_direct === false) {
      return (
        `NOTE: ${pkg} is a TRANSITIVE dependency — it is not listed in the project manifest. ` +
        `The standard fix is an "overrides" (npm) or "resolutions" (yarn) entry in package.json ` +
        `forcing the fixed version${fixed ? ` (>= ${fixed})` : ''}; do not hand-edit the lockfile.`
      );
    }
    return `NOTE: ${pkg} is a direct dependency listed in the project manifest${
      fixed ? `; the fixed version is ${fixed}` : ''
    }.`;
  } catch {
    return null; // best-effort — a brief without the note is still a valid brief
  }
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
 * Seed the task-chat with Aegis's opening turn: a short plain-text narration.
 * The agent then narrates its real tool calls inline as it works — there's no
 * separate clickable "plan" card (a task just runs). Best-effort.
 */
async function postTaskOpeningMessage(threadId: string, text: string): Promise<void> {
  await supabase
    .from('aegis_chat_messages')
    .insert({ thread_id: threadId, role: 'assistant', content: text })
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

  // 0. CONCURRENCY GATE — compare-and-swap the proposed→working flip. A
  //    double-clicked Accept fires two concurrent requests that BOTH pass the
  //    JS status check above; only one wins this atomic flip (0 rows for the
  //    loser, because status is no longer 'proposed'). The loser returns the
  //    existing thread idempotently instead of fanning out a SECOND set of fix
  //    rows / machines / draft PRs. (The partial unique index on agent fix rows
  //    is the last-line backstop if this somehow slips.)
  const nowIso = new Date().toISOString();
  const { data: claimed } = await supabase
    .from('aegis_agent_tasks')
    .update({ status: 'working', accepted_at: nowIso, started_at: nowIso })
    .eq('id', taskId)
    .eq('status', 'proposed')
    .select('id');
  if (!claimed || claimed.length === 0) {
    if (task.threadId) return { threadId: task.threadId };
    // The winner may not have stamped thread_id yet — reload once before giving up.
    const { data: reloaded } = await supabase
      .from('aegis_agent_tasks')
      .select('thread_id')
      .eq('id', taskId)
      .maybeSingle();
    if (reloaded?.thread_id) return { threadId: reloaded.thread_id as string };
    throw new Error('Task is already being accepted');
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

  // 3. Stamp total_fixes + thread_id UP FRONT (before any fix exists) so the
  //    rollup trigger never sees a momentarily-empty fix set as "completed".
  //    (status/accepted_at/started_at were already set by the CAS above.)
  await supabase
    .from('aegis_agent_tasks')
    .update({ thread_id: threadId, total_fixes: resolved.length })
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

  // 5. Create one AGENT fix row per target instantly (strategy='agent',
  //    status='approved', fully stamped with the clone base + sentinel plan) and
  //    file the Aegis chip. This is FAST — no LLM calls — so the accept request
  //    returns in well under a second. Each row is claimed off the existing fix
  //    pool by the worker, which runs the autonomous agent loop; there is no
  //    plan-generation step to background anymore.
  const pending: Array<{ fixId: string; target: AegisTaskTarget; findingId: string }> = [];
  let lastInsertError: string | null = null;
  for (const { target, findingId } of resolved) {
    const summary = task.title;
    // Dependency context (direct vs transitive + fixed version) saves the agent
    // a lockfile-spelunking run; best-effort, null on any miss.
    const depNote = await vulnDependencyNote(target);
    // Cap the brief: task.description is user/AI-authored and otherwise
    // unbounded, and it becomes the agent's first (always-kept) prompt turn —
    // an oversized one would eat the context window before the run starts.
    const findingBrief =
      ([target.label, task.description, depNote].filter(Boolean).join('\n\n') || undefined)?.slice(0, 8000);
    const ins = await insertAgentFixRow({
      organizationId,
      projectId: target.projectId,
      findingType: target.findingType,
      findingId,
      triggeredByUserId: userId,
      threadId,
      taskId,
      summary,
      findingBrief,
    });
    if ('fixId' in ins) pending.push({ fixId: ins.fixId, target, findingId });
    else {
      lastInsertError = ins.error ?? lastInsertError;
      console.error('[aegis-task] agent fix row insert skipped:', target.findingKey, ins.error);
    }

    // File an 'aegis' tracker link so the finding shows the Aegis chip. The
    // rollup trigger flips it to ✓ when the task resolves cleanly.
    await supabase
      .from('finding_tracker_links')
      .upsert(
        {
          organization_id: organizationId,
          project_id: target.projectId,
          finding_type: trackerFindingType(target.findingType),
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

  // Zero-PENDING terminal: we resolved targets to fix but EVERY fix-row insert
  // failed (e.g. the GitHub App was uninstalled between propose and accept, or
  // getBranchSha threw). With no fix row, the rollup trigger never fires, so the
  // task would sit at 'working' forever showing "fixing 0 findings". Fail it
  // honestly instead — the mirror of the zero-RESOLVED terminal above.
  if (pending.length === 0) {
    const detail = lastInsertError ? ` (${lastInsertError})` : '';
    await supabase
      .from('aegis_agent_tasks')
      .update({
        status: 'failed',
        completed_at: new Date().toISOString(),
        summary: 'Could not start the fix — the repository connection may have been removed.',
      })
      .eq('id', taskId);
    await postTaskOpeningMessage(
      threadId,
      `I couldn't set up the fix for this task${detail}. This usually means the GitHub connection was removed. Nothing was changed — reconnect the repository and send it to me again.`,
    );
    await logSecurityEvent({
      organizationId,
      actorId: userId,
      action: 'aegis_task_accepted',
      targetType: 'aegis_task',
      targetId: taskId,
      metadata: { fixCount: 0, targets: task.targets.length, insertFailed: true },
    });
    return { threadId };
  }

  // 6. Seed the task-chat NOW with Aegis's opening turn. The agent narrates its
  //    real work inline as it runs — no plan card.
  const n = pending.length;
  const skipped = resolved.length - n;
  const opening =
    `On it — I'm fixing ${n} ${n === 1 ? 'finding' : 'findings'} and will open ` +
    `${n === 1 ? 'a draft PR' : 'draft PRs'} for ${n === 1 ? 'it' : 'each'}. ` +
    `You can watch each one below; I'll only stop to ask if something blocks me.` +
    (skipped > 0 ? ` (${skipped} target${skipped === 1 ? '' : 's'} were no longer present and were skipped.)` : '');
  await postTaskOpeningMessage(threadId, opening);

  await logSecurityEvent({
    organizationId,
    actorId: userId,
    action: 'aegis_task_accepted',
    targetType: 'aegis_task',
    targetId: taskId,
    metadata: { fixCount: n, targets: task.targets.length },
  });

  // 7. Boot ONE fix-worker machine to claim the queued agent rows. The rows are
  //    already 'approved', so the worker claims + runs them immediately — no
  //    background plan generation. Best-effort: if the boot fails, the
  //    fix-recovery cron surfaces orphaned approved jobs and starts a machine.
  if (pending.length > 0) {
    try {
      await startFixMachine();
    } catch (e: any) {
      console.warn(`[aegis-task] Failed to start fix-worker machine: ${e?.message ?? e}`);
    }
  }

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

/**
 * Stop a running task. Rejects its in-flight agent fix rows — the worker's
 * per-step cancel check (isJobCancelled → status==='rejected') aborts the run to
 * an honest 'cancelled' failure and never pushes; if no worker is live, the
 * rollup trigger rolls the task to failed. Tenant-scoped.
 */
export async function cancelTask(args: {
  taskId: string;
  userId: string;
  organizationId: string;
}): Promise<{ cancelled: number }> {
  const { taskId, userId, organizationId } = args;
  const { data: row } = await supabase
    .from('aegis_agent_tasks')
    .select('id, organization_id')
    .eq('id', taskId)
    .maybeSingle();
  if (!row) throw new Error('Task not found');
  if (row.organization_id !== organizationId) throw new Error('Task not in current organization');

  const { data: candidates } = await supabase
    .from('project_security_fixes')
    .select('id, status, plan')
    .eq('task_id', taskId)
    .eq('strategy', 'agent')
    .in('status', ['planning', 'approved', 'executing']);
  const rows = (candidates ?? []) as Array<{ id: string; status: string; plan: any }>;

  // Stop-restore split: an UNCLAIMED resume of a previously-COMPLETED task
  // (wake_agent_fix stamped plan.resume + plan.prior_status='completed', and no
  // worker has claimed it yet) must NOT be downgraded to 'rejected' — the
  // rollup counts rejected as failed, which would erase the original success.
  // Restore those to 'completed'; the trigger re-completes the task and
  // re-greens the chips. An EXECUTING resume-of-completed still flips to
  // 'rejected' so the worker's per-step cancel check aborts the run — ITS
  // finalizeFailure path restores the prior success.
  const restoreIds = rows
    .filter(
      (r) =>
        r.status !== 'executing' &&
        r.plan?.resume === true &&
        r.plan?.prior_status === 'completed',
    )
    .map((r) => r.id);
  const rejectIds = rows.filter((r) => !restoreIds.includes(r.id)).map((r) => r.id);

  // Both writes re-verify the status they decided on (the old single UPDATE
  // was atomic on `.in('status', ...)`) — a row whose status changed between
  // the SELECT and the UPDATE must not be clobbered: a just-completed row must
  // not flip completed->rejected (erasing a real success), and a restore must
  // not stomp a row a worker just claimed to 'executing'.
  if (restoreIds.length > 0) {
    await supabase
      .from('project_security_fixes')
      .update({ status: 'completed', completed_at: new Date().toISOString() })
      .in('id', restoreIds)
      .in('status', ['planning', 'approved']);
  }
  if (rejectIds.length > 0) {
    await supabase
      .from('project_security_fixes')
      .update({
        status: 'rejected',
        rejected_at: new Date().toISOString(),
        rejected_by_user_id: userId,
      })
      .in('id', rejectIds)
      .in('status', ['planning', 'approved', 'executing']);
  }

  await logSecurityEvent({
    organizationId,
    actorId: userId,
    action: 'aegis_task_cancelled',
    targetType: 'aegis_task',
    targetId: taskId,
    metadata: { cancelled: rejectIds.length, restored: restoreIds.length },
  });
  return { cancelled: rejectIds.length };
}

/**
 * Follow-up message on a task thread: persist the user turn into the task's
 * chat, then idempotently wake the task's agent fix row so the SAME agent
 * resumes (replays the thread, amends its PR). Never routes to the chat agent.
 *
 * Wake semantics live in the `wake_agent_fix` RPC: it resets a TERMINAL
 * ('completed'/'failed'/'rejected') agent row back to 'approved' and does ALL
 * the re-open housekeeping itself (run_seq bump for the billing meter,
 * plan.resume + plan.prior_status stamp, task un-cancel + completed_at reset,
 * aegis tracker chips back to 'open'). It returns NULL when the row is
 * non-terminal — a run is active or already queued — in which case the message
 * just sits in the thread and the worker's end-of-run drain picks it up.
 */
export async function sendTaskFollowup(args: {
  taskId: string;
  userId: string;
  organizationId: string;
  message: string;
}): Promise<{ woke: boolean; queued: boolean; threadId: string }> {
  const { taskId, userId, organizationId, message } = args;

  // 1. Load + authorize the task; it must have a bound thread to message into.
  const { data: row } = await supabase
    .from('aegis_agent_tasks')
    .select('id, organization_id, thread_id, status')
    .eq('id', taskId)
    .maybeSingle();
  if (!row) throw new Error('Task not found');
  if (row.organization_id !== organizationId) throw new Error('Task not in current organization');
  if (!row.thread_id) throw new Error('Task has no chat thread');
  const threadId = row.thread_id as string;

  // 2. Persist the user turn FIRST (same shape as the chat path), so the
  //    message is visible in the thread — and drainable by the worker — even if
  //    everything after this point fails.
  await saveUserMessage({ threadId, userId, content: message });

  let woke = false;
  let queued = false;
  if (row.status === 'proposed') {
    // 3a. Not accepted yet: the finding door pre-creates the thread while the
    //     task is still 'proposed', so the input is live under the Accept card
    //     — but nothing has been fanned out and acceptTask (not this path) is
    //     the consent gate. Don't fall through to the misleading "nothing in
    //     progress" reply below.
    await postTaskOpeningMessage(
      threadId,
      "This task hasn't been accepted yet — accept it and I'll get started. I won't act on messages sent before then.",
    );
  } else {
    // 3b. Resume target: the task's most-recent agent fix row (v1 resumes a
    //     single target; multi-target tasks resume the newest row).
    const { data: fixes } = await supabase
      .from('project_security_fixes')
      .select('id, status')
      .eq('task_id', taskId)
      .eq('strategy', 'agent')
      .order('created_at', { ascending: false })
      .limit(1);
    const target = (fixes ?? [])[0] as { id: string } | undefined;

    if (!target) {
      // Zero-fix task (nothing was ever fanned out): nothing to resume.
      await postTaskOpeningMessage(
        threadId,
        "There's nothing in progress here to continue — start a new task to fix something new.",
      );
    } else {
      // 4. Idempotent wake — a no-op (NULL) while a run is active or queued.
      //    An RPC ERROR must throw, not report queued: the target row is
      //    terminal, so no end-of-run drain (and no recovery pass) would ever
      //    deliver the message — surface a retryable failure to the sender.
      const { data: wokeId, error: wakeError } = await supabase.rpc('wake_agent_fix', {
        p_fix_id: target.id,
      });
      if (wakeError) {
        throw new Error(`Failed to wake the task agent: ${wakeError.message}`);
      }
      if (wokeId) {
        woke = true;
        // 5. Best-effort boot. The row is already 'approved', so if this fails
        //    the fix-recovery cron's orphaned-approved sweep is the boot
        //    backstop (the wake is never lost, just delayed up to one cron
        //    interval).
        try {
          await startFixMachine();
        } catch (e: any) {
          console.warn(`[aegis-task] wake boot failed: ${e?.message ?? e}`);
          captureInfraError(e, 'aegis-task', { phase: 'wake-boot', task_id: taskId, fix_id: target.id });
        }
      } else {
        queued = true;
      }
    }
  }

  await logSecurityEvent({
    organizationId,
    actorId: userId,
    action: 'aegis_task_message',
    targetType: 'aegis_task',
    targetId: taskId,
    metadata: { woke, queued },
  });

  return { woke, queued, threadId };
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

export interface TaskRunStatus {
  taskStatus: string;
  run: {
    fixStatus: string;
    step: number | null;
    contextTokens: number | null;
    contextWindow: number | null;
    contextPct: number | null;
    startedAt: string | null;
    prNumber: number | null;
  } | null;
}

/**
 * The task's live run telemetry for the chat's context meter + /status. Reads
 * the CURRENT agent run (prefer an 'executing' fix row, else the newest) and its
 * agent_run_stats. Returns null only when the task doesn't exist in the org.
 */
export async function getTaskRunStatus(taskId: string, orgId: string): Promise<TaskRunStatus | null> {
  const { data: task } = await supabase
    .from('aegis_agent_tasks')
    .select('id, status')
    .eq('id', taskId)
    .eq('organization_id', orgId)
    .maybeSingle();
  if (!task) return null;

  const { data: rows } = await supabase
    .from('project_security_fixes')
    .select('status, agent_run_stats, started_at, pr_number, created_at')
    .eq('task_id', taskId)
    .eq('strategy', 'agent')
    .order('created_at', { ascending: false })
    .limit(5);
  const list = (rows ?? []) as any[];
  const row = list.find((r) => r.status === 'executing') ?? list[0] ?? null;
  if (!row) return { taskStatus: task.status as string, run: null };

  const stats = (row.agent_run_stats ?? {}) as Record<string, unknown>;
  const tokens = typeof stats.inputTokens === 'number' ? stats.inputTokens : null;
  const window = typeof stats.window === 'number' ? stats.window : null;
  return {
    taskStatus: task.status as string,
    run: {
      fixStatus: row.status as string,
      step: typeof stats.step === 'number' ? stats.step : null,
      contextTokens: tokens,
      contextWindow: window,
      contextPct: tokens != null && window ? Math.min(1, tokens / window) : null,
      startedAt: (row.started_at as string) ?? null,
      prNumber: (row.pr_number as number) ?? null,
    },
  };
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
    .eq('finding_type', trackerFindingType(findingType))
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
