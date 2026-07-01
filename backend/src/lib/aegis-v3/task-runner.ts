import { ToolLoopAgent, stepCountIs, tool, jsonSchema } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { supabase } from '../supabase';
import { getActiveExtractionId } from '../active-extraction';
import { getLanguageModelForOrg } from './provider';
import { ALL_AEGIS_TOOLS } from './tools';
import { buildSDKTool, newTurnState, type AegisToolContext } from './tool-types';
import { ensureTaskThread, resolveTargetFindingId } from './tasks';
import { insertFixRow, planAndApproveFix } from './fix-request';
import type { AegisTaskTarget } from './task-types';

// ---------------------------------------------------------------------------
// Aegis Task Runner — slice 1: NARRATE.
//
// A task is a chat with one goal, driven by an autonomous agent loop. This is
// the loop. It loads the task, runs a ToolLoopAgent with the org's READ-ONLY
// tools (so it genuinely investigates the findings) plus two control tools
// (`apply_fix` / `finish_task`), and persists each narration beat into the
// task's chat thread as it happens — so the user watches Aegis work in real
// time (the task thread realtime-subscribes to aegis_chat_messages).
//
// `apply_fix` is REAL: it routes through the fix pipeline (the deployed
// fix-worker clones the repo, edits the file, verifies, and opens a real PR).
// The chat narrates in the FIRST PERSON — the agent IS the one doing the work,
// there is no separate "worker" it talks about. The PR card (ChangeCard) is the
// live source of truth for completion; the prose never claims the PR is open.
//
// Runtime note: today this runs IN-PROCESS (fine locally; on Vercel the request
// is killed once the loop returns). Slice 2 moves this exact function onto a
// durable Fly machine so the task keeps running after the user leaves — and so
// the narration can stream from the worker's REAL steps instead of intent. The
// runner is written runtime-agnostic — it takes a taskId and runs; slice 2 just
// changes where it's invoked from (Fly entrypoint instead of the dev endpoint).
// ---------------------------------------------------------------------------

interface TaskRow {
  id: string;
  organization_id: string;
  project_id: string | null;
  thread_id: string | null;
  title: string;
  description: string | null;
  targets: AegisTaskTarget[];
  created_by: string;
}

// Persist a text-only narration beat (used for the opening/error beats).
async function postNarration(threadId: string, text: string): Promise<void> {
  const trimmed = text.trim();
  if (!trimmed) return;
  await supabase
    .from('aegis_chat_messages')
    .insert({
      thread_id: threadId,
      role: 'assistant',
      content: trimmed,
      metadata: { parts: [{ type: 'text', text: trimmed }] },
    })
    .then(undefined, (e: any) => console.error('[task-runner] narration insert failed:', e?.message));
}

// Persist one agent STEP's text beat into the task chat. Tool calls themselves
// stay invisible (read tools, finish_task are mechanics); only the model's prose
// shows. The caller gates this off once a fix is in flight, so everything here
// is a pre-fix "thinking" beat.
// Reasoning models (DeepSeek etc.) emit <think>…</think> before their answer.
// Keep only what follows the last </think>; if the block never closed, the beat
// is pure chain-of-thought — drop it rather than show reasoning in the chat.
function stripReasoning(raw: string): string {
  let s = raw ?? '';
  const close = s.lastIndexOf('</think>');
  if (close !== -1) s = s.slice(close + '</think>'.length);
  else if (/<think>/i.test(s)) return '';
  return s.replace(/<\/?think>/gi, '').trim();
}

async function persistBeat(threadId: string, text: string, _toolCalls: any[]): Promise<void> {
  const trimmed = stripReasoning(text ?? '');
  if (!trimmed) return;
  await supabase
    .from('aegis_chat_messages')
    .insert({
      thread_id: threadId,
      role: 'assistant',
      content: trimmed,
      metadata: { parts: [{ type: 'text', text: trimmed }] },
    })
    .then(undefined, (e: any) => console.error('[task-runner] beat insert failed:', e?.message));
}

function describeTargets(targets: AegisTaskTarget[], projectNames: Map<string, string>): string {
  if (!targets.length) return '(no specific findings were attached to this task)';
  return targets
    .map((t, i) => {
      const name = projectNames.get(t.projectId) ?? 'a project';
      const bits = [
        `${i + 1}. ${t.label || t.findingKey}`,
        `type=${t.findingType}`,
        `project="${name}"`,
        `projectId=${t.projectId} (for tool calls only — never say this aloud)`,
      ];
      if (t.osvId) bits.push(`osv=${t.osvId}`);
      if (t.findingHandle) bits.push(`at=${t.findingHandle}`);
      return bits.join('  ');
    })
    .join('\n');
}

function buildTaskInstructions(task: TaskRow, projectNames: Map<string, string>): string {
  return [
    'You are Aegis, an autonomous security engineer. You have been handed ONE task and you do it',
    'yourself, start to finish — investigating the finding, editing the code, running the tests, and',
    'opening the pull request. This chat is your live workspace: you are not answering a person, you',
    'are narrating your OWN work out loud as you do it, in short first-person beats (1–2 sentences).',
    '',
    `# Your task\n${task.title}${task.description ? `\n${task.description}` : ''}`,
    '',
    `# Findings you were assigned\n${describeTargets(task.targets, projectNames)}`,
    '',
    '# Voice — read this twice',
    '- First person, ALWAYS. "I\'m updating package.json", "I\'ll run the tests", "I\'m opening the pull request." You are the one doing every step.',
    '- There is NO "worker", no "agent", no "it", no separate system you hand things off to. Never mention a worker or describe your work in the third person. If you are about to write "the worker", rewrite it as "I".',
    '- Refer to a project by its NAME (e.g. "the Backend project"). NEVER write a raw id, UUID, or finding key in anything you say — those are for tool calls only.',
    '- Speak plainly. No markdown headers, no bullet lists. Do NOT invent a PR number, and do NOT state a specific target version you are not certain of — say "a patched release" unless a tool gave you the exact version (the precise version shows on the pull-request card).',
    '',
    '# The arc — a handful of beats, not an essay',
    '1. A brief "Starting on this" beat that names the goal in your own words.',
    '2. Look at the finding with your read tools, then say what you found.',
    '3. Say what the fix is, concretely — which file, what change.',
    '4. Call `apply_fix` with the `file` you are changing and a one-line `summary`. The moment you call it, the edit, the tests, and the pull request all run and post their OWN first-person progress into this chat as each step happens — so you do NOT narrate those steps yourself.',
    '5. Immediately call `finish_task` with a one-to-two sentence summary of what you set out to do. Do NOT post a closing beat afterwards — the step-by-step and the pull-request card appear on their own.',
    '',
    '# Hard rules after apply_fix',
    '- The edit, the tests, and the pull-request card post THEMSELVES into this chat. You do not write them, you cannot see them, and you must NOT poll, "check the status", claim the tests passed or failed, or say the PR is open. Just call finish_task and stop.',
  ].join('\n');
}

// Build a TRUE, specific task description from the finding itself (package,
// version, project, severity, the CVE summary) — so the detail sidebar reads
// like a real task, not boilerplate about Aegis's process. Vulnerability
// targets only; returns null otherwise (caller keeps whatever's there).
async function buildTaskDescription(target: AegisTaskTarget): Promise<string | null> {
  if (target.findingType !== 'vulnerability' || !target.osvId) return null;
  const run = await getActiveExtractionId(supabase, target.projectId);
  if (!run) return null;
  const { data: v } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('severity, summary, fixed_versions, project_dependency_id')
    .eq('project_id', target.projectId)
    .eq('osv_id', target.osvId)
    .eq('extraction_run_id', run)
    .limit(1)
    .maybeSingle();
  if (!v) return null;

  let pkg = '';
  let version = '';
  if ((v as any).project_dependency_id) {
    const { data: dep } = await supabase
      .from('project_dependencies')
      .select('name, version')
      .eq('id', (v as any).project_dependency_id)
      .maybeSingle();
    pkg = (dep as any)?.name ?? '';
    version = (dep as any)?.version ?? '';
  }
  const { data: proj } = await supabase
    .from('projects')
    .select('name')
    .eq('id', target.projectId)
    .maybeSingle();

  const projName = (proj as any)?.name ?? 'this project';
  const pkgRef = pkg ? `${pkg}${version ? `@${version}` : ''}` : 'the affected dependency';
  const sev = (v as any).severity ? `${String((v as any).severity).toLowerCase()} ` : '';
  const fixedArr = (v as any).fixed_versions;
  const patched =
    Array.isArray(fixedArr) && fixedArr.length
      ? ` to a patched release (${fixedArr[0]})`
      : ' to a patched release';
  const summary = (v as any).summary ? ` ${String((v as any).summary).trim()}` : '';

  // Finding-grounded WHAT + a brief plan (resolve → test → PR), then the CVE
  // detail as its own sentence.
  const out =
    `Upgrade ${pkgRef}${patched} in the ${projName} project to resolve ${target.osvId}, ` +
    `a ${sev}vulnerability, then run the test suite to confirm nothing breaks and open a ` +
    `pull request for review.${summary}`.trim();
  return /[.!?]$/.test(out) ? out : `${out}.`;
}

/**
 * Run the task agent to completion, persisting narration into the task chat.
 * Runtime-agnostic: callable from the dev `/run` endpoint today and a Fly
 * machine entrypoint later. Best-effort — a model/tool failure marks the task
 * `failed` and posts an apologetic beat rather than throwing out.
 */
export async function runTaskAgent(
  taskId: string,
): Promise<{ ok: boolean; threadId?: string; error?: string }> {
  const { data: raw } = await supabase
    .from('aegis_agent_tasks')
    .select('id, organization_id, project_id, thread_id, title, description, targets, created_by, status')
    .eq('id', taskId)
    .maybeSingle();
  if (!raw) return { ok: false, error: 'Task not found' };

  // Backstop against a double-run (a re-dispatch, a double-click): never
  // re-drive a task that already finished — it would apply the fix again.
  if (raw.status === 'completed' || raw.status === 'failed') {
    return { ok: true, threadId: raw.thread_id ?? undefined };
  }

  const task: TaskRow = {
    id: raw.id,
    organization_id: raw.organization_id,
    project_id: raw.project_id ?? null,
    thread_id: raw.thread_id ?? null,
    title: raw.title ?? 'Aegis task',
    description: raw.description ?? null,
    targets: Array.isArray(raw.targets) ? (raw.targets as AegisTaskTarget[]) : [],
    created_by: raw.created_by,
  };

  const orgId = task.organization_id;
  const userId = task.created_by;
  const threadId = await ensureTaskThread(taskId);

  await supabase
    .from('aegis_agent_tasks')
    .update({ status: 'working', started_at: new Date().toISOString() })
    .eq('id', taskId);

  // Give the task a true, finding-grounded description (unless it already has a
  // real one — i.e. not empty, not just the title, not the terse "Fix <label>"
  // the finding-door writes). Single-target for now.
  const existing = task.description?.trim() ?? '';
  const hasRealDescription =
    existing.length > 0 && existing !== task.title.trim() && !existing.startsWith('Fix ');
  if (!hasRealDescription && task.targets.length === 1) {
    const generated = await buildTaskDescription(task.targets[0]);
    if (generated) {
      await supabase.from('aegis_agent_tasks').update({ description: generated }).eq('id', taskId);
      task.description = generated;
    }
  }

  // Resolve project names so the agent narrates by name, never by id/UUID.
  const projectNames = new Map<string, string>();
  const projectIds = Array.from(new Set(task.targets.map((t) => t.projectId).filter(Boolean)));
  if (projectIds.length) {
    const { data: projs } = await supabase.from('projects').select('id, name').in('id', projectIds);
    for (const p of projs ?? []) projectNames.set(p.id as string, p.name as string);
  }

  // Read-only org tools (danger 'safe') so the agent can truly investigate
  // without creating real fixes during a narration run.
  const ctx: AegisToolContext = {
    orgId,
    userId,
    threadId,
    operatingMode: 'propose',
    supabase: supabase as unknown as SupabaseClient,
    turnState: newTurnState(),
  };
  const readOnlyTools = Object.fromEntries(
    ALL_AEGIS_TOOLS.filter((e) => (e.danger ?? 'safe') === 'safe').map((e) => [
      e.name,
      buildSDKTool(e, ctx),
    ]),
  );

  // Control tools. apply_fix routes through the REAL fix pipeline (the deployed
  // fix-worker clones the repo, edits the file, verifies, opens a PR, and
  // narrates each step into this chat); finish_task closes the task out — but
  // only when no fix was started, since a started fix's pipeline owns the
  // terminal status (it flips the task to completed/failed at the end).
  let startedAFix = false;
  const controlTools = {
    apply_fix: tool({
      description:
        'Apply your fix for a finding. This begins the change — editing the file, running the tests, and opening a pull request for review — which completes over the next minute or two. Pass the `file` you are changing and a one-line `summary`, then call finish_task. Call this at most once per finding.',
      inputSchema: jsonSchema({
        type: 'object',
        properties: {
          finding: { type: 'string', minLength: 1, description: 'Which finding you are fixing.' },
          file: {
            type: 'string',
            description: 'The file the patch changes, e.g. "package.json".',
          },
          summary: {
            type: 'string',
            description: 'One line describing the change, e.g. "Bump simple-git 3.30.0 → 3.36.0".',
          },
        },
        required: ['finding'],
        additionalProperties: false,
      }),
      execute: async ({
        finding,
        file,
        summary,
      }: {
        finding: string;
        file?: string;
        summary?: string;
      }) => {
        // Pick the target this call is about (single-target tasks: the one;
        // multi: match the finding text, else the first).
        const f = (finding ?? '').toLowerCase();
        const target =
          task.targets.length === 1
            ? task.targets[0]
            : task.targets.find(
                (t) =>
                  (t.osvId && f.includes(t.osvId.toLowerCase())) ||
                  (t.label && f.includes(t.label.toLowerCase())),
              ) ?? task.targets[0];
        if (!target) return { error: 'No matching finding to fix.' };

        // Resolve the live finding id against the latest scan — works for all
        // three types: vulnerability (osv_id), semgrep / secret (the finding row
        // id, keyed by file:line). Row uuids churn on every rescan, so we never
        // trust a stale one off the task target.
        const findingId = await resolveTargetFindingId(target);
        if (!findingId) {
          return {
            error:
              'I could not find this finding in the latest scan — it may already be resolved or moved.',
          };
        }

        // Kick-off beat — lands immediately, so the ~minute of plan generation
        // that follows doesn't read as dead air before the pipeline's own step
        // beats start. Phrasing is type-aware.
        const projName = projectNames.get(target.projectId) ?? 'the project';
        const kickoff = ((): string => {
          switch (target.findingType) {
            case 'vulnerability':
              return `Working out the exact change for the ${projName} project and a safe version to upgrade to.`;
            case 'base_image':
            case 'container':
              return `Working out which base image to move ${projName} to.`;
            case 'dataflow':
              return `Tracing the data flow for ${target.label} in ${projName} to find where to sanitize it.`;
            case 'dast':
              return `Locating the vulnerable endpoint handler for ${target.label} in ${projName}.`;
            case 'iac':
              return `Working out the infrastructure fix for ${target.label} in ${projName}.`;
            default:
              return `Working out the fix for ${target.label} in the ${projName} project.`;
          }
        })();
        await postNarration(threadId, kickoff);

        const ins = await insertFixRow({
          organizationId: orgId,
          projectId: target.projectId,
          findingType: target.findingType,
          findingId,
          triggeredByUserId: userId,
          threadId,
          taskId,
          payloadSource: 'aegis_task',
        });
        if ('error' in ins) return { error: ins.error };

        // AWAIT plan + auto-approve + start the worker, so the fix-worker machine
        // is booting before this (script) process can exit. The Fly machine then
        // runs the clone/patch/test/PR independently.
        const res = await planAndApproveFix({
          fixId: ins.fixId,
          organizationId: orgId,
          projectId: target.projectId,
          findingType: target.findingType,
          findingId,
          triggeredByUserId: userId,
          autoApprove: true,
        });

        if (res.status === 'approved') startedAFix = true;

        return {
          fixId: ins.fixId,
          status: res.status,
          started: res.status === 'approved',
          file: file ?? null,
          summary: summary ?? null,
          error: res.error ?? null,
        };
      },
    }),
    finish_task: tool({
      description:
        'Close out the task once the fix(es) are done. Marks the task complete with your summary.',
      inputSchema: jsonSchema({
        type: 'object',
        properties: {
          summary: {
            type: 'string',
            minLength: 1,
            description: 'A one-to-two sentence summary of what you did.',
          },
        },
        required: ['summary'],
        additionalProperties: false,
      }),
      execute: async ({ summary }: { summary: string }) => {
        // When a fix is in flight, leave the terminal status to the pipeline —
        // it marks the task completed when the PR opens (or failed if it can't
        // land). Only close the task out here when nothing async will.
        const update: Record<string, unknown> = { summary };
        if (!startedAFix) {
          update.status = 'completed';
          update.completed_at = new Date().toISOString();
        }
        await supabase.from('aegis_agent_tasks').update(update).eq('id', taskId);
        return { finished: true };
      },
    }),
  };

  const model = await getLanguageModelForOrg(orgId);
  const agent = new ToolLoopAgent({
    model,
    instructions: buildTaskInstructions(task, projectNames),
    tools: { ...readOnlyTools, ...controlTools },
    stopWhen: stepCountIs(14),
    maxOutputTokens: 4096,
  });

  try {
    await agent.generate({
      messages: [
        {
          role: 'user',
          content:
            'Begin the task now. Post your opening beat, then work through the arc end to end.',
        },
      ],
      // Persist each thinking beat as it lands — UNTIL a fix is in flight, then
      // the agent goes silent. From that point the fix pipeline narrates every
      // remaining step (editing, verifying, opening the PR) and posts the card,
      // so any further model text ("the fix is applied", "all done") would only
      // duplicate, pre-empt, or contradict it — and interleave with the real
      // beats. startedAFix is already set by the time apply_fix's own step
      // finishes, so this silences that step and everything after it.
      onStepFinish: async ({ text, toolCalls }) => {
        if (startedAFix) return;
        await persistBeat(threadId, text ?? '', toolCalls ?? []);
      },
    });
  } catch (err: any) {
    const msg = err?.message ?? 'unknown error';
    console.error('[task-runner] agent run failed', taskId, msg);
    await postNarration(
      threadId,
      `I ran into a problem and had to stop before finishing: ${msg}.`,
    );
    await supabase
      .from('aegis_agent_tasks')
      .update({ status: 'failed', summary: `Run failed: ${msg}` })
      .eq('id', taskId);
    return { ok: false, threadId, error: msg };
  }

  return { ok: true, threadId };
}
