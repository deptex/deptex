import { tool } from 'ai';
import { z } from 'zod';
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { spawn } from 'child_process';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { LanguageModel } from 'ai';
import type { FindingType, FixPlan } from './../plan-types';
import { commitAndPushFix, openPullRequest } from './../pr';
import { markCompleted, markFailed, isJobCancelled } from './../job-db';
import {
  narrateStep,
  postPrReadyCard,
  postFailureCard,
  describeFailure,
  markTaskFromFix,
  type TaskStep,
} from './../task-chat';
import { FixLogger } from './../logger';

const MAX_FILE_PEEK_BYTES = 32 * 1024;
const MAX_COMMAND_MS = 300_000;
const MAX_OUTPUT_CHARS = 8_000;
const MAX_GREP_LINES = 60;

/**
 * Terminal categories the agent can resolve to. Mirrors the vocabulary
 * `describeFailure` understands so the FixFailureCard reads honestly.
 */
export type FinishCategory = 'not_fixable' | 'budget_exhausted' | 'cancelled';

/** Mutable run state shared between the tools and the loop's terminal fallback. */
export interface AgentRunState {
  /** A draft PR was opened + the row marked completed. */
  prOpened: boolean;
  /** A terminal DB write (markCompleted / markFailed) already ran. */
  terminal: boolean;
  /** Count of side-effecting tool calls, for stall detection. */
  progressCalls: number;
}

export interface AgentToolDeps {
  supabase: SupabaseClient;
  /** The fix-row id — the claimable unit + the billing/rollup key. */
  fixId: string;
  /** This worker's machine id — the lease fence re-reads it before push. */
  machineId: string;
  organizationId: string;
  projectId: string | null;
  threadId: string | null;
  taskId: string | null;
  /** The repo clone root (git ops + file confinement live here). */
  repoRoot: string;
  /** The project subdir where installs/tests run ('' monorepos → repoRoot). */
  projectDir: string;
  installationToken: string;
  repoFullName: string;
  baseBranch: string;
  fixType: FindingType;
  /** The finding this task targets — powers the PR title/branch/body. */
  finding: { type: FindingType; id: string; severity?: string };
  projectName: string;
  logger: FixLogger;
  model: LanguageModel;
  state: AgentRunState;
}

/** Confine a relative path to the clone — no traversal out of repoRoot. */
function resolveWithin(root: string, relPath: string): { ok: true; full: string } | { ok: false; error: string } {
  const full = path.resolve(root, relPath);
  if (full !== root && !full.startsWith(root + path.sep)) {
    return { ok: false, error: 'path is outside the repository' };
  }
  return { ok: true, full };
}

/** Strip the installation token (and Bearer-shaped secrets) from any surfaced output. */
function scrubSecrets(text: string, token: string): string {
  let out = text;
  if (token) out = out.split(token).join('***');
  return out.replace(/(x-access-token:)[^@\s]+/gi, '$1***').replace(/(ghs_|gho_|ghp_)[A-Za-z0-9]+/g, '$1***');
}

function cap(text: string): string {
  return text.length > MAX_OUTPUT_CHARS ? text.slice(0, MAX_OUTPUT_CHARS) + '\n... [truncated]' : text;
}

/** Run a command async (never blocks the event loop → the 60s heartbeat keeps firing). */
function runShell(command: string, cwd: string): Promise<{ code: number; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, { cwd, shell: true, env: process.env });
    let out = '';
    const onData = (b: Buffer) => {
      out += b.toString();
      if (out.length > MAX_OUTPUT_CHARS * 4) out = out.slice(-MAX_OUTPUT_CHARS * 4);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      out += `\n... [command exceeded ${Math.round(MAX_COMMAND_MS / 1000)}s and was killed]`;
    }, MAX_COMMAND_MS);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, output: out });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: -1, output: `${out}\n${err.message}` });
    });
  });
}

/** Re-read the lease before any irreversible write (push / complete). */
async function leaseHeld(deps: AgentToolDeps): Promise<boolean> {
  const { data } = await deps.supabase
    .from('project_security_fixes')
    .select('machine_id, status')
    .eq('id', deps.fixId)
    .single();
  return !!data && data.machine_id === deps.machineId && data.status === 'executing';
}

/** Build a PR-shaped plan for commitAndPushFix/openPullRequest from the agent's title/body. */
function prPlan(deps: AgentToolDeps, title: string, body: string): FixPlan {
  return {
    summary: title,
    finding: { type: deps.finding.type, id: deps.finding.id, severity: deps.finding.severity },
    description: body,
    fileChanges: [],
    testCommand: '',
    language: 'other',
    estimatedDiffSize: 'medium',
    wallClockBudgetSec: 0,
  } as FixPlan;
}

export function buildAgentTools(deps: AgentToolDeps) {
  const { supabase, threadId, repoRoot, projectDir, fixType, state } = deps;
  const step = (s: TaskStep) => narrateStep(supabase, threadId, s);
  const redactDiffs = fixType === 'secret';

  const read_file = tool({
    description: 'Read a UTF-8 text file from the repository (relative path). Returns file contents.',
    inputSchema: z.object({ path: z.string().describe('repo-relative file path') }),
    execute: async ({ path: rel }) => {
      const r = resolveWithin(repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        const stat = await fsp.stat(r.full);
        if (stat.isDirectory()) return 'path is a directory (use list_dir)';
        const raw = await fsp.readFile(r.full, 'utf-8');
        return stat.size > MAX_FILE_PEEK_BYTES ? raw.slice(0, MAX_FILE_PEEK_BYTES) + '\n... [truncated]' : raw;
      } catch (e: any) {
        return e?.code === 'ENOENT' ? 'file not found' : (e?.message ?? 'read failed');
      }
    },
  });

  const list_dir = tool({
    description: 'List the entries of a repository directory (relative path; "." for the repo root).',
    inputSchema: z.object({ path: z.string().describe('repo-relative directory path') }),
    execute: async ({ path: rel }) => {
      const r = resolveWithin(repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        const entries = await fsp.readdir(r.full, { withFileTypes: true });
        const lines = entries
          .filter((e) => e.name !== 'node_modules' && e.name !== '.git')
          .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
          .sort();
        return lines.length ? lines.join('\n') : '(empty directory)';
      } catch (e: any) {
        return e?.code === 'ENOENT' ? 'directory not found' : (e?.message ?? 'list failed');
      }
    },
  });

  const grep = tool({
    description: 'Search the repository for a regex pattern (ripgrep-style). Returns matching file:line results.',
    inputSchema: z.object({
      pattern: z.string().describe('extended regex to search for'),
      glob: z.string().optional().describe('optional path/glob filter, e.g. "src"'),
    }),
    execute: async ({ pattern, glob }) => {
      const target = glob ? glob : '.';
      const { output } = await runShell(
        `grep -rInE --exclude-dir=node_modules --exclude-dir=.git -- ${JSON.stringify(pattern)} ${JSON.stringify(target)}`,
        repoRoot,
      );
      const lines = output.split('\n').filter(Boolean);
      if (!lines.length) return 'no matches';
      const shown = lines.slice(0, MAX_GREP_LINES).join('\n');
      return lines.length > MAX_GREP_LINES ? `${shown}\n... [${lines.length - MAX_GREP_LINES} more matches]` : shown;
    },
  });

  const write_file = tool({
    description:
      'Write the FULL new contents of a file (creates or overwrites). Use this for every edit — provide the complete file, not a diff.',
    inputSchema: z.object({
      path: z.string().describe('repo-relative file path'),
      content: z.string().describe('the complete new file contents'),
    }),
    execute: async ({ path: rel, content }) => {
      const r = resolveWithin(repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        await fsp.mkdir(path.dirname(r.full), { recursive: true });
        await fsp.writeFile(r.full, content, 'utf-8');
        state.progressCalls++;
        // Surface the working-tree diff for this file as a FileDiffCard. For a
        // secret finding the removed line IS the plaintext credential, so we
        // never render the diff — token-scrub covers command output, not diffs.
        let diff: string | undefined;
        if (!redactDiffs) {
          const { output } = await runShell(`git diff -- ${JSON.stringify(rel)}`, repoRoot);
          const trimmed = scrubSecrets(output, deps.installationToken).trim();
          diff = trimmed ? trimmed.slice(0, 6000) : undefined;
        }
        await step({
          icon: 'edit',
          label: `Edited ${rel}`,
          diff: redactDiffs ? undefined : diff,
        });
        return `wrote ${rel} (${content.split('\n').length} lines)`;
      } catch (e: any) {
        return `write failed: ${e?.message ?? 'unknown error'}`;
      }
    },
  });

  const run_command = tool({
    description:
      'Run a shell command in the project directory (install, build, test, lint, git). Use this to verify your own work. Returns exit code + combined stdout/stderr.',
    inputSchema: z.object({ command: z.string().describe('the shell command to run') }),
    execute: async ({ command }) => {
      state.progressCalls++;
      const { code, output } = await runShell(command, projectDir);
      const scrubbed = cap(scrubSecrets(output, deps.installationToken));
      await step({ icon: 'verify', label: command, command, output: scrubbed });
      return `exit ${code}\n${scrubbed}`;
    },
  });

  const open_pull_request = tool({
    description:
      'Commit all changes and open a draft pull request. Call this once, after you have applied and verified the fix. Ends the task successfully.',
    inputSchema: z.object({
      title: z.string().describe('concise PR title'),
      body: z.string().describe('PR description — what changed and why it fixes the finding'),
    }),
    execute: async ({ title, body }) => {
      // Dup-guard: a crash-after-PR requeue must not open a second PR.
      if (state.prOpened) return 'a pull request was already opened for this task';
      // Lease fence: if recovery requeued this row and another machine claimed
      // it, WE are the loser of the race — become a no-op (no push, no PR).
      if (!(await leaseHeld(deps))) {
        return 'this task was reassigned to another run; stopping without pushing';
      }
      const plan = prPlan(deps, title, body);
      try {
        // Deterministic lockfile guarantee for dep bumps: regenerate so CI's
        // `npm ci` resolves even if the model skipped the install itself.
        if (deps.fixType === 'vulnerability' && fs.existsSync(path.join(projectDir, 'package.json'))) {
          const { output } = await runShell('npm install --package-lock-only --ignore-scripts', projectDir);
          await deps.logger.info('setup', `Regenerated lockfile before PR:\n${cap(output)}`);
        }

        const { prBranch, diffSummary, pushOutput } = await commitAndPushFix({
          workDir: repoRoot,
          fixId: deps.fixId,
          plan,
          installationToken: deps.installationToken,
          repoFullName: deps.repoFullName,
          baseBranch: deps.baseBranch,
          logger: deps.logger,
        });
        const pr = await openPullRequest({
          installationToken: deps.installationToken,
          repoFullName: deps.repoFullName,
          branch: prBranch,
          baseBranch: deps.baseBranch,
          plan,
          diffSummary,
          logger: deps.logger,
        });
        // Re-check the lease immediately before the terminal write.
        if (!(await leaseHeld(deps))) return 'this task was reassigned mid-push; not marking complete';

        await markCompleted(supabase, deps.fixId, {
          prUrl: pr.prUrl,
          prNumber: pr.prNumber,
          prBranch: pr.prBranch,
          prRepoFullName: pr.prRepoFullName,
          diffSummary,
        });
        await step({
          icon: 'pr',
          label: `Opened pull request #${pr.prNumber}`,
          command: `git push origin ${prBranch}`,
          output: scrubSecrets(pushOutput, deps.installationToken),
        });
        await postPrReadyCard(supabase, threadId, deps.fixId);
        await markTaskFromFix(supabase, deps.taskId, { status: 'completed', summary: title });
        state.prOpened = true;
        state.terminal = true;
        return `Opened draft PR #${pr.prNumber}. Call finish_task with status "completed" to end.`;
      } catch (e: any) {
        const msg = e?.message ?? 'failed to open pull request';
        return `couldn't open the pull request: ${msg}. Fix the issue and try again, or call finish_task if it can't be resolved.`;
      }
    },
  });

  const finish_task = tool({
    description:
      'End the task. Use status "completed" ONLY after open_pull_request succeeded. Use status "failed" with a category when the finding cannot be safely fixed.',
    inputSchema: z.object({
      status: z.enum(['completed', 'failed']),
      summary: z.string().describe('one-sentence summary of the outcome'),
      category: z.enum(['not_fixable', 'budget_exhausted', 'cancelled']).optional(),
    }),
    execute: async ({ status, summary, category }) => {
      if (status === 'completed') {
        if (state.prOpened) return 'task completed';
        // "completed" without a PR is not a real success — record it honestly.
        await finalizeFailure(deps, 'not_fixable', summary || 'The agent finished without opening a pull request.');
        return 'no pull request was opened, so this was recorded as unresolved';
      }
      await finalizeFailure(deps, category ?? 'not_fixable', summary || 'The finding could not be fixed automatically.');
      return 'task ended';
    },
  });

  return { read_file, list_dir, grep, write_file, run_command, open_pull_request, finish_task };
}

/** The single terminal-failure writer: markFailed + honest FixFailureCard + task rollup. */
export async function finalizeFailure(deps: AgentToolDeps, category: FinishCategory, message: string): Promise<void> {
  if (deps.state.terminal) return;
  deps.state.terminal = true;
  const failCategory =
    category === 'budget_exhausted' ? 'budget_wall_clock' : category === 'cancelled' ? 'not_fixable' : 'not_fixable';
  const copy = describeFailure(failCategory, message, {});
  const headline = category === 'cancelled' ? 'Task stopped at your request.' : copy.headline;
  const leadIn = category === 'cancelled' ? 'Understood — stopping here.' : copy.leadIn;
  const stepLabel = category === 'cancelled' ? 'Task cancelled' : copy.stepLabel;

  await markFailed(deps.supabase, deps.fixId, message, category, {
    category,
    headline,
    explanation: copy.explanation,
    nextStep: copy.nextStep,
  });
  await narrateStep(deps.supabase, deps.threadId, { icon: 'failed', label: stepLabel });
  await postFailureCard(deps.supabase, deps.threadId, deps.fixId, copy.nextStep);
  await markTaskFromFix(deps.supabase, deps.taskId, { status: 'failed', summary: headline });
  // Post the honest lead-in as a prose beat (best-effort — no throw).
  try {
    const { makeTaskNarrator } = await import('./../task-chat');
    await makeTaskNarrator(deps.supabase, deps.threadId)(leadIn);
  } catch {
    /* narration is best-effort */
  }
}
