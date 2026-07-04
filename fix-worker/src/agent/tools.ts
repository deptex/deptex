import { tool } from 'ai';
import { z } from 'zod';
import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { spawn } from 'child_process';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { LanguageModel } from 'ai';
import type { FindingType, FixPlan } from './../plan-types';
import { commitAndPushFix, openPullRequest } from './../pr';
import { markCompleted, markFailed, markAnswered, isJobCancelled } from './../job-db';
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
export type FinishCategory = 'not_fixable' | 'budget_exhausted' | 'cancelled' | 'system_error';

/** Mutable run state shared between the tools and the loop's terminal fallback. */
export interface AgentRunState {
  /** A draft PR was opened + the row marked completed. */
  prOpened: boolean;
  /** A terminal DB write (markCompleted / markFailed) already ran. */
  terminal: boolean;
  /** Count of side-effecting tool calls, for stall detection. */
  progressCalls: number;
  /** Repo-relative paths already shown live as a write_file diff (dedupe at PR time). */
  editedFiles: Set<string>;
  /** Tool steps queued during a model step, flushed by the loop AFTER that step's
   *  reasoning text — so the narration reads "let me do X" → X, not X → "let me do
   *  X" (tools run before the loop's onStepFinish). */
  pendingSteps: TaskStep[];
  /** Deferred non-step narrations (the PR-ready card), flushed AFTER pendingSteps
   *  so the card lands last: reasoning text → step rows → PR card. */
  pendingAfter: Array<() => Promise<void>>;
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
  /** Non-null when this is a resume amending a still-open prior PR: the clone
   *  is that PR's head branch, and open_pull_request pushes an update to it. */
  resumeMode: { prNumber: number; prUrl: string; branch: string } | null;
  /** row.run_seq — 0 = first run; >0 suffixes the create-mode branch name. */
  runSeq: number;
  /** plan.prior_status — lets a Stop of a resume-of-completed restore the
   *  original success instead of downgrading it to failed. */
  resumePriorStatus: string | null;
}

/**
 * Resolve a tool path against the project directory (so a monorepo agent's
 * `package.json` means the project's manifest, matching where run_command runs),
 * while still confining to the clone root — no traversal out of the repository.
 */
function resolveWithin(
  resolveRoot: string,
  confineRoot: string,
  relPath: string,
): { ok: true; full: string } | { ok: false; error: string } {
  const full = path.resolve(resolveRoot, relPath);
  if (full !== confineRoot && !full.startsWith(confineRoot + path.sep)) {
    return { ok: false, error: 'path is outside the repository' };
  }
  return { ok: true, full };
}

/** Repo-root-relative POSIX path for git pathspecs. */
function toGitPath(repoRoot: string, full: string): string {
  return path.relative(repoRoot, full).split(path.sep).join('/');
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

/**
 * A unified diff of old→new content, computed by comparing the two strings
 * directly (git diff --no-index on temp files) — independent of the repo's
 * index/staging/tracking state, which plain `git diff` is not.
 */
async function computeContentDiff(
  gitRel: string,
  oldStr: string,
  newStr: string,
  token: string,
): Promise<string | undefined> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'aegis-diff-'));
  try {
    const a = path.join(dir, 'a');
    const b = path.join(dir, 'b');
    await fsp.writeFile(a, oldStr);
    await fsp.writeFile(b, newStr);
    // --no-index compares two files with no repo involvement; it exits 1 when they
    // differ, so tolerate the non-zero exit.
    const { output } = await runShell(
      `git diff --no-index --no-color -- ${JSON.stringify(a)} ${JSON.stringify(b)} || true`,
      dir,
    );
    // Rewrite the temp paths in the header to the real repo-relative path.
    const rewritten = output
      .split('\n')
      .map((line) => {
        if (line.startsWith('diff --git ')) return `diff --git a/${gitRel} b/${gitRel}`;
        if (line.startsWith('--- ')) return line.includes('/dev/null') ? line : `--- a/${gitRel}`;
        if (line.startsWith('+++ ')) return line.includes('/dev/null') ? line : `+++ b/${gitRel}`;
        return line;
      })
      .join('\n');
    const trimmed = scrubSecrets(rewritten, token).trim();
    return trimmed ? trimmed.slice(0, 6000) : undefined;
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** Split a multi-file `git diff` into per-file { path, diff } sections. */
function splitDiffByFile(unified: string): Array<{ path: string; diff: string }> {
  const files: Array<{ path: string; diff: string }> = [];
  for (const part of unified.split(/\n(?=diff --git )/)) {
    if (!part.startsWith('diff --git ')) continue;
    const m = part.match(/^\+\+\+ b\/(.+)$/m) ?? part.match(/^diff --git a\/(.+?) b\//);
    files.push({ path: (m?.[1] ?? 'file').trim(), diff: part });
  }
  return files;
}

/** Generated lockfiles — mechanical, huge, and not worth a diff card. */
function isNoisyFile(p: string): boolean {
  return /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|poetry\.lock|Gemfile\.lock)$/.test(p);
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
  // Every tool step is QUEUED and flushed by the loop right after the model's
  // reasoning text for that step, so narration reads "let me do X" → X, not
  // X → "let me do X" (tools run before the loop's onStepFinish). The PR-ready
  // card is queued separately (pendingAfter) so it lands after the step rows.
  const step = (s: TaskStep): Promise<void> => {
    state.pendingSteps.push(s);
    return Promise.resolve();
  };
  const redactDiffs = fixType === 'secret';

  const read_file = tool({
    description: 'Read a UTF-8 text file from the repository (relative path). Returns file contents.',
    inputSchema: z.object({ path: z.string().describe('repo-relative file path') }),
    execute: async ({ path: rel }) => {
      const r = resolveWithin(projectDir, repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        const stat = await fsp.stat(r.full);
        if (stat.isDirectory()) return 'path is a directory (use list_dir)';
        const raw = await fsp.readFile(r.full, 'utf-8');
        // Narrate the read so the investigation is visible in the timeline (the
        // agent's "let me look at X" isn't left as an unbacked claim). Read-only,
        // so it doesn't count toward progress (stall detection stays honest).
        await step({ icon: 'read', label: `Read ${rel}` });
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
      const r = resolveWithin(projectDir, repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        const entries = await fsp.readdir(r.full, { withFileTypes: true });
        const lines = entries
          .filter((e) => e.name !== 'node_modules' && e.name !== '.git')
          .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
          .sort();
        await step({ icon: 'read', label: `Listed ${rel === '.' ? 'the project directory' : rel}` });
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
        projectDir,
      );
      const lines = output.split('\n').filter(Boolean);
      const n = lines.length;
      await step({
        icon: 'search',
        label: `Searched for "${pattern}"${n ? ` — ${n} match${n === 1 ? '' : 'es'}` : ' — no matches'}`,
      });
      if (!lines.length) return 'no matches';
      const shown = lines.slice(0, MAX_GREP_LINES).join('\n');
      return lines.length > MAX_GREP_LINES ? `${shown}\n... [${lines.length - MAX_GREP_LINES} more matches]` : shown;
    },
  });

  const write_file = tool({
    description:
      "Create a NEW file, or replace a file wholesale, by providing its FULL contents. To edit an existing file, prefer str_replace — write_file forces you to reproduce the entire file, which is slower and more error-prone.",
    inputSchema: z.object({
      path: z.string().describe('repo-relative file path'),
      content: z.string().describe('the complete new file contents'),
    }),
    execute: async ({ path: rel, content }) => {
      const r = resolveWithin(projectDir, repoRoot, rel);
      if (!r.ok) return r.error;
      const gitRel = toGitPath(repoRoot, r.full);
      try {
        // Read the current content first so we can diff old→new directly (immune
        // to git index/staging state) and skip a no-op write.
        let oldContent = '';
        try {
          oldContent = await fsp.readFile(r.full, 'utf-8');
        } catch {
          /* new file */
        }
        if (oldContent === content) {
          return `${gitRel} already has exactly that content — nothing to change.`;
        }
        await fsp.mkdir(path.dirname(r.full), { recursive: true });
        await fsp.writeFile(r.full, content, 'utf-8');
        state.progressCalls++;
        state.editedFiles.add(gitRel);
        // Live FileDiffCard. For a secret finding the removed line IS the plaintext
        // credential, so we never render the diff (token-scrub covers command
        // output, not diffs).
        const diff = redactDiffs
          ? undefined
          : await computeContentDiff(gitRel, oldContent, content, deps.installationToken);
        await step({ icon: 'edit', label: `Edited ${gitRel}`, diff });
        return `wrote ${gitRel} (${content.split('\n').length} lines)`;
      } catch (e: any) {
        return `write failed: ${e?.message ?? 'unknown error'}`;
      }
    },
  });

  const str_replace = tool({
    description:
      'Make a small, surgical edit: replace an exact snippet of a file with new text. This is the PREFERRED way to edit — you only provide the changed part, not the whole file. old_string must appear EXACTLY ONCE (include a few surrounding lines to make it unique).',
    inputSchema: z.object({
      path: z.string().describe('repo-relative file path'),
      old_string: z.string().describe('the exact existing text to replace, copied verbatim (whitespace included)'),
      new_string: z.string().describe('the replacement text'),
    }),
    execute: async ({ path: rel, old_string, new_string }) => {
      const r = resolveWithin(projectDir, repoRoot, rel);
      if (!r.ok) return r.error;
      const gitRel = toGitPath(repoRoot, r.full);
      let oldContent: string;
      try {
        oldContent = await fsp.readFile(r.full, 'utf-8');
      } catch {
        return `file not found: ${gitRel}. Use write_file to create a new file.`;
      }
      const idx = oldContent.indexOf(old_string);
      if (idx === -1) {
        return `couldn't find that exact text in ${gitRel}. Read the file again and copy the snippet verbatim (including indentation).`;
      }
      if (oldContent.indexOf(old_string, idx + old_string.length) !== -1) {
        return `that text appears more than once in ${gitRel} — add more surrounding context so it matches exactly one place.`;
      }
      const newContent = oldContent.slice(0, idx) + new_string + oldContent.slice(idx + old_string.length);
      if (newContent === oldContent) return `${gitRel} is unchanged (old and new are identical).`;
      await fsp.writeFile(r.full, newContent, 'utf-8');
      state.progressCalls++;
      state.editedFiles.add(gitRel);
      const diff = redactDiffs
        ? undefined
        : await computeContentDiff(gitRel, oldContent, newContent, deps.installationToken);
      await step({ icon: 'edit', label: `Edited ${gitRel}`, diff });
      return `edited ${gitRel}`;
    },
  });

  const run_command = tool({
    description:
      'Run a shell command (install, build, test, lint, git). It ALREADY runs in the project directory — do NOT cd into it. Use it to verify your work, NOT to edit files. Returns exit code + combined stdout/stderr.',
    inputSchema: z.object({
      description: z
        .string()
        .describe(
          'a short, human-readable title for what this command does, written for the user to read (e.g. "Regenerate the lockfile", "Type-check the project"). NOT the command itself.',
        ),
      command: z.string().describe('the shell command to run'),
    }),
    execute: async ({ description, command }) => {
      state.progressCalls++;
      const { code, output } = await runShell(command, projectDir);
      const scrubbed = cap(scrubSecrets(output, deps.installationToken));
      await step({ icon: 'verify', label: description?.trim() || command, command, output: scrubbed });
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
        // SKIPPED on an edit-free amend: an answer-only turn that wrongly calls
        // open_pull_request must stay a true noChanges — the regen would dirty
        // the lockfile and push a pointless commit.
        if (
          deps.fixType === 'vulnerability' &&
          fs.existsSync(path.join(projectDir, 'package.json')) &&
          !(deps.resumeMode && state.editedFiles.size === 0)
        ) {
          const { output } = await runShell('npm install --package-lock-only --ignore-scripts', projectDir);
          await deps.logger.info('setup', `Regenerated lockfile before PR:\n${cap(output)}`);
        }

        // Authoritative change set: whatever actually changed (write_file, sed,
        // npm, …), rendered as FileDiffCard(s) — the reliable "here's what I
        // changed", independent of HOW the agent edited. Skip files already shown
        // live and skip generated lockfiles. Best-effort; the PR still opens.
        try {
          await runShell('git add -A', repoRoot);
          const { output: fullDiff } = await runShell('git diff --cached --no-color', repoRoot);
          for (const f of splitDiffByFile(fullDiff)) {
            if (isNoisyFile(f.path) || state.editedFiles.has(f.path)) continue;
            const shown =
              deps.fixType === 'secret'
                ? undefined
                : scrubSecrets(f.diff, deps.installationToken).slice(0, 6000);
            await step({ icon: 'edit', label: `Changed ${f.path}`, diff: shown });
          }
        } catch {
          /* change-set narration is best-effort */
        }

        // AMEND (resume with a still-open prior PR): push a fast-forward commit
        // to the SAME branch/PR — never a second PR.
        if (deps.resumeMode) {
          const { diffSummary, pushOutput, noChanges } = await commitAndPushFix({
            workDir: repoRoot,
            fixId: deps.fixId,
            plan,
            installationToken: deps.installationToken,
            repoFullName: deps.repoFullName,
            baseBranch: deps.baseBranch,
            logger: deps.logger,
            mode: 'amend',
            existingBranch: deps.resumeMode.branch,
          });
          if (noChanges) {
            // Not terminal — the agent can still answer and finish_task.
            return 'no new changes to push — the pull request already reflects the current state';
          }
          // Re-check the lease immediately before the terminal write.
          if (!(await leaseHeld(deps))) return 'this task was reassigned mid-push; not marking complete';

          // Re-stamp the EXISTING PR (same number/url/branch, fresh diff
          // summary). Machine-fenced: a zombie run must not clobber a reclaim.
          await markCompleted(
            supabase,
            deps.fixId,
            {
              prUrl: deps.resumeMode.prUrl,
              prNumber: deps.resumeMode.prNumber,
              prBranch: deps.resumeMode.branch,
              prRepoFullName: deps.repoFullName,
              diffSummary,
            },
            deps.machineId,
          );
          await step({
            icon: 'pr',
            label: `Updated pull request #${deps.resumeMode.prNumber}`,
            command: `git push origin ${deps.resumeMode.branch}`,
            output: scrubSecrets(pushOutput, deps.installationToken),
          });
          // Do NOT queue postPrReadyCard: the run-1 card already live-renders
          // from this fixId — a second card would duplicate.
          await markTaskFromFix(supabase, deps.taskId, { status: 'completed', summary: title });
          state.prOpened = true;
          state.terminal = true;
          return `Pushed an update to pull request #${deps.resumeMode.prNumber}. Call finish_task with status "completed" to end.`;
        }

        const { prBranch, diffSummary, pushOutput } = await commitAndPushFix({
          workDir: repoRoot,
          fixId: deps.fixId,
          plan,
          installationToken: deps.installationToken,
          repoFullName: deps.repoFullName,
          baseBranch: deps.baseBranch,
          logger: deps.logger,
          // A resume that must open a NEW PR reuses the same fix row → same
          // deterministic branch name → the old remote branch may survive a
          // merge/close → non-fast-forward rejection. Suffix per run.
          branchSuffix: deps.runSeq > 0 ? `-r${deps.runSeq}` : undefined,
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

        await markCompleted(
          supabase,
          deps.fixId,
          {
            prUrl: pr.prUrl,
            prNumber: pr.prNumber,
            prBranch: pr.prBranch,
            prRepoFullName: pr.prRepoFullName,
            diffSummary,
          },
          deps.machineId,
        );
        await step({
          icon: 'pr',
          label: `Opened pull request #${pr.prNumber}`,
          command: `git push origin ${prBranch}`,
          output: scrubSecrets(pushOutput, deps.installationToken),
        });
        // Defer the PR-ready card so it flushes after the step rows (text → steps → card).
        state.pendingAfter.push(() => postPrReadyCard(supabase, threadId, deps.fixId));
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
        if (deps.resumeMode) {
          // Answer-only resume on a still-open PR: a legit completion — the
          // prior PR already stands. markAnswered preserves pr_*/diff_summary.
          await markAnswered(supabase, deps.fixId, deps.machineId);
          await markTaskFromFix(supabase, deps.taskId, { status: 'completed', summary });
          state.terminal = true;
          return 'task completed — the existing pull request stands';
        }
        if (deps.resumePriorStatus === 'completed' && !state.prOpened) {
          // The prior run genuinely SUCCEEDED but its PR is merged/closed (so
          // no resumeMode). An answer-only turn must NOT downgrade the task to
          // failed — the original fix already stands.
          await markAnswered(supabase, deps.fixId, deps.machineId);
          await markTaskFromFix(supabase, deps.taskId, { status: 'completed', summary });
          state.terminal = true;
          return 'task completed — the original fix already stands';
        }
        // "completed" without a PR (and no standing PR) is not a real success —
        // record it honestly.
        await finalizeFailure(deps, 'not_fixable', summary || 'The agent finished without opening a pull request.');
        return 'no pull request was opened, so this was recorded as unresolved';
      }
      await finalizeFailure(deps, category ?? 'not_fixable', summary || 'The finding could not be fixed automatically.');
      return 'task ended';
    },
  });

  return { read_file, list_dir, grep, str_replace, write_file, run_command, open_pull_request, finish_task };
}

/** The single terminal-failure writer: markFailed + honest FixFailureCard + task rollup. */
export async function finalizeFailure(deps: AgentToolDeps, category: FinishCategory, message: string): Promise<void> {
  if (deps.state.terminal) return;

  // ANY failure of a resume-of-completed (Stop, not_fixable, budget, system
  // error) must RESTORE the original success, not downgrade it: the rollup
  // counts 'rejected'/'failed' rows as failures and would silently flip a
  // genuinely-completed task to failed. This also covers the merged/closed-PR
  // resume (resumeMode null) — the fix already landed. No failure card, no
  // failed step — the earlier fix still stands.
  if (deps.resumePriorStatus === 'completed' && !deps.state.prOpened) {
    deps.state.terminal = true;
    await markAnswered(deps.supabase, deps.fixId, deps.machineId);
    await markTaskFromFix(deps.supabase, deps.taskId, { status: 'completed' });
    try {
      const { makeTaskNarrator } = await import('./../task-chat');
      // Never leak a raw provider message (system_error) into the chat.
      const safeMessage =
        category === 'system_error' ? 'I hit a temporary problem on my side.' : message;
      const line =
        category === 'cancelled'
          ? 'Understood — stopping. The pull request I opened earlier still stands.'
          : `I couldn't complete that follow-up — ${safeMessage} The fix I made earlier still stands.`;
      await makeTaskNarrator(deps.supabase, deps.threadId)(line);
    } catch {
      /* narration is best-effort */
    }
    return;
  }

  deps.state.terminal = true;

  // Build the user-facing copy per category. Infra/model failures (system_error)
  // must NEVER surface the raw provider message to the user — the raw text stays
  // in the error_message column for our logs, but the card + beat stay generic
  // ("something went wrong"), not "your Anthropic credit balance is too low".
  let headline: string;
  let explanation: string;
  let leadIn: string;
  let stepLabel: string;
  let nextStep: string;
  if (category === 'cancelled') {
    headline = 'Task stopped at your request.';
    explanation = "You stopped this task, so I didn't make any changes.";
    leadIn = 'Understood — stopping here.';
    stepLabel = 'Task cancelled';
    nextStep = "Send me a new task whenever you're ready.";
  } else if (category === 'system_error') {
    headline = 'Something went wrong';
    explanation = "I hit a temporary problem on my side and stopped without making changes — this isn't a problem with your code.";
    leadIn = 'Something went wrong on my end, so I stopped without making any changes.';
    stepLabel = 'Something went wrong';
    nextStep = 'Try running this again in a little while.';
  } else {
    // not_fixable (the agent's own stated reason) / budget_exhausted — safe,
    // first-person copy from describeFailure.
    const failCategory = category === 'budget_exhausted' ? 'budget_wall_clock' : 'not_fixable';
    const copy = describeFailure(failCategory, message, {});
    headline = copy.headline;
    explanation = copy.explanation;
    leadIn = copy.leadIn;
    stepLabel = copy.stepLabel;
    nextStep = copy.nextStep;
  }

  await markFailed(
    deps.supabase,
    deps.fixId,
    message,
    category,
    {
      category,
      headline,
      explanation,
      nextStep,
    },
    deps.machineId,
  );
  await narrateStep(deps.supabase, deps.threadId, { icon: 'failed', label: stepLabel });
  await postFailureCard(deps.supabase, deps.threadId, deps.fixId, nextStep);
  await markTaskFromFix(deps.supabase, deps.taskId, { status: 'failed', summary: headline });
  // Post the lead-in as a prose beat (best-effort — no throw).
  try {
    const { makeTaskNarrator } = await import('./../task-chat');
    await makeTaskNarrator(deps.supabase, deps.threadId)(leadIn);
  } catch {
    /* narration is best-effort */
  }
}
