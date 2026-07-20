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
  describeFailure,
  markTaskFromFix,
  type TaskStep,
} from './../task-chat';
import { FixLogger } from './../logger';
import { scrubString } from './../observability/scrub';

const MAX_FILE_PEEK_BYTES = 32 * 1024;
const MAX_COMMAND_MS = 300_000;
const MAX_OUTPUT_CHARS = 8_000;
const MAX_GREP_LINES = 60;
const MAX_LIST_ENTRIES = 500;

/**
 * Terminal categories the agent can resolve to. Mirrors the vocabulary
 * `describeFailure` understands so the FixFailureCard reads honestly.
 * 'stall' is loop-detected only — it is deliberately NOT in finish_task's
 * schema (the model shouldn't self-report it).
 */
export type FinishCategory =
  | 'not_fixable'
  | 'budget_exhausted'
  | 'context_exhausted'
  | 'cancelled'
  | 'system_error'
  | 'stall';

/** Mutable run state shared between the tools and the loop's terminal fallback. */
export interface AgentRunState {
  /** A draft PR was opened + the row marked completed. */
  prOpened: boolean;
  /** A terminal DB write (markCompleted / markFailed) already ran. */
  terminal: boolean;
  /** Count of side-effecting tool calls, for stall detection. */
  progressCalls: number;
  /** Distinct read-only calls already made (read:/list:/grep: keys) — repeats
   *  of these are the true spin signal; new ones are legitimate investigation. */
  seenCalls: Set<string>;
  /** Count of FIRST-time read-only calls (novelty). The stall detector treats
   *  a step that read/listed/grepped something NEW as progress. */
  novelCalls: number;
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
  // Fast lexical reject (handles ../ and absolute paths).
  if (full !== confineRoot && !full.startsWith(confineRoot + path.sep)) {
    return { ok: false, error: 'path is outside the repository' };
  }
  // Authoritative check: resolve symlinks. A repo can commit a symlink
  // (git mode 120000) pointing at /etc or /proc/self/environ; path.resolve does
  // NOT follow it, but fs.readFile/writeFile would. Realpath the nearest
  // existing ancestor (the target itself may not exist yet on a write) and
  // re-check containment against the realpathed root.
  try {
    const realConfine = fs.realpathSync(confineRoot);
    let probe = full;
    while (!fs.existsSync(probe) && path.dirname(probe) !== probe) probe = path.dirname(probe);
    const realProbe = fs.realpathSync(probe);
    if (realProbe !== realConfine && !realProbe.startsWith(realConfine + path.sep)) {
      return { ok: false, error: 'path is outside the repository' };
    }
  } catch {
    return { ok: false, error: 'could not resolve path' };
  }
  return { ok: true, full };
}

/** Repo-root-relative POSIX path for git pathspecs. */
function toGitPath(repoRoot: string, full: string): string {
  return path.relative(repoRoot, full).split(path.sep).join('/');
}

/**
 * Strip secrets from any string surfaced to the chat OR fed back to the model.
 * Two layers: mask the exact installation token (defeats format drift / partial
 * matches), then the shared pattern scrubber (PEM / JWT / Stripe / GitHub /
 * Google / Anthropic / OpenAI / Bearer) — the same redactor the Sentry pipeline
 * uses. Encoding a secret (base64/hex) still defeats pattern-scrubbing, which is
 * why the PRIMARY control is keeping secrets out of the run_command env
 * (SAFE_ENV below); this is the backstop for anything that slips through.
 */
export function scrubOutput(text: string, token: string): string {
  const masked = token ? text.split(token).join('***') : text;
  return scrubString(masked);
}

// Env keys whose presence in the agent's shell would hand a prompt-injected
// agent the platform's crown jewels (the GitHub App private key mints
// installation tokens for EVERY org; the service-role key is god-mode on the
// DB). Deny-list (not allow-list) so real toolchain vars — PATH, HOME, NODE_*,
// language caches — survive while anything secret-shaped by name is dropped.
const SECRET_ENV_KEY_RE =
  /(secret|token|passwo?rd|api[_-]?key|private[_-]?key|encryption[_-]?key|service[_-]?role|credential|webhook|signing|_key$|^key$)/i;
const SECRET_ENV_PREFIXES = [
  'SUPABASE_', 'GITHUB_', 'FLY_', 'QSTASH_', 'UPSTASH_', 'STRIPE_', 'RESEND_',
  'SENTRY_', 'OPENAI_', 'ANTHROPIC_', 'GOOGLE_', 'GEMINI_', 'DEEPINFRA_',
  'INTERNAL_', 'AI_', 'EMAIL_', 'ADMIN_',
];

/**
 * The environment the agent's shell (and our own local git/npm helpers) run
 * with: process.env minus every secret-shaped var. A prompt-injected
 * `printenv` / `node -e 'console.log(process.env)'` then finds no platform
 * secret to exfiltrate. Computed once — the worker's env is stable.
 */
export function buildSafeEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(source)) {
    if (SECRET_ENV_KEY_RE.test(k)) continue;
    if (SECRET_ENV_PREFIXES.some((p) => k.startsWith(p))) continue;
    out[k] = v;
  }
  return out;
}
const SAFE_ENV = buildSafeEnv();

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
    const trimmed = scrubOutput(rewritten, token).trim();
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

/** npm-family lockfiles we REGENERATE ourselves (`npm install
 *  --package-lock-only`) — mechanical, huge, not worth a diff card. Other
 *  ecosystems' lockfiles (Gemfile.lock, go.sum, …) are only in the change set
 *  because the agent edited them by hand, so they ARE shown. */
function isNoisyFile(p: string): boolean {
  return /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(p);
}

/** Run a command async (never blocks the event loop → the 60s heartbeat keeps firing). */
function runShell(command: string, cwd: string): Promise<{ code: number; output: string }> {
  return new Promise((resolve) => {
    // detached:true (POSIX only — the prod worker is Linux) puts the child in
    // its OWN process group so a timeout can kill the whole tree; a backgrounded
    // grandchild (`nohup curl … &`, a miner) would otherwise be reparented to
    // init and outlive a plain SIGKILL of the shell. On Windows (dev/test)
    // detached breaks stdio-pipe capture and negative-pid signalling is
    // unsupported, so we leave it off there. SAFE_ENV strips every secret-shaped
    // var so a prompt-injected `printenv` has nothing to exfiltrate.
    const posix = process.platform !== 'win32';
    const child = spawn(command, { cwd, shell: true, env: SAFE_ENV, detached: posix });
    let out = '';
    const onData = (b: Buffer) => {
      out += b.toString();
      if (out.length > MAX_OUTPUT_CHARS * 4) out = out.slice(-MAX_OUTPUT_CHARS * 4);
    };
    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);
    const killTree = (signal: NodeJS.Signals) => {
      try {
        if (posix && child.pid) process.kill(-child.pid, signal); // negative pid = the whole group
        else child.kill(signal);
      } catch {
        try {
          child.kill(signal);
        } catch {
          /* already gone */
        }
      }
    };
    const timer = setTimeout(() => {
      killTree('SIGKILL');
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

/**
 * npm quirks (e.g. a "//" comment key inside "overrides") can silently treat
 * the manifest as EMPTY and rewrite the lockfile as a 7-line stub ("up to
 * date, audited 1 package") — valid JSON, catastrophic semantics: committing
 * it breaks `npm ci` on the PR. If the regenerated lockfile shrank
 * implausibly, restore the pre-regen version and keep going (the PR's CI
 * regenerates it). Returns true when it tripped. Never throws — the guard is
 * strictly best-effort protection around a best-effort regen.
 */
export async function revertImplausibleLockfileRegen(
  projectDir: string,
  repoRoot: string,
  beforeBytes: number,
  logger: FixLogger,
): Promise<boolean> {
  try {
    const lockPath = path.join(projectDir, 'package-lock.json');
    let after = 0;
    try {
      after = fs.statSync(lockPath).size;
    } catch {
      after = 0;
    }
    // Trip on: an existing lockfile shrinking to under a tenth of its size, or
    // a suspiciously tiny lockfile appearing where none existed before.
    const implausibleShrink = beforeBytes > 2048 && after < beforeBytes / 10;
    const freshStub = beforeBytes === 0 && after > 0 && after < 1024;
    if (!implausibleShrink && !freshStub) return false;

    if (beforeBytes > 0) {
      // The file came from the clone, so it's tracked — restore it from git.
      const gitRel = toGitPath(repoRoot, lockPath);
      await runShell(`git checkout -- ${JSON.stringify(gitRel)}`, repoRoot);
    } else {
      fs.rmSync(lockPath, { force: true });
    }
    await logger.warn(
      'setup',
      `Lockfile regen produced an implausibly small file (${beforeBytes} -> ${after} bytes) — reverted; the PR CI will regenerate it.`,
    );
    return true;
  } catch {
    return true; // tripped but the restore itself failed — still non-fatal
  }
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
  // Novelty tracking for the read-only tools: a FIRST-time read/list/grep is
  // legitimate investigation and counts as progress for the stall detector;
  // only repeats of calls already made signal a true spin.
  const noteCall = (key: string): void => {
    if (!state.seenCalls.has(key)) {
      state.seenCalls.add(key);
      state.novelCalls++;
    }
  };

  const read_file = tool({
    description: 'Read a UTF-8 text file from the repository (relative path). Returns file contents.',
    inputSchema: z.object({ path: z.string().describe('repo-relative file path') }),
    execute: async ({ path: rel }) => {
      noteCall(`read:${rel}`);
      const r = resolveWithin(projectDir, repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        const stat = await fsp.stat(r.full);
        if (stat.isDirectory()) return 'path is a directory (use list_dir)';
        const raw = await fsp.readFile(r.full, 'utf-8');
        // Narrate the read so the investigation is visible in the timeline (the
        // agent's "let me look at X" isn't left as an unbacked claim). Read-only,
        // so it never bumps progressCalls — but the FIRST read of a path counts
        // as novelty (noteCall above), so real investigation doesn't stall-trip.
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
      noteCall(`list:${rel}`);
      const r = resolveWithin(projectDir, repoRoot, rel);
      if (!r.ok) return r.error;
      try {
        const entries = await fsp.readdir(r.full, { withFileTypes: true });
        const lines = entries
          .filter((e) => e.name !== 'node_modules' && e.name !== '.git')
          .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
          .sort();
        await step({ icon: 'read', label: `Listed ${rel === '.' ? 'the project directory' : rel}` });
        if (!lines.length) return '(empty directory)';
        // Cap a pathologically large directory so one list_dir can't dominate
        // the context window (mirrors grep's cap).
        return lines.length > MAX_LIST_ENTRIES
          ? `${lines.slice(0, MAX_LIST_ENTRIES).join('\n')}\n... [${lines.length - MAX_LIST_ENTRIES} more entries]`
          : lines.join('\n');
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
      noteCall(`grep:${pattern}|${glob ?? ''}`);
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
      const scrubbed = cap(scrubOutput(output, deps.installationToken));
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
        // Deterministic lockfile guarantee: whenever the project's npm manifest
        // or lockfile changed — WHATEVER the finding type; a container fix can
        // add an "overrides" entry too (the PR #20 dogfood catch: fixType-gated
        // regen shipped a manifest override with an untouched lockfile → npm ci
        // EUSAGE) — regenerate so CI resolves even if the model skipped the
        // install itself. "Did the npm files change?" is answered by GIT, not
        // fixType or the editor-tool ledger: the heal-2 incident restored
        // package-lock.json via run_command (`git checkout origin/<base> --
        // <file>`), which left state.editedFiles empty, skipped the regen, and
        // shipped a lockfile out of sync with the manifest's overrides. An
        // edit-free run (answer-only amend) leaves both clean → no regen, so a
        // true noChanges amend is preserved. The regen is idempotent and the
        // plausibility guard below protects its output.
        // (`git status --porcelain` is staging-agnostic, and this runs BEFORE
        // the change-set narration's `git add -A` anyway.)
        let npmFilesDirty = false;
        if (fs.existsSync(path.join(projectDir, 'package.json'))) {
          const { output: porcelain } = await runShell('git status --porcelain', repoRoot);
          const manifestRel = toGitPath(repoRoot, path.join(projectDir, 'package.json'));
          const lockRel = toGitPath(repoRoot, path.join(projectDir, 'package-lock.json'));
          npmFilesDirty = porcelain.split('\n').some((line) => {
            const p = line.slice(3).trim().replace(/^"|"$/g, '');
            return p === manifestRel || p === lockRel;
          });
        }
        if (npmFilesDirty) {
          // Pre-regen size — the plausibility baseline for the guard below.
          let lockBytesBefore = 0;
          try {
            lockBytesBefore = fs.statSync(path.join(projectDir, 'package-lock.json')).size;
          } catch {
            lockBytesBefore = 0;
          }
          const { output } = await runShell('npm install --package-lock-only --ignore-scripts', projectDir);
          await deps.logger.info('setup', `Regenerated lockfile before PR:\n${cap(output)}`);
          // Guard: a manifest quirk can make npm silently rewrite the lockfile
          // as an empty stub — revert implausible shrinkage (non-fatal).
          await revertImplausibleLockfileRegen(projectDir, repoRoot, lockBytesBefore, deps.logger);
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
                : scrubOutput(f.diff, deps.installationToken).slice(0, 6000);
            // Accurate verb from the diff — a removed secret file must read
            // "Removed", not "Changed" (the redacted-diff card has no body to
            // make that obvious otherwise).
            const verb = /(^|\n)deleted file mode|\n\+\+\+ \/dev\/null/.test(f.diff)
              ? 'Removed'
              : /(^|\n)new file mode|\n--- \/dev\/null/.test(f.diff)
                ? 'Added'
                : 'Changed';
            await step({ icon: 'edit', label: `${verb} ${f.path}`, diff: shown });
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
            output: scrubOutput(pushOutput, deps.installationToken),
          });
          // Do NOT queue postPrReadyCard: the run-1 card already live-renders
          // from this fixId — a second card would duplicate. But that card was
          // run 1's closing beat, so without one the timeline ends abruptly on
          // the step row — queue a short closing text beat instead, deferred
          // via pendingAfter so it flushes last (mirrors the create path's
          // deferred card).
          state.pendingAfter.push(async () => {
            const { makeTaskNarrator } = await import('./../task-chat');
            await makeTaskNarrator(supabase, threadId)('The update is up — same pull request, one new commit.');
          });
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
          output: scrubOutput(pushOutput, deps.installationToken),
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
          await finalizeAnswered(deps, summary);
          return 'task completed — the existing pull request stands';
        }
        if (deps.resumePriorStatus === 'completed' && !state.prOpened) {
          // The prior run genuinely SUCCEEDED but its PR is merged/closed (so
          // no resumeMode). An answer-only turn must NOT downgrade the task to
          // failed — the original fix already stands.
          await finalizeAnswered(deps, summary);
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

/** Answer-only terminal: the standing fix survives (open-PR amend resume, or a
 *  prior-completed run whose PR is merged/closed) and this turn's outcome was
 *  an ANSWER, not a change. markAnswered preserves the pr_ columns + diff
 *  summary; the task stays completed. The success mirror of finalizeFailure. */
export async function finalizeAnswered(deps: AgentToolDeps, summary?: string): Promise<void> {
  if (deps.state.terminal) return;
  await markAnswered(deps.supabase, deps.fixId, deps.machineId);
  await markTaskFromFix(
    deps.supabase,
    deps.taskId,
    summary ? { status: 'completed', summary } : { status: 'completed' },
  );
  deps.state.terminal = true;
}

/** A NATURAL stop (no abort, no error, no finish_task) on a resume whose fix
 *  already stands, where the model answered in chat and left the working tree
 *  clean, IS an answer-only turn — weak models routinely write the answer and
 *  stop without calling finish_task. Record it as answered: appending
 *  "I couldn't complete that follow-up" to a perfectly good answer reads as
 *  nonsense (the PR #16 wake). A dirty tree stays on the failure path so
 *  half-made edits are never silently passed off as success. Returns whether
 *  it resolved the run. */
export async function maybeFinalizeAnsweredNaturalStop(
  deps: AgentToolDeps,
  narrated: boolean,
): Promise<boolean> {
  if (deps.state.terminal || deps.state.prOpened) return false;
  if (!narrated) return false;
  if (!deps.resumeMode && deps.resumePriorStatus !== 'completed') return false;
  try {
    const { output } = await runShell('git status --porcelain', deps.repoRoot);
    if (output.trim() !== '') return false;
    await finalizeAnswered(deps);
    return true;
  } catch {
    // Git or DB hiccup — let the always-terminal failure path resolve the row.
    return false;
  }
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
  } else if (category === 'stall') {
    // Loop-detected spin (no novel work for STALL_LIMIT steps). Deliberately
    // NOT "budget/room" wording — a paying user reads that as their prepaid
    // billing balance. The nextStep invites the reply-to-resume wake feature.
    headline = "I couldn't find a clear fix";
    explanation = "I investigated the code but couldn't find a safe change to make, so I stopped rather than guess.";
    leadIn = "I've been investigating but haven't found a safe change I'm confident in — stopping here rather than guessing.";
    stepLabel = 'Stopped — no clear fix found';
    nextStep = "Reply with a hint (a file, a version, an approach) and I'll pick this up again.";
  } else if (category === 'budget_exhausted') {
    // A single run's budget ran out — either the wall-clock time limit OR the
    // step cap (both are "more than one run allows"). Wording rule: never
    // "budget" (money collision); nextStep invites reply-to-resume.
    headline = 'This needs another run to finish';
    explanation = 'The task ran longer than a single pass allows, so I stopped where I was.';
    leadIn = "I've done as much as one run allows — here's where I got to.";
    stepLabel = 'Paused — needs another run';
    nextStep = "Reply and I'll pick it up again from where I left off.";
  } else if (category === 'context_exhausted') {
    // The run filled the model's context window. Recoverable via the dedicated
    // "Compact context" action on the card, which wakes a resume that rebuilds a
    // COMPACTED history (replay's tail budget) and continues. The card is
    // deliberately minimal — just the headline + the Compact button — so the
    // extra prose beat + gray failed line are SKIPPED for this category below.
    headline = 'Context window limit reached';
    explanation = "The run filled the model's context window before it could finish.";
    leadIn = '';
    stepLabel = 'Context window limit reached';
    nextStep = '';
  } else {
    // not_fixable (the agent's own stated reason) — safe, first-person copy
    // from describeFailure (shared with the old pipeline; not touched here).
    const copy = describeFailure('not_fixable', message, {});
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
  // The failure surface in a task chat is JUST a single muted "failed" step line
  // (e.g. "Something went wrong" / "Paused — needs another run") — no card, no
  // lead-in prose. markFailed still records the full failure_details on the row
  // (headline/explanation/nextStep) for the task-detail view + our logs; the chat
  // itself stays minimal.
  await narrateStep(deps.supabase, deps.threadId, { icon: 'failed', label: stepLabel });
  await markTaskFromFix(deps.supabase, deps.taskId, { status: 'failed', summary: headline });
}
