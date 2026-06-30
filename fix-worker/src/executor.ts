import { execSync, type ExecSyncOptionsWithStringEncoding } from 'child_process';
import { generateText, type LanguageModel } from 'ai';
import * as fs from 'fs';
import * as path from 'path';
import type { FixLogger } from './logger';
import type { FixPlan } from './plan-types';
import { MAX_DIFF_LOC, MAX_TOOL_CALLS, REPAIR_BUDGET } from './plan-types';
import { applyDiffText } from './edit-tool';
import { runRepair } from './repair';
import { runTests, type TestResult } from './test-runner';

const EXEC_OPTS: ExecSyncOptionsWithStringEncoding = { encoding: 'utf-8', timeout: 60_000 };

const ARCHITECT_SYSTEM = `You are the editor of Aegis Fix Agent. You receive an approved plan, the relevant source files, and you produce a single Aider-style udiff that resolves the finding.

OUTPUT FORMAT (strict):
1. Think briefly about the patch in 1–3 sentences.
2. Emit the udiff for every file you change. Use the standard format:

   --- a/path/to/file.ext
   +++ b/path/to/file.ext
   @@ ... @@
    context
   -removed
   +added
    context

   For new files use "--- /dev/null" and "+++ b/path/to/file".
   For deletions use "+++ /dev/null".

RULES:
- Do not invent line numbers in the @@ header — "@@ ... @@" is fine.
- Include 2–3 lines of unchanged context above and below each change so the
  patch applies unambiguously.
- Make the smallest possible change that resolves the finding. No refactors.
- Do not elide code with "// rest unchanged" or "...". The editor must always
  show the actual lines.
- Touch only files listed in the plan unless absolutely required.
- Output ONLY the reasoning paragraph followed by the udiff. No extra text
  after the final hunk.`;

const MAX_FILE_PEEK_BYTES = 32_000;

function readFileForPrompt(workDir: string, relPath: string): string | null {
  try {
    const full = path.join(workDir, relPath);
    if (!fs.existsSync(full)) return null;
    const stat = fs.statSync(full);
    if (stat.size > MAX_FILE_PEEK_BYTES) {
      return fs.readFileSync(full, 'utf-8').slice(0, MAX_FILE_PEEK_BYTES) + '\n... [truncated]';
    }
    return fs.readFileSync(full, 'utf-8');
  } catch {
    return null;
  }
}

function buildUserPrompt(plan: FixPlan, workDir: string): string {
  const lines: string[] = [];
  lines.push(`PLAN SUMMARY: ${plan.summary}`);
  lines.push(`FINDING: ${plan.finding.type}/${plan.finding.id} (severity: ${plan.finding.severity ?? 'n/a'})`);
  lines.push('');
  lines.push('DESCRIPTION:');
  // Fallback to summary for plans persisted under the prior schema (which
  // had currentState/desiredState bullets instead of a description field).
  lines.push(plan.description ?? plan.summary);
  lines.push('');
  lines.push('FILES TO CHANGE:');
  for (const fc of plan.fileChanges) {
    lines.push(`- [${fc.action}] ${fc.path} — ${fc.description}`);
  }
  lines.push('');
  lines.push(`LANGUAGE: ${plan.language}`);
  lines.push('');
  lines.push('CURRENT FILE CONTENTS:');
  for (const fc of plan.fileChanges) {
    if (fc.action === 'create' || fc.action === 'delete') continue;
    const contents = readFileForPrompt(workDir, fc.path);
    if (contents === null) {
      lines.push(`--- ${fc.path} (file does not exist; treat as new)`);
      continue;
    }
    lines.push(`--- ${fc.path} ---`);
    lines.push(contents);
    lines.push(`--- end ${fc.path} ---`);
  }
  lines.push('');
  lines.push('Produce the udiff now.');
  return lines.join('\n');
}

export interface ExecutorResult {
  filesChanged: string[];
  rawDiff: string;
  tokensUsed: number;
  // Set when the udiff parsed but at least one hunk didn't match the file.
  // The pipeline routes this into the repair loop so the model can see
  // current file contents and try again, instead of dying mid-pipeline.
  applyError?: string;
}

export async function runEditor(opts: {
  model: LanguageModel;
  plan: FixPlan;
  workDir: string;
  logger: FixLogger;
}): Promise<ExecutorResult> {
  const { model, plan, workDir, logger } = opts;
  await logger.info('edit', 'Calling editor LLM for udiff');
  const startedAt = Date.now();

  let result;
  try {
    result = await generateText({
      model,
      system: ARCHITECT_SYSTEM,
      prompt: buildUserPrompt(plan, workDir),
    });
  } catch (err: any) {
    // Surface the underlying provider error so we can diagnose 422s etc.
    const detail = err?.responseBody ? ` body=${err.responseBody}` : '';
    const status = err?.statusCode ? ` status=${err.statusCode}` : '';
    const url = err?.url ? ` url=${err.url}` : '';
    await logger.error('edit', `Editor LLM call failed:${status}${url}${detail}`, err);
    throw err;
  }

  const tokensUsed =
    (result.usage?.inputTokens ?? 0) + (result.usage?.outputTokens ?? 0);
  await logger.success('edit', `Editor produced udiff`, Date.now() - startedAt, {
    tokens: tokensUsed,
  });

  const text = result.text ?? '';
  const diffStart = text.indexOf('--- ');
  if (diffStart === -1) {
    throw new Error('Editor LLM did not return a udiff (no "--- " marker found)');
  }
  const diffText = text.slice(diffStart);
  try {
    const { filesChanged } = applyDiffText(workDir, diffText);
    return { filesChanged, rawDiff: diffText, tokensUsed };
  } catch (err: any) {
    // Editor LLMs frequently emit context lines that don't quite match the
    // file (off-by-one whitespace, drifted line numbers, hallucinated
    // surrounding code). Don't crash — surface the error to runFixPipeline
    // so it can route the situation through the repair loop, where the
    // model gets actual file contents and a second chance.
    await logger.warn('edit', `Editor patch failed to apply: ${err.message}`);
    return { filesChanged: [], rawDiff: diffText, tokensUsed, applyError: err.message };
  }
}

function cumulativeDiffLoc(repoRoot: string): number {
  // Lines from the working tree against the base SHA. The clone reset us to
  // baseSha at start, so HEAD is the base; staged + unstaged together is the
  // entire fix delta. Counts every "+ "/"-" line including additions and
  // deletions, ignoring file headers. MUST run at the repo root (where the
  // branch/commit live) — `git diff HEAD` there captures edits made in a
  // monorepo subdir too.
  try {
    const out = execSync('git diff HEAD', { ...EXEC_OPTS, cwd: repoRoot });
    return out
      .split('\n')
      .filter((l) => (l.startsWith('+') || l.startsWith('-')) && !l.startsWith('+++') && !l.startsWith('---'))
      .length;
  } catch {
    return 0;
  }
}

export class FixPipelineError extends Error {
  constructor(message: string, public category: string) {
    super(message);
  }
}

export interface RunFixPipelineOpts {
  model: LanguageModel;
  plan: FixPlan;
  // The finding type this fix targets ('vulnerability' | 'semgrep' | 'secret').
  // Dependency bumps ('vulnerability') verify by re-resolving deps rather than
  // running the app's full test suite (too slow + needs CI's full setup).
  fixType?: string | null;
  // Project directory (the monorepo subdir, or the repo root when there is no
  // subdir). Used as the cwd for tests and as the base for resolving the
  // plan's file-edit paths (which are relative to the project root).
  workDir: string;
  // The clone / repo root, where the branch + commit live. Used only for git
  // ops (the cumulative-diff cap). Equals workDir for non-monorepo projects.
  repoRoot: string;
  logger: FixLogger;
  extraEnv: Record<string, string>;
  pipelineStartMs: number;
}

export interface RunFixPipelineResult {
  rawDiff: string;
  testResult: TestResult;
  tokensUsed: number;
  toolCalls: number;
  repairAttempts: number;
}

// Verify a dependency bump by re-resolving deps. For JS/TS that's `npm install`
// — it validates the bumped version exists and regenerates package-lock.json so
// CI's `npm ci` passes; a non-existent version fails here (real signal, no PR).
// For languages without a fast, reliable re-resolve in this sandbox, skip local
// verification (soft-pass) and let the PR's CI be the gate.
async function verifyDependencyBump(opts: {
  workDir: string;
  language: string;
  logger: FixLogger;
  timeoutMs: number;
}): Promise<TestResult> {
  if (opts.language === 'js' || opts.language === 'ts') {
    return runTests({
      workDir: opts.workDir,
      testCommand: 'npm install --no-audit --no-fund',
      logger: opts.logger,
      timeoutMs: opts.timeoutMs,
    });
  }
  await opts.logger.info(
    'tests',
    `No fast dependency re-resolve for language "${opts.language}" — opening PR; the PR's CI verifies`,
  );
  return {
    passed: true,
    exitCode: 0,
    stdout: '',
    stderr: '',
    durationMs: 0,
    timedOut: false,
    noTestSuite: true,
  };
}

/**
 * Single entry point for "produce a fix that passes tests".
 *
 * Flow:
 *   1. Editor produces a udiff (1 tool call).
 *   2. Test runs.
 *   3. If failing, up to REPAIR_BUDGET repair cycles (each = 1 tool call + 1 test).
 *
 * Safety caps enforced inline:
 *   - Wall-clock budget from plan.wallClockBudgetSec, measured from the
 *     pipeline start (clone + setup eat into the budget).
 *   - Tool-call cap (MAX_TOOL_CALLS) across editor + repairs.
 *   - Cumulative diff cap (MAX_DIFF_LOC) checked after editor and after
 *     every repair, so a runaway repair can't ratchet the diff past the
 *     line-count budget.
 */
export async function runFixPipeline(opts: RunFixPipelineOpts): Promise<RunFixPipelineResult> {
  const { model, plan, workDir, repoRoot, logger, extraEnv, pipelineStartMs } = opts;

  const wallClockBudgetMs = plan.wallClockBudgetSec * 1000;
  const checkBudget = (label: string) => {
    const elapsed = Date.now() - pipelineStartMs;
    if (elapsed > wallClockBudgetMs) {
      throw new FixPipelineError(
        `Wall-clock budget exhausted before ${label} (elapsed ${Math.round(elapsed / 1000)}s > ${plan.wallClockBudgetSec}s)`,
        'budget_wall_clock',
      );
    }
  };

  let toolCalls = 0;
  const trackToolCall = (label: string) => {
    toolCalls += 1;
    if (toolCalls > MAX_TOOL_CALLS) {
      throw new FixPipelineError(
        `Tool-call cap (${MAX_TOOL_CALLS}) exceeded at ${label}`,
        'budget_tool_calls',
      );
    }
  };

  const checkDiffCap = (label: string) => {
    const loc = cumulativeDiffLoc(repoRoot);
    if (loc > MAX_DIFF_LOC) {
      throw new FixPipelineError(
        `Diff too large after ${label}: ${loc} LOC > cap ${MAX_DIFF_LOC}. Split this fix into smaller plans.`,
        'diff_too_large',
      );
    }
  };

  // 1. Editor pass.
  checkBudget('editor');
  trackToolCall('editor');
  const editorResult = await runEditor({ model, plan, workDir, logger });
  let totalTokens = editorResult.tokensUsed;
  let lastDiff = editorResult.rawDiff;

  // 2. Initial test run — OR a synthetic failure if the editor's patch
  // didn't apply cleanly. Either way, the repair loop has the same shape:
  // fix the diff, retry. Repair already reads current file contents so it
  // can recover from off-by-one context drift.
  const remainingBudgetMs = (label: string): number => {
    const elapsed = Date.now() - pipelineStartMs;
    const remaining = wallClockBudgetMs - elapsed;
    if (remaining <= 0) {
      throw new FixPipelineError(
        `Wall-clock budget exhausted before ${label}`,
        'budget_wall_clock',
      );
    }
    return Math.min(remaining, 10 * 60 * 1000);
  };

  // Verify the change. Dependency bumps RE-RESOLVE deps (fast — validates the
  // bumped version exists + regenerates a consistent lockfile, which CI's
  // `npm ci` checks) instead of running the app's full test suite (too slow for
  // the wall-clock budget + needs the multi-package / service setup only CI
  // has; the PR's CI runs build + tests). Code fixes run the suite. The SAME
  // picker is used for the initial check and every repair re-check.
  const isDependencyBump = (opts.fixType ?? '') === 'vulnerability';
  const verify = (label: string): Promise<TestResult> =>
    isDependencyBump
      ? verifyDependencyBump({ workDir, language: plan.language, logger, timeoutMs: remainingBudgetMs(label) })
      : runTests({ workDir, testCommand: plan.testCommand, logger, timeoutMs: remainingBudgetMs(label), extraEnv });

  let testResult: TestResult;
  if (editorResult.applyError) {
    testResult = {
      passed: false,
      exitCode: -1,
      stdout: '',
      stderr: `Patch from editor did not apply: ${editorResult.applyError}\nFix the hunk so it matches the CURRENT file content shown below, then re-emit the full udiff.`,
      durationMs: 0,
      timedOut: false,
      noTestSuite: false,
    };
  } else {
    checkDiffCap('editor');
    testResult = await verify(isDependencyBump ? 'dependency install' : 'initial test');
  }

  // 3. Repair cycles. These recover from a patch that DIDN'T APPLY (re-emit the
  // edit) as much as from a test failure — so a dependency bump repairs too: its
  // package.json hunk can drift exactly like any other patch. It just re-verifies
  // via the fast re-resolve; a version that still won't resolve after
  // REPAIR_BUDGET is a real, unfixable failure.
  let repairAttempts = 0;
  while (!testResult.passed && repairAttempts < REPAIR_BUDGET) {
    repairAttempts += 1;
    await logger.info('repair', `Repair cycle ${repairAttempts}/${REPAIR_BUDGET}`);

    checkBudget(`repair ${repairAttempts}`);
    trackToolCall(`repair ${repairAttempts}`);
    const repair = await runRepair({
      model,
      plan,
      workDir,
      previousDiff: lastDiff,
      testResult,
      logger,
    });
    totalTokens += repair.tokensUsed;
    lastDiff = repair.repairDiff;
    if (repair.applyError) {
      // Repair patch didn't apply either. Keep looping with the apply error
      // as the synthetic test failure — same recovery shape as the editor
      // case above.
      testResult = {
        passed: false,
        exitCode: -1,
        stdout: '',
        stderr: `Repair patch did not apply: ${repair.applyError}\nFix the hunk so it matches the CURRENT file content shown below, then re-emit the full udiff.`,
        durationMs: 0,
        timedOut: false,
        noTestSuite: false,
      };
      continue;
    }
    checkDiffCap(`repair ${repairAttempts}`);
    testResult = await verify(`test after repair ${repairAttempts}`);
  }

  if (!testResult.passed) {
    throw new FixPipelineError(
      `Tests still failing after ${repairAttempts} repair cycle${repairAttempts === 1 ? '' : 's'} (exit ${testResult.exitCode})`,
      'tests_failed',
    );
  }

  return {
    rawDiff: lastDiff,
    testResult,
    tokensUsed: totalTokens,
    toolCalls,
    repairAttempts,
  };
}
