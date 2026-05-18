import { generateText, type LanguageModel } from 'ai';
import * as fs from 'fs';
import * as path from 'path';
import type { FixLogger } from './logger';
import type { FixPlan } from './plan-types';
import { applyDiffText } from './edit-tool';
import type { TestResult } from './test-runner';

const REPAIR_SYSTEM = `You are repairing a failed fix attempt. The plan was approved and partially applied, but tests are now failing.

You will receive:
- The original plan
- The previous diff that was applied
- The CURRENT contents of every file the plan touched (post-previous-diff)
- The test failure output

Produce a NEW Aider-style udiff against the CURRENT working state shown below. Match your hunk context to those CURRENT contents — the previous diff has ALREADY been applied, so do not re-add lines you can already see. Do not undo the prior fix unless it is the cause of the test failure. Stay tightly scoped — only change what is needed to make the tests pass.

OUTPUT: brief reasoning then a udiff using "--- a/path", "+++ b/path", "@@ ... @@".`;

const MAX_FILE_PEEK_BYTES = 32_000;

function readFilesContext(workDir: string, plan: FixPlan): string {
  const lines: string[] = ['CURRENT FILE CONTENTS (after previous diff was applied):'];
  for (const fc of plan.fileChanges) {
    if (fc.action === 'delete') continue;
    const full = path.join(workDir, fc.path);
    if (!fs.existsSync(full)) {
      lines.push(`--- ${fc.path} (does not exist)`);
      continue;
    }
    try {
      const stat = fs.statSync(full);
      const raw = fs.readFileSync(full, 'utf-8');
      const content = stat.size > MAX_FILE_PEEK_BYTES
        ? raw.slice(0, MAX_FILE_PEEK_BYTES) + '\n... [truncated]'
        : raw;
      lines.push(`--- ${fc.path} ---`);
      lines.push(content);
      lines.push(`--- end ${fc.path} ---`);
    } catch {
      lines.push(`--- ${fc.path} (read failed)`);
    }
  }
  return lines.join('\n');
}

function buildRepairPrompt(workDir: string, plan: FixPlan, previousDiff: string, tests: TestResult): string {
  const stderrTail = tests.stderr.slice(-4_000);
  const stdoutTail = tests.stdout.slice(-4_000);
  return [
    `PLAN SUMMARY: ${plan.summary}`,
    `FINDING: ${plan.finding.type}/${plan.finding.id}`,
    '',
    'PREVIOUS DIFF:',
    previousDiff,
    '',
    readFilesContext(workDir, plan),
    '',
    `TEST EXIT CODE: ${tests.exitCode}`,
    'TEST STDERR (tail):',
    stderrTail || '(empty)',
    '',
    'TEST STDOUT (tail):',
    stdoutTail || '(empty)',
    '',
    'Produce a repair udiff now.',
  ].join('\n');
}

export interface RepairResult {
  repairDiff: string;
  filesChanged: string[];
  tokensUsed: number;
  // Same contract as ExecutorResult: when the repair LLM emits a hunk that
  // doesn't match the file, the pipeline keeps the cycle alive (next loop
  // iteration retries with this error in the test stderr context).
  applyError?: string;
}

export async function runRepair(opts: {
  model: LanguageModel;
  plan: FixPlan;
  workDir: string;
  previousDiff: string;
  testResult: TestResult;
  logger: FixLogger;
}): Promise<RepairResult> {
  const { model, plan, workDir, previousDiff, testResult, logger } = opts;
  await logger.info('repair', 'Asking LLM for repair udiff after test failure');
  const startedAt = Date.now();

  const result = await generateText({
    model,
    system: REPAIR_SYSTEM,
    prompt: buildRepairPrompt(workDir, plan, previousDiff, testResult),
  });

  const tokensUsed =
    (result.usage?.inputTokens ?? 0) + (result.usage?.outputTokens ?? 0);
  const text = result.text ?? '';
  const diffStart = text.indexOf('--- ');
  if (diffStart === -1) {
    throw new Error('Repair LLM did not return a udiff');
  }
  const diffText = text.slice(diffStart);
  try {
    const { filesChanged } = applyDiffText(workDir, diffText);
    await logger.success('repair', 'Repair udiff applied', Date.now() - startedAt, { tokens: tokensUsed });
    return { repairDiff: diffText, filesChanged, tokensUsed };
  } catch (err: any) {
    await logger.warn('repair', `Repair patch failed to apply: ${err.message}`);
    return { repairDiff: diffText, filesChanged: [], tokensUsed, applyError: err.message };
  }
}
