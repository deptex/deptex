import { generateText, type LanguageModel } from 'ai';
import type { FixLogger } from './logger';
import type { FixPlan } from './plan-types';
import { applyDiffText } from './edit-tool';
import type { TestResult } from './test-runner';

// M5 lands a 1-cycle repair stub: when tests fail, give the LLM the failures
// once and let it produce a follow-up udiff. M7 expands this into a 2-cycle
// budget with the full safety caps.

const REPAIR_SYSTEM = `You are repairing a failed fix attempt. The plan was approved and partially applied, but tests are now failing.

You will receive:
- The original plan
- The previous diff that was applied
- The test failure output

Produce a NEW Aider-style udiff against the CURRENT working state (post-previous-diff). Do not undo the prior fix unless it is the cause of the test failure. Stay tightly scoped — only change what is needed to make the tests pass.

OUTPUT: brief reasoning then a udiff using "--- a/path", "+++ b/path", "@@ ... @@".`;

function buildRepairPrompt(plan: FixPlan, previousDiff: string, tests: TestResult): string {
  const stderrTail = tests.stderr.slice(-4_000);
  const stdoutTail = tests.stdout.slice(-4_000);
  return [
    `PLAN SUMMARY: ${plan.summary}`,
    `FINDING: ${plan.finding.type}/${plan.finding.id}`,
    '',
    'PREVIOUS DIFF:',
    previousDiff,
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
    prompt: buildRepairPrompt(plan, previousDiff, testResult),
  });

  const tokensUsed =
    (result.usage?.inputTokens ?? 0) + (result.usage?.outputTokens ?? 0);
  const text = result.text ?? '';
  const diffStart = text.indexOf('--- ');
  if (diffStart === -1) {
    throw new Error('Repair LLM did not return a udiff');
  }
  const diffText = text.slice(diffStart);
  const { filesChanged } = applyDiffText(workDir, diffText);

  await logger.success('repair', 'Repair udiff applied', Date.now() - startedAt, { tokens: tokensUsed });
  return { repairDiff: diffText, filesChanged, tokensUsed };
}
