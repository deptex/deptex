import { generateText, type LanguageModel } from 'ai';
import * as fs from 'fs';
import * as path from 'path';
import type { FixLogger } from './logger';
import type { FixPlan } from './plan-types';
import { applyDiffText } from './edit-tool';

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
  lines.push('CURRENT STATE:');
  for (const b of plan.currentState) lines.push(`- ${b}`);
  lines.push('');
  lines.push('DESIRED STATE:');
  for (const b of plan.desiredState) lines.push(`- ${b}`);
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

  const result = await generateText({
    model,
    system: ARCHITECT_SYSTEM,
    prompt: buildUserPrompt(plan, workDir),
  });

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
  const { filesChanged } = applyDiffText(workDir, diffText);
  return { filesChanged, rawDiff: diffText, tokensUsed };
}
