// Agentic explore-then-edit loop for finding types where the planner can't
// name the exact edit site up front — dataflow (insert a sanitizer along a
// taint path) and dast (patch a vulnerable endpoint handler). The model gets
// read-only tools (read_file / grep / list_dir) scoped to the clone so it can
// LOOK AROUND before patching — trace the source→sink path, find the handler,
// see how inputs reach the sink — instead of only seeing the files the plan
// named. It then emits the same Aider-style udiff the normal editor produces,
// so it slots into runFixPipeline (apply → verify → repair) unchanged.
//
// Budget is separate from the edit/repair MAX_TOOL_CALLS pool (see
// MAX_EXPLORE_STEPS / MAX_EXPLORE_TOOL_CALLS) so a deep path can't starve the
// downstream repair cycles.

import { execFileSync } from 'child_process';
import { generateText, tool, stepCountIs, type LanguageModel } from 'ai';
import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import type { FixLogger } from './logger';
import type { FixPlan } from './plan-types';
import { MAX_EXPLORE_STEPS, MAX_EXPLORE_TOOL_CALLS } from './plan-types';
import { applyDiffText } from './edit-tool';
import type { ExecutorResult } from './executor';

const MAX_FILE_PEEK_BYTES = 32_000;
const MAX_GREP_LINES = 60;
const MAX_LIST_ENTRIES = 200;

const EXPLORE_SYSTEM = `You are the code-exploring editor of Aegis Fix Agent. You fix exactly ONE security finding in a customer's repository.

Unlike a blind patcher, you can EXPLORE the repo first with tools:
- read_file(path): read a file (relative to the repo/project root).
- grep(pattern, glob?): search file contents (extended-regex) across the project.
- list_dir(path): list a directory.

PROCESS:
1. Read the plan: the finding, the description, and the seed files it points at.
2. Explore ONLY as much as you need to understand the fix — read the seed files, grep for the
   source / sink / handler / the tainted variable, read the function(s) involved. A handful of
   focused reads, not a crawl.
3. When you understand it, STOP calling tools and output a single Aider-style udiff.

UDIFF FORMAT (strict):
- Emit a udiff for every file you change:
    --- a/path/to/file.ext
    +++ b/path/to/file.ext
    @@ ... @@
     context
    -removed
    +added
     context
- Do not invent line numbers in the @@ header — "@@ ... @@" is fine.
- Include 2–3 lines of unchanged context above and below each change.
- Never elide code with "// ..." — show the actual lines.

FIX RULES:
- Make the SMALLEST change that actually neutralizes the vulnerability CLASS:
  - sql_injection → parameterized query / prepared statement (NOT string escaping).
  - xss → HTML-entity encode the user input in the rendering context (NOT URL encoding).
  - path_traversal → canonicalize + confine (resolve within a base dir), NOT a regex filter.
  - command_injection → pass args as an array to execFile/spawn (no shell).
  - ssrf → allowlist the host + block private IPs.
  - open_redirect → validate the redirect target against an allowlist.
- Prefer adding/using a helper the codebase already has over inventing a new dependency.
- Be honest: you are sanitizing the reported flow, not proving the whole CVE gone.
- Output ONLY the udiff as your FINAL message (after any tool calls). No prose after the last hunk.`;

function readWithinRepo(workDir: string, relPath: string): { ok: true; content: string } | { ok: false; error: string } {
  const full = path.resolve(workDir, relPath);
  // Confine to the clone — no path traversal out of workDir.
  if (full !== workDir && !full.startsWith(workDir + path.sep)) {
    return { ok: false, error: 'path is outside the repository' };
  }
  try {
    if (!fs.existsSync(full)) return { ok: false, error: 'file not found' };
    const stat = fs.statSync(full);
    if (stat.isDirectory()) return { ok: false, error: 'path is a directory (use list_dir)' };
    const raw = fs.readFileSync(full, 'utf-8');
    return {
      ok: true,
      content: stat.size > MAX_FILE_PEEK_BYTES ? raw.slice(0, MAX_FILE_PEEK_BYTES) + '\n... [truncated]' : raw,
    };
  } catch (e: any) {
    return { ok: false, error: e?.message ?? 'read failed' };
  }
}

function buildExplorePrompt(plan: FixPlan, workDir: string): string {
  const lines: string[] = [];
  lines.push(`PLAN SUMMARY: ${plan.summary}`);
  lines.push(`FINDING: ${plan.finding.type}/${plan.finding.id} (severity: ${plan.finding.severity ?? 'n/a'})`);
  lines.push('');
  lines.push('DESCRIPTION:');
  lines.push(plan.description ?? plan.summary);
  if (plan.issue) {
    lines.push('');
    lines.push('ISSUE:');
    lines.push(plan.issue);
  }
  lines.push('');
  lines.push('SEED FILES (start here; explore outward with the tools if you need more):');
  for (const fc of plan.fileChanges) {
    lines.push(`- [${fc.action}] ${fc.path} — ${fc.description}`);
  }
  lines.push('');
  lines.push('CONTENTS OF THE SEED FILES:');
  for (const fc of plan.fileChanges) {
    if (fc.action === 'create' || fc.action === 'delete') continue;
    const r = readWithinRepo(workDir, fc.path);
    if (!r.ok) {
      lines.push(`--- ${fc.path} (${r.error}) ---`);
      continue;
    }
    lines.push(`--- ${fc.path} ---`);
    lines.push(r.content);
    lines.push(`--- end ${fc.path} ---`);
  }
  lines.push('');
  lines.push('Explore as needed, then produce the udiff.');
  return lines.join('\n');
}

export async function runExplorer(opts: {
  model: LanguageModel;
  plan: FixPlan;
  workDir: string;
  logger: FixLogger;
}): Promise<ExecutorResult> {
  const { model, plan, workDir, logger } = opts;
  await logger.info('explore', 'Exploring the codebase to place the fix');
  const startedAt = Date.now();

  let toolCalls = 0;
  const overBudget = () => toolCalls >= MAX_EXPLORE_TOOL_CALLS;

  const tools = {
    read_file: tool({
      description: 'Read a file from the repository (path relative to the project root).',
      inputSchema: z.object({ path: z.string().describe('File path relative to the project root') }),
      execute: async ({ path: p }) => {
        toolCalls += 1;
        if (overBudget()) return 'Explore budget exhausted — stop exploring and output the udiff now.';
        const r = readWithinRepo(workDir, p);
        return r.ok ? r.content : `Could not read ${p}: ${r.error}`;
      },
    }),
    grep: tool({
      description: 'Search file contents across the project with an extended-regex pattern.',
      inputSchema: z.object({
        pattern: z.string().describe('Extended-regex (grep -E) pattern to search for'),
        glob: z.string().optional().describe('Optional filename glob to limit the search, e.g. "*.ts"'),
      }),
      execute: async ({ pattern, glob }) => {
        toolCalls += 1;
        if (overBudget()) return 'Explore budget exhausted — stop exploring and output the udiff now.';
        try {
          const args = ['-rInE', '--exclude-dir=node_modules', '--exclude-dir=.git'];
          if (glob) args.push(`--include=${glob}`);
          // `--` terminates options so a pattern starting with `-` is safe;
          // execFileSync (no shell) avoids injection.
          args.push('--', pattern, '.');
          const out = execFileSync('grep', args, {
            cwd: workDir,
            encoding: 'utf-8',
            timeout: 20_000,
            maxBuffer: 4_000_000,
          });
          const linesOut = out.split('\n').filter(Boolean);
          const shown = linesOut.slice(0, MAX_GREP_LINES).join('\n');
          return linesOut.length > MAX_GREP_LINES
            ? `${shown}\n... (${linesOut.length - MAX_GREP_LINES} more matches; narrow the pattern)`
            : shown || 'no matches';
        } catch (e: any) {
          // grep exits 1 on no matches — not an error for us.
          if (e?.status === 1) return 'no matches';
          return `grep failed: ${e?.message ?? 'error'}`;
        }
      },
    }),
    list_dir: tool({
      description: 'List the entries of a directory (path relative to the project root).',
      inputSchema: z.object({ path: z.string().describe('Directory path relative to the project root, "." for root') }),
      execute: async ({ path: p }) => {
        toolCalls += 1;
        if (overBudget()) return 'Explore budget exhausted — stop exploring and output the udiff now.';
        const full = path.resolve(workDir, p);
        if (full !== workDir && !full.startsWith(workDir + path.sep)) return 'path is outside the repository';
        try {
          const entries = fs
            .readdirSync(full, { withFileTypes: true })
            .filter((e) => e.name !== 'node_modules' && e.name !== '.git')
            .slice(0, MAX_LIST_ENTRIES)
            .map((e) => (e.isDirectory() ? `${e.name}/` : e.name));
          return entries.length ? entries.join('\n') : '(empty)';
        } catch (e: any) {
          return `Could not list ${p}: ${e?.message ?? 'error'}`;
        }
      },
    }),
  };

  let result;
  try {
    result = await generateText({
      model,
      system: EXPLORE_SYSTEM,
      prompt: buildExplorePrompt(plan, workDir),
      tools,
      stopWhen: stepCountIs(MAX_EXPLORE_STEPS),
    });
  } catch (err: any) {
    const detail = err?.responseBody ? ` body=${err.responseBody}` : '';
    const status = err?.statusCode ? ` status=${err.statusCode}` : '';
    await logger.error('explore', `Explore LLM call failed:${status}${detail}`, err);
    throw err;
  }

  const usage: any = (result as any).totalUsage ?? result.usage ?? {};
  const tokensUsed = (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0);
  await logger.success('explore', `Explored the code (${toolCalls} lookups) and produced a patch`, Date.now() - startedAt, {
    tokens: tokensUsed,
  });

  const text = result.text ?? '';
  const diffStart = text.indexOf('--- ');
  if (diffStart === -1) {
    return { filesChanged: [], rawDiff: '', tokensUsed, applyError: 'Explorer produced no udiff (no "--- " marker)' };
  }
  const diffText = text.slice(diffStart);
  try {
    const { filesChanged } = applyDiffText(workDir, diffText);
    return { filesChanged, rawDiff: diffText, tokensUsed };
  } catch (err: any) {
    await logger.warn('explore', `Explorer patch failed to apply: ${err.message}`);
    return { filesChanged: [], rawDiff: diffText, tokensUsed, applyError: err.message };
  }
}
