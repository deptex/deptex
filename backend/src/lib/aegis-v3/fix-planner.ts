import { generateObject, NoObjectGeneratedError } from 'ai';
import { supabase } from '../../lib/supabase';
import { getLanguageModelForOrg } from '../aegis/llm-provider';
import { createInstallationToken, getBranchSha } from '../github';
import {
  gatherSecretContext,
  gatherSemgrepContext,
  gatherVulnerabilityContext,
  type FixRequest,
} from '../ai-fix-engine';
import {
  DEFAULT_WALL_CLOCK_BUDGET_SEC,
  fixPlanSchema,
  type FindingType,
  type FixPlan,
} from './plan-types';

export interface PlannerInput {
  organizationId: string;
  projectId: string;
  findingType: FindingType;
  findingId: string;
  triggeredByUserId: string;
}

export interface PlannerResult {
  plan: FixPlan;
  baseSha: string;
  baseBranch: string;
  repoFullName: string;
}

interface RepoLookup {
  repoFullName: string;
  defaultBranch: string;
  installationId: string;
}

async function resolveRepo(projectId: string, organizationId: string): Promise<RepoLookup> {
  const { data: repo, error: repoError } = await supabase
    .from('project_repositories')
    .select('repo_full_name, default_branch, installation_id, status')
    .eq('project_id', projectId)
    .maybeSingle();
  if (repoError) throw new Error(`Failed to load repository: ${repoError.message}`);
  if (!repo || repo.status === 'not_connected' || !repo.repo_full_name || !repo.default_branch) {
    throw new Error('Project has no connected repository.');
  }

  const fallbackInstallationId = await (async () => {
    if (repo.installation_id) return repo.installation_id as string;
    const { data: org, error: orgError } = await supabase
      .from('organizations')
      .select('github_installation_id')
      .eq('id', organizationId)
      .single();
    if (orgError) throw new Error(`Failed to load organization: ${orgError.message}`);
    if (!org?.github_installation_id) {
      throw new Error('Organization has no GitHub App installation.');
    }
    return org.github_installation_id as string;
  })();

  return {
    repoFullName: repo.repo_full_name,
    defaultBranch: repo.default_branch,
    installationId: fallbackInstallationId,
  };
}

async function gatherFindingContext(
  input: PlannerInput,
): Promise<Record<string, any>> {
  if (input.findingType === 'vulnerability') {
    const { data: link, error } = await supabase
      .from('project_dependencies')
      .select('id, dependency_id')
      .eq('project_id', input.projectId)
      .limit(50);
    if (error) throw new Error(`Failed to load project dependencies: ${error.message}`);

    const fixReq: FixRequest = {
      projectId: input.projectId,
      organizationId: input.organizationId,
      userId: input.triggeredByUserId,
      strategy: 'code_patch',
      vulnerabilityOsvId: input.findingId,
    };

    if (link && link.length > 0) {
      const { data: vulnLinks } = await supabase
        .from('dependency_vulnerabilities')
        .select('dependency_id')
        .eq('osv_id', input.findingId);
      const vulnDepIds = new Set((vulnLinks ?? []).map((v: any) => v.dependency_id));
      const matchedPd = link.find((l: any) => vulnDepIds.has(l.dependency_id));
      if (matchedPd) {
        fixReq.projectDependencyId = matchedPd.id;
        fixReq.dependencyId = matchedPd.dependency_id;
      }
    }
    return gatherVulnerabilityContext(fixReq);
  }

  if (input.findingType === 'semgrep') {
    return gatherSemgrepContext(input.findingId, input.projectId);
  }
  return gatherSecretContext(input.findingId, input.projectId);
}

const PLANNER_SYSTEM_PROMPT = `You are the architect of Aegis Fix Agent. Your job is to design a single, tightly-scoped patch that resolves ONE security finding in a customer's repository — and nothing else.

You will receive:
- The finding (vulnerability / Semgrep / secret) and its details
- The dependency (when relevant) including current and patched versions
- Reachability evidence and importing files
- Repository information

Produce a structured plan as JSON matching the provided schema.

PLANNING RULES:
1. Stay tightly scoped. Patch THIS finding only — no refactors, no opportunistic improvements.
2. Prefer the lowest-risk strategy: bump version > pin > minimal code patch.
3. Pick the test command that exercises the patched code in this repo's primary language. Defaults:
   - js/ts: \`npm test\` (or \`npm run test\`).
   - python: \`pytest\` — the executor sets up a venv with pytest available, so just write \`pytest\` (or \`pytest path/to/test.py\` to scope). Do NOT prefix with \`.venv/bin/\`.
   - go: \`go test ./...\` (or a narrower package path if appropriate). \`go mod download\` runs automatically before tests.
   - java: \`mvn test\`. ruby: \`bundle exec rspec\`. php: \`composer test\`. rust: \`cargo test\`. csharp: \`dotnet test\`.
4. estimatedDiffSize: small (<100 LOC), medium (100-500), large (>500). Plans estimated as "large" should be split.
5. wallClockBudgetSec defaults to 300. Increase only when the language toolchain is slow (e.g., Java/Maven up to 600).
6. fileChanges should list each touched file with a one-sentence rationale. Do not include diffs — those are produced during execution.
7. summary is one short title-style sentence a developer can scan in two seconds (e.g. "Fix exposed AWS key in src/config.js" — verb + object, ≤80 chars).
8. description is 1-2 short sentences explaining WHAT THE FIX DOES — the plan, in plain English. Do NOT just restate the summary; add a fact the title alone doesn't convey. No bullet points. The issue itself goes in \`issue\`, not here. Verification details go in verificationSteps.
8a. issue is markdown explaining WHAT THE PROBLEM IS — the user reads this to understand why a fix is needed. Aim for 2-4 sentences. When the finding has affected source code (Semgrep findings, secrets, sometimes reachable vulnerabilities), include a fenced code block with the relevant excerpt INSIDE the issue field. Use the actual snippet from the context (do NOT fabricate code). Use language tags that match the file extension (\`\`\`ts, \`\`\`py, \`\`\`go, etc.) and immediately precede or follow the fence with one line citing the file and line (e.g. \`src/api.ts:42\`). For dependency vulnerabilities where there's no specific file excerpt to show, omit the code fence and instead describe the package + advisory in prose. Keep the whole field under 4000 characters. Never paraphrase identifiers or pretend data exists that isn't in the context.
9. todos is an ordered list of short imperative steps the user reads to understand WHAT will happen. Use as many or as few as the change actually requires — a one-line bump is one todo, a multi-step refactor may be many. Each todo is { title, detail? }:
   - title: an imperative sentence ≤80 chars naming the action ("Bump axios from 1.5.0 to 1.6.0", "Move the hardcoded API key to an environment variable", "Update the lockfile and re-run installs"). NOT a file path — file-level work belongs in fileChanges.
   - detail: OPTIONAL one-sentence elaboration when the title alone would be ambiguous. Omit when the title is self-explanatory.
   These are the user-facing plan; fileChanges is the executor's work breakdown. Do not pad with filler ("Review the change", "Make sure tests pass" — verification belongs in verificationSteps).
10. verificationSteps is an array of 1-4 concrete checks the user should expect to pass before merging. Each step is { command, description }:
   - command: the exact shell command we'd run, named with the tool this project actually uses (look at the context — package.json scripts, language ecosystem, lockfiles). Examples: "npm test", "npm run lint", "tsc --noEmit", "ruff check .", "mypy src/", "go vet ./...", "go test ./...".
   - description: ONE sentence explaining WHAT this check covers and why it's relevant to THIS fix (not a generic "runs the test suite" filler).
   The first step MUST match testCommand (so the worker's verification step is represented). Add lint / type check / build steps when the project clearly uses those tools. If the change is too small or isolated for tests to meaningfully cover (e.g. removing a hardcoded secret, deleting a single line), still include testCommand but be honest in its description ("the secret removal is a one-line delete; tests confirm nothing else broke") and lean on lint/type-check.

REFUSAL RULES:
The refusal field is OPTIONAL. OMIT it entirely from your output when the fix is feasible. Do NOT emit \`refusal: null\`, \`refusal: {}\`, \`refusal: { reason: "" }\`, \`refusal: { reason: "null" }\`, or \`refusal: { reason: "none" }\` — those will be treated as a real refusal and the plan will fail.

Include refusal.reason ONLY when a fix cannot be safely produced. Examples of real refusals:
- No patched version exists for this vulnerability.
- The finding is ambiguous or already remediated.
- The required change is too large for v1 (>500 LOC) and must be split.
- Language not in the v1 ship gate (anything outside js/ts/python/go) — set refusal.reason to "Language X is not supported by Aegis Fix Agent v1." with no manualSuggestion needed.

When you DO set refusal, still populate the other fields with best-effort placeholders so the schema validates; humans will read the refusal first.`;

function buildUserPrompt(input: PlannerInput, ctx: Record<string, any>, repo: RepoLookup): string {
  return [
    `Finding type: ${input.findingType}`,
    `Finding id: ${input.findingId}`,
    `Repository: ${repo.repoFullName} (default branch: ${repo.defaultBranch})`,
    '',
    'CONTEXT:',
    JSON.stringify(ctx, null, 2),
    '',
    `Default wall-clock budget: ${DEFAULT_WALL_CLOCK_BUDGET_SEC}s.`,
    'Produce the plan now.',
  ].join('\n');
}

// Cheap-tier models (DeepSeek V4 Flash, Qwen 3.6, GPT-5 nano) flake on nested
// structured output and several DeepInfra models don't even support the SDK's
// JSON schema mode (warning: `responseFormat is only supported with
// structuredOutputs`). The actual model output is usually sensible content
// with a slightly off shape — flat `findingId` / `findingType` instead of a
// nested `finding` object, `"javascript/typescript"` instead of `"js"`,
// extra fields like `fixStrategy`. Massaging the raw text into the right
// shape recovers far more attempts than retrying with a stricter prompt.
function normalizePlanShape(raw: any, input: PlannerInput): any {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return raw;
  const out: any = { ...raw };

  // Flat `findingId` + `findingType` -> nested `finding: { type, id }`.
  if (!out.finding && (out.findingId || out.findingType)) {
    out.finding = {
      type: out.findingType ?? input.findingType,
      id: out.findingId ?? input.findingId,
    };
  }
  if (!out.finding) {
    out.finding = { type: input.findingType, id: input.findingId };
  }
  delete out.findingId;
  delete out.findingType;
  delete out.fixStrategy; // common extra field models invent

  // Old-shape fallback: if the model still emits currentState / desiredState
  // arrays (the prior schema), join them into a description paragraph so we
  // don't lose the content. Drop the bullets afterward.
  if (!out.description) {
    const parts: string[] = [];
    if (Array.isArray(out.currentState) && out.currentState.length > 0) {
      parts.push(`Currently: ${out.currentState.join('. ')}.`);
    }
    if (Array.isArray(out.desiredState) && out.desiredState.length > 0) {
      parts.push(`After the fix: ${out.desiredState.join('. ')}.`);
    }
    if (parts.length > 0) out.description = parts.join(' ');
  }
  delete out.currentState;
  delete out.desiredState;

  // Language aliases. Some models output natural-language combos.
  if (typeof out.language === 'string') {
    const langAliases: Record<string, string> = {
      javascript: 'js',
      'javascript/typescript': 'js',
      'js/ts': 'js',
      typescript: 'ts',
      py: 'python',
      golang: 'go',
      'c#': 'csharp',
      cs: 'csharp',
    };
    const key = out.language.toLowerCase().trim();
    if (langAliases[key]) out.language = langAliases[key];
  }

  // todos normalization. Cheap models often emit strings instead of
  // { title, detail } objects, or wrap them under `steps` / `plan` keys.
  if (!Array.isArray(out.todos)) {
    if (Array.isArray(out.steps)) out.todos = out.steps;
    else if (Array.isArray(out.plan)) out.todos = out.plan;
  }
  if (Array.isArray(out.todos)) {
    out.todos = out.todos
      .map((t: any) => {
        if (typeof t === 'string') return { title: t };
        if (t && typeof t === 'object') {
          const title = t.title ?? t.step ?? t.name ?? t.summary;
          if (typeof title === 'string' && title.trim().length > 0) {
            const detail = typeof t.detail === 'string' && t.detail.trim().length > 0
              ? t.detail
              : typeof t.description === 'string' && t.description.trim().length > 0
                ? t.description
                : undefined;
            return detail ? { title, detail } : { title };
          }
        }
        return null;
      })
      .filter((t: any) => t !== null);
    if (out.todos.length === 0) delete out.todos;
  }
  delete out.steps;
  delete out.plan;

  // fileChanges normalization. Drop entries with empty paths, accept
  // `rationale` as `description`, default unknown actions to "modify".
  if (Array.isArray(out.fileChanges)) {
    out.fileChanges = out.fileChanges
      .filter((fc: any) => fc && typeof fc.path === 'string' && fc.path.trim().length > 0)
      .map((fc: any) => ({
        path: String(fc.path),
        action: ['modify', 'create', 'delete'].includes(fc.action) ? fc.action : 'modify',
        description: fc.description ?? fc.rationale ?? `Update ${fc.path}`,
      }));
  }

  // Strip refusal sentinels — the prompt warns about these but cheap models
  // still emit them. Real refusals have a substantive reason.
  if (out.refusal) {
    const reason = String(out.refusal.reason ?? '').trim().toLowerCase();
    const sentinels = new Set(['', 'null', 'none', 'n/a', 'na', 'no', 'false']);
    if (sentinels.has(reason)) {
      delete out.refusal;
    }
  }

  return out;
}

function extractJSONFromText(text: string): any {
  const trimmed = String(text ?? '').trim();
  // Strip markdown fences like ```json ... ``` or ``` ... ```.
  const fenceMatch = /^```(?:json)?\s*([\s\S]*?)\s*```\s*$/m.exec(trimmed);
  const candidate = fenceMatch ? fenceMatch[1] : trimmed;
  // Locate first { and last } as the JSON object boundary; tolerates the
  // model emitting a brief prose preamble before the JSON.
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start < 0 || end < 0 || end <= start) {
    throw new Error(`No JSON object found in model output: ${candidate.slice(0, 200)}`);
  }
  return JSON.parse(candidate.slice(start, end + 1));
}

async function generatePlanWithRetry(
  model: any,
  userPrompt: string,
  input: PlannerInput,
): Promise<{ object: any; attempts: number; recoveredFrom?: string }> {
  const baseArgs = { model, schema: fixPlanSchema, system: PLANNER_SYSTEM_PROMPT };

  try {
    const result = await generateObject({ ...baseArgs, prompt: userPrompt });
    return { object: result.object, attempts: 1 };
  } catch (err: any) {
    if (!NoObjectGeneratedError.isInstance(err)) throw err;

    const rawText = (err as any).text ?? '';
    const firstZodIssue = (err as any).cause?.message ?? err.message ?? 'unknown schema error';
    console.warn(
      '[fix-planner] First attempt failed schema. Trying shape recovery.',
      `\nzod issue: ${String(firstZodIssue).slice(0, 600)}`,
      `\nraw model output (truncated): ${String(rawText).slice(0, 1200)}`,
    );

    // Recovery path 1: parse + normalize + re-validate.
    if (rawText) {
      try {
        const parsed = extractJSONFromText(rawText);
        const massaged = normalizePlanShape(parsed, input);
        const validated = fixPlanSchema.parse(massaged);
        console.log('[fix-planner] Recovered via shape normalization.');
        return { object: validated, attempts: 1, recoveredFrom: 'shape_normalization' };
      } catch (recoverErr: any) {
        console.warn(
          '[fix-planner] Shape recovery failed; retrying with feedback prompt.',
          recoverErr?.message ?? recoverErr,
        );
      }
    }

    // Recovery path 2: retry with the validator error as feedback.
    const retryPrompt = [
      userPrompt,
      '',
      'CRITICAL: your previous response did NOT match the required schema.',
      `Validator error: ${firstZodIssue}`,
      '',
      'Output ONLY a JSON object with EXACTLY these top-level fields and no others:',
      '{',
      '  "summary": "<short title sentence, verb + object, ≤80 chars>",',
      `  "finding": { "type": "${input.findingType}", "id": "${input.findingId}" },`,
      '  "description": "<1-2 sentences describing WHAT THE FIX DOES>",',
      '  "issue": "<markdown describing WHAT THE PROBLEM IS, optionally with a fenced code block from the context>",',
      '  "todos": [',
      '    { "title": "<imperative step, ≤80 chars, NO file paths>", "detail": "<optional one-sentence clarifier>" },',
      '    { "title": "<imperative step>" }',
      '  ],',
      '  "fileChanges": [ { "path": "src/foo.ts", "action": "modify", "description": "..." } ],',
      '  "testCommand": "npm test",',
      '  "verificationSteps": [',
      '    { "command": "npm test", "description": "<one sentence on what this covers for THIS fix>" },',
      '    { "command": "npm run lint", "description": "<one sentence>" }',
      '  ],',
      '  "language": "js" | "ts" | "python" | "go" | "java" | "ruby" | "php" | "rust" | "csharp",',
      '  "estimatedDiffSize": "small" | "medium" | "large",',
      '  "wallClockBudgetSec": 300',
      '}',
      '',
      'Rules:',
      '- Do NOT wrap in markdown fences. Pure JSON only.',
      '- Do NOT include findingId or findingType at top level — they go INSIDE the `finding` object.',
      '- Do NOT include `currentState`, `desiredState`, `fixStrategy`, or any other field not listed above.',
      '- `description` is prose — do NOT use bullet points or numbered lists in this field.',
      '- OMIT the `refusal` field entirely unless a real refusal is needed.',
    ].join('\n');

    try {
      const result = await generateObject({ ...baseArgs, prompt: retryPrompt });
      return { object: result.object, attempts: 2 };
    } catch (retryErr: any) {
      if (!NoObjectGeneratedError.isInstance(retryErr)) throw retryErr;
      const retryText = (retryErr as any).text ?? '';
      const retryIssue = (retryErr as any).cause?.message ?? retryErr.message;

      // One more shape-recovery attempt on the retry text.
      if (retryText) {
        try {
          const parsed = extractJSONFromText(retryText);
          const massaged = normalizePlanShape(parsed, input);
          const validated = fixPlanSchema.parse(massaged);
          console.log('[fix-planner] Recovered via shape normalization on retry.');
          return { object: validated, attempts: 2, recoveredFrom: 'shape_normalization_retry' };
        } catch {
          // Fall through to throw.
        }
      }

      console.error(
        '[fix-planner] All recovery paths exhausted.',
        `\nzod issue: ${String(retryIssue).slice(0, 600)}`,
        `\nraw model output (truncated): ${String(retryText).slice(0, 1200)}`,
      );
      throw new Error(
        `Planner could not produce a schema-valid plan after 2 attempts and shape recovery. Last validator error: ${retryIssue}`,
      );
    }
  }
}

export async function generateFixPlan(input: PlannerInput): Promise<PlannerResult> {
  const repo = await resolveRepo(input.projectId, input.organizationId);

  const installationToken = await createInstallationToken(repo.installationId);
  const baseSha = await getBranchSha(installationToken, repo.repoFullName, repo.defaultBranch);

  const findingContext = await gatherFindingContext(input);

  const model = await getLanguageModelForOrg(input.organizationId);

  const userPrompt = buildUserPrompt(input, findingContext, repo);
  const { object, attempts, recoveredFrom } = await generatePlanWithRetry(model, userPrompt, input);
  if (attempts > 1 || recoveredFrom) {
    console.log(
      `[fix-planner] Plan succeeded for ${input.findingType}/${input.findingId} ` +
        `(attempts=${attempts}${recoveredFrom ? `, recovered=${recoveredFrom}` : ''})`,
    );
  }

  const plan: FixPlan = {
    ...object,
    finding: {
      type: input.findingType,
      id: input.findingId,
      severity: object.finding.severity,
    },
    wallClockBudgetSec: object.wallClockBudgetSec ?? DEFAULT_WALL_CLOCK_BUDGET_SEC,
  };

  return {
    plan,
    baseSha,
    baseBranch: repo.defaultBranch,
    repoFullName: repo.repoFullName,
  };
}
