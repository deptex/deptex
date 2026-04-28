import { generateObject } from 'ai';
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
3. Pick the test command that exercises the patched code in this repo's primary language. Default by language: npm test (js/ts), pytest (python), go test ./... (go), mvn test (java), bundle exec rspec (ruby), composer test (php), cargo test (rust), dotnet test (csharp).
4. estimatedDiffSize: small (<100 LOC), medium (100-500), large (>500). Plans estimated as "large" should be split.
5. wallClockBudgetSec defaults to 300. Increase only when the language toolchain is slow (e.g., Java/Maven up to 600).
6. fileChanges should list each touched file with a one-sentence rationale. Do not include diffs — those are produced during execution.
7. currentState bullets describe what's broken today. desiredState bullets describe the post-fix state.
8. summary is one or two sentences a developer can scan in two seconds.

REFUSAL RULES:
Set refusal.reason ONLY when a fix cannot be safely produced. Examples:
- No patched version exists for this vulnerability.
- The finding is ambiguous or already remediated.
- The required change is too large for v1 (>500 LOC) and must be split.
- Language not in the v1 ship gate (anything outside js/ts/python/go) — set refusal.reason to "Language X is not supported by Aegis Fix Agent v1." with no manualSuggestion needed.

When you set refusal, still populate the other fields with best-effort placeholders so the schema validates; humans will read the refusal first.`;

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

export async function generateFixPlan(input: PlannerInput): Promise<PlannerResult> {
  const repo = await resolveRepo(input.projectId, input.organizationId);

  const installationToken = await createInstallationToken(repo.installationId);
  const baseSha = await getBranchSha(installationToken, repo.repoFullName, repo.defaultBranch);

  const findingContext = await gatherFindingContext(input);

  const model = await getLanguageModelForOrg(input.organizationId);

  const { object } = await generateObject({
    model,
    schema: fixPlanSchema,
    system: PLANNER_SYSTEM_PROMPT,
    prompt: buildUserPrompt(input, findingContext, repo),
  });

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
