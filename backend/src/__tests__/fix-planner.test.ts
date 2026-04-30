import { MockLanguageModelV3 } from 'ai/test';

import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const PROJECT_ID = '00000000-0000-0000-0000-000000000002';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const INSTALLATION_ID = '99999';
const REPO_FULL_NAME = 'acme/payments-service';
const DEFAULT_BRANCH = 'main';
const HEAD_SHA = 'a1b2c3d4e5f6';

const mockGetLanguageModelForOrg = jest.fn();

jest.mock('../lib/aegis/llm-provider', () => ({
  __esModule: true,
  getLanguageModelForOrg: (orgId: string) => mockGetLanguageModelForOrg(orgId),
}));

jest.mock('../lib/github', () => ({
  __esModule: true,
  createInstallationToken: jest.fn().mockResolvedValue('ghs_test_token'),
  getBranchSha: jest.fn().mockResolvedValue(HEAD_SHA),
}));

import { generateFixPlan } from '../lib/aegis-v3/fix-planner';

function happyPlanText(): string {
  return JSON.stringify({
    summary: 'Bump lodash 4.17.20 to 4.17.21 to resolve prototype pollution.',
    finding: {
      type: 'vulnerability',
      id: 'GHSA-xxxx-yyyy-zzzz',
      severity: 'high',
    },
    currentState: ['lodash@4.17.20 in package.json', 'Imported by 3 files'],
    desiredState: ['lodash@4.17.21 (patched)', 'Lockfile regenerated'],
    fileChanges: [
      { path: 'package.json', action: 'modify', description: 'Bump version' },
      { path: 'package-lock.json', action: 'modify', description: 'Regenerate' },
    ],
    testCommand: 'npm test',
    language: 'js',
    estimatedDiffSize: 'small',
    wallClockBudgetSec: 300,
  });
}

function refusalPlanText(): string {
  return JSON.stringify({
    summary: 'Cannot fix — no patched version exists.',
    finding: { type: 'vulnerability', id: 'GHSA-aaaa-bbbb-cccc' },
    currentState: ['vulnerable@1.0.0'],
    desiredState: ['no patched version available'],
    fileChanges: [],
    testCommand: 'npm test',
    language: 'js',
    estimatedDiffSize: 'small',
    wallClockBudgetSec: 300,
    refusal: { reason: 'No patched version available for this vulnerability.' },
  });
}

function makeModel(text: string): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    doGenerate: async () => ({
      finishReason: 'stop',
      usage: { inputTokens: 10, outputTokens: 50, totalTokens: 60 },
      content: [{ type: 'text', text }],
      warnings: [],
    }),
  });
}

function setRepoAndOrgRows() {
  setTableResponse('project_repositories', 'maybeSingle', {
    data: {
      repo_full_name: REPO_FULL_NAME,
      default_branch: DEFAULT_BRANCH,
      installation_id: INSTALLATION_ID,
      status: 'connected',
    },
    error: null,
  });
  setTableResponse('organizations', 'single', {
    data: { github_installation_id: INSTALLATION_ID },
    error: null,
  });
}

describe('generateFixPlan', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    mockGetLanguageModelForOrg.mockReset();
  });

  it('returns a valid FixPlan for a vulnerability finding (happy path)', async () => {
    setRepoAndOrgRows();
    setTableResponse('dependency_vulnerabilities', 'single', {
      data: {
        osv_id: 'GHSA-xxxx-yyyy-zzzz',
        severity: 'high',
        summary: 'Prototype pollution',
        details: '...',
        affected_versions: '<4.17.21',
        fixed_versions: '>=4.17.21',
        references: [],
      },
      error: null,
    });
    mockGetLanguageModelForOrg.mockResolvedValue(makeModel(happyPlanText()));

    const result = await generateFixPlan({
      organizationId: ORG_ID,
      projectId: PROJECT_ID,
      findingType: 'vulnerability',
      findingId: 'GHSA-xxxx-yyyy-zzzz',
      triggeredByUserId: USER_ID,
    });

    expect(result.baseSha).toBe(HEAD_SHA);
    expect(result.baseBranch).toBe(DEFAULT_BRANCH);
    expect(result.repoFullName).toBe(REPO_FULL_NAME);
    expect(result.plan.summary).toContain('lodash');
    expect(result.plan.finding.id).toBe('GHSA-xxxx-yyyy-zzzz');
    expect(result.plan.finding.type).toBe('vulnerability');
    expect(result.plan.fileChanges).toHaveLength(2);
    expect(result.plan.language).toBe('js');
    expect(result.plan.refusal).toBeUndefined();
    expect(mockGetLanguageModelForOrg).toHaveBeenCalledWith(ORG_ID);
  });

  it('passes through a refusal from the planner', async () => {
    setRepoAndOrgRows();
    setTableResponse('dependency_vulnerabilities', 'single', {
      data: { osv_id: 'GHSA-aaaa-bbbb-cccc', severity: 'low' },
      error: null,
    });
    mockGetLanguageModelForOrg.mockResolvedValue(makeModel(refusalPlanText()));

    const result = await generateFixPlan({
      organizationId: ORG_ID,
      projectId: PROJECT_ID,
      findingType: 'vulnerability',
      findingId: 'GHSA-aaaa-bbbb-cccc',
      triggeredByUserId: USER_ID,
    });

    expect(result.plan.refusal).toBeDefined();
    expect(result.plan.refusal?.reason).toMatch(/No patched version/);
  });

  it('throws when project has no connected repository', async () => {
    setTableResponse('project_repositories', 'maybeSingle', {
      data: { status: 'not_connected' },
      error: null,
    });
    mockGetLanguageModelForOrg.mockResolvedValue(makeModel(happyPlanText()));

    await expect(
      generateFixPlan({
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        findingType: 'vulnerability',
        findingId: 'GHSA-xxxx-yyyy-zzzz',
        triggeredByUserId: USER_ID,
      }),
    ).rejects.toThrow(/no connected repository/i);
  });

  it('handles a Semgrep finding context path', async () => {
    setRepoAndOrgRows();
    setTableResponse('project_semgrep_findings', 'single', {
      data: {
        rule_id: 'javascript.lang.security.audit.detect-eval-with-expression',
        severity: 'high',
        message: 'Avoid eval with user input',
        path: 'src/utils/parse.js',
        line_start: 12,
        line_end: 14,
        category: 'security',
        cwe_ids: ['CWE-95'],
      },
      error: null,
    });
    mockGetLanguageModelForOrg.mockResolvedValue(
      makeModel(
        JSON.stringify({
          summary: 'Replace eval() with JSON.parse() in parse.js.',
          finding: { type: 'semgrep', id: 'sg-123', severity: 'high' },
          currentState: ['Uses eval() on user input'],
          desiredState: ['Uses JSON.parse() with try/catch'],
          fileChanges: [
            { path: 'src/utils/parse.js', action: 'modify', description: 'Replace eval' },
          ],
          testCommand: 'npm test',
          language: 'js',
          estimatedDiffSize: 'small',
          wallClockBudgetSec: 300,
        }),
      ),
    );

    const result = await generateFixPlan({
      organizationId: ORG_ID,
      projectId: PROJECT_ID,
      findingType: 'semgrep',
      findingId: 'sg-123',
      triggeredByUserId: USER_ID,
    });

    expect(result.plan.finding.type).toBe('semgrep');
    expect(result.plan.fileChanges[0].path).toBe('src/utils/parse.js');
  });
});
