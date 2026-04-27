import { execSync, ExecSyncOptionsWithStringEncoding } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { FixLogger } from './logger';
import { FixJobRow } from './job-db';
import { SupabaseClient } from '@supabase/supabase-js';

const EXEC_OPTS: ExecSyncOptionsWithStringEncoding = { encoding: 'utf-8', timeout: 120_000 };

export interface PRResult {
  prUrl: string;
  prNumber: number;
  prBranch: string;
  diffSummary: string;
}

function getCloneUrl(provider: string, repoFullName: string, token: string): string {
  switch (provider) {
    case 'gitlab':
      return `https://oauth2:${token}@gitlab.com/${repoFullName}.git`;
    case 'bitbucket':
      return `https://x-token-auth:${token}@bitbucket.org/${repoFullName}.git`;
    default:
      return `https://x-access-token:${token}@github.com/${repoFullName}.git`;
  }
}

export async function cloneRepo(
  repoFullName: string,
  defaultBranch: string,
  provider: string,
  token: string,
  workDir: string,
  logger: FixLogger,
): Promise<void> {
  const cloneUrl = getCloneUrl(provider, repoFullName, token);
  const startMs = Date.now();

  await logger.info('clone', `Cloning ${repoFullName} (${defaultBranch})...`);

  execSync(
    `git clone --depth 1 --single-branch --branch ${defaultBranch} --filter=blob:limit=10m "${cloneUrl}" "${workDir}"`,
    { ...EXEC_OPTS, timeout: 300_000 },
  );

  const duration = Date.now() - startMs;
  await logger.success('clone', `Cloned ${repoFullName}`, duration);
}

export function getBranchName(job: FixJobRow, rootDir?: string): string {
  let scope = '';
  if (rootDir) scope = `${rootDir.replace(/\//g, '-')}/`;

  switch (job.strategy) {
    case 'bump_version':
    case 'code_patch':
    case 'add_wrapper':
    case 'pin_transitive':
    case 'remove_unused':
      return `fix/${scope}${job.osv_id || `vuln-${job.id.slice(0, 8)}`}`;
    case 'fix_semgrep':
      return `fix/${scope}semgrep-${job.semgrep_finding_id?.slice(0, 8) || job.id.slice(0, 8)}`;
    case 'remediate_secret':
      return `fix/${scope}secret-${job.secret_finding_id?.slice(0, 8) || job.id.slice(0, 8)}`;
    default:
      return `fix/${scope}${job.id.slice(0, 8)}`;
  }
}

export async function resolveBranchName(
  workDir: string,
  baseName: string,
  logger: FixLogger,
): Promise<string> {
  try {
    execSync(`git ls-remote --exit-code --heads origin ${baseName}`, { ...EXEC_OPTS, cwd: workDir });
  } catch {
    return baseName;
  }

  // Branch exists — try suffixes
  for (let i = 2; i <= 10; i++) {
    const suffixed = `${baseName}-${i}`;
    try {
      execSync(`git ls-remote --exit-code --heads origin ${suffixed}`, { ...EXEC_OPTS, cwd: workDir });
    } catch {
      await logger.info('push', `Branch ${baseName} exists, using ${suffixed}`);
      return suffixed;
    }
  }
  throw new Error(`Too many existing branches for ${baseName}`);
}

export async function commitAndPush(
  workDir: string,
  branchName: string,
  commitMessage: string,
  logger: FixLogger,
): Promise<string> {
  await logger.info('push', `Creating branch ${branchName}`);
  execSync(`git checkout -b "${branchName}"`, { ...EXEC_OPTS, cwd: workDir });
  execSync('git add -A', { ...EXEC_OPTS, cwd: workDir });

  const diff = execSync('git diff --cached --stat', { ...EXEC_OPTS, cwd: workDir });
  if (!diff.trim()) {
    throw new Error('no_changes');
  }

  execSync(`git commit -m "${commitMessage.replace(/"/g, '\\"')}"`, { ...EXEC_OPTS, cwd: workDir });

  const startMs = Date.now();
  await logger.info('push', 'Pushing changes...');
  execSync(`git push origin "${branchName}"`, { ...EXEC_OPTS, cwd: workDir, timeout: 120_000 });
  await logger.success('push', 'Pushed to remote', Date.now() - startMs);

  return diff.trim();
}

export function getDiffSummary(workDir: string): string {
  try {
    return execSync('git diff HEAD~1 --stat', { ...EXEC_OPTS, cwd: workDir }).trim();
  } catch {
    return '';
  }
}

export function checkDiskSpace(workDir: string, logger: FixLogger): void {
  try {
    const df = execSync('df -BG . 2>/dev/null || true', { ...EXEC_OPTS, cwd: path.dirname(workDir) });
    const match = df.match(/(\d+)G\s+\d+%/);
    if (match && parseInt(match[1]) < 2) {
      logger.log('init', 'warning', 'Low disk space (<2GB free)');
    }
  } catch { /* non-fatal */ }
}

// ---------- PR creation via GitHub/GitLab/Bitbucket API ----------

export async function createPullRequest(
  supabase: SupabaseClient,
  job: FixJobRow,
  branchName: string,
  diffSummary: string,
  validationResult: any,
): Promise<PRResult | null> {
  const repoInfo = job.payload.repo;
  if (!repoInfo) return null;

  const { data: integration } = await supabase
    .from('organization_integrations')
    .select('access_token, provider')
    .eq('id', repoInfo.integrationId)
    .single();

  if (!integration?.access_token) return null;

  const title = buildPRTitle(job);
  const body = buildPRDescription(job, diffSummary, validationResult);
  const provider = repoInfo.provider || 'github';
  const [owner, repo] = repoInfo.fullName.split('/');

  try {
    if (provider === 'github') {
      return await createGitHubPR(integration.access_token, owner, repo, branchName, repoInfo.defaultBranch, title, body);
    }
    // GitLab and Bitbucket follow similar patterns
    return null;
  } catch (err: any) {
    console.error(`[AIDER] Failed to create PR: ${err.message}`);
    return null;
  }
}

async function createGitHubPR(
  token: string,
  owner: string,
  repo: string,
  head: string,
  base: string,
  title: string,
  body: string,
): Promise<PRResult> {
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/vnd.github+json',
    },
    body: JSON.stringify({ title, body, head, base, draft: true }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub PR creation failed: ${res.status} ${text}`);
  }

  const pr = (await res.json()) as { html_url: string; number: number };
  return { prUrl: pr.html_url, prNumber: pr.number, prBranch: head, diffSummary: '' };
}

function buildPRTitle(job: FixJobRow): string {
  const rootDir = job.payload.repo?.rootDirectory;
  const scope = rootDir ? `[${rootDir}] ` : '';

  switch (job.strategy) {
    case 'bump_version':
      return `${scope}Fix ${job.osv_id}: upgrade ${job.payload.dependency?.name ?? 'dependency'} to ${job.target_version ?? 'safe version'}`;
    case 'code_patch':
      return `${scope}Fix ${job.osv_id}: add application-level mitigation`;
    case 'add_wrapper':
      return `${scope}Fix ${job.osv_id}: add safe wrapper for ${job.payload.dependency?.name ?? 'dependency'}`;
    case 'pin_transitive':
      return `${scope}Fix ${job.osv_id}: pin transitive dependency ${job.payload.dependency?.name ?? ''}`;
    case 'remove_unused':
      return `${scope}Remove unused dependency ${job.payload.dependency?.name ?? ''}`;
    case 'fix_semgrep':
      return `${scope}Fix Semgrep finding: ${job.payload.semgrepFinding?.rule_id ?? 'security issue'}`;
    case 'remediate_secret':
      return `${scope}Remediate exposed ${job.payload.secretFinding?.detector_type ?? 'secret'}`;
    default:
      return `${scope}Security fix by Deptex AI`;
  }
}

function formatValidation(val: boolean | null): string {
  if (val === true) return 'Passed';
  if (val === false) return 'Failed';
  return 'Skipped';
}

function formatStrategy(strategy: string, targetVersion?: string | null): string {
  const labels: Record<string, string> = {
    bump_version: `Version bump${targetVersion ? ` to ${targetVersion}` : ''}`,
    code_patch: 'Application-level code patch',
    add_wrapper: 'Safe wrapper function',
    pin_transitive: 'Pin transitive dependency',
    remove_unused: 'Remove unused dependency',
    fix_semgrep: 'Semgrep finding fix',
    remediate_secret: 'Secret remediation',
  };
  return labels[strategy] ?? strategy;
}

function buildPRDescription(job: FixJobRow, diffSummary: string, validationResult: any): string {
  const vr = validationResult || {};
  const lines = [
    `## Security Fix: ${job.osv_id || job.strategy}`,
    '',
    `**Strategy:** ${formatStrategy(job.strategy, job.target_version)}`,
    `**Severity:** ${job.payload.vulnerability?.severity || 'N/A'}`,
    `**Ecosystem:** ${job.payload.dependency?.ecosystem || job.payload.repo?.provider || 'N/A'}`,
    `**Generated by:** Deptex AI (Aider)`,
    '',
    '### What changed',
    diffSummary || 'See diff below.',
    '',
    '### Validation',
    `- Audit: ${formatValidation(vr.auditPassed)}`,
    `- Tests: ${vr.testsSkipped ? 'Skipped (no test command detected)' : formatValidation(vr.testsPassed)}`,
  ];

  if (vr.notes?.length) {
    for (const note of vr.notes) {
      lines.push(`- Note: ${note}`);
    }
  }

  if (job.introduced_vulns?.length) {
    lines.push('', '### Warnings');
    lines.push(`- This fix introduces: ${job.introduced_vulns.join(', ')}`);
  }

  lines.push('', '---');
  lines.push('*This is a draft PR created by [Deptex AI](https://deptex.dev). Review carefully before merging.*');

  return lines.join('\n');
}
