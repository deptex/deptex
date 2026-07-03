import simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createSupabaseStorage } from './storage/supabase';
import { cloneRepository, cleanupRepository, checkoutCommit } from './github';
import type { ExtractionJob } from './pipeline';

export { cloneRepository, cleanupRepository };

async function getIntegrationToken(integrationId: string): Promise<{ access_token: string; provider: string; metadata: any }> {
  const supabase = createSupabaseStorage();
  const { data, error } = await supabase
    .from('organization_integrations')
    .select('access_token, provider, metadata')
    .eq('id', integrationId)
    .single();
  if (error || !data?.access_token) {
    throw new Error(`Failed to get integration token for ${integrationId}: ${error?.message || 'no token'}`);
  }
  return data;
}

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-extract-'));
}

async function cloneWithToken(
  repoUrl: string,
  branch: string,
  commitSha?: string
): Promise<string> {
  const tempDir = makeTempDir();
  try {
    const git = simpleGit(tempDir);
    await git.clone(repoUrl, tempDir, ['--branch', branch, '--depth', '1', '--single-branch']);
    if (commitSha) await checkoutCommit(tempDir, commitSha);
    return tempDir;
  } catch (error: any) {
    if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

/**
 * The ref to clone. Prefer the explicitly requested branch (a webhook push to a
 * non-default branch sets `job.branch`); fall back to the repo default for
 * manual/initial/scheduled runs that don't pin a branch.
 */
function cloneRef(job: ExtractionJob): string {
  return job.branch || job.default_branch;
}

export async function cloneByProvider(job: ExtractionJob): Promise<string> {
  const provider = job.provider || 'github';
  const branch = cloneRef(job);
  const commitSha = job.commit_sha;

  if (provider === 'github') {
    return cloneRepository(job.installation_id, job.repo_full_name, branch, commitSha);
  }

  if (!job.integration_id) {
    throw new Error(`${provider} clone requires integration_id`);
  }

  const integ = await getIntegrationToken(job.integration_id);

  if (provider === 'gitlab') {
    const gitlabUrl = integ.metadata?.gitlab_url || process.env.GITLAB_URL || 'https://gitlab.com';
    const repoUrl = `https://oauth2:${integ.access_token}@${new URL(gitlabUrl).host}/${job.repo_full_name}.git`;
    return cloneWithToken(repoUrl, branch, commitSha);
  }

  if (provider === 'bitbucket') {
    const repoUrl = `https://x-token-auth:${integ.access_token}@bitbucket.org/${job.repo_full_name}.git`;
    return cloneWithToken(repoUrl, branch, commitSha);
  }

  throw new Error(`Unsupported provider: ${provider}`);
}
