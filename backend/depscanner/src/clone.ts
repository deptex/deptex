import simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createClient } from '@supabase/supabase-js';
import { cloneRepository, cleanupRepository } from './github';
import type { ExtractionJob } from './pipeline';

export { cloneRepository, cleanupRepository };

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key);
}

async function getIntegrationToken(integrationId: string): Promise<{ access_token: string; provider: string; metadata: any }> {
  const supabase = getSupabase();
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
  const tempDir = path.join(
    os.tmpdir(),
    `deptex-extract-${Date.now()}-${Math.random().toString(36).substring(7)}`
  );
  fs.mkdirSync(tempDir, { recursive: true });
  return tempDir;
}

async function cloneWithToken(
  repoUrl: string,
  branch: string
): Promise<string> {
  const tempDir = makeTempDir();
  try {
    const git = simpleGit(tempDir);
    await git.clone(repoUrl, tempDir, ['--branch', branch, '--depth', '1', '--single-branch']);
    return tempDir;
  } catch (error: any) {
    if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

export async function cloneByProvider(job: ExtractionJob): Promise<string> {
  const provider = job.provider || 'github';

  if (provider === 'github') {
    return cloneRepository(job.installation_id, job.repo_full_name, job.default_branch);
  }

  if (!job.integration_id) {
    throw new Error(`${provider} clone requires integration_id`);
  }

  const integ = await getIntegrationToken(job.integration_id);

  if (provider === 'gitlab') {
    const gitlabUrl = integ.metadata?.gitlab_url || process.env.GITLAB_URL || 'https://gitlab.com';
    const repoUrl = `https://oauth2:${integ.access_token}@${new URL(gitlabUrl).host}/${job.repo_full_name}.git`;
    return cloneWithToken(repoUrl, job.default_branch);
  }

  if (provider === 'bitbucket') {
    const repoUrl = `https://x-token-auth:${integ.access_token}@bitbucket.org/${job.repo_full_name}.git`;
    return cloneWithToken(repoUrl, job.default_branch);
  }

  throw new Error(`Unsupported provider: ${provider}`);
}
