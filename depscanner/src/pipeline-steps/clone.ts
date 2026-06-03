/**
 * STEP: Clone (CRITICAL — or bypass for local-mode)
 *
 * Clones the repo via the configured provider OR adopts a pre-existing
 * workspace path (CLI local-mode). Records HEAD commit on the scan job for
 * Recent Activity. Validates the package_json_path subdirectory exists.
 *
 * Mutates ctx.repoPath, ctx.workspaceRoot, ctx.runId, ctx.jobEcosystem.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { cloneByProvider } from '../clone';
import { updateJobPayloadCommit } from '../job-db';
import { runStage } from '../pipeline-stage-runner';
import { retry, updateStep, setError, classifyCloneError } from '../pipeline-helpers';
import { ScanFailedError } from '../scan-errors';
import type { PipelineContext } from '../pipeline-types';

export async function doClone(ctx: PipelineContext): Promise<void> {
  const { job, supabase, projectId, log } = ctx;
  const packageJsonPath = (job.package_json_path ?? '').trim();

  await updateStep(supabase, projectId, 'cloning', 'extracting');

  const cloneStart = Date.now();
  let repoPath: string;

  if (job.localWorkspacePath) {
    if (!fs.existsSync(job.localWorkspacePath)) {
      const msg = `Local workspace not found: ${job.localWorkspacePath}`;
      await log.error('cloning', msg);
      await setError(supabase, projectId, msg);
      throw new ScanFailedError(msg);
    }
    repoPath = job.localWorkspacePath;
    await log.info('cloning', `Scanning local workspace: ${job.localWorkspacePath}`);
    await log.success('cloning', 'Local workspace ready', Date.now() - cloneStart);
  } else {
    await log.info(
      'cloning',
      `Cloning repository from ${(job.provider || 'github').charAt(0).toUpperCase() + (job.provider || 'github').slice(1)}...`,
    );
    repoPath = (await runStage({
      name: 'clone',
      timeoutMs: 15 * 60_000,
      fn: () => retry(() => cloneByProvider(job), 'clone'),
      supabase,
      jobId: job.jobId,
      projectId,
      log,
      severity: 'error',
      onError: async ({ err }) => {
        const userMsg = classifyCloneError((err as Error).message ?? String(err));
        await log.error('cloning', userMsg, err);
        await setError(supabase, projectId, userMsg);
        return { rethrow: true, throwAs: new ScanFailedError(userMsg) };
      },
    })) as string;
    await log.success('cloning', 'Repository cloned successfully', Date.now() - cloneStart);
  }

  ctx.repoPath = repoPath;

  // Record HEAD commit into job payload for Recent Activity (manual/initial runs;
  // webhook already set it).
  if (job.jobId && repoPath) {
    try {
      const commitSha = execSync('git rev-parse HEAD', { cwd: repoPath, encoding: 'utf-8' }).trim();
      const commitMessage = execSync('git log -1 --format=%s%n%b', { cwd: repoPath, encoding: 'utf-8' }).trim();
      await updateJobPayloadCommit(supabase, job.jobId, {
        commit_sha: commitSha,
        commit_message: commitMessage.slice(0, 2000) || undefined,
        branch: job.default_branch,
      });
    } catch (e) {
      // non-fatal: UI will show trigger type only for this run
    }
  }

  const workspaceRoot = packageJsonPath ? path.join(repoPath, packageJsonPath) : repoPath;

  if (!fs.existsSync(workspaceRoot)) {
    const msg = `No package manifest found at '${packageJsonPath || '(root)'}' — check your project's package path setting`;
    await log.error('cloning', msg);
    await setError(supabase, projectId, msg);
    throw new ScanFailedError(msg);
  }

  ctx.workspaceRoot = workspaceRoot;
  ctx.jobEcosystem = job.ecosystem || 'npm';
  // Use job id so GET /sbom can find the file (it looks up scan_jobs.id → projectId/{id}/sbom.json)
  ctx.runId = job.jobId ?? Date.now().toString();
}
