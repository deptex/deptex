/**
 * STEP: Dependency resolution (ecosystem-specific install before SBOM).
 *
 * Different ecosystems need different install commands for cdxgen to
 * accurately resolve the dependency tree. Failure is non-fatal — the SBOM
 * step still runs against whatever lockfile/manifest is on disk.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { runStage } from '../pipeline-stage-runner';
import { stripAnsi } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

async function resolveDependencies(
  workspacePath: string,
  ecosystem: string,
  // Loose-typed for the same reason ctx.log is — LogStep doesn't include
  // 'resolve' so passing a typed ExtractionLogger here would fail strict TS.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  log: any,
): Promise<void> {
  // For npm, choose the install command from the lockfile present. Hardcoding
  // npm install fails on pnpm-workspace and yarn monorepos (e.g. next.js,
  // react, vite, turborepo-shaped projects) because package.json uses
  // workspace: references that npm rejects. The lockfile is the
  // unambiguous signal of which manager to use; corepack (Node ≥ 16.9) shims
  // pnpm and yarn so they're available without a separate install.
  const npmCmd = (() => {
    if (fs.existsSync(path.join(workspacePath, 'pnpm-lock.yaml'))) {
      return 'corepack pnpm install --ignore-scripts 2>&1';
    }
    if (fs.existsSync(path.join(workspacePath, 'yarn.lock'))) {
      return 'corepack yarn install --ignore-scripts --no-immutable 2>&1';
    }
    return 'npm install --ignore-scripts --no-audit --no-fund 2>&1';
  })();
  const resolveCommands: Record<string, { check: string; cmd: string; timeout: number }> = {
    npm: {
      check: 'package.json',
      cmd: npmCmd,
      timeout: 300_000,
    },
    maven: {
      check: 'pom.xml',
      cmd: 'mvn dependency:resolve -B -q 2>&1',
      timeout: 600_000,
    },
    golang: {
      check: 'go.mod',
      cmd: 'go mod download 2>&1',
      timeout: 300_000,
    },
    pypi: {
      check: 'requirements.txt',
      cmd: 'pip3 install --no-cache-dir --break-system-packages -r requirements.txt 2>&1 || true',
      timeout: 300_000,
    },
    cargo: {
      check: 'Cargo.toml',
      cmd: 'cargo fetch 2>&1',
      timeout: 300_000,
    },
    gem: {
      check: 'Gemfile',
      cmd: 'bundle install --jobs 4 2>&1',
      timeout: 300_000,
    },
    composer: {
      check: 'composer.json',
      cmd: 'composer install --no-scripts --no-interaction 2>&1',
      timeout: 300_000,
    },
  };

  const config = resolveCommands[ecosystem];
  if (!config) return;

  const manifestPath = path.join(workspacePath, config.check);
  if (!fs.existsSync(manifestPath)) return;

  const resolveStart = Date.now();
  await log.info('resolve', 'Installing dependencies...');
  try {
    execSync(config.cmd, {
      cwd: workspacePath,
      encoding: 'utf8',
      timeout: config.timeout,
      maxBuffer: 20 * 1024 * 1024,
    });
    await log.success('resolve', 'Dependencies installed successfully', Date.now() - resolveStart);
  } catch (err: any) {
    const stderr = err.stderr ? stripAnsi(err.stderr).slice(-1000) : err.message?.slice(0, 1000);
    throw new Error(`${ecosystem} dependency resolution failed: ${stderr}`);
  }
}

export async function doResolve(ctx: PipelineContext): Promise<void> {
  const { supabase, job, projectId, log, workspaceRoot, jobEcosystem } = ctx;
  await runStage({
    name: 'resolve',
    timeoutMs: 10 * 60_000,
    fn: () => resolveDependencies(workspaceRoot, jobEcosystem, log),
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    severity: 'warn',
    onError: async ({ err }) => {
      await log.warn('resolve', `Dependency resolution failed (non-fatal): ${(err as Error).message ?? String(err)}`);
    },
  });
}
