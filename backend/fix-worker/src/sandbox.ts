import { execSync, type ExecSyncOptionsWithStringEncoding } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import type { FixLogger } from './logger';
import type { PlanLanguage } from './plan-types';

const EXEC_OPTS: ExecSyncOptionsWithStringEncoding = { encoding: 'utf-8', timeout: 120_000 };

export interface SandboxHandle {
  workDir: string;
  cleanup: () => void;
}

export function createSandbox(fixId: string): SandboxHandle {
  const workDir = path.join('/work', `fix-${fixId}`);
  if (fs.existsSync(workDir)) {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
  fs.mkdirSync(workDir, { recursive: true });
  return {
    workDir,
    cleanup: () => {
      try {
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    },
  };
}

export async function cloneAtSha(opts: {
  workDir: string;
  installationToken: string;
  repoFullName: string;
  branch: string;
  baseSha: string;
  logger: FixLogger;
}): Promise<void> {
  const { workDir, installationToken, repoFullName, branch, baseSha, logger } = opts;
  const cloneUrl = `https://x-access-token:${installationToken}@github.com/${repoFullName}.git`;
  const startedAt = Date.now();
  await logger.info('clone', `Cloning ${repoFullName}@${branch}`);

  // Shallow clone the branch tip then hard-reset to baseSha so the worker
  // operates against the exact SHA the user approved. If baseSha is no longer
  // reachable from the shallow tip we fall back to a full fetch of that SHA.
  execSync(
    `git clone --depth 1 --single-branch --branch ${branch} "${cloneUrl}" "${workDir}"`,
    { ...EXEC_OPTS, timeout: 300_000 },
  );

  try {
    execSync(`git -C "${workDir}" cat-file -e ${baseSha}`, EXEC_OPTS);
  } catch {
    execSync(`git -C "${workDir}" fetch --depth 1 origin ${baseSha}`, { ...EXEC_OPTS, timeout: 180_000 });
  }
  execSync(`git -C "${workDir}" reset --hard ${baseSha}`, EXEC_OPTS);

  await logger.success('clone', `Cloned ${repoFullName} at ${baseSha.slice(0, 7)}`, Date.now() - startedAt);
}

export async function setupForLanguage(opts: {
  workDir: string;
  language: PlanLanguage;
  logger: FixLogger;
}): Promise<void> {
  const { workDir, language, logger } = opts;
  const startedAt = Date.now();

  // M5 ship gate: JS/TS bootstrap. Python + Go land in M6, stretch in M8.
  if (language === 'js' || language === 'ts') {
    await logger.info('setup', 'Installing JS dependencies (npm ci)');
    if (fs.existsSync(path.join(workDir, 'package-lock.json'))) {
      try {
        execSync('npm ci --no-audit --no-fund', {
          ...EXEC_OPTS,
          cwd: workDir,
          timeout: 300_000,
        });
      } catch (err: any) {
        // Fall back to npm install if ci fails (lockfile drift, etc.).
        await logger.warn('setup', `npm ci failed, falling back to npm install: ${err.message}`);
        execSync('npm install --no-audit --no-fund', {
          ...EXEC_OPTS,
          cwd: workDir,
          timeout: 300_000,
        });
      }
    } else {
      execSync('npm install --no-audit --no-fund', {
        ...EXEC_OPTS,
        cwd: workDir,
        timeout: 300_000,
      });
    }
    await logger.success('setup', 'JS dependencies installed', Date.now() - startedAt);
    return;
  }

  await logger.warn('setup', `Language ${language} bootstrap not implemented in M5; skipping setup.`);
}

export function readFileSafe(workDir: string, relPath: string): string | null {
  try {
    return fs.readFileSync(path.join(workDir, relPath), 'utf-8');
  } catch {
    return null;
  }
}
