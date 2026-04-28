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

export interface SetupResult {
  // Extra env to merge into spawnSync when running tests / subcommands.
  // Lets the Python venv binaries take precedence over system ones without
  // requiring the planner to know venv layout.
  extraEnv: Record<string, string>;
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

function fileExists(workDir: string, relPath: string): boolean {
  return fs.existsSync(path.join(workDir, relPath));
}

async function setupJs(workDir: string, logger: FixLogger): Promise<void> {
  await logger.info('setup', 'Installing JS dependencies (npm ci)');
  if (fileExists(workDir, 'package-lock.json')) {
    try {
      execSync('npm ci --no-audit --no-fund', { ...EXEC_OPTS, cwd: workDir, timeout: 300_000 });
      return;
    } catch (err: any) {
      await logger.warn('setup', `npm ci failed, falling back to npm install: ${err.message}`);
    }
  }
  execSync('npm install --no-audit --no-fund', { ...EXEC_OPTS, cwd: workDir, timeout: 300_000 });
}

async function setupPython(workDir: string, logger: FixLogger): Promise<Record<string, string>> {
  // Always create a per-job venv so test deps don't pollute the image and
  // so multiple concurrent jobs in different sandboxes don't fight over
  // /usr/lib site-packages.
  const venvDir = path.join(workDir, '.venv');
  await logger.info('setup', 'Creating Python virtualenv');
  execSync(`python3 -m venv "${venvDir}"`, { ...EXEC_OPTS, cwd: workDir, timeout: 60_000 });

  const venvBin = path.join(venvDir, 'bin');
  const venvPy = path.join(venvBin, 'python');
  const venvPip = path.join(venvBin, 'pip');

  // Prefer pyproject.toml if present (pip understands PEP 517 directly).
  // Fall back to requirements.txt, then setup.py. Always finish by ensuring
  // pytest is available so the planner's default test command works even
  // for repos that didn't list pytest in their deps.
  const installs: Array<{ label: string; cmd: string }> = [];
  if (fileExists(workDir, 'pyproject.toml')) {
    installs.push({ label: 'pip install -e . (pyproject)', cmd: `"${venvPip}" install -e . --quiet` });
  } else if (fileExists(workDir, 'requirements.txt')) {
    installs.push({ label: 'pip install -r requirements.txt', cmd: `"${venvPip}" install -r requirements.txt --quiet` });
  } else if (fileExists(workDir, 'setup.py')) {
    installs.push({ label: 'pip install -e . (setup.py)', cmd: `"${venvPip}" install -e . --quiet` });
  }
  // Many repos pin test deps in requirements-dev.txt or test-requirements.txt.
  if (fileExists(workDir, 'requirements-dev.txt')) {
    installs.push({ label: 'pip install -r requirements-dev.txt', cmd: `"${venvPip}" install -r requirements-dev.txt --quiet` });
  } else if (fileExists(workDir, 'test-requirements.txt')) {
    installs.push({ label: 'pip install -r test-requirements.txt', cmd: `"${venvPip}" install -r test-requirements.txt --quiet` });
  }

  for (const { label, cmd } of installs) {
    try {
      await logger.info('setup', label);
      execSync(cmd, { ...EXEC_OPTS, cwd: workDir, timeout: 600_000 });
    } catch (err: any) {
      // Don't hard-fail if a dev-deps install hits a transient error;
      // the test command will surface the real problem if it matters.
      await logger.warn('setup', `${label} failed: ${err.message?.slice(0, 200)}`);
    }
  }

  // Pytest fallback so `pytest` works even if the project hasn't listed it.
  try {
    execSync(`"${venvPy}" -c "import pytest"`, { ...EXEC_OPTS, cwd: workDir });
  } catch {
    await logger.info('setup', 'Installing pytest fallback');
    execSync(`"${venvPip}" install pytest --quiet`, { ...EXEC_OPTS, cwd: workDir, timeout: 120_000 });
  }

  // Prepend venv bin to PATH so plan.testCommand of "pytest" resolves to
  // the venv's pytest, not whatever the system might have.
  return {
    PATH: `${venvBin}:${process.env.PATH ?? ''}`,
    VIRTUAL_ENV: venvDir,
  };
}

async function setupGo(workDir: string, logger: FixLogger): Promise<void> {
  if (!fileExists(workDir, 'go.mod')) {
    await logger.warn('setup', 'No go.mod at repo root — skipping go mod download');
    return;
  }
  await logger.info('setup', 'go mod download');
  execSync('go mod download', { ...EXEC_OPTS, cwd: workDir, timeout: 300_000 });
}

export async function setupForLanguage(opts: {
  workDir: string;
  language: PlanLanguage;
  logger: FixLogger;
}): Promise<SetupResult> {
  const { workDir, language, logger } = opts;
  const startedAt = Date.now();
  let extraEnv: Record<string, string> = {};

  if (language === 'js' || language === 'ts') {
    await setupJs(workDir, logger);
  } else if (language === 'python') {
    extraEnv = await setupPython(workDir, logger);
  } else if (language === 'go') {
    await setupGo(workDir, logger);
  } else {
    await logger.warn('setup', `Language ${language} bootstrap not implemented; skipping setup.`);
  }

  await logger.success('setup', `${language} setup complete`, Date.now() - startedAt);
  return { extraEnv };
}

export function readFileSafe(workDir: string, relPath: string): string | null {
  try {
    return fs.readFileSync(path.join(workDir, relPath), 'utf-8');
  } catch {
    return null;
  }
}
