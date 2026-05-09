/**
 * Cross-cutting helpers shared by pipeline.ts + per-step modules.
 *
 * Lives outside `pipeline-steps/` because every step uses some of these and we
 * don't want a step module to import another step module just to grab
 * `updateStep` or `binaryAvailable`.
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Storage } from './storage';

export const MAX_RETRIES = 3;
export const RETRY_DELAY_MS = 2000;

/** Strip ANSI so dep-scan stderr excerpts are readable in logs on failure. */
export function stripAnsi(text: string): string {
  return text.replace(/\[[0-9;]*m/g, '');
}

export async function retry<T>(fn: () => Promise<T>, stepName: string): Promise<T> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (e: any) {
      console.error(`[${stepName}] Attempt ${attempt}/${MAX_RETRIES} failed:`, e.message);
      if (attempt === MAX_RETRIES) throw e;
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS * attempt));
    }
  }
  throw new Error('Unreachable');
}

export function getSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key);
}

export async function updateStep(
  supabase: Storage,
  projectId: string,
  step: string,
  status?: string
): Promise<void> {
  await supabase
    .from('project_repositories')
    .update({
      extraction_step: step,
      ...(status ? { status, extraction_error: null } : {}),
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);
}

export async function setError(
  supabase: Storage,
  projectId: string,
  message: string
): Promise<void> {
  await supabase
    .from('project_repositories')
    .update({
      status: 'error',
      extraction_error: message,
      extraction_step: null,
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);
}

export async function callQueuePopulate(
  backendBaseUrl: string,
  workerSecret: string | undefined,
  projectId: string,
  organizationId: string,
  deps: Array<{ dependencyId: string; name: string }>,
  ecosystem: string
): Promise<void> {
  const url = `${backendBaseUrl.replace(/\/$/, '')}/api/workers/queue-populate`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (workerSecret) {
    headers['X-Worker-Secret'] = workerSecret;
  }
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      projectId,
      organizationId,
      ecosystem,
      dependencies: deps.map((d) => ({ dependencyId: d.dependencyId, name: d.name, ecosystem })),
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`queue-populate failed: ${res.status} ${text}`);
  }
}

/**
 * Probe for a binary on PATH without spawning the real command. Returns true
 * if `<name> --version` (or `-version`) exits cleanly. Keeps noise out of logs
 * so we can surface a friendly install hint instead of a stack trace.
 */
export function binaryAvailable(name: string): boolean {
  try {
    const res = spawnSync(name, ['--version'], { stdio: 'ignore', timeout: 5000 });
    if (res.status === 0) return true;
    // trufflehog uses `--version`, semgrep uses `--version` — both 0 on success.
    // Fall back to a PATH lookup via `where`/`which` for binaries that don't
    // implement --version in the expected way.
    const which = process.platform === 'win32' ? 'where' : 'which';
    const lookup = spawnSync(which, [name], { stdio: 'ignore', timeout: 5000 });
    return lookup.status === 0;
  } catch {
    return false;
  }
}

export const INSTALL_HINTS: Record<string, string> = {
  semgrep:
    "Semgrep not found — the Dockerfile bundles it, so this likely means the image is misbuilt or you are running the worker outside the container. Static analysis skipped.",
  trufflehog:
    "TruffleHog not found — the Dockerfile bundles it, so this likely means the image is misbuilt or you are running the worker outside the container. Secret scanning skipped.",
  guarddog:
    "GuardDog binary not found at /opt/guarddog-venv/bin/guarddog — the Dockerfile installs it into an isolated venv, so this likely means the image is misbuilt or you are running the worker outside the container. Malicious-package source-code analysis skipped (feed lookup still runs).",
};

export function classifyCloneError(message: string): string {
  if (/401|403|authentication|authorization/i.test(message)) {
    return 'Authentication failed — your source code integration may need to be reconnected in Organization Settings';
  }
  if (/404|not found/i.test(message)) {
    return 'Repository not found — it may have been deleted or made private';
  }
  if (/could not find remote branch|unknown revision/i.test(message)) {
    return `Branch not found in repository`;
  }
  if (/ENOSPC|no space left/i.test(message)) {
    return 'Repository is too large to scan';
  }
  return `Clone failed: ${message.slice(0, 200)}`;
}

export function classifyCdxgenError(message: string): string {
  if (/timeout|timed out/i.test(message)) {
    return 'SBOM generation timed out — the repository may be too large or complex';
  }
  return `SBOM generation failed: ${message.slice(0, 200)}`;
}

/** Clear only dep-scan cache on the volume; do NOT delete VDB (the VDB extract is ~30GB and is reused between runs). */
export function clearDepscanCacheOnly(): void {
  const cacheDir = process.env.DEPSCAN_CACHE_DIR || (process.env.VDB_HOME ? path.join(process.env.VDB_HOME, 'cache') : null);
  if (!cacheDir || !cacheDir.startsWith('/data')) return;
  if (!fs.existsSync(cacheDir)) return;
  try {
    const entries = fs.readdirSync(cacheDir, { withFileTypes: true });
    for (const e of entries) {
      fs.rmSync(path.join(cacheDir, e.name), { recursive: true, force: true });
    }
  } catch (err) {
    console.warn('[EXTRACT] Failed to clear dep-scan cache:', (err as Error).message);
  }
}

/** Clear entire /data (VDB + cache). Use only for corruption recovery so dep-scan re-downloads a fresh VDB. */
export function clearVdbVolumeForRecovery(): void {
  const dataDir = process.env.VDB_HOME;
  if (!dataDir || dataDir !== '/data') return;
  if (!fs.existsSync(dataDir)) return;
  try {
    const entries = fs.readdirSync(dataDir, { withFileTypes: true });
    for (const e of entries) {
      fs.rmSync(path.join(dataDir, e.name), { recursive: true, force: true });
    }
    fs.mkdirSync(path.join(dataDir, 'cache'), { recursive: true });
  } catch (err) {
    console.warn('[EXTRACT] Failed to clear VDB volume for recovery:', (err as Error).message);
  }
}
