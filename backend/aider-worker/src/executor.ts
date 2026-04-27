import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { FixLogger } from './logger';

export interface AiderResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export function getAiderEnvVars(provider: string, apiKey: string): Record<string, string> {
  const envMap: Record<string, string> = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    google: 'GEMINI_API_KEY',
  };
  return { [envMap[provider] ?? 'OPENAI_API_KEY']: apiKey };
}

export function getAiderModelFlag(provider: string, model: string): string {
  if (provider === 'google') return `gemini/${model}`;
  return model;
}

export async function invokeAider(
  workDir: string,
  prompt: string,
  files: string[],
  model: string,
  envVars: Record<string, string>,
  logger: FixLogger,
  watchdogMs: number = 10 * 60 * 1000,
): Promise<AiderResult> {
  const promptFile = path.join(workDir, '.deptex-fix-prompt.md');
  fs.writeFileSync(promptFile, prompt, 'utf-8');

  const args = [
    '--yes-always',
    '--no-auto-commits',
    '--no-stream',
    '--model', model,
    '--message-file', promptFile,
    ...files.flatMap(f => ['--file', f]),
    '--timeout', '120',
  ];

  return new Promise((resolve, reject) => {
    const child = spawn('aider', args, {
      cwd: workDir,
      env: { ...process.env, ...envVars },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d: Buffer) => {
      const chunk = d.toString();
      stdout += chunk;
      const lines = chunk.trim().split('\n');
      for (const line of lines) {
        if (line.trim()) {
          logger.log('aider', 'info', line.trim());
        }
      }
    });

    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
    });

    const watchdog = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* already dead */ }
      }, 5000);
      reject(new Error('Aider execution timed out after 10 minutes'));
    }, watchdogMs);

    child.on('close', (code) => {
      clearTimeout(watchdog);
      try { fs.unlinkSync(promptFile); } catch { /* best-effort */ }
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });

    child.on('error', (err) => {
      clearTimeout(watchdog);
      try { fs.unlinkSync(promptFile); } catch { /* best-effort */ }
      reject(err);
    });
  });
}

export function parseTokenUsage(output: string): { tokens: number; cost: number } {
  let tokens = 0;
  let cost = 0;
  const tokenMatch = output.match(/Tokens:\s*([\d,]+)\s*sent,\s*([\d,]+)\s*received/);
  if (tokenMatch) {
    tokens = parseInt(tokenMatch[1].replace(/,/g, ''), 10) + parseInt(tokenMatch[2].replace(/,/g, ''), 10);
  }
  const costMatch = output.match(/Cost:\s*\$?([\d.]+)/);
  if (costMatch) {
    cost = parseFloat(costMatch[1]);
  }
  return { tokens, cost };
}

export function clearLLMKeys(): void {
  delete process.env.OPENAI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.GEMINI_API_KEY;
}
