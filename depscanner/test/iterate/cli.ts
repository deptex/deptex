/**
 * CLI entry for running a single variant against the corpus.
 *
 *   npm run iterate -- --variant=v_base --provider=openai --model=Qwen/Qwen3-235B-A22B-Instruct-2507 --base-url=https://api.deepinfra.com/v1/openai
 *   npm run iterate -- --variant=v_base --provider=google --model=gemini-2.5-flash
 *   npm run iterate -- --variant=v_meta --concurrency=2
 *
 * Loads .env from the worktree's backend/.env automatically. API keys are
 * resolved by provider:
 *   anthropic -> ANTHROPIC_API_KEY
 *   google    -> GOOGLE_API_KEY || GOOGLE_AI_API_KEY
 *   openai    -> by base-url hostname (DeepInfra / OpenRouter / DashScope) else OPENAI_API_KEY
 *
 * Output: bench-iterate/<variant>/<timestamp>/{report.json, summary.txt}
 */

import * as fs from 'fs';
import * as path from 'path';
import { pathToFileURL } from 'url';
import * as dotenv from 'dotenv';
import type { VariantModule } from './runner';
import { runVariant, formatSummary } from './runner';
import type { AiProviderName } from '../../src/rule-generator/generate';

interface CliFlags {
  variant: string;
  provider: AiProviderName;
  model: string;
  baseUrl?: string;
  concurrency: number;
  dryRun: boolean;
  limit?: number;
  outputRoot: string;
}

function parseFlags(argv: string[]): CliFlags {
  const flags: Partial<CliFlags> = { concurrency: 2, dryRun: false };
  for (const arg of argv) {
    if (arg.startsWith('--variant=')) flags.variant = arg.slice('--variant='.length);
    else if (arg.startsWith('--provider=')) flags.provider = arg.slice('--provider='.length) as AiProviderName;
    else if (arg.startsWith('--model=')) flags.model = arg.slice('--model='.length);
    else if (arg.startsWith('--base-url=')) flags.baseUrl = arg.slice('--base-url='.length);
    else if (arg.startsWith('--concurrency=')) flags.concurrency = parseInt(arg.slice('--concurrency='.length), 10);
    else if (arg === '--dry-run') flags.dryRun = true;
    else if (arg.startsWith('--limit=')) flags.limit = parseInt(arg.slice('--limit='.length), 10);
    else if (arg.startsWith('--output-root=')) flags.outputRoot = arg.slice('--output-root='.length);
  }
  if (!flags.variant) throw new Error('missing --variant=<name>');
  if (!flags.provider) flags.provider = 'openai';
  if (!flags.model) {
    if (flags.provider === 'openai' && (flags.baseUrl ?? '').includes('deepinfra')) {
      flags.model = 'Qwen/Qwen3-235B-A22B-Instruct-2507';
    } else if (flags.provider === 'google') {
      flags.model = 'gemini-2.5-flash';
    } else if (flags.provider === 'anthropic') {
      flags.model = 'claude-sonnet-4-6';
    } else {
      flags.model = 'gpt-4o-mini';
    }
  }
  if (!flags.outputRoot) flags.outputRoot = path.resolve(__dirname, '..', '..', 'bench-iterate');
  return flags as CliFlags;
}

function loadEnv(): void {
  // Worktree's backend/.env (4 levels up from this file).
  const worktreeEnv = path.resolve(__dirname, '..', '..', '..', '.env');
  if (fs.existsSync(worktreeEnv)) dotenv.config({ path: worktreeEnv });
  // Main repo's backend/.env (probed as a fallback for keys missing from
  // the worktree). Use a Windows-style absolute since worktrees can be
  // anywhere under .claude/worktrees/.
  const mainEnvWindows = 'C:\\Coding\\Deptex\\backend\\.env';
  const mainEnvPosix = '/c/Coding/Deptex/backend/.env';
  for (const cand of [mainEnvWindows, mainEnvPosix]) {
    if (fs.existsSync(cand)) dotenv.config({ path: cand });
  }
}

function resolveApiKey(provider: AiProviderName, baseUrl?: string): string | null {
  if (provider === 'anthropic') return process.env.ANTHROPIC_API_KEY ?? null;
  if (provider === 'google') return process.env.GOOGLE_API_KEY ?? process.env.GOOGLE_AI_API_KEY ?? null;
  if (provider === 'openai') {
    const url = baseUrl ?? '';
    if (url.includes('deepinfra')) return process.env.DEEPINFRA_API_KEY ?? null;
    if (url.includes('openrouter')) return process.env.OPENROUTER_API_KEY ?? null;
    if (url.includes('aliyuncs') || url.includes('dashscope')) return process.env.DASHSCOPE_API_KEY ?? null;
    return process.env.OPENAI_API_KEY ?? null;
  }
  return null;
}

async function loadVariant(name: string): Promise<VariantModule> {
  const file = path.join(__dirname, 'variants', `${name}.ts`);
  if (!fs.existsSync(file)) throw new Error(`variant file not found: ${file}`);
  // On Windows the dynamic ESM loader rejects `c:\...` paths — wrap as file:// URL.
  const mod = await import(pathToFileURL(file).href);
  if (!mod.NAME || !mod.VERSION || typeof mod.buildGenerationPrompt !== 'function') {
    throw new Error(`variant ${name} missing required exports (NAME, VERSION, buildGenerationPrompt)`);
  }
  return mod as VariantModule;
}

async function main(): Promise<void> {
  loadEnv();
  const flags = parseFlags(process.argv.slice(2));
  const variant = await loadVariant(flags.variant);
  const apiKey = flags.dryRun ? 'dry-run-no-key' : resolveApiKey(flags.provider, flags.baseUrl);
  if (!apiKey) {
    throw new Error(`No API key resolved for provider=${flags.provider} baseUrl=${flags.baseUrl ?? '(none)'}. Check backend/.env.`);
  }

  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const outputDir = path.join(flags.outputRoot, variant.NAME, ts);
  process.stderr.write(`[${variant.NAME}] starting variant=${variant.NAME}@${variant.VERSION} provider=${flags.provider} model=${flags.model} baseUrl=${flags.baseUrl ?? '(default)'} → ${outputDir}\n`);

  const { CANDIDATES } = await import('./candidates');
  const candidates = flags.limit ? CANDIDATES.slice(0, flags.limit) : CANDIDATES;

  const report = await runVariant({
    variant,
    provider: flags.provider,
    model: flags.model,
    apiKey,
    baseUrl: flags.baseUrl,
    candidates,
    concurrency: flags.concurrency,
    outputDir,
    dryRun: flags.dryRun,
  });

  process.stdout.write(formatSummary(report));
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
