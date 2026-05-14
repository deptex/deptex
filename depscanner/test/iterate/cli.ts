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
import { runVariant, runMultiTrial, formatSummary, formatMultiTrialSummary } from './runner';
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
  /** Provider-side sampling seed for reproducible iterate measurements.
   *  Plumbed through to OpenAI-compatible `seed` body field. Anthropic /
   *  Google ignore it (they don't expose a seed knob). Setting this lets
   *  engine-change recall lifts emerge from AI-variance noise that
   *  otherwise masks <6pp signal at temperature 0.1. */
  seed?: number;
  /** Sampling temperature override. Default 0.1; use 0 for greedy decoding
   *  (closest to deterministic per-CVE with seed). */
  temperature?: number;
  /** Number of independent trials per CVE. When N>1, dispatch all (CVE × trial)
   *  pairs through one pLimit gate and aggregate to union / majority /
   *  intersection. Per-trial seed = `seed + trialIndex` so trial 0 reproduces
   *  the single-trial baseline. Default 1 (preserves prior behaviour). */
  trials: number;
  /** Comma-separated CVE id allowlist. When set, only the listed CVE ids from
   *  the CANDIDATES corpus are exercised — useful for cheap targeted re-runs
   *  after a YAML / engine change (e.g. validating ~10 bucket-G targets for
   *  ~$0.10 instead of the full 88-CVE run for ~$0.25). Matches case-
   *  insensitively against `Candidate.cveId`. Unknown ids throw at startup. */
  cves?: string[];
}

function parseFlags(argv: string[]): CliFlags {
  const flags: Partial<CliFlags> = { concurrency: 2, dryRun: false, trials: 1 };
  for (const arg of argv) {
    if (arg.startsWith('--variant=')) flags.variant = arg.slice('--variant='.length);
    else if (arg.startsWith('--provider=')) flags.provider = arg.slice('--provider='.length) as AiProviderName;
    else if (arg.startsWith('--model=')) flags.model = arg.slice('--model='.length);
    else if (arg.startsWith('--base-url=')) flags.baseUrl = arg.slice('--base-url='.length);
    else if (arg.startsWith('--concurrency=')) flags.concurrency = parseInt(arg.slice('--concurrency='.length), 10);
    else if (arg === '--dry-run') flags.dryRun = true;
    else if (arg.startsWith('--limit=')) flags.limit = parseInt(arg.slice('--limit='.length), 10);
    else if (arg.startsWith('--output-root=')) flags.outputRoot = arg.slice('--output-root='.length);
    else if (arg.startsWith('--seed=')) {
      const n = parseInt(arg.slice('--seed='.length), 10);
      if (!Number.isFinite(n)) throw new Error(`--seed must be an integer, got "${arg.slice('--seed='.length)}"`);
      flags.seed = n;
    }
    else if (arg.startsWith('--temperature=')) {
      const t = parseFloat(arg.slice('--temperature='.length));
      if (!Number.isFinite(t) || t < 0 || t > 2) throw new Error(`--temperature must be in [0, 2], got "${arg.slice('--temperature='.length)}"`);
      flags.temperature = t;
    }
    else if (arg.startsWith('--trials=')) {
      const n = parseInt(arg.slice('--trials='.length), 10);
      if (!Number.isFinite(n) || n < 1) throw new Error(`--trials must be a positive integer, got "${arg.slice('--trials='.length)}"`);
      flags.trials = n;
    }
    else if (arg.startsWith('--cves=')) {
      const raw = arg.slice('--cves='.length);
      flags.cves = raw.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
      if (flags.cves.length === 0) throw new Error('--cves requires at least one comma-separated CVE id');
    }
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
  let candidates = flags.limit ? CANDIDATES.slice(0, flags.limit) : CANDIDATES;
  if (flags.cves) {
    const allowed = new Set(flags.cves.map((c) => c.toLowerCase()));
    const known = new Set(CANDIDATES.map((c) => c.cveId.toLowerCase()));
    const unknown = flags.cves.filter((c) => !known.has(c.toLowerCase()));
    if (unknown.length) throw new Error(`--cves contains unknown CVE id(s): ${unknown.join(', ')}`);
    candidates = candidates.filter((c) => allowed.has(c.cveId.toLowerCase()));
  }

  if (flags.trials > 1) {
    if (flags.dryRun) throw new Error('--dry-run is incompatible with --trials > 1 (no AI calls to repeat).');
    const report = await runMultiTrial({
      variant,
      provider: flags.provider,
      model: flags.model,
      apiKey,
      baseUrl: flags.baseUrl,
      candidates,
      concurrency: flags.concurrency,
      outputDir,
      seed: flags.seed,
      temperature: flags.temperature,
      trials: flags.trials,
    });
    process.stdout.write(formatMultiTrialSummary(report));
    return;
  }

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
    seed: flags.seed,
    temperature: flags.temperature,
  });

  process.stdout.write(formatSummary(report));
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
