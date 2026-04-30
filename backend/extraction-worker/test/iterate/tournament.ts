/**
 * Tournament: run N variants against the same candidate corpus on a single
 * provider/model and dump a comparison table.
 *
 *   npm run iterate:tournament -- --variants=v_base,v_meta,v_grammar,v_audit,v_cot,v_negfew,v_instance,v_quote --provider=openai --base-url=https://api.deepinfra.com/v1/openai --model=Qwen/Qwen3-235B-A22B-Instruct-2507 --concurrency=3
 *
 * Variants run sequentially (single shared rate-limit queue inside one node
 * process). Each variant's report is written to bench-iterate/<variant>/<ts>/.
 * The aggregate table is written to bench-iterate/tournament-<ts>/summary.md.
 */

import * as fs from 'fs';
import * as path from 'path';
import { pathToFileURL } from 'url';
import * as dotenv from 'dotenv';
import { runVariant, formatSummary, type VariantModule, type VariantRunReport } from './runner';
import type { AiProviderName } from '../../src/rule-generator/generate';

interface CliFlags {
  variants: string[];
  provider: AiProviderName;
  model: string;
  baseUrl?: string;
  concurrency: number;
  limit?: number;
  outputRoot: string;
}

function parseFlags(argv: string[]): CliFlags {
  const flags: Partial<CliFlags> = { concurrency: 3 };
  for (const arg of argv) {
    if (arg.startsWith('--variants=')) flags.variants = arg.slice('--variants='.length).split(',').map((s) => s.trim()).filter(Boolean);
    else if (arg.startsWith('--provider=')) flags.provider = arg.slice('--provider='.length) as AiProviderName;
    else if (arg.startsWith('--model=')) flags.model = arg.slice('--model='.length);
    else if (arg.startsWith('--base-url=')) flags.baseUrl = arg.slice('--base-url='.length);
    else if (arg.startsWith('--concurrency=')) flags.concurrency = parseInt(arg.slice('--concurrency='.length), 10);
    else if (arg.startsWith('--limit=')) flags.limit = parseInt(arg.slice('--limit='.length), 10);
    else if (arg.startsWith('--output-root=')) flags.outputRoot = arg.slice('--output-root='.length);
  }
  if (!flags.variants || flags.variants.length === 0) throw new Error('missing --variants=v_a,v_b,...');
  if (!flags.provider) flags.provider = 'openai';
  if (!flags.model) flags.model = 'Qwen/Qwen3-235B-A22B-Instruct-2507';
  if (!flags.outputRoot) flags.outputRoot = path.resolve(__dirname, '..', '..', 'bench-iterate');
  return flags as CliFlags;
}

function loadEnv(): void {
  const worktreeEnv = path.resolve(__dirname, '..', '..', '..', '.env');
  if (fs.existsSync(worktreeEnv)) dotenv.config({ path: worktreeEnv });
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
  const mod = await import(pathToFileURL(file).href);
  if (!mod.NAME || !mod.VERSION || typeof mod.buildGenerationPrompt !== 'function') {
    throw new Error(`variant ${name} missing required exports`);
  }
  return mod as VariantModule;
}

function aggregateMarkdown(reports: VariantRunReport[]): string {
  const lines: string[] = [];
  const N = reports[0]?.candidates ?? 0;
  lines.push(`# Tournament summary`);
  lines.push(``);
  lines.push(`Provider: ${reports[0]?.provider}/${reports[0]?.model}`);
  if (reports[0]?.baseUrl) lines.push(`Base URL: ${reports[0].baseUrl}`);
  lines.push(`Candidates per variant: ${N}`);
  lines.push(``);
  lines.push(`| Variant | Validated | Schema | FixturePre | FixtureSafe | PatchPostClean | Cost ($) | Time (s) |`);
  lines.push(`|---|---|---|---|---|---|---|---|`);
  // Sort by validated descending.
  const sorted = [...reports].sort((a, b) => b.validated - a.validated);
  for (const r of sorted) {
    const rate = r.candidates > 0 ? ((r.validated / r.candidates) * 100).toFixed(1) : '0.0';
    lines.push(`| ${r.variant.name} | **${r.validated}/${r.candidates}** (${rate}%) | ${r.funnel.schemaPass} | ${r.funnel.fixturePre} | ${r.funnel.fixtureSafe} | ${r.funnel.patchPostClean} | ${r.totalCostUsd.toFixed(4)} | ${(r.totalDurationMs / 1000).toFixed(1)} |`);
  }
  lines.push(``);
  lines.push(`## Per-CVE pass map`);
  lines.push(``);
  // Header row: variants
  const variantNames = reports.map((r) => r.variant.name);
  lines.push(`| CVE | ${variantNames.join(' | ')} |`);
  lines.push(`|---|${variantNames.map(() => '---').join('|')}|`);
  // Each row: a CVE with ✓ / ✗ across variants
  const cveIds = reports[0].perCve.map((c) => c.cveId);
  for (const cveId of cveIds) {
    const cells = reports.map((r) => {
      const c = r.perCve.find((x) => x.cveId === cveId);
      if (!c) return '?';
      if (c.status === 'validated') return '✓';
      if (c.status === 'no_advisory' || c.status === 'no_fix_commit' || c.status === 'fetch_failed') return '–';
      return '✗';
    });
    lines.push(`| ${cveId} | ${cells.join(' | ')} |`);
  }
  return lines.join('\n') + '\n';
}

async function main(): Promise<void> {
  loadEnv();
  const flags = parseFlags(process.argv.slice(2));
  const apiKey = resolveApiKey(flags.provider, flags.baseUrl);
  if (!apiKey) throw new Error(`No API key for provider=${flags.provider} baseUrl=${flags.baseUrl ?? '(none)'}`);

  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const tournamentDir = path.join(flags.outputRoot, `tournament-${ts}`);
  fs.mkdirSync(tournamentDir, { recursive: true });
  process.stderr.write(`# Tournament: variants=${flags.variants.join(',')} provider=${flags.provider} model=${flags.model}\n`);

  const { CANDIDATES } = await import('./candidates');
  const candidates = flags.limit ? CANDIDATES.slice(0, flags.limit) : CANDIDATES;

  const reports: VariantRunReport[] = [];
  for (const name of flags.variants) {
    const variant = await loadVariant(name);
    const variantDir = path.join(tournamentDir, name);
    process.stderr.write(`\n=== ${name} ===\n`);
    const report = await runVariant({
      variant,
      provider: flags.provider,
      model: flags.model,
      apiKey,
      baseUrl: flags.baseUrl,
      candidates,
      concurrency: flags.concurrency,
      outputDir: variantDir,
    });
    reports.push(report);
    process.stderr.write(formatSummary(report));
    // Persist incremental aggregate after each variant so a partial run is still useful.
    fs.writeFileSync(path.join(tournamentDir, 'summary.md'), aggregateMarkdown(reports), 'utf8');
    fs.writeFileSync(path.join(tournamentDir, 'reports.json'), JSON.stringify(reports, null, 2), 'utf8');
  }

  process.stdout.write(aggregateMarkdown(reports));
  process.stderr.write(`\nTournament outputs: ${tournamentDir}\n`);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
